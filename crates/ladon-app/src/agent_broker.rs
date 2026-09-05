use std::{
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use ladon_core::{
    LadonError, RpcMethod, RpcRequest, RpcResponse, RpcResult, RunCaller, RunRequest,
    SecretFieldSummary, SecretSummary, validate_run_request,
};
use uuid::Uuid;

use crate::{
    ApprovalCoordinator, LocalServer, PendingApproval, RunCancellation, RunTermination, Supervisor,
    VaultController, VaultUiPhase, default_endpoint_path,
};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_CONNECTION_WORKERS: usize = 8;

pub struct LocalBrokerHandle {
    stop: Arc<AtomicBool>,
    coordinator: Arc<RunCoordinator>,
    approval: Arc<ApprovalCoordinator>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Default)]
struct RunCoordinator {
    state: Mutex<RunCoordinatorState>,
    changed: Condvar,
}

#[derive(Default)]
struct RunCoordinatorState {
    active: Option<RunCancellation>,
    block_new: bool,
}

struct RunLease {
    coordinator: Arc<RunCoordinator>,
}

struct RunBlock {
    coordinator: Arc<RunCoordinator>,
}

impl RunCoordinator {
    fn try_start(self: &Arc<Self>, cancellation: RunCancellation) -> Result<RunLease, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        if state.block_new || state.active.is_some() {
            return Err(LadonError::Busy);
        }
        state.active = Some(cancellation);
        Ok(RunLease {
            coordinator: Arc::clone(self),
        })
    }

    fn cancel_active(&self) {
        if let Ok(state) = self.state.lock() {
            if let Some(cancellation) = state.active.as_ref() {
                cancellation.cancel();
            }
        }
    }

    fn block_new_runs(self: &Arc<Self>) -> Result<RunBlock, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        while state.block_new {
            state = self
                .changed
                .wait(state)
                .map_err(|_| LadonError::ProcessFailure)?;
        }
        state.block_new = true;
        if let Some(cancellation) = state.active.as_ref() {
            cancellation.cancel();
        }
        while state.active.is_some() {
            state = self
                .changed
                .wait(state)
                .map_err(|_| LadonError::ProcessFailure)?;
        }
        Ok(RunBlock {
            coordinator: Arc::clone(self),
        })
    }

    fn try_block_new_runs(self: &Arc<Self>) -> Result<Option<RunBlock>, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        if state.block_new || state.active.is_some() {
            return Ok(None);
        }
        state.block_new = true;
        Ok(Some(RunBlock {
            coordinator: Arc::clone(self),
        }))
    }
}

impl Drop for RunLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            state.active = None;
            self.coordinator.changed.notify_all();
        }
    }
}

impl Drop for RunBlock {
    fn drop(&mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            state.block_new = false;
            self.coordinator.changed.notify_all();
        }
    }
}

impl LocalBrokerHandle {
    pub fn start(controller: Arc<Mutex<VaultController>>) -> Result<Self, LadonError> {
        Self::start_at(controller, default_endpoint_path())
    }

    pub fn start_at(
        controller: Arc<Mutex<VaultController>>,
        endpoint: impl AsRef<Path>,
    ) -> Result<Self, LadonError> {
        let server = LocalServer::bind(endpoint)?;
        server.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let worker_stop = Arc::clone(&stop);
        let worker_coordinator = Arc::clone(&coordinator);
        let worker_approval = Arc::clone(&approval);
        let thread = thread::spawn(move || {
            let broker = Arc::new(AgentBroker::new(
                controller,
                worker_coordinator,
                worker_approval,
                Arc::clone(&worker_stop),
            ));
            let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
            while !worker_stop.load(Ordering::Acquire) {
                let mut index = 0;
                while index < workers.len() {
                    if workers[index].is_finished() {
                        let worker = workers.swap_remove(index);
                        let _ = worker.join();
                    } else {
                        index += 1;
                    }
                }
                match server.try_accept() {
                    Ok(Some(connection)) if workers.len() < MAX_CONNECTION_WORKERS => {
                        let broker = Arc::clone(&broker);
                        workers.push(thread::spawn(move || {
                            let _ = connection.serve(|request, cancellation| {
                                broker.handle(request, cancellation)
                            });
                        }));
                    }
                    Ok(Some(_)) | Ok(None) | Err(_) => thread::sleep(ACCEPT_POLL_INTERVAL),
                }
            }
            broker.cancel_active_run();
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            stop,
            coordinator,
            approval,
            thread: Some(thread),
        })
    }

    pub fn cancel_active_run(&self) {
        self.coordinator.cancel_active();
    }

    pub fn cancel_active_run_and_wait(&self) -> Result<(), LadonError> {
        self.approval.cancel_pending()?;
        let _block = self.coordinator.block_new_runs()?;
        Ok(())
    }

    pub fn cancel_active_run_and_lock(
        &self,
        controller: &Arc<Mutex<VaultController>>,
    ) -> Result<(), LadonError> {
        self.approval.cancel_pending()?;
        self.approval.revoke_all()?;
        let _block = self.coordinator.block_new_runs()?;
        controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?
            .lock();
        Ok(())
    }

    pub fn auto_lock_controller_if_idle(
        &self,
        controller: &Arc<Mutex<VaultController>>,
    ) -> Result<bool, LadonError> {
        let Some(_block) = self.coordinator.try_block_new_runs()? else {
            return Ok(false);
        };
        let locked = controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?
            .auto_lock_if_idle();
        if locked {
            self.approval.cancel_pending()?;
            self.approval.revoke_all()?;
        }
        Ok(locked)
    }

    pub fn pending_approval(&self) -> Result<Option<PendingApproval>, LadonError> {
        self.approval.pending()
    }

    pub fn approve(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.approval.approve(approval_id)
    }

    pub fn deny(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.approval.deny(approval_id)
    }

    pub fn revoke_grants(&self) -> Result<(), LadonError> {
        self.approval.cancel_pending()?;
        let _block = self.coordinator.block_new_runs()?;
        self.approval.revoke_all()
    }
}

impl Drop for LocalBrokerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.approval.cancel_pending();
        let _ = self.approval.revoke_all();
        let _ = self.cancel_active_run_and_wait();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct AgentBroker {
    controller: Arc<Mutex<VaultController>>,
    supervisor: Supervisor,
    coordinator: Arc<RunCoordinator>,
    approval: Arc<ApprovalCoordinator>,
    shutting_down: Arc<AtomicBool>,
}

impl AgentBroker {
    fn new(
        controller: Arc<Mutex<VaultController>>,
        coordinator: Arc<RunCoordinator>,
        approval: Arc<ApprovalCoordinator>,
        shutting_down: Arc<AtomicBool>,
    ) -> Self {
        Self {
            controller,
            supervisor: Supervisor::new(),
            coordinator,
            approval,
            shutting_down,
        }
    }

    fn handle(&self, request: RpcRequest, cancellation: RunCancellation) -> RpcResponse {
        let request_id = request.request_id;
        match self.handle_method(
            request.client_session_id,
            request.client_label,
            request.method,
            cancellation,
        ) {
            Ok(result) => RpcResponse::success(request_id, result),
            Err(error) => RpcResponse::error(request_id, error),
        }
    }

    fn handle_method(
        &self,
        client_session_id: Uuid,
        client_label: String,
        method: RpcMethod,
        connection_cancellation: RunCancellation,
    ) -> Result<RpcResult, LadonError> {
        match method {
            RpcMethod::Status => {
                let controller = self.controller()?;
                Ok(RpcResult::Status {
                    state: phase_name(controller.phase()).to_owned(),
                    idle_remaining_ms: controller.remaining_unlocked().map(duration_millis),
                })
            }
            RpcMethod::List => {
                let controller = self.controller()?;
                if controller.phase() != VaultUiPhase::Unlocked {
                    return Err(LadonError::VaultLocked);
                }
                let secrets = controller
                    .secrets()
                    .into_iter()
                    .map(|secret| {
                        let id = Uuid::parse_str(&secret.id.to_string())
                            .map_err(|_| LadonError::InvalidVaultPayload)?;
                        Ok(SecretSummary {
                            id,
                            name: secret.name,
                            fields: secret
                                .field_names
                                .into_iter()
                                .map(|name| SecretFieldSummary { name, text: true })
                                .collect(),
                        })
                    })
                    .collect::<Result<Vec<_>, LadonError>>()?;
                Ok(RpcResult::List { secrets })
            }
            RpcMethod::Lock => {
                self.approval.cancel_pending()?;
                self.approval.revoke_all()?;
                let _block = self.coordinator.block_new_runs()?;
                self.controller()?.lock();
                Ok(RpcResult::Locked)
            }
            RpcMethod::Run {
                executable,
                arguments,
                working_directory,
                bindings,
                timeout_ms,
                output_limit_bytes,
            } => {
                if self.shutting_down.load(Ordering::Acquire) {
                    return Err(LadonError::EndpointUnavailable);
                }
                let validated = validate_run_request(
                    RunRequest {
                        executable,
                        arguments,
                        working_directory,
                        bindings,
                        timeout_ms,
                        output_limit_bytes,
                    },
                    RunCaller::Cli,
                )?;
                let cancellation = connection_cancellation;
                let _run_lease = self.coordinator.try_start(cancellation.clone())?;
                if self.shutting_down.load(Ordering::Acquire) {
                    return Err(LadonError::EndpointUnavailable);
                }
                if !validated.bindings().is_empty() {
                    let approval_plan = self.controller()?.approval_plan(validated.bindings())?;
                    let ticket = self.approval.authorize(
                        PendingApproval::new(
                            approval_plan.vault_session_id,
                            client_session_id,
                            client_label,
                            approval_plan.secrets,
                            validated.executable(),
                            validated.arguments().iter().map(String::as_str),
                            validated.working_directory(),
                        ),
                        &cancellation,
                    )?;
                    let binding_secret_ids = approval_plan.binding_secret_ids;
                    let result = self.supervisor.run(validated, cancellation, |bindings| {
                        self.approval.with_valid_grant(&ticket, || {
                            self.controller()?
                                .resolve_bindings_for_ids(bindings, &binding_secret_ids)
                        })
                    });
                    if let Ok(mut controller) = self.controller.lock() {
                        controller.record_secret_activity();
                    }
                    return run_result(result);
                }
                let result = self.supervisor.run(validated, cancellation, |bindings| {
                    self.controller()?.resolve_bindings(bindings)
                });
                if let Ok(mut controller) = self.controller.lock() {
                    controller.record_secret_activity();
                }
                run_result(result)
            }
        }
    }

    fn controller(&self) -> Result<std::sync::MutexGuard<'_, VaultController>, LadonError> {
        self.controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)
    }

    fn cancel_active_run(&self) {
        self.coordinator.cancel_active();
    }
}

fn phase_name(phase: VaultUiPhase) -> &'static str {
    match phase {
        VaultUiPhase::FirstRun => "first_run",
        VaultUiPhase::Locked => "locked",
        VaultUiPhase::RecoveryRequired => "recovery_required",
        VaultUiPhase::Unlocked => "unlocked",
    }
}

fn termination_name(termination: RunTermination) -> &'static str {
    match termination {
        RunTermination::Exited => "exited",
        RunTermination::TimedOut => "timed_out",
        RunTermination::Cancelled => "cancelled",
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn run_result(result: Result<crate::RunResult, LadonError>) -> Result<RpcResult, LadonError> {
    let result = result?;
    Ok(RpcResult::Run {
        exit_code: result.exit_code,
        termination: termination_name(result.termination).to_owned(),
        stdout: result.stdout,
        stderr: result.stderr,
        duration_ms: duration_millis(result.duration),
        redaction_count: result.redaction_count,
        output_truncated: result.output_truncated || result.output_suppressed,
        temp_cleanup_warning: result.temp_cleanup_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_new_runs_atomically_cancels_and_waits_for_the_active_run() {
        let coordinator = Arc::new(RunCoordinator::default());
        let active = RunCancellation::new();
        let lease = coordinator.try_start(active.clone()).unwrap();
        let (blocked_tx, blocked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiting_coordinator = Arc::clone(&coordinator);
        let waiter = thread::spawn(move || {
            let block = waiting_coordinator.block_new_runs().unwrap();
            blocked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(block);
        });
        while !active.is_cancelled() {
            thread::yield_now();
        }
        drop(lease);
        blocked_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        assert!(matches!(
            coordinator.try_start(RunCancellation::new()),
            Err(LadonError::Busy)
        ));
        release_tx.send(()).unwrap();
        waiter.join().unwrap();
        assert!(coordinator.try_start(RunCancellation::new()).is_ok());
    }
}
