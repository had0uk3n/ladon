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
    ApprovalCoordinator, EditSecretDraft, LocalServer, PendingApproval, RunCancellation,
    RunTermination, Supervisor, VaultController, VaultUiPhase, default_endpoint_path,
};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_CONNECTION_WORKERS: usize = 8;

pub struct LocalBrokerHandle {
    stop: Arc<AtomicBool>,
    coordinator: Arc<RunCoordinator>,
    approval: Arc<ApprovalCoordinator>,
    ui_locks: Option<Arc<UiLockCoordinator>>,
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

struct UiLockCoordinator {
    state: Mutex<UiLockState>,
    changed: Condvar,
    wake_ui: Arc<dyn Fn() + Send + Sync>,
}

#[derive(Default)]
struct UiLockState {
    requested: u64,
    acknowledged: u64,
    ready: Option<u64>,
    local_operation: bool,
    connected: bool,
}

struct UiLocalOperation {
    coordinator: Arc<UiLockCoordinator>,
}

impl UiLockCoordinator {
    fn new(wake_ui: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            state: Mutex::new(UiLockState {
                connected: true,
                ..UiLockState::default()
            }),
            changed: Condvar::new(),
            wake_ui,
        }
    }

    fn begin_request(&self) -> Result<u64, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        while (state.requested > state.acknowledged || state.local_operation) && state.connected {
            state = self
                .changed
                .wait(state)
                .map_err(|_| LadonError::ProcessFailure)?;
        }
        if !state.connected {
            return Err(LadonError::EndpointUnavailable);
        }
        state.requested = state
            .requested
            .checked_add(1)
            .ok_or(LadonError::ProcessFailure)?;
        Ok(state.requested)
    }

    fn try_begin_local_operation(self: &Arc<Self>) -> Result<Option<UiLocalOperation>, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        if !state.connected {
            return Err(LadonError::EndpointUnavailable);
        }
        if state.requested > state.acknowledged {
            return Ok(None);
        }
        if state.local_operation {
            return Err(LadonError::Busy);
        }
        state.local_operation = true;
        Ok(Some(UiLocalOperation {
            coordinator: Arc::clone(self),
        }))
    }

    fn finish_request(&self, request_id: u64) -> Result<(), LadonError> {
        {
            let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
            if request_id != state.requested || request_id <= state.acknowledged {
                return Err(LadonError::InvalidRequest);
            }
            state.ready = Some(request_id);
        }
        (self.wake_ui)();

        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        while state.acknowledged < request_id && state.connected {
            state = self
                .changed
                .wait(state)
                .map_err(|_| LadonError::ProcessFailure)?;
        }
        if state.acknowledged >= request_id {
            Ok(())
        } else {
            Err(LadonError::EndpointUnavailable)
        }
    }

    fn pending_request(&self) -> Result<Option<u64>, LadonError> {
        let state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        Ok(
            (state.ready == Some(state.requested) && state.requested > state.acknowledged)
                .then_some(state.requested),
        )
    }

    fn request_in_progress(&self) -> Result<bool, LadonError> {
        let state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        Ok(state.requested > state.acknowledged)
    }

    fn acknowledge(&self, request_id: u64) -> Result<(), LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        if request_id != state.requested
            || state.ready != Some(request_id)
            || request_id <= state.acknowledged
        {
            return Err(LadonError::InvalidRequest);
        }
        state.acknowledged = request_id;
        state.ready = None;
        self.changed.notify_all();
        Ok(())
    }

    fn disconnect(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.connected = false;
            self.changed.notify_all();
        }
    }
}

impl Drop for UiLocalOperation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.coordinator.state.lock() {
            state.local_operation = false;
            self.coordinator.changed.notify_all();
        }
    }
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

fn lock_controller_and_runs(
    coordinator: &Arc<RunCoordinator>,
    approval: &ApprovalCoordinator,
    controller: &Arc<Mutex<VaultController>>,
    ui_locks: Option<&Arc<UiLockCoordinator>>,
) -> Result<(), LadonError> {
    let mut first_error = None;
    let ui_request = match ui_locks.map(|ui_locks| ui_locks.begin_request()) {
        Some(Ok(request_id)) => Some(request_id),
        Some(Err(error)) => {
            first_error = Some(error);
            None
        }
        None => None,
    };
    if let Err(error) = approval.cancel_pending() {
        if first_error.is_none() {
            first_error = Some(error);
        }
    }
    if let Err(error) = approval.revoke_all()
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    let _block = match coordinator.block_new_runs() {
        Ok(block) => Some(block),
        Err(error) => {
            if first_error.is_none() {
                first_error = Some(error);
            }
            None
        }
    };
    match controller.lock() {
        Ok(mut controller) => controller.lock(),
        Err(_) if first_error.is_none() => {
            first_error = Some(LadonError::ProcessFailure);
        }
        Err(_) => {}
    }
    if let (Some(ui_locks), Some(request_id)) = (ui_locks, ui_request)
        && let Err(error) = ui_locks.finish_request(request_id)
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    first_error.map_or(Ok(()), Err)
}

impl LocalBrokerHandle {
    pub fn start(controller: Arc<Mutex<VaultController>>) -> Result<Self, LadonError> {
        Self::start_at(controller, default_endpoint_path())
    }

    pub(crate) fn start_for_desktop(
        controller: Arc<Mutex<VaultController>>,
        wake_ui: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, LadonError> {
        Self::start_inner(
            controller,
            default_endpoint_path(),
            Some(Arc::new(UiLockCoordinator::new(wake_ui))),
        )
    }

    #[cfg(test)]
    pub(crate) fn start_at_for_desktop(
        controller: Arc<Mutex<VaultController>>,
        endpoint: impl AsRef<Path>,
        wake_ui: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, LadonError> {
        Self::start_inner(
            controller,
            endpoint,
            Some(Arc::new(UiLockCoordinator::new(wake_ui))),
        )
    }

    pub fn start_at(
        controller: Arc<Mutex<VaultController>>,
        endpoint: impl AsRef<Path>,
    ) -> Result<Self, LadonError> {
        Self::start_inner(controller, endpoint, None)
    }

    fn start_inner(
        controller: Arc<Mutex<VaultController>>,
        endpoint: impl AsRef<Path>,
        ui_locks: Option<Arc<UiLockCoordinator>>,
    ) -> Result<Self, LadonError> {
        let server = LocalServer::bind(endpoint)?;
        server.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let worker_stop = Arc::clone(&stop);
        let worker_coordinator = Arc::clone(&coordinator);
        let worker_approval = Arc::clone(&approval);
        let worker_ui_locks = ui_locks.clone();
        let thread = thread::spawn(move || {
            let broker = Arc::new(AgentBroker::new(
                controller,
                worker_coordinator,
                worker_approval,
                Arc::clone(&worker_stop),
                worker_ui_locks,
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
            ui_locks,
            thread: Some(thread),
        })
    }

    pub(crate) fn pending_external_lock(&self) -> Result<Option<u64>, LadonError> {
        self.ui_locks
            .as_ref()
            .map_or(Ok(None), |ui_locks| ui_locks.pending_request())
    }

    pub(crate) fn acknowledge_external_lock(&self, request_id: u64) -> Result<(), LadonError> {
        self.ui_locks
            .as_ref()
            .ok_or(LadonError::InvalidRequest)?
            .acknowledge(request_id)
    }

    pub(crate) fn external_lock_in_progress(&self) -> Result<bool, LadonError> {
        self.ui_locks
            .as_ref()
            .map_or(Ok(false), |ui_locks| ui_locks.request_in_progress())
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
        let _local_operation = if let Some(ui_locks) = &self.ui_locks {
            let Some(operation) = ui_locks.try_begin_local_operation()? else {
                // The external request already owns the lock transition. Returning lets the GUI
                // wipe its state and acknowledge that request instead of waiting on its run block.
                return Ok(());
            };
            Some(operation)
        } else {
            None
        };
        lock_controller_and_runs(&self.coordinator, &self.approval, controller, None)
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
        let _local_operation = if let Some(ui_locks) = &self.ui_locks {
            let Some(operation) = ui_locks.try_begin_local_operation()? else {
                // An external lock cancels pending approval and revokes all grants itself.
                return Ok(());
            };
            Some(operation)
        } else {
            None
        };
        self.approval.cancel_pending()?;
        let _block = self.coordinator.block_new_runs()?;
        self.approval.revoke_all()
    }

    pub fn update_secret(
        &self,
        controller: &Arc<Mutex<VaultController>>,
        draft: &EditSecretDraft,
    ) -> Result<(), LadonError> {
        self.approval.coordinate_secret_mutation(
            draft.id(),
            || {
                controller
                    .lock()
                    .map_err(|_| LadonError::ProcessFailure)?
                    .prepare_secret_update(draft)
            },
            |update| {
                controller
                    .lock()
                    .map_err(|_| LadonError::ProcessFailure)?
                    .apply_secret_update(update)
            },
        )
    }

    pub fn delete_secret(
        &self,
        controller: &Arc<Mutex<VaultController>>,
        id: ladon_core::SecretId,
    ) -> Result<(), LadonError> {
        self.approval.coordinate_secret_mutation(
            id,
            || {
                controller
                    .lock()
                    .map_err(|_| LadonError::ProcessFailure)?
                    .ensure_secret_exists(id)
            },
            |()| {
                controller
                    .lock()
                    .map_err(|_| LadonError::ProcessFailure)?
                    .delete_secret(id)
            },
        )
    }
}

impl Drop for LocalBrokerHandle {
    fn drop(&mut self) {
        if let Some(ui_locks) = &self.ui_locks {
            ui_locks.disconnect();
        }
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
    ui_locks: Option<Arc<UiLockCoordinator>>,
}

impl AgentBroker {
    fn new(
        controller: Arc<Mutex<VaultController>>,
        coordinator: Arc<RunCoordinator>,
        approval: Arc<ApprovalCoordinator>,
        shutting_down: Arc<AtomicBool>,
        ui_locks: Option<Arc<UiLockCoordinator>>,
    ) -> Self {
        Self {
            controller,
            supervisor: Supervisor::new(),
            coordinator,
            approval,
            shutting_down,
            ui_locks,
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
                lock_controller_and_runs(
                    &self.coordinator,
                    &self.approval,
                    &self.controller,
                    self.ui_locks.as_ref(),
                )?;
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
    fn external_broker_lock_waits_for_gui_ack_after_controller_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let passphrase = crate::SensitiveText::from("correct horse");
        let controller = Arc::new(Mutex::new(VaultController::new(path)));
        controller
            .lock()
            .unwrap()
            .create(&passphrase, &passphrase)
            .unwrap();
        let ui_locks = Arc::new(UiLockCoordinator::new(Arc::new(|| {})));
        let broker = Arc::new(AgentBroker::new(
            Arc::clone(&controller),
            Arc::new(RunCoordinator::default()),
            Arc::new(ApprovalCoordinator::session_defaults()),
            Arc::new(AtomicBool::new(false)),
            Some(Arc::clone(&ui_locks)),
        ));
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let locking = thread::spawn(move || {
            let result = broker.handle_method(
                Uuid::new_v4(),
                "test client".to_owned(),
                RpcMethod::Lock,
                RunCancellation::new(),
            );
            finished_tx.send(result).unwrap();
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let request_id = loop {
            if let Some(request_id) = ui_locks.pending_request().unwrap() {
                break request_id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "GUI lock request never arrived"
            );
            thread::yield_now();
        };
        assert_eq!(controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        assert!(finished_rx.recv_timeout(Duration::from_millis(30)).is_err());

        ui_locks.acknowledge(request_id).unwrap();
        assert_eq!(
            finished_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(RpcResult::Locked)
        );
        locking.join().unwrap();
    }

    #[test]
    fn gui_lock_does_not_wait_on_an_external_lock_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let passphrase = crate::SensitiveText::from("correct horse");
        let controller = Arc::new(Mutex::new(VaultController::new(path)));
        controller
            .lock()
            .unwrap()
            .create(&passphrase, &passphrase)
            .unwrap();
        let coordinator = Arc::new(RunCoordinator::default());
        let active_run = coordinator
            .try_start(RunCancellation::new())
            .expect("test run should start");
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let ui_locks = Arc::new(UiLockCoordinator::new(Arc::new(|| {})));
        let broker = Arc::new(AgentBroker::new(
            Arc::clone(&controller),
            Arc::clone(&coordinator),
            Arc::clone(&approval),
            Arc::new(AtomicBool::new(false)),
            Some(Arc::clone(&ui_locks)),
        ));
        let handle = Arc::new(LocalBrokerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            coordinator,
            approval,
            ui_locks: Some(Arc::clone(&ui_locks)),
            thread: None,
        });

        let (external_tx, external_rx) = std::sync::mpsc::channel();
        let locking = thread::spawn(move || {
            let result = broker.handle_method(
                Uuid::new_v4(),
                "test client".to_owned(),
                RpcMethod::Lock,
                RunCancellation::new(),
            );
            external_tx.send(result).unwrap();
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while !ui_locks.request_in_progress().unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "external lock intent never arrived"
            );
            thread::yield_now();
        }
        assert!(ui_locks.pending_request().unwrap().is_none());

        let (gui_tx, gui_rx) = std::sync::mpsc::channel();
        let gui_handle = Arc::clone(&handle);
        let gui_controller = Arc::clone(&controller);
        let gui_locking = thread::spawn(move || {
            gui_tx
                .send(gui_handle.cancel_active_run_and_lock(&gui_controller))
                .unwrap();
        });
        let immediate_gui_result = gui_rx.recv_timeout(Duration::from_millis(30)).ok();
        let gui_waited = immediate_gui_result.is_none();

        drop(active_run);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let request_id = loop {
            if let Some(request_id) = ui_locks.pending_request().unwrap() {
                break request_id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "external lock request never became ready"
            );
            thread::yield_now();
        };
        ui_locks.acknowledge(request_id).unwrap();
        assert_eq!(
            external_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(RpcResult::Locked)
        );
        let gui_result = immediate_gui_result
            .unwrap_or_else(|| gui_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        assert_eq!(gui_result, Ok(()));
        locking.join().unwrap();
        gui_locking.join().unwrap();
        drop(handle);

        assert!(
            !gui_waited,
            "GUI lock waited on the run barrier after an external lock intent"
        );
    }

    #[test]
    fn coordination_failure_does_not_skip_the_vault_lock_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let passphrase = crate::SensitiveText::from("correct horse");
        let controller = Arc::new(Mutex::new(VaultController::new(path)));
        controller
            .lock()
            .unwrap()
            .create(&passphrase, &passphrase)
            .unwrap();
        let coordinator = Arc::new(RunCoordinator::default());
        let poisoned = Arc::clone(&coordinator);
        assert!(
            thread::spawn(move || {
                let _guard = poisoned.state.lock().unwrap();
                panic!("poison coordinator");
            })
            .join()
            .is_err()
        );
        let broker = LocalBrokerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            coordinator,
            approval: Arc::new(ApprovalCoordinator::session_defaults()),
            ui_locks: None,
            thread: None,
        };

        assert_eq!(
            broker.cancel_active_run_and_lock(&controller),
            Err(LadonError::ProcessFailure)
        );
        assert_eq!(controller.lock().unwrap().phase(), VaultUiPhase::Locked);
    }

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
