use std::{
    path::Path,
    sync::{
        Arc, Mutex,
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
    LocalServer, RunCancellation, RunTermination, Supervisor, VaultController, VaultUiPhase,
    default_endpoint_path,
};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_CONNECTION_WORKERS: usize = 8;

pub struct LocalBrokerHandle {
    stop: Arc<AtomicBool>,
    cancellation: Arc<Mutex<Option<RunCancellation>>>,
    run_gate: Arc<Mutex<()>>,
    thread: Option<thread::JoinHandle<()>>,
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
        Supervisor::cleanup_stale_temp_directories()?;
        server.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::new(Mutex::new(None));
        let run_gate = Arc::new(Mutex::new(()));
        let worker_stop = Arc::clone(&stop);
        let worker_cancellation = Arc::clone(&cancellation);
        let worker_run_gate = Arc::clone(&run_gate);
        let thread = thread::spawn(move || {
            let broker = Arc::new(AgentBroker::new(
                controller,
                worker_cancellation,
                worker_run_gate,
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
            cancellation,
            run_gate,
            thread: Some(thread),
        })
    }

    pub fn cancel_active_run(&self) {
        if let Ok(cancellation) = self.cancellation.lock() {
            if let Some(cancellation) = cancellation.as_ref() {
                cancellation.cancel();
            }
        }
    }

    pub fn cancel_active_run_and_wait(&self) -> Result<(), LadonError> {
        self.cancel_active_run();
        drop(
            self.run_gate
                .lock()
                .map_err(|_| LadonError::ProcessFailure)?,
        );
        Ok(())
    }

    pub fn cancel_active_run_and_lock(
        &self,
        controller: &Arc<Mutex<VaultController>>,
    ) -> Result<(), LadonError> {
        self.cancel_active_run();
        let _run_guard = self
            .run_gate
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?;
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
        let _run_guard = match self.run_gate.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(false),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err(LadonError::ProcessFailure);
            }
        };
        Ok(controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?
            .auto_lock_if_idle())
    }
}

impl Drop for LocalBrokerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.cancel_active_run_and_wait();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct AgentBroker {
    controller: Arc<Mutex<VaultController>>,
    supervisor: Supervisor,
    cancellation: Arc<Mutex<Option<RunCancellation>>>,
    run_gate: Arc<Mutex<()>>,
    shutting_down: Arc<AtomicBool>,
}

impl AgentBroker {
    fn new(
        controller: Arc<Mutex<VaultController>>,
        cancellation: Arc<Mutex<Option<RunCancellation>>>,
        run_gate: Arc<Mutex<()>>,
        shutting_down: Arc<AtomicBool>,
    ) -> Self {
        Self {
            controller,
            supervisor: Supervisor::new(),
            cancellation,
            run_gate,
            shutting_down,
        }
    }

    fn handle(&self, request: RpcRequest, cancellation: RunCancellation) -> RpcResponse {
        let request_id = request.request_id;
        match self.handle_method(request.method, cancellation) {
            Ok(result) => RpcResponse::success(request_id, result),
            Err(error) => RpcResponse::error(request_id, error),
        }
    }

    fn handle_method(
        &self,
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
                self.cancel_active_run();
                let _run_guard = self
                    .run_gate
                    .lock()
                    .map_err(|_| LadonError::ProcessFailure)?;
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
                let _run_guard = self.run_gate.try_lock().map_err(|error| match error {
                    std::sync::TryLockError::WouldBlock => LadonError::Busy,
                    std::sync::TryLockError::Poisoned(_) => LadonError::ProcessFailure,
                })?;
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
                self.set_cancellation(Some(cancellation.clone()))?;
                let result = self.supervisor.run(validated, cancellation, |bindings| {
                    self.controller()?.resolve_bindings(bindings)
                });
                if let Ok(mut controller) = self.controller.lock() {
                    controller.record_secret_activity();
                }
                self.set_cancellation(None)?;
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
        }
    }

    fn controller(&self) -> Result<std::sync::MutexGuard<'_, VaultController>, LadonError> {
        self.controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)
    }

    fn set_cancellation(&self, cancellation: Option<RunCancellation>) -> Result<(), LadonError> {
        *self
            .cancellation
            .lock()
            .map_err(|_| LadonError::ProcessFailure)? = cancellation;
        Ok(())
    }

    fn cancel_active_run(&self) {
        if let Ok(cancellation) = self.cancellation.lock() {
            if let Some(cancellation) = cancellation.as_ref() {
                cancellation.cancel();
            }
        }
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
