use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TryRecvError},
    },
    thread,
    time::Duration,
};

use ladon_core::{
    LadonError, RpcMethod, RpcRequest, RpcResponse, RpcResult, RunCaller, RunRequest,
    SecretFieldSummary, SecretId, SecretSummary, validate_run_request,
};
use uuid::Uuid;

use crate::{
    AppAccessState, ApprovalCoordinator, EditSecretDraft, LocalServer, PendingApproval,
    RunCancellation, RunTermination, Supervisor, VaultController, VaultUiPhase,
    default_endpoint_path,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AgentGrantView {
    client_session_id: Uuid,
    client_label: String,
    secret_id: SecretId,
    secret_name: String,
    remaining: Duration,
    running: bool,
}

impl AgentGrantView {
    pub(crate) const fn client_session_id(&self) -> Uuid {
        self.client_session_id
    }

    pub(crate) fn client_label(&self) -> &str {
        &self.client_label
    }

    pub(crate) const fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    pub(crate) fn secret_name(&self) -> &str {
        &self.secret_name
    }

    pub(crate) const fn remaining(&self) -> Duration {
        self.remaining
    }

    pub(crate) const fn running(&self) -> bool {
        self.running
    }
}

#[derive(Default)]
struct RunCoordinator {
    state: Mutex<RunCoordinatorState>,
    changed: Condvar,
}

#[derive(Default)]
struct RunCoordinatorState {
    active: Option<ActiveRun>,
    block_new: bool,
}

struct ActiveRun {
    cancellation: RunCancellation,
    client_session_id: Uuid,
    secret_ids: Option<Vec<SecretId>>,
    running: bool,
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

pub(crate) struct AppLockAttempt {
    epoch: u64,
    result: Receiver<Result<(), LadonError>>,
}

impl AppLockAttempt {
    pub(crate) const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn try_result(&self) -> Option<Result<(), LadonError>> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(LadonError::ProcessFailure)),
        }
    }
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
    fn try_start(
        self: &Arc<Self>,
        cancellation: RunCancellation,
        client_session_id: Uuid,
    ) -> Result<RunLease, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        if state.block_new || state.active.is_some() {
            return Err(LadonError::Busy);
        }
        state.active = Some(ActiveRun {
            cancellation,
            client_session_id,
            secret_ids: None,
            running: false,
        });
        Ok(RunLease {
            coordinator: Arc::clone(self),
        })
    }

    fn cancel_active(&self) {
        if let Ok(state) = self.state.lock() {
            if let Some(active) = state.active.as_ref() {
                active.cancellation.cancel();
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
        if let Some(active) = state.active.as_ref() {
            active.cancellation.cancel();
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

    fn running_pairs(&self) -> Result<HashSet<(Uuid, SecretId)>, LadonError> {
        let state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        Ok(state
            .active
            .as_ref()
            .filter(|active| active.running)
            .into_iter()
            .flat_map(|active| {
                active
                    .secret_ids
                    .iter()
                    .flatten()
                    .map(|id| (active.client_session_id, *id))
            })
            .collect())
    }

    fn block_for_revoke(
        self: &Arc<Self>,
        client_session_id: Uuid,
        secret_id: SecretId,
    ) -> Result<RunBlock, LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        while state.block_new {
            state = self
                .changed
                .wait(state)
                .map_err(|_| LadonError::ProcessFailure)?;
        }
        state.block_new = true;
        let matches = state.active.as_ref().is_some_and(|active| {
            active.client_session_id == client_session_id
                && active
                    .secret_ids
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&secret_id))
        });
        if matches {
            if let Some(active) = &state.active {
                active.cancellation.cancel();
            }
            // Waiting releases the mutex so the worker can finish cleanup and drop its lease.
            while state.active.is_some() {
                state = self
                    .changed
                    .wait(state)
                    .map_err(|_| LadonError::ProcessFailure)?;
            }
        }
        Ok(RunBlock {
            coordinator: Arc::clone(self),
        })
    }
}

impl RunLease {
    fn set_secret_context(&self, secret_ids: Vec<SecretId>) -> Result<(), LadonError> {
        let mut state = self
            .coordinator
            .state
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?;
        let active = state.active.as_mut().ok_or(LadonError::InvalidRequest)?;
        if active.secret_ids.is_some() {
            return Err(LadonError::InvalidRequest);
        }
        active.secret_ids = Some(secret_ids);
        Ok(())
    }

    fn mark_running(&self) -> Result<(), LadonError> {
        let mut state = self
            .coordinator
            .state
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?;
        let active = state.active.as_mut().ok_or(LadonError::InvalidRequest)?;
        if active.secret_ids.is_none() {
            return Err(LadonError::InvalidRequest);
        }
        if active.cancellation.is_cancelled() {
            return Err(LadonError::ApprovalCancelled);
        }
        active.running = true;
        Ok(())
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
    let controller_locked = match controller.lock() {
        Ok(mut controller) => {
            controller.lock();
            true
        }
        Err(_) if first_error.is_none() => {
            first_error = Some(LadonError::ProcessFailure);
            false
        }
        Err(_) => false,
    };
    if controller_locked
        && let Err(error) = approval.reset_after_vault_lock()
        && first_error.is_none()
    {
        first_error = Some(error);
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

    pub(crate) fn begin_app_lock(&self) -> Result<AppLockAttempt, LadonError> {
        let ui_locks = self.ui_locks.as_ref().ok_or(LadonError::InvalidRequest)?;
        let local_operation = ui_locks
            .try_begin_local_operation()?
            .ok_or(LadonError::Busy)?;
        let epoch = self.approval.begin_app_lock()?;
        self.coordinator.cancel_active();

        let coordinator = Arc::clone(&self.coordinator);
        let approval = Arc::clone(&self.approval);
        let (result_tx, result) = mpsc::channel();
        thread::Builder::new()
            .name("ladon-app-lock".to_owned())
            .spawn(move || {
                let result = (|| {
                    let _block = coordinator.block_new_runs()?;
                    approval.finish_app_lock(epoch)?;
                    drop(local_operation);
                    Ok(())
                })();
                let _ = result_tx.send(result);
            })
            .map_err(|_| LadonError::ProcessFailure)?;

        Ok(AppLockAttempt { epoch, result })
    }

    pub(crate) fn unlock_app(&self, epoch: u64) -> Result<(), LadonError> {
        self.approval.unlock_app(epoch)
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
            self.approval.reset_after_vault_lock()?;
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

    pub(crate) fn agent_grants(
        &self,
        controller: &Arc<Mutex<VaultController>>,
    ) -> Result<Vec<AgentGrantView>, LadonError> {
        // Each snapshot releases its mutex before the next one is acquired.
        let grants = self.approval.active_grants()?;
        let running = self.coordinator.running_pairs()?;
        let secret_names: HashMap<_, _> = controller
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?
            .secrets()
            .into_iter()
            .map(|secret| (secret.id, secret.name))
            .collect();
        let mut views: Vec<_> = grants
            .into_iter()
            .filter_map(|grant| {
                let secret_name = secret_names.get(&grant.secret_id())?.clone();
                Some(AgentGrantView {
                    client_session_id: grant.client_session_id(),
                    client_label: grant.client_label().to_owned(),
                    secret_id: grant.secret_id(),
                    secret_name,
                    remaining: grant.remaining(),
                    running: running.contains(&(grant.client_session_id(), grant.secret_id())),
                })
            })
            .collect();
        views.sort_by(|left, right| {
            left.client_label
                .cmp(&right.client_label)
                .then_with(|| left.client_session_id.cmp(&right.client_session_id))
                .then_with(|| left.secret_name.cmp(&right.secret_name))
        });
        Ok(views)
    }

    pub(crate) fn revoke_grant(
        &self,
        client_session_id: Uuid,
        secret_id: SecretId,
    ) -> Result<(), LadonError> {
        let _local_operation = self
            .ui_locks
            .as_ref()
            .map(|ui_locks| {
                ui_locks
                    .try_begin_local_operation()?
                    .ok_or(LadonError::Busy)
            })
            .transpose()?;
        let _block = self
            .coordinator
            .block_for_revoke(client_session_id, secret_id)?;
        self.approval.revoke_pair(client_session_id, secret_id)?;
        Ok(())
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
        if let Err(error) = self
            .approval
            .observe_client(client_session_id, &client_label)
            && !matches!(&method, RpcMethod::Lock)
        {
            return Err(error);
        }
        // Hard lock must still attempt vault cleanup when approval coordination has failed.
        match method {
            RpcMethod::Status => {
                if self.approval.app_access_state()? != AppAccessState::Active {
                    return Ok(RpcResult::Status {
                        state: "locked".to_owned(),
                        idle_remaining_ms: None,
                    });
                }
                let controller = self.controller()?;
                Ok(RpcResult::Status {
                    state: phase_name(controller.phase()).to_owned(),
                    idle_remaining_ms: controller.remaining_unlocked().map(duration_millis),
                })
            }
            RpcMethod::List => {
                self.approval.require_app_active()?;
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
                self.approval.require_app_active()?;
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
                let run_lease = self
                    .coordinator
                    .try_start(cancellation.clone(), client_session_id)?;
                self.approval.require_app_active()?;
                if self.shutting_down.load(Ordering::Acquire) {
                    return Err(LadonError::EndpointUnavailable);
                }
                if !validated.bindings().is_empty() {
                    let approval_plan = self.controller()?.approval_plan(validated.bindings())?;
                    run_lease.set_secret_context(approval_plan.binding_secret_ids.clone())?;
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
                    run_lease.mark_running()?;
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
                run_lease.set_secret_context(Vec::new())?;
                run_lease.mark_running()?;
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
    use crate::{AddSecretDraft, ApprovalSecret, LocalClient, SensitiveText};
    use ladon_core::{BindingTarget, SecretBindingRequest};
    use std::time::Instant;

    #[test]
    fn running_snapshot_marks_only_bound_secret_pairs() {
        let coordinator = Arc::new(RunCoordinator::default());
        let client = Uuid::new_v4();
        let first = SecretId::new();
        let second = SecretId::new();
        let lease = coordinator
            .try_start(RunCancellation::new(), client)
            .unwrap();
        assert!(coordinator.running_pairs().unwrap().is_empty());
        lease.set_secret_context(vec![first]).unwrap();
        assert!(coordinator.running_pairs().unwrap().is_empty());
        lease.mark_running().unwrap();

        let running = coordinator.running_pairs().unwrap();
        assert_eq!(running.len(), 1);
        assert!(running.contains(&(client, first)));
        assert!(!running.contains(&(client, second)));
    }

    #[test]
    fn targeted_block_cancels_same_client_pre_context_but_not_another_client() {
        let coordinator = Arc::new(RunCoordinator::default());
        let first_client = Uuid::new_v4();
        let second_client = Uuid::new_v4();
        let secret = SecretId::new();
        let cancellation = RunCancellation::new();
        let lease = coordinator
            .try_start(cancellation.clone(), first_client)
            .unwrap();
        let (finished_tx, finished_rx) = mpsc::channel();
        let blocking = {
            let coordinator = Arc::clone(&coordinator);
            thread::spawn(move || {
                let block = coordinator.block_for_revoke(first_client, secret).unwrap();
                finished_tx.send(()).unwrap();
                drop(block);
            })
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancellation.is_cancelled() {
            assert!(Instant::now() < deadline, "targeted revoke did not cancel");
            thread::yield_now();
        }
        assert!(matches!(
            coordinator.try_start(RunCancellation::new(), second_client),
            Err(LadonError::Busy)
        ));
        assert!(finished_rx.recv_timeout(Duration::from_millis(30)).is_err());
        drop(lease);
        finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        blocking.join().unwrap();

        let other_cancellation = RunCancellation::new();
        let other_lease = coordinator
            .try_start(other_cancellation.clone(), second_client)
            .unwrap();
        let block = coordinator.block_for_revoke(first_client, secret).unwrap();
        assert!(!other_cancellation.is_cancelled());
        drop(block);
        drop(other_lease);
    }

    #[test]
    fn targeted_block_preserves_a_known_non_matching_secret_and_drop_clears_metadata() {
        let coordinator = Arc::new(RunCoordinator::default());
        let client = Uuid::new_v4();
        let bound = SecretId::new();
        let requested = SecretId::new();
        let cancellation = RunCancellation::new();
        let lease = coordinator.try_start(cancellation.clone(), client).unwrap();
        lease.set_secret_context(vec![bound]).unwrap();
        lease.mark_running().unwrap();

        let block = coordinator.block_for_revoke(client, requested).unwrap();
        assert!(!cancellation.is_cancelled());
        drop(block);
        drop(lease);
        assert!(coordinator.running_pairs().unwrap().is_empty());
    }

    #[test]
    fn targeted_block_waits_for_a_matching_running_lease_and_holds_admission() {
        let coordinator = Arc::new(RunCoordinator::default());
        let client = Uuid::new_v4();
        let secret = SecretId::new();
        let cancellation = RunCancellation::new();
        let lease = coordinator.try_start(cancellation.clone(), client).unwrap();
        lease.set_secret_context(vec![secret]).unwrap();
        lease.mark_running().unwrap();
        let (blocked_tx, blocked_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let blocking = {
            let coordinator = Arc::clone(&coordinator);
            thread::spawn(move || {
                let block = coordinator.block_for_revoke(client, secret).unwrap();
                blocked_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                drop(block);
            })
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancellation.is_cancelled() {
            assert!(Instant::now() < deadline, "running revoke did not cancel");
            thread::yield_now();
        }
        assert!(blocked_rx.recv_timeout(Duration::from_millis(30)).is_err());
        drop(lease);
        blocked_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(coordinator.running_pairs().unwrap().is_empty());
        assert!(matches!(
            coordinator.try_start(RunCancellation::new(), client),
            Err(LadonError::Busy)
        ));
        release_tx.send(()).unwrap();
        blocking.join().unwrap();
        assert!(
            coordinator
                .try_start(RunCancellation::new(), client)
                .is_ok()
        );
    }

    #[test]
    fn secret_context_is_immutable_and_required_before_running() {
        let coordinator = Arc::new(RunCoordinator::default());
        let client = Uuid::new_v4();
        let lease = coordinator
            .try_start(RunCancellation::new(), client)
            .unwrap();
        assert_eq!(lease.mark_running(), Err(LadonError::InvalidRequest));
        lease.set_secret_context(Vec::new()).unwrap();
        assert_eq!(
            lease.set_secret_context(vec![SecretId::new()]),
            Err(LadonError::InvalidRequest)
        );
        lease.mark_running().unwrap();
        assert!(coordinator.running_pairs().unwrap().is_empty());
        let block = coordinator
            .block_for_revoke(client, SecretId::new())
            .unwrap();
        drop(block);
        drop(lease);
    }

    fn desktop_handle(
        coordinator: Arc<RunCoordinator>,
        approval: Arc<ApprovalCoordinator>,
    ) -> LocalBrokerHandle {
        LocalBrokerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            coordinator,
            approval,
            ui_locks: Some(Arc::new(UiLockCoordinator::new(Arc::new(|| {})))),
            thread: None,
        }
    }

    fn wait_for_app_lock_result(attempt: &AppLockAttempt) -> Result<(), LadonError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(result) = attempt.try_result() {
                return result;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "app-lock worker did not finish"
            );
            thread::yield_now();
        }
    }

    fn request_for(client_session_id: Uuid, method: RpcMethod) -> RpcRequest {
        RpcRequest {
            version: 2,
            request_id: Uuid::new_v4(),
            client_session_id,
            client_label: "app-lock test".to_owned(),
            method,
        }
    }

    fn secret_run(working_directory: &Path) -> RpcMethod {
        RpcMethod::Run {
            executable: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "printf run-finished".to_owned()],
            working_directory: working_directory.to_string_lossy().into_owned(),
            bindings: vec![SecretBindingRequest {
                secret_ref: "app-lock-token".to_owned(),
                field: "value".to_owned(),
                target: BindingTarget::Environment {
                    name: "TOKEN".to_owned(),
                },
            }],
            timeout_ms: 5_000,
            output_limit_bytes: 64 * 1024,
        }
    }

    fn plain_run(working_directory: &Path) -> RpcMethod {
        RpcMethod::Run {
            executable: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "printf plain-run".to_owned()],
            working_directory: working_directory.to_string_lossy().into_owned(),
            bindings: Vec::new(),
            timeout_ms: 5_000,
            output_limit_bytes: 64 * 1024,
        }
    }

    fn wait_for_pending_approval(handle: &LocalBrokerHandle) -> PendingApproval {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(pending) = handle.pending_approval().unwrap() {
                return pending;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "approval never became pending"
            );
            thread::yield_now();
        }
    }

    fn grant_access(
        handle: &LocalBrokerHandle,
        vault_session_id: Uuid,
        client: Uuid,
        label: &str,
        secrets: Vec<ApprovalSecret>,
    ) {
        let request = PendingApproval::new(
            vault_session_id,
            client,
            label,
            secrets,
            "/usr/bin/true",
            std::iter::empty::<&str>(),
            "/tmp",
        );
        let approval = Arc::clone(&handle.approval);
        let (finished_tx, finished_rx) = mpsc::channel();
        let waiting = thread::spawn(move || {
            finished_tx
                .send(approval.authorize(request, &RunCancellation::new()))
                .unwrap();
        });
        let pending = wait_for_pending_approval(handle);
        handle.approve(pending.id()).unwrap();
        finished_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        waiting.join().unwrap();
    }

    #[test]
    fn broker_snapshot_marks_running_and_exact_revoke_preserves_the_other_pair() {
        let directory = tempfile::tempdir().unwrap();
        let passphrase = SensitiveText::from("correct horse");
        let mut vault = VaultController::new(directory.path().join("vault.ladon"));
        vault.create(&passphrase, &passphrase).unwrap();
        let mut first = AddSecretDraft::new();
        first.set_name("first");
        first.fields_mut()[0]
            .value_mut()
            .push_str("fake-first-value");
        let first_id = vault.add_secret(&mut first).unwrap();
        let mut second = AddSecretDraft::new();
        second.set_name("second");
        second.fields_mut()[0]
            .value_mut()
            .push_str("fake-second-value");
        let second_id = vault.add_secret(&mut second).unwrap();
        let vault_session_id = vault.session_id().unwrap();
        let controller = Arc::new(Mutex::new(vault));
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let handle = desktop_handle(Arc::clone(&coordinator), Arc::clone(&approval));
        let client = Uuid::from_u128(2);
        let other_client = Uuid::from_u128(1);
        grant_access(
            &handle,
            vault_session_id,
            client,
            "Codex — deploy",
            vec![
                ApprovalSecret::new(second_id, "old-second-name", ["value"]),
                ApprovalSecret::new(first_id, "old-first-name", ["value"]),
                ApprovalSecret::new(SecretId::new(), "missing-secret", ["value"]),
            ],
        );
        grant_access(
            &handle,
            vault_session_id,
            other_client,
            "Codex — deploy",
            vec![ApprovalSecret::new(first_id, "first", ["value"])],
        );

        let cancellation = RunCancellation::new();
        let lease = coordinator.try_start(cancellation.clone(), client).unwrap();
        lease.set_secret_context(vec![first_id]).unwrap();
        lease.mark_running().unwrap();
        let grants = handle.agent_grants(&controller).unwrap();
        assert_eq!(grants.len(), 3);
        assert_eq!(grants[0].client_session_id(), other_client);
        assert_eq!(grants[1].secret_name(), "first");
        assert_eq!(grants[2].secret_name(), "second");
        assert!(!grants[0].running());
        assert!(grants[1].running());
        assert!(!grants[2].running());
        assert!(
            grants
                .iter()
                .all(|grant| grant.remaining() > Duration::ZERO)
        );
        assert!(!format!("{grants:?}").contains("fake-first-value"));
        assert!(!format!("{grants:?}").contains("fake-second-value"));

        let broker = AgentBroker::new(
            Arc::clone(&controller),
            Arc::clone(&coordinator),
            Arc::clone(&approval),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        for (method, label) in [(RpcMethod::Status, "A-status"), (RpcMethod::List, "B-list")] {
            broker
                .handle_method(client, label.to_owned(), method, RunCancellation::new())
                .unwrap();
            let refreshed = handle.agent_grants(&controller).unwrap();
            assert_eq!(refreshed.len(), 3);
            assert_eq!(refreshed[0].client_session_id(), client);
            assert_eq!(refreshed[0].client_label(), label);
            assert!(refreshed[0].remaining() <= grants[1].remaining());
            assert_eq!(refreshed[2].client_label(), "Codex — deploy");
        }

        handle.revoke_grant(client, second_id).unwrap();
        assert!(!cancellation.is_cancelled());
        let grants = handle.agent_grants(&controller).unwrap();
        assert_eq!(grants.len(), 2);
        assert!(grants.iter().all(|grant| grant.secret_id() == first_id));
        drop(lease);
        handle.revoke_grant(client, first_id).unwrap();
        let grants = handle.agent_grants(&controller).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].client_session_id(), other_client);
        assert!(!grants[0].running());
        handle.revoke_grant(other_client, first_id).unwrap();
        assert!(handle.agent_grants(&controller).unwrap().is_empty());
    }

    #[test]
    fn targeted_revoke_does_not_mutate_grants_when_an_external_lock_owns_the_transition() {
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let handle = desktop_handle(coordinator, Arc::clone(&approval));
        let client = Uuid::new_v4();
        let secret = SecretId::new();
        grant_access(
            &handle,
            Uuid::new_v4(),
            client,
            "test client",
            vec![ApprovalSecret::new(secret, "secret", ["value"])],
        );
        handle.ui_locks.as_ref().unwrap().begin_request().unwrap();
        assert_eq!(handle.revoke_grant(client, secret), Err(LadonError::Busy));
        assert_eq!(approval.active_grants().unwrap().len(), 1);
    }

    #[test]
    fn revoking_a_pre_context_existing_grant_prevents_child_launch() {
        let directory = tempfile::tempdir().unwrap();
        let passphrase = SensitiveText::from("correct horse");
        let mut vault = VaultController::new(directory.path().join("vault.ladon"));
        vault.create(&passphrase, &passphrase).unwrap();
        let mut secret = AddSecretDraft::new();
        secret.set_name("app-lock-token");
        secret.fields_mut()[0].value_mut().push_str("fake-secret");
        let secret_id = vault.add_secret(&mut secret).unwrap();
        let vault_session_id = vault.session_id().unwrap();
        let controller = Arc::new(Mutex::new(vault));
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let handle = Arc::new(desktop_handle(
            Arc::clone(&coordinator),
            Arc::clone(&approval),
        ));
        let client = Uuid::new_v4();
        grant_access(
            &handle,
            vault_session_id,
            client,
            "test client",
            vec![ApprovalSecret::new(secret_id, "app-lock-token", ["value"])],
        );
        let broker = AgentBroker::new(
            Arc::clone(&controller),
            Arc::clone(&coordinator),
            Arc::clone(&approval),
            Arc::new(AtomicBool::new(false)),
            None,
        );
        let mut method = secret_run(directory.path());
        let RpcMethod::Run { arguments, .. } = &mut method else {
            unreachable!("secret_run builds a run request");
        };
        *arguments = vec!["-c".to_owned(), "printf started > child-started".to_owned()];
        let marker = directory.path().join("child-started");
        let cancellation = RunCancellation::new();
        let run_cancellation = cancellation.clone();
        // Prevent approval_plan from attaching secret context after the reservation is made.
        let preparation_pause = controller.lock().unwrap();
        let (run_tx, run_rx) = mpsc::channel();
        let running = thread::spawn(move || {
            run_tx
                .send(broker.handle_method(
                    client,
                    "test client".to_owned(),
                    method,
                    run_cancellation,
                ))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(active) = coordinator.state.lock().unwrap().active.as_ref() {
                assert_eq!(active.client_session_id, client);
                assert!(active.secret_ids.is_none());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "run was not reserved before preparation"
            );
            thread::yield_now();
        }
        let revoking_handle = Arc::clone(&handle);
        let (revoke_tx, revoke_rx) = mpsc::channel();
        let revoking = thread::spawn(move || {
            revoke_tx
                .send(revoking_handle.revoke_grant(client, secret_id))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancellation.is_cancelled() {
            assert!(
                Instant::now() < deadline,
                "targeted revoke did not cancel preparation"
            );
            thread::yield_now();
        }
        assert!(revoke_rx.recv_timeout(Duration::from_millis(30)).is_err());
        assert_eq!(approval.active_grants().unwrap().len(), 1);
        drop(preparation_pause);

        let result = run_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        revoke_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        running.join().unwrap();
        revoking.join().unwrap();
        assert!(!marker.exists(), "cancelled preparation launched a child");
        assert_eq!(result, Err(LadonError::ApprovalCancelled));
        assert!(approval.active_grants().unwrap().is_empty());
        assert!(coordinator.running_pairs().unwrap().is_empty());
    }

    #[test]
    fn client_observation_failure_does_not_skip_the_vault_lock_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let passphrase = SensitiveText::from("correct horse");
        let mut vault = VaultController::new(directory.path().join("vault.ladon"));
        vault.create(&passphrase, &passphrase).unwrap();
        let controller = Arc::new(Mutex::new(vault));
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let poisoned = Arc::clone(&approval);
        assert!(
            thread::spawn(move || {
                let _ = poisoned.coordinate_secret_mutation(
                    SecretId::new(),
                    || -> Result<(), LadonError> { panic!("poison approval coordinator") },
                    |()| Ok(()),
                );
            })
            .join()
            .is_err()
        );
        let broker = AgentBroker::new(
            Arc::clone(&controller),
            Arc::new(RunCoordinator::default()),
            approval,
            Arc::new(AtomicBool::new(false)),
            None,
        );

        assert_eq!(
            broker.handle_method(
                Uuid::new_v4(),
                "test client".to_owned(),
                RpcMethod::Lock,
                RunCancellation::new(),
            ),
            Err(LadonError::ProcessFailure)
        );
        assert_eq!(controller.lock().unwrap().phase(), VaultUiPhase::Locked);
    }

    #[test]
    fn app_lock_cancels_an_established_run_and_completes_after_its_lease_drops() {
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let handle = desktop_handle(Arc::clone(&coordinator), Arc::clone(&approval));
        let cancellation = RunCancellation::new();
        let (established_tx, established_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let run_coordinator = Arc::clone(&coordinator);
        let run_cancellation = cancellation.clone();
        let run = thread::spawn(move || {
            let run_lease = run_coordinator
                .try_start(run_cancellation, Uuid::new_v4())
                .unwrap();
            established_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(run_lease);
        });
        established_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let attempt = handle.begin_app_lock().unwrap();
        assert!(cancellation.is_cancelled());
        assert!(attempt.try_result().is_none());
        release_tx.send(()).unwrap();
        run.join().unwrap();
        wait_for_app_lock_result(&attempt).unwrap();
        assert_eq!(
            handle.approval.app_access_state().unwrap(),
            AppAccessState::Locked {
                epoch: attempt.epoch()
            }
        );
    }

    #[test]
    fn app_lock_unlock_accepts_only_the_completed_epoch() {
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let handle = desktop_handle(coordinator, Arc::clone(&approval));

        let attempt = handle.begin_app_lock().unwrap();
        wait_for_app_lock_result(&attempt).unwrap();
        assert_eq!(
            handle.unlock_app(attempt.epoch().wrapping_add(1)),
            Err(LadonError::InvalidRequest)
        );
        handle.unlock_app(attempt.epoch()).unwrap();
        assert_eq!(approval.app_access_state().unwrap(), AppAccessState::Active);
    }

    #[test]
    fn app_lock_attempt_maps_a_disconnected_worker_to_process_failure() {
        let (result_tx, result) = mpsc::channel();
        drop(result_tx);
        let attempt = AppLockAttempt { epoch: 1, result };

        assert_eq!(attempt.try_result(), Some(Err(LadonError::ProcessFailure)));
    }

    #[test]
    fn app_lock_returns_busy_while_an_external_hard_lock_owns_the_transition() {
        let coordinator = Arc::new(RunCoordinator::default());
        let approval = Arc::new(ApprovalCoordinator::session_defaults());
        let ui_locks = Arc::new(UiLockCoordinator::new(Arc::new(|| {})));
        let handle = LocalBrokerHandle {
            stop: Arc::new(AtomicBool::new(false)),
            coordinator,
            approval: Arc::clone(&approval),
            ui_locks: Some(Arc::clone(&ui_locks)),
            thread: None,
        };
        ui_locks.begin_request().unwrap();

        assert!(matches!(handle.begin_app_lock(), Err(LadonError::Busy)));
        assert_eq!(approval.app_access_state().unwrap(), AppAccessState::Active);
    }

    #[test]
    fn app_lock_fails_closed_over_the_socket_and_keeps_hard_lock_callable() {
        let directory = tempfile::tempdir().unwrap();
        let passphrase = SensitiveText::from("correct horse");
        let mut initial = VaultController::new(directory.path().join("vault.ladon"));
        initial.create(&passphrase, &passphrase).unwrap();
        let mut secret = AddSecretDraft::new();
        secret.set_name("app-lock-token");
        secret.fields_mut()[0]
            .value_mut()
            .push_str("fake-app-lock-secret");
        initial.add_secret(&mut secret).unwrap();
        let controller = Arc::new(Mutex::new(initial));
        let endpoint = directory.path().join("broker.sock");
        let handle = LocalBrokerHandle::start_at_for_desktop(
            Arc::clone(&controller),
            &endpoint,
            Arc::new(|| {}),
        )
        .unwrap();
        let client = LocalClient::new(&endpoint);
        let client_session_id = Uuid::new_v4();

        let first_client = client.clone();
        let first_run = secret_run(directory.path());
        let first =
            thread::spawn(move || first_client.call(&request_for(client_session_id, first_run)));
        let pending = wait_for_pending_approval(&handle);
        handle.approve(pending.id()).unwrap();
        assert!(matches!(
            first.join().unwrap().unwrap().result(),
            Some(RpcResult::Run { .. })
        ));

        let attempt = handle.begin_app_lock().unwrap();
        wait_for_app_lock_result(&attempt).unwrap();
        assert_eq!(controller.lock().unwrap().phase(), VaultUiPhase::Unlocked);

        let status = client
            .call(&request_for(client_session_id, RpcMethod::Status))
            .unwrap();
        assert!(matches!(
            status.result(),
            Some(RpcResult::Status {
                state,
                idle_remaining_ms: None
            }) if state == "locked"
        ));
        let list = client
            .call(&request_for(client_session_id, RpcMethod::List))
            .unwrap();
        assert_eq!(
            list.error_details(),
            Some(("vault_locked", "vault is locked"))
        );
        let run = client
            .call(&request_for(client_session_id, plain_run(directory.path())))
            .unwrap();
        assert_eq!(
            run.error_details(),
            Some(("vault_locked", "vault is locked"))
        );

        handle.unlock_app(attempt.epoch()).unwrap();
        let list = client
            .call(&request_for(client_session_id, RpcMethod::List))
            .unwrap();
        assert!(matches!(list.result(), Some(RpcResult::List { .. })));

        let retry_client = client.clone();
        let retry_method = secret_run(directory.path());
        let retry =
            thread::spawn(move || retry_client.call(&request_for(client_session_id, retry_method)));
        let pending = wait_for_pending_approval(&handle);
        handle.deny(pending.id()).unwrap();
        let denied = retry.join().unwrap().unwrap();
        assert_eq!(
            denied.error_details(),
            Some(("approval_denied", "agent request was denied"))
        );

        let second_attempt = handle.begin_app_lock().unwrap();
        wait_for_app_lock_result(&second_attempt).unwrap();
        let lock_client = client.clone();
        let locking = thread::spawn(move || {
            lock_client.call(&request_for(client_session_id, RpcMethod::Lock))
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let request_id = loop {
            if let Some(request_id) = handle.pending_external_lock().unwrap() {
                break request_id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "hard-lock request never reached the UI barrier"
            );
            thread::yield_now();
        };
        assert_eq!(controller.lock().unwrap().phase(), VaultUiPhase::Locked);
        handle.acknowledge_external_lock(request_id).unwrap();
        assert!(matches!(
            locking.join().unwrap().unwrap().result(),
            Some(RpcResult::Locked)
        ));
        assert_eq!(
            handle.unlock_app(second_attempt.epoch()),
            Err(LadonError::InvalidRequest)
        );

        let debug = format!("{status:?}{list:?}{run:?}{denied:?}");
        assert!(!debug.contains("fake-app-lock-secret"));
    }

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
            .try_start(RunCancellation::new(), Uuid::new_v4())
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
        let lease = coordinator
            .try_start(active.clone(), Uuid::new_v4())
            .unwrap();
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
            coordinator.try_start(RunCancellation::new(), Uuid::new_v4()),
            Err(LadonError::Busy)
        ));
        release_tx.send(()).unwrap();
        waiter.join().unwrap();
        assert!(
            coordinator
                .try_start(RunCancellation::new(), Uuid::new_v4())
                .is_ok()
        );
    }
}
