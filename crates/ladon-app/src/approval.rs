use std::{
    collections::HashSet,
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use ladon_core::{GrantStore, LadonError, MonotonicClock, SecretId, SystemMonotonicClock};
use uuid::Uuid;

use crate::RunCancellation;

const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(20);
pub const DEFAULT_GRANT_LIFETIME: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(2 * 60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalSecret {
    id: SecretId,
    name: String,
    fields: Vec<String>,
}

impl ApprovalSecret {
    #[must_use]
    pub fn new(
        id: SecretId,
        name: impl Into<String>,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            fields: fields.into_iter().map(Into::into).collect(),
        }
    }

    #[must_use]
    pub const fn id(&self) -> SecretId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn fields(&self) -> &[String] {
        &self.fields
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApproval {
    id: Uuid,
    vault_session_id: Uuid,
    client_session_id: Uuid,
    client_label: String,
    secrets: Vec<ApprovalSecret>,
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
}

impl PendingApproval {
    #[must_use]
    pub fn new(
        vault_session_id: Uuid,
        client_session_id: Uuid,
        client_label: impl Into<String>,
        secrets: Vec<ApprovalSecret>,
        executable: impl Into<String>,
        arguments: impl IntoIterator<Item = impl Into<String>>,
        working_directory: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            vault_session_id,
            client_session_id,
            client_label: client_label.into(),
            secrets,
            executable: executable.into(),
            arguments: arguments.into_iter().map(Into::into).collect(),
            working_directory: working_directory.into(),
        }
    }

    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    #[must_use]
    pub const fn client_session_id(&self) -> Uuid {
        self.client_session_id
    }

    #[must_use]
    pub const fn vault_session_id(&self) -> Uuid {
        self.vault_session_id
    }

    #[must_use]
    pub fn client_label(&self) -> &str {
        &self.client_label
    }

    #[must_use]
    pub fn secrets(&self) -> &[ApprovalSecret] {
        &self.secrets
    }

    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &str {
        &self.working_directory
    }
}

pub struct ApprovalCoordinator<C = SystemMonotonicClock> {
    state: Mutex<ApprovalState<C>>,
    changed: Condvar,
    approval_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppAccessState {
    Active,
    Locking { epoch: u64 },
    Locked { epoch: u64 },
}

struct ApprovalState<C> {
    grants: GrantStore<C>,
    vault_session_id: Option<Uuid>,
    pending: Option<PendingState>,
    app_access: AppAccessState,
    lock_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantTicket {
    vault_session_id: Uuid,
    client_session_id: Uuid,
    secret_ids: Vec<SecretId>,
}

struct PendingState {
    request: PendingApproval,
    requested_secret_ids: Vec<SecretId>,
    decision: Option<ApprovalDecision>,
}

#[derive(Clone, Copy)]
enum ApprovalDecision {
    Approve,
    Deny,
    Cancel,
}

impl<C: MonotonicClock> ApprovalCoordinator<C> {
    #[must_use]
    pub fn new(clock: C, grant_lifetime: Duration, approval_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(ApprovalState {
                grants: GrantStore::new(clock, grant_lifetime),
                vault_session_id: None,
                pending: None,
                app_access: AppAccessState::Active,
                lock_epoch: 0,
            }),
            changed: Condvar::new(),
            approval_timeout,
        }
    }

    pub fn authorize(
        &self,
        mut request: PendingApproval,
        cancellation: &RunCancellation,
    ) -> Result<GrantTicket, LadonError> {
        let mut state = self.lock_state()?;
        if !is_app_active(&state) {
            return Err(LadonError::VaultLocked);
        }
        if state.pending.is_some() {
            return Err(LadonError::Busy);
        }

        if state.vault_session_id != Some(request.vault_session_id) {
            state.grants.revoke_all();
            state.vault_session_id = Some(request.vault_session_id);
        }
        let mut seen = HashSet::new();
        let ticket = GrantTicket {
            vault_session_id: request.vault_session_id,
            client_session_id: request.client_session_id,
            secret_ids: request
                .secrets
                .iter()
                .map(ApprovalSecret::id)
                .filter(|secret_id| seen.insert(*secret_id))
                .collect(),
        };

        let missing = state.grants.missing(
            request.client_session_id,
            request.secrets.iter().map(ApprovalSecret::id),
        );
        if missing.is_empty() {
            return Ok(ticket);
        }

        let missing: HashSet<_> = missing.into_iter().collect();
        request
            .secrets
            .retain(|secret| missing.contains(&secret.id()));
        let approval_id = request.id;
        state.pending = Some(PendingState {
            request,
            requested_secret_ids: ticket.secret_ids.clone(),
            decision: None,
        });
        self.changed.notify_all();

        let deadline = Instant::now() + self.approval_timeout;
        loop {
            if cancellation.is_cancelled() {
                clear_pending(&mut state, approval_id);
                self.changed.notify_all();
                return Err(LadonError::ApprovalCancelled);
            }

            if let Some(decision) = decision_for(&state, approval_id) {
                let pending = state.pending.take().ok_or(LadonError::ProcessFailure)?;
                match decision {
                    ApprovalDecision::Approve => {
                        let secret_ids = pending.request.secrets.iter().map(ApprovalSecret::id);
                        state
                            .grants
                            .grant(pending.request.client_session_id, secret_ids);
                        self.changed.notify_all();
                        return Ok(ticket);
                    }
                    ApprovalDecision::Deny => {
                        self.changed.notify_all();
                        return Err(LadonError::ApprovalDenied);
                    }
                    ApprovalDecision::Cancel => {
                        self.changed.notify_all();
                        return Err(LadonError::ApprovalCancelled);
                    }
                }
            }

            let now = Instant::now();
            if now >= deadline {
                clear_pending(&mut state, approval_id);
                self.changed.notify_all();
                return Err(LadonError::ApprovalTimeout);
            }
            let wait_for = CANCELLATION_POLL_INTERVAL.min(deadline.saturating_duration_since(now));
            let (next_state, _) = self
                .changed
                .wait_timeout(state, wait_for)
                .map_err(|_| LadonError::ProcessFailure)?;
            state = next_state;
        }
    }

    pub fn pending(&self) -> Result<Option<PendingApproval>, LadonError> {
        Ok(self
            .lock_state()?
            .pending
            .as_ref()
            .filter(|pending| pending.decision.is_none())
            .map(|pending| pending.request.clone()))
    }

    pub fn app_access_state(&self) -> Result<AppAccessState, LadonError> {
        Ok(self.lock_state()?.app_access)
    }

    pub fn require_app_active(&self) -> Result<(), LadonError> {
        let state = self.lock_state()?;
        if is_app_active(&state) {
            Ok(())
        } else {
            Err(LadonError::VaultLocked)
        }
    }

    pub fn begin_app_lock(&self) -> Result<u64, LadonError> {
        let mut state = self.lock_state()?;
        if !is_app_active(&state) {
            return Err(LadonError::Busy);
        }
        let epoch = state
            .lock_epoch
            .checked_add(1)
            .ok_or(LadonError::InvalidRequest)?;
        state.lock_epoch = epoch;
        state.app_access = AppAccessState::Locking { epoch };
        cancel_pending(&mut state);
        state.grants.revoke_all();
        self.changed.notify_all();
        Ok(epoch)
    }

    pub fn finish_app_lock(&self, epoch: u64) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        if state.app_access != (AppAccessState::Locking { epoch }) {
            return Err(LadonError::InvalidRequest);
        }
        state.app_access = AppAccessState::Locked { epoch };
        self.changed.notify_all();
        Ok(())
    }

    pub fn unlock_app(&self, epoch: u64) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        if state.app_access != (AppAccessState::Locked { epoch }) {
            return Err(LadonError::InvalidRequest);
        }
        state.app_access = AppAccessState::Active;
        self.changed.notify_all();
        Ok(())
    }

    pub fn reset_after_vault_lock(&self) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        state.lock_epoch = state
            .lock_epoch
            .checked_add(1)
            .ok_or(LadonError::InvalidRequest)?;
        state.app_access = AppAccessState::Active;
        cancel_pending(&mut state);
        state.grants.revoke_all();
        state.vault_session_id = None;
        self.changed.notify_all();
        Ok(())
    }

    pub fn approve(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::Approve)
    }

    pub fn deny(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::Deny)
    }

    pub fn cancel_pending(&self) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        if let Some(pending) = state.pending.as_mut() {
            pending.decision = Some(ApprovalDecision::Cancel);
            self.changed.notify_all();
        }
        Ok(())
    }

    pub fn revoke_all(&self) -> Result<(), LadonError> {
        self.lock_state()?.grants.revoke_all();
        Ok(())
    }

    pub fn coordinate_secret_mutation<P, T>(
        &self,
        secret_id: SecretId,
        prepare: impl FnOnce() -> Result<P, LadonError>,
        commit: impl FnOnce(P) -> Result<T, LadonError>,
    ) -> Result<T, LadonError> {
        let mut state = self.lock_state()?;
        let prepared = prepare()?;
        if let Some(pending) = state.pending.as_mut()
            && pending.requested_secret_ids.contains(&secret_id)
        {
            pending.decision = Some(ApprovalDecision::Cancel);
            self.changed.notify_all();
        }
        state.grants.revoke_secret(secret_id);
        let result = commit(prepared);
        self.changed.notify_all();
        result
    }

    pub fn with_valid_grant<T>(
        &self,
        ticket: &GrantTicket,
        operation: impl FnOnce() -> Result<T, LadonError>,
    ) -> Result<T, LadonError> {
        let mut state = self.lock_state()?;
        if !is_app_active(&state)
            || state.vault_session_id != Some(ticket.vault_session_id)
            || !state
                .grants
                .missing(ticket.client_session_id, ticket.secret_ids.iter().copied())
                .is_empty()
        {
            return Err(LadonError::ApprovalCancelled);
        }
        operation()
    }

    fn set_decision(
        &self,
        approval_id: Uuid,
        decision: ApprovalDecision,
    ) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        let pending = state.pending.as_mut().ok_or(LadonError::InvalidRequest)?;
        if pending.request.id != approval_id || pending.decision.is_some() {
            return Err(LadonError::InvalidRequest);
        }
        pending.decision = Some(decision);
        self.changed.notify_all();
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ApprovalState<C>>, LadonError> {
        self.state.lock().map_err(|_| LadonError::ProcessFailure)
    }
}

fn is_app_active<C>(state: &ApprovalState<C>) -> bool {
    state.app_access == AppAccessState::Active
}

impl ApprovalCoordinator<SystemMonotonicClock> {
    #[must_use]
    pub fn session_defaults() -> Self {
        Self::new(
            SystemMonotonicClock::new(),
            DEFAULT_GRANT_LIFETIME,
            DEFAULT_APPROVAL_TIMEOUT,
        )
    }
}

fn decision_for<C>(state: &ApprovalState<C>, approval_id: Uuid) -> Option<ApprovalDecision> {
    state.pending.as_ref().and_then(|pending| {
        (pending.request.id == approval_id)
            .then_some(pending.decision)
            .flatten()
    })
}

fn clear_pending<C>(state: &mut ApprovalState<C>, approval_id: Uuid) {
    if state
        .pending
        .as_ref()
        .is_some_and(|pending| pending.request.id == approval_id)
    {
        state.pending = None;
    }
}

fn cancel_pending<C>(state: &mut ApprovalState<C>) {
    if let Some(pending) = state.pending.as_mut() {
        pending.decision = Some(ApprovalDecision::Cancel);
    }
}
