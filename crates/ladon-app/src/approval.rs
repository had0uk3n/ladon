use std::{
    collections::{HashMap, HashSet},
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime},
};

use ladon_core::{GrantStore, LadonError, MonotonicClock, SecretId, SystemMonotonicClock};
use uuid::Uuid;

use crate::RunCancellation;

pub(crate) const MAX_TRACKED_SESSIONS: usize = 32;

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
    client_labels: HashMap<Uuid, String>,
    client_sessions: HashMap<Uuid, RunCancellation>,
    sessions_closed: bool,
    app_access: AppAccessState,
    lock_epoch: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantTicket {
    vault_session_id: Uuid,
    client_session_id: Uuid,
    secret_ids: Vec<SecretId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveGrantSnapshot {
    client_session_id: Uuid,
    client_label: String,
    secret_id: SecretId,
    remaining: Duration,
    expires_with_session: bool,
}

impl ActiveGrantSnapshot {
    #[must_use]
    pub const fn client_session_id(&self) -> Uuid {
        self.client_session_id
    }

    #[must_use]
    pub fn client_label(&self) -> &str {
        &self.client_label
    }

    #[must_use]
    pub const fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    #[must_use]
    pub const fn remaining(&self) -> Duration {
        self.remaining
    }

    pub fn expires_with_session(&self) -> bool {
        self.expires_with_session
    }
}

struct PendingState {
    request: PendingApproval,
    requested_secret_ids: Vec<SecretId>,
    decision: Option<ApprovalDecision>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ApprovalDecision {
    Approve(Option<Duration>),
    ApproveUntil(SystemTime),
    ApproveSession,
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
                client_labels: HashMap::new(),
                client_sessions: HashMap::new(),
                sessions_closed: false,
                app_access: AppAccessState::Active,
                lock_epoch: 0,
            }),
            changed: Condvar::new(),
            approval_timeout,
        }
    }

    pub fn authorize(
        &self,
        request: PendingApproval,
        cancellation: &RunCancellation,
    ) -> Result<GrantTicket, LadonError> {
        self.authorize_with_wake(request, cancellation, || {})
    }

    pub(crate) fn authorize_with_wake(
        &self,
        mut request: PendingApproval,
        cancellation: &RunCancellation,
        wake: impl FnOnce(),
    ) -> Result<GrantTicket, LadonError> {
        let mut state = self.lock_state()?;
        purge_disconnected_clients(&mut state);
        if !is_app_active(&state) {
            return Err(LadonError::VaultLocked);
        }
        if state.pending.is_some() {
            return Err(LadonError::Busy);
        }

        if state.vault_session_id != Some(request.vault_session_id) {
            state.grants.revoke_all();
            state.client_labels.clear();
            state.vault_session_id = Some(request.vault_session_id);
        }
        state
            .client_labels
            .insert(request.client_session_id, request.client_label.clone());
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
        drop(state);
        wake();
        let mut state = self.lock_state()?;
        loop {
            purge_disconnected_clients(&mut state);
            if cancellation.is_cancelled() {
                clear_pending(&mut state, approval_id);
                self.changed.notify_all();
                return Err(LadonError::ApprovalCancelled);
            }

            if let Some(decision) = decision_for(&state, approval_id) {
                let pending = state.pending.take().ok_or(LadonError::ProcessFailure)?;
                match decision {
                    ApprovalDecision::Approve(lifetime) => {
                        let client_session_id = pending.request.client_session_id;
                        let client_label = pending.request.client_label.clone();
                        let secret_ids = pending.request.secrets.iter().map(ApprovalSecret::id);
                        if let Some(lifetime) = lifetime {
                            state
                                .grants
                                .grant_for(client_session_id, secret_ids, lifetime);
                        } else {
                            state.grants.grant(client_session_id, secret_ids);
                        }
                        state.client_labels.insert(client_session_id, client_label);
                        self.changed.notify_all();
                        return Ok(ticket);
                    }
                    ApprovalDecision::ApproveUntil(deadline) => {
                        let client = pending.request.client_session_id;
                        state.grants.grant_until(
                            client,
                            pending.request.secrets.iter().map(ApprovalSecret::id),
                            deadline,
                        );
                        state
                            .client_labels
                            .insert(client, pending.request.client_label);
                        self.changed.notify_all();
                        return Ok(ticket);
                    }
                    ApprovalDecision::ApproveSession => {
                        let client = pending.request.client_session_id;
                        if !state
                            .client_sessions
                            .get(&client)
                            .is_some_and(|session| !session.is_cancelled())
                        {
                            return Err(LadonError::ApprovalCancelled);
                        }
                        state.grants.grant_session(
                            client,
                            pending.request.secrets.iter().map(ApprovalSecret::id),
                        );
                        state
                            .client_labels
                            .insert(client, pending.request.client_label);
                        self.changed.notify_all();
                        return Ok(ticket);
                    }
                    ApprovalDecision::Deny => {
                        prune_client_labels(&mut state);
                        self.changed.notify_all();
                        return Err(LadonError::ApprovalDenied);
                    }
                    ApprovalDecision::Cancel => {
                        prune_client_labels(&mut state);
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

    pub fn register_client_session(
        &self,
        client: Uuid,
        cancellation: RunCancellation,
    ) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        purge_disconnected_clients(&mut state);
        if state.sessions_closed
            || state.client_sessions.contains_key(&client)
            || state.client_sessions.len() >= MAX_TRACKED_SESSIONS
        {
            return Err(LadonError::Busy);
        }
        state.grants.revoke_client(client);
        state.client_sessions.insert(client, cancellation);
        Ok(())
    }

    pub fn client_session_connected(&self, client: Uuid) -> Result<bool, LadonError> {
        let mut state = self.lock_state()?;
        purge_disconnected_clients(&mut state);
        Ok(state.client_sessions.contains_key(&client))
    }

    #[cfg(any(unix, test))]
    pub(crate) fn close_client_sessions(&self) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        state.sessions_closed = true;
        for cancellation in state.client_sessions.values() {
            cancellation.cancel();
        }
        purge_disconnected_clients(&mut state);
        self.changed.notify_all();
        Ok(())
    }

    pub fn pending(&self) -> Result<Option<PendingApproval>, LadonError> {
        let mut state = self.lock_state()?;
        purge_disconnected_clients(&mut state);
        Ok(state
            .pending
            .as_ref()
            .filter(|pending| pending.decision.is_none())
            .map(|pending| pending.request.clone()))
    }

    pub fn observe_client(
        &self,
        client_session_id: Uuid,
        client_label: &str,
    ) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        let owns_active_grant = state
            .grants
            .active()
            .iter()
            .any(|grant| grant.client_session_id() == client_session_id);
        let has_pending_request = state.pending.as_ref().is_some_and(|pending| {
            pending.decision.is_none() && pending.request.client_session_id == client_session_id
        });
        if owns_active_grant || has_pending_request {
            let client_label = client_label.to_owned();
            if let Some(pending) = state
                .pending
                .as_mut()
                .filter(|pending| pending.request.client_session_id == client_session_id)
            {
                pending.request.client_label = client_label.clone();
            }
            state.client_labels.insert(client_session_id, client_label);
        }
        prune_client_labels(&mut state);
        Ok(())
    }

    pub fn active_grants(&self) -> Result<Vec<ActiveGrantSnapshot>, LadonError> {
        let mut state = self.lock_state()?;
        purge_disconnected_clients(&mut state);
        let active = state.grants.active();
        let active_clients: HashSet<_> = active
            .iter()
            .map(|grant| grant.client_session_id())
            .collect();
        state
            .client_labels
            .retain(|client_session_id, _| active_clients.contains(client_session_id));
        Ok(active
            .into_iter()
            .map(|grant| ActiveGrantSnapshot {
                client_session_id: grant.client_session_id(),
                client_label: state
                    .client_labels
                    .get(&grant.client_session_id())
                    .cloned()
                    .unwrap_or_else(|| "MCP client".to_owned()),
                secret_id: grant.secret_id(),
                remaining: grant.remaining(),
                expires_with_session: grant.expires_with_session(),
            })
            .collect())
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
        state.client_labels.clear();
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
        state.client_labels.clear();
        state.vault_session_id = None;
        self.changed.notify_all();
        Ok(())
    }

    pub fn approve(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::Approve(None))
    }

    pub fn approve_for(&self, approval_id: Uuid, lifetime: Duration) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::Approve(Some(lifetime)))
    }

    pub fn approve_until(&self, approval_id: Uuid, deadline: SystemTime) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::ApproveUntil(deadline))
    }

    pub fn approve_session(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::ApproveSession)
    }

    pub fn deny(&self, approval_id: Uuid) -> Result<(), LadonError> {
        self.set_decision(approval_id, ApprovalDecision::Deny)
    }

    pub fn cancel_pending(&self) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        if let Some(pending) = state.pending.as_mut() {
            pending.decision = Some(ApprovalDecision::Cancel);
            prune_client_labels(&mut state);
            self.changed.notify_all();
        }
        Ok(())
    }

    pub fn revoke_all(&self) -> Result<(), LadonError> {
        let mut state = self.lock_state()?;
        state.grants.revoke_all();
        state.client_labels.clear();
        Ok(())
    }

    pub fn revoke_pair(
        &self,
        client_session_id: Uuid,
        secret_id: SecretId,
    ) -> Result<bool, LadonError> {
        let mut state = self.lock_state()?;
        if let Some(pending) = state.pending.as_mut().filter(|pending| {
            pending.request.client_session_id == client_session_id
                && pending.requested_secret_ids.contains(&secret_id)
        }) {
            pending.decision = Some(ApprovalDecision::Cancel);
        }
        let revoked = state.grants.revoke_pair(client_session_id, secret_id);
        prune_client_labels(&mut state);
        self.changed.notify_all();
        Ok(revoked)
    }

    pub fn coordinate_secret_mutation<P, T>(
        &self,
        secret_id: SecretId,
        prepare: impl FnOnce() -> Result<P, LadonError>,
        commit: impl FnOnce(P) -> Result<T, LadonError>,
    ) -> Result<T, LadonError> {
        let mut state = self.lock_state()?;
        let prepared = prepare()?;
        if let Some(pending) = state
            .pending
            .as_mut()
            .filter(|pending| pending.requested_secret_ids.contains(&secret_id))
        {
            pending.decision = Some(ApprovalDecision::Cancel);
            self.changed.notify_all();
        }
        state.grants.revoke_secret(secret_id);
        prune_client_labels(&mut state);
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
        purge_disconnected_clients(&mut state);
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
        purge_disconnected_clients(&mut state);
        if decision == ApprovalDecision::ApproveSession {
            let client = state
                .pending
                .as_ref()
                .ok_or(LadonError::InvalidRequest)?
                .request
                .client_session_id;
            if !state.client_sessions.contains_key(&client) {
                return Err(LadonError::ApprovalCancelled);
            }
        }
        let pending = state.pending.as_mut().ok_or(LadonError::InvalidRequest)?;
        if pending.request.id != approval_id || pending.decision.is_some() {
            return Err(LadonError::InvalidRequest);
        }
        pending.decision = Some(decision);
        if !matches!(
            decision,
            ApprovalDecision::Approve(_)
                | ApprovalDecision::ApproveUntil(_)
                | ApprovalDecision::ApproveSession
        ) {
            prune_client_labels(&mut state);
        }
        self.changed.notify_all();
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ApprovalState<C>>, LadonError> {
        self.state.lock().map_err(|_| LadonError::ProcessFailure)
    }
}

fn purge_disconnected_clients<C: MonotonicClock>(state: &mut ApprovalState<C>) {
    let disconnected: Vec<_> = state
        .client_sessions
        .iter()
        .filter(|(_, token)| token.is_cancelled())
        .map(|(client, _)| *client)
        .collect();
    for client in disconnected {
        state.client_sessions.remove(&client);
        state.grants.revoke_client(client);
        state.client_labels.remove(&client);
        if let Some(pending) = state
            .pending
            .as_mut()
            .filter(|pending| pending.request.client_session_id == client)
        {
            pending.decision = Some(ApprovalDecision::Cancel);
        }
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

fn clear_pending<C: MonotonicClock>(state: &mut ApprovalState<C>, approval_id: Uuid) {
    if state
        .pending
        .as_ref()
        .is_some_and(|pending| pending.request.id == approval_id)
    {
        state.pending = None;
        prune_client_labels(state);
    }
}

fn cancel_pending<C: MonotonicClock>(state: &mut ApprovalState<C>) {
    if let Some(pending) = state.pending.as_mut() {
        pending.decision = Some(ApprovalDecision::Cancel);
    }
}

fn prune_client_labels<C: MonotonicClock>(state: &mut ApprovalState<C>) {
    let active_clients: HashSet<_> = state
        .grants
        .active()
        .iter()
        .map(|grant| grant.client_session_id())
        .collect();
    state
        .client_labels
        .retain(|client_session_id, _| active_clients.contains(client_session_id));
}

#[cfg(test)]
mod wake_tests {
    use super::*;

    #[test]
    fn shutdown_rejects_session_registration_after_cancelling_existing_connections() {
        let coordinator = ApprovalCoordinator::session_defaults();
        let token = RunCancellation::new();
        coordinator
            .register_client_session(Uuid::new_v4(), token.clone())
            .unwrap();
        coordinator.close_client_sessions().unwrap();
        assert!(token.is_cancelled());
        assert_eq!(
            coordinator.register_client_session(Uuid::new_v4(), RunCancellation::new()),
            Err(LadonError::Busy)
        );
    }

    #[test]
    fn approval_wakes_after_publication_without_holding_the_state_mutex() {
        let coordinator = ApprovalCoordinator::session_defaults();
        let request = PendingApproval::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "test agent",
            vec![ApprovalSecret::new(SecretId::new(), "test", ["value"])],
            "/usr/bin/true",
            [] as [&str; 0],
            "/tmp",
        );
        let result = coordinator.authorize_with_wake(request, &RunCancellation::new(), || {
            let pending = coordinator
                .pending()
                .unwrap()
                .expect("published before waking");
            coordinator.deny(pending.id()).unwrap();
        });
        assert_eq!(result, Err(LadonError::ApprovalDenied));
        assert!(coordinator.pending().unwrap().is_none());
    }
}

#[cfg(test)]
mod session_capacity_tests {
    use super::*;

    #[test]
    fn session_capacity_is_bounded_and_disconnect_releases_a_slot() {
        let coordinator = ApprovalCoordinator::session_defaults();
        let first = RunCancellation::new();
        let client = Uuid::new_v4();
        coordinator
            .register_client_session(client, first.clone())
            .unwrap();
        for _ in 1..MAX_TRACKED_SESSIONS {
            coordinator
                .register_client_session(Uuid::new_v4(), RunCancellation::new())
                .unwrap();
        }
        assert_eq!(
            coordinator.register_client_session(Uuid::new_v4(), RunCancellation::new()),
            Err(LadonError::Busy)
        );
        assert!(coordinator.client_session_connected(client).unwrap());
        first.cancel();
        coordinator
            .register_client_session(Uuid::new_v4(), RunCancellation::new())
            .unwrap();
        assert!(!coordinator.client_session_connected(client).unwrap());
        coordinator.close_client_sessions().unwrap();
    }
}
