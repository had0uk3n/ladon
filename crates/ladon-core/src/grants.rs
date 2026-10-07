use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant, SystemTime},
};

use uuid::Uuid;

use crate::{MonotonicClock, SecretId};

pub struct GrantStore<C> {
    clock: C,
    lifetime_millis: u64,
    deadlines: HashMap<(Uuid, SecretId), GrantDeadline>,
}

#[derive(Clone, Copy)]
enum GrantDeadline {
    Elapsed(u64),
    WallClock(SystemTime),
    Session,
}

impl GrantDeadline {
    fn remaining(self, elapsed: u64, wall: SystemTime) -> Duration {
        match self {
            Self::Elapsed(deadline) => Duration::from_millis(deadline.saturating_sub(elapsed)),
            Self::WallClock(deadline) => deadline.duration_since(wall).unwrap_or(Duration::ZERO),
            Self::Session => Duration::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantEntry {
    client_session_id: Uuid,
    secret_id: SecretId,
    remaining: Duration,
    expires_with_session: bool,
}

impl GrantEntry {
    pub const fn client_session_id(&self) -> Uuid {
        self.client_session_id
    }

    pub const fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    /// Session grants have no timed deadline and report Duration::MAX.
    pub const fn remaining(&self) -> Duration {
        self.remaining
    }

    pub const fn expires_with_session(&self) -> bool {
        self.expires_with_session
    }
}

impl<C: MonotonicClock> GrantStore<C> {
    #[must_use]
    pub fn new(clock: C, lifetime: Duration) -> Self {
        Self {
            clock,
            lifetime_millis: duration_millis(lifetime),
            deadlines: HashMap::new(),
        }
    }

    pub fn grant(
        &mut self,
        client_session_id: Uuid,
        secret_ids: impl IntoIterator<Item = SecretId>,
    ) {
        self.grant_for(
            client_session_id,
            secret_ids,
            Duration::from_millis(self.lifetime_millis),
        );
    }

    pub fn grant_for(
        &mut self,
        client_session_id: Uuid,
        secret_ids: impl IntoIterator<Item = SecretId>,
        lifetime: Duration,
    ) {
        self.purge_expired();
        let deadline = self
            .clock
            .now_millis()
            .saturating_add(duration_millis(lifetime));
        for secret_id in secret_ids {
            self.deadlines.insert(
                (client_session_id, secret_id),
                GrantDeadline::Elapsed(deadline),
            );
        }
    }

    pub fn grant_until(
        &mut self,
        client_session_id: Uuid,
        secret_ids: impl IntoIterator<Item = SecretId>,
        deadline: SystemTime,
    ) {
        self.purge_expired();
        for secret_id in secret_ids {
            self.deadlines.insert(
                (client_session_id, secret_id),
                GrantDeadline::WallClock(deadline),
            );
        }
    }

    pub fn grant_session(
        &mut self,
        client_session_id: Uuid,
        secret_ids: impl IntoIterator<Item = SecretId>,
    ) {
        self.purge_expired();
        for secret_id in secret_ids {
            self.deadlines
                .insert((client_session_id, secret_id), GrantDeadline::Session);
        }
    }

    pub fn revoke_client(&mut self, client_session_id: Uuid) {
        self.deadlines
            .retain(|(client, _), _| *client != client_session_id);
    }

    pub fn missing(
        &mut self,
        client_session_id: Uuid,
        secret_ids: impl IntoIterator<Item = SecretId>,
    ) -> Vec<SecretId> {
        self.purge_expired();
        let mut seen = HashSet::new();
        secret_ids
            .into_iter()
            .filter(|secret_id| seen.insert(*secret_id))
            .filter(|secret_id| {
                !self
                    .deadlines
                    .contains_key(&(client_session_id, *secret_id))
            })
            .collect()
    }

    pub fn remaining(&mut self, client_session_id: Uuid, secret_id: SecretId) -> Option<Duration> {
        self.purge_expired();
        self.deadlines
            .get(&(client_session_id, secret_id))
            .map(|deadline| deadline.remaining(self.clock.now_millis(), self.clock.wall_time()))
    }

    pub fn revoke_all(&mut self) {
        self.deadlines.clear();
    }

    pub fn revoke_secret(&mut self, secret_id: SecretId) {
        self.deadlines
            .retain(|(_, granted_secret_id), _| *granted_secret_id != secret_id);
    }

    pub fn active(&mut self) -> Vec<GrantEntry> {
        self.purge_expired();
        let now = self.clock.now_millis();
        self.deadlines
            .iter()
            .map(|((client_session_id, secret_id), deadline)| GrantEntry {
                client_session_id: *client_session_id,
                secret_id: *secret_id,
                remaining: deadline.remaining(now, self.clock.wall_time()),
                expires_with_session: matches!(deadline, GrantDeadline::Session),
            })
            .collect()
    }

    pub fn revoke_pair(&mut self, client_session_id: Uuid, secret_id: SecretId) -> bool {
        self.purge_expired();
        self.deadlines
            .remove(&(client_session_id, secret_id))
            .is_some()
    }

    #[must_use]
    pub fn len(&mut self) -> usize {
        self.purge_expired();
        self.deadlines.len()
    }

    #[must_use]
    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    fn purge_expired(&mut self) {
        let now = self.clock.now_millis();
        let wall = self.clock.wall_time();
        self.deadlines
            .retain(|_, deadline| !deadline.remaining(now, wall).is_zero());
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug)]
pub struct SystemMonotonicClock {
    started: Instant,
}

impl SystemMonotonicClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now_millis(&self) -> u64 {
        duration_millis(self.started.elapsed())
    }
}
