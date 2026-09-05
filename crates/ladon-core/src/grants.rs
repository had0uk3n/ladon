use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use uuid::Uuid;

use crate::{MonotonicClock, SecretId};

pub struct GrantStore<C> {
    clock: C,
    lifetime_millis: u64,
    deadlines: HashMap<(Uuid, SecretId), u64>,
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
        self.purge_expired();
        let deadline = self.clock.now_millis().saturating_add(self.lifetime_millis);
        for secret_id in secret_ids {
            self.deadlines
                .insert((client_session_id, secret_id), deadline);
        }
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
            .map(|deadline| Duration::from_millis(deadline.saturating_sub(self.clock.now_millis())))
    }

    pub fn revoke_all(&mut self) {
        self.deadlines.clear();
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
        self.deadlines.retain(|_, deadline| now < *deadline);
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
