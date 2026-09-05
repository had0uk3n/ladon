use std::{cell::Cell, rc::Rc, time::Duration};

use ladon_core::{GrantStore, MonotonicClock, SecretId};
use uuid::Uuid;

#[derive(Clone)]
struct FakeClock(Rc<Cell<u64>>);

impl FakeClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(0)))
    }

    fn advance(&self, duration: Duration) {
        self.0
            .set(self.0.get().saturating_add(duration.as_millis() as u64));
    }
}

impl MonotonicClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.0.get()
    }
}

#[test]
fn grants_only_the_approved_client_and_secret_pairs() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock, Duration::from_secs(30 * 60));
    let approved_client = Uuid::new_v4();
    let other_client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();

    grants.grant(approved_client, [first]);

    assert!(grants.missing(approved_client, [first]).is_empty());
    assert_eq!(grants.missing(approved_client, [second]), vec![second]);
    assert_eq!(grants.missing(other_client, [first]), vec![first]);
}

#[test]
fn one_approval_grants_each_distinct_secret_in_the_request() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock, Duration::from_secs(30 * 60));
    let client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();

    grants.grant(client, [first, second, first]);

    assert!(grants.missing(client, [second, first]).is_empty());
    assert_eq!(grants.len(), 2);
}

#[test]
fn use_does_not_extend_the_fixed_thirty_minute_deadline() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock.clone(), Duration::from_secs(30 * 60));
    let client = Uuid::new_v4();
    let secret = SecretId::new();
    grants.grant(client, [secret]);

    clock.advance(Duration::from_secs(29 * 60));
    assert!(grants.missing(client, [secret]).is_empty());
    assert_eq!(
        grants.remaining(client, secret),
        Some(Duration::from_secs(60))
    );

    clock.advance(Duration::from_secs(60));
    assert_eq!(grants.missing(client, [secret]), vec![secret]);
    assert_eq!(grants.remaining(client, secret), None);
}

#[test]
fn revoke_all_removes_every_active_grant() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock, Duration::from_secs(30 * 60));
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    grants.grant(first_client, [first, second]);
    grants.grant(second_client, [first]);

    grants.revoke_all();

    assert_eq!(
        grants.missing(first_client, [first, second]),
        vec![first, second]
    );
    assert_eq!(grants.missing(second_client, [first]), vec![first]);
    assert_eq!(grants.len(), 0);
}

#[test]
fn revoke_secret_removes_only_that_secret_across_clients() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock, Duration::from_secs(60));
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let changed = SecretId::new();
    let untouched = SecretId::new();
    grants.grant(first_client, [changed, untouched]);
    grants.grant(second_client, [changed]);

    grants.revoke_secret(changed);

    assert_eq!(grants.missing(first_client, [changed]), [changed]);
    assert!(grants.missing(first_client, [untouched]).is_empty());
    assert_eq!(grants.missing(second_client, [changed]), [changed]);
}
