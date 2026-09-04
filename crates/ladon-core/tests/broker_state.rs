use std::{cell::Cell, rc::Rc, time::Duration};

use ladon_core::{
    ActivityEntry, ActivityOutcome, BrokerDecision, BrokerState, LockReason, MonotonicClock,
    SessionStatus,
};

#[derive(Clone)]
struct FakeClock(Rc<Cell<u64>>);

impl FakeClock {
    fn new() -> Self {
        Self(Rc::new(Cell::new(0)))
    }

    fn advance(&self, duration: Duration) {
        self.0.set(self.0.get() + duration.as_millis() as u64);
    }
}

impl MonotonicClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.0.get()
    }
}

#[test]
fn permits_only_one_two_minute_unlock_request() {
    let clock = FakeClock::new();
    let mut broker = BrokerState::new(clock.clone(), Duration::from_secs(30 * 60));

    assert_eq!(broker.request_secret_access(), BrokerDecision::PromptUnlock);
    assert_eq!(broker.request_secret_access(), BrokerDecision::Busy);
    clock.advance(Duration::from_secs(120));
    assert_eq!(broker.tick(), BrokerDecision::UnlockTimedOut);
    assert_eq!(broker.status(), SessionStatus::Locked);
}

#[test]
fn cannot_approve_an_unlock_dialog_after_its_deadline() {
    let clock = FakeClock::new();
    let mut broker = BrokerState::new(clock.clone(), Duration::from_secs(30 * 60));
    broker.request_secret_access();
    clock.advance(Duration::from_secs(121));

    assert_eq!(broker.complete_unlock(true), BrokerDecision::UnlockTimedOut);
    assert_eq!(broker.status(), SessionStatus::Locked);
}

#[test]
fn unlock_resumes_pending_request_and_idle_activity_expires() {
    let clock = FakeClock::new();
    let mut broker = BrokerState::new(clock.clone(), Duration::from_secs(30 * 60));
    assert_eq!(broker.request_secret_access(), BrokerDecision::PromptUnlock);

    assert_eq!(broker.complete_unlock(true), BrokerDecision::Authorized);
    assert_eq!(broker.status(), SessionStatus::Unlocked);
    clock.advance(Duration::from_secs(29 * 60));
    broker.secret_activity();
    clock.advance(Duration::from_secs(29 * 60));
    assert_eq!(broker.tick(), BrokerDecision::NoChange);
    clock.advance(Duration::from_secs(61));
    assert_eq!(broker.tick(), BrokerDecision::Locked);
}

#[test]
fn active_run_pauses_idle_and_manual_lock_cancels_before_wipe() {
    let clock = FakeClock::new();
    let mut broker = BrokerState::new(clock.clone(), Duration::from_secs(30 * 60));
    broker.request_secret_access();
    broker.complete_unlock(true);
    assert_eq!(broker.start_run(), BrokerDecision::Authorized);

    clock.advance(Duration::from_secs(60 * 60));
    assert_eq!(broker.tick(), BrokerDecision::NoChange);
    assert_eq!(
        broker.request_lock(LockReason::Manual),
        BrokerDecision::CancelRunBeforeLock
    );
    assert_eq!(broker.status(), SessionStatus::Locking);

    assert_eq!(broker.finish_run(), BrokerDecision::Locked);
    assert_eq!(broker.status(), SessionStatus::Locked);
}

#[test]
fn normal_run_completion_restarts_full_idle_window() {
    let clock = FakeClock::new();
    let mut broker = BrokerState::new(clock.clone(), Duration::from_secs(30 * 60));
    broker.request_secret_access();
    broker.complete_unlock(true);
    broker.start_run();
    clock.advance(Duration::from_secs(60 * 60));

    assert_eq!(broker.finish_run(), BrokerDecision::NoChange);
    clock.advance(Duration::from_secs(29 * 60));
    assert_eq!(broker.tick(), BrokerDecision::NoChange);
    clock.advance(Duration::from_secs(61));
    assert_eq!(broker.tick(), BrokerDecision::Locked);
}

#[test]
fn activity_is_metadata_only_and_bounded_to_one_hundred_entries() {
    let clock = FakeClock::new();
    let mut broker = BrokerState::new(clock, Duration::from_secs(30 * 60));
    for index in 0..101 {
        broker.record_activity(ActivityEntry {
            client_label: "Codex".to_owned(),
            executable: Some("/usr/bin/env".to_owned()),
            timestamp_millis: index,
            outcome: ActivityOutcome::Succeeded,
            redaction_count: 0,
            referenced_fields: vec![],
        });
    }

    assert_eq!(broker.activities().len(), 100);
    assert_eq!(broker.activities()[0].timestamp_millis, 1);
    let debug = format!("{:?}", broker.activities());
    assert!(!debug.contains("stdout"));
    assert!(!debug.contains("arguments"));
    assert!(!debug.contains("value"));
}
