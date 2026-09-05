use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use ladon_app::{ApprovalCoordinator, ApprovalSecret, PendingApproval, RunCancellation};
use ladon_core::{LadonError, MonotonicClock, SecretId};
use uuid::Uuid;

#[derive(Clone)]
struct FakeClock(Arc<AtomicU64>);

impl FakeClock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    fn advance(&self, duration: Duration) {
        self.0
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }
}

impl MonotonicClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

fn request(client: Uuid, secrets: &[(SecretId, &str)]) -> PendingApproval {
    request_for_vault(Uuid::nil(), client, secrets)
}

fn request_for_vault(
    vault_session_id: Uuid,
    client: Uuid,
    secrets: &[(SecretId, &str)],
) -> PendingApproval {
    PendingApproval::new(
        vault_session_id,
        client,
        "MCP client (unverified)",
        secrets
            .iter()
            .map(|(id, name)| ApprovalSecret::new(*id, *name, ["value"]))
            .collect(),
        "/usr/bin/curl",
        ["https://example.test"],
        "/tmp",
    )
}

fn wait_for_pending<C: MonotonicClock>(coordinator: &ApprovalCoordinator<C>) -> PendingApproval {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(pending) = coordinator.pending().unwrap() {
            return pending;
        }
        assert!(Instant::now() < deadline, "approval never became pending");
        thread::yield_now();
    }
}

#[test]
fn approval_grants_the_same_client_and_secrets_without_sliding_expiry() {
    let clock = FakeClock::new();
    let coordinator = Arc::new(ApprovalCoordinator::new(
        clock.clone(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    ));
    let client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    let cancellation = RunCancellation::new();
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        let approval = request(client, &[(first, "github"), (second, "registry")]);
        let cancellation = cancellation.clone();
        thread::spawn(move || coordinator.authorize(approval, &cancellation))
    };
    let pending = wait_for_pending(&coordinator);

    coordinator.approve(pending.id()).unwrap();
    assert!(waiting.join().unwrap().is_ok());
    assert_eq!(
        coordinator
            .authorize(
                request(client, &[(first, "github"), (second, "registry")]),
                &RunCancellation::new(),
            )
            .map(|_| ()),
        Ok(())
    );

    clock.advance(Duration::from_secs(29 * 60));
    assert_eq!(
        coordinator
            .authorize(
                request(client, &[(first, "github")]),
                &RunCancellation::new(),
            )
            .map(|_| ()),
        Ok(())
    );
    clock.advance(Duration::from_secs(60));
    let expired = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(first, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.deny(pending.id()).unwrap();
    assert_eq!(expired.join().unwrap(), Err(LadonError::ApprovalDenied));
}

#[test]
fn another_client_or_secret_requires_a_separate_approval() {
    let coordinator = Arc::new(ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    ));
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();

    for approval in [
        request(first_client, &[(first, "github")]),
        request(first_client, &[(second, "registry")]),
        request(second_client, &[(first, "github")]),
    ] {
        let waiting = {
            let coordinator = Arc::clone(&coordinator);
            thread::spawn(move || coordinator.authorize(approval, &RunCancellation::new()))
        };
        let pending = wait_for_pending(&coordinator);
        coordinator.approve(pending.id()).unwrap();
        assert!(waiting.join().unwrap().is_ok());
    }
}

#[test]
fn denial_timeout_disconnect_and_revoke_fail_closed() {
    let coordinator = Arc::new(ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(30 * 60),
        Duration::from_millis(40),
    ));
    let client = Uuid::new_v4();
    let secret = SecretId::new();

    let denied = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(secret, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.deny(pending.id()).unwrap();
    assert_eq!(denied.join().unwrap(), Err(LadonError::ApprovalDenied));

    assert_eq!(
        coordinator.authorize(
            request(client, &[(secret, "github")]),
            &RunCancellation::new(),
        ),
        Err(LadonError::ApprovalTimeout)
    );

    let cancellation = RunCancellation::new();
    let disconnected = {
        let coordinator = Arc::clone(&coordinator);
        let cancellation = cancellation.clone();
        thread::spawn(move || {
            coordinator.authorize(request(client, &[(secret, "github")]), &cancellation)
        })
    };
    wait_for_pending(&coordinator);
    cancellation.cancel();
    assert_eq!(
        disconnected.join().unwrap(),
        Err(LadonError::ApprovalCancelled)
    );

    let approved = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(secret, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.approve(pending.id()).unwrap();
    assert!(approved.join().unwrap().is_ok());
    coordinator.revoke_all().unwrap();

    let revoked = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(secret, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.deny(pending.id()).unwrap();
    assert_eq!(revoked.join().unwrap(), Err(LadonError::ApprovalDenied));
}

#[test]
fn only_one_request_can_be_pending() {
    let coordinator = Arc::new(ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    ));
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(first_client, &[(first, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);

    assert_eq!(
        coordinator.authorize(
            request(second_client, &[(second, "registry")]),
            &RunCancellation::new(),
        ),
        Err(LadonError::Busy)
    );

    coordinator.deny(pending.id()).unwrap();
    assert_eq!(waiting.join().unwrap(), Err(LadonError::ApprovalDenied));
}

#[test]
fn ticket_is_rechecked_at_resolution_and_revoke_waits_for_in_flight_resolution() {
    let clock = FakeClock::new();
    let coordinator = Arc::new(ApprovalCoordinator::new(
        clock.clone(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    ));
    let client = Uuid::new_v4();
    let secret = SecretId::new();
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(secret, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.approve(pending.id()).unwrap();
    let ticket = waiting.join().unwrap().unwrap();

    clock.advance(Duration::from_secs(30 * 60));
    let resolved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    assert_eq!(
        coordinator.with_valid_grant(&ticket, || {
            resolved.store(true, Ordering::Relaxed);
            Ok(())
        }),
        Err(LadonError::ApprovalCancelled)
    );
    assert!(!resolved.load(Ordering::Relaxed));

    clock.advance(Duration::from_secs(1));
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(secret, "github")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.approve(pending.id()).unwrap();
    let ticket = waiting.join().unwrap().unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let resolving = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.with_valid_grant(&ticket, || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        })
    };
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let (revoked_tx, revoked_rx) = std::sync::mpsc::channel();
    let revoking = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.revoke_all().unwrap();
            revoked_tx.send(()).unwrap();
        })
    };
    assert!(revoked_rx.recv_timeout(Duration::from_millis(30)).is_err());
    release_tx.send(()).unwrap();
    assert_eq!(resolving.join().unwrap(), Ok(()));
    revoked_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    revoking.join().unwrap();
}

#[test]
fn a_new_vault_unlock_session_invalidates_old_grants() {
    let coordinator = Arc::new(ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    ));
    let client = Uuid::new_v4();
    let secret = SecretId::new();
    let first_vault_session = Uuid::new_v4();
    let first = request_for_vault(first_vault_session, client, &[(secret, "github")]);
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || coordinator.authorize(first, &RunCancellation::new()))
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.approve(pending.id()).unwrap();
    assert!(waiting.join().unwrap().is_ok());

    let reopened = request_for_vault(Uuid::new_v4(), client, &[(secret, "github")]);
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || coordinator.authorize(reopened, &RunCancellation::new()))
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.deny(pending.id()).unwrap();
    assert_eq!(waiting.join().unwrap(), Err(LadonError::ApprovalDenied));
}

#[test]
fn secret_mutation_validation_failure_preserves_the_grant() {
    let coordinator = Arc::new(ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(60),
        Duration::from_secs(2),
    ));
    let client = Uuid::new_v4();
    let secret = SecretId::new();
    let waiting = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(client, &[(secret, "changed")]),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.approve(pending.id()).unwrap();
    let ticket = waiting.join().unwrap().unwrap();

    assert_eq!(
        coordinator.coordinate_secret_mutation(
            secret,
            || Err::<(), _>(LadonError::DuplicateSecretName),
            |()| -> Result<(), LadonError> { panic!("commit must not run") },
        ),
        Err(LadonError::DuplicateSecretName)
    );
    assert_eq!(coordinator.with_valid_grant(&ticket, || Ok(7)), Ok(7));
}

#[test]
fn secret_mutation_cancels_pending_and_revokes_only_the_changed_secret() {
    let coordinator = Arc::new(ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(60),
        Duration::from_secs(2),
    ));
    let approved_client = Uuid::new_v4();
    let waiting_client = Uuid::new_v4();
    let changed = SecretId::new();
    let untouched = SecretId::new();
    let initial = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(
                    approved_client,
                    &[(changed, "changed"), (untouched, "untouched")],
                ),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending(&coordinator);
    coordinator.approve(pending.id()).unwrap();
    let changed_ticket = initial.join().unwrap().unwrap();
    let untouched_ticket = coordinator
        .authorize(
            request(approved_client, &[(untouched, "untouched")]),
            &RunCancellation::new(),
        )
        .unwrap();
    let blocked = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            coordinator.authorize(
                request(waiting_client, &[(changed, "changed")]),
                &RunCancellation::new(),
            )
        })
    };
    wait_for_pending(&coordinator);

    assert_eq!(
        coordinator.coordinate_secret_mutation(changed, || Ok("prepared"), Ok),
        Ok("prepared")
    );
    assert_eq!(blocked.join().unwrap(), Err(LadonError::ApprovalCancelled));
    assert_eq!(
        coordinator.with_valid_grant(&changed_ticket, || Ok(())),
        Err(LadonError::ApprovalCancelled)
    );
    assert_eq!(
        coordinator.with_valid_grant(&untouched_ticket, || Ok(9)),
        Ok(9)
    );
}
