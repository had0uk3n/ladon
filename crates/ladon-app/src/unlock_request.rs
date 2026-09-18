use crate::RunCancellation;
use ladon_core::LadonError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

/// Value-free request metadata; the agent can request a prompt, never authenticate.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct PendingUnlock {
    pub id: Uuid,
    pub client_label: String,
    pub purpose: String,
}

struct UnlockState {
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    request: PendingUnlock,
    decision: Option<Result<(), LadonError>>,
}

#[derive(Default)]
pub(crate) struct UnlockRequests {
    state: Mutex<Option<UnlockState>>,
    changed: Condvar,
    epoch: AtomicU64,
}

impl UnlockRequests {
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
    #[cfg(any(feature = "gui", test))]
    pub fn pending(&self) -> Result<Option<PendingUnlock>, LadonError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| LadonError::ProcessFailure)?
            .as_ref()
            .filter(|state| state.decision.is_none())
            .map(|state| state.request.clone()))
    }

    #[cfg(any(feature = "gui", test))]
    pub fn resolve(&self, id: Uuid, allow: bool) -> Result<(), LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        let Some(UnlockState {
            request: pending,
            decision,
        }) = state.as_mut()
        else {
            return Err(LadonError::InvalidRequest);
        };
        if pending.id != id || decision.is_some() {
            return Err(LadonError::InvalidRequest);
        }
        *decision = Some(if allow {
            Ok(())
        } else {
            Err(LadonError::ApprovalDenied)
        });
        self.changed.notify_all();
        Ok(())
    }

    pub fn cancel(&self) -> Result<(), LadonError> {
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        self.epoch.fetch_add(1, Ordering::AcqRel);
        if let Some(UnlockState { decision, .. }) = state.as_mut() {
            *decision = Some(Err(LadonError::ApprovalCancelled));
        }
        self.changed.notify_all();
        Ok(())
    }

    pub fn wait(
        &self,
        epoch: u64,
        client_label: &str,
        purpose: &str,
        cancellation: &RunCancellation,
        timeout: Duration,
        wake: impl FnOnce(),
    ) -> Result<(), LadonError> {
        let deadline = Instant::now() + timeout;
        {
            let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
            if epoch != self.epoch() {
                return Err(LadonError::ApprovalCancelled);
            }
            if state.is_some() {
                return Err(LadonError::Busy);
            }
            *state = Some(UnlockState {
                request: PendingUnlock {
                    id: Uuid::new_v4(),
                    client_label: client_label.to_owned(),
                    purpose: purpose.to_owned(),
                },
                decision: None,
            });
        }
        wake();
        let mut state = self.state.lock().map_err(|_| LadonError::ProcessFailure)?;
        let result = loop {
            if cancellation.is_cancelled() {
                break Err(LadonError::ApprovalCancelled);
            }
            if Instant::now() >= deadline {
                break Err(LadonError::ApprovalTimeout);
            }
            if let Some(UnlockState {
                decision: Some(decision),
                ..
            }) = state.as_ref()
            {
                break *decision;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, Duration::from_millis(20))
                .map_err(|_| LadonError::ProcessFailure)?;
            state = next;
        };
        *state = None;
        self.changed.notify_all();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    #[test]
    fn waits_for_local_decision_and_rejects_stale_completion() {
        let requests = Arc::new(UnlockRequests::default());
        let worker = Arc::clone(&requests);
        let join = thread::spawn(move || {
            worker.wait(
                0,
                "agent",
                "Run command",
                &RunCancellation::new(),
                Duration::from_secs(1),
                || {},
            )
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let pending = loop {
            if let Some(pending) = requests.pending().unwrap() {
                break pending;
            }
            assert!(Instant::now() < deadline);
            thread::yield_now();
        };
        assert!(!join.is_finished());
        assert_eq!(
            requests.resolve(Uuid::new_v4(), true),
            Err(LadonError::InvalidRequest)
        );
        requests.resolve(pending.id, true).unwrap();
        assert_eq!(join.join().unwrap(), Ok(()));
        assert!(requests.pending().unwrap().is_none());
    }

    #[test]
    fn cancellation_and_timeout_clear_the_pending_request() {
        let requests = UnlockRequests::default();
        let cancellation = RunCancellation::new();
        cancellation.cancel();
        assert_eq!(
            requests.wait(
                0,
                "agent",
                "List secrets",
                &cancellation,
                Duration::from_secs(1),
                || {}
            ),
            Err(LadonError::ApprovalCancelled)
        );
        assert!(requests.pending().unwrap().is_none());
        assert_eq!(
            requests.wait(
                0,
                "agent",
                "List secrets",
                &RunCancellation::new(),
                Duration::ZERO,
                || {}
            ),
            Err(LadonError::ApprovalTimeout)
        );
        assert!(requests.pending().unwrap().is_none());
    }

    #[test]
    fn lock_between_snapshot_and_registration_rejects_the_old_request() {
        let requests = UnlockRequests::default();
        let epoch = requests.epoch();
        requests.cancel().unwrap();
        assert_eq!(
            requests.wait(
                epoch,
                "agent",
                "Run",
                &RunCancellation::new(),
                Duration::from_secs(1),
                || panic!("stale request must not open UI")
            ),
            Err(LadonError::ApprovalCancelled)
        );
        assert!(requests.pending().unwrap().is_none());
    }

    #[test]
    fn hard_lock_cancels_and_second_request_is_busy() {
        let requests = UnlockRequests::default();
        let result = requests.wait(
            0,
            "agent",
            "List secrets",
            &RunCancellation::new(),
            Duration::from_secs(1),
            || {
                assert_eq!(
                    requests.wait(
                        0,
                        "second",
                        "Run",
                        &RunCancellation::new(),
                        Duration::ZERO,
                        || {}
                    ),
                    Err(LadonError::Busy)
                );
                requests.cancel().unwrap();
            },
        );
        assert_eq!(result, Err(LadonError::ApprovalCancelled));
        assert!(requests.pending().unwrap().is_none());
    }
}
