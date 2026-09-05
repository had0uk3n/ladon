use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, TryRecvError},
};

use ladon_core::LadonError;

pub struct TouchIdAuthenticator;

pub(crate) struct TouchIdAttempt {
    result: Receiver<Result<(), LadonError>>,
    cancelled: Arc<AtomicBool>,
}

impl TouchIdAttempt {
    fn start(reason: String) -> Result<Self, LadonError> {
        if reason.is_empty() {
            return Err(LadonError::InvalidRequest);
        }
        Self::spawn_with(move |cancelled| platform::authenticate(&reason, &cancelled))
    }

    pub(crate) fn spawn_with(
        authenticate: impl FnOnce(Arc<AtomicBool>) -> Result<(), LadonError> + Send + 'static,
    ) -> Result<Self, LadonError> {
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = Arc::clone(&cancelled);
        let (sender, result) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("ladon-touch-id".to_owned())
            .spawn(move || {
                let _ = sender.send(authenticate(worker_cancelled));
            })
            .map_err(|_| LadonError::ProcessFailure)?;
        Ok(Self { result, cancelled })
    }

    pub(crate) fn try_result(&self) -> Option<Result<(), LadonError>> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(LadonError::ProcessFailure)),
        }
    }
}

impl Drop for TouchIdAttempt {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl TouchIdAuthenticator {
    #[must_use]
    pub fn is_available() -> bool {
        platform::is_available()
    }

    pub(crate) fn authenticate_secret(secret_name: &str) -> Result<TouchIdAttempt, LadonError> {
        let escaped_name = crate::ui::sanitize_untrusted(secret_name);
        TouchIdAttempt::start(format!(
            "Unlock Ladon secret “{escaped_name}” for viewing and editing"
        ))
    }

    pub(crate) fn authenticate_agent_session() -> Result<TouchIdAttempt, LadonError> {
        TouchIdAttempt::start(
            "Allow this agent session to use the displayed Ladon secrets for 30 minutes".to_owned(),
        )
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };

    use block2::RcBlock;
    use ladon_core::LadonError;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(60);

    pub fn is_available() -> bool {
        let context = unsafe { LAContext::new() };
        unsafe {
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .is_ok()
        }
    }

    pub fn authenticate(reason: &str, cancelled: &Arc<AtomicBool>) -> Result<(), LadonError> {
        if reason.is_empty() {
            return Err(LadonError::InvalidRequest);
        }
        let context = unsafe { LAContext::new() };
        unsafe {
            context
                .canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
                .map_err(|_| LadonError::TouchIdUnavailable)?;
            context.setTouchIDAuthenticationAllowableReuseDuration(0.0);
            context.setLocalizedFallbackTitle(Some(&NSString::from_str("")));
        }

        let localized_reason = NSString::from_str(reason);
        let (sender, receiver) = mpsc::sync_channel(1);
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _ = sender.send(bool::from(success));
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &localized_reason,
                &reply,
            );
        }

        let deadline = Instant::now() + AUTHENTICATION_TIMEOUT;
        loop {
            if cancelled.load(Ordering::Acquire) {
                unsafe { context.invalidate() };
                return Err(LadonError::ApprovalCancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                unsafe { context.invalidate() };
                return Err(LadonError::ApprovalAuthenticationFailed);
            }
            let wait_for = Duration::from_millis(20).min(deadline.saturating_duration_since(now));
            match receiver.recv_timeout(wait_for) {
                Ok(true) => return Ok(()),
                Ok(false) => return Err(LadonError::ApprovalAuthenticationFailed),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(LadonError::ApprovalAuthenticationFailed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::Ordering, mpsc},
        time::Duration,
    };

    use super::*;

    #[test]
    fn touch_id_attempt_runs_off_the_caller_thread_and_cancels_on_drop() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (cancelled_tx, cancelled_rx) = mpsc::channel();
        let attempt = TouchIdAttempt::spawn_with(move |cancelled| {
            entered_tx.send(()).unwrap();
            while !cancelled.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            cancelled_tx.send(()).unwrap();
            Err(LadonError::ApprovalCancelled)
        })
        .unwrap();

        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(attempt.try_result().is_none());
        drop(attempt);
        cancelled_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn touch_id_attempt_delivers_the_background_result_once() {
        let (release_tx, release_rx) = mpsc::channel();
        let attempt = TouchIdAttempt::spawn_with(move |_cancelled: Arc<_>| {
            release_rx.recv().unwrap();
            Ok(())
        })
        .unwrap();

        assert!(attempt.try_result().is_none());
        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(result) = attempt.try_result() {
                assert_eq!(result, Ok(()));
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "Touch ID result never arrived"
            );
            std::thread::yield_now();
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use std::sync::{Arc, atomic::AtomicBool};

    use ladon_core::LadonError;

    pub const fn is_available() -> bool {
        false
    }

    pub fn authenticate(_reason: &str, _cancelled: &Arc<AtomicBool>) -> Result<(), LadonError> {
        Err(LadonError::TouchIdUnavailable)
    }
}
