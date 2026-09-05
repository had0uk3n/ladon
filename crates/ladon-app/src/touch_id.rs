use ladon_core::LadonError;

pub struct TouchIdAuthenticator;

impl TouchIdAuthenticator {
    #[must_use]
    pub fn is_available() -> bool {
        platform::is_available()
    }

    pub fn authenticate(reason: &str) -> Result<(), LadonError> {
        platform::authenticate(reason)
    }

    pub fn authenticate_secret(secret_name: &str) -> Result<(), LadonError> {
        let escaped_name = crate::ui::sanitize_untrusted(secret_name);
        Self::authenticate(&format!(
            "Unlock Ladon secret “{escaped_name}” for viewing and editing"
        ))
    }

    pub fn authenticate_agent_session() -> Result<(), LadonError> {
        Self::authenticate(
            "Allow this agent session to use the displayed Ladon secrets for 30 minutes",
        )
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{sync::mpsc, time::Duration};

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

    pub fn authenticate(reason: &str) -> Result<(), LadonError> {
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

        match receiver.recv_timeout(AUTHENTICATION_TIMEOUT) {
            Ok(true) => Ok(()),
            Ok(false) => Err(LadonError::ApprovalAuthenticationFailed),
            Err(_) => {
                unsafe { context.invalidate() };
                Err(LadonError::ApprovalAuthenticationFailed)
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use ladon_core::LadonError;

    pub const fn is_available() -> bool {
        false
    }

    pub fn authenticate(_reason: &str) -> Result<(), LadonError> {
        Err(LadonError::TouchIdUnavailable)
    }
}
