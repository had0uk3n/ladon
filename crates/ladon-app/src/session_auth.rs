use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use ladon_core::LadonError;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::SensitiveText;

const PIN_SALT_BYTES: usize = 16;
const PIN_HASH_BYTES: usize = 32;
const PIN_MEMORY_KIB: u32 = 64 * 1024;
const PIN_PASSES: u32 = 3;
pub const MAX_FAILED_PIN_ATTEMPTS: u8 = 5;

pub struct SessionPin {
    salt: Zeroizing<[u8; PIN_SALT_BYTES]>,
    hash: Zeroizing<[u8; PIN_HASH_BYTES]>,
}

impl SessionPin {
    pub fn new(pin: &SensitiveText, confirmation: &SensitiveText) -> Result<Self, LadonError> {
        if pin.as_str() != confirmation.as_str() || !valid_pin(pin.as_str()) {
            return Err(LadonError::InvalidPin);
        }

        let mut salt = Zeroizing::new([0_u8; PIN_SALT_BYTES]);
        getrandom::fill(salt.as_mut()).map_err(|_| LadonError::CryptoUnavailable)?;
        let hash = derive(pin.as_str().as_bytes(), salt.as_ref())?;
        Ok(Self { salt, hash })
    }

    pub fn verify(&self, pin: &SensitiveText) -> Result<(), LadonError> {
        let candidate = derive(pin.as_str().as_bytes(), self.salt.as_ref())?;
        if bool::from(candidate.as_ref().ct_eq(self.hash.as_ref())) {
            Ok(())
        } else {
            Err(LadonError::ApprovalAuthenticationFailed)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinVerification {
    Accepted,
    Rejected { remaining_attempts: u8 },
    LockVault,
}

pub struct SessionConfirmation {
    pin: Option<SessionPin>,
    failed_pin_attempts: u8,
}

impl SessionConfirmation {
    pub const fn touch_id_only() -> Self {
        Self {
            pin: None,
            failed_pin_attempts: 0,
        }
    }

    pub const fn with_pin(pin: SessionPin) -> Self {
        Self {
            pin: Some(pin),
            failed_pin_attempts: 0,
        }
    }

    pub const fn has_pin(&self) -> bool {
        self.pin.is_some()
    }

    pub fn verify_pin(&mut self, candidate: &SensitiveText) -> Result<PinVerification, LadonError> {
        let Some(pin) = &self.pin else {
            return Ok(PinVerification::Rejected {
                remaining_attempts: 0,
            });
        };
        match pin.verify(candidate) {
            Ok(()) => {
                self.failed_pin_attempts = 0;
                return Ok(PinVerification::Accepted);
            }
            Err(LadonError::ApprovalAuthenticationFailed) => {}
            Err(error) => return Err(error),
        }
        self.failed_pin_attempts = self.failed_pin_attempts.saturating_add(1);
        if self.failed_pin_attempts >= MAX_FAILED_PIN_ATTEMPTS {
            Ok(PinVerification::LockVault)
        } else {
            Ok(PinVerification::Rejected {
                remaining_attempts: MAX_FAILED_PIN_ATTEMPTS - self.failed_pin_attempts,
            })
        }
    }

    pub fn record_touch_id_success(&mut self) {
        self.failed_pin_attempts = 0;
    }
}

impl fmt::Debug for SessionPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionPin([REDACTED])")
    }
}

fn valid_pin(pin: &str) -> bool {
    (4..=12).contains(&pin.len()) && pin.bytes().all(|byte| byte.is_ascii_digit())
}

fn derive(pin: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; PIN_HASH_BYTES]>, LadonError> {
    let params = Params::new(PIN_MEMORY_KIB, PIN_PASSES, 1, Some(PIN_HASH_BYTES))
        .map_err(|_| LadonError::CryptoUnavailable)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; PIN_HASH_BYTES]);
    argon2
        .hash_password_into(pin, salt, output.as_mut())
        .map_err(|_| LadonError::CryptoUnavailable)?;
    Ok(output)
}
