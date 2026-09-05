use ladon_app::{PinVerification, SensitiveText, SessionConfirmation, SessionPin};
use ladon_core::LadonError;

#[test]
fn accepts_only_matching_four_to_twelve_ascii_digits() {
    for valid in ["1234", "123456789012"] {
        assert!(SessionPin::new(&SensitiveText::from(valid), &SensitiveText::from(valid)).is_ok());
    }

    for invalid in ["123", "1234567890123", "１２３４", "123a"] {
        assert_eq!(
            SessionPin::new(&SensitiveText::from(invalid), &SensitiveText::from(invalid))
                .unwrap_err(),
            LadonError::InvalidPin
        );
    }
    assert_eq!(
        SessionPin::new(&SensitiveText::from("1234"), &SensitiveText::from("4321")).unwrap_err(),
        LadonError::InvalidPin
    );
}

#[test]
fn invalid_pin_safe_message_describes_the_four_to_twelve_digit_requirement() {
    assert_eq!(
        LadonError::InvalidPin.safe_message(),
        "PIN must match and contain 4 to 12 ASCII digits"
    );
}

#[test]
fn verifies_the_correct_pin_and_rejects_a_wrong_one_generically() {
    let verifier = SessionPin::new(
        &SensitiveText::from("123456"),
        &SensitiveText::from("123456"),
    )
    .unwrap();

    assert!(verifier.verify(&SensitiveText::from("123456")).is_ok());
    assert_eq!(
        verifier.verify(&SensitiveText::from("654321")).unwrap_err(),
        LadonError::ApprovalAuthenticationFailed
    );
}

#[test]
fn debug_output_never_contains_pin_material() {
    let verifier = SessionPin::new(
        &SensitiveText::from("870421"),
        &SensitiveText::from("870421"),
    )
    .unwrap();

    let debug = format!("{verifier:?}");

    assert!(!debug.contains("870421"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn pin_is_optional_and_five_consecutive_failures_request_vault_lock() {
    let pin = SessionPin::new(&SensitiveText::from("1234"), &SensitiveText::from("1234")).unwrap();
    let mut confirmation = SessionConfirmation::with_pin(pin);
    assert!(confirmation.has_pin());
    for remaining in [4, 3, 2, 1] {
        assert_eq!(
            confirmation
                .verify_pin(&SensitiveText::from("9999"))
                .unwrap(),
            PinVerification::Rejected {
                remaining_attempts: remaining
            }
        );
    }
    assert_eq!(
        confirmation
            .verify_pin(&SensitiveText::from("9999"))
            .unwrap(),
        PinVerification::LockVault
    );
    assert!(!SessionConfirmation::touch_id_only().has_pin());
}

#[test]
fn success_resets_the_shared_pin_failure_counter() {
    let pin = SessionPin::new(&SensitiveText::from("1234"), &SensitiveText::from("1234")).unwrap();
    let mut confirmation = SessionConfirmation::with_pin(pin);
    assert!(matches!(
        confirmation
            .verify_pin(&SensitiveText::from("9999"))
            .unwrap(),
        PinVerification::Rejected {
            remaining_attempts: 4
        }
    ));
    confirmation.record_touch_id_success();
    assert!(matches!(
        confirmation
            .verify_pin(&SensitiveText::from("9999"))
            .unwrap(),
        PinVerification::Rejected {
            remaining_attempts: 4
        }
    ));
}
