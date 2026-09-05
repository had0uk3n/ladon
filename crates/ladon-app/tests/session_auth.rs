use ladon_app::{SensitiveText, SessionPin};
use ladon_core::LadonError;

#[test]
fn accepts_only_matching_six_to_twelve_ascii_digits() {
    for valid in ["123456", "123456789012"] {
        assert!(SessionPin::new(&SensitiveText::from(valid), &SensitiveText::from(valid)).is_ok());
    }

    for invalid in ["12345", "1234567890123", "１２３４５６", "12345a"] {
        assert_eq!(
            SessionPin::new(&SensitiveText::from(invalid), &SensitiveText::from(invalid))
                .unwrap_err(),
            LadonError::InvalidPin
        );
    }
    assert_eq!(
        SessionPin::new(
            &SensitiveText::from("123456"),
            &SensitiveText::from("654321")
        )
        .unwrap_err(),
        LadonError::InvalidPin
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
