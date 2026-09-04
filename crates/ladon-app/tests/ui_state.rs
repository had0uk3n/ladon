use std::time::Duration;

use ladon_app::{
    AddSecretDraft, ClipboardLease, PendingRequestView, RevealLease, SensitiveText,
    VaultController, VaultUiPhase, validate_new_passphrase,
};
use ladon_core::SensitiveBytes;

#[test]
fn first_run_requires_matching_passphrases_with_twelve_unicode_scalars() {
    assert!(validate_new_passphrase("12345678901", "12345678901").is_err());
    assert!(validate_new_passphrase("🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐", "different").is_err());
    assert!(validate_new_passphrase("correct horse", "correct horse").is_ok());
    assert!(validate_new_passphrase(&"x".repeat(1025), &"x".repeat(1025)).is_err());
}

#[test]
fn add_form_starts_simple_and_expands_to_ordered_additional_fields() {
    let mut draft = AddSecretDraft::new();
    assert_eq!(draft.fields().len(), 1);
    assert_eq!(draft.fields()[0].name(), "value");

    draft.add_field();
    draft.fields_mut()[1].set_name("access_key");

    assert_eq!(draft.fields().len(), 2);
    assert_eq!(draft.fields()[1].name(), "access_key");
}

#[test]
fn reveal_lease_expires_after_ten_seconds() {
    let lease = RevealLease::new(1_000);
    assert!(lease.is_active(10_999));
    assert!(!lease.is_active(11_000));
}

#[test]
fn clipboard_is_cleared_only_if_the_copied_value_is_still_present() {
    let lease = ClipboardLease::new(SensitiveBytes::new(b"copied-value".to_vec()), 5_000);
    assert!(!lease.should_clear(34_999, b"copied-value"));
    assert!(lease.should_clear(35_000, b"copied-value"));
    assert!(!lease.should_clear(35_000, b"user-replaced-it"));
}

#[test]
fn pending_request_escapes_controls_and_bidi_without_interpreting_markup() {
    let view = PendingRequestView::new(
        "Codex\n[trusted]",
        "/usr/bin/tool\u{202e}txt",
        &["--flag".to_owned(), "line\rbreak".to_owned()],
        "/tmp",
        Duration::from_secs(120),
    );

    assert_eq!(view.client_label(), "Codex\\u{a}[trusted]");
    assert_eq!(view.executable(), "/usr/bin/tool\\u{202e}txt");
    assert_eq!(view.arguments()[1], "line\\u{d}break");
    assert_eq!(view.timeout(), Duration::from_secs(120));
}

#[test]
fn sensitive_text_never_exposes_its_contents_through_debug() {
    let text = SensitiveText::from("fake-sensitive-value");
    let debug = format!("{text:?}");
    assert!(!debug.contains("fake-sensitive-value"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn vault_controller_persists_a_new_secret_and_locks_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path.clone());
    assert_eq!(controller.phase(), VaultUiPhase::FirstRun);

    controller.create(&passphrase, &passphrase).unwrap();
    let mut draft = AddSecretDraft::new();
    draft.set_name("example-token");
    draft.fields_mut()[0]
        .value_mut()
        .push_str("fake-secret-for-tests");
    controller.add_secret(&mut draft).unwrap();
    assert_eq!(controller.secrets().len(), 1);

    controller.lock();
    assert_eq!(controller.phase(), VaultUiPhase::Locked);
    assert!(controller.secrets().is_empty());

    let mut reopened = VaultController::new(path);
    reopened.unlock(&passphrase).unwrap();
    assert_eq!(reopened.secrets()[0].name, "example-token");
    assert_eq!(reopened.secrets()[0].field_names, vec!["value"]);

    let id = reopened.secrets()[0].id;
    reopened.delete_secret(id).unwrap();
    assert!(reopened.secrets().is_empty());
}
