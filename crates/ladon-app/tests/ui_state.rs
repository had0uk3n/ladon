use std::{fs, time::Duration};

use ladon_app::{
    AddSecretDraft, ApprovalSecret, ClipboardLease, EditSecretDraft, EditableField, EditableValue,
    NavigationResult, NavigationTarget, PendingApproval, PendingRequestView, SecretDetailState,
    SensitiveText, VaultController, VaultUiPhase, validate_new_passphrase,
};
use ladon_core::{
    ActivitySink, FieldName, LadonError, MAX_FIELD_BYTES, SecretField, SecretId, SensitiveBytes,
    TextHint, VaultOpen, VaultPayload, VaultSession, VaultStore, create_vault,
};

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
fn untouched_optional_fields_are_ignored_when_saved() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path);
    controller.create(&passphrase, &passphrase).unwrap();
    let mut draft = AddSecretDraft::new();
    draft.set_name("example");
    draft.fields_mut()[0]
        .value_mut()
        .push_str("fake-primary-value");
    draft.add_field();

    let id = controller.add_secret(&mut draft).unwrap();
    let loaded = controller.load_secret(id).unwrap();

    assert_eq!(loaded.fields().len(), 1);
    assert_eq!(loaded.fields()[0].name(), "value");
}

#[test]
fn optional_fields_can_be_removed_but_the_primary_field_cannot() {
    let mut draft = AddSecretDraft::new();
    draft.add_field();
    draft.fields_mut()[1]
        .value_mut()
        .push_str("fake-removed-value");

    assert!(!draft.remove_field(0));
    assert!(draft.remove_field(1));
    assert_eq!(draft.fields().len(), 1);
    assert_eq!(draft.fields()[0].name(), "value");
}

#[test]
fn rejected_add_keeps_every_visible_draft_field() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path);
    controller.create(&passphrase, &passphrase).unwrap();
    let mut draft = AddSecretDraft::new();
    draft.set_name("id:not-a-valid-secret-name");
    draft.fields_mut()[0]
        .value_mut()
        .push_str("fake-preserved-value");
    draft.add_field();

    assert_eq!(
        controller.add_secret(&mut draft),
        Err(LadonError::InvalidSecretRef)
    );
    assert_eq!(draft.fields().len(), 2);
    assert_eq!(draft.fields()[0].value().as_str(), "fake-preserved-value");
    assert!(draft.fields()[1].name().is_empty());
    assert!(draft.fields()[1].value().as_str().is_empty());
}

fn text_draft(id: SecretId) -> EditSecretDraft {
    EditSecretDraft::from_parts(
        id,
        "example",
        vec![EditableField::text(
            "value",
            SensitiveText::from("fake-state-secret"),
        )],
    )
}

fn authorized_state() -> (SecretDetailState, uuid::Uuid, SecretId) {
    let session = uuid::Uuid::new_v4();
    let secret = SecretId::new();
    let mut state = SecretDetailState::default();
    state.navigate_now(NavigationTarget::Secret(secret));
    let attempt = state.authentication_attempt(session).unwrap();
    assert!(state.accept_authentication(attempt, session));
    (state, session, secret)
}

#[test]
fn authorization_is_bound_to_session_secret_and_selection_epoch() {
    let session = uuid::Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    let mut state = SecretDetailState::default();
    state.navigate_now(NavigationTarget::Secret(first));
    let stale = state.authentication_attempt(session).unwrap();
    state.navigate_now(NavigationTarget::Secret(second));
    state.navigate_now(NavigationTarget::Secret(first));
    assert!(!state.accept_authentication(stale, session));
    assert!(!state.is_authorized(session));
}

#[test]
fn dirty_edit_requires_discard_before_navigation_but_lock_never_waits() {
    let (mut state, session, secret) = authorized_state();
    state.begin_edit(session, text_draft(secret)).unwrap();
    state.mark_dirty();
    assert_eq!(
        state.request_navigation(NavigationTarget::Add),
        NavigationResult::ConfirmDiscard
    );
    assert!(state.is_editing());
    state.clear_for_vault_lock();
    assert_eq!(state.selected(), None);
    assert!(!state.has_sensitive_buffer());
}

#[test]
fn hiding_drops_values_but_keeps_current_secret_authorized() {
    let (mut state, session, secret) = authorized_state();
    state.begin_reveal(session, text_draft(secret)).unwrap();
    state.hide_values();
    assert!(!state.has_sensitive_buffer());
    assert!(state.is_authorized(session));
}

#[test]
fn finishing_save_drops_the_editor_but_keeps_current_secret_authorized() {
    let (mut state, session, secret) = authorized_state();
    state.begin_edit(session, text_draft(secret)).unwrap();
    state.mark_dirty();
    state.finish_save();
    assert!(!state.has_sensitive_buffer());
    assert!(!state.is_editing());
    assert!(state.is_authorized(session));
}

#[test]
fn reveal_and_edit_reject_authorization_from_a_stale_vault_session() {
    let (mut state, _, secret) = authorized_state();
    let reopened_session = uuid::Uuid::new_v4();

    assert_eq!(
        state.begin_reveal(reopened_session, text_draft(secret)),
        Err(ladon_app::DetailStateError::NotAuthorized)
    );
    assert!(!state.has_sensitive_buffer());
    assert_eq!(
        state.begin_edit(reopened_session, text_draft(secret)),
        Err(ladon_app::DetailStateError::NotAuthorized)
    );
    assert!(!state.has_sensitive_buffer());
}

#[test]
fn clipboard_is_cleared_only_if_the_copied_value_is_still_present() {
    let lease = ClipboardLease::new(SensitiveBytes::new(b"copied-value".to_vec()), 5_000);
    assert!(!lease.is_expired(34_999));
    assert!(lease.is_expired(35_000));
    assert!(!lease.should_clear(34_999, b"copied-value"));
    assert!(lease.should_clear(35_000, b"copied-value"));
    assert!(!lease.should_clear(35_000, b"user-replaced-it"));
}

#[test]
fn pending_request_escapes_controls_and_bidi_without_interpreting_markup() {
    let approval = PendingApproval::new(
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
        "Codex\n[trusted]",
        vec![ApprovalSecret::new(
            SecretId::new(),
            "prod\u{202e}token",
            ["value\rname"],
        )],
        "/usr/bin/tool\u{202e}txt",
        ["--flag", "line\rbreak"],
        "/tmp",
    );
    let view = PendingRequestView::from_approval(&approval, Duration::from_secs(120));

    assert_eq!(view.client_label(), "Codex\\u{a}[trusted]");
    assert_eq!(view.secrets()[0].0, "prod\\u{202e}token");
    assert_eq!(view.secrets()[0].1, ["value\\u{d}name"]);
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
fn editor_loads_only_valid_utf8_as_text_and_redacts_debug() {
    #[derive(Default)]
    struct TestActivity;
    impl ActivitySink for TestActivity {
        fn secret_activity(&mut self) {}
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let password = SensitiveBytes::new(b"correct horse".to_vec());
    let payload = VaultPayload::new(SecretId::new(), 0, vec![]).unwrap();
    let unlocked = create_vault(payload, &password).unwrap().0;
    let store = VaultStore::new(path.clone());
    let mut session = VaultSession::new(unlocked, TestActivity);
    let id = session
        .add(
            "mixed",
            vec![
                SecretField::new(
                    FieldName::parse("value").unwrap(),
                    b"fake-text-canary".to_vec(),
                    TextHint::Text,
                )
                .unwrap(),
                SecretField::new(
                    FieldName::parse("invalid").unwrap(),
                    vec![0xff],
                    TextHint::Text,
                )
                .unwrap(),
                SecretField::new(
                    FieldName::parse("blob").unwrap(),
                    vec![0, 1, 2],
                    TextHint::Binary,
                )
                .unwrap(),
            ],
        )
        .unwrap();
    session.commit_to(&store).unwrap();
    let mut controller = VaultController::new(path);
    controller.unlock(&passphrase).unwrap();

    let draft = controller.load_secret(id).unwrap();
    assert!(matches!(draft.fields()[0].value(), EditableValue::Text(_)));
    assert!(matches!(
        draft.fields()[1].value(),
        EditableValue::Binary { .. }
    ));
    assert!(matches!(
        draft.fields()[2].value(),
        EditableValue::Binary { .. }
    ));
    assert!(!format!("{draft:?}").contains("fake-text-canary"));
}

#[test]
fn prepared_secret_update_persists_fields_preserves_id_and_increments_once() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path.clone());
    controller.create(&passphrase, &passphrase).unwrap();
    let mut initial = AddSecretDraft::new();
    initial.set_name("before");
    initial.fields_mut()[0]
        .value_mut()
        .push_str("fake-old-value");
    let id = controller.add_secret(&mut initial).unwrap();
    let store = VaultStore::new(path.clone());
    let revision_before = match store.open(&passphrase.to_sensitive_bytes()).unwrap() {
        VaultOpen::Primary { vault, .. } => vault.payload().revision(),
        VaultOpen::RestoreRequired { .. } => panic!("expected primary vault"),
    };

    let draft = EditSecretDraft::from_parts(
        id,
        "after",
        vec![
            EditableField::text("value", SensitiveText::from("fake-new-value")),
            EditableField::binary(
                "blob",
                SensitiveBytes::new(vec![0xff, 0, 1]),
                TextHint::Binary,
            ),
        ],
    );
    let update = controller.prepare_secret_update(&draft).unwrap();
    let unchanged_before_apply = match store.open(&passphrase.to_sensitive_bytes()).unwrap() {
        VaultOpen::Primary { vault, .. } => vault.payload().revision(),
        VaultOpen::RestoreRequired { .. } => panic!("expected primary vault"),
    };
    assert_eq!(unchanged_before_apply, revision_before);
    controller.apply_secret_update(update).unwrap();

    let revision_after = match store.open(&passphrase.to_sensitive_bytes()).unwrap() {
        VaultOpen::Primary { vault, .. } => vault.payload().revision(),
        VaultOpen::RestoreRequired { .. } => panic!("expected primary vault"),
    };
    assert_eq!(revision_after, revision_before + 1);
    controller.lock();

    let mut reopened = VaultController::new(path);
    reopened.unlock(&passphrase).unwrap();
    let loaded = reopened.load_secret(id).unwrap();
    assert_eq!(loaded.id(), id);
    assert_eq!(loaded.name(), "after");
    assert_eq!(loaded.fields().len(), 2);
    let EditableValue::Text(value) = loaded.fields()[0].value() else {
        panic!("expected text field");
    };
    assert_eq!(value.as_str(), "fake-new-value");
    let EditableValue::Binary {
        bytes,
        original_hint,
    } = loaded.fields()[1].value()
    else {
        panic!("expected binary field");
    };
    assert_eq!(*original_hint, TextHint::Binary);
    bytes.expose(|value| assert_eq!(value, [0xff, 0, 1]));
}

#[test]
fn duplicate_name_update_leaves_stored_record_and_revision_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path.clone());
    controller.create(&passphrase, &passphrase).unwrap();
    let mut first = AddSecretDraft::new();
    first.set_name("first");
    let id = controller.add_secret(&mut first).unwrap();
    let mut occupied = AddSecretDraft::new();
    occupied.set_name("occupied");
    controller.add_secret(&mut occupied).unwrap();
    let store = VaultStore::new(path);
    let revision_before = match store.open(&passphrase.to_sensitive_bytes()).unwrap() {
        VaultOpen::Primary { vault, .. } => vault.payload().revision(),
        VaultOpen::RestoreRequired { .. } => panic!("expected primary vault"),
    };
    let draft = EditSecretDraft::from_parts(
        id,
        "occupied",
        vec![EditableField::text(
            "value",
            SensitiveText::from("fake-replacement"),
        )],
    );

    assert_eq!(
        controller.prepare_secret_update(&draft).unwrap_err(),
        LadonError::DuplicateSecretName
    );
    let revision_after = match store.open(&passphrase.to_sensitive_bytes()).unwrap() {
        VaultOpen::Primary { vault, .. } => vault.payload().revision(),
        VaultOpen::RestoreRequired { .. } => panic!("expected primary vault"),
    };
    assert_eq!(revision_after, revision_before);
    assert_eq!(controller.load_secret(id).unwrap().name(), "first");
}

#[test]
fn editor_field_validation_rejects_invalid_names_and_oversized_values() {
    let invalid_name = EditSecretDraft::from_parts(
        SecretId::new(),
        "example",
        vec![EditableField::binary(
            "invalid name",
            SensitiveBytes::new(b"fake-invalid-name-value".to_vec()),
            TextHint::Binary,
        )],
    );
    assert_eq!(
        invalid_name.to_fields().unwrap_err(),
        LadonError::InvalidFieldName
    );

    let oversized_value = EditSecretDraft::from_parts(
        SecretId::new(),
        "example",
        vec![EditableField::binary(
            "value",
            SensitiveBytes::new(vec![0xff; MAX_FIELD_BYTES + 1]),
            TextHint::Binary,
        )],
    );
    assert_eq!(
        oversized_value.to_fields().unwrap_err(),
        LadonError::FieldTooLarge
    );
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

#[test]
fn vault_controller_requires_recovery_when_backup_is_newer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let store = VaultStore::new(path.clone());
    let password = SensitiveBytes::new(b"correct horse".to_vec());
    let vault_id = SecretId::new();
    let old = create_vault(VaultPayload::new(vault_id, 1, vec![]).unwrap(), &password)
        .unwrap()
        .1;
    let newer = create_vault(VaultPayload::new(vault_id, 2, vec![]).unwrap(), &password)
        .unwrap()
        .1;
    fs::write(&path, old).unwrap();
    fs::write(store.backup_path(), newer).unwrap();

    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path);
    controller.unlock(&passphrase).unwrap();

    assert_eq!(controller.phase(), VaultUiPhase::RecoveryRequired);
    assert!(controller.remaining_unlocked().is_some());
    controller.restore_backup().unwrap();
    assert_eq!(controller.phase(), VaultUiPhase::Unlocked);
}

#[test]
fn newer_backup_recovery_can_keep_the_authoritative_primary() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let store = VaultStore::new(path.clone());
    let password = SensitiveBytes::new(b"correct horse".to_vec());
    let vault_id = SecretId::new();
    let primary = create_vault(VaultPayload::new(vault_id, 1, vec![]).unwrap(), &password)
        .unwrap()
        .1;
    let newer_backup = create_vault(VaultPayload::new(vault_id, 2, vec![]).unwrap(), &password)
        .unwrap()
        .1;
    fs::write(&path, primary).unwrap();
    fs::write(store.backup_path(), newer_backup).unwrap();

    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path);
    controller.unlock(&passphrase).unwrap();
    assert!(controller.can_continue_with_primary());

    controller.continue_with_primary().unwrap();
    assert_eq!(controller.phase(), VaultUiPhase::Unlocked);
    controller.lock();
    controller.unlock(&passphrase).unwrap();
    assert_eq!(controller.phase(), VaultUiPhase::RecoveryRequired);
}
