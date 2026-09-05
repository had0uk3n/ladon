# Protected Secret View and Edit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the owner select, authenticate, reveal, and atomically edit one secret in the desktop GUI while keeping agent-facing APIs value-free.

**Architecture:** Add a zeroizing editor model and a small pure state machine between `desktop.rs` and `VaultController`. Core gains whole-record read/replace operations, while the approval coordinator serializes per-secret grant invalidation with mutation using the existing `approval -> vault` lock order. Touch ID remains a fresh strict-biometric check per action; an optional in-memory PIN is accepted alongside it.

**Tech Stack:** Rust 2024 workspace, `egui`/`eframe` 0.32.3, `zeroize`, Argon2id, macOS LocalAuthentication, existing local IPC and vault persistence.

**Spec:** `docs/superpowers/specs/2026-09-04-ladon-design.md`

## Global Constraints

- The distributed application must require no cloud service, browser engine, JavaScript runtime, optional credential store, or provider adapter.
- The public CLI, MCP protocol, and agent-facing local IPC must never return a plaintext managed value or accept PIN/Touch ID input.
- Touch ID uses a fresh `LAContext`, `DeviceOwnerAuthenticationWithBiometrics`, zero reuse duration, and no password or Apple Watch fallback.
- A session PIN contains 4--12 ASCII digits, is represented only by a salted Argon2id verifier, and disappears on vault lock or process exit.
- Five consecutive wrong PIN submissions across protected GUI actions lock the vault; successful PIN or Touch ID confirmation resets the counter.
- Local authorization is scoped to `(vault_session_id, secret_id, selection_epoch)` and is cleared on navigation, vault lock, manager exit, or app exit.
- Secret values and edit buffers use non-cloneable zeroizing containers with redacted `Debug`; masked values use a constant-length placeholder.
- A whole-record edit preserves the immutable `SecretId`, validates before grant revocation, increments the vault revision once, and follows section 7.3 recovery on persistence failure.
- Every path that needs both shared locks acquires the approval coordinator before the vault controller.
- Existing binary fields are preserved byte-for-byte and are never decoded lossily; inline binary replacement is not part of this plan.

---

## File Structure

- `crates/ladon-core/src/vault.rs`: whole-record read plus validated, revision-bound atomic replacement inside an unlocked vault session.
- `crates/ladon-core/src/grants.rs`: targeted removal of every grant for one immutable secret ID.
- `crates/ladon-core/tests/vault_crud.rs`: record replacement and rejected-mutation behavior.
- `crates/ladon-core/tests/grants.rs`: per-secret grant invalidation without collateral revocation.
- `crates/ladon-app/src/session_auth.rs`: optional PIN state and five-failure lock decision.
- `crates/ladon-app/src/secret_editor.rs`: zeroizing edit draft, prepared update, and pure selected-secret UI state.
- `crates/ladon-app/src/ui.rs`: controller methods that load and persist a prepared whole-record update.
- `crates/ladon-app/src/approval.rs`: mutation serialization, pending-request cancellation, and grant revocation.
- `crates/ladon-app/src/agent_broker.rs`: GUI mutation entry points that enforce approval-before-vault lock order.
- `crates/ladon-app/src/desktop.rs`: session setup, secret detail screen, authentication controls, navigation, and close handling.
- `crates/ladon-app/src/touch_id.rs`: keep strict policy and expose dynamically checked authentication without caching.
- `crates/ladon-app/src/lib.rs`: exports for tested application-layer types.
- `crates/ladon-app/tests/session_auth.rs`: PIN boundaries and failure counter.
- `crates/ladon-app/tests/ui_state.rs`: zeroizing drafts and selection/reveal/edit transitions.
- `crates/ladon-app/tests/approval_state.rs`: mutation/grant concurrency contract.
- `crates/ladon-app/tests/agent_broker_unix.rs`: end-to-end future-use denial after an edit.
- `README.md`, `docs/security-review.md`, `docs/threat-model.md`, `docs/protocol.md`: user-visible behavior and security boundaries after implementation.

---

### Task 1: Optional session PIN and failure policy

**Files:**
- Modify: `crates/ladon-app/src/session_auth.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Test: `crates/ladon-app/tests/session_auth.rs`

**Interfaces:**
- Consumes: existing `SessionPin`, `SensitiveText`, and `LadonError`.
- Produces: `SessionConfirmation::{touch_id_only, with_pin, has_pin, verify_pin, record_touch_id_success}` and `PinVerification::{Accepted, Rejected, LockVault}`.

- [ ] **Step 1: Write failing PIN-boundary tests**

Replace the six-digit boundary test with assertions that `"1234"` and `"123456789012"` succeed while three digits, thirteen digits, Unicode digits, nondigits, and mismatched confirmation return `LadonError::InvalidPin`.

```rust
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
}
```

- [ ] **Step 2: Run the boundary test and verify RED**

Run: `cargo test -p ladon-app --test session_auth accepts_only_matching_four_to_twelve_ascii_digits --all-features`

Expected: FAIL because the existing validator rejects four-digit PINs.

- [ ] **Step 3: Change only the PIN boundary**

```rust
fn valid_pin(pin: &str) -> bool {
    (4..=12).contains(&pin.len()) && pin.bytes().all(|byte| byte.is_ascii_digit())
}
```

- [ ] **Step 4: Run the boundary test and verify GREEN**

Run: `cargo test -p ladon-app --test session_auth accepts_only_matching_four_to_twelve_ascii_digits --all-features`

Expected: PASS.

- [ ] **Step 5: Write failing optional-PIN and lockout tests**

Add the desired public state types to the test imports, then assert the capability and counter behavior.

```rust
#[test]
fn pin_is_optional_and_five_consecutive_failures_request_vault_lock() {
    let pin = SessionPin::new(&SensitiveText::from("1234"), &SensitiveText::from("1234")).unwrap();
    let mut confirmation = SessionConfirmation::with_pin(pin);
    assert!(confirmation.has_pin());
    for remaining in [4, 3, 2, 1] {
        assert_eq!(
            confirmation.verify_pin(&SensitiveText::from("9999")).unwrap(),
            PinVerification::Rejected { remaining_attempts: remaining }
        );
    }
    assert_eq!(
        confirmation.verify_pin(&SensitiveText::from("9999")).unwrap(),
        PinVerification::LockVault
    );
    assert!(!SessionConfirmation::touch_id_only().has_pin());
}

#[test]
fn success_resets_the_shared_pin_failure_counter() {
    let pin = SessionPin::new(&SensitiveText::from("1234"), &SensitiveText::from("1234")).unwrap();
    let mut confirmation = SessionConfirmation::with_pin(pin);
    assert!(matches!(
        confirmation.verify_pin(&SensitiveText::from("9999")).unwrap(),
        PinVerification::Rejected { remaining_attempts: 4 }
    ));
    confirmation.record_touch_id_success();
    assert!(matches!(
        confirmation.verify_pin(&SensitiveText::from("9999")).unwrap(),
        PinVerification::Rejected { remaining_attempts: 4 }
    ));
}
```

- [ ] **Step 6: Run the new tests and verify RED**

Run: `cargo test -p ladon-app --test session_auth --all-features`

Expected: compilation fails because `SessionConfirmation` and `PinVerification` do not exist.

- [ ] **Step 7: Implement the minimal in-memory confirmation state**

```rust
pub const MAX_FAILED_PIN_ATTEMPTS: u8 = 5;

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
        Self { pin: None, failed_pin_attempts: 0 }
    }

    pub const fn with_pin(pin: SessionPin) -> Self {
        Self { pin: Some(pin), failed_pin_attempts: 0 }
    }

    pub const fn has_pin(&self) -> bool {
        self.pin.is_some()
    }

    pub fn verify_pin(&mut self, candidate: &SensitiveText) -> Result<PinVerification, LadonError> {
        let Some(pin) = &self.pin else {
            return Ok(PinVerification::Rejected { remaining_attempts: 0 });
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
```

Export `PinVerification` and `SessionConfirmation` from `lib.rs`. Keep `Debug` absent for `SessionConfirmation` so the verifier cannot be formatted accidentally.

- [ ] **Step 8: Run session-auth tests and commit**

Run: `cargo test -p ladon-app --test session_auth --all-features`

Expected: all session-auth tests PASS.

```bash
git add crates/ladon-app/src/session_auth.rs crates/ladon-app/src/lib.rs crates/ladon-app/tests/session_auth.rs
git commit -m "feat: support optional four-digit session PINs"
```

---

### Task 2: Prepared whole-record vault replacement

**Files:**
- Modify: `crates/ladon-core/src/vault.rs`
- Modify: `crates/ladon-core/src/lib.rs`
- Test: `crates/ladon-core/tests/vault_crud.rs`

**Interfaces:**
- Consumes: `SecretRef`, `SecretRecord`, `SecretField`, and the existing revision/activity rules.
- Produces: `PreparedRecordReplacement` and `VaultSession::{with_record, prepare_record_replacement, apply_record_replacement}`.

- [ ] **Step 1: Write failing whole-record tests**

```rust
#[test]
fn whole_record_read_and_replace_preserve_id_and_increment_once() {
    let mut session = session();
    let id = session.add("before", vec![field("value", b"old")]).unwrap();
    let reference = SecretRef::parse(&format!("id:{id}")).unwrap();
    let before = session.revision();

    let observed = session
        .with_record(&reference, |record| {
            (record.id(), record.name().to_owned(), record.fields().len())
        })
        .unwrap();
    assert_eq!(observed, (id, "before".to_owned(), 1));

    let prepared = session
        .prepare_record_replacement(&reference, "after", vec![field("token", b"new")])
        .unwrap();
    assert_eq!(session.revision(), before);
    session.apply_record_replacement(prepared).unwrap();
    assert_eq!(session.revision(), before + 1);
    assert_eq!(session.list()[0].id, id);
    assert_eq!(session.list()[0].name, "after");
    assert_eq!(session.list()[0].field_names, vec!["token".to_owned()]);
}

#[test]
fn rejected_whole_record_replace_changes_nothing() {
    let mut session = session();
    let id = session.add("first", vec![field("value", b"one")]).unwrap();
    session.add("occupied", vec![field("value", b"two")]).unwrap();
    let revision = session.revision();
    let touches = session.activity().touches;
    let reference = SecretRef::parse(&format!("id:{id}")).unwrap();

    assert_eq!(
        session
            .prepare_record_replacement(
                &reference,
                "occupied",
                vec![field("value", b"replacement")],
            )
            .unwrap_err(),
        LadonError::DuplicateSecretName
    );
    assert_eq!(session.revision(), revision);
    assert_eq!(session.activity().touches, touches);
    assert_eq!(session.list()[0].name, "first");
}
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `cargo test -p ladon-core --test vault_crud whole_record --all-features`

Expected: compilation fails because the prepared-replacement API is missing.

- [ ] **Step 3: Implement read, preparation, and atomic application**

Build and validate the replacement before incrementing the revision or touching activity. Bind it to the observed vault revision so an obsolete prepared value fails closed.

```rust
pub fn with_record<R>(
    &mut self,
    reference: &SecretRef,
    operation: impl FnOnce(&SecretRecord) -> R,
) -> Result<R, LadonError> {
    let Self { vault, activity } = self;
    let target = find_record_index(vault.payload().records(), reference)?;
    let result = operation(&vault.payload().records()[target]);
    activity.secret_activity();
    Ok(result)
}

pub struct PreparedRecordReplacement {
    expected_revision: u64,
    target_id: SecretId,
    replacement: SecretRecord,
}

impl fmt::Debug for PreparedRecordReplacement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRecordReplacement")
            .field("expected_revision", &self.expected_revision)
            .field("target_id", &self.target_id)
            .field("replacement", &"[REDACTED]")
            .finish()
    }
}

pub fn prepare_record_replacement(
    &self,
    reference: &SecretRef,
    new_name: &str,
    fields: Vec<SecretField>,
) -> Result<PreparedRecordReplacement, LadonError> {
    let target = find_record_index(self.vault.payload().records(), reference)?;
    let current = &self.vault.payload().records()[target];
    let replacement = SecretRecord::from_parts(current.id(), new_name, fields)?;
    if self
        .vault
        .payload()
        .records()
        .iter()
        .enumerate()
        .any(|(index, record)| index != target && record.name() == replacement.name())
    {
        return Err(LadonError::DuplicateSecretName);
    }
    Ok(PreparedRecordReplacement {
        expected_revision: self.vault.payload().revision(),
        target_id: current.id(),
        replacement,
    })
}

pub fn apply_record_replacement(
    &mut self,
    prepared: PreparedRecordReplacement,
) -> Result<(), LadonError> {
    if self.vault.payload().revision() != prepared.expected_revision {
        return Err(LadonError::InvalidRequest);
    }
    let target = find_record_index(
        self.vault.payload().records(),
        &SecretRef::Id(prepared.target_id),
    )?;
    let payload = self.vault.payload_mut();
    payload.increment_revision()?;
    payload.records_mut()[target] = prepared.replacement;
    self.activity.secret_activity();
    Ok(())
}
```

- [ ] **Step 4: Run core CRUD tests and commit**

Run: `cargo test -p ladon-core --test vault_crud --all-features`

Expected: all vault CRUD tests PASS.

```bash
git add crates/ladon-core/src/vault.rs crates/ladon-core/src/lib.rs crates/ladon-core/tests/vault_crud.rs
git commit -m "feat: replace complete vault records atomically"
```

---

### Task 3: Zeroizing secret editor and controller operations

**Files:**
- Create: `crates/ladon-app/src/secret_editor.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Modify: `crates/ladon-app/src/ui.rs`
- Test: `crates/ladon-app/tests/ui_state.rs`

**Interfaces:**
- Consumes: `VaultSession::{with_record, prepare_record_replacement, apply_record_replacement}`, `PreparedRecordReplacement`, `SensitiveText`, `SensitiveBytes`, `SecretField`, and `TextHint`.
- Produces: `EditSecretDraft::{from_parts, from_record}`, `EditableField::{text, binary}`, `EditableValue`, and `VaultController::{session_id, load_secret, prepare_secret_update, apply_secret_update, ensure_secret_exists}`.

- [ ] **Step 1: Write failing draft tests**

Use this test fixture to load valid text, invalid UTF-8 marked as text, and binary bytes. It asserts that only valid UTF-8 becomes `EditableValue::Text`, while the other values remain byte-for-byte `EditableValue::Binary`, and that `Debug` contains no canary value.

```rust
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
            SecretField::new(FieldName::parse("value").unwrap(), b"fake-text-canary".to_vec(), TextHint::Text).unwrap(),
            SecretField::new(FieldName::parse("invalid").unwrap(), vec![0xff], TextHint::Text).unwrap(),
            SecretField::new(FieldName::parse("blob").unwrap(), vec![0, 1, 2], TextHint::Binary).unwrap(),
        ],
    )
        .unwrap();
    session.commit_to(&store).unwrap();
    let mut controller = VaultController::new(path);
    controller.unlock(&passphrase).unwrap();

    let draft = controller.load_secret(id).unwrap();
    assert!(matches!(draft.fields()[0].value(), EditableValue::Text(_)));
    assert!(matches!(draft.fields()[1].value(), EditableValue::Binary { .. }));
    assert!(matches!(draft.fields()[2].value(), EditableValue::Binary { .. }));
    assert!(!format!("{draft:?}").contains("fake-text-canary"));
}
```

- [ ] **Step 2: Run the draft test and verify RED**

Run: `cargo test -p ladon-app --test ui_state editor_loads_only_valid_utf8_as_text_and_redacts_debug --all-features`

Expected: compilation fails because the editor types and controller loader do not exist.

- [ ] **Step 3: Implement the sensitive editor model**

Create `secret_editor.rs` with these owned types. `EditableValue::Binary` keeps both the bytes and original hint so an unrelated text edit cannot alter a binary or invalid-UTF-8 field.

```rust
pub enum EditableValue {
    Text(SensitiveText),
    Binary {
        bytes: SensitiveBytes,
        original_hint: TextHint,
    },
}

pub struct EditableField {
    name: String,
    value: EditableValue,
}

pub struct EditSecretDraft {
    id: SecretId,
    name: String,
    fields: Vec<EditableField>,
}

```

Implement redacted `Debug`, read/mutable accessors, `from_parts`, `from_record`, `EditableField::{text, binary}`, `add_text_field`, `remove_field` with at least one field retained, and `to_fields`. `to_fields` parses every field name and copies bytes only into the short-lived core `PreparedRecordReplacement` created by the controller.

- [ ] **Step 4: Add controller load, prepare, and apply methods**

```rust
pub fn session_id(&self) -> Option<uuid::Uuid> {
    self.session_id
}

pub fn load_secret(&mut self, id: SecretId) -> Result<EditSecretDraft, LadonError> {
    let ManagedVault::Unlocked(session) = &mut self.state else {
        return Err(LadonError::VaultLocked);
    };
    session.with_record(&SecretRef::Id(id), EditSecretDraft::from_record)
}

pub fn prepare_secret_update(
    &self,
    draft: &EditSecretDraft,
) -> Result<PreparedRecordReplacement, LadonError> {
    let ManagedVault::Unlocked(session) = &self.state else {
        return Err(LadonError::VaultLocked);
    };
    session.prepare_record_replacement(
        &SecretRef::Id(draft.id()),
        draft.name(),
        draft.to_fields()?,
    )
}

pub fn apply_secret_update(
    &mut self,
    update: PreparedRecordReplacement,
) -> Result<(), LadonError> {
    let ManagedVault::Unlocked(session) = &mut self.state else {
        return Err(LadonError::VaultLocked);
    };
    session.apply_record_replacement(update)?;
    if let Err(error) = session.commit_to(&self.store) {
        self.state = ManagedVault::Locked;
        self.session_id = None;
        return Err(error);
    }
    Ok(())
}

pub fn ensure_secret_exists(&self, id: SecretId) -> Result<(), LadonError> {
    let ManagedVault::Unlocked(session) = &self.state else {
        return Err(LadonError::VaultLocked);
    };
    session
        .list()
        .iter()
        .any(|secret| secret.id == id)
        .then_some(())
        .ok_or(LadonError::SecretNotFound)
}
```

- [ ] **Step 5: Write failing persistence and revision tests**

Assert that a prepared update changes name and fields, preserves ID, survives reopen, and increments exactly once. Add a duplicate-name validation case proving the stored record and revision remain unchanged.

- [ ] **Step 6: Run UI/controller tests and verify GREEN**

Run: `cargo test -p ladon-app --test ui_state --all-features`

Expected: all UI-state tests PASS and canary values are absent from failure output.

- [ ] **Step 7: Commit the editor boundary**

```bash
git add crates/ladon-app/src/secret_editor.rs crates/ladon-app/src/lib.rs crates/ladon-app/src/ui.rs crates/ladon-app/tests/ui_state.rs
git commit -m "feat: add zeroizing secret editor state"
```

---

### Task 4: Per-secret grant invalidation and mutation serialization

**Files:**
- Modify: `crates/ladon-core/src/grants.rs`
- Test: `crates/ladon-core/tests/grants.rs`
- Modify: `crates/ladon-app/src/approval.rs`
- Modify: `crates/ladon-app/src/agent_broker.rs`
- Test: `crates/ladon-app/tests/approval_state.rs`
- Test: `crates/ladon-app/tests/agent_broker_unix.rs`

**Interfaces:**
- Consumes: `PreparedRecordReplacement`, `VaultController::{prepare_secret_update, apply_secret_update, delete_secret}`, `PendingApproval`, and the existing `approval -> controller` lock order.
- Produces: `GrantStore::revoke_secret`, `ApprovalCoordinator::coordinate_secret_mutation`, and `LocalBrokerHandle::{update_secret, delete_secret}`.

- [ ] **Step 1: Write and fail a targeted grant-revocation test**

```rust
#[test]
fn revoke_secret_removes_only_that_secret_across_clients() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock, Duration::from_secs(60));
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let changed = SecretId::new();
    let untouched = SecretId::new();
    grants.grant(first_client, [changed, untouched]);
    grants.grant(second_client, [changed]);

    grants.revoke_secret(changed);

    assert_eq!(grants.missing(first_client, [changed]), [changed]);
    assert!(grants.missing(first_client, [untouched]).is_empty());
    assert_eq!(grants.missing(second_client, [changed]), [changed]);
}
```

Run: `cargo test -p ladon-core --test grants revoke_secret --all-features`

Expected: compilation fails because `revoke_secret` is missing.

- [ ] **Step 2: Implement and pass targeted revocation**

```rust
pub fn revoke_secret(&mut self, secret_id: SecretId) {
    self.deadlines
        .retain(|(_, granted_secret_id), _| *granted_secret_id != secret_id);
}
```

Run: `cargo test -p ladon-core --test grants --all-features`

Expected: all grant tests PASS.

- [ ] **Step 3: Write failing coordinator tests**

Use the existing `request` and `wait_for_pending` helpers to exercise real coordinator threads.

```rust
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
                request(approved_client, &[(changed, "changed"), (untouched, "untouched")]),
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
        coordinator.coordinate_secret_mutation(changed, || Ok("prepared"), |value| Ok(value)),
        Ok("prepared")
    );
    assert_eq!(blocked.join().unwrap(), Err(LadonError::ApprovalCancelled));
    assert_eq!(
        coordinator.with_valid_grant(&changed_ticket, || Ok(())),
        Err(LadonError::ApprovalCancelled)
    );
    assert_eq!(coordinator.with_valid_grant(&untouched_ticket, || Ok(9)), Ok(9));
}
```

- [ ] **Step 4: Run coordinator tests and verify RED**

Run: `cargo test -p ladon-app --test approval_state secret_mutation --all-features`

Expected: compilation fails because the coordinator API is missing.

- [ ] **Step 5: Implement the canonical lock-order operation**

```rust
pub fn coordinate_secret_mutation<P, T>(
    &self,
    secret_id: SecretId,
    prepare: impl FnOnce() -> Result<P, LadonError>,
    commit: impl FnOnce(P) -> Result<T, LadonError>,
) -> Result<T, LadonError> {
    let mut state = self.lock_state()?;
    let prepared = prepare()?;
    if let Some(pending) = state.pending.as_mut()
        && pending
            .request
            .secrets()
            .iter()
            .any(|secret| secret.id() == secret_id)
    {
        pending.decision = Some(ApprovalDecision::Cancel);
        self.changed.notify_all();
    }
    state.grants.revoke_secret(secret_id);
    let result = commit(prepared);
    self.changed.notify_all();
    result
}
```

The `state` guard intentionally remains alive through `commit`; do not drop it early. Both closures may acquire the vault controller because the approval lock is already held.

- [ ] **Step 6: Route GUI update and delete through the broker handle**

```rust
pub fn update_secret(
    &self,
    controller: &Arc<Mutex<VaultController>>,
    draft: &EditSecretDraft,
) -> Result<(), LadonError> {
    self.approval.coordinate_secret_mutation(
        draft.id(),
        || controller.lock().map_err(|_| LadonError::ProcessFailure)?.prepare_secret_update(draft),
        |update| controller.lock().map_err(|_| LadonError::ProcessFailure)?.apply_secret_update(update),
    )
}
```

Add the delete entry point with the same lock order:

```rust
pub fn delete_secret(
    &self,
    controller: &Arc<Mutex<VaultController>>,
    id: SecretId,
) -> Result<(), LadonError> {
    self.approval.coordinate_secret_mutation(
        id,
        || controller.lock().map_err(|_| LadonError::ProcessFailure)?.ensure_secret_exists(id),
        |()| controller.lock().map_err(|_| LadonError::ProcessFailure)?.delete_secret(id),
    )
}
```

On non-Unix builds, call the controller directly because no agent broker is compiled there yet.

- [ ] **Step 7: Add the broker regression test**

Add a separate test so the existing active-run revocation scenario remains independent.

```rust
#[test]
fn edit_revokes_the_old_grant_before_future_use() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut initial = VaultController::new(directory.path().join("vault.ladon"));
    initial.create(&passphrase, &passphrase).unwrap();
    let mut added = AddSecretDraft::new();
    added.set_name("test-token");
    added.fields_mut()[0].value_mut().push_str("fake-broker-secret");
    let secret_id = initial.add_secret(&mut added).unwrap();
    let controller = Arc::new(Mutex::new(initial));
    let endpoint = directory.path().join("broker.sock");
    let server = LocalBrokerHandle::start_at(Arc::clone(&controller), &endpoint).unwrap();
    let client = LocalClient::new(&endpoint);
    let client_session_id = Uuid::new_v4();
    let run = || RpcMethod::Run {
        executable: "/bin/sh".to_owned(),
        arguments: vec!["-c".to_owned(), "printf %s \"$TOKEN\"".to_owned()],
        working_directory: directory.path().to_string_lossy().into_owned(),
        bindings: vec![SecretBindingRequest {
            secret_ref: "test-token".to_owned(),
            field: "value".to_owned(),
            target: BindingTarget::Environment { name: "TOKEN".to_owned() },
        }],
        timeout_ms: 5_000,
        output_limit_bytes: 64 * 1024,
    };

    let first_client = client.clone();
    let first_method = run();
    let first = thread::spawn(move || {
        first_client.call(&request_for(client_session_id, first_method))
    });
    let pending = wait_for_pending(&server);
    server.approve(pending.id()).unwrap();
    assert!(matches!(first.join().unwrap().unwrap().result(), Some(RpcResult::Run { .. })));

let mut edit = controller.lock().unwrap().load_secret(secret_id).unwrap();
let EditableValue::Text(value) = edit.fields_mut()[0].value_mut() else {
    panic!("expected text field");
};
value.clear();
value.push_str("fake-replacement-secret");
server.update_secret(&controller, &edit).unwrap();

    let retry_client = client.clone();
    let retry_method = run();
    let retry = thread::spawn(move || {
        retry_client.call(&request_for(client_session_id, retry_method))
    });
let pending = wait_for_pending(&server);
server.deny(pending.id()).unwrap();
let response = retry.join().unwrap().unwrap();
assert_eq!(
    response.error_details(),
    Some(("approval_denied", "agent request was denied"))
);
let debug = format!("{response:?}");
assert!(!debug.contains("fake-broker-secret"));
assert!(!debug.contains("fake-replacement-secret"));
}
```

- [ ] **Step 8: Run grant, approval, and broker tests and commit**

Run: `cargo test -p ladon-core --test grants --all-features`

Run outside restricted sandboxes when Unix socket creation is denied: `cargo test -p ladon-app --test approval_state --test agent_broker_unix --all-features`

Expected: all selected tests PASS.

```bash
git add crates/ladon-core/src/grants.rs crates/ladon-core/tests/grants.rs crates/ladon-app/src/approval.rs crates/ladon-app/src/agent_broker.rs crates/ladon-app/tests/approval_state.rs crates/ladon-app/tests/agent_broker_unix.rs
git commit -m "feat: invalidate grants when secrets change"
```

---

### Task 5: Pure selected-secret state machine

**Files:**
- Modify: `crates/ladon-app/src/secret_editor.rs`
- Modify: `crates/ladon-app/src/ui.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Test: `crates/ladon-app/tests/ui_state.rs`

**Interfaces:**
- Consumes: `EditSecretDraft`, `SecretId`, and vault-session UUIDs.
- Produces: `SecretDetailState`, `DetailMode`, `NavigationTarget`, `NavigationResult`, and `LocalAuthAttempt`.

- [ ] **Step 1: Write failing transition tests**

Cover these concrete transitions:

```rust
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

fn authorized_state() -> (SecretDetailState, Uuid, SecretId) {
    let session = Uuid::new_v4();
    let secret = SecretId::new();
    let mut state = SecretDetailState::default();
    state.navigate_now(NavigationTarget::Secret(secret));
    let attempt = state.authentication_attempt(session).unwrap();
    assert!(state.accept_authentication(attempt, session));
    (state, session, secret)
}

#[test]
fn authorization_is_bound_to_session_secret_and_selection_epoch() {
    let session = Uuid::new_v4();
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
    let (mut state, _, secret) = authorized_state();
    state.begin_edit(text_draft(secret)).unwrap();
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
    state.begin_reveal(text_draft(secret)).unwrap();
    state.hide_values();
    assert!(!state.has_sensitive_buffer());
    assert!(state.is_authorized(session));
}

#[test]
fn finishing_save_drops_the_editor_but_keeps_current_secret_authorized() {
    let (mut state, session, secret) = authorized_state();
    state.begin_edit(text_draft(secret)).unwrap();
    state.mark_dirty();
    state.finish_save();
    assert!(!state.has_sensitive_buffer());
    assert!(!state.is_editing());
    assert!(state.is_authorized(session));
}
```

- [ ] **Step 2: Run transition tests and verify RED**

Run: `cargo test -p ladon-app --test ui_state authorization_is_bound --all-features`

Expected: compilation fails because the state types are missing.

- [ ] **Step 3: Implement the minimal state machine**

Use these state shapes; `selection_epoch` increments on every applied navigation, including navigating away and back to the same ID.

```rust
pub enum DetailMode {
    Hidden,
    Revealed(EditSecretDraft),
    Editing { draft: EditSecretDraft, dirty: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavigationTarget {
    Add,
    Secret(SecretId),
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NavigationResult {
    Applied,
    ConfirmDiscard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAuthAttempt {
    vault_session_id: Uuid,
    secret_id: SecretId,
    selection_epoch: u64,
}

pub struct SecretDetailState {
    selected: Option<SecretId>,
    authorized: Option<LocalAuthAttempt>,
    selection_epoch: u64,
    mode: DetailMode,
    pending_navigation: Option<NavigationTarget>,
}
```

All transitions that discard a `Revealed` or `Editing` mode replace it with `Hidden` before changing selection so zeroizing fields drop immediately.

- [ ] **Step 4: Remove the obsolete timed reveal state**

Delete `REVEAL_MILLIS`, `RevealLease`, its export from `lib.rs`, and `reveal_lease_expires_after_ten_seconds`. The failing state tests above now specify the replacement lifecycle: reveal ends by explicit hide or navigation, not by a timer.

- [ ] **Step 5: Run UI-state tests and commit**

Run: `cargo test -p ladon-app --test ui_state --all-features`

Expected: all UI-state tests PASS.

```bash
git add crates/ladon-app/src/secret_editor.rs crates/ladon-app/src/ui.rs crates/ladon-app/src/lib.rs crates/ladon-app/tests/ui_state.rs
git commit -m "feat: model selected secret authorization"
```

---

### Task 6: Desktop secret detail, reveal, edit, and dual authentication

**Files:**
- Modify: `crates/ladon-app/src/desktop.rs`
- Modify: `crates/ladon-app/src/touch_id.rs`
- Modify: `crates/ladon-app/src/ui.rs`
- Test: inline tests in `crates/ladon-app/src/desktop.rs`

**Interfaces:**
- Consumes: Tasks 1--5 APIs, existing `sensitive_text_field`, `TouchIdAuthenticator`, `LocalBrokerHandle`, and `VaultUiPhase`.
- Produces: the complete user-visible workflow and stale-authentication rejection.

- [ ] **Step 1: Write failing desktop-state tests**

Define the desired capability helpers through these tests. Task 5 already covers stale attempts, navigation, and dirty-close decisions; Task 1 covers the fifth-failure lock decision.

```rust
#[test]
fn session_setup_requires_pin_only_when_touch_id_is_unavailable() {
    assert!(can_finish_session_setup(true, false));
    assert!(can_finish_session_setup(true, true));
    assert!(can_finish_session_setup(false, true));
    assert!(!can_finish_session_setup(false, false));
}

#[test]
fn protected_actions_offer_every_current_confirmation_capability() {
    assert_eq!(
        confirmation_actions(true, true),
        vec![ConfirmationAction::TouchId, ConfirmationAction::Pin]
    );
    assert_eq!(
        confirmation_actions(true, false),
        vec![ConfirmationAction::TouchId]
    );
    assert_eq!(
        confirmation_actions(false, true),
        vec![ConfirmationAction::Pin]
    );
    assert!(confirmation_actions(false, false).is_empty());
}
```

- [ ] **Step 2: Run desktop tests and verify RED**

Run: `cargo test -p ladon-app --lib desktop::tests --all-features`

Expected: compilation or assertion failure because the desktop still stores mutually exclusive `SessionAuthentication` and cached `touch_id_available`.

- [ ] **Step 3: Replace mutually exclusive authentication state**

Change `LadonDesktop` to own:

```rust
session_confirmation: Option<SessionConfirmation>,
detail: SecretDetailState,
local_pin: SensitiveText,
discard_confirmation: bool,
```

Remove `touch_id_available` and `SessionAuthentication`. The post-passphrase screen calls `TouchIdAuthenticator::is_available()` without storing its result. On a supported Mac it offers **Continue with Touch ID** and the optional 4--12 digit PIN fields; without Touch ID, only successful PIN setup can continue.

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfirmationAction {
    TouchId,
    Pin,
}

fn can_finish_session_setup(touch_id_available: bool, pin_configured: bool) -> bool {
    touch_id_available || pin_configured
}

fn confirmation_actions(
    touch_id_available: bool,
    pin_configured: bool,
) -> Vec<ConfirmationAction> {
    let mut actions = Vec::with_capacity(2);
    if touch_id_available {
        actions.push(ConfirmationAction::TouchId);
    }
    if pin_configured {
        actions.push(ConfirmationAction::Pin);
    }
    actions
}
```

- [ ] **Step 4: Render add versus selected-secret workspaces**

Keep the existing palette and type scale. Add **+ New secret** above the rail list. Selecting a secret renders its name, immutable ID, field names, and the constant mask `••••••••`; it does not load field bytes.

For an unauthorized selection render **Unlock this secret**. For an authorized hidden selection render **Show** and **Edit**. `Show` loads a draft and renders valid text values through a read-only Ladon `TextBuffer`, never `RichText` or `format!`; `Hide` drops the draft. `Edit` renders text fields with `sensitive_text_field`, binary fields as `Binary · N bytes`, and provides **Add field**, **Remove**, **Save changes**, and **Cancel**.

- [ ] **Step 5: Implement PIN and Touch ID action handling**

Every action captures `LocalAuthAttempt` before authentication. After success, compare its session UUID, secret ID, and selection epoch with current state before accepting it. Use action-specific Touch ID reasons:

```text
Unlock Ladon secret “<escaped name>” for viewing and editing
Allow this agent session to use the displayed Ladon secrets for 30 minutes
```

When both methods exist, render **Confirm with Touch ID** as the primary action and the PIN field plus **Confirm with PIN** as the alternative. A `PinVerification::LockVault` result calls the existing broker-aware immediate lock path and clears all GUI state.

- [ ] **Step 6: Make the agent approval window truly modal**

Use `egui::Modal` so the secret manager cannot accept clicks while a request is pending. Re-query Touch ID for that approval, allow either Touch ID or configured PIN, and bind successful authentication to the exact pending approval ID and current vault-session UUID before calling `approve`.

- [ ] **Step 7: Route save and delete through coordinated mutations**

On Unix call `LocalBrokerHandle::{update_secret, delete_secret}`. On non-Unix call the controller methods directly. After successful save, drop the editor buffer, retain selected authorization, and render the hidden card. After persistence failure, synchronize the locked phase immediately and clear every sensitive GUI field.

- [ ] **Step 8: Handle navigation and close events**

Before applying selection, **New secret**, or close, call `request_navigation`. If it returns `ConfirmDiscard`, render a modal with **Continue editing** and **Discard changes**. For a native close request with dirty state, send `egui::ViewportCommand::CancelClose`; after discard, send `ViewportCommand::Close`. `on_exit` remains the unconditional final wipe.

- [ ] **Step 9: Run desktop and focused integration tests**

Run: `cargo test -p ladon-app --lib desktop::tests --all-features`

Run: `cargo test -p ladon-app --test ui_state --test session_auth --all-features`

Expected: all selected tests PASS.

- [ ] **Step 10: Commit the GUI workflow**

```bash
git add crates/ladon-app/src/desktop.rs crates/ladon-app/src/touch_id.rs crates/ladon-app/src/ui.rs
git commit -m "feat: reveal and edit selected secrets"
```

---

### Task 7: Documentation, full verification, and packaged smoke test

**Files:**
- Modify: `README.md`
- Modify: `docs/security-review.md`
- Modify: `docs/threat-model.md`
- Modify: `docs/protocol.md`
- Modify: `docs/superpowers/plans/2026-09-05-secret-view-edit.md` checkbox state only

**Interfaces:**
- Consumes: the completed behavior from Tasks 1--6.
- Produces: accurate operator instructions and a verified release build.

- [ ] **Step 1: Update user and security documentation**

Document the 4--12 digit optional PIN, dual Touch ID/PIN choice, five-failure vault lock, selected-secret unlock lifecycle, explicit show/hide, atomic text editing, binary-field limitation, per-ID grant invalidation, stale Touch ID rejection, and unchanged value-free agent APIs. Remove claims that PIN and Touch ID are mutually exclusive or that reveal automatically expires after ten seconds.

- [ ] **Step 2: Scan documentation for contradictions**

Run:

```bash
rg -n '6--12|6–12|automatically hides.*ten seconds|choose Touch ID instead|session configured for Touch ID' README.md docs crates/ladon-app/src
```

Expected: no active product documentation or GUI copy contains the obsolete behavior; historical completed plans may retain their original wording.

- [ ] **Step 3: Run formatting and lint checks**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Expected: both commands exit 0 with no warnings.

- [ ] **Step 4: Run the complete automated test suite**

Run outside restricted sandboxes when local socket creation is denied: `cargo test --workspace --all-features`

Expected: every non-ignored test passes and there are zero failures.

- [ ] **Step 5: Build and launch the release GUI**

Run: `cargo build --release -p ladon-app --features gui`

Run: `./target/release/ladon-app`

Manually verify on macOS with a disposable secret:

1. unlock the vault and continue with Touch ID plus an optional four-digit PIN;
2. select the secret and confirm that only a constant mask is visible;
3. unlock it once with Touch ID, show/hide it, edit and save it;
4. switch away and back and confirm that authentication is required again;
5. confirm that either Touch ID or the configured PIN works;
6. verify that a previously granted agent session needs approval again after edit;
7. verify that closing with a dirty edit asks before discarding.

- [ ] **Step 6: Run a final secret-leak scan**

Use only synthetic canaries from tests. Run:

```bash
rg -n 'fake-text-canary|fake-broker-secret|fake-original-secret' target/debug target/release 2>/dev/null
```

Expected: canaries may occur in compiled test fixtures, but never in Ladon logs, generated documentation, IPC captures, or MCP output artifacts. Inspect any match outside compiled binaries before delivery.

- [ ] **Step 7: Commit documentation and verification notes**

```bash
git add README.md docs/security-review.md docs/threat-model.md docs/protocol.md docs/superpowers/plans/2026-09-05-secret-view-edit.md
git commit -m "docs: explain protected secret management"
```

- [ ] **Step 8: Review and land**

Invoke `superpowers:requesting-code-review`, resolve every Critical or Important finding through a fresh red-green cycle, rerun Steps 2--6, fetch `origin/main`, incorporate it without rewriting concurrent work, and push the verified commits to `origin/main`. Confirm the remote ref equals the landed commit SHA.
