# Stable Secret Form UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep selected-secret actions stationary and make add-secret fields visible, removable, tolerant of untouched optional rows, and precise about validation failures.

**Architecture:** Keep normalization and validation in the existing `AddSecretDraft` application model so GUI and direct controller calls agree, while retaining core validation as the final safety boundary. Add one form-local error value to the desktop and a visible sensitive-input helper that preserves the existing undo-history clearing. Reorder only the selected-card action rendering; do not change authentication or vault state.

**Tech Stack:** Rust 1.85, egui/eframe 0.32.3, existing `SensitiveText`/`zeroize`, Cargo workspace tests.

**Spec:** `docs/superpowers/specs/2026-09-12-secret-form-ux-design.md`

## Global Constraints

- Do not add dependencies or change the vault format, IPC schema, CLI syntax, MCP tools, PIN, Touch ID, or 30-minute timing.
- Keep secret bytes in `SensitiveText`; never log, format, clone, or include a secret value in an error.
- The add form alone shows newly entered plaintext; saved-secret reveal and edit authorization remain unchanged.
- Ignore only optional rows whose name is exactly empty and whose value has zero bytes; never trim secret values.
- Preserve the entire draft until persistence succeeds, and preserve existing fail-closed hard-lock behavior on persistence failure.
- Begin every behavior change with a focused failing test and keep commits task-scoped.

## File Structure

- `crates/ladon-app/src/ui.rs`: owns optional-row inclusion, removal, field validation, and controller preparation.
- `crates/ladon-app/src/desktop.rs`: owns local error lifetime, visible input rendering, field-row controls, and selected-card action order.
- `crates/ladon-app/tests/ui_state.rs`: verifies draft and controller behavior through the public application API.
- `docs/superpowers/specs/2026-09-12-secret-form-ux-design.md`: records accepted UX and security boundaries.
- `docs/superpowers/plans/2026-09-12-secret-form-ux.md`: records executable TDD steps and verification.

---

### Task 1: Optional-row semantics and contextual validation

**Files:**

- Modify: `crates/ladon-app/src/ui.rs`
- Test: `crates/ladon-app/src/ui.rs`
- Test: `crates/ladon-app/tests/ui_state.rs`

**Interfaces:**

- Consumes: `AddSecretDraft`, `DraftField`, `SensitiveText`, `FieldName::parse`, `MAX_FIELD_BYTES`, and `MAX_FIELDS_PER_RECORD`.
- Produces: `AddDraftValidationError`, `AddSecretDraft::{remove_field, can_add_field, validate_fields, included_fields}`, and controller filtering that uses `included_fields` without mutating the draft.

- [ ] **Step 1: Write failing draft and controller tests**

Add unit tests in `ui.rs` for the crate-private validation result and public behavior tests in `tests/ui_state.rs`:

```rust
fn unlocked_controller() -> (VaultController, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("vault.ladon");
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(path);
    controller.create(&passphrase, &passphrase).unwrap();
    (controller, directory)
}

#[test]
fn untouched_optional_fields_are_ignored_when_saved() {
    let (mut controller, _directory) = unlocked_controller();
    let mut draft = AddSecretDraft::new();
    draft.set_name("example");
    draft.fields_mut()[0].value_mut().push_str("fake-primary-value");
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
    draft.fields_mut()[1].value_mut().push_str("fake-removed-value");

    assert!(!draft.remove_field(0));
    assert!(draft.remove_field(1));
    assert_eq!(draft.fields().len(), 1);
    assert_eq!(draft.fields()[0].name(), "value");
}
```

In the `ui.rs` test module, add exact validation assertions:

```rust
#[test]
fn add_draft_validation_targets_the_displayed_field() {
    let mut draft = AddSecretDraft::new();
    draft.add_field();
    draft.fields_mut()[1].value_mut().push_str("fake-value");
    assert_eq!(
        draft.validate_fields(),
        Err(AddDraftValidationError::MissingName { field_index: 1 })
    );

    draft.fields_mut()[1].set_name("not valid");
    assert_eq!(
        draft.validate_fields(),
        Err(AddDraftValidationError::InvalidName { field_index: 1 })
    );

    draft.fields_mut()[1].set_name("value");
    assert_eq!(
        draft.validate_fields(),
        Err(AddDraftValidationError::DuplicateName { field_index: 1 })
    );
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo test -p ladon-app add_draft_validation_targets_the_displayed_field --all-features -- --nocapture
cargo test -p ladon-app --test ui_state untouched_optional_fields_are_ignored_when_saved --all-features -- --nocapture
cargo test -p ladon-app --test ui_state optional_fields_can_be_removed_but_the_primary_field_cannot --all-features -- --nocapture
```

Expected: compilation fails because the new validation and removal interfaces do not exist, and the existing controller rejects the untouched optional field.

- [ ] **Step 3: Implement the model without copying secret bytes during validation**

Import `HashSet`, `MAX_FIELD_BYTES`, and `MAX_FIELDS_PER_RECORD`. Add the crate-private result:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddDraftValidationError {
    MissingName { field_index: usize },
    InvalidName { field_index: usize },
    DuplicateName { field_index: usize },
    ValueTooLarge { field_index: usize },
}

impl AddDraftValidationError {
    const fn as_ladon_error(self) -> LadonError {
        match self {
            Self::MissingName { .. } | Self::InvalidName { .. } => {
                LadonError::InvalidFieldName
            }
            Self::DuplicateName { .. } => LadonError::DuplicateField,
            Self::ValueTooLarge { .. } => LadonError::FieldTooLarge,
        }
    }
}
```

Add helpers whose indices always refer to the visible `fields` vector:

```rust
impl DraftField {
    fn is_untouched(&self) -> bool {
        self.name.is_empty() && self.value.as_str().is_empty()
    }
}

impl AddSecretDraft {
    pub fn can_add_field(&self) -> bool {
        self.fields.len() < MAX_FIELDS_PER_RECORD
    }

    pub fn add_field(&mut self) {
        if self.can_add_field() {
            self.fields.push(DraftField {
                name: String::new(),
                value: SensitiveText::default(),
            });
        }
    }

    pub fn remove_field(&mut self, index: usize) -> bool {
        if index == 0 || index >= self.fields.len() {
            return false;
        }
        self.fields[index].value.clear();
        self.fields.remove(index);
        true
    }

    fn included_fields(&self) -> impl Iterator<Item = (usize, &DraftField)> {
        self.fields
            .iter()
            .enumerate()
            .filter(|(index, field)| *index == 0 || !field.is_untouched())
    }
}
```

Implement validation by iterating `included_fields()` once. Do not clone, expose, format, or compare field values beyond `as_str().len()`:

```rust
pub(crate) fn validate_fields(&self) -> Result<(), AddDraftValidationError> {
    let mut names = HashSet::new();
    for (field_index, field) in self.included_fields() {
        if field_index > 0 && field.name().is_empty() {
            return Err(AddDraftValidationError::MissingName { field_index });
        }
        let name = FieldName::parse(field.name())
            .map_err(|_| AddDraftValidationError::InvalidName { field_index })?;
        if field.value().as_str().len() > MAX_FIELD_BYTES {
            return Err(AddDraftValidationError::ValueTooLarge { field_index });
        }
        if !names.insert(name) {
            return Err(AddDraftValidationError::DuplicateName { field_index });
        }
    }
    Ok(())
}
```

On the same error type, add the index accessor used later by the renderer:

```rust
pub(crate) const fn field_index(self) -> usize {
    match self {
        Self::MissingName { field_index }
        | Self::InvalidName { field_index }
        | Self::DuplicateName { field_index }
        | Self::ValueTooLarge { field_index } => field_index,
    }
}
```

Change `VaultController::add_secret` to map the contextual application error back to the existing core error API and build `SecretField`s only from the immutable filtered iterator:

```rust
draft
    .validate_fields()
    .map_err(AddDraftValidationError::as_ladon_error)?;
let fields = draft
    .included_fields()
    .map(|(_, field)| {
        SecretField::new(
            FieldName::parse(field.name())?,
            field.value().to_sensitive_bytes().expose(<[u8]>::to_vec),
            TextHint::Text,
        )
    })
    .collect::<Result<Vec<_>, LadonError>>()?;
```

Keep `*draft = AddSecretDraft::new()` after a successful commit only; do not prune the draft in place.

- [ ] **Step 4: Add boundary tests**

Test all remaining semantics:

```rust
#[test]
fn whitespace_is_not_an_untouched_optional_field() {
    let mut draft = AddSecretDraft::new();
    draft.add_field();
    draft.fields_mut()[1].set_name(" ");
    assert_eq!(
        draft.validate_fields(),
        Err(AddDraftValidationError::InvalidName { field_index: 1 })
    );
}

#[test]
fn add_draft_stops_at_the_core_field_limit() {
    let mut draft = AddSecretDraft::new();
    for _ in 1..MAX_FIELDS_PER_RECORD {
        draft.add_field();
    }
    assert!(!draft.can_add_field());
    draft.add_field();
    assert_eq!(draft.fields().len(), MAX_FIELDS_PER_RECORD);
}
```

Construct a value of `MAX_FIELD_BYTES + 1` bytes and assert `ValueTooLarge { field_index: 0 }`. Also assert a completely untouched optional row followed by an invalid row reports the latter's original visible index rather than its filtered position.

Add a controller test with an invalid secret name, one populated primary row, and one untouched optional row. Assert `add_secret` returns `InvalidSecretRef` and both rows—including the fake primary value—remain in the draft, proving filtering does not mutate the form before persistence succeeds.

- [ ] **Step 5: Run focused verification**

Run:

```bash
cargo test -p ladon-app add_draft --all-features -- --nocapture
cargo test -p ladon-app --test ui_state --all-features -- --nocapture
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: all tests pass and Clippy reports no warnings.

- [ ] **Step 6: Commit the draft behavior**

```bash
git add crates/ladon-app/src/ui.rs crates/ladon-app/tests/ui_state.rs
git commit -m "fix: make optional secret fields forgiving"
```

---

### Task 2: Visible entry, removable rows, and scoped errors

**Files:**

- Modify: `crates/ladon-app/src/desktop.rs`
- Test: `crates/ladon-app/src/desktop.rs`

**Interfaces:**

- Consumes: Task 1's `AddDraftValidationError` and `AddSecretDraft::{remove_field, can_add_field, validate_fields}`.
- Produces: `LadonDesktop::add_form_error`, `visible_sensitive_text_field`, contextual error copy, deferred row removal, and navigation-scoped notices.

- [ ] **Step 1: Write failing helper and lifecycle tests**

Add tests to the existing `desktop.rs` test module:

```rust
#[test]
fn visible_sensitive_widget_does_not_retain_undo_history() {
    let context = egui::Context::default();
    let mut value = SensitiveText::from("fake-visible-secret");
    let mut widget_id = None;
    let _ = context.run(egui::RawInput::default(), |context| {
        egui::CentralPanel::default().show(context, |ui| {
            widget_id = Some(
                visible_sensitive_text_field(ui, &mut value, "Secret value", 230.0).id,
            );
        });
    });
    let state = TextEdit::load_state(&context, widget_id.unwrap()).unwrap();
    let current = (
        state.cursor.char_range().unwrap_or_default(),
        value.as_str().to_owned(),
    );
    assert!(!state.undoer().has_undo(&current));
}

#[test]
fn add_form_error_copy_identifies_the_visible_row() {
    assert_eq!(
        add_form_error_text(AddDraftValidationError::MissingName { field_index: 1 }),
        "Field 2: enter a name or remove this field"
    );
    assert_eq!(
        add_form_error_text(AddDraftValidationError::DuplicateName { field_index: 2 }),
        "Field 3: this name is already used"
    );
}
```

On Unix, reuse `app_with_sensitive_detail(false)` for the navigation lifecycle assertion:

```rust
#[cfg(unix)]
#[test]
fn applied_navigation_clears_form_feedback() {
    let (mut app, _endpoint, _directory) = app_with_sensitive_detail(false);
    app.add_form_error = Some(AddDraftValidationError::InvalidName { field_index: 1 });
    app.notice = Some(Notice {
        text: "stale feedback".to_owned(),
        danger: true,
    });

    app.request_navigation(NavigationTarget::Add);

    assert!(app.add_form_error.is_none());
    assert!(app.notice.is_none());
}
```

The production cleanup helper must run only for `NavigationResult::Applied`, not when navigation returns `ConfirmDiscard`.

- [ ] **Step 2: Run the desktop tests and confirm RED**

Run:

```bash
cargo test -p ladon-app --lib desktop::tests::visible_sensitive_widget_does_not_retain_undo_history --all-features -- --nocapture
cargo test -p ladon-app --lib desktop::tests::add_form_error_copy_identifies_the_visible_row --all-features -- --nocapture
cargo test -p ladon-app --lib desktop::tests::applied_navigation_clears_form_feedback --all-features -- --nocapture
```

Expected: compilation fails because the helper, local error state, and copy mapper do not exist.

- [ ] **Step 3: Add visible sensitive input without undo retention**

Factor the existing widget-state cleanup into a shared helper and keep password inputs unchanged:

```rust
fn sensitive_text_edit(
    ui: &mut egui::Ui,
    value: &mut SensitiveText,
    hint: &str,
    width: f32,
    password: bool,
) -> egui::Response {
    let mut output = TextEdit::singleline(value)
        .password(password)
        .hint_text(hint)
        .desired_width(width)
        .show(ui);
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
    output.response
}
```

Keep `sensitive_text_field` as the `password: true` wrapper and add `visible_sensitive_text_field` as the `password: false` wrapper. Use the visible wrapper only in `show_add_workspace`, with `Secret value` as the placeholder. Do not change PIN, passphrase, reveal, or edit widgets.

- [ ] **Step 4: Render optional-row removal and field-local errors safely**

Add `add_form_error: Option<AddDraftValidationError>` to `LadonDesktop`, initialize it to `None`, add it to every test-only `LadonDesktop` struct literal, and clear it from both sensitive-state clearing paths.

In `show_add_workspace`, copy the current error before borrowing `self.draft.fields_mut()`. Accumulate `changed: bool` and `remove_index: Option<usize>` while rendering. Show a compact `×` button with `on_hover_text("Remove field")` only for `index > 0`; defer `self.draft.remove_field(index)` until after the mutable iteration. This avoids mutating the vector while it is borrowed and ensures the removed value is zeroized by Task 1.

Use this control-flow shape so no vector mutation occurs during iteration:

```rust
let current_error = self.add_form_error;
let mut changed = false;
let mut remove_index = None;
for (index, field) in self.draft.fields_mut().iter_mut().enumerate() {
    changed |= ui
        .add(
            TextEdit::singleline(field.name_mut())
                .hint_text("field_name")
                .desired_width(120.0),
        )
        .changed();
    changed |= visible_sensitive_text_field(ui, field.value_mut(), "Secret value", 230.0)
        .changed();
    if index > 0 && quiet_button(ui, "×").on_hover_text("Remove field").clicked() {
        remove_index = Some(index);
    }
    if let Some(error) = current_error.filter(|error| error.field_index() == index) {
        ui.label(RichText::new(add_form_error_text(error)).color(DANGER));
    }
}
if let Some(index) = remove_index {
    changed |= self.draft.remove_field(index);
}
if changed {
    self.add_form_error = None;
    self.notice = None;
}
```

Use Task 1's `field_index` accessor to support this rendering without string inspection. Map variants to static, non-secret-bearing copy:

```rust
fn add_form_error_text(error: AddDraftValidationError) -> String {
    let field = error.field_index() + 1;
    let detail = match error {
        AddDraftValidationError::MissingName { .. } => {
            "enter a name or remove this field"
        }
        AddDraftValidationError::InvalidName { .. } => {
            "start with a letter; then use letters, numbers, _ or -"
        }
        AddDraftValidationError::DuplicateName { .. } => "this name is already used",
        AddDraftValidationError::ValueTooLarge { .. } => "value exceeds 1 MiB",
    };
    format!("Field {field}: {detail}")
}
```

Render `add_form_error_text(error)` in `DANGER` directly below the matching row. Clear `add_form_error` after any changed name/value response, add click, or remove click. Disable `+ Add field` when `!self.draft.can_add_field()`.

On Save, run `self.draft.validate_fields()` first. Store its error locally without calling the controller. Only a valid draft reaches `controller.add_secret`; `handle_add_result` clears the local error on success, and app/vault lock clearing paths also set it to `None`.

- [ ] **Step 5: Scope stale feedback to its screen**

Extract the cleanup currently performed for `NavigationResult::Applied` into `finish_applied_navigation()` and add:

```rust
self.add_form_error = None;
self.notice = None;
```

Call it only after applied navigation, never while a dirty edit awaits discard confirmation. Keep successful `Secret saved locally` feedback visible on the add form until the next interaction or applied navigation.

- [ ] **Step 6: Run focused verification**

Run:

```bash
cargo test -p ladon-app --lib desktop::tests --all-features -- --nocapture
cargo test -p ladon-app --test ui_state --all-features -- --nocapture
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: all tests pass, the original masked-widget undo test still passes, and Clippy reports no warnings.

- [ ] **Step 7: Commit the add-form UI**

```bash
git add crates/ladon-app/src/desktop.rs
git commit -m "fix: clarify secret field entry errors"
```

---

### Task 3: Stable selected-secret action row and release verification

**Files:**

- Modify: `crates/ladon-app/src/desktop.rs`
- Test: `crates/ladon-app/src/desktop.rs`
- Verify: `README.md`, `docs/threat-model.md`, and `docs/protocol.md` remain accurate; modify only if behavior described there becomes false.

**Interfaces:**

- Consumes: existing `DetailMode`, `DetailAction`, authorization state, and selected-secret confirmation flow.
- Produces: a selected-card action row before all field rendering, with no authentication or lifetime changes.

- [ ] **Step 1: Write a failing action-order regression test**

Extract a pure ordering helper rather than snapshot-testing pixels:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectedActionSet {
    Unlock,
    Hidden,
    Revealed,
    Editing,
}

fn selected_action_set(authorized: bool, mode: &DetailMode) -> SelectedActionSet;
```

Implement it with the existing mode as the only state input:

```rust
fn selected_action_set(authorized: bool, mode: &DetailMode) -> SelectedActionSet {
    match (authorized, mode) {
        (_, DetailMode::Editing { .. }) => SelectedActionSet::Editing,
        (false, _) => SelectedActionSet::Unlock,
        (true, DetailMode::Hidden) => SelectedActionSet::Hidden,
        (true, DetailMode::Revealed(_)) => SelectedActionSet::Revealed,
    }
}
```

Test the states:

```rust
#[test]
fn selected_action_set_is_independent_of_field_count() {
    let hidden = DetailMode::Hidden;
    assert_eq!(selected_action_set(false, &hidden), SelectedActionSet::Unlock);
    assert_eq!(selected_action_set(true, &hidden), SelectedActionSet::Hidden);

    let revealed = DetailMode::Revealed(EditSecretDraft::from_parts(
        SecretId::new(),
        "example",
        vec![],
    ));
    assert_eq!(selected_action_set(true, &revealed), SelectedActionSet::Revealed);
}
```

The helper deliberately accepts no field count, so field cardinality cannot influence action placement.

- [ ] **Step 2: Run the focused test and confirm RED**

Run:

```bash
cargo test -p ladon-app --lib desktop::tests::selected_action_set_is_independent_of_field_count --all-features -- --nocapture
```

Expected: compilation fails because `SelectedActionSet` and `selected_action_set` do not exist.

- [ ] **Step 3: Render actions before fields**

In `show_selected_workspace`, retain the title/delete header, separator, and edit-mode behavior. For non-editing modes, render one action row immediately after the separator and before the first field:

- `Unlock`: primary `Unlock this secret`;
- `Hidden`: primary `Show`, quiet `Edit`;
- `Revealed`: the existing `Hide` action.

Keep the row's spacing and height identical across these states. Field loops render after this row. Remove the old unlock/show/edit/hide controls below the field loops. Continue dispatching the same `DetailAction` values and opening the same confirmation modal; do not touch grant duration or authentication code.

Use one pre-field dispatch block and leave editing controls in their existing editor block:

```rust
if !editing {
    ui.horizontal(|ui| match selected_action_set(authorized, self.detail.mode()) {
        SelectedActionSet::Unlock => {
            if primary_button(ui, "Unlock this secret").clicked() {
                self.unlock_confirmation = true;
                self.local_pin.clear();
            }
        }
        SelectedActionSet::Hidden => {
            if primary_button(ui, "Show").clicked() {
                action = Some(DetailAction::Show);
            }
            if quiet_button(ui, "Edit").clicked() {
                action = Some(DetailAction::Edit);
            }
        }
        SelectedActionSet::Revealed => {
            if quiet_button(ui, "Hide").clicked() {
                action = Some(DetailAction::Hide);
            }
        }
        SelectedActionSet::Editing => {}
    });
    ui.add_space(14.0);
}
```

- [ ] **Step 4: Run automated regression checks**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
scripts/smoke-test.sh
cargo build --workspace --all-features --release
```

Expected: formatting and lint pass, all tests and the smoke script pass, and release binaries build.

- [ ] **Step 5: Perform macOS acceptance checks with fake secrets**

Launch `target/release/ladon-app` and verify all seven acceptance checks in the spec using values prefixed with `fake-`. Additionally verify:

1. Touch ID and PIN still unlock the selected secret in one confirmation flow.
2. Switching among locked one-field and multi-field secrets keeps the unlock action fixed.
3. The add form shows typed plaintext, uses `Secret value`, ignores untouched optional rows, and removes only the chosen optional row.
4. Invalid, duplicate, and oversized fields point to the visible row; editing or leaving the form removes the message.
5. Lock app, unlock app, full vault lock, reveal, edit, delete, CLI execution, and MCP smoke behavior remain unchanged.

Expected: no secret value appears in terminal output, application logs, error text, or test failure output.

- [ ] **Step 6: Commit the stable action row**

```bash
git add crates/ladon-app/src/desktop.rs
git commit -m "fix: stabilize selected secret actions"
```

- [ ] **Step 7: Synchronize and land the exact verified tree**

Fetch `origin/main`, incorporate it without rewriting concurrent work, rerun Step 4 on the exact result, and add one current-month work-report row only if `reports/2026-09-work-report.md` already exists at that point. Commit any required report update, push the verified commits to `origin/main`, and confirm the remote ref contains the landed SHA.
