# Soft App Lock and One-Step Unlock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a memory-only app lock that denies GUI and agent access but unlocks with one Touch ID click or the current session PIN, while preserving the existing hard vault lock and compacting the requested visual states.

**Architecture:** Extend `ApprovalCoordinator` with a value-free access gate and monotonic lock epoch, then let `LocalBrokerHandle` coordinate app lock with the existing run and external-lock coordinators. The desktop mirrors that state only for presentation, clears its plaintext buffers immediately, and reopens broker access only after locally authenticated Touch ID or PIN success. Full vault lock remains the fallback and the only behavior exposed through MCP `lock`.

**Tech Stack:** Rust 1.85, egui/eframe 0.32.3, existing `std::sync` primitives, existing Argon2id session PIN verifier, macOS LocalAuthentication adapter, Cargo workspace tests.

**Spec:** `docs/superpowers/specs/2026-09-07-soft-app-lock-design.md`

## Global Constraints

- Keep the vault passphrase as the only credential that decrypts the portable vault.
- Keep the unlocked vault's original 30-minute idle deadline; app lock and app unlock must not reset or extend it.
- Keep the 4--12 ASCII digit PIN, five-failure hard-lock policy, and strict biometric-only Touch ID policy unchanged.
- Do not add Keychain, Secure Enclave, DPAPI, Credential Manager, Secret Service, a daemon, or any new runtime dependency.
- Do not change the vault format, IPC schema, CLI syntax, or MCP tool schema.
- MCP `lock`, idle expiry, process exit, detectable OS lock/logout/suspend, and emergency fallback remain hard vault locks.
- While app access is closed, broker `list` and `run` fail with `vault_locked`; `status` reports `locked` with no idle duration; MCP `lock` remains callable.
- Never return, log, format, or persist a managed value, passphrase, PIN, verifier, or Touch ID material.
- Preserve the established lock order: approval coordinator, run coordinator, then vault controller.

## File Structure

- `crates/ladon-app/src/approval.rs`: owns the value-free broker access gate, epoch, grant cancellation, and stale-transition rejection.
- `crates/ladon-app/src/agent_broker.rs`: coordinates non-blocking app-lock startup, run cancellation/wait, broker admission, hard-lock reset, and status behavior.
- `crates/ladon-app/src/desktop.rs`: owns the presentation state, buffer clearing, one-click unlock flow, PIN fallback, and compact visual polish.
- `crates/ladon-app/src/touch_id.rs`: adds the app-unlock-specific LocalAuthentication reason while retaining the existing adapter policy.
- `crates/ladon-app/src/lib.rs`: exports only the gate state needed by integration tests and neighboring modules.
- `crates/ladon-app/tests/approval_state.rs`: deterministic access-gate, grant, and epoch tests.
- `crates/ladon-app/tests/agent_broker_unix.rs`: Unix socket behavior for app-locked status/list/run and hard MCP lock.
- `README.md`, `docs/protocol.md`, `docs/threat-model.md`: user behavior and security-boundary documentation.

---

### Task 1: Value-free app access gate

**Files:**

- Modify: `crates/ladon-app/src/approval.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Test: `crates/ladon-app/tests/approval_state.rs`

**Interfaces:**

- Consumes: existing `ApprovalCoordinator`, `GrantStore`, `PendingState`, and `LadonError::{Busy, InvalidRequest, VaultLocked, ApprovalCancelled}`.
- Produces: `AppAccessState`, `ApprovalCoordinator::{app_access_state, require_app_active, begin_app_lock, finish_app_lock, unlock_app, reset_after_vault_lock}`.

- [ ] **Step 1: Write failing state-transition tests**

Add imports and tests that exercise exact epochs and forbidden transitions:

```rust
use ladon_app::{AppAccessState, ApprovalCoordinator};

#[test]
fn app_access_gate_rejects_stale_and_overlapping_transitions() {
    let coordinator = ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    );

    assert_eq!(coordinator.app_access_state().unwrap(), AppAccessState::Active);
    let first = coordinator.begin_app_lock().unwrap();
    assert_eq!(
        coordinator.app_access_state().unwrap(),
        AppAccessState::Locking { epoch: first }
    );
    assert_eq!(coordinator.begin_app_lock(), Err(LadonError::Busy));
    assert_eq!(
        coordinator.finish_app_lock(first.wrapping_add(1)),
        Err(LadonError::InvalidRequest)
    );

    coordinator.finish_app_lock(first).unwrap();
    assert_eq!(
        coordinator.app_access_state().unwrap(),
        AppAccessState::Locked { epoch: first }
    );
    assert_eq!(
        coordinator.unlock_app(first.wrapping_add(1)),
        Err(LadonError::InvalidRequest)
    );
    coordinator.unlock_app(first).unwrap();
    assert_eq!(coordinator.app_access_state().unwrap(), AppAccessState::Active);
}

#[test]
fn hard_lock_reset_invalidates_a_soft_lock_epoch() {
    let coordinator = ApprovalCoordinator::new(
        FakeClock::new(),
        Duration::from_secs(30 * 60),
        Duration::from_secs(2),
    );
    let epoch = coordinator.begin_app_lock().unwrap();
    coordinator.finish_app_lock(epoch).unwrap();
    coordinator.reset_after_vault_lock().unwrap();

    assert_eq!(coordinator.app_access_state().unwrap(), AppAccessState::Active);
    assert_eq!(
        coordinator.unlock_app(epoch),
        Err(LadonError::InvalidRequest)
    );
}
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo test -p ladon-app --test approval_state app_access_gate -- --nocapture
cargo test -p ladon-app --test approval_state hard_lock_reset -- --nocapture
```

Expected: compilation fails because `AppAccessState` and the transition methods do not exist.

- [ ] **Step 3: Implement the gate and monotonic epoch**

Add the state beside `ApprovalState`, store it in the same mutex, and initialize it as active:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppAccessState {
    Active,
    Locking { epoch: u64 },
    Locked { epoch: u64 },
}

struct ApprovalState<C> {
    grants: GrantStore<C>,
    vault_session_id: Option<Uuid>,
    pending: Option<PendingState>,
    app_access: AppAccessState,
    lock_epoch: u64,
}
```

Implement the exact transition rules:

```rust
pub fn app_access_state(&self) -> Result<AppAccessState, LadonError>;
pub fn require_app_active(&self) -> Result<(), LadonError>;
pub fn begin_app_lock(&self) -> Result<u64, LadonError>;
pub fn finish_app_lock(&self, epoch: u64) -> Result<(), LadonError>;
pub fn unlock_app(&self, epoch: u64) -> Result<(), LadonError>;
pub fn reset_after_vault_lock(&self) -> Result<(), LadonError>;
```

`begin_app_lock` accepts only `Active`, increments with `checked_add`, switches to `Locking`, marks a pending approval `Cancel`, revokes all grants, and notifies the condition variable before returning the epoch. `finish_app_lock` accepts only the matching `Locking` epoch. `unlock_app` accepts only the matching `Locked` epoch. `reset_after_vault_lock` increments the epoch, cancels pending approval, revokes grants, clears `vault_session_id`, and restores `Active`; callers invoke it only after the controller is cryptographically locked.

In `authorize`, check the private predicate immediately after acquiring the existing state mutex and return `VaultLocked` when it is false. Make `with_valid_grant` reject a non-active gate with `ApprovalCancelled` before executing its closure. `require_app_active` is for callers that do not already hold the coordinator mutex; avoid recursive locking by using a small private predicate internally:

```rust
fn is_app_active<C>(state: &ApprovalState<C>) -> bool {
    state.app_access == AppAccessState::Active
}
```

Export `AppAccessState` from `lib.rs` with the existing approval types.

- [ ] **Step 4: Add cancellation and grant-recheck tests**

Create one pending authorization in a worker thread, call `begin_app_lock`, and assert that the worker returns `ApprovalCancelled` and `pending()` becomes `None`. Create a granted `GrantTicket`, enter app lock, and assert `with_valid_grant` returns `ApprovalCancelled` without calling its closure. Finally assert a new `authorize` call while `Locked` returns `VaultLocked` immediately and creates no pending request.

- [ ] **Step 5: Run the approval suite and lint the touched crate**

Run:

```bash
cargo test -p ladon-app --test approval_state -- --nocapture
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: all approval tests pass and Clippy reports no warning.

- [ ] **Step 6: Commit the access gate**

```bash
git add crates/ladon-app/src/approval.rs crates/ladon-app/src/lib.rs crates/ladon-app/tests/approval_state.rs
git commit -m "feat: add app access gate"
```

---

### Task 2: Broker coordination and fail-closed RPC behavior

**Files:**

- Modify: `crates/ladon-app/src/agent_broker.rs`
- Test: `crates/ladon-app/src/agent_broker.rs`

**Interfaces:**

- Consumes: Task 1's gate transitions and the existing `RunCoordinator`, `UiLockCoordinator`, `LocalBrokerHandle`, and `lock_controller_and_runs` order.
- Produces: `AppLockAttempt::{epoch, try_result}`, `LocalBrokerHandle::{begin_app_lock, unlock_app}`, and broker-wide app-lock admission checks.

- [ ] **Step 1: Write failing non-blocking coordination tests**

In the internal `agent_broker.rs` test module, hold a `RunLease` with a cancellation token, call `LocalBrokerHandle::begin_app_lock`, and assert all of these without using timing as the synchronization primitive:

```rust
let attempt = handle.begin_app_lock().unwrap();
assert!(cancellation.is_cancelled());
assert!(attempt.try_result().is_none());
drop(run_lease);
wait_for_app_lock_result(&attempt).unwrap();
assert_eq!(
    handle.approval.app_access_state().unwrap(),
    AppAccessState::Locked { epoch: attempt.epoch() }
);
```

Use a channel/barrier to prove the lease is established before beginning the lock and a one-second deadline only as a failure bound. Add a second test proving `unlock_app` accepts the completed epoch and rejects a stale epoch.

- [ ] **Step 2: Run the internal tests and confirm RED**

Run:

```bash
cargo test -p ladon-app agent_broker::tests::app_lock -- --nocapture
```

Expected: compilation fails because `AppLockAttempt` and `begin_app_lock` do not exist.

- [ ] **Step 3: Implement asynchronous app-lock completion**

Add an internal result handle patterned after `TouchIdAttempt`:

```rust
pub(crate) struct AppLockAttempt {
    epoch: u64,
    result: Receiver<Result<(), LadonError>>,
}

impl AppLockAttempt {
    pub(crate) const fn epoch(&self) -> u64 { self.epoch }
    pub(crate) fn try_result(&self) -> Option<Result<(), LadonError>>;
}
```

`LocalBrokerHandle::begin_app_lock` must:

1. acquire `UiLocalOperation`, returning `Busy` if an external hard lock owns the transition;
2. call `approval.begin_app_lock()` so list/run admission closes synchronously;
3. call `coordinator.cancel_active()`;
4. spawn a named `ladon-app-lock` worker that obtains `block_new_runs()`, waits for the active lease to drop, calls `approval.finish_app_lock(epoch)`, explicitly drops `UiLocalOperation`, then publishes its result; and
5. return immediately with `AppLockAttempt`.

Use these signatures:

```rust
pub(crate) fn begin_app_lock(&self) -> Result<AppLockAttempt, LadonError>;
pub(crate) fn unlock_app(&self, epoch: u64) -> Result<(), LadonError>;
```

If thread creation fails, return `ProcessFailure` and leave the gate closed so the desktop can hard-lock. A disconnected result channel also maps to `ProcessFailure`.

- [ ] **Step 4: Gate every relevant RPC path**

Change `AgentBroker::handle_method` as follows:

```rust
RpcMethod::Status => {
    if self.approval.app_access_state()? != AppAccessState::Active {
        return Ok(RpcResult::Status {
            state: "locked".to_owned(),
            idle_remaining_ms: None,
        });
    }
    let controller = self.controller()?;
    Ok(RpcResult::Status {
        state: phase_name(controller.phase()).to_owned(),
        idle_remaining_ms: controller.remaining_unlocked().map(duration_millis),
    })
}
```

At the first line of the `List` arm, insert `self.approval.require_app_active()?;`. At the first line of the `Run` arm, insert the same check; insert it again immediately after `self.coordinator.try_start(cancellation.clone())?` returns the `RunLease`. Keep `RpcMethod::Lock` outside the gate. `authorize` and `with_valid_grant` from Task 1 supply the final checks for races occurring after run admission.

After every successful controller hard lock in `lock_controller_and_runs` and `auto_lock_controller_if_idle`, call `approval.reset_after_vault_lock()` before releasing the run block. Do not reopen the gate if the controller mutex or controller lock fails.

- [ ] **Step 5: Add Unix socket behavior tests inside the broker module**

Inside `agent_broker.rs`, where crate-private app-lock methods are accessible, start a desktop broker around an unlocked test vault, finish an app lock, and assert:

```rust
assert_eq!(controller.lock().unwrap().phase(), VaultUiPhase::Unlocked);
assert!(matches!(
    status.result(),
    Some(RpcResult::Status { state, idle_remaining_ms: None }) if state == "locked"
));
assert_eq!(list.error_details(), Some(("vault_locked", "vault is locked")));
assert_eq!(plain_run.error_details(), Some(("vault_locked", "vault is locked")));
```

Unlock with the captured epoch and verify list succeeds but prior grants are gone. Enter app lock again, invoke MCP `lock`, verify the controller becomes `VaultUiPhase::Locked`, and verify `unlock_app` with the old epoch returns `InvalidRequest`.

- [ ] **Step 6: Run focused and full broker tests**

Run:

```bash
cargo test -p ladon-app agent_broker::tests::app_lock -- --nocapture
cargo test -p ladon-app --test agent_broker_unix -- --nocapture
cargo test -p ladon-app --test runner_integration -- --nocapture
```

Expected: all tests pass without a sleep-based success assertion or plaintext in debug output.

- [ ] **Step 7: Commit broker coordination**

```bash
git add crates/ladon-app/src/agent_broker.rs
git commit -m "feat: coordinate broker app locking"
```

---

### Task 3: Desktop lock lifecycle and immediate value clearing

**Files:**

- Modify: `crates/ladon-app/src/desktop.rs`
- Test: `crates/ladon-app/src/desktop.rs`

**Interfaces:**

- Consumes: Task 2's `AppLockAttempt`, `LocalBrokerHandle::begin_app_lock`, and matching epoch.
- Produces: `DesktopLockState`, separate soft/hard clearing paths, manager **Lock app**, value-free locking/locked screens, and hard-lock fallback.

- [ ] **Step 1: Write failing desktop state and clearing tests**

Add a private presentation enum:

```rust
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DesktopLockState {
    #[default]
    Active,
    Locking { epoch: u64 },
    Locked { epoch: u64 },
}
```

Extend the existing sensitive-detail fixture, call `clear_for_app_lock`, and assert:

```rust
let vault_session_id = app.vault_session_id().unwrap();
app.clear_for_app_lock();

assert_eq!(app.vault_session_id().unwrap(), vault_session_id);
assert!(app.session_confirmation.is_some());
assert!(app.draft.name().is_empty());
assert!(app.local_pin.as_str().is_empty());
assert!(app.detail.selected().is_none());
assert!(!app.detail.has_sensitive_buffer());
assert!(app.pending_touch_id.is_none());
assert!(app.focused_approval.is_none());
assert!(!app.unlock_confirmation);
assert!(!app.discard_confirmation);
assert!(app.pending_delete.is_none());
```

Retain the existing hard-lock assertions that `clear_sensitive_state` also removes `session_confirmation`, passphrase/PIN setup fields, and every app-lock attempt/state.

- [ ] **Step 2: Run the desktop clearing tests and confirm RED**

Run:

```bash
cargo test -p ladon-app desktop::tests::app_lock_clears -- --nocapture
cargo test -p ladon-app desktop::tests::leaving_unlocked_clears -- --nocapture
```

Expected: the new test fails to compile because `DesktopLockState` and `clear_for_app_lock` do not exist.

- [ ] **Step 3: Split soft and hard cleanup**

Add fields to `LadonDesktop`:

```rust
desktop_lock: DesktopLockState,
desktop_lock_epoch: u64,
#[cfg(unix)]
pending_app_lock: Option<AppLockAttempt>,
app_unlock_pin_visible: bool,
```

Implement `clear_for_app_lock` by clearing passphrase entry, PIN setup entry, local PIN entry, pending Touch ID, focused approval, add draft, secret detail authorization/buffers, navigation/delete confirmations, and the current notice. It must retain `session_confirmation`, the unlocked controller, `desktop_lock`, `desktop_lock_epoch`, and the pending background app-lock attempt.

Refactor `clear_sensitive_state` to call `clear_for_app_lock`, then clear `session_confirmation`, cancel/drop `pending_app_lock`, reset `desktop_lock` to `Active`, and clear all remaining authentication fields.

- [ ] **Step 4: Wire the soft-lock request and completion**

Replace the manager action text with **Lock app**. Implement:

```rust
fn lock_app(&mut self);
#[cfg(unix)]
fn process_app_lock_result(&mut self);
fn show_app_locking(&mut self, ui: &mut egui::Ui);
fn show_app_locked(&mut self, ui: &mut egui::Ui);
```

On Unix, `lock_app` calls `broker.begin_app_lock` first. Once it returns an epoch, copy it to `desktop_lock_epoch`, set `DesktopLockState::Locking`, store the attempt, immediately call `clear_for_app_lock`, and repaint. On non-Unix, where no agent broker exists, increment `desktop_lock_epoch` with `checked_add`, clear immediately, and finish in `Locked` synchronously.

If neither current strict Touch ID nor a configured PIN is available, call the existing `lock_immediately` hard-lock path. Any begin/completion error also calls `lock_immediately`; do not restore the manager.

`process_app_lock_result` accepts completion only for the exact `Locking` epoch held by the attempt and changes it to `Locked`. A mismatched or disconnected completion hard-locks. `show_app_locking` displays only Ladon branding and “Finishing active command cleanup…”; it has no secret metadata or unlock control.

- [ ] **Step 5: Route update, timeout, external lock, and exit correctly**

In `eframe::App::update`:

1. process external hard lock;
2. run existing idle expiry even while app-locked;
3. process app-lock completion and Touch ID completion;
4. render hard vault phases first;
5. for an unlocked controller render `Locking`, `Locked`, session setup, or manager in that order.

Use auth-window dimensions for `Locking` and `Locked`; manager dimensions apply only to `Active` with a configured `SessionConfirmation`. External MCP lock, idle expiry, `lock_immediately`, and `on_exit` continue through `clear_sensitive_state` and leave the controller cryptographically locked.

- [ ] **Step 6: Add timeout and fallback regression tests**

Assert that soft lock does not call any controller activity method by comparing `remaining_unlocked()` before and after lock/unlock within a small tolerance that only permits elapsed time to decrease. Add deterministic state tests proving:

- a completion for the wrong epoch invokes the hard-lock path;
- controller idle expiry while `DesktopLockState::Locked` clears the retained `SessionConfirmation`;
- external MCP lock while app-locked ends with `VaultUiPhase::Locked` and `DesktopLockState::Active` for the next passphrase session;
- failure returned by `AppLockAttempt` wipes all GUI buffers and hard-locks the controller.

- [ ] **Step 7: Run desktop and external-lock tests**

Run:

```bash
cargo test -p ladon-app desktop::tests -- --nocapture
cargo test -p ladon-app --test agent_broker_unix -- --nocapture
```

Expected: all tests pass; existing external-lock acknowledgement tests remain unchanged in behavior.

- [ ] **Step 8: Commit desktop lifecycle**

```bash
git add crates/ladon-app/src/desktop.rs
git commit -m "feat: add desktop soft lock lifecycle"
```

---

### Task 4: One-click Touch ID unlock with PIN fallback

**Files:**

- Modify: `crates/ladon-app/src/touch_id.rs`
- Modify: `crates/ladon-app/src/desktop.rs`
- Test: `crates/ladon-app/src/touch_id.rs`
- Test: `crates/ladon-app/src/desktop.rs`

**Interfaces:**

- Consumes: Task 3's completed `DesktopLockState::Locked { epoch }`, retained `SessionConfirmation`, and existing `PendingTouchId` polling.
- Produces: `TouchIdAuthenticator::authenticate_app`, `TouchIdTarget::AppUnlock`, and locally authenticated `unlock_app(epoch)` flow.

- [ ] **Step 1: Write failing unlock-decision and stale-result tests**

Add a pure choice helper and cover all capability combinations:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppUnlockStart {
    TouchId,
    Pin,
    HardLock,
}

fn app_unlock_start(touch_id_available: bool, pin_configured: bool) -> AppUnlockStart {
    match (touch_id_available, pin_configured) {
        (true, _) => AppUnlockStart::TouchId,
        (false, true) => AppUnlockStart::Pin,
        (false, false) => AppUnlockStart::HardLock,
    }
}
```

Test that a single `begin_app_unlock` invocation chooses Touch ID when both methods exist. Build a fake `TouchIdAttempt` with `spawn_with`, attach `TouchIdTarget::AppUnlock { vault_session_id, lock_epoch }`, change the current epoch before releasing the result, and assert the stale success does not call broker `unlock_app` or show the manager.

- [ ] **Step 2: Run the focused tests and confirm RED**

Run:

```bash
cargo test -p ladon-app desktop::tests::app_unlock -- --nocapture
cargo test -p ladon-app touch_id::tests -- --nocapture
```

Expected: compilation fails because the app-unlock target and authenticator entry point do not exist.

- [ ] **Step 3: Add the app-specific Touch ID request**

In `touch_id.rs`, add:

```rust
const APP_UNLOCK_REASON: &str = "Unlock Ladon on this device";

pub(crate) fn authenticate_app() -> Result<TouchIdAttempt, LadonError> {
    TouchIdAttempt::start(APP_UNLOCK_REASON.to_owned())
}
```

This uses the existing fresh `LAContext`, biometric-only policy, zero reuse duration, hidden system fallback title, cancellation, and timeout. Unit-test that `APP_UNLOCK_REASON` is nonempty and contains no dynamic secret or client data; do not call the platform adapter from a test.

- [ ] **Step 4: Implement one-click UI and PIN alternative**

On the locked screen:

- **Unlock** is the single primary button;
- clicking it calls `begin_app_unlock`; Touch ID starts immediately when available;
- when a PIN exists, **Use PIN instead** is always available as a secondary action;
- choosing PIN drops the pending Touch ID attempt, reveals and focuses one password field, and exposes **Unlock with PIN**;
- **Lock vault completely** calls `lock_immediately`;
- a cancelled or failed Touch ID attempt leaves the app locked and does not increment the PIN counter.

Extend the target enum exactly:

```rust
AppUnlock {
    vault_session_id: uuid::Uuid,
    lock_epoch: u64,
},
```

Before accepting PIN or Touch ID success, compare controller phase, vault-session UUID, `DesktopLockState::Locked` epoch, and pending target. On Unix call `broker.unlock_app(epoch)` as the final authenticated transition; only after it succeeds set `DesktopLockState::Active`. On non-Unix set the local state active after the same context checks. Clear the local PIN and any pending Touch ID on every result.

- [ ] **Step 5: Preserve the shared failure counter**

Use the existing `SessionConfirmation::verify_pin`. `Accepted` unlocks the app, `Rejected` keeps the app locked and reports remaining attempts, and `LockVault` calls `lock_immediately`. On Touch ID success call `record_touch_id_success()` before reopening the gate.

Add a regression sequence: submit four incorrect PINs, process a successful app-unlock Touch ID result, soft-lock again, then submit one incorrect PIN and assert four attempts remain. Separately, five incorrect app-unlock PINs must leave the controller hard-locked and `session_confirmation` absent.

- [ ] **Step 6: Run auth, desktop, and broker tests**

Run:

```bash
cargo test -p ladon-app --test session_auth -- --nocapture
cargo test -p ladon-app desktop::tests -- --nocapture
cargo test -p ladon-app touch_id::tests -- --nocapture
cargo test -p ladon-app --test agent_broker_unix -- --nocapture
```

Expected: all tests pass; no test opens a real Touch ID dialog.

- [ ] **Step 7: Commit one-click unlock**

```bash
git add crates/ladon-app/src/desktop.rs crates/ladon-app/src/touch_id.rs
git commit -m "feat: unlock app with touch id or pin"
```

---

### Task 5: Selected-row and destructive-action polish

**Files:**

- Modify: `crates/ladon-app/src/desktop.rs`
- Test: `crates/ladon-app/src/desktop.rs`

**Interfaces:**

- Consumes: existing `COBALT`, `DANGER`, compact `SECRET_RAIL_WIDTH`, `summarize_field_names`, and delete confirmation state.
- Produces: a full-row selected fill and one shared danger-button renderer used by both delete steps.

- [ ] **Step 1: Write failing visual-contract helper tests**

Extract the decisions from widget construction:

```rust
fn secret_row_fill(selected: bool) -> Color32 {
    if selected { COBALT } else { Color32::TRANSPARENT }
}

#[test]
fn selected_secret_row_uses_cobalt_fill() {
    assert_eq!(secret_row_fill(true), COBALT);
    assert_eq!(secret_row_fill(false), Color32::TRANSPARENT);
}
```

Add one source-level rendering invariant by routing both the initial and confirming delete buttons through the exact same `danger_button(ui, text)` helper; the compiler then prevents the two call sites from drifting in fill, text color, stroke, and corner radius.

- [ ] **Step 2: Run the visual-contract test and confirm RED**

Run:

```bash
cargo test -p ladon-app desktop::tests::selected_secret_row_uses_cobalt_fill -- --nocapture
```

Expected: compilation fails because `secret_row_fill` does not exist.

- [ ] **Step 3: Render a compact full-row selection**

Wrap each secret rail row in a rounded frame using `secret_row_fill(selected)`, keep the name, first field, and `+N` summary on one line, and allocate the row across the rail's usable width. Use white name text and a high-contrast pale metadata color on the selected cobalt fill. Preserve the existing `+N` hover text and make the row click target cover the filled row, not just the name.

Use one full-row interaction rather than nested buttons:

```rust
let metadata_color = if selected {
    Color32::from_rgb(226, 234, 255)
} else {
    Color32::from_rgb(173, 187, 214)
};
let row = Frame::new()
    .fill(secret_row_fill(selected))
    .corner_radius(6)
    .inner_margin(Margin::symmetric(6, 4))
    .show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.add_sized(
                [74.0, 22.0],
                egui::Label::new(RichText::new(&secret.name).color(Color32::WHITE))
                    .truncate(),
            )
            .on_hover_text(&secret.name);
            if let Some(primary) = summary.primary {
                ui.label(RichText::new(primary).size(10.0).color(metadata_color))
                    .on_hover_text(primary);
            }
            if summary.additional_count > 0 {
                ui.label(
                    RichText::new(format!("+{}", summary.additional_count))
                        .size(10.0)
                        .strong()
                        .color(metadata_color),
                )
                .on_hover_text(&summary.additional_hover);
            }
        });
    });
let response = ui.interact(
    row.response.rect,
    ui.make_persistent_id(("secret-row", secret.id.to_string())),
    egui::Sense::click(),
);
if response.clicked() {
    self.request_navigation(NavigationTarget::Secret(secret.id));
}
```

Do not change `SECRET_RAIL_WIDTH`, `WORKSPACE_CARD_WIDTH`, or window sizes.

- [ ] **Step 4: Share one filled red button implementation**

Add:

```rust
fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).strong().color(Color32::WHITE))
            .fill(DANGER)
            .stroke(Stroke::NONE)
            .corner_radius(6),
    )
}
```

Use this helper for both the initial **Delete** button and the confirming **Delete** button. Keep the current two-step state machine and **Cancel** behavior intact.

- [ ] **Step 5: Run desktop tests and manually inspect the egui frame**

Run:

```bash
cargo test -p ladon-app desktop::tests -- --nocapture
cargo run --release -p ladon-app
```

Inspect: selected row fill spans the compact row; unselected rows stay dark; long names truncate; first field and `+N` stay inline; hover still lists extra fields; both delete steps are filled red; the card width does not jump.

- [ ] **Step 6: Commit visual polish**

```bash
git add crates/ladon-app/src/desktop.rs
git commit -m "fix: clarify selected and destructive actions"
```

---

### Task 6: User and security documentation

**Files:**

- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/threat-model.md`

**Interfaces:**

- Consumes: Tasks 1--5 behavior and the approved addendum.
- Produces: public explanation of soft versus hard lock without overstating memory protection.

- [ ] **Step 1: Update the README usage flow**

In **Build and run**, explain that **Lock app** clears the visible selection, edit/reveal buffers, approvals, grants, and active agent run while retaining the unlocked vault key and session PIN verifier only until the original idle deadline. Explain that one **Unlock** click starts Touch ID, with **Use PIN instead** when configured.

In **Agent use**, state that list/run return `vault_locked` during app lock and that MCP `lock` always performs the full passphrase-requiring vault lock. Replace the blanket “locking/reopening” sentence with an explicit distinction between app lock and vault lock.

- [ ] **Step 2: Update protocol semantics without changing schemas**

Document these exact existing-schema results in `docs/protocol.md`:

```text
AppLocked status => state "locked", idle_remaining_ms absent/null
AppLocked list   => vault_locked
AppLocked run    => vault_locked
AppLocked lock   => success after hard vault lock
```

State that no RPC can request soft lock, Touch ID, PIN submission, or app unlock.

- [ ] **Step 3: Update the threat model and invariants**

Add `AppLocked` to the trust-boundary section: key and PIN verifier remain in Ladon memory, GUI values are wiped, agent admission is closed, grants are revoked, and active supervised runs are cancelled before completion. State plainly that this improves accidental-disclosure behavior but not resistance to same-user memory compromise.

Split invariant 6 into two concrete invariants: app lock blocks admission before clearing GUI values and does not complete until child cleanup; hard lock additionally drops the unlocked session. Update the memory-only statement so session confirmation survives app lock but never hard lock or process exit.

- [ ] **Step 4: Scan for contradictory claims**

Run:

```bash
rg -n 'Lock now|locking/reopening always|PIN verifiers.*removed when Ladon locks|MCP.*soft lock|idle.*reset.*unlock app' README.md SECURITY.md docs crates/ladon-app/src
```

Expected: no stale public claim says every UI lock drops the key or PIN verifier, and no text suggests an agent can soft-unlock Ladon.

- [ ] **Step 5: Commit documentation**

```bash
git add README.md docs/protocol.md docs/threat-model.md
git commit -m "docs: explain soft and hard lock boundaries"
```

---

### Task 7: Whole-branch verification and delivery

**Files:**

- Verify: entire Cargo workspace and documentation tree
- Conditionally modify: `reports/2026-09-work-report.md` only if that file already exists at execution time

**Interfaces:**

- Consumes: all preceding task commits.
- Produces: one verified, landed `origin/main` commit chain with no uncommitted in-scope change.

- [ ] **Step 1: Run formatting and strict linting**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: both commands exit 0.

- [ ] **Step 2: Run the complete automated suite and release build**

```bash
cargo test --workspace --all-features
scripts/smoke-test.sh
cargo build --workspace --all-features --release
```

Expected: every test and smoke check passes and both `target/release/ladon-app` and `target/release/ladon` build.

- [ ] **Step 3: Perform the macOS manual acceptance pass**

Run `target/release/ladon-app` and verify in order:

1. select a secret and confirm the cobalt row highlight;
2. confirm both delete steps use the same filled-red style, then cancel without deleting;
3. reveal or edit a test secret, choose **Lock app**, and confirm values disappear immediately;
4. while app-locked, run `target/release/ladon status`, `list`, and a harmless binding-free `run`; confirm status says locked and list/run return `vault_locked`;
5. click **Unlock** once and complete Touch ID; confirm the manager returns without passphrase entry and without restoring selection or grants;
6. lock again, choose **Use PIN instead**, and unlock with the configured PIN;
7. cancel Touch ID and confirm the app stays locked;
8. invoke `target/release/ladon lock` while soft-locked and confirm the next GUI unlock requires the vault passphrase;
9. leave the app soft-locked until its original idle deadline and confirm it becomes hard-locked.

Use only fake test values during this pass.

- [ ] **Step 4: Record the monthly work row only when the current file exists**

Check:

```bash
test -f reports/2026-09-work-report.md
```

If the command succeeds, append exactly one row using that file's existing schema after verification. The row must state the soft-lock outcome, the exact verification commands, manual macOS coverage actually performed, and a conservative time estimate. If the command exits nonzero, do not create a report.

- [ ] **Step 5: Synchronize with `origin/main` and reverify the landing tree**

```bash
git fetch origin main
git rebase origin/main
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
scripts/smoke-test.sh
cargo build --workspace --all-features --release
```

Resolve only in-scope conflicts and preserve concurrent report rows byte-for-byte. Do not rewrite or discard another worktree's changes.

- [ ] **Step 6: Commit any verified report row and land**

If Step 4 changed the existing report:

```bash
git add reports/2026-09-work-report.md
git commit -m "docs: record soft app lock delivery"
```

Then land the verified branch:

```bash
git push origin HEAD:main
git fetch origin main
git merge-base --is-ancestor HEAD origin/main
git rev-parse origin/main
git status --short
```

Expected: push succeeds, the ancestry check exits 0, status is clean, and the reported delivery SHA is the fetched `origin/main` SHA.
