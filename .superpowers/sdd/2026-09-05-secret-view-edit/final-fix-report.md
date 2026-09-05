# Protected Secret View/Edit final fix report

Date: 2026-09-05

Worktree: `/Users/ortnec/Documents/GitHub/personal/ladon/.worktrees/secret-view-edit`

Starting commit: `441076c` (`fix: correct session PIN validation message`)

Authoritative specification: `docs/superpowers/specs/2026-09-04-ladon-design.md`

Implementation plan: `docs/superpowers/plans/2026-09-05-secret-view-edit.md`

## Outcome

All final-review code findings were fixed in one wave. External MCP lock now has a
broker-to-GUI completion boundary: the vault is locked and new secret-bearing runs
remain blocked while the broker waits for the GUI to erase its plaintext/authentication
state, and only then can the lock RPC succeed. Touch ID evaluation runs on a background
thread and every completed result is rebound to the captured vault session and exact
secret-selection or approval identity before acceptance. Stale-session transitions,
mixed-request mutation cancellation, mutation commit failure, and delete/replacement
reapproval have explicit regressions. README wording now describes exactly when a PIN
is optional. The unperformed macOS interaction check is explicitly unchecked and
pending.

The exact formatting, workspace clippy, workspace test, and optimized GUI build gates
all pass. The release application was built but deliberately not launched or marked as
manually smoke-tested.

## Finding 1: external lock completion and asynchronous Touch ID

### Defect and security consequence

`RpcMethod::Lock` previously canceled/revoked broker state, waited for a run, and
locked `VaultController`, then immediately returned. `LadonDesktop` separately owned
revealed/editing drafts, the in-memory PIN verifier, entered PIN text, selection
authorization, and confirmation state. Therefore a successful external lock response
did not prove those GUI-owned values were gone. In addition, the UI called the
60-second Touch ID wait synchronously, so it could not service any lock-driven wipe
while LocalAuthentication was pending.

### RED evidence

The following tests were written before their production support:

```text
cargo test -p ladon-app --lib --all-features external_broker_lock_waits_for_gui_ack_after_controller_lock
RED: compilation failed because AgentBroker had no UI lock coordinator/ack channel.

cargo test -p ladon-app --lib --all-features external_lock_waits_until_revealed_secret_is_wiped
cargo test -p ladon-app --lib --all-features external_lock_waits_until_unsaved_edit_is_wiped_without_prompt
RED: compilation failed because LadonDesktop had no process_external_lock operation.

cargo test -p ladon-app --lib --all-features external_lock_cancels_pending_touch_id_before_acknowledgement
RED: compilation failed because TouchIdAttempt/pending asynchronous authentication did not exist.

cargo test -p ladon-app --lib --all-features gui_lock_does_not_wait_on_an_external_lock_intent -- --nocapture
RED: test ran and failed with "GUI lock waited on the run barrier after an external lock intent".
```

That last RED was added during the explicit lock-order audit. It reproduced the cycle
where the external worker owned/waited for the run barrier and would later wait for a
GUI acknowledgement, while the GUI could synchronously enter another broker lock or
revoke operation before the external request became ready.

### Implementation and architecture evidence

- `crates/ladon-app/src/agent_broker.rs:53` adds `UiLockCoordinator`, a small
  counter/state machine guarded by one mutex and condition variable. An external lock
  registers its intent before touching approval/run/controller state. After the
  controller lock attempt, it publishes `ready`, requests an egui repaint, and waits
  for that exact request ID to be acknowledged.
- `crates/ladon-app/src/agent_broker.rs:260` centralizes fail-closed ordering in
  `lock_controller_and_runs`: register UI intent; cancel pending approval; revoke
  grants; acquire the run block (which cancels and waits for the active run); lock the
  controller; publish/wait for the GUI wipe; then return the first error, if any. An
  approval/coordinator error does not skip later lock/wipe attempts.
- `crates/ladon-app/src/agent_broker.rs:102` adds an RAII local-operation guard. If a
  GUI lock/revoke owns this guard first, external intent waits for it before becoming
  visible. If external intent owns the transition first, GUI lock/revoke defers to that
  transition and returns to the event loop, where it can wipe and acknowledge. This
  closes the check-then-block race without another dependency or a timeout.
- `crates/ladon-app/src/agent_broker.rs:315` uses the acknowledgement coordinator only
  for the GUI-owned broker. Headless/test broker construction retains immediate lock
  semantics because it has no separate GUI plaintext owner.
- `crates/ladon-app/src/agent_broker.rs:405` exposes only the narrow poll/ack/in-progress
  operations required by the desktop. Dropping the broker marks the UI side
  disconnected and wakes waiters before shutdown/join, so exit cannot strand a worker
  on the acknowledgement condition variable.
- `crates/ladon-app/src/desktop.rs:1111` polls the ready request at the beginning of an
  update, calls the existing comprehensive `clear_sensitive_state`, sets the observed
  phase to locked, and only then acknowledges. The wipe covers unlock/passphrase
  fields, session PIN setup fields, entered PIN, the `SessionConfirmation` verifier,
  pending Touch ID, focused approval, add draft, revealed/editor draft, authorization,
  selection, dirty-discard state, and pending delete.
- `crates/ladon-app/src/desktop.rs:1155` recognizes the earlier external intent if the
  controller phase becomes locked just before `ready`. It clears GUI state without
  entering a competing synchronous revoke. The following repaint receives `ready` and
  acknowledges it.
- `crates/ladon-app/src/touch_id.rs:11` introduces `TouchIdAttempt`: a named standard
  library worker thread plus a nonblocking receiver. Dropping an attempt sets a
  cancellation flag. The macOS worker checks it at most every 20 ms and invalidates
  its `LAContext` on cancellation or timeout.
- `crates/ladon-app/src/desktop.rs:859` consumes completed authentication without
  blocking. Secret results are accepted only through the captured `LocalAuthAttempt`
  (vault UUID, secret ID, selection epoch) and current vault UUID. Approval results
  require the captured approval UUID and vault UUID to still match the exact broker
  pending request. Navigation, denial, request replacement/disappearance, PIN use,
  delete, phase loss, close, and external lock all drop/cancel the pending attempt.
- Strict Touch ID properties remain explicit in
  `crates/ladon-app/src/touch_id.rs:104-123`: a fresh `LAContext` per attempt,
  `DeviceOwnerAuthenticationWithBiometrics` for preflight and evaluation, allowable
  reuse duration `0.0`, empty fallback title, and no broader owner-authentication
  policy. No password/Apple Watch fallback was introduced.

The acknowledgement wait deliberately retains the `RunBlock`, but it does not retain
the run-coordinator mutex, controller mutex, approval mutex, or UI-lock mutex. The GUI
acknowledgement path acquires none of the run/controller/approval locks. Consequently
there is no reverse edge back into a lock held by the external worker. The local
operation guard prevents the only UI-thread/run-barrier cycle found in the audit.

### GREEN evidence

`crates/ladon-app/src/agent_broker.rs:759` and `:811`, plus
`crates/ladon-app/src/desktop.rs:1892`, `:1898`, and `:1904`, prove:

- the controller reaches `Locked` before the acknowledgement is offered;
- the client lock response remains pending while revealed/editing plaintext exists;
- a dirty editor is wiped without a discard prompt on lock;
- session authentication and entered PIN state are also wiped;
- a pending Touch ID worker observes cancellation before acknowledgement;
- a GUI lock does not wait behind an external transition's run block; and
- response `Debug` output does not contain the synthetic plaintext canary.

Final focused output:

```text
cargo test -p ladon-app --lib --all-features
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The first restricted-sandbox run reported three `EndpointUnavailable` failures at
desktop test setup because it could not create the Unix sockets. The identical command
was rerun with socket access and passed all 22 tests; this was an environment
permission failure, not an assertion or product failure.

## Finding 2: manual macOS verification was incorrectly marked complete

`docs/superpowers/plans/2026-09-05-secret-view-edit.md:1171` is now unchecked. Lines
1173-1174 explicitly state that the controller/human macOS smoke run has not been
performed and that an automated release build does not complete it. None of the seven
manual observations is claimed as passed in this report.

No synthetic RED test is appropriate for a truthful manual checklist state. The
document diff itself is the evidence: `[x]` changed to `[ ]`, followed by an explicit
pending notice. The optimized GUI does compile successfully, as recorded under final
verification below.

## Finding 3: reveal/edit transition accepted stale vault authorization

### RED evidence

```text
cargo test -p ladon-app --test ui_state reveal_and_edit_reject_authorization_from_a_stale_vault_session -- --exact
RED: error[E0061], begin_reveal/begin_edit accepted only the draft and had no current-session argument.
```

### Implementation and GREEN evidence

`SecretDetailState::begin_reveal`, `begin_edit`, and `begin_with_draft` now require a
current vault-session UUID (`crates/ladon-app/src/ui.rs:824-920`). The final transition
uses `authorization_for_current_selection` and therefore compares the full tuple:
vault-session UUID, selected immutable secret ID, and selection epoch. Draft ID must
also equal the selected ID.

The desktop obtains the session UUID and plaintext draft and performs the detail-state
transition while retaining the same controller mutex guard
(`crates/ladon-app/src/desktop.rs:916`). An external lock therefore cannot replace the
current vault session between the controller read and the transition boundary.

`crates/ladon-app/tests/ui_state.rs:105` exercises both reveal and edit with an
authorization from an earlier session and verifies `NotAuthorized` with no sensitive
buffer retained.

```text
cargo test -p ladon-app --test ui_state --all-features
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Finding 4: mutation of an already-granted ID did not cancel a mixed pending request

### RED evidence

```text
cargo test -p ladon-app --test approval_state mutation_of_already_granted_secret_cancels_mixed_pending_without_expanding_display -- --exact
RED assertion: authorization returned ApprovalTimeout instead of ApprovalCancelled.
```

### Implementation and GREEN evidence

`PendingState` now keeps `requested_secret_ids` separately from the sanitized/displayed
`PendingApproval` (`crates/ladon-app/src/approval.rs:150`). The full, deduplicated ID
list comes from the value-free `GrantTicket` before already-granted IDs are filtered
out of the UI request. Mutation checks the complete list
(`crates/ladon-app/src/approval.rs:297-310`), while `pending()` still clones only the
missing-secret metadata.

`crates/ladon-app/tests/approval_state.rs:456` first grants secret A, opens a mixed
A+B request, proves the displayed request contains only B, mutates A, and proves the
mixed request is canceled.

```text
cargo test -p ladon-app --test approval_state --all-features
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

No values are stored in either ID list, and the displayed metadata surface was not
expanded.

## Finding 5: README overstated PIN optionality

`README.md:50-56` now says precisely:

- on a supported Mac where strict Touch ID is currently available, the user may use
  Touch ID alone or configure an optional 4-12 digit session PIN; and
- whenever strict Touch ID is unavailable, that PIN is required before secret use.

The obsolete-copy scan was rerun:

```text
rg -n '6--12|6–12|automatically hides.*ten seconds|choose Touch ID instead|session configured for Touch ID' README.md docs crates/ladon-app/src crates/ladon-core/src
```

Output contains only two statements in the completed historical
`2026-09-05-session-secret-grants.md` plan and the grep command itself in the current
plan. The current plan explicitly permits historical completed plans to retain their
original wording; no active README, security documentation, or GUI copy matched.

## Finding 6: commit-error and broker delete-path regressions

### Coordinator commit error

`crates/ladon-app/tests/approval_state.rs:508` grants one secret, performs a validated
mutation whose commit returns `StorageFailure`, proves the commit was reached, proves
the old ticket is already canceled, and proves a later request needs a new approval.
This captures the required ordering: validation succeeds first; pending decision and
old grant are invalidated under the approval mutex; only then does commit run. Commit
failure is returned without restoring authority.

The production path already had the correct ordering. To establish RED rather than
merely add a passing characterization test, I temporarily mutation-tested it by
removing `revoke_secret`:

```text
cargo test -p ladon-app --test approval_state mutation_commit_failure_stays_revoked_and_requires_future_reapproval -- --exact
RED assertion: with_valid_grant returned Ok(()) where ApprovalCancelled was required.
```

Restoring fail-closed invalidation made the test GREEN. Validation-failure behavior is
unchanged and remains covered separately: a failed `prepare` does not revoke a valid
grant because no mutation was eligible to commit.

### Broker delete and replacement

`crates/ladon-app/tests/agent_broker_unix.rs:336` covers the real socket/broker path. It
grants the soon-to-be-deleted secret, starts a mixed request whose value-free display
contains only the other (missing) secret, deletes through `LocalBrokerHandle`, and
proves the request is canceled. A same-name replacement gets a new immutable ID and
must prompt again; denial returns the safe error. Concatenated response `Debug` text is
checked against old, other, and replacement canaries.

The path already used coordinated delete. Its test was mutation-tested by temporarily
bypassing `ApprovalCoordinator::coordinate_secret_mutation`:

```text
cargo test -p ladon-app --test agent_broker_unix delete_cancels_mixed_pending_and_replacement_requires_reapproval_without_leakage -- --exact
RED assertion: "delete did not cancel a mixed request that included the deleted ID".
```

The coordinated implementation was restored and the final suite is GREEN:

```text
cargo test -p ladon-app --test agent_broker_unix --all-features
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Final verification

These commands were run on the final code tree after the lock-boundary tightening:

```text
cargo fmt --all -- --check
exit 0; no formatting differences

cargo clippy --workspace --all-targets --all-features -- -D warnings
Finished `dev` profile; exit 0; no warnings

cargo test --workspace --all-features
exit 0; 152 passed, 0 failed, 8 ignored fixture entry points; all doc-tests passed

cargo build --release -p ladon-app --features gui
Finished `release` profile [optimized]; exit 0

git diff --check
exit 0; no whitespace errors
```

The workspace test command was granted local Unix-socket access, as required by the
repository's broker/IPC tests. The eight ignored tests are helper fixture entry points
in `runner_integration`; the nine actual runner integration scenarios all passed.

Leak checks used all old and new synthetic canaries:

```text
rg -n 'fake-text-canary|fake-broker-secret|fake-original-secret|fake-external-lock-secret|fake-deleted-secret|fake-other-secret|fake-replacement-after-delete' --glob '!target/**' .
```

Matches were limited to test source assertions/fixtures and example snippets in the
implementation plan. A binary-aware scan (`rg -a -l` with the same pattern under
`target/debug target/release`) found only debug test executables, object files, and
incremental caches. It found no `target/release` artifact, application log, IPC/MCP
capture, or generated product documentation containing a canary.

## Files changed

- `README.md`
- `crates/ladon-app/src/agent_broker.rs`
- `crates/ladon-app/src/approval.rs`
- `crates/ladon-app/src/desktop.rs`
- `crates/ladon-app/src/touch_id.rs`
- `crates/ladon-app/src/ui.rs`
- `crates/ladon-app/tests/agent_broker_unix.rs`
- `crates/ladon-app/tests/approval_state.rs`
- `crates/ladon-app/tests/ui_state.rs`
- `docs/superpowers/plans/2026-09-05-secret-view-edit.md`
- `.superpowers/sdd/2026-09-05-secret-view-edit/final-fix-report.md`

No dependency, protocol schema, plaintext-returning API, vault file format, or grant
lifetime was added or changed.

## Remaining concerns

1. The seven required macOS GUI/Touch ID interactions in plan Task 7 Step 5 still need
   a controller/human run with a disposable secret and actual Touch ID hardware. The
   step intentionally remains unchecked.
2. Automated tests exercise asynchronous completion/cancellation with deterministic
   fake workers, and the macOS release build validates the LocalAuthentication binding,
   but CI cannot assert the physical biometric prompt or OS presentation behavior.
3. Historical completed implementation plans still contain their then-current 6-12
   digit wording. The current plan explicitly treats historical wording as allowable;
   active product documentation and GUI behavior use 4-12 digits.
