# Agent Access Observability and Secret UX Implementation Plan

> Clipboard lifecycle note (2026-09-18): the product requirement was narrowed
> to one explicit clipboard write. Task 5's lease, timer, readback, and cleanup
> design is superseded by the final design spec and is retained below only as
> historical implementation context.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Show and selectively revoke active agent grants, let MCP sessions report a useful display name, and correct the requested secret reveal/edit/copy and desktop alignment defects.

**Architecture:** Keep grant deadlines and pair identity in `ladon-core`, keep untrusted labels and authorization cleanup in `ApprovalCoordinator`, and combine those snapshots with current-run and vault metadata only inside the GUI broker handle. Add a process-local MCP identification tool, a focused clipboard adapter over the already-compiled `arboard`, and pure UI formatting/layout helpers so security behavior and visual state can be tested independently.

**Tech Stack:** Rust 1.85, Cargo workspace, egui/eframe 0.32.3, arboard 3.6.1, Unix local broker tests, existing monotonic clocks and zeroizing sensitive buffers.

**Spec:** `docs/superpowers/specs/2026-09-17-agent-access-observability-ux-design.md`

## Global Constraints

- Grants remain in memory, fixed at 30 minutes, and keyed only by `(client_session_id, secret_id)`.
- No grant snapshot, client-session UUID, targeted revoke, or secret value is added to local RPC, CLI, or MCP.
- MCP-reported client names are untrusted display metadata, limited to 64 UTF-8 bytes, and marked `(reported)` in the GUI.
- The access list has no persistent history and disappears when empty.
- Clipboard clearing is conditional: never erase content copied after the Ladon value.
- Text values may be copied; binary values remain non-copyable and non-editable as text.
- No new OS-installed runtime dependency or background service is introduced.
- Existing lock, grant expiry, secret mutation, and dirty-edit safety semantics remain authoritative.
- Every production behavior change follows red-green-refactor.

---

### Task 1: Enumerate and revoke exact grant pairs in the core

**Files:**
- Modify: `crates/ladon-core/src/grants.rs`
- Modify: `crates/ladon-core/src/lib.rs`
- Modify: `crates/ladon-core/tests/grants.rs`

**Interfaces:**
- Consumes: existing `GrantStore<C>`, `MonotonicClock`, `Uuid`, and `SecretId`.
- Produces: exported `GrantEntry`, `GrantStore::active`, and `GrantStore::revoke_pair` for Task 3.

- [ ] **Step 1: Write failing tests for active enumeration and exact-pair revoke**

Add tests that use the existing `FakeClock` and assert identifiers and remaining time without any value type:

```rust
#[test]
fn active_entries_purge_expired_pairs_and_report_remaining_time() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock.clone(), Duration::from_secs(60));
    let client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    grants.grant(client, [first]);
    clock.advance(Duration::from_secs(30));
    grants.grant(client, [second]);

    clock.advance(Duration::from_secs(30));
    let entries = grants.active();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].client_session_id(), client);
    assert_eq!(entries[0].secret_id(), second);
    assert_eq!(entries[0].remaining(), Duration::from_secs(30));
}

#[test]
fn revoke_pair_removes_only_the_exact_client_and_secret() {
    let clock = FakeClock::new();
    let mut grants = GrantStore::new(clock, Duration::from_secs(60));
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    grants.grant(first_client, [first, second]);
    grants.grant(second_client, [first]);

    assert!(grants.revoke_pair(first_client, first));
    assert!(!grants.revoke_pair(first_client, first));
    assert!(grants.missing(first_client, [first]).contains(&first));
    assert!(grants.missing(first_client, [second]).is_empty());
    assert!(grants.missing(second_client, [first]).is_empty());
}
```

- [ ] **Step 2: Run the core grant tests and verify RED**

Run:

```bash
cargo test -p ladon-core --test grants
```

Expected: compilation fails because `GrantStore::active`, `GrantEntry` accessors, and `GrantStore::revoke_pair` do not exist.

- [ ] **Step 3: Implement the minimal core snapshot API**

Add a value-free entry type and methods that always purge before reading:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantEntry {
    client_session_id: Uuid,
    secret_id: SecretId,
    remaining: Duration,
}

impl GrantEntry {
    pub const fn client_session_id(&self) -> Uuid { self.client_session_id }
    pub const fn secret_id(&self) -> SecretId { self.secret_id }
    pub const fn remaining(&self) -> Duration { self.remaining }
}

impl<C: MonotonicClock> GrantStore<C> {
    pub fn active(&mut self) -> Vec<GrantEntry> {
        self.purge_expired();
        let now = self.clock.now_millis();
        self.deadlines
            .iter()
            .map(|((client_session_id, secret_id), deadline)| GrantEntry {
                client_session_id: *client_session_id,
                secret_id: *secret_id,
                remaining: Duration::from_millis(deadline.saturating_sub(now)),
            })
            .collect()
    }

    pub fn revoke_pair(&mut self, client_session_id: Uuid, secret_id: SecretId) -> bool {
        self.purge_expired();
        self.deadlines.remove(&(client_session_id, secret_id)).is_some()
    }
}
```

Export `GrantEntry` from `ladon-core/src/lib.rs`. Do not add labels, values, ordering, or persistence to the core type.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run:

```bash
cargo test -p ladon-core --test grants
cargo clippy -p ladon-core --all-targets -- -D warnings
```

Expected: all core grant tests and Clippy pass.

- [ ] **Step 5: Commit the core grant API**

```bash
git add crates/ladon-core/src/grants.rs crates/ladon-core/src/lib.rs crates/ladon-core/tests/grants.rs
git commit -m "feat: expose active grant pairs"
```

---

### Task 2: Let an MCP process report a non-secret session name

**Files:**
- Modify: `crates/ladon-cli/src/mcp.rs`
- Modify: `crates/ladon-cli/tests/mcp_contract.rs`

**Interfaces:**
- Consumes: existing per-process `client_session_id` and `RpcRequest::client_label`.
- Produces: process-local `McpSession`, optional `ladon_identify_session`, initialization-name capture, and a validated label on every later broker request.

- [ ] **Step 1: Write failing MCP contract tests**

Extend the fake transport tests with initialization, identification, fallback, and rejection cases:

```rust
#[test]
fn identify_session_changes_the_reported_label_without_exposing_the_private_id() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"Codex\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_identify_session\",\"arguments\":{\"display_name\":\"Codex — deploy payments\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].client_label, "Codex — deploy payments");
    assert!(!String::from_utf8(output).unwrap().contains(&seen[0].client_session_id.to_string()));
}

#[test]
fn invalid_identification_preserves_the_initialized_client_name() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"Codex\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_identify_session\",\"arguments\":{\"display_name\":\"bad\\nname\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    assert_eq!(transport.seen.borrow()[0].client_label, "Codex");
    assert!(String::from_utf8(output).unwrap().contains("invalid_request"));
}

#[test]
fn absent_identification_uses_the_mcp_client_fallback() {
    let transport = FakeTransport::new();
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n";

    serve_mcp(input.as_slice(), &mut Vec::new(), &transport).unwrap();

    assert_eq!(transport.seen.borrow()[0].client_label, "MCP client");
}
```

Also change the existing tool-list assertion to require `ladon_identify_session` and assert the output never contains `fake-plaintext-value` or a UUID.

- [ ] **Step 2: Run MCP tests and verify RED**

Run:

```bash
cargo test -p ladon --test mcp_contract
```

Expected: tests fail because the identification tool and mutable MCP session state do not exist.

- [ ] **Step 3: Implement process-local naming and validation**

Replace the loose UUID local with a mutable state object:

```rust
const MAX_REPORTED_NAME_BYTES: usize = 64;

struct McpSession {
    id: Uuid,
    initialized_name: Option<String>,
    display_name: Option<String>,
}

impl McpSession {
    fn new() -> Self {
        Self { id: Uuid::new_v4(), initialized_name: None, display_name: None }
    }

    fn label(&self) -> &str {
        self.display_name
            .as_deref()
            .or(self.initialized_name.as_deref())
            .unwrap_or("MCP client")
    }

    fn validate_name(value: &str) -> Result<String, LadonError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_REPORTED_NAME_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(LadonError::InvalidRequest);
        }
        Ok(value.to_owned())
    }

    fn identify(&mut self, value: &str) -> Result<(), LadonError> {
        self.display_name = Some(Self::validate_name(value)?);
        Ok(())
    }
}
```

Pass `&mut McpSession` through `handle_message` and `call_tool`. During `initialize`, validate and record `params.clientInfo.name` with the same function but leave the fallback intact on invalid input. `ladon_identify_session` updates only this process-local object and returns a structured non-secret acknowledgement. All transported requests use `session.id` and `session.label()`.

Add this tool declaration:

```rust
{
    "name": "ladon_identify_session",
    "description": "Set a short non-secret reported name for this MCP process, such as 'Codex — deploy payments'. Call once before the first secret-bearing run when a useful task name is known.",
    "inputSchema": {
        "type": "object",
        "required": ["display_name"],
        "additionalProperties": false,
        "properties": {
            "display_name": { "type": "string", "minLength": 1, "maxLength": 64 }
        }
    },
    "annotations": { "readOnlyHint": false, "destructiveHint": false }
}
```

Update MCP initialization instructions to recommend a non-secret name but never require one. Do not return the private session UUID.

- [ ] **Step 4: Run MCP contracts and Clippy**

Run:

```bash
cargo test -p ladon --test mcp_contract
cargo clippy -p ladon --all-targets -- -D warnings
```

Expected: all MCP tests pass; invalid names leave the previous label unchanged.

- [ ] **Step 5: Commit MCP identification**

```bash
git add crates/ladon-cli/src/mcp.rs crates/ladon-cli/tests/mcp_contract.rs
git commit -m "feat: name ladon mcp sessions"
```

---

### Task 3: Track labels and expose value-free active grants from approval state

**Files:**
- Modify: `crates/ladon-app/src/approval.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Modify: `crates/ladon-app/tests/approval_state.rs`

**Interfaces:**
- Consumes: `GrantStore::active` and `GrantStore::revoke_pair` from Task 1.
- Produces: exported `ActiveGrantSnapshot`, `ApprovalCoordinator::observe_client`, `ApprovalCoordinator::active_grants`, and `ApprovalCoordinator::revoke_pair` for Task 4.

- [ ] **Step 1: Write failing approval-state tests**

Add a label-aware request helper and tests for snapshots, rename without deadline extension, exact revoke, expiry cleanup, and full cleanup:

```rust
fn request_with_label(
    client: Uuid,
    label: &str,
    secrets: &[(SecretId, &str)],
) -> PendingApproval {
    PendingApproval::new(
        Uuid::nil(),
        client,
        label,
        secrets
            .iter()
            .map(|(id, name)| ApprovalSecret::new(*id, *name, ["value"]))
            .collect(),
        "/usr/bin/curl",
        ["https://example.test"],
        "/tmp",
    )
}

fn approve_request(
    coordinator: &Arc<ApprovalCoordinator<FakeClock>>,
    approval: PendingApproval,
) {
    let waiting = {
        let coordinator = Arc::clone(coordinator);
        thread::spawn(move || coordinator.authorize(approval, &RunCancellation::new()))
    };
    let pending = wait_for_pending(coordinator);
    coordinator.approve(pending.id()).unwrap();
    assert!(waiting.join().unwrap().is_ok());
}

#[test]
fn active_grants_report_untrusted_labels_without_secret_values() {
    let clock = FakeClock::new();
    let coordinator = Arc::new(ApprovalCoordinator::new(
        clock.clone(), Duration::from_secs(60), Duration::from_secs(2),
    ));
    let client = Uuid::new_v4();
    let secret = SecretId::new();
    approve_request(
        &coordinator,
        request_with_label(client, "Codex — deploy", &[(secret, "prod")]),
    );

    clock.advance(Duration::from_secs(15));
    let active = coordinator.active_grants().unwrap();

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].client_session_id(), client);
    assert_eq!(active[0].secret_id(), secret);
    assert_eq!(active[0].client_label(), "Codex — deploy");
    assert_eq!(active[0].remaining(), Duration::from_secs(45));
    assert!(!format!("{active:?}").contains("fake-state-secret"));
}

#[test]
fn rename_updates_display_only_and_exact_revoke_preserves_other_pairs() {
    let clock = FakeClock::new();
    let coordinator = Arc::new(ApprovalCoordinator::new(
        clock.clone(), Duration::from_secs(60), Duration::from_secs(2),
    ));
    let client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    approve_request(
        &coordinator,
        request_with_label(client, "Codex", &[(first, "first"), (second, "second")]),
    );
    clock.advance(Duration::from_secs(10));

    coordinator.observe_client(client, "Codex — renamed").unwrap();
    let active = coordinator.active_grants().unwrap();
    assert_eq!(active.len(), 2);
    assert!(active.iter().all(|grant| grant.client_label() == "Codex — renamed"));
    assert!(active.iter().all(|grant| grant.remaining() == Duration::from_secs(50)));

    assert!(coordinator.revoke_pair(client, first).unwrap());
    let active = coordinator.active_grants().unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].secret_id(), second);
}
```

In the existing app-lock, `revoke_all`, and secret-mutation tests, append this
exact postcondition after the operation succeeds:

```rust
assert!(coordinator.active_grants().unwrap().is_empty());
```

- [ ] **Step 2: Run approval tests and verify RED**

Run:

```bash
cargo test -p ladon-app --test approval_state
```

Expected: compilation fails because snapshot, label map, and exact revoke APIs are missing.

- [ ] **Step 3: Implement application-level label ownership and cleanup**

Add a safe snapshot type:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveGrantSnapshot {
    client_session_id: Uuid,
    client_label: String,
    secret_id: SecretId,
    remaining: Duration,
}
```

Provide accessors only; do not expose mutable fields. Add
`client_labels: HashMap<Uuid, String>` to `ApprovalState`. In `authorize`:

1. clear grants and labels when `vault_session_id` changes;
2. insert the request's label for its client before checking missing grants;
3. preserve existing deadlines when `missing` is empty.

Implement:

```rust
pub fn observe_client(
    &self,
    client_session_id: Uuid,
    client_label: &str,
) -> Result<(), LadonError>;
pub fn active_grants(&self) -> Result<Vec<ActiveGrantSnapshot>, LadonError>;
pub fn revoke_pair(
    &self,
    client_session_id: Uuid,
    secret_id: SecretId,
) -> Result<bool, LadonError>;
```

`observe_client` updates display metadata only if that session already owns an
active grant or has the current pending request. It never creates a grant,
changes a deadline, or keeps an otherwise unreferenced label. The broker calls
it for every request, which lets a process-local MCP rename appear on the next
status/list/run/lock request without granting access.

`active_grants` purges expired pairs through the core API, retains labels only
for session IDs that still own active grants, and falls back to `MCP client` if
state is unexpectedly missing a label. `revoke_pair` cancels a pending request
only when both its client ID and requested secret IDs match, revokes one pair,
then prunes unused labels.

Call the same label cleanup after approval denial/cancellation/timeout,
`revoke_secret`, and expiry enumeration. Clear labels in `revoke_all`, app lock,
vault lock/reset, and session replacement.

- [ ] **Step 4: Run focused approval tests and Clippy**

Run:

```bash
cargo test -p ladon-app --test approval_state
cargo clippy -p ladon-app --all-targets --no-default-features -- -D warnings
```

Expected: snapshot, rename, expiry, exact revoke, and cleanup tests pass.

- [ ] **Step 5: Commit approval observability**

```bash
git add crates/ladon-app/src/approval.rs crates/ladon-app/src/lib.rs crates/ladon-app/tests/approval_state.rs
git commit -m "feat: expose active approval grants"
```

---

### Task 4: Track the active run and make targeted revoke race-safe

**Files:**
- Modify: `crates/ladon-app/src/agent_broker.rs`
- Modify: `crates/ladon-app/tests/agent_broker_unix.rs`

**Interfaces:**
- Consumes: `ActiveGrantSnapshot` and exact revoke from Task 3 plus immutable secret metadata from `VaultController`.
- Produces: GUI-only `AgentGrantView`, `LocalBrokerHandle::agent_grants`, and `LocalBrokerHandle::revoke_grant` for Task 7.

- [ ] **Step 1: Write failing coordinator unit tests**

Inside `agent_broker.rs` tests, specify the run-state transitions and selective blocking:

```rust
#[test]
fn running_snapshot_marks_only_bound_secret_pairs() {
    let coordinator = Arc::new(RunCoordinator::default());
    let client = Uuid::new_v4();
    let first = SecretId::new();
    let second = SecretId::new();
    let lease = coordinator
        .try_start(RunCancellation::new(), client)
        .unwrap();
    lease.set_secret_context(vec![first]).unwrap();
    lease.mark_running().unwrap();

    let running = coordinator.running_pairs().unwrap();
    assert!(running.contains(&(client, first)));
    assert!(!running.contains(&(client, second)));
}

#[test]
fn targeted_block_cancels_same_client_pre_context_but_not_another_client() {
    let coordinator = Arc::new(RunCoordinator::default());
    let first_client = Uuid::new_v4();
    let second_client = Uuid::new_v4();
    let secret = SecretId::new();
    let cancellation = RunCancellation::new();
    let lease = coordinator
        .try_start(cancellation.clone(), first_client)
        .unwrap();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let blocking = {
        let coordinator = Arc::clone(&coordinator);
        thread::spawn(move || {
            let block = coordinator.block_for_revoke(first_client, secret).unwrap();
            finished_tx.send(()).unwrap();
            drop(block);
        })
    };
    let deadline = Instant::now() + Duration::from_secs(1);
    while !cancellation.is_cancelled() {
        assert!(Instant::now() < deadline, "targeted revoke did not cancel");
        thread::yield_now();
    }
    assert!(finished_rx.recv_timeout(Duration::from_millis(30)).is_err());
    drop(lease);
    finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    blocking.join().unwrap();

    let other_cancellation = RunCancellation::new();
    let other_lease = coordinator
        .try_start(other_cancellation.clone(), second_client)
        .unwrap();
    let block = coordinator
        .block_for_revoke(first_client, secret)
        .unwrap();
    assert!(!other_cancellation.is_cancelled());
    drop(block);
    drop(other_lease);
}

#[test]
fn targeted_block_preserves_a_known_non_matching_secret_and_drop_clears_metadata() {
    let coordinator = Arc::new(RunCoordinator::default());
    let client = Uuid::new_v4();
    let bound = SecretId::new();
    let requested = SecretId::new();
    let cancellation = RunCancellation::new();
    let lease = coordinator
        .try_start(cancellation.clone(), client)
        .unwrap();
    lease.set_secret_context(vec![bound]).unwrap();
    lease.mark_running().unwrap();

    let block = coordinator.block_for_revoke(client, requested).unwrap();
    assert!(!cancellation.is_cancelled());
    drop(block);
    drop(lease);

    assert!(coordinator.running_pairs().unwrap().is_empty());
}
```

- [ ] **Step 2: Run coordinator tests and verify RED**

Run:

```bash
cargo test -p ladon-app --features gui agent_broker::tests::running_snapshot_marks_only_bound_secret_pairs
```

Expected: compilation fails because `RunCoordinatorState` has no metadata and the lease methods do not exist.

- [ ] **Step 3: Implement active-run metadata and targeted admission blocking**

Replace `active: Option<RunCancellation>` with:

```rust
struct ActiveRun {
    cancellation: RunCancellation,
    client_session_id: Uuid,
    secret_ids: Option<Vec<SecretId>>,
    running: bool,
}
```

Change the reservation signature and add lease transitions:

```rust
fn try_start(
    self: &Arc<Self>,
    cancellation: RunCancellation,
    client_session_id: Uuid,
) -> Result<RunLease, LadonError>;

impl RunLease {
    fn set_secret_context(&self, secret_ids: Vec<SecretId>) -> Result<(), LadonError>;
    fn mark_running(&self) -> Result<(), LadonError>;
}
```

Add `RunCoordinator::running_pairs() -> Result<HashSet<(Uuid, SecretId)>, LadonError>` and a targeted block method. While holding the coordinator mutex, the targeted method sets `block_new = true` and cancels only when:

```rust
active.client_session_id == requested_client
    && active.secret_ids.as_ref().is_none_or(|ids| ids.contains(&requested_secret))
```

If cancelled, wait until the lease drops; otherwise return the admission block immediately while the unrelated run continues. Never hold the mutex while waiting for the child process itself.

In `AgentBroker::handle_method`, call `approval.observe_client` before method
dispatch so every request can refresh existing display metadata. Reserve with
the client ID, attach the resolved immutable IDs immediately after
`approval_plan`, and mark running immediately before `Supervisor::run`. Mark
no-secret runs running with an empty secret list.

- [ ] **Step 4: Write failing broker tests for snapshot and exact revoke**

Add this unit test beside the coordinator tests; it uses the existing
`wait_for_pending_approval` helper and no plaintext-bearing snapshot fields:

```rust
#[test]
fn broker_snapshot_marks_running_and_exact_revoke_preserves_the_other_pair() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut vault = VaultController::new(directory.path().join("vault.ladon"));
    vault.create(&passphrase, &passphrase).unwrap();
    let mut first = AddSecretDraft::new();
    first.set_name("first");
    first.fields_mut()[0].value_mut().push_str("fake-first-value");
    let first_id = vault.add_secret(&mut first).unwrap();
    let mut second = AddSecretDraft::new();
    second.set_name("second");
    second.fields_mut()[0].value_mut().push_str("fake-second-value");
    let second_id = vault.add_secret(&mut second).unwrap();
    let vault_session_id = vault.session_id().unwrap();
    let controller = Arc::new(Mutex::new(vault));
    let coordinator = Arc::new(RunCoordinator::default());
    let approval = Arc::new(ApprovalCoordinator::session_defaults());
    let handle = desktop_handle(Arc::clone(&coordinator), Arc::clone(&approval));
    let client = Uuid::new_v4();
    let waiting = {
        let approval = Arc::clone(&approval);
        thread::spawn(move || {
            approval.authorize(
                PendingApproval::new(
                    vault_session_id,
                    client,
                    "Codex — deploy",
                    vec![
                        ApprovalSecret::new(first_id, "first", ["value"]),
                        ApprovalSecret::new(second_id, "second", ["value"]),
                    ],
                    "/usr/bin/true",
                    std::iter::empty::<&str>(),
                    "/tmp",
                ),
                &RunCancellation::new(),
            )
        })
    };
    let pending = wait_for_pending_approval(&handle);
    handle.approve(pending.id()).unwrap();
    waiting.join().unwrap().unwrap();

    let lease = coordinator
        .try_start(RunCancellation::new(), client)
        .unwrap();
    lease.set_secret_context(vec![first_id]).unwrap();
    lease.mark_running().unwrap();
    let grants = handle.agent_grants(&controller).unwrap();
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().any(|grant| grant.secret_id() == first_id && grant.running()));
    assert!(grants.iter().any(|grant| grant.secret_id() == second_id && !grant.running()));
    assert!(!format!("{grants:?}").contains("fake-first-value"));

    handle.revoke_grant(client, second_id).unwrap();
    let grants = handle.agent_grants(&controller).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].secret_id(), first_id);
    drop(lease);
    handle.revoke_grant(client, first_id).unwrap();
    assert!(handle.agent_grants(&controller).unwrap().is_empty());
}
```

The coordinator tests from Step 1 provide bounded-channel proof that matching
pre-context/active work is cancelled and awaited while another client and a
known non-matching secret continue. Keep every wait bounded by
`recv_timeout`/`Instant` as shown there.

- [ ] **Step 5: Implement the GUI-only broker view and revoke method**

Add a metadata-only type with accessors:

```rust
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AgentGrantView {
    client_session_id: Uuid,
    client_label: String,
    secret_id: SecretId,
    secret_name: String,
    remaining: Duration,
    running: bool,
}
```

Implement on `LocalBrokerHandle`:

```rust
pub(crate) fn agent_grants(
    &self,
    controller: &Arc<Mutex<VaultController>>,
) -> Result<Vec<AgentGrantView>, LadonError>;

pub(crate) fn revoke_grant(
    &self,
    client_session_id: Uuid,
    secret_id: SecretId,
) -> Result<(), LadonError>;
```

`agent_grants` takes independent short-lived snapshots from approval,
coordinator, and controller; it must not hold two mutexes simultaneously. Join
secret IDs to current names, skip a missing ID defensively, set `running` from
the pair set, then sort by stored label, UUID bytes/string, and secret name.
Sanitize untrusted labels only in Task 7 at the rendering boundary.

`revoke_grant` acquires the existing local-UI operation guard, obtains the
targeted run block, calls `approval.revoke_pair`, and returns only after matching
child cleanup. A failed or externally owned operation returns a safe error and
does not mutate the row optimistically.

- [ ] **Step 6: Run broker tests and Clippy**

Run:

```bash
cargo test -p ladon-app --features gui agent_broker::tests -- --test-threads=1
cargo test -p ladon-app --test agent_broker_unix -- --test-threads=1
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: coordinator, snapshot, selective cancellation, and integration tests pass without deadlock.

- [ ] **Step 7: Commit race-safe broker observability**

```bash
git add crates/ladon-app/src/agent_broker.rs crates/ladon-app/tests/agent_broker_unix.rs
git commit -m "feat: observe and revoke agent grants"
```

---

### Task 5: Wire a conditionally clearing system clipboard

**Files:**
- Modify: `crates/ladon-app/Cargo.toml`
- Create: `crates/ladon-app/src/clipboard.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Modify: `crates/ladon-app/src/ui.rs`
- Modify: `crates/ladon-app/tests/ui_state.rs`

**Interfaces:**
- Consumes: existing `ClipboardLease`, `SensitiveBytes`, and already-resolved `arboard` 3.6.1 dependency.
- Produces: GUI-internal `SecretClipboard::copy`, `poll_clear`, and `clear_if_owned` for Task 6.

- [ ] **Step 1: Write failing backend-independent clipboard tests**

Create the module test with a fake backend holding a `Zeroizing<String>`:

```rust
#[test]
fn expired_ladon_value_is_cleared_but_newer_user_content_is_preserved() {
    let backend = FakeClipboard::default();
    let mut clipboard = SecretClipboard::with_backend(backend);
    clipboard
        .copy(SensitiveText::from("fake-copy-value").to_sensitive_bytes(), 1_000)
        .unwrap();

    clipboard.poll_clear(30_999).unwrap();
    assert_eq!(clipboard.test_text(), "fake-copy-value");
    clipboard.poll_clear(31_000).unwrap();
    assert_eq!(clipboard.test_text(), "");

    clipboard
        .copy(SensitiveText::from("fake-second-value").to_sensitive_bytes(), 40_000)
        .unwrap();
    clipboard.replace_for_test("user-newer-value");
    clipboard.poll_clear(70_000).unwrap();
    assert_eq!(clipboard.test_text(), "user-newer-value");
}

#[test]
fn lock_clear_is_immediate_only_when_ladon_still_owns_the_clipboard() {
    let backend = FakeClipboard::default();
    let mut clipboard = SecretClipboard::with_backend(backend);
    clipboard
        .copy(SensitiveText::from("fake-copy-value").to_sensitive_bytes(), 1_000)
        .unwrap();
    clipboard.clear_if_owned().unwrap();
    assert_eq!(clipboard.test_text(), "");

    clipboard
        .copy(SensitiveText::from("fake-second-value").to_sensitive_bytes(), 2_000)
        .unwrap();
    clipboard.replace_for_test("user-newer-value");
    clipboard.clear_if_owned().unwrap();
    assert_eq!(clipboard.test_text(), "user-newer-value");
}
```

Keep the existing `ClipboardLease` timing test and add `is_expired` assertions so backend reads can be skipped before the deadline.

- [ ] **Step 2: Run clipboard tests and verify RED**

Run:

```bash
cargo test -p ladon-app --all-features clipboard
cargo test -p ladon-app --test ui_state clipboard
```

Expected: compilation fails because `SecretClipboard` and `ClipboardLease::is_expired` are missing.

- [ ] **Step 3: Add the focused clipboard adapter**

Declare `arboard = { version = "3.6.1", optional = true }` and include
`dep:arboard` in the existing `gui` feature. Add an internal error with only the
safe display text `Clipboard is unavailable`; do not add clipboard errors to
the local RPC protocol.

Implement an internal backend boundary:

```rust
trait ClipboardBackend {
    fn set_text(&mut self, text: &str) -> Result<(), ClipboardError>;
    fn get_text(&mut self) -> Result<String, ClipboardError>;
}

pub(crate) struct SecretClipboard<B = SystemClipboard> {
    backend: B,
    lease: Option<ClipboardLease>,
}

impl<B: ClipboardBackend> SecretClipboard<B> {
    pub(crate) fn copy(&mut self, value: SensitiveBytes, now_ms: u64)
        -> Result<(), ClipboardError>;
    pub(crate) fn poll_clear(&mut self, now_ms: u64)
        -> Result<(), ClipboardError>;
    pub(crate) fn clear_if_owned(&mut self) -> Result<(), ClipboardError>;
}
```

`SystemClipboard` initializes `arboard::Clipboard` lazily. On copy, write the
UTF-8 text exposed from the owned `SensitiveBytes` and only then move those
bytes into a new `ClipboardLease`. On poll, avoid reading before
expiry; after expiry, zeroize the returned `String`, clear only on equality, and
drop the lease. On read/write error, keep the lease so a later frame or lock can
retry, but surface only the safe error.

- [ ] **Step 4: Run clipboard tests and GUI Clippy**

Run:

```bash
cargo test -p ladon-app --all-features clipboard
cargo test -p ladon-app --test ui_state clipboard
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: fake-backend tests prove conditional clear; no secret appears in Debug output.

- [ ] **Step 5: Commit clipboard lifecycle support**

```bash
git add crates/ladon-app/Cargo.toml Cargo.lock crates/ladon-app/src/clipboard.rs crates/ladon-app/src/lib.rs crates/ladon-app/src/ui.rs crates/ladon-app/tests/ui_state.rs
git commit -m "feat: clear copied secrets conditionally"
```

---

### Task 6: Correct selected-secret actions, visible editing, copy, and row sizing

**Files:**
- Modify: `crates/ladon-app/src/desktop.rs`

**Interfaces:**
- Consumes: `SecretClipboard` from Task 5 and existing `DetailMode`, `EditableValue`, and sensitive text-edit helpers.
- Produces: stable action-row helpers and the requested reveal/edit/copy UI behavior.

- [ ] **Step 1: Write failing pure action/layout tests**

Extend desktop tests with exact state-to-label expectations and sizing constants:

```rust
#[test]
fn selected_action_rows_keep_delete_with_the_primary_actions() {
    assert_eq!(selected_action_labels(SelectedActionSet::Unlock), (["Unlock this secret"].as_slice(), "Delete"));
    assert_eq!(selected_action_labels(SelectedActionSet::Hidden), (["Show", "Edit"].as_slice(), "Delete"));
    assert_eq!(selected_action_labels(SelectedActionSet::Revealed), (["Hide", "Edit"].as_slice(), "Delete"));
}

#[test]
fn remove_control_matches_the_sensitive_text_row_height() {
    assert_eq!(REMOVE_BUTTON_HEIGHT, SENSITIVE_FIELD_HEIGHT);
}
```

Add an egui headless test proving the editing helper is visible and still clears
undo state, paralleling the existing add-form visible-input test.

- [ ] **Step 2: Run focused desktop tests and verify RED**

Run:

```bash
cargo test -p ladon-app --all-features desktop::tests::selected_action_rows_keep_delete_with_the_primary_actions
cargo test -p ladon-app --all-features desktop::tests::editing_sensitive_input_is_visible_and_clears_undo
```

Expected: tests fail because the action-label helper/constants do not exist and edit mode still uses password rendering.

- [ ] **Step 3: Render one stable top action row**

Refactor `show_selected_workspace` so one `ui.horizontal` renders left actions
and a right-to-left destructive area in the same row. Keep confirmation in that
right-hand area:

```text
normal:  ... [Delete]
confirm: ... [Delete] [Cancel]
```

Preserve the existing `DetailAction` and `DeleteAction` state machines. Do not
allow delete while `DetailMode::Editing`; save/cancel remain below the draft.
Keep the action row before all fields.

- [ ] **Step 4: Make edit values visible and size remove controls**

Use `visible_sensitive_text_field` for `EditableValue::Text` in edit mode. Set a
single `SENSITIVE_FIELD_HEIGHT` for field-name, value, copy, and remove controls,
using `ui.add_sized` rather than glyph-dependent intrinsic height. Preserve:

- add-form index 0 cannot be removed;
- edit-form any index can be removed while more than one field remains; and
- binary fields remain a label without text editing or copy.

- [ ] **Step 5: Write failing copy-selection tests**

Extract a pure helper that returns text only for text values and test both modes:

```rust
#[test]
fn only_text_values_are_copyable() {
    let text = EditableValue::Text(SensitiveText::from("fake-copy-value"));
    assert_eq!(copyable_text(&text), Some("fake-copy-value"));
    let binary = EditableValue::Binary {
        bytes: SensitiveBytes::new(vec![0xff]),
        original_hint: TextHint::Binary,
    };
    assert_eq!(copyable_text(&binary), None);
}
```

- [ ] **Step 6: Integrate revealed/edit copy with the clipboard manager**

Add `clipboard: SecretClipboard` and `ui_clock_started: Instant` to
`LadonDesktop`. Render `Copy` next to every revealed text field and every
editable text value. Capture an owned
`SensitiveBytes` copy request during the UI borrow, then call the clipboard
manager after the match so no nested mutable borrow of `self` occurs. Copy the
current draft value in edit mode.

Use `ui_clock_started.elapsed()` with saturating `u128`-to-`u64` conversion as
the monotonic millisecond source; do not use wall-clock time. At the start of
each GUI update, call `poll_clear`; report one safe notice on failure without
replacing a more important destructive or authentication error. Before app
lock, vault lock, and shutdown cleanup, call `clear_if_owned` best-effort and
then drop the lease.

- [ ] **Step 7: Run selected-workspace tests**

Run:

```bash
cargo test -p ladon-app --all-features desktop::tests -- --test-threads=1
cargo test -p ladon-app --test ui_state
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: action layout, visible editing, copy selection, undo clearing, and lock cleanup pass.

- [ ] **Step 8: Commit selected-secret UX fixes**

```bash
git add crates/ladon-app/src/desktop.rs
git commit -m "fix: refine secret reveal and edit actions"
```

---

### Task 7: Render active access and normalize the left rail

**Files:**
- Modify: `crates/ladon-app/src/desktop.rs`

**Interfaces:**
- Consumes: `LocalBrokerHandle::agent_grants` and `revoke_grant` from Task 4.
- Produces: bounded active-access panel, live countdown, vector status marker, and normalized secret navigation typography/alignment.

- [ ] **Step 1: Write failing view-format tests**

Add pure tests for short IDs, countdown copy, stable sorting, and visual tokens:

```rust
#[test]
fn agent_access_formatting_is_stable_and_compact() {
    let id = Uuid::parse_str("a31f92c4-1111-2222-3333-444444444444").unwrap();
    assert_eq!(short_session_id(id), "a31f92c4");
    assert_eq!(format_grant_remaining(Duration::from_secs(23 * 60 + 41)), "23:41");
    assert_eq!(SECRET_ROW_TEXT_SIZE, NEW_SECRET_TEXT_SIZE);
    assert_eq!(SECRET_ROW_HEIGHT, NEW_SECRET_ROW_HEIGHT);
}
```

Add a view-model sorting test with repeated labels and names that verifies label,
full UUID, then secret-name order. Add a status-marker test against a pure
`status_dot_geometry` helper so the marker is a circle primitive, not `●` text.

- [ ] **Step 2: Run rail tests and verify RED**

Run:

```bash
cargo test -p ladon-app --all-features desktop::tests::agent_access_formatting_is_stable_and_compact
```

Expected: compilation fails because the format/layout helpers are absent.

- [ ] **Step 3: Add cached GUI-only access state and refresh logic**

Add `#[cfg(unix)] agent_grants: Vec<AgentGrantView>` to `LadonDesktop`, matching
the existing platform boundary around the local broker. Refresh it from the
broker once per UI frame while the app is active; `ApprovalCoordinator` already
purges on snapshot. On success replace the cache, on failure retain the previous
frame and surface the safe error once until a successful refresh resets the
error suppression.

When the vector is non-empty, call:

```rust
context.request_repaint_after(Duration::from_secs(1));
```

Clear the cache immediately on soft/hard lock, shutdown cleanup, full revoke,
and vault-session changes.

- [ ] **Step 4: Render the bounded active-access section**

Between unlocked status and the secret list, render:

- `Agent access · N`;
- a `ScrollArea::vertical().max_height(AGENT_ACCESS_MAX_HEIGHT)`;
- label plus `(reported)` and eight-character ID;
- secret name, optional `Running`, and `MM:SS` countdown;
- per-row `Revoke`; and
- `Revoke all` below the scroll area.

Capture a requested `(Uuid, SecretId)` during rendering and invoke
`revoke_grant` afterward. Refresh only after success. Keep the row and show a
safe notice on failure. Attach full label/name/UUID hover text and never put
secret field names or values in the panel.

- [ ] **Step 5: Normalize rail alignment and draw the status circle**

Replace `RichText::new("●  UNLOCKED")` with a horizontally allocated vector
circle using `Painter::circle_filled`, centered against the text baseline.
Define one `SECRET_ROW_TEXT_SIZE`, one `SECRET_ROW_HEIGHT`, and one leading
inset for `+ New secret` and all secret names. Render row contents with
`Layout::left_to_right(Align::Center)` and use only fill/text color to indicate
selection; do not change weight or size for the selected row.

- [ ] **Step 6: Run desktop and broker integration tests**

Run:

```bash
cargo test -p ladon-app --all-features desktop::tests -- --test-threads=1
cargo test -p ladon-app --test agent_broker_unix -- --test-threads=1
cargo clippy -p ladon-app --all-targets --all-features -- -D warnings
```

Expected: countdown, targeted action, cleanup, sorting, typography-token, and vector-marker tests pass.

- [ ] **Step 7: Commit active-access and rail UX**

```bash
git add crates/ladon-app/src/desktop.rs
git commit -m "feat: show active agent access"
```

---

### Task 8: Update security documentation, verify, review, and land

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol.md`
- Modify: `docs/threat-model.md`
- Modify only if it exists at landing time: `reports/2026-09-work-report.md`

**Interfaces:**
- Consumes: all shipped behavior from Tasks 1–7.
- Produces: accurate public behavior/security documentation and a verified commit landed on `origin/main`.

- [ ] **Step 1: Update documentation with exact shipped behavior**

Document all of the following explicitly:

```text
- ladon_identify_session is optional, process-local, untrusted, and non-secret.
- Active grants and targeted revoke are GUI-only and never cross RPC/MCP.
- Each grant remains fixed at 30 minutes and use does not extend it.
- Targeted revoke cancels a matching run and cannot erase bytes already consumed.
- Text copies are conditionally cleared after 30 seconds.
- Clipboard managers, OS history, and same-user impersonation remain out of scope.
```

Update the MCP tool list from four to five tools. Keep README examples free of real tokens.

- [ ] **Step 2: Run formatting and strict static analysis**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: both commands exit 0 with no warnings.

- [ ] **Step 3: Run the full suite serially**

Run:

```bash
cargo test --workspace --all-features -- --test-threads=1
```

Expected: all enabled tests pass; platform-specific ignored tests remain explicitly reported.

- [ ] **Step 4: Run smoke and release verification**

Run:

```bash
scripts/smoke-test.sh
cargo build --workspace --all-features --release
```

Expected: smoke exits 0 and both `target/release/ladon` and `target/release/ladon-app` build successfully.

- [ ] **Step 5: Perform the macOS UX/security checklist**

Launch `target/release/ladon-app` and verify with a real configured MCP client:

```text
1. ClientInfo fallback appears with an eight-character ID.
2. ladon_identify_session updates the reported name on the next request.
3. Approval creates one 30-minute row and the countdown decreases.
4. Running appears only during the child command.
5. Per-row revoke cancels a matching command but preserves another grant.
6. Revoke all clears every row.
7. Reveal and edit show text; Copy clears after 30 seconds but preserves newer clipboard content.
8. Unlock/Delete, Show/Edit/Delete, and Hide/Edit/Delete remain one line.
9. Remove buttons match inputs; rail text is aligned; the unlocked marker is circular.
10. App lock clears grants and attempts conditional clipboard cleanup.
```

- [ ] **Step 6: Request code review and resolve every critical/important finding**

Use `superpowers:requesting-code-review` over the complete feature range. For
each finding, use `superpowers:receiving-code-review`, reproduce it with a
failing test, implement the smallest fix, and rerun the relevant focused tests.

- [ ] **Step 7: Re-run exact final-tree verification after review fixes**

Run these commands again on the post-review tree; do not reuse earlier results:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --test-threads=1
scripts/smoke-test.sh
cargo build --workspace --all-features --release
```

Expected: every command exits 0 and both release binaries exist.

- [ ] **Step 8: Add the monthly work-report row only if the file exists**

After all verification passes, check for `reports/2026-09-work-report.md`. If it
exists, add exactly one row using its existing schema and style, preserving all
concurrent entries. If absent, do not create it.

- [ ] **Step 9: Commit documentation and any report row**

```bash
git add README.md docs/protocol.md docs/threat-model.md
git add reports/2026-09-work-report.md  # only when the file exists and changed
git commit -m "docs: explain active agent access"
```

- [ ] **Step 10: Synchronize and land the verified tree**

Using `superpowers:finishing-a-development-branch` and the repository delivery
rules:

```bash
git fetch origin main
git merge origin/main
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --test-threads=1
scripts/smoke-test.sh
cargo build --workspace --all-features --release
git push origin HEAD:main
git ls-remote origin refs/heads/main
```

Expected: the merged tree passes every check, and remote `refs/heads/main` SHA
equals the verified local feature SHA. If protection, authentication, a
concurrent non-fast-forward update, or verification failure blocks landing,
report the exact blocker and leave the verified commits recoverable without
claiming completion.
