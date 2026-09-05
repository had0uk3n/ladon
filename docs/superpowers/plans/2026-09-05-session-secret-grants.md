# Session Secret Grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one local client session use explicitly approved secrets for a fixed 30-minute lease, confirmed by an in-memory PIN or macOS Touch ID, without placing managed values in agent-visible data.

**Architecture:** The MCP/CLI process generates a random session UUID and includes it in every protocol-v2 request. The app resolves requested references to immutable secret IDs, consults an in-memory grant table keyed by `(client_session_id, secret_id)`, and pauses the first ungranted run for GUI approval. PIN verification and Touch ID authorize the pending grant; neither credential nor grant survives app exit, and no Keychain/native credential-store persistence is used.

**Tech Stack:** Rust 1.85, existing Cargo workspace, `eframe`/`egui`, Argon2id, Unix local IPC, macOS LocalAuthentication through `objc2-local-authentication`.

**Spec:** `docs/superpowers/specs/2026-09-04-ladon-design.md`

## Global Constraints

- No cloud service, provider adapter, browser engine, or user-installed runtime dependency.
- Managed values never appear in agent-facing RPC/MCP arguments or results.
- A grant is scoped to one client-session UUID and immutable secret ID, lasts a fixed 30 minutes, does not slide on use, and is revocable.
- Logical chat identity is not claimed because local clients do not provide a universal trusted conversation identifier.
- PIN verifier, grants, pending approval, and Touch ID state are memory-only and disappear on app exit; Keychain is not used.
- Touch ID is a macOS authorization gate for this threat model, not a cryptographic key-unwrapping claim.
- The vault file format remains unchanged.

---

### Task 1: Correct the approved specification

**Files:**
- Modify: `docs/superpowers/specs/2026-09-04-ladon-design.md`
- Modify: `docs/threat-model.md`
- Modify: `docs/protocol.md`

**Interfaces:**
- Consumes: the approved conversation decision.
- Produces: the normative lease and authentication rules used by all later tasks.

- [x] **Step 1: Replace persistent quick-PIN language**

Document this exact lifecycle: passphrase opens the vault; the user chooses a session PIN or Touch ID on macOS; the first ungranted use creates a two-minute pending approval; success creates fixed 30-minute grants for every referenced secret ID; PIN/auth state and grants are process-memory-only.

- [x] **Step 2: Replace global unlocked-session authorization**

Specify the key as `(client_session_id, secret_id)`, non-sliding expiry, early revocation, multi-secret approval, MCP-process scope rather than chat scope, and the impossibility of revoking a copy already received by an authorized child.

- [x] **Step 3: Update protocol and acceptance criteria**

Specify protocol v2 `client_session_id`, per-client/per-secret grant scope, PIN fallback, strict Touch ID behavior, and no native credential store.

### Task 2: Add portable fixed grant semantics

**Files:**
- Create: `crates/ladon-core/src/grants.rs`
- Modify: `crates/ladon-core/src/lib.rs`
- Test: `crates/ladon-core/tests/grants.rs`

**Interfaces:**
- Consumes: `MonotonicClock`, `SecretId`, and `uuid::Uuid`.
- Produces: `GrantStore<C>::new(clock, Duration)`, `grant(client_session_id, secret_ids)`, `missing(client_session_id, secret_ids)`, `revoke_all()`, and `remaining(client_session_id, secret_id)`.

- [x] **Step 1: Write failing fixed-scope tests**

Tests must prove that a grant covers only the exact client/secret pair, a multi-secret approval covers each listed ID, use does not extend the deadline, expiry removes access, and `revoke_all` removes every lease.

- [x] **Step 2: Run the focused test and observe RED**

Run `cargo test -p ladon-core --test grants`; expect an unresolved `GrantStore` import before implementation.

- [x] **Step 3: Implement the minimal grant table**

Use a `HashMap<(Uuid, SecretId), u64>` with saturating monotonic deadlines, purge expired entries before queries, and deduplicate input IDs.

- [x] **Step 4: Run focused and core tests GREEN**

Run `cargo test -p ladon-core --test grants` and `cargo test -p ladon-core --all-targets`.

### Task 3: Add client-session identity to protocol v2

**Files:**
- Modify: `crates/ladon-core/src/protocol.rs`
- Modify: `crates/ladon-cli/src/commands.rs`
- Modify: `crates/ladon-cli/src/mcp.rs`
- Test: `crates/ladon-core/tests/protocol.rs`
- Test: `crates/ladon-cli/tests/mcp_contract.rs`
- Test: `crates/ladon-cli/tests/cli_contract.rs`

**Interfaces:**
- Consumes: `RpcRequest` and MCP stdio loop.
- Produces: required `client_session_id: Uuid`; one random ID reused for the lifetime of `ladon mcp`; a fresh ID for a one-shot human CLI invocation.

- [x] **Step 1: Write failing protocol and MCP tests**

Assert that protocol v1 is rejected, protocol v2 round-trips a client session UUID, two MCP calls from one server instance send the same UUID, and a new server instance uses a different UUID.

- [x] **Step 2: Run focused tests and observe RED**

Run `cargo test -p ladon-core --test protocol` and `cargo test -p ladon --test mcp_contract`.

- [x] **Step 3: Implement protocol v2 and stable MCP identity**

Add `client_session_id` to `RpcRequest`, validate `version == 2`, generate the MCP UUID once in `serve_mcp`, and thread it through `call_tool`; do not expose it as a tool argument or result.

- [x] **Step 4: Run focused tests GREEN**

Run both focused test commands and confirm no managed value or session token appears in MCP output.

### Task 4: Add memory-only session authentication

**Files:**
- Create: `crates/ladon-app/src/session_auth.rs`
- Create: `crates/ladon-app/src/touch_id.rs`
- Modify: `crates/ladon-app/src/lib.rs`
- Modify: `crates/ladon-app/Cargo.toml`
- Test: `crates/ladon-app/tests/session_auth.rs`

**Interfaces:**
- Produces: `SessionPin::new(pin, confirmation)`, `SessionPin::verify(pin)`, and `TouchIdAuthenticator::{is_available, authenticate}` with a non-macOS unavailable implementation.

- [x] **Step 1: Write failing PIN behavior tests**

Prove 6--12 ASCII digits are accepted, mismatches/non-digits/other lengths are rejected, the correct PIN verifies, an incorrect PIN fails generically, and Debug output contains no PIN.

- [x] **Step 2: Run the PIN test and observe RED**

Run `cargo test -p ladon-app --test session_auth --no-default-features`.

- [x] **Step 3: Implement PIN hashing**

Generate a random salt with `getrandom`, hash with Argon2id into a fixed 32-byte `Zeroizing` buffer, compare verification output in constant time, and retain only salt/hash/attempt state in memory.

- [x] **Step 4: Add the macOS Touch ID adapter**

On macOS, preflight and evaluate `LAPolicyDeviceOwnerAuthenticationWithBiometrics` with a fresh `LAContext`, no allowable reuse duration, and no system-password fallback. On other targets return unavailable without adding a runtime dependency.

- [x] **Step 5: Run authentication tests GREEN and compile GUI**

Run `cargo test -p ladon-app --test session_auth --no-default-features` and `cargo check -p ladon-app --all-features`.

### Task 5: Gate secret-bearing runs through GUI approval

**Files:**
- Create: `crates/ladon-app/src/approval.rs`
- Modify: `crates/ladon-app/src/agent_broker.rs`
- Modify: `crates/ladon-app/src/ui.rs`
- Modify: `crates/ladon-app/src/desktop.rs`
- Test: `crates/ladon-app/tests/approval_state.rs`
- Test: `crates/ladon-app/tests/agent_broker_unix.rs`
- Test: `crates/ladon-app/tests/ui_state.rs`

**Interfaces:**
- Consumes: protocol-v2 session UUID, validated bindings, immutable secret IDs, `GrantStore`, and `RunCancellation`.
- Produces: `ApprovalCoordinator::{authorize, pending, approve, deny, revoke_all}` and a sanitized pending view containing client label, executable/arguments/cwd, and secret names/fields but no values.

- [x] **Step 1: Write failing coordinator tests**

Prove the first access blocks and exposes one pending request, approval resumes it and grants every referenced secret, repeated use during the fixed lease skips the prompt, another session/secret prompts, denial/timeout/disconnect starts no child, and only one request can be pending.

- [x] **Step 2: Run focused tests and observe RED**

Run `cargo test -p ladon-app --test approval_state --no-default-features`.

- [x] **Step 3: Implement the coordinator and metadata resolution**

Resolve secret references to IDs before extracting values, wait on a condition variable for at most two minutes while checking connection cancellation, grant only the pending request's missing IDs, and clear grants on vault lock/shutdown.

- [x] **Step 4: Add session-auth setup and approval GUI**

After vault create/unlock, require either a 6--12 digit session PIN or available Touch ID. Render pending metadata as escaped plain text; approve only after credential success; provide Deny and Revoke grants actions; clear PIN entry immediately.

- [x] **Step 5: Add and run Unix integration tests**

Run `cargo test -p ladon-app --test agent_broker_unix -- --test-threads=1` outside the filesystem sandbox. Verify a first request does not launch before approval and a second request for the same pair launches without another approval.

### Task 6: Documentation, review, and delivery

**Files:**
- Modify: `README.md`
- Modify: `docs/security-review.md`
- Modify: `docs/protocol.md`

**Interfaces:**
- Consumes: implemented behavior and final verification output.
- Produces: accurate user instructions, limitations, build/test steps, and a landed commit on `origin/main`.

- [x] **Step 1: Update user documentation**

Explain setup, PIN/Touch ID choice, 30-minute per-client/per-secret lease, manual revocation, fixed expiry, MCP-process scope, and the already-delivered-value limitation.

- [x] **Step 2: Run format, lint, tests, and smoke test**

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features` outside the socket-restricted sandbox, and `scripts/smoke-test.sh`.

- [x] **Step 3: Request independent code review**

Review the complete diff against this plan, fix every Critical/Important issue, and rerun the affected tests.

- [ ] **Step 4: Synchronize and land**

Fetch `origin/main`, incorporate concurrent changes without rewriting them, rerun verification on the exact tree, commit all in-scope changes, push `main`, and confirm `origin/main` resolves to the landed SHA.
