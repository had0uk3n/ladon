# Session identification and unattended access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify live MCP connections and authorize a locally confirmed snapshot of secrets for unattended use through automatic UI locking.

**Architecture:** Extend the existing grant store with an explicit unattended permission flag. Keep bounded connection metadata and local aliases in the approval coordinator. The broker preserves only those grants on automatic locking and checks them again before secret resolution and spawn; the GUI captures a grant snapshot before authentication.

**Tech Stack:** Rust 1.85, existing egui/eframe GUI, local authenticated Unix IPC.

**Spec:** `docs/superpowers/specs/2026-10-12-session-unattended-access.md`

## Global Constraints

- MCP UUIDs remain the permission key; names, notes and paths cannot authorize.
- Metadata is bounded, memory-only and removed on disconnection.
- Unattended access requires fresh local Touch ID or session PIN confirmation.
- New secrets are excluded; edits/deletions revoke affected access and invalidate in-flight confirmations.
- Automatic interface locking preserves only explicitly confirmed unattended grants.
- Manual app lock, hard vault lock, revoke, deadline, connection loss and application exit revoke access.
- No secret values enter RPC or activity metadata; existing platform feature gates remain supported.

## Review Focus

- Manual lock after automatic lock must revoke preserved grants.
- A reconnect cannot inherit permissions or an alias from a disconnected connection.
- Mixed authorized/unauthorized secret requests while locked must fail closed.
- A delayed Touch ID result after a mutation or lock must not grant access.
- Clock changes and computer sleep must not extend the fixed calendar deadline.

### Task 1: Permission and session state

**Files:** Modify `crates/ladon-core/src/grants.rs`, `crates/ladon-app/src/approval.rs`, `crates/ladon-app/src/lib.rs`; test `crates/ladon-core/tests/grants.rs`, `crates/ladon-app/tests/approval_state.rs`.

**Interfaces:** `GrantStore::grant_unattended_until`, `missing_unattended`, `retain_unattended`; `ApprovalCoordinator::sessions`, `set_session_annotation`, `observe_run`, `grant_unattended`, `begin_auto_app_lock`, `require_client_access`.

- [x] Add and run failing behavioral tests: grant two snapshot IDs, automatic lock, verify the original request is still authorized and a third ID is rejected. Advance the fake wall clock to the deadline and reject the original IDs.
- [x] Implement explicit unattended grant metadata and bounded connected-session annotations; keep original grants unchanged.
- [x] Test disconnect/reconnect, stale mutation/lock snapshots, renaming without renewal, targeted revoke and manual lock after automatic lock.
- [x] Run `cargo test -p ladon-core --test grants` and `cargo test -p ladon-app --test approval_state`, with the integrated final candidate.

```rust
assert!(coordinator.with_valid_grant(&ticket, || Ok(())).is_ok());
clock.advance(Duration::from_secs(8 * 3600));
assert_eq!(coordinator.with_valid_grant(&ticket, || Ok(())), Err(LadonError::ApprovalCancelled));
```

### Task 2: Broker integration

**Files:** Modify `crates/ladon-app/src/agent_broker.rs`.

**Interfaces:** Consumes the coordinator interfaces; produces GUI-only session snapshots, captured unattended consent, grant/revoke operations and automatic app-lock completion.

- [x] Add failing integration tests against the real controller/broker: an authorized connection executes through automatic UI lock, another connection cannot, and metadata listing excludes newly added secrets.
- [x] Capture secret IDs, revision and lock epoch before authentication; validate them under the approval mutex before granting.
- [x] Bypass local unlock only for live connections with valid unattended grants, and retain the final grant check before resolution/spawn.
- [x] Preserve authorized running commands through automatic lock; cancel ordinary commands. Manual/full locks continue to cancel all commands.
- [x] Run `cargo test -p ladon-app --lib agent_broker::tests` outside the IPC-restricting sandbox with the integrated final candidate.

### Task 3: Cards, confirmation and delivery

**Files:** Modify `crates/ladon-app/src/desktop.rs`, `crates/ladon-app/src/approval_lifetime.rs`, `docs/threat-model.md`, `docs/protocol.md`, `README.md`.

**Interfaces:** Consumes broker session snapshots and captured consent; creates a separate unattended Touch ID target with immutable captured context.

- [x] Add failing GUI/auth tests for stale consent, manual lock after automatic lock and independent session annotations.
- [x] Render one card per live connection, including connections without grants; expose alias/note editing, project, last activity, status and session-wide revoke.
- [x] Add a dedicated snapshot confirmation modal with fixed expiry presets and local HH:MM, explicit locked-UI behavior and Touch ID/PIN actions.
- [x] Change only automatic lock to preserve unattended permissions; clear all new local UI buffers on locking.
- [x] Update human-facing access documentation; run format, clippy, workspace tests and release build.
- [ ] Review the complete branch in a fresh context; synchronize current main, verify relevant changed inputs, commit and publish the verified candidate directly to main under the user’s explicit Ladon MR exemption.
- [ ] Verify origin/main contains the delivered candidate; no MR or Gandalf run is required under the user’s explicit exemption. Publish one central work-report row only after verified source landing.
