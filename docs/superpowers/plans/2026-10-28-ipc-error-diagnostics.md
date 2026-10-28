# IPC error diagnostics Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans; implement the single integrated slice below. Steps use checkbox syntax for tracking.

**Goal:** Replace misleading IPC failures with accurate, safe agent-facing recovery information without stopping the shared Ladon app.

**Architecture:** Classify transport closure and timeout separately from malformed frames. Reply to a well-framed but rejected request when its validated request UUID is recoverable. Keep the MCP consumer aware of whether failure happened before submitting a command or after dispatch, with user-owned recovery and no implicit retry.

**Tech Stack:** Existing Rust workspace, bounded JSON/Unix IPC, MCP bridge; no new dependencies.

**Spec:** The scope and constraints in this plan implement the user’s 2026-10-28 request to fix the error that prompted another agent to restart Ladon.

## Scope and global constraints

- Diagnose the actual compatibility failure: pre-SessionOpen GUI builds reject the newer session handshake while sharing protocol version 2.
- Preserve version 2 framing, existing authentication, frame/JSON bounds and session authorization. Never fall back to untracked grants.
- No changes to the running GUI, user vault, integration settings or broad agent permissions. Use only isolated temporary sockets and fake data for reproduction.
- Distinguish EOF/disconnect, timeout, malformed frame and invalid/mismatched response. No raw JSON, executable arguments, bindings or secret values in diagnostics.
- A rejected request must not reach its handler. Reply only when a bounded, valid JSON envelope supplies a valid request UUID.
- MCP communication failures identify the local service, phase and recovery owner. Session admission failure means the command was not submitted. A lost run reply means execution is unknown and must never trigger automatic retry.
- Recovery requires the user to check the running app/client compatibility; agents must not kill, restart, lock or replace the shared app.
- Implement natively in the existing isolated worktree; obtain fresh independent review after local verification. The user’s explicit Ladon no-MR exception remains in force. Publish only the fully verified candidate directly to main, then one central report row.

## Review focus

- Legacy GUI closes an unsupported session handshake: return actionable admission failure; no Run is sent.
- GUI disappears after accepting Run: report uncertain execution; no replay.
- Invalid version/method/parameters with valid identity: correlated safe rejection; handler side effects remain absent.
- Truncated or invalid JSON and spoofed response UUIDs: reject deterministically without reflecting payload data.
- Current GUI sessions, locked status, denial and ordinary tool errors keep their existing behavior.

## Integrated task: typed IPC failure and MCP recovery

**Files:** `crates/ladon-core/src/error.rs`, `crates/ladon-core/src/protocol.rs`, `crates/ladon-app/src/ipc.rs`, `crates/ladon-cli/src/mcp.rs`, `crates/ladon-cli/src/client.rs`, `crates/ladon-cli/src/commands.rs`, protocol exports, focused tests in corresponding modules and `crates/ladon-cli/tests/`, plus `docs/protocol.md`.

**Interfaces:** Add closed transport/response failure variants to LadonError. Add a bounded request-error response adapter in protocol.rs, consumed by every LocalServer entry point. The MCP error adapter receives the local call phase and projects safe recovery metadata.

- [x] Reproduce legacy SessionOpen failure using the actual older headless IPC server source and current installed client, on a private socket.
- [x] Add failing behavioral tests for EOF/timeout/correlation and safe request rejection, with truthful @covers markers; verify RED before production changes.
- [x] Add an MCP socket integration regression: legacy admission failure emits ask-user recovery and sends no run; lost reply reports uncertainty and causes no retry. Verify RED.
- [x] Implement the minimal shared adapters and MCP projection; run focused tests GREEN.
- [x] Update protocol documentation and review complete delta independently.
- [ ] Run required fmt, all-feature/all-target clippy, serial workspace tests, smoke and release build; refresh main, inspect changed inputs, commit and deliver the verified candidate under the existing no-MR exception.
- [ ] Verify remote main, preserve a separate build for user-controlled app update, and publish one source-free central report row after landing.

## Contract Impact — local-ipc-agent-error
Mode: full
Boundary, component owner, and accountable owner: Ladon local IPC and MCP error boundary; owning component and maintainer are the Ladon repository maintainers.
Producer: LocalServer request decoder and LocalClient response reader.
Change classification — new contract, contract evolution, or documented-behavior restoration: Contract evolution of communication-failure states and safe rejection responses.
Contract type and version: Existing bounded protocol-v2 RpcResponse/RpcRequest, closed LadonError codes, additive MCP recovery metadata.
Raw sources/versions, canonical adapters, unknown-field policy, and intrinsic validator: Existing length-prefixed JSON v2 and canonical bounded JSON validator; unknown methods/semantic versions reject. Recover only UUID identity from independently validated JSON on decoder failure. Unrelated fields are ignored by identity recovery because they neither authorize nor affect the constant error response.
Allowed inputs, states, outputs, and closed failures: Current requests succeed unchanged. Closed, timed-out, malformed and invalid responses remain distinct. Well-framed rejected requests yield a safe correlated RpcResponse. MCP distinguishes pre-dispatch admission failure and uncertain post-dispatch execution.
Direct and passthrough consumers: LocalClient, LocalRpcTransport, CLI execute_cli, MCP serve_mcp and external tool clients. New core codes round-trip through from_code. CLI distinguishes local usage/output errors from service rejection and reports recovery only for the latter. Unknown peer error codes become canonical invalid_response; raw peer codes/messages are never reflected. MCP emits isError plus bounded recovery metadata.
Composition stages, aggregate postconditions, source precedence, identity, ordering, duplicates, conflicts, and completeness: Read complete bounded frame, validate JSON and protocol, validate response UUID, project typed error. Error response echoes only validated request UUID; no partial message becomes a success. No independent aggregate or merge.
Concurrency invariant, linearization point, recovery, and side-effect cardinality: Request handler runs only after successful decode. Failed session opening never sends the run request. A sent request is never automatically replayed after connection failure. Existing session/run serialization remains unchanged.
Context delta and sole merger: Not applicable — no cross-call context delta; MCP constructs the sole tool error result.
Effects, capabilities, receipts, fences, retries, and uncertainty: No new authorization or global process-management capability. Transport failure after Run dispatch is explicitly uncertain, not evidence that no command ran. Recovery belongs to the user; no automatic retry or app restart.
Compatibility, rollout, adapter, and removal condition: Preserve wire version 2 and existing success shapes. New GUI safely rejects malformed/unsupported requests. Updated clients diagnose EOF from old GUI without changing or restarting it. Existing legacy core readers reject unknown errors conservatively; updated CLI preserves new codes. Binary rollout is user-controlled and separate from the running shared app.
Finite state matrix, total generated-case/time budgets, and tests: Explicit cases for empty/partial EOF, read timeout, malformed length/JSON, mismatched response UUID, unsupported version/method, valid response, pre-dispatch session rejection, and post-dispatch lost reply. No random or generated expansion. Focused suite target under 60 seconds excluding compilation; full workspace uses existing serial command.
Bounds, performance budget, and safe diagnostics: Existing 4 MiB frame and JSON depth limits. Additional bounded parsing occurs only on rejected requests; no retries or extra success-path RPC. Diagnostics contain constant messages, enum codes, phase and UUID correlation only, never raw payloads or secret values.
Unresolved evidence and fail-closed resolution: none for this slice. The legacy-source reproduction, focused RED/GREEN, safe unknown-code closure, independent review and final checks completed. The running app and MCP processes remain unchanged; deploying binaries is user-controlled. OS-level process isolation is a separate task.
Exact evidence revision, commands/environment, and closure verdict: complete — implementation fingerprint sha256:3f2b2f12a376887ed3b4b075a0566e24e218325d2918dc22651f26ce9232b0c0 over sorted changed Rust path/SHA256 pairs serialized by json.dumps(mapping, sort_keys=True), default separators; starting revision dc2bd9c1dff0543aa2150e90cc635da9e5f19c2b, final implementation commit contains this record. On macOS with rustc/cargo 1.98.0, cargo fmt --all -- --check; cargo clippy --workspace --all-targets --all-features -- -D warnings; cargo test --workspace --all-features -- --test-threads=1 (338 passed, 8 pre-existing ignored); scripts/smoke-test.sh; CARGO_NET_OFFLINE=true cargo build --workspace --all-features --release all passed. Actual749b511 headless server plus installed pre-fix client reproduced status success and SessionOpen invalid_frame on an isolated socket; final integration tests prove safe recovery for that closure and uncertain Run replies. Final independent scoped review accepted both genuine P2 repairs. Test-writing packet test-writing-rules.v1, contract sha256:e148f9c0f8931a3d44107daa940e74e3d2b122cb32d477e9d7203ac308c78f59, no project-specific rules returned.
