# Ladon V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan.

**Goal:** Deliver a small, auditable, cross-platform local secret broker whose GUI owns an encrypted vault and whose CLI/MCP runner injects named secrets without returning their plaintext.

**Architecture:** A Rust workspace separates portable security logic (`ladon-core`) from the desktop broker (`ladon-app`) and the thin human/MCP client (`ladon`). The application is the only process that decrypts the vault; clients communicate over same-user local IPC and can request metadata, locking, or a bounded child-process run. Platform-specific IPC, credential-store, screen-lock, and process-tree code sits behind narrow traits so the portable vault and protocol remain independently testable.

**Tech Stack:** Stable Rust (MSRV 1.85), Cargo workspace, `eframe`/`egui`, XChaCha20-Poly1305, Argon2id, `minicbor`, `serde_json`, Unix domain sockets / Windows named pipes, native credential stores, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-04-ladon-design.md`

## Global Constraints

- Plaintext secret bytes never appear in CLI arguments, IPC results, normal logs, panic messages, or persisted activity.
- GUI is the only CRUD and reveal surface; CLI and MCP expose only `list`, `status`, `lock`, and `run`.
- The generic runner is provider-independent and accepts only environment, stdin, or temporary-file bindings.
- Protocol frames, vault payloads, fields, bindings, output, timeouts, and concurrency are bounded exactly as specified.
- Every behavior change starts with a failing test. Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features` before landing.
- Never use real credentials in fixtures, snapshots, examples, or CI.

---

### Task 1: Bootstrap the workspace and shared domain model

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `crates/ladon-core/Cargo.toml`
- Create: `crates/ladon-core/src/lib.rs`
- Create: `crates/ladon-core/src/error.rs`
- Create: `crates/ladon-core/src/model.rs`
- Create: `crates/ladon-core/tests/model_validation.rs`
- Create: `crates/ladon-app/Cargo.toml`
- Create: `crates/ladon-app/src/main.rs`
- Create: `crates/ladon-cli/Cargo.toml`
- Create: `crates/ladon-cli/src/main.rs`

- [x] Write validation tests for NFC-normalized secret names, reserved `id:` and `::`, bidi/control rejection, field grammar, per-field size, and immutable UUID references.
- [x] Run `cargo test -p ladon-core --test model_validation`; expect compilation or missing-symbol failure.
- [x] Add `SecretId`, `SecretRef`, `FieldName`, `SecretRecord`, `SecretField`, `TextHint`, and a non-secret `LadonError` with stable machine-readable codes.
- [x] Implement constructors as the only public route to validated names and fields. Example public surface:

```rust
impl SecretRef {
    pub fn parse(input: &str) -> Result<Self, LadonError>;
}

impl FieldName {
    pub fn parse(input: &str) -> Result<Self, LadonError>;
}
```

- [x] Re-run the focused test, then `cargo test --workspace`; expect pass.
- [x] Commit: `feat: bootstrap Ladon workspace and domain model`.

### Task 2: Implement secret-memory wrappers and deterministic vault encoding

**Files:**
- Create: `crates/ladon-core/src/sensitive.rs`
- Create: `crates/ladon-core/src/codec.rs`
- Create: `crates/ladon-core/tests/codec_roundtrip.rs`
- Modify: `crates/ladon-core/src/lib.rs`
- Modify: `crates/ladon-core/src/model.rs`

- [x] Write tests proving `SensitiveBytes` has redacted `Debug`, is non-cloneable and non-serializable, permits only explicit closure access, and rejects a decoded payload above 64 MiB. Delegate drop zeroization to `zeroize::Zeroizing` rather than testing upstream internals.
- [x] Add golden-byte tests for deterministic canonical CBOR ordering and round-tripping binary and text-hinted fields.
- [x] Run `cargo test -p ladon-core --test codec_roundtrip`; expect failure.
- [x] Implement `SensitiveBytes` with `zeroize`, explicit exposure methods scoped to closures, and constant non-secret formatting.
- [x] Encode the payload manually with `minicbor::Encoder` using integer map keys in ascending order; reject unknown required fields, duplicate keys, invalid UUIDs, invalid names, and trailing bytes on decode.
- [x] Re-run focused and workspace tests; expect pass.
- [x] Commit: `feat: add bounded canonical vault payload codec`.

### Task 3: Implement the versioned encrypted vault envelope

**Files:**
- Create: `crates/ladon-core/src/crypto.rs`
- Create: `crates/ladon-core/tests/vault_crypto.rs`
- Create: `crates/ladon-core/tests/fixtures/v1-empty-vault.hex`
- Modify: `crates/ladon-core/src/lib.rs`

- [x] Write tests for XChaCha20-Poly1305 round trip, wrong passphrase, modified header/ciphertext/tag, truncated input, unsupported version/KDF/cipher IDs, and fixed v1 fixture compatibility.
- [x] Write a test confirming passphrase rotation replaces the data-encryption key, wrapping salt, both nonces, and both ciphertexts so an old vault copy cannot be unlocked with the new session key.
- [x] Run `cargo test -p ladon-core --test vault_crypto`; expect failure.
- [x] Implement the exact v1 envelope from the spec: authenticated fixed header, Argon2id parameters (64 MiB, 3 iterations, parallelism 4), random salt/nonces/DEK, and XChaCha20-Poly1305 for both wrapped DEK and payload.
- [x] Keep passphrases/keys in `SensitiveBytes`, cap attacker-controlled lengths before allocation or KDF work, and map all authentication failures to one non-oracular error.
- [x] Generate the fixture from deterministic test-only inputs and document that production randomness cannot be overridden.
- [x] Re-run focused and workspace tests; expect pass.
- [x] Commit: `feat: implement authenticated portable vault envelope`.

### Task 4: Add crash-safe vault persistence and GUI-owned CRUD service

**Files:**
- Create: `crates/ladon-core/src/store.rs`
- Create: `crates/ladon-core/src/vault.rs`
- Create: `crates/ladon-core/tests/store_recovery.rs`
- Create: `crates/ladon-core/tests/vault_crud.rs`
- Modify: `crates/ladon-core/src/lib.rs`

- [x] Write CRUD tests for duplicate normalized names, UUID lookup, ordered multi-field records, rename/update/delete, generation increments, and the 64 MiB aggregate bound.
- [x] Write filesystem fault tests for first save, replacement, primary corruption with valid `.bak`, both copies invalid, stale temporary files, and restrictive permissions.
- [x] Run the two focused tests; expect failure.
- [x] Implement an unlocked `VaultSession` that owns the DEK and records, exposes no plaintext serialization, and resets an injected idle-clock hook only on use/mutation.
- [x] Implement the two-current-copy write protocol: write/sync two candidates, atomically install the first as `.bak`, atomically install the second as primary, sync each directory change where supported, and never promote an unauthenticated copy.
- [x] Re-run focused and workspace tests; expect pass.
- [x] Commit: `feat: add crash-safe vault store and CRUD service`.

### Task 5: Define bounded IPC and broker state transitions

**Files:**
- Create: `crates/ladon-core/src/protocol.rs`
- Create: `crates/ladon-core/src/broker.rs`
- Create: `crates/ladon-core/tests/protocol.rs`
- Create: `crates/ladon-core/tests/broker_state.rs`
- Modify: `crates/ladon-core/src/lib.rs`

- [x] Write JSON fixture tests for versioned `status`, `list`, `lock`, and `run` requests/results plus stable error codes.
- [x] Write length-prefix tests rejecting zero/oversized (>4 MiB), malformed, partial, duplicate-field, and extra trailing frames before state mutation.
- [x] Write a deterministic state-machine test for locked, one pending unlock, busy rejection, two-minute timeout, unlocked idle expiry, active-run timer pause, and lock-triggered cancellation-before-wipe.
- [x] Run focused tests; expect failure.
- [x] Implement explicit DTOs that contain only secret references/field names and sanitized metadata; add a recursive test that successful agent-facing responses contain no secret-byte field.
- [x] Implement `BrokerState` with injected monotonic clock and event enum; keep only bounded in-memory current-lifetime activity.
- [x] Re-run focused and workspace tests; expect pass.
- [x] Commit: `feat: define bounded IPC protocol and broker state`.

### Task 6: Implement streaming output redaction

**Files:**
- Create: `crates/ladon-core/src/redact.rs`
- Create: `crates/ladon-core/tests/redaction.rs`
- Modify: `crates/ladon-core/src/lib.rs`

- [x] Write tests for raw, JSON-escaped, URL-encoded percent-case variants, hexadecimal, Base64/Base64URL padded and unpadded values, overlapping secrets, binary output, and secrets split across read boundaries.
- [x] Add property tests asserting that no configured transform of a managed value survives in returned output and output never exceeds the configured 512 KiB default / 2 MiB hard maximum.
- [x] Run `cargo test -p ladon-core --test redaction`; expect failure.
- [x] Implement a streaming multi-pattern redactor that holds enough suffix bytes to detect boundary-spanning matches, replaces matches with labeled `[REDACTED:secret-id.field]` markers, and records truncation/redaction flags without logging needles.
- [x] Re-run focused and workspace tests; expect pass.
- [x] Commit: `feat: add bounded streaming secret redaction`.

### Task 7: Implement generic run validation and process supervision

**Files:**
- Create: `crates/ladon-core/src/runner.rs`
- Create: `crates/ladon-app/src/supervisor.rs`
- Create: `crates/ladon-app/tests/runner_integration.rs`
- Create: `crates/ladon-app/tests/helpers/echo_fixture.rs`
- Modify: `crates/ladon-app/src/main.rs`

- [x] Write tests rejecting relative executable paths at the app boundary, duplicate env names, multiple stdin bindings, invalid temp filenames, >16 bindings, >1 MiB aggregate injected bytes, and timeout/output limits above policy.
- [x] Write integration tests for env/stdin/temp-file injection, minimal inherited environment, direct execution without a shell, temp cleanup, output redaction, timeout, user cancellation, large duplex I/O, and one-run concurrency.
- [x] Run `cargo test -p ladon-app --test runner_integration`; expect failure.
- [x] Implement `RunRequest` validation in core and a supervisor that resolves secret fields only after all non-secret validation passes.
- [x] On Unix, create a new process group, disable core dumps, cancel the group TERM→bounded grace→KILL, and keep the unlocked session until the process tree is gone. On Windows, use a Job Object with kill-on-close behind `cfg(windows)`.
- [x] Open temp files with user-only permissions and delete them on every normal/error/cancel path; clearly surface best-effort deletion semantics.
- [x] Re-run focused and workspace tests, plus strict Windows cross-compilation; expect pass.
- [x] Commit: `feat: add generic supervised secret runner`.

Before the security-preview release, add the Unix app-death liveness pipe and
native Windows ACL integration test described in the specification; these are
release gates, not required for exercising the end-to-end local MVP.

### Task 8: Add same-user local transports and the thin CLI/MCP client

**Files:**
- Create: `crates/ladon-app/src/ipc.rs`
- Create: `crates/ladon-app/src/ipc/unix.rs`
- Create: `crates/ladon-app/src/ipc/windows.rs`
- Create: `crates/ladon-cli/src/client.rs`
- Create: `crates/ladon-cli/src/commands.rs`
- Create: `crates/ladon-cli/src/mcp.rs`
- Create: `crates/ladon-cli/tests/cli_contract.rs`
- Create: `crates/ladon-cli/tests/mcp_contract.rs`
- Modify: `crates/ladon-cli/src/main.rs`
- Modify: `crates/ladon-app/src/main.rs`

- [ ] Write transport tests for owner-only endpoint permissions, peer-user validation, stale endpoint recovery, single-instance refusal, partial/oversized frames, and connection teardown.
- [ ] Write CLI/MCP contract tests proving stdout/JSON-RPC never contains injected values, list returns metadata only, run resolves executable names client-side then sends an absolute path, and MCP caps timeouts at 15 minutes while CLI caps at 2 hours.
- [ ] Run focused tests; expect failure.
- [ ] Implement Unix sockets in a `0700` runtime directory with peer credentials where available; implement Windows named pipes with an owner-only security descriptor and client impersonation/SID validation.
- [ ] Implement `ladon status|list|lock|run`, structured exit codes, and stdio MCP tools `ladon_status`, `ladon_list`, `ladon_lock`, `ladon_run`; ensure diagnostics go to stderr and never include plaintext.
- [ ] Implement `ladon setup codex|claude` as an idempotent, preview-before-write configuration edit with a timestamped backup.
- [ ] Re-run focused and workspace tests; expect pass.
- [ ] Commit: `feat: add local IPC CLI and MCP bridge`.

### Task 9: Build the minimal tray GUI and quick-unlock abstraction

**Files:**
- Create: `crates/ladon-app/src/app.rs`
- Create: `crates/ladon-app/src/ui.rs`
- Create: `crates/ladon-app/src/quick_unlock.rs`
- Create: `crates/ladon-app/src/quick_unlock/macos.rs`
- Create: `crates/ladon-app/src/quick_unlock/windows.rs`
- Create: `crates/ladon-app/src/quick_unlock/linux.rs`
- Create: `crates/ladon-app/tests/ui_state.rs`
- Modify: `crates/ladon-app/src/main.rs`

- [ ] Write headless UI-state tests for first-run passphrase validation, one-field default add flow, additional fields, locked/unlocked views, ten-second reveal, clipboard-clear eligibility, sanitized unlock-request rendering, deny/timeout, and exact pending-request resumption.
- [ ] Run `cargo test -p ladon-app --test ui_state`; expect failure.
- [ ] Implement the small state model first, then render it with `eframe`/`egui`; closing hides the manager while the broker remains alive, and tray state exposes remaining idle time and lock/quit controls.
- [ ] Add a `QuickUnlockStore` trait. Implement Keychain, Credential Manager, and Secret Service adapters so only a random device wrapping key is native-stored; bind the PIN verifier/wrapped material to vault ID and apply retry backoff. If unavailable, hide quick PIN and keep passphrase unlock functional.
- [ ] Integrate screen-lock/suspend notifications behind platform modules; on notification, invoke the same cancel-then-wipe transition tested in Task 5.
- [ ] Re-run focused and workspace tests; expect pass.
- [ ] Commit: `feat: add minimal tray vault manager`.

### Task 10: Package, document, and harden the security preview

**Files:**
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `LICENSE`
- Create: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`
- Create: `deny.toml`
- Create: `docs/threat-model.md`
- Create: `docs/file-format.md`
- Create: `docs/protocol.md`
- Create: `scripts/smoke-test.sh`
- Modify: `.gitignore`

- [ ] Write smoke tests that initialize a temporary vault, add a fake value through the application test harness, run a fixture through CLI and MCP, assert redaction, lock, and verify subsequent use requires unlock.
- [ ] Document the threat boundaries prominently, including same-user compromise, malicious authorized children, transformed exfiltration, clipboard/temp-file residue, crash dumps, backups, and rollback.
- [ ] Add macOS/Windows/Linux CI for format, clippy, tests, dependency/license policy, and release builds; do not place secrets in CI.
- [ ] Run `cargo fmt --check`, strict clippy, all workspace tests/features, `cargo deny check`, and `scripts/smoke-test.sh`; expect pass.
- [ ] Perform a source scan for `println!`, `dbg!`, `Debug` derives on secret-bearing types, secret values in errors, unbounded allocations, and shell invocation.
- [ ] Build release artifacts on all three CI platforms, exercise first run/add/run/lock/unlock, and record remaining platform caveats in the release notes.
- [ ] Commit: `docs: prepare Ladon security preview`.

### Task 11: Independent review fixes and stable-v1 gate

**Files:**
- Modify: files identified by review
- Create: `docs/security-review.md`

- [ ] Have an independent reviewer inspect cryptography, serialization, IPC authorization, runner cleanup, secret lifetime, and every agent-facing output against the spec.
- [ ] Convert each confirmed issue into a failing regression test before fixing it.
- [ ] Re-run the complete verification matrix on the exact release tree; expect pass on macOS, Windows, and Linux.
- [ ] Confirm every acceptance criterion in section 15 with a link to a test or documented manual check; do not promote while any criterion is unverified.
- [ ] Commit: `fix: address independent security review`.

### Task 12: Land without losing concurrent work

**Files:**
- Modify: `reports/2026-09-work-report.md` only if it already exists at completion time

- [ ] Fetch `origin/main`; inspect divergence and any concurrent work before integrating.
- [ ] Rebase or merge without rewriting unrelated changes, then rerun the complete required verification on the exact landing tree.
- [ ] If the monthly report already exists, append exactly one non-duplicative row after verification and include it in the landed commit.
- [ ] Push the verified commit to `origin/main` and verify `git ls-remote origin refs/heads/main` equals the local landing SHA.
- [ ] Report the remote `main` SHA and any explicitly deferred security-preview limitations.
