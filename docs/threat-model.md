# Threat model

## Goal

Ladon makes the common handoff from a human-owned secret to a local coding
agent safer and easier. Its primary objective is preventing accidental plaintext
disclosure in chat, shell history, process arguments, routine logs, and returned
command output.

## Protected assets

- vault plaintext, passphrase, data-encryption key, and wrapping material;
- secret field values injected into a supervised child;
- encrypted vault integrity and authenticated metadata;
- the boundary between agent-visible metadata and managed values.

Names, field names, executable paths, arguments, working directories, status,
and bounded activity metadata are not confidential.

## Trust boundaries

The GUI owns the unlocked vault and is the only CRUD surface. CLI and MCP are
untrusted local clients authenticated only as the same operating-system user.
They may request metadata, locking, or a bounded run, but cannot request secret
plaintext. A launched child is trusted for the fields deliberately injected
into it and untrusted for all other fields.

`AppLocked` is an additional trust boundary inside the unlocked process. The
unlocked vault key and session PIN verifier remain in Ladon memory only until
the original idle deadline; GUI values are wiped, agent admission is closed,
all grants are revoked, and active supervised runs are cancelled before
completion. This improves accidental-disclosure behavior, but it does not
improve resistance to a same-user process that can inspect or control Ladon
memory.

Secret-bearing runs also require an unexpired in-memory grant for every
referenced secret. A grant is scoped to a random client-session UUID and an
immutable secret ID for a fixed 30 minutes, within one vault unlock lifetime.
The broker revalidates that grant immediately before reading plaintext and
serializes resolution against revocation. This prevents accidental reuse by a
different integration instance; it is not authentication against a malicious
process already running as the same user. MCP does not provide a universal
trusted chat identifier, so the scope is an integration process rather than a
conversation.

`ladon_identify_session` is optional, process-local MCP state containing only
an untrusted, non-secret reported name. Initialization's `clientInfo.name` or
`MCP client` supplies a fallback. The GUI marks names as reported and pairs
them with a short session ID; neither proves identity. Renaming only changes
display metadata on the next broker request, never the grant key or expiry.

The active-grant list and per-pair revoke controls are GUI-only and never
cross RPC/MCP. Each row represents one process/secret grant with a fixed
30-minute lifetime; use does not extend it. Targeted revoke cancels and waits
for a matching run while preserving unrelated grants. Revoke all cancels the
active run and clears all grants. Neither operation can erase bytes already
consumed, retained, or transmitted by an authorized child.

Within the GUI, selecting a secret exposes metadata and a constant mask only.
Viewing or editing its values requires a fresh local confirmation for that
selection: an optional in-memory 4–12 digit PIN, strict Touch ID where
available, or either when both are configured. Five consecutive wrong PINs lock
the vault. Authorization is scoped to the vault session, immutable secret ID,
and selection epoch; it is cleared on navigation, lock, or exit, and stale
Touch ID results are rejected. Values are shown and hidden explicitly rather
than on a timer. Text edits are validated before one atomic whole-record update;
existing binary fields are retained but cannot be replaced inline.

Revealed and editable text is readable on screen. The explicit **Copy** button
exports text fields to the OS clipboard; binary fields cannot be copied this
way, and keyboard Copy/Cut in sensitive fields is disabled. Ladon retains a
zeroizing copy for comparison and attempts to clear the clipboard after 30
seconds only if it still contains the copied text. Newer, different content is
preserved. App lock, vault lock, and exit also attempt conditional cleanup.
Clipboard access failures, a crash, or retained clipboard history can leave
copies behind; this is best-effort cleanup rather than guaranteed erasure.

The operating system, cryptographic libraries, Rust toolchain, and Ladon binary
are trusted. Repository source is assumed public; no protection depends on code
secrecy.

## Defended scenarios

- accidental copy/paste of a token into an agent conversation;
- secrets appearing in Ladon-generated argv or shell history;
- another OS user connecting to the Unix endpoint;
- tampered, truncated, oversized, or non-canonical vault/protocol input;
- common exact raw, JSON-escaped, percent-encoded, hex, and Base64 output forms;
- runaway output, timeouts, manual cancellation, and child process trees;
- crashes during the two-copy vault save sequence on supported Unix filesystems.

## Explicit non-goals and residual risk

- Malware or an attacker already executing as the same OS user can inspect
  memory, inject into processes, replace binaries/configuration, or impersonate
  a client.
- An authorized child can transmit a secret directly, encrypt it, hash it,
  split it, or otherwise transform it beyond exact-pattern redaction.
- Grant expiry and revocation prevent future Ladon resolutions but cannot erase
  a value already delivered to an authorized child process.
- Clipboard managers, OS clipboard history, swap, hibernation, terminal
  recording, accessibility APIs, keyboard capture, screenshots, filesystem
  snapshots, and backups may retain data outside Ladon's control.
- Environment and temporary-file injection are observable to the authorized
  child and may be exposed by platform/debugging tools available to the user.
- Rollback to an older authenticated vault copy is not prevented by an external
  monotonic counter.
- Denial of service by the current OS user is only bounded, not eliminated.
- The current Windows build has no authenticated IPC transport and therefore no
  supported agent bridge.

## Security invariants

1. No agent-facing success response contains a managed value field.
2. Secret values are never accepted in CLI/MCP request schemas or argv.
3. All attacker-controlled lengths are checked before expensive work or large
   allocation.
4. Vault headers and payloads are authenticated; authentication errors are
   non-oracular.
5. Secret output is redacted or suppressed before crossing the broker boundary.
6. App lock blocks agent admission before clearing GUI values and does not
   complete until active child cleanup finishes.
7. Hard lock additionally drops the unlocked session.
8. Setup writes only an absolute local MCP command and makes a backup before
   changing an existing client configuration.
9. Session PIN verifiers, Touch ID choice, pending approvals, and grants are
   memory-only. App lock clears pending approvals and grants but retains the
   in-memory session confirmation only until the original idle deadline; hard
   lock and process exit remove it. No native credential store is used.
10. Any new vault unlock lifetime invalidates grants from the preceding one;
   grant expiry or revocation is rechecked before plaintext resolution.
11. Saving or deleting a secret invalidates every grant for that immutable
    secret ID before future plaintext resolution; agent-facing APIs remain
    value-free.
12. Active-grant snapshots and targeted revoke remain GUI-only. Reported names
    confer no authority and cannot renew grants or change their scope.
13. Managed text-copy cleanup only clears clipboard contents equal to the
    copied text; it does not erase clipboard-manager or OS history.

## Review gates before stable v1

- owner-only Windows named pipe plus server/client SID checks;
- Unix app-death liveness signal and native Windows ACL/temp cleanup tests;
- tray/quit lifecycle and screen-lock/suspend integration;
- independent review of crypto, serialization, IPC, runner, memory lifetime,
  setup edits, and every agent-visible response;
- release tests and signed artifacts on macOS, Windows, and Linux.
