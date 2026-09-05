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
- Clipboard managers, swap, hibernation, terminal recording, accessibility
  APIs, keyboard capture, screenshots, filesystem snapshots, and backups may
  retain data outside Ladon's control.
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
6. Lock cancels an active supervised process before dropping the unlocked
   session.
7. Setup writes only an absolute local MCP command and makes a backup before
   changing an existing client configuration.

## Review gates before stable v1

- owner-only Windows named pipe plus server/client SID checks;
- Unix app-death liveness signal and native Windows ACL/temp cleanup tests;
- tray/quit lifecycle and screen-lock/suspend integration;
- independent review of crypto, serialization, IPC, runner, memory lifetime,
  setup edits, and every agent-visible response;
- release tests and signed artifacts on macOS, Windows, and Linux.
