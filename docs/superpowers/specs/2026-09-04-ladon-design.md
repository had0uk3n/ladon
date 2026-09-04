# Ladon: Local Secret Broker for Coding Agents

**Status:** Approved specification; four self-review iterations complete

**Date:** 2026-09-04

**Initial release label:** Security preview

## 1. Summary

Ladon is a lightweight, local, cross-platform secret broker for people who use
coding agents such as Codex and Claude Code. It lets an agent run a local
program with user-selected secrets without placing the secret values in the
conversation, agent-facing tool arguments, shell history, process arguments,
ordinary Ladon logs, or MCP results created by Ladon itself.

Ladon is not a service-specific credential adapter. It does not contain GitLab,
GitHub, AWS, or other provider logic. Its central operation is a generic process
runner that binds opaque secret fields to a child process through environment
variables, standard input, or short-lived files.

The desktop tray application owns the encrypted vault and the unlocked session.
A small `ladon` executable provides human-facing CLI commands and a local stdio
MCP bridge. Both connect to the tray process through operating-system-local IPC.

## 2. Product goals

1. Make handing a named secret to a coding agent easier than copying a token.
2. Prevent accidental disclosure through prompts, transcripts, command lines,
   normal diagnostic output, and Ladon logs.
3. Keep all secret storage and use local to the user's device.
4. Work without a cloud account, server, browser extension, or provider adapter.
5. Ship ready-to-run desktop packages for macOS, Windows, and Linux.
6. Keep the storage format portable across supported operating systems.
7. Use public, standard cryptographic primitives and permit independent review.

## 3. Non-goals for version 1

- Protecting secrets after the user's operating-system account is fully
  compromised.
- Preventing an intentionally malicious child program from transforming or
  exfiltrating a secret it was authorized to receive.
- Cloud synchronization, team vaults, sharing, mobile clients, or remote vaults.
- Provider-specific API adapters or a plugin runtime.
- Remote MCP transport.
- Interactive PTY/ConPTY process proxying.
- Transparent injection into an already-running process.
- Detecting replacement of a valid vault by an older, valid encrypted copy.
- Persisting a history of commands run by agents. The tray shows only bounded
  activity from the current application lifetime.

These exclusions are security boundaries, not claims that the features are
impossible. They keep version 1 small enough to audit.

## 4. Threat model

### 4.1 Primary threats

Ladon must protect against:

- a user pasting a secret into an agent conversation;
- an agent including a secret in a shell command or MCP argument;
- a child program accidentally printing the injected value;
- logs or error messages recording a managed secret;
- shell history or process inspection exposing a managed secret in arguments;
- theft of a vault file without the passphrase;
- a different local operating-system user connecting to Ladon's IPC endpoint;
- malformed or corrupted vault and IPC data;
- interrupted writes leaving the vault unusable.

### 4.2 Secondary threats

Ladon provides limited defense against:

- prompt injection causing an unintended use of a secret;
- another process running as the same operating-system user;
- replacement of the vault with an older authenticated generation;
- offline guessing of a short device PIN after both the vault and the native
  device credential store are compromised;
- memory inspection, swap, hibernation images, crash dumps, or privileged
  debugging;
- filesystem snapshots, backups, or forensic remnants of an explicitly
  requested plaintext temporary-file binding.

These risks are reduced by explicit unlock context, OS-level IPC permissions,
short unlocked sessions, device-bound PIN material, output redaction,
best-effort memory locking and zeroization, and disabled core dumps. Ladon does
not claim to eliminate them. In particular, unlocking authorizes requests from
other processes running as the same OS user until the idle session expires.

### 4.3 Security invariant

The cryptographic algorithms, file format, IPC protocol, and source code are
assumed public. Confidentiality depends on the passphrase, generated keys, and
operating-system access controls, never on hidden implementation details.

## 5. User experience

### 5.1 First run

1. The user launches `ladon-app`.
2. Ladon creates a vault at the platform's standard per-user application-data
   location unless the user chooses another path.
3. The user enters and confirms a passphrase of at least 12 Unicode scalar
   values and at most 1,024 UTF-8 bytes. Spaces are allowed; Ladon imposes no
   composition rules.
4. Ladon explains that a lost passphrase cannot be reset and offers an immediate
   encrypted vault backup.
5. When a supported native credential store is available, Ladon offers a
   device-local quick PIN. The passphrase remains the portable recovery method.
6. Ladon offers one-click setup for Codex and Claude Code.

### 5.2 Adding a secret

The default form contains only:

- **Name**
- **Value**
- **Save**

The value is stored internally under the field name `value`. An expandable
**Additional fields** control supports credentials that naturally contain
multiple values. Dragging a file into the form stores its bytes as one field and
preserves a sanitized suggested filename for temporary-file injection.
Binary fields are shown as a byte count and may be replaced from a file; the GUI
never performs a lossy text conversion.

Secret names are UTF-8 strings between 1 and 128 bytes after NFC normalization.
They cannot contain ASCII control characters, Unicode bidi-control characters,
the delimiter `::`, or begin with the reserved prefix `id:`. Names are unique
by exact normalized value. Every record also receives an immutable random UUID.
An unprefixed reference is always an exact name; `id:<uuid>` is always an ID.
There is no heuristic UUID detection.

Field names use `[A-Za-z][A-Za-z0-9_-]{0,63}`. A record contains one or more
ordered fields. Field values are opaque bytes with an optional `text` hint for
display; Ladon does not infer provider or credential types. One field is limited
to 1 MiB and the decrypted vault payload to 64 MiB. These limits keep IPC,
redaction, backup, and authenticated decoding bounded.

In structured RPC and MCP messages, the secret reference and field name are
always separate properties. Human CLI syntax uses `secret-ref` for the default
`value` field and `secret-ref::field` for an explicit field. The reserved name
rules make this syntax unambiguous.

### 5.3 Tray-first desktop model

The tray menu shows:

- locked or unlocked state;
- remaining idle time when unlocked;
- the last request's client and outcome, without values;
- **Open vault**;
- **Lock now**;
- **Quit**.

The full manager window opens only for initialization, unlocking, settings,
current-session activity, and create/read/update/delete operations. Closing the
window keeps the tray process running. Autostart at login is disabled by default
and can be enabled in settings.

### 5.4 Unlock-on-request

When an agent request arrives while the vault is locked, Ladon opens a native
window containing:

- an explicit **unverified local client label**, such as Codex or Claude Code;
- any secret references and fields exactly as supplied by the client;
- the requested operation and, for a run, the executable, arguments, and working
  directory;
- a PIN field when quick unlock is available, plus an option to use the
  passphrase;
- **Deny** and **Unlock and continue** actions.

All client-controlled strings are rendered with control and bidi characters
escaped and cannot supply markup. The request waits for up to two minutes. A
successful unlock resumes the exact
pending request without asking the agent to retry. Denial, timeout, window
closure, or authentication failure returns a structured error and never starts
the child process.

Only one unlock request is pending at a time. Additional run or list requests
receive `busy`; Ladon does not merge dialogs or silently queue commands.

### 5.5 Unlocked session

The default idle timeout is 30 minutes. A successful secret use or vault
mutation resets it. Merely opening the tray menu or settings does not. Ladon
locks immediately when:

- the timer expires;
- the user selects **Lock now**;
- the MCP `lock` tool succeeds;
- the operating system reports screen lock, logout, or suspend;
- the tray process exits.

An active secret-bearing run pauses the idle countdown; the countdown restarts
when the run ends. Manual lock, MCP lock, screen lock, logout, suspend, or tray
shutdown cancels active runs before wiping the unlocked session. Ladon never
claims to be locked while a managed child still retains an injected value.

While unlocked, requests from the same OS user do not require confirmation per
operation in version 1. This is a deliberate usability trade-off, not a
client identity guarantee. The tray keeps the unlocked state and remaining time
visible. Per-client or per-secret grants are deferred until real usage shows
that their additional prompts justify the complexity.

### 5.6 Human reveal and copy

Only the GUI may reveal or copy a plaintext value. Reveal is an explicit action
and automatically hides the value after ten seconds. Copy shows a warning that
clipboard managers are outside Ladon's control and attempts to clear an
unchanged clipboard after 30 seconds. Agent-facing APIs never reveal or copy.

## 6. Architecture

### 6.1 Technology

The implementation is a Rust workspace. The GUI uses `egui` through `eframe`.
No browser engine, JavaScript runtime, cloud service, or language runtime is
required by the distributed application.

The workspace has three primary packages:

- `ladon-core`: vault model, cryptography, serialization, secret references,
  redaction, and platform-independent request/response types;
- `ladon-app`: tray GUI, unlocked session, platform services, local IPC server,
  and process runner;
- `ladon`: human CLI and the `ladon mcp` stdio bridge.

`ladon-core` must not depend on `egui`, MCP, or platform GUI code. Secret values
are represented by dedicated non-cloneable zeroizing byte containers rather
than ordinary application strings. Passphrase, PIN, and value-entry widgets use
a Ladon-owned `egui::TextBuffer` implementation backed by the same kind of
container; password masking alone is not treated as memory protection. Undo,
copy, drag, and accessibility value export are disabled for these widgets.

### 6.2 Process lifecycle

`ladon-app` is the single owner of the vault key and decrypted payload. The CLI
and MCP bridge never decrypt the vault. On Unix, a small runner subprocess may
receive only the values required for one run through an anonymous private pipe;
it never receives the vault key or payload and zeroizes its request buffer after
starting the child. This supervisor is an internal mode of the installed
`ladon-app` executable, not another service or user-facing binary.

When `ladon run` or `ladon mcp` cannot reach the local endpoint, it starts the
installed tray application with platform-native process APIs and waits up to
five seconds for a readiness handshake. A single-instance lock prevents two tray
processes from owning the same vault. Startup failure returns an actionable
error containing no secret data.

### 6.3 Data flow

```text
Codex / Claude Code
        |
        | MCP arguments: references, bindings, program, args, cwd
        v
ladon mcp
        |
        | OS-authenticated agent-facing local IPC; no managed secret values
        v
ladon-app
        |-- unlocks vault when required
        |-- resolves secret references
        |-- starts the managed child or Unix supervisor
        |-- injects values without exposing them to the agent
        |-- redacts output before agent-facing IPC
        v
MCP receives exit status and sanitized output
```

Only `ladon-app` can resolve a vault field into plaintext. On Unix it may pass
the resolved bytes to the single-run supervisor over an anonymous pipe that is
not addressable by other processes. No public or agent-facing RPC returns a
plaintext value. Secret creation, editing, import, reveal, and deletion exist
only in the GUI in version 1, so plaintext values never cross the public local
IPC endpoint.

## 7. Vault and cryptography

### 7.1 Envelope encryption

Vault creation generates a random 256-bit data-encryption key (DEK) using the
operating system CSPRNG. The passphrase derives a 256-bit key-encryption key
(KEK) with Argon2id. The KEK encrypts the DEK; the DEK encrypts the vault
payload.

The default Argon2id profile is the RFC 9106 memory-constrained recommendation:

- memory: 64 MiB;
- passes: 3;
- parallelism: 4;
- salt: 128 random bits;
- output: 256 bits.

Parameters are stored in the authenticated header so future releases can
upgrade them. Before running Argon2id, the locked decoder rejects parameters
outside format-version bounds. Version 1 accepts 32--256 MiB of memory, 1--10
passes, parallelism 1--16, and a 16--64 byte salt. This prevents a malformed
header from requesting unbounded work.

Passphrases are encoded as the exact UTF-8 bytes entered and are not normalized
or case-folded. The same rule is used on every platform and is explained beside
the first passphrase field so visually similar Unicode strings are not implied
to be equivalent.

A passphrase change requires the current passphrase even while the vault is
unlocked. A successful change generates a fresh salt, KEK, and DEK and
re-encrypts the payload. If quick PIN is enabled, its replacement wrapper is
prepared before the vault commit. Failure to prepare it aborts the change; a
failure while committing it after the new vault is durable disables quick PIN
and leaves the new passphrase usable. This is intentionally a less frequent
operation than ordinary vault writes and gives a
passphrase change clear revocation semantics for files managed by Ladon.
Previously copied vaults, sidecars, backups outside Ladon's managed paths, and
storage-forensic remnants cannot be revoked and are explicitly outside this
guarantee.

XChaCha20-Poly1305 encrypts both the wrapped DEK and the serialized payload. Each
encryption uses a fresh random 192-bit nonce and produces its own 128-bit tag.
The two operations use distinct domain labels in their associated data. There
is no separate password verifier: successful authenticated decryption is the
verifier.

Ladon uses established Rust cryptography libraries and never implements an
algorithm itself.

### 7.2 Portable file format

The vault is one versioned binary file. Multibyte integer fields are unsigned
big-endian. Version 1 has this exact framing:

```text
magic=`LADONV1\0`[8] | version[u16] | header_len[u32] | payload_len[u64] |
canonical-CBOR header[header_len] |
DEK nonce[24] | encrypted DEK[32] | DEK tag[16] |
payload nonce[24] | encrypted canonical-CBOR payload[payload_len] |
payload tag[16]
```

The version 1 header is a canonical CBOR map containing exactly `kdf`,
`memory_kib`, `passes`, `parallelism`, and `salt`; `kdf` must be `argon2id`.
`header_len` and `payload_len` are bounded before allocation; version 1 limits
the header to 4 KiB and encrypted payload to 64 MiB plus AEAD overhead. The DEK
associated data is the bytes before `DEK nonce` prefixed with
`ladon/dek/v1`. The payload associated data is every preceding byte through the
DEK tag prefixed with `ladon/payload/v1`. Canonical CBOR is required so these
byte sequences have one representation. The fixed test vectors include the
complete file bytes, not only primitive-level outputs.

An ordinary mutation reuses the authenticated header and wrapped DEK and creates
only a fresh payload nonce and ciphertext. Passphrase rotation creates a fresh
header, both nonces, and both ciphertexts. The KEK is discarded immediately
after DEK unwrap or wrap; an unlocked session retains the DEK, not the
passphrase-derived key.

Only format and KDF information is visible while locked. Secret names, field
names, timestamps, and portable settings are inside the encrypted payload.
The decoder enforces size, nesting, record-count, and string-length limits before
allocation.

The payload contains:

- vault UUID and monotonic revision;
- secret records and fields;
- user settings that should travel with the vault.

Version 1 accepts at most 10,000 records, 64 fields per record, 16 levels of
CBOR nesting, and the string limits defined by their model fields. Aggregate
plaintext remains capped at 64 MiB. These values are format limits, not tunable
settings.

Device-specific settings such as autostart, native credential-store handles,
window placement, and quick-PIN configuration remain outside the portable
payload and never contain managed secret values.

An unsupported file version or extra version 1 header key causes a hard failure.
Unknown top-level payload keys are preserved during read/write; a future feature
that changes required interpretation must use a new file version rather than an
unknown payload key.

### 7.3 Atomic persistence and recovery

After a successful mutation, primary and backup are two copies of the newest
committed generation, not a version history. Every mutation follows this
sequence:

1. Serialize and encrypt a complete new generation in memory.
2. Write identical bytes to two randomly named candidates in the same directory
   with owner-only permissions.
3. Flush, close, reopen, and authenticate both candidates.
4. Atomically replace `.bak` with the first candidate and sync directory
   metadata using the platform's durable-replace primitive.
5. Atomically replace the primary with the second candidate and sync again.
6. Report success only after both replacements complete.

If interrupted before step 5 completes, the old primary remains authoritative
and the mutation is not acknowledged. If interrupted during or after step 5,
at least one candidate contains the fully authenticated new generation. The
implementation has an explicit per-platform state machine for replace and
directory synchronization. The durability guarantee applies to the standard
local filesystems in the supported-platform test matrix. A custom path on a
filesystem without equivalent primitives requires an explicit warning and is
not described as crash-safe.

On startup, Ladon never silently selects a backup. If the primary fails
authentication or structural validation and the backup succeeds, the GUI offers
an explicit restore showing only generation metadata after passphrase entry. If
both are valid but have different revisions after an interrupted mutation, the
primary remains authoritative and the GUI offers the newer backup only when its
revision is greater. A passphrase change and secret deletion use the same
two-candidate procedure, so a successfully completed operation does not leave an
old-password or deleted-secret generation in Ladon's managed `.bak` path.

### 7.4 Device-local quick PIN

Quick unlock is available only when Ladon can store a random 256-bit device
secret in macOS Keychain, Windows DPAPI/Credential Manager, or a compatible Linux
Secret Service implementation.

Enabling a PIN creates a device-local sidecar containing:

- a cleartext sidecar format version and vault UUID;
- a random PIN salt;
- Argon2id parameters;
- a nonce;
- the DEK encrypted by a quick-unlock KEK and its AEAD tag;
- the cleartext fields above as associated data.

The quick-unlock KEK is produced by Argon2id using the PIN as its password input,
the sidecar salt as its salt input, and the device secret as Argon2's optional
secret input. The vault UUID and wrapper format version are included in the
authenticated context. Neither the sidecar nor the native credential item is
sufficient alone. After quick unwrap, Ladon accepts the session only if payload
authentication succeeds and its encrypted vault UUID matches the sidecar UUID.

The sidecar uses owner-only permissions and versioned canonical CBOR and is
replaced atomically. It is not copied by the GUI backup action. Native credential
items are requested as device-local and non-synchronizing where the platform
offers that distinction; otherwise the setup screen states the platform's actual
behavior.

PINs contain 6--12 digits. The sidecar decoder applies the same KDF bounds as
the vault header before running Argon2id. Five consecutive failures introduce an
exponential in-process delay. This delay is not claimed to resist an attacker
who has extracted both device artifacts and can perform an offline attack.

If the device store is missing, locked, or unavailable, Ladon falls back to the
passphrase. **Disable quick PIN** requires the passphrase, rotates the DEK using
the same durable procedure, then removes the native item and sidecar. Changing
the passphrase rotates the DEK and updates the sidecar instead. Copying a vault
never copies a usable PIN unlock mechanism.

### 7.5 Memory handling

- DEKs, KEKs, PIN material, passphrases, and plaintext fields use zeroizing
  containers.
- Secret containers are non-cloneable, have redacted `Debug`, no `Display`, and
  no general-purpose serialization implementation.
- Temporary copies are minimized and never formatted through general logging.
- The tray process attempts to lock sensitive pages in RAM and disables core
  dumps where supported. Failure is recorded as a non-secret diagnostic and does
  not make the vault unusable.
- Locking drops the decrypted payload and overwrites dedicated sensitive buffers
  before release.
- Ladon does not claim that compiler, OS, swap, hibernation, or privileged
  inspection can never retain a copy.

## 8. Local IPC

Ladon never listens on TCP, HTTP, or a network interface.

### 8.1 macOS and Linux

The app uses a Unix stream socket inside an owner-only runtime directory. The
directory mode is `0700` and socket mode is `0600`. The server checks kernel-
reported peer credentials and rejects peers whose effective UID differs from
the app owner. After connecting, the client likewise verifies kernel-reported
server credentials before sending a request; path ownership alone is not used as
server identity. Startup rejects symlinks and an existing directory or socket
owned by another user; it fails closed if it cannot create or validate a private
runtime path.

### 8.2 Windows

The app uses a local named pipe with an explicit DACL granting access only to
the current logon SID and denying network access. It does not rely on the default
named-pipe security descriptor. Both sides validate that they are in the same
user logon context.

### 8.3 Protocol

Messages are length-prefixed UTF-8 JSON with:

- protocol version;
- request UUID;
- claimed client label;
- method;
- typed parameters.

Protocol version 1 permits at most 16 levels of JSON nesting, a 64-byte client
label, 256 arguments, 256 KiB of arguments in total, and 32 KiB each for an
executable or working directory. Runner-specific binding and output limits apply
in addition.

The maximum frame is 4 MiB, accommodating the maximum sanitized process response
without streaming. Environment, output, and aggregate request limits are
checked independently rather than inferred from frame size. Invalid UTF-8,
excessive lengths, duplicate object keys, unknown methods, and incompatible
versions are rejected. Responses echo the request UUID and contain either a
typed result or a stable error code plus a redacted human message.

No shared IPC token is used. A token readable by every process under the same
user would not improve the selected security boundary. The client label shown
in the GUI is informational and is not represented as a cryptographic identity.

### 8.4 RPC authorization

Agent-facing MCP can call only:

- list secret IDs, names, field names, and value type hints;
- run a process with secret bindings;
- read lock/session status;
- lock the vault.

It cannot create, update, delete, reveal, copy, export, or decrypt a secret. No
public IPC method performs those operations. The GUI is the only management
surface in version 1.

Listing names while locked opens the same unlock window as a run request. Secret
names and field names are metadata, not managed values, but the setup screen
warns that listing exposes them to the local agent and its transcript.

## 9. Generic process runner

### 9.1 Request shape

A public run RPC request contains:

- an absolute executable path;
- arguments as an array of strings;
- absolute working directory;
- zero or more secret bindings;
- timeout and output limit within configured bounds.

Executable, arguments, and working directory are Unicode strings without NUL.
Version 1 returns `unsupported_path_encoding` for non-UTF-8 Unix paths rather
than adding a second byte-string representation to the public protocol.

A run has at most 16 secret bindings and at most 1 MiB of injected secret bytes
in total. The default timeout is five minutes. MCP callers may request up to 15
minutes; a human CLI caller may request up to two hours. Version 1 does not
support an unlimited run or more than one concurrent secret-bearing run. A
second run receives `busy` rather than entering a hidden queue; status and lock
remain available.

Ladon uses direct process creation. It never implicitly wraps the request in
`sh -c`, `cmd.exe`, or PowerShell. A caller that genuinely needs a shell must
name it explicitly. Managed secret values are rejected if they appear in the
executable, arguments, or working directory.

The human CLI and MCP tool accept an absolute path, a path relative to the
requested working directory, or a bare executable name. The local `ladon`
frontend canonicalizes a path or resolves a bare name once using its own PATH,
then sends the absolute result to the app. The app rejects relative RPC paths,
verifies the target is an executable file and the working directory is an
existing directory, shows that same path in the unlock dialog, and passes it
unchanged to process creation.

All runs start from a documented minimal platform environment containing the
target executable's directory, standard system command directories, temporary
directory, user home, and locale. Version 1 never inherits the requesting
process's complete environment and accepts no caller-supplied non-secret
environment map. A caller may pass non-secret configuration through the target
program's ordinary arguments.

### 9.2 Secret bindings

Version 1 supports three targets:

1. **Environment**: set a named child environment variable. The field must be
   valid text for the target OS and contain no NUL.
2. **Standard input**: write the selected field bytes to the child's stdin and
   close it. A request may contain at most one stdin binding and cannot also
   proxy interactive stdin.
3. **Temporary file environment**: create an owner-only temporary directory,
   write the field to an owner-only file, and set a named environment variable
   to the file path.

Ladon never places secret values in the direct child's command-line arguments.
It cannot prevent an authorized child from copying a value into a descendant's
arguments, files, or network traffic.
Environment target names must be valid for the target OS and cannot contain NUL
or `=`. Targets must be unique after platform comparison (case-insensitive on
Windows) and secret bindings override the corresponding minimal-environment
value. Duplicate or conflicting bindings are rejected before unlock.

Temporary file names are random. A sanitized suggested basename may provide a
file extension when required, but cannot add directories or escape the temporary
root. The directory is removed after normal completion, cancellation, timeout,
or spawn failure. Startup removes stale Ladon temporary directories after
validating ownership and an unguessable marker; it never recursively deletes an
unvalidated path.

Temporary-file binding necessarily writes plaintext to local storage. The GUI
and tool description prefer environment or stdin and warn that filesystem
snapshots, backups, and forensic recovery are outside Ladon's control. The file
mode exists only for programs that require a credential path.

### 9.3 Output redaction

The app captures stdout and stderr and applies streaming redaction before any
byte crosses IPC or enters a log. The matcher handles values split across read
boundaries and covers each injected field in these representations:

- raw bytes;
- UTF-8 JSON string escaping when the value is valid UTF-8;
- percent encoding when the value is valid UTF-8;
- lowercase and uppercase hexadecimal;
- standard and URL-safe Base64, padded and unpadded.

JSON escaping follows the serializer used by the protocol. Percent patterns
cover byte-wise RFC 3986 encoding with upper- and lowercase hex. Duplicate
derived patterns are removed before matching. These are deliberately common
accidental representations, not an open-ended transformation engine.

Matches become `[REDACTED:secret-id.field]`. Empty values have no pattern. If any
non-empty injected value or generated representation is shorter than four
bytes, Ladon suppresses stdout and stderr entirely for that run rather than risk
unbounded marker expansion. Redaction operates on bytes. After redaction,
remaining invalid UTF-8 bytes are rendered as `\xNN`; this conversion never runs
on unredacted bytes. The combined response is capped after replacement and
escaping at 512 KiB by default and 2 MiB maximum. Ladon retains a bounded head
and tail and reports omitted byte counts.

Redaction is defense against accidental disclosure, not a data-loss-prevention
sandbox. A malicious child can split, encrypt, hash, or transmit its input.

### 9.4 Cancellation and process trees

Each run owns a Job Object with kill-on-last-handle-close on Windows. On macOS
and Linux, a minimal single-run supervisor owns a new process group and watches
an anonymous liveness pipe from `ladon-app`; EOF terminates the group. The app
also watches the supervisor and terminates the group if the supervisor fails.
Timeout, client cancellation, deliberate lock, tray shutdown, or either side of
the supervision channel disappearing terminates the group, waits for cleanup,
and removes temporary files. The supervisor accepts no public connections,
persists nothing, and exits with the child. Ladon reports exit code or
terminating signal where the platform provides one.

These lifecycle guarantees cover the direct child and descendants that remain
in the assigned Job Object or process group. Deliberately escaping containment
is malicious-child behavior and remains a non-goal.

Version 1 does not allocate a PTY/ConPTY. Programs must be usable
non-interactively when called through MCP.

### 9.5 Result and current-session activity

The response contains:

- exit code or termination reason;
- redacted stdout and stderr;
- duration;
- redaction count;
- output-truncated flag.

For usability, the running tray keeps at most 100 metadata-only activity entries
in memory: unverified client label, resolved executable, referenced secret IDs
and fields, timestamps, outcome, and redaction count. It never stores arguments,
environment values, secret values, stdin, temporary-file contents, stdout, or
stderr. The list is cleared on tray exit and is not part of the vault. Persistent
audit history is deferred because it is not required for safe secret handoff and
would add a second encrypted persistence protocol or force a full-vault write on
every command.

## 10. CLI and MCP integration

### 10.1 Human CLI

Initial commands are:

```text
ladon status
ladon list
ladon run [bindings] -- <program> [args...]
ladon lock
ladon integrate codex
ladon integrate claude
ladon mcp
```

The initial CLI deliberately has no add, edit, reveal, export, or remove command.
Those operations stay in the GUI so the local protocol never needs a general
"return secret" or plaintext-management path. Structured output modes never
include plaintext values.

Example bindings:

```bash
ladon run --env GITLAB_TOKEN=gitlab-work -- glab mr list

ladon run \
  --env AWS_ACCESS_KEY_ID=aws-prod::access_key_id \
  --env AWS_SECRET_ACCESS_KEY=aws-prod::secret_access_key \
  -- terraform plan

ladon run \
  --file-env GOOGLE_APPLICATION_CREDENTIALS=gcp::credentials_json \
  -- gcloud projects list
```

### 10.2 MCP tools

`ladon mcp` is a local stdio MCP server exposing:

- `ladon_list_secrets`
- `ladon_run`
- `ladon_status`
- `ladon_lock`

Tool descriptions tell the model to refer to secrets by exact name or
`id:<uuid>` and never ask the user to paste a value. `ladon_run` is marked as
potentially destructive because the arbitrary child command can modify external
state. Ladon never intentionally places secret values in MCP resources, prompts,
tool schemas, tool arguments, progress notifications, errors, or results. Known
output representations are redacted as specified in section 9.3; a malicious
child's transformed output remains outside that guarantee.

The MCP bridge and `ladon-app` must run on the same machine and under the same OS
user. The integration command states this requirement before writing anything.
If the configured MCP process cannot reach the app, it returns an actionable
local-only error; Ladon does not try to infer every client's remote-execution
mode.

### 10.3 One-command setup

`ladon integrate codex` and `ladon integrate claude`:

1. locate the installed `ladon` executable;
2. show the exact local stdio MCP configuration to be created;
3. ask for confirmation;
4. invoke the client's documented MCP configuration command when available;
5. configure a tool timeout of at least 16 minutes where the client supports it,
   so Ladon's maximum MCP run can return its cleanup result;
6. verify that the resulting client configuration starts `ladon mcp` by absolute
   local path and does not select a remote execution environment;
7. print a manual configuration snippet if the client command or timeout setting
   is unavailable or incompatible.

The integration command never writes credentials into Codex or Claude
configuration.

## 11. Failure handling

- **Wrong passphrase/PIN:** one generic authentication failure; no distinction
  between wrong credentials and damaged wrapped-key bytes.
- **Lost passphrase:** no reset or recovery bypass exists. A device PIN is not a
  portable backup.
- **Unavailable keychain:** offer passphrase immediately and leave the vault
  usable.
- **Unknown secret/field:** return a stable not-found error without opening a
  process.
- **Locked request timeout:** deny and return `unlock_timeout`.
- **No interactive desktop:** a locked request returns `ui_unavailable`; MCP
  never falls back to asking for a passphrase or PIN in the agent transcript.
- **Vault corruption:** never overwrite the primary; validate the encrypted
  backup and offer explicit recovery.
- **IPC version mismatch:** show installed client/app versions and request an
  upgrade; never downgrade silently.
- **Spawn failure:** return the platform error after redaction and clean all
  temporary material.
- **Redactor failure:** suppress output and report a redaction error rather than
  forwarding unsanitized bytes.
- **Supervisor failure:** do not start the target if supervision is not ready;
  if supervision disappears later, terminate the target and suppress any output
  that has not completed redaction.

All user-visible errors use stable codes and actionable text. Internal logs use
structured fields with an allowlist; arbitrary request objects and environments
are never formatted into logs.

## 12. Packaging and platform support

The first stable release targets:

- macOS 13 or later, Apple Silicon and x86_64;
- Windows 10 or later, x86_64;
- mainstream glibc-based Linux distributions, x86_64, distributed initially as
  AppImage and a compressed CLI archive.

Release CI builds each target on a native GitHub Actions runner. The project does
not claim that one host can cross-compile and sign every platform. Packages
contain both `ladon-app` and `ladon` and require no Rust toolchain.

Security-preview builds may reach the three platforms sequentially. A platform
is not called supported until its native credential store, IPC, lock events,
process supervision, installer, and leakage tests pass. This preserves the
three-platform product goal without making simultaneous parity a release gate
for early feedback.

macOS applications are code-signed and notarized. Windows installers and
executables are Authenticode-signed. Linux artifacts include checksums and a
Sigstore signature. Every release publishes an SBOM and records the source
commit used to build it.

## 13. Public repository and secure development

The repository is public from the beginning. It includes:

- `SECURITY.md` with supported versions and coordinated-disclosure instructions;
- GitHub private vulnerability reporting;
- protected release branches and required CI;
- dependency lockfiles and automated dependency review;
- secret scanning;
- `cargo audit` and license/source policy checks;
- signed release tags;
- an explicit security-preview warning until an independent review is complete.

The vault format and threat model are public. Security reports involving active
exploitation or an unpatched bypass are handled privately through GitHub Security
Advisories until a fixed release is available.

## 14. Verification strategy

### 14.1 Cryptography and vault

- fixed test vectors for KDF, DEK wrapping, payload encryption, and quick unlock;
- whole-file byte-for-byte vectors for every format version;
- round-trip tests for every supported format version;
- mutation tests proving that header, nonce, ciphertext, and tag changes fail;
- wrong passphrase, wrong PIN, wrong device secret, and wrong vault UUID tests;
- KDF-boundary tests proving oversized parameters fail before Argon2 allocation;
- passphrase-rotation tests proving the old passphrase and old PIN wrapper cannot
  open the new primary or managed backup;
- property tests for atomic generations and preserved unknown payload keys;
- fuzzing for the locked header and decrypted CBOR decoder;
- fault injection at every atomic-write step, including recovery from `.bak`.

### 14.2 IPC

- permissions/ACL tests on each supported OS;
- different-user rejection tests where CI permits;
- peer-credential validation tests;
- frame length, invalid JSON, duplicate key, cancellation, and version mismatch
  tests;
- maximum-size request and sanitized-response tests within the frame limit;
- assertions that the public method table contains no plaintext management or
  reveal operation;
- fuzzing of request decoding and dispatch;
- startup races proving only one tray owner becomes ready.

### 14.3 Runner and leakage

- assert managed values never appear in process arguments;
- verify environment, stdin, and file bindings independently;
- verify the minimal environment, absence of inherited variables, and executable
  resolution;
- verify raw and encoded redaction across every possible chunk boundary;
- verify short-secret output suppression, invalid UTF-8 escaping, marker
  expansion, and post-redaction output limits;
- verify no unredacted output is emitted when the redactor fails;
- verify cleanup after success, non-zero exit, spawn failure, timeout,
  cancellation, and forced process death;
- scan test logs, MCP fixtures, snapshots, and crash output for canary secrets;
- kill the app and supervisor independently and verify process-tree termination
  and temporary-file cleanup on macOS, Linux, and Windows.

### 14.4 GUI and integration

- deterministic UI state tests for setup, add/edit, lock, PIN failure, request
  denial, request timeout, and automatic continuation;
- accessibility checks for keyboard navigation, focus, and screen-reader labels;
- packaged smoke tests on all supported OS targets;
- protocol-level MCP conformance tests;
- smoke tests against supported Codex and Claude Code versions before release,
  including client cancellation and configured tool timeout.

### 14.5 Independent review gate

The project may publish security-preview builds before an external review. It
must not remove the security-preview label until an independent reviewer has
assessed at minimum:

- vault format and key lifecycle;
- native quick unlock;
- IPC access control;
- process creation and cleanup;
- output redaction limitations;
- release pipeline integrity.

## 15. Acceptance criteria for stable version 1

Stable version 1 is feature-complete when all of the following are true:

1. A new user can create, lock, unlock, back up, and reopen a portable vault.
2. A user can add a single value with only a name and value, add multiple fields,
   and import a file.
3. Quick PIN unlock works where a supported native credential store is present,
   and passphrase fallback always works.
4. The 30-minute idle timer and immediate lock events behave as specified.
5. `ladon run` supports environment, stdin, and temporary-file bindings without
   managed values in process arguments.
6. Canary values do not appear in Ladon logs, agent-facing IPC captures, MCP
   transcripts, or sanitized child output in the leakage test suite. The public
   local IPC endpoint is separately verified to be owner-only and value-free.
7. Codex and Claude Code can be configured through the integration commands and
   can list names and run commands without receiving plaintext values.
8. Owner-only IPC access is verified on macOS, Linux, and Windows.
9. Interrupted vault writes recover without losing both the primary and backup
   generations, and successful passphrase rotation leaves neither managed file
   decryptable with the old passphrase.
10. Signed installable artifacts and SBOMs are produced from a tagged public
    commit for every supported platform.

## 16. References

- [RFC 9106: Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
- [libsodium XChaCha20-Poly1305 documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)
- [Codex MCP documentation](https://developers.openai.com/codex/mcp/)
- [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)
- [Linux Unix-domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- [macOS `getpeereid`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)
- [Windows named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
