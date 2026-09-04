# Ladon: Local Secret Broker for Coding Agents

**Status:** Draft specification for user review; product direction approved

**Date:** 2026-09-04

**Initial release label:** Security preview

## 1. Summary

Ladon is a lightweight, local, cross-platform secret broker for people who use
coding agents such as Codex and Claude Code. It lets an agent run an arbitrary
local program with user-selected secrets without placing the secret values in
the conversation, tool arguments, shell history, process arguments, ordinary
logs, or MCP results.

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

## 3. Non-goals for the first release

- Protecting secrets after the user's operating-system account is fully
  compromised.
- Preventing an intentionally malicious child program from transforming or
  exfiltrating a secret it was authorized to receive.
- Cloud synchronization, team vaults, sharing, mobile clients, or remote vaults.
- Provider-specific API adapters or a plugin runtime.
- Remote MCP transport.
- Interactive PTY/ConPTY process proxying.
- Transparent injection into an already-running process.

These exclusions are security boundaries, not claims that the features are
impossible. They keep the first release small enough to audit.

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
- offline guessing of a short device PIN after both the vault and the native
  device credential store are compromised;
- memory inspection, swap, hibernation images, crash dumps, or privileged
  debugging.

These risks are reduced by explicit unlock context, OS-level IPC permissions,
short unlocked sessions, device-bound PIN material, output redaction, best-effort
memory locking and zeroization, and disabled core dumps. Ladon does not claim to
eliminate them.

### 4.3 Security invariant

The cryptographic algorithms, file format, IPC protocol, and source code are
assumed public. Confidentiality depends on the passphrase, generated keys, and
operating-system access controls, never on hidden implementation details.

## 5. User experience

### 5.1 First run

1. The user launches `ladon-app`.
2. Ladon creates a vault at the platform's standard per-user application-data
   location unless the user chooses another path.
3. The user enters and confirms a strong passphrase.
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

Secret names are UTF-8 strings between 1 and 128 bytes after NFC normalization.
Names are unique by exact normalized value. Every record also receives an
immutable random UUID. Agent and CLI references accept either the exact name or
UUID; a syntactically valid UUID is resolved as an ID before name lookup.

Field names use `[A-Za-z][A-Za-z0-9_-]{0,63}`. A record contains one or more
ordered fields. Field values are opaque bytes with an optional `text` hint for
display; Ladon does not infer provider or credential types. One field is limited
to 1 MiB and the decrypted vault payload to 64 MiB. These limits keep IPC,
redaction, backup, and authenticated decoding bounded.

### 5.3 Tray-first desktop model

The tray menu shows:

- locked or unlocked state;
- remaining idle time when unlocked;
- the last request's client and outcome, without values;
- **Open vault**;
- **Lock now**;
- **Quit**.

The full manager window opens only for initialization, unlocking, settings,
history, and create/read/update/delete operations. Closing the window keeps the
tray process running. Autostart at login is disabled by default and can be
enabled in settings.

### 5.4 Unlock-on-request

When an agent request arrives while the vault is locked, Ladon opens a native
window containing:

- the claimed client name, such as Codex or Claude Code;
- the secret references and fields exactly as supplied by the client;
- the executable, arguments, and working directory;
- a PIN field when quick unlock is available, plus an option to use the
  passphrase;
- **Deny** and **Unlock and continue** actions.

The request waits for up to two minutes. A successful unlock resumes the exact
pending request without asking the agent to retry. Denial, timeout, window
closure, or authentication failure returns a structured error and never starts
the child process.

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

While unlocked, requests from the same user do not require confirmation per
operation in the first release.

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
are represented by dedicated zeroizing types rather than ordinary application
strings wherever library APIs permit.

### 6.2 Process lifecycle

`ladon-app` is the single owner of the vault key and decrypted payload. The CLI
and MCP bridge never decrypt the vault.

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
        | authenticated local IPC; no managed secret values
        v
ladon-app
        |-- unlocks vault when required
        |-- resolves secret references
        |-- starts the child itself
        |-- injects values in memory
        |-- redacts output before IPC
        v
MCP receives exit status and sanitized output
```

The only routine that converts a vault field into plaintext process input lives
inside `ladon-app` and is not exposed as an RPC method.

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
upgrade them. A successful passphrase change generates a fresh salt and KEK and
rewraps the existing DEK. It does not re-encrypt every logical record.

XChaCha20-Poly1305 encrypts both the wrapped DEK and the serialized payload. Each
encryption uses a fresh random 192-bit nonce. The cleartext format version and
cryptographic header are supplied as associated data so tampering is detected.
There is no separate password verifier: successful authenticated decryption is
the verifier.

Ladon uses established Rust cryptography libraries and never implements an
algorithm itself.

### 7.2 Portable file format

The vault is one versioned binary file:

```text
magic | format version | authenticated CBOR header | encrypted DEK |
payload nonce | encrypted canonical-CBOR payload | authentication tag
```

Only format and KDF information is visible while locked. Secret names, field
names, audit entries, timestamps, and settings are inside the encrypted payload.
The decoder enforces size, nesting, record-count, and string-length limits before
allocation.

The payload contains:

- vault UUID and monotonic revision;
- secret records and fields;
- encrypted audit history;
- user settings that should travel with the vault.

Device-specific settings such as autostart, native credential-store handles,
window placement, and quick-PIN configuration remain outside the portable
payload and never contain managed secret values.

Unknown critical format features cause a hard failure. Unknown non-critical
payload fields are preserved during read/write so an older compatible client
does not silently destroy newer data.

### 7.3 Atomic persistence and recovery

Every mutation follows this sequence:

1. Serialize and encrypt a complete new generation in memory.
2. Write it to a randomly named file in the same directory with owner-only
   permissions.
3. Flush and close the candidate.
4. Reopen and authenticate it before replacement.
5. Preserve the previous valid generation as one encrypted `.bak` file.
6. Atomically replace the primary file and sync directory metadata where the OS
   provides that operation.

On startup, Ladon never silently selects a backup. If the primary fails
authentication or structural validation and the backup succeeds, the GUI offers
an explicit restore showing only generation metadata after passphrase entry.

### 7.4 Device-local quick PIN

Quick unlock is available only when Ladon can store a random 256-bit device
secret in macOS Keychain, Windows DPAPI/Credential Manager, or a compatible Linux
Secret Service implementation.

Enabling a PIN creates a device-local sidecar containing:

- a random PIN salt;
- Argon2id parameters;
- a nonce;
- the DEK encrypted by a quick-unlock KEK;
- the vault UUID and format version as associated data.

The quick-unlock KEK is produced by Argon2id using the PIN as its password input,
the sidecar salt as its salt input, and the device secret as Argon2's optional
secret input. The vault UUID and wrapper format version are included in the
authenticated context. Neither the sidecar nor the native credential item is
sufficient alone.

PINs contain at least six digits. Five consecutive failures introduce an
exponential in-process delay. This delay is not claimed to resist an attacker
who has extracted both device artifacts and can perform an offline attack.

If the device store is missing, locked, or unavailable, Ladon falls back to the
passphrase. Removing quick unlock deletes the native item and sidecar. Copying a
vault never copies a usable PIN unlock mechanism.

### 7.5 Memory handling

- DEKs, KEKs, PIN material, passphrases, and plaintext fields use zeroizing
  containers.
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
the app owner. The client likewise verifies endpoint ownership before sending a
request.

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

The maximum frame is 1 MiB. Invalid UTF-8, excessive lengths, duplicate object
keys, unknown methods, and incompatible versions are rejected. Responses echo
the request UUID and contain either a typed result or a stable error code plus a
redacted human message.

No shared IPC token is used. A token readable by every process under the same
user would not improve the selected security boundary. The client label shown
in the GUI is informational and is not represented as a cryptographic identity.

### 8.4 RPC authorization

Agent-facing MCP can call only:

- list secret IDs, names, field names, and value type hints;
- run a process with secret bindings;
- read lock/session status;
- lock the vault.

It cannot create, update, delete, reveal, copy, export, or decrypt a secret. The
human CLI may perform create/update/delete through a separate RPC role, but
requires an interactive terminal and cannot accept a plaintext value in an
argument. The GUI has the complete management surface.

## 9. Generic process runner

### 9.1 Request shape

A run request contains:

- executable as one string;
- arguments as an array of strings;
- absolute working directory;
- environment inheritance mode;
- zero or more secret bindings;
- timeout and output limit within configured bounds.

Ladon uses direct process creation. It never implicitly wraps the request in
`sh -c`, `cmd.exe`, or PowerShell. A caller that genuinely needs a shell must
name it explicitly. Managed secret values are rejected if they appear in the
executable, arguments, working directory, or non-secret environment values.

The requesting CLI sends its environment snapshot through protected IPC because
the tray process may have been launched outside the user's shell. Environment
values are never logged. `clean` mode instead starts from a documented minimal
platform environment. The resolved executable path is included in the unlock
dialog and encrypted audit entry.

### 9.2 Secret bindings

The first release supports three targets:

1. **Environment**: set a named child environment variable. The field must be
   valid text for the target OS and contain no NUL.
2. **Standard input**: write the selected field bytes to the child's stdin and
   close it. A request may contain at most one stdin binding and cannot also
   proxy interactive stdin.
3. **Temporary file environment**: create an owner-only temporary directory,
   write the field to an owner-only file, and set a named environment variable
   to the file path.

Secret values are never supported in command-line arguments.

Temporary file names are random. A sanitized suggested basename may provide a
file extension when required, but cannot add directories or escape the temporary
root. The directory is removed after normal completion, cancellation, timeout,
or spawn failure. Startup removes stale Ladon temporary directories after
validating ownership and an unguessable marker; it never recursively deletes an
unvalidated path.

### 9.3 Output redaction

The app captures stdout and stderr and applies streaming redaction before any
byte crosses IPC or enters a log. The matcher handles values split across read
boundaries and covers each injected field in these representations:

- raw bytes;
- UTF-8 JSON string escaping when the value is valid UTF-8;
- percent encoding when the value is valid UTF-8;
- standard and URL-safe Base64, padded and unpadded.

Matches become `[REDACTED:secret-id.field]`. Empty values have no pattern. Short
values may heavily redact output; safety takes precedence over readability.
Output is capped at 10 MiB combined by default and 50 MiB maximum. Truncation is
explicitly reported.

Redaction is defense against accidental disclosure, not a data-loss-prevention
sandbox. A malicious child can split, encrypt, hash, or transmit its input.

### 9.4 Cancellation and process trees

Each run owns a process group on Unix and a Job Object on Windows. Timeout,
client cancellation, or tray shutdown terminates the group, waits for cleanup,
removes temporary files, and returns a structured outcome. Ladon reports exit
code or terminating signal where the platform provides one.

The first release does not allocate a PTY/ConPTY. Programs must be usable
non-interactively when called through MCP.

### 9.5 Result and audit

The response contains:

- exit code or termination reason;
- redacted stdout and stderr;
- duration;
- redaction count;
- output-truncated flag.

The encrypted bounded audit log stores client label, resolved executable,
arguments, working directory, referenced secret IDs and fields, timestamps,
outcome, and redaction count. It never stores environment values, secret values,
stdin, temporary-file contents, stdout, or stderr. The first release retains the
most recent 1,000 entries.

## 10. CLI and MCP integration

### 10.1 Human CLI

Initial commands are:

```text
ladon status
ladon list
ladon add
ladon edit <ref>
ladon remove <ref>
ladon run [bindings] -- <program> [args...]
ladon lock
ladon integrate codex
ladon integrate claude
ladon mcp
```

`add` and `edit` read values from a no-echo terminal prompt, stdin, or a file.
They reject value-bearing command-line options. Structured output modes never
include plaintext values.

Example bindings:

```bash
ladon run --env GITLAB_TOKEN=gitlab-work -- glab mr list

ladon run \
  --env AWS_ACCESS_KEY_ID=aws-prod.access_key_id \
  --env AWS_SECRET_ACCESS_KEY=aws-prod.secret_access_key \
  -- terraform plan

ladon run \
  --file-env GOOGLE_APPLICATION_CREDENTIALS=gcp.credentials_json \
  -- gcloud projects list
```

### 10.2 MCP tools

`ladon mcp` is a local stdio MCP server exposing:

- `ladon_list_secrets`
- `ladon_run`
- `ladon_status`
- `ladon_lock`

Tool descriptions tell the model to refer to secrets by exact name or ID and
never ask the user to paste a value. `ladon_run` is marked as potentially
destructive because the arbitrary child command can modify external state.
Secret values never appear in MCP resources, prompts, tool schemas, tool
arguments, progress notifications, errors, or results.

### 10.3 One-command setup

`ladon integrate codex` and `ladon integrate claude`:

1. locate the installed `ladon` executable;
2. show the exact local stdio MCP configuration to be created;
3. ask for confirmation;
4. invoke the client's documented MCP configuration command when available;
5. verify that the resulting client configuration starts `ladon mcp` by absolute
   path;
6. print a manual configuration snippet if the client command is unavailable or
   incompatible.

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
- **Vault corruption:** never overwrite the primary; validate the encrypted
  backup and offer explicit recovery.
- **IPC version mismatch:** show installed client/app versions and request an
  upgrade; never downgrade silently.
- **Spawn failure:** return the platform error after redaction and clean all
  temporary material.
- **Redactor failure:** suppress output and report a redaction error rather than
  forwarding unsanitized bytes.
- **Audit failure:** fail closed before starting a process when the audit entry
  cannot be committed, unless audit was explicitly disabled in GUI settings.

All user-visible errors use stable codes and actionable text. Internal logs use
structured fields with an allowlist; arbitrary request objects and environments
are never formatted into logs.

## 12. Packaging and platform support

The first public release targets:

- macOS 13 or later, Apple Silicon and x86_64;
- Windows 10 or later, x86_64;
- mainstream glibc-based Linux distributions, x86_64, distributed initially as
  AppImage and a compressed CLI archive.

Release CI builds each target on a native GitHub Actions runner. The project does
not claim that one host can cross-compile and sign every platform. Packages
contain both `ladon-app` and `ladon` and require no Rust toolchain.

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
- round-trip tests for every supported format version;
- mutation tests proving that header, nonce, ciphertext, and tag changes fail;
- wrong passphrase, wrong PIN, wrong device secret, and wrong vault UUID tests;
- property tests for atomic generations and unknown non-critical fields;
- fuzzing for the locked header and decrypted CBOR decoder;
- fault injection at every atomic-write step, including recovery from `.bak`.

### 14.2 IPC

- permissions/ACL tests on each supported OS;
- different-user rejection tests where CI permits;
- peer-credential validation tests;
- frame length, invalid JSON, duplicate key, cancellation, and version mismatch
  tests;
- fuzzing of request decoding and dispatch;
- startup races proving only one tray owner becomes ready.

### 14.3 Runner and leakage

- assert managed values never appear in process arguments;
- verify environment, stdin, and file bindings independently;
- verify raw and encoded redaction across every possible chunk boundary;
- verify no unredacted output is emitted when the redactor fails;
- verify cleanup after success, non-zero exit, spawn failure, timeout,
  cancellation, and forced process death;
- scan test logs, MCP fixtures, snapshots, and crash output for canary secrets;
- verify process-tree termination on macOS, Linux, and Windows.

### 14.4 GUI and integration

- deterministic UI state tests for setup, add/edit, lock, PIN failure, request
  denial, request timeout, and automatic continuation;
- accessibility checks for keyboard navigation, focus, and screen-reader labels;
- packaged smoke tests on all supported OS targets;
- protocol-level MCP conformance tests;
- smoke tests against supported Codex and Claude Code versions before release.

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

## 15. Acceptance criteria for the first release

The first release is feature-complete when all of the following are true:

1. A new user can create, lock, unlock, back up, and reopen a portable vault.
2. A user can add a single value with only a name and value, add multiple fields,
   and import a file.
3. Quick PIN unlock works where a supported native credential store is present,
   and passphrase fallback always works.
4. The 30-minute idle timer and immediate lock events behave as specified.
5. `ladon run` supports environment, stdin, and temporary-file bindings without
   managed values in process arguments.
6. Canary values do not appear in Ladon logs, IPC captures, MCP transcripts, or
   sanitized child output in the leakage test suite.
7. Codex and Claude Code can be configured through the integration commands and
   can list names and run commands without receiving plaintext values.
8. Owner-only IPC access is verified on macOS, Linux, and Windows.
9. Interrupted vault writes recover without losing both the primary and backup
   generations.
10. Signed installable artifacts and SBOMs are produced from a tagged public
    commit for every supported platform.

## 16. References

- [RFC 9106: Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106.html)
- [libsodium XChaCha20-Poly1305 documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf)
- [Model Context Protocol specification](https://modelcontextprotocol.io/specification/)
- [Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp)
- [Linux Unix-domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html)
- [macOS `getpeereid`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html)
- [Windows named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
