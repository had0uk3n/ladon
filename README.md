# Ladon

Ladon is a small local secret vault and process runner for coding agents. You
store a named value in the GUI; Codex, Claude Code, or the CLI can ask Ladon to
run a local command with that value injected through an environment variable,
standard input, or a temporary file. The secret itself is never returned over
MCP or local IPC and does not need to appear in chat or command arguments.

Ladon is an early security preview, not a general-purpose password manager or a
data-loss-prevention system. The currently usable end-to-end agent bridge is
macOS/Linux only. The Windows GUI and process supervisor compile, but the
owner-authenticated named-pipe transport is not implemented yet.

## What works now

- encrypted, portable, passphrase-protected vault;
- native GUI for first run, unlock, add/list/delete, protected secret viewing
  and editing, explicit backup recovery, and 30-minute activity locking;
- optional memory-only 4–12 digit session PIN on every platform plus strict
  Touch ID on macOS;
- one-confirmation, fixed 30-minute access per agent-process/secret pair, with
  a live GUI access list and per-grant or all-grant revocation;
- generic direct process execution without a shell added by Ladon;
- environment, stdin, and temporary-file injection by secret name or ID;
- bounded stdout/stderr capture and redaction of common raw/encoded forms;
- same-user Unix socket with peer credential checks;
- `ladon status`, `list`, `lock`, `run`, and stdio `mcp`;
- preview-before-write `ladon integrate codex|claude`, with a timestamped
  configuration backup and idempotent updates.

Tray/background lifecycle, OS screen-lock handling, Windows named pipes, binary
file drag-and-drop, and signed installers remain release work.

## Build and run

Building Ladon requires Rust 1.85 or newer and the platform's normal native
linker. On Ubuntu 24.04, install the GUI development packages used by CI first:

```sh
sudo apt-get install libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

Then build both the GUI and CLI:

```sh
cargo build --release
./target/release/ladon-app
```

On first launch, create a passphrase of at least 12 Unicode characters. When
strict Touch ID is available on a supported Mac, you may continue with Touch ID
alone or add an optional 4–12 digit PIN for the app session; either configured
method can confirm a protected action. Whenever strict Touch ID is unavailable,
configuring a 4–12 digit session PIN is required before secret use. Five
consecutive wrong PIN submissions lock the vault; a successful PIN or Touch ID
confirmation resets the counter. The PIN verifier and all agent permissions
stay only in memory. A hard vault lock or process exit forgets the PIN verifier;
**Lock app** revokes all agent permissions while retaining the verifier only
until the original idle deadline. The resulting release binaries do not require
Rust to be installed on the computer where they run.

While the vault is unlocked, choose **Lock app** for a temporary UI lock. It
clears the visible selection, reveal and edit buffers, pending approvals, and
all agent grants, closes agent admission, and cancels the active agent run
before the lock completes. The unlocked vault key and session PIN verifier
remain available only until the original idle deadline. One **Unlock** click
starts Touch ID when it is
available; when a session PIN is configured, **Use PIN instead** provides the
fallback. App lock and app unlock do not extend the idle deadline. Choose
**Lock vault completely** when the passphrase should be required again.

## Viewing and editing a secret

Select a secret in the unlocked GUI to see its metadata and a constant mask,
never its value. Authenticate the selected secret with Touch ID or the configured
PIN before choosing **Show value** or **Edit**. Values remain visible only until
you explicitly choose **Hide value**, navigate away, lock the app or vault, or
close the app; a selection requires authentication again after you leave and
return.

Revealed text and text being edited are readable. Use the explicit **Copy**
button to copy a text field; binary fields cannot be copied this way. Ladon
attempts to clear the copy after 30 seconds only if the clipboard still contains
the copied text, preserving newer, different clipboard content. App lock, vault
lock, and exit also start this conditional cleanup without waiting for clipboard
I/O. Clipboard access can fail; this is best-effort cleanup, not a guarantee of
erasure. Clipboard managers and OS history may retain copies outside Ladon's
control. Keyboard Copy/Cut in sensitive fields is disabled so copies use the
managed **Copy** button.

Edits are prepared and validated before a single atomic vault update, preserving
the secret ID. Existing binary fields are preserved but cannot be edited inline.
After saving or deleting a secret, Ladon invalidates every agent grant for that
secret ID, so a later agent run requires a new approval. If you navigate away or
close with an unsaved edit, Ladon asks whether to discard it. A Touch ID result
that arrives after the selection or vault session changed is rejected.

In a second terminal:

```sh
./target/release/ladon status
./target/release/ladon list
```

Configure a local coding agent after reviewing the displayed change:

```sh
./target/release/ladon integrate codex
./target/release/ladon integrate claude
```

The generated configuration contains only the absolute path to `ladon mcp`.
It never contains vault values or credentials. Codex is configured with a
16-minute MCP tool timeout so Ladon's bounded 15-minute MCP run can report
cleanup and redaction results.

## Generic runner

The default field is named `value`:

```sh
ladon run --env API_TOKEN=my-service -- curl https://example.test/api
```

For a multi-field secret, use `name::field`:

```sh
ladon run \
  --env ACCESS_KEY=object-store::access_key \
  --env SECRET_KEY=object-store::secret_key \
  -- your-local-program
```

Other bindings:

```sh
ladon run --stdin signing-key::pem -- your-local-program
ladon run --file-env CERT_FILE=client-cert::pem -- your-local-program
```

Ladon resolves the executable on the client, sends an absolute path to the app,
starts it directly, supplies a minimal environment, and returns only bounded,
redacted output. Ladon does not provide service-specific adapters.

## Agent use

After MCP setup, a useful request is:

> Run the local command using the Ladon secret named `my-service` in the
> `API_TOKEN` environment variable. Do not ask me to paste the value.

Secret names, field names, executable paths, arguments, and working directories
are metadata visible to the agent. Do not put secret material in those names or
arguments.

The MCP server exposes five tools: `ladon_status`, `ladon_list_secrets`,
`ladon_lock`, `ladon_identify_session`, and `ladon_run`.
`ladon_identify_session` is optional: it sets a process-local, untrusted,
non-secret reported name, such as `Codex — demo task`. Its `display_name` is
trimmed and must contain 1–64 UTF-8 bytes with no control characters. Without
it, Ladon uses a valid MCP `clientInfo.name`, or `MCP client` as a fallback.
The new name reaches the GUI on the next broker request. It does not change
the session ID, grant duration, or permissions, and does not authenticate a chat.

The first run from an MCP process that needs a particular secret opens a local
approval window. Confirm once with the session PIN or Touch ID and that MCP
process may use the displayed secret for a fixed 30 minutes; use does not extend
the timer. A different MCP process or another secret asks separately. The GUI's
**Agent access** panel shows one row per active process/secret grant, with its
reported name, eight-character session ID, secret name, remaining time, and
**Running** while that pair is in use. **Revoke** removes only that row's grant
and cancels a matching supervised run before returning, preserving unrelated
grants. **Revoke all** clears every grant and cancels the active run. These
active-grant views and targeted revoke controls are GUI-only; neither is
exposed over RPC or MCP. A one-shot `ladon run` invocation has a fresh client
identity, so it asks each time. Revocation cannot erase bytes a child has
already consumed, retained, or transmitted. If a grant expires while its
authorized command is still finishing, the empty grant list stays hidden but
the GUI keeps an **Agent command running** indicator and **Revoke all** control.

**Lock app** is a soft UI lock. It revokes grants, cancels the active run,
closes agent admission, and makes `list` and `run` return `vault_locked`; it
retains the unlocked vault key and session PIN verifier only until the original
idle deadline. Use the local GUI's **Unlock** action to resume, with Touch ID
started by the first click when available and **Use PIN instead** when a session
PIN is configured. A hard vault lock drops the unlocked session and requires
the passphrase again. The MCP `lock` operation always performs that full vault
lock; an agent cannot request a soft lock, submit a PIN, or unlock Ladon.

Saving or deleting a secret also revokes every existing grant for that immutable
secret ID. Agent-facing CLI, MCP, and local IPC APIs remain value-free: they
expose metadata and redacted run results, never a secret-value read or export.

If an app or vault lock is active, the request returns `vault_locked`; unlock
Ladon in the local GUI and retry it. An approval waits for at most two minutes
and starts no child process before confirmation.

## Security boundary

Ladon primarily prevents accidental disclosure into chat, shell history,
process arguments, logs, and ordinary command output. It encrypts the vault at
rest and rejects other OS users at the local Unix endpoint.

Same-user client impersonation, clipboard managers, and OS clipboard history
remain out of scope. Ladon cannot protect a secret from malware running as your
user, a malicious authorized child process, screen/keyboard capture, or deliberate
transformation and exfiltration by a child. Redaction recognizes common exact
representations; it is not semantic DLP. Expiry or revocation prevents future
resolution but cannot erase a value already delivered to a running authorized
child. Read [SECURITY.md](SECURITY.md) and the
[threat model](docs/threat-model.md) before using real credentials.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --test-threads=1
scripts/smoke-test.sh
cargo build --workspace --all-features --release
```

Unix socket integration tests need permission to create a local Unix socket;
some restricted sandboxes block that operation even when the code is correct.

The detailed [design specification](docs/superpowers/specs/2026-09-04-ladon-design.md),
[implementation plan](docs/superpowers/plans/2026-09-04-ladon-v1-implementation.md),
[session-grants plan](docs/superpowers/plans/2026-09-05-session-secret-grants.md),
[file format](docs/file-format.md), and [protocol](docs/protocol.md) are kept in
the repository so the security design is reviewable alongside the code.

## License

Apache-2.0.
