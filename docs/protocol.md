# Local protocol and MCP surface

## Local broker protocol

On Unix, `ladon-app` listens on an owner-only Unix socket under
`$XDG_RUNTIME_DIR/ladon/broker.sock` or an owner-specific temporary directory.
The directory is mode `0700`, the socket is `0600`, and both sides verify peer
UID credentials. Connections use one length-prefixed protocol-v2 JSON request
and response;
the maximum JSON payload is 4 MiB and nesting/duplicate keys are rejected.

Every request contains a random `client_session_id`. `ladon mcp` generates it
once at process startup and reuses it for that process lifetime; a one-shot CLI
command uses a fresh value. It is internal protocol metadata, never an MCP tool
argument or result, and scopes grants without claiming to identify a logical
chat or resist impersonation by a malicious same-user process.

The existing `client_label` field carries the current untrusted reported name;
it is non-secret display metadata, not an authentication claim. The GUI marks
it as reported and shows an eight-character session ID for disambiguation.

Protocol version 2 supports four methods:

- `status`: lock state and non-secret idle time;
- `list`: secret IDs, names, and field names only;
- `lock`: cancel the active run and lock the vault;
- `run`: executable, arguments, working directory, secret references, binding
  targets, timeout, and output limit.

App lock is a GUI-only state and does not add a protocol method or change any
schema. While the GUI is `AppLocked`, the existing methods produce these
results:

```text
AppLocked status => state "locked", idle_remaining_ms absent/null
AppLocked list   => vault_locked
AppLocked run    => vault_locked
AppLocked lock   => success after hard vault lock
```

No RPC can request soft lock, start Touch ID, submit a PIN, or unlock the app.
The agent-facing `lock` operation always performs the full vault lock and
requires the passphrase for a subsequent unlock.

There is no get/export/plaintext method. A run response contains exit status,
termination reason, bounded redacted stdout/stderr, duration, redaction count,
truncation state, and a non-sensitive temporary-file cleanup warning.

The broker accepts at most eight concurrent same-user connection workers and
one active run. Socket reads/writes have five-second timeouts. Run bindings are
limited to 16 and one MiB of injected data in aggregate.

Before a secret-bearing run, the app resolves references to immutable secret
IDs and checks a fixed 30-minute in-memory grant for every
`(client_session_id, secret_id)` pair. Missing grants create one bounded pending
GUI approval. PIN or Touch ID approval grants only the displayed missing IDs;
use does not extend expiry. Denial, timeout, or client disconnect starts no
child. Listing metadata and runs with no secret bindings do not create grants.
Only one run may reserve the approval/execution slot at a time, so a busy request
cannot accidentally obtain a grant. Lock and app shutdown cancel a pending
approval and clear all grants. Each unlock has a fresh internal epoch, so an
abnormal lock cannot leave a reusable permission. The broker rechecks expiry
and revocation immediately before plaintext resolution.

The GUI's **Agent access** panel lists active grants, their reported names,
session IDs, secret names, remaining time, and whether each pair is running.
Its per-row **Revoke** removes exactly one `(client_session_id, secret_id)`
grant, cancels and waits for a matching active run, and preserves other grants.
**Revoke all** clears every grant and cancels and waits for the active run.
Active-grant snapshots and targeted revocation are GUI-only and never cross
RPC or MCP; protocol v2 still has only the four methods above. Revocation
cannot erase bytes already consumed, retained, or transmitted by an authorized
child. If the last grant expires before its command finishes, the GUI hides the
empty list but retains an **Agent command running** indicator and **Revoke all**
until that command exits or is cancelled.

Saving or deleting a secret in the GUI also invalidates every grant for that
immutable secret ID. This does not add a protocol method: the local selected-
secret view/edit flow is GUI-only, requires a fresh PIN or Touch ID confirmation,
and rejects a stale Touch ID completion after the selection or vault session
changes. CLI, MCP, and local IPC remain value-free.

The GUI's explicit **Copy** action supports text fields only. It attempts to
clear the clipboard after 30 seconds, or on app lock, vault lock, or exit, only
when its contents still equal the copied text. Newer, different contents are
preserved. Cleanup is best-effort if the clipboard is unavailable and cannot
clear clipboard managers or OS history. Clipboard values never enter RPC/MCP.

## MCP

`ladon mcp` is a local stdio MCP server exposing only these five tools:

- `ladon_status`
- `ladon_list_secrets`
- `ladon_lock`
- `ladon_identify_session`
- `ladon_run`

`ladon_identify_session` is optional and process-local. Its only argument is
`display_name`, a non-secret, untrusted reported name. The server trims it and
requires 1–64 UTF-8 bytes with no control characters; unknown arguments are
rejected. For example:

```json
{"display_name": "Codex — demo task"}
```

This call updates only the MCP process's label and does not contact the broker.
The next broker request forwards the new label in the existing `client_label`
field, without changing the private session UUID or renewing any grant. The
response acknowledges `identified: true` without returning the label or UUID.
If no explicit name is supplied, a valid `clientInfo.name` from initialization
is used; otherwise the label is `MCP client`. Reported names cannot authenticate
a client or chat, and same-user impersonation remains out of scope.

Run tool arguments contain references such as `my-secret` or
`id:<uuid>` plus a field name. They never contain a value property. The MCP run
timeout is capped at 15 minutes. stdout is reserved for JSON-RPC; ordinary
diagnostics use stderr and stable non-secret error messages.

`ladon integrate codex` writes an absolute local stdio command and a 960-second
tool timeout. `ladon integrate claude` writes the equivalent user-scoped
`mcpServers` entry. Both show the exact change first, require confirmation unless
`--yes` is supplied, preserve unrelated settings, and back up an existing
configuration before an atomic replacement.

The configured coding agent and `ladon-app` must execute on the same machine and
as the same OS user. Hosted/cloud agent execution cannot reach this local
broker.
