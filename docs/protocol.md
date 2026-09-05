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

Protocol version 2 supports four methods:

- `status`: lock state and non-secret idle time;
- `list`: secret IDs, names, and field names only;
- `lock`: cancel the active run and lock the vault;
- `run`: executable, arguments, working directory, secret references, binding
  targets, timeout, and output limit.

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
and revocation immediately before plaintext resolution. Manual revocation also
cancels and waits for the active run; it still cannot erase bytes retained or
transmitted by a child that was already authorized.

Saving or deleting a secret in the GUI also invalidates every grant for that
immutable secret ID. This does not add a protocol method: the local selected-
secret view/edit flow is GUI-only, requires a fresh PIN or Touch ID confirmation,
and rejects a stale Touch ID completion after the selection or vault session
changes. CLI, MCP, and local IPC remain value-free.

## MCP

`ladon mcp` is a local stdio MCP server exposing only:

- `ladon_status`
- `ladon_list_secrets`
- `ladon_lock`
- `ladon_run`

Tool arguments contain references such as `my-secret` or
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
