# Local protocol and MCP surface

## Local broker protocol

On Unix, `ladon-app` listens on an owner-only Unix socket under
`$XDG_RUNTIME_DIR/ladon/broker.sock` or an owner-specific temporary directory.
The directory is mode `0700`, the socket is `0600`, and both sides verify peer
UID credentials. Connections use one length-prefixed protocol-v2 JSON request
and response (the lifecycle connection described below stays open);
the maximum JSON payload is 4 MiB and nesting/duplicate keys are rejected.

Every request contains a random `client_session_id`. `ladon mcp` generates it
once at process startup and reuses it for that process lifetime; a one-shot CLI
command uses a fresh value. It is internal protocol metadata, never an MCP tool
argument or result, and scopes grants without claiming to identify a logical
chat or resist impersonation by a malicious same-user process.

The existing `client_label` field carries the current untrusted reported name;
it is non-secret display metadata, not an authentication claim. The GUI marks
it as reported and shows an eight-character session ID for disambiguation.

Protocol version 2 supports five methods:

- `session_open`: register a process-lifetime connection;
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
AppLocked list   => authorized unattended snapshot, otherwise local unlock prompt
AppLocked run    => valid unattended grants, otherwise local unlock prompt and approval
AppLocked lock   => success after hard vault lock
```

List/run on a desktop broker can request an unlock prompt, never submit a PIN,
perform authentication, or create unattended permissions. Status remains silent.
A locked request waits up to two minutes for local authentication; denial,
disconnection, shutdown, timeout or a subsequent hard lock terminates it.
Only one unlock request waits at a time (others receive `busy`). The request
is bound to a lock generation so an intervening hard lock invalidates it.
Headless brokers retain `vault_locked`. No wire schema changes are needed.
The agent-facing `lock` operation always performs the full vault lock and
requires the passphrase for a subsequent unlock.

There is no get/export/plaintext method. A run response contains exit status,
termination reason, bounded redacted stdout/stderr, duration, redaction count,
truncation state, and a non-sensitive temporary-file cleanup warning.

Clients open a separate `session_open` connection before their first list or run
request. A `session_opened` response acknowledges registration; the client keeps
the socket open for its process lifetime, while ordinary RPCs use separate
connections. Status and lock never require a lifecycle slot, so admission
limits cannot prevent hard locking. EOF or a socket error revokes that client's grants and cancels its
pending approval. A duplicate live UUID is rejected. MCP reconnects before its
next tool call if Ladon has restarted. A one-shot CLI command holds the connection
until its RPC completes. This is internal IPC, not a sixth MCP tool. Older direct
RPC clients can still use timed approvals, but cannot select session expiry.

The broker accepts at most 40 concurrent same-user connection workers, with at
most 32 lifecycle connections, leaving capacity for ordinary RPCs. Only one run
can execute at a time. Socket reads/writes have five-second timeouts; established
lifecycle sockets instead monitor disconnection until shutdown. Run bindings are
limited to 16 and one MiB of injected data in aggregate.

Before a secret-bearing run, the app resolves references to immutable secret
IDs and checks an unexpired in-memory grant for every
`(client_session_id, secret_id)` pair. Missing grants create one bounded pending
GUI approval. PIN or Touch ID approval grants only the displayed missing IDs;
the selected expiry is 30 minutes by default, the next local midnight, or the
end of the tracked MCP process. Midnight uses a wall-clock deadline, including
sleep and daylight-saving changes; 30-minute grants use elapsed time. Use does
not extend expiry. Tracked client disconnection revokes its grants. Denial,
timeout, or client disconnect starts no
child. Listing metadata and runs with no secret bindings do not create grants.
Only one run may reserve the approval/execution slot at a time, so a busy request
cannot accidentally obtain a grant. Manual lock and app shutdown cancel a pending
approval and clear all grants. Each unlock has a fresh internal epoch, so an
abnormal lock cannot leave a reusable permission. The broker rechecks expiry
and revocation immediately before plaintext resolution.

The GUI's left **Active sessions** button includes every live lifecycle connection,
including connections without grants, plus legacy clients with active grants.
Connection cards show reported names, local aliases/notes, project, last activity,
waiting/running/idle state and grants with expiration. Annotations are bounded,
memory-only and removed on disconnection; they never alter UUID permission keys.
Its per-row **Revoke** removes exactly one `(client_session_id, secret_id)`
grant, cancels and waits for a matching active run, and preserves other grants.
**Revoke all** clears every grant and cancels and waits for the active run.
Active-grant snapshots and targeted revocation are GUI-only and never cross
RPC or MCP. Revocation
cannot erase bytes already consumed, retained, or transmitted by an authorized
child. If the last grant expires before its command finishes, the session view
retains an **Agent command running** indicator and **Revoke all**
until that command exits or is cancelled.

Unattended approval is GUI-only and requires fresh local PIN or Touch ID.
The GUI captures immutable secret IDs, vault session, mutation revision and lock
epoch before authentication. Completion validates this context before granting;
a mutation or intervening lock rejects stale confirmation. Expiration is fixed
at confirmation capture: 30 minutes, 2/8/12 hours or local HH:MM within 24 hours.
It uses an absolute wall-clock deadline with an elapsed-time ceiling, so clock
changes or sleep cannot extend the grant. New secrets never join that snapshot.
Automatic interface locking preserves only these grants and eligible runs.
While locked, every referenced secret must have unattended access; listing is
restricted to that connection's authorized IDs. Missing access requires local
unlock. Manual app lock, hard lock, targeted/session/global revoke, deadline,
disconnection and exit revoke access. A manual lock while already automatically
locked still revokes retained grants. **Revoke session** also cancels that
connection's pending/running command.

Saving or deleting a secret in the GUI also invalidates every grant for that
immutable secret ID. This does not add a protocol method: the local selected-
secret view/edit flow is GUI-only, requires a fresh PIN or Touch ID confirmation,
and rejects a stale Touch ID completion after the selection or vault session
changes. CLI, MCP, and local IPC remain value-free.

The GUI's explicit **Copy** action supports text fields only and writes the
current value to the system clipboard. Ladon does not subsequently read, time,
or clear that clipboard content. Clipboard managers and OS history remain
outside Ladon's control. Clipboard values never enter RPC/MCP.

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


### Communication failures and recovery

The app and CLI/MCP client are independently running processes. Some older
protocol-v2 app builds predate `session_open`; protocol version 2 alone does not
prove session-handshake support. They can answer `status` but close a session
request without replying. Do not fall back to untracked secret access.

Transport EOF, including a partial header or payload, reports `ipc_disconnected`;
a read deadline reports `ipc_timeout`. `invalid_frame` is reserved for malformed
framing. A malformed response or a response with another request UUID reports
`invalid_response`. A valid, bounded request with a recoverable UUID receives a
correlated rejection instead of a silent disconnect; malformed or ambiguous JSON
never gets its contents reflected in diagnostics.

MCP communication errors retain `code`, `message` and `isError: true`, and add
`source: local_ladon`, `phase`, `execution` and `recovery`. A `session_open` failure
has `execution: not_started`: the requested command was not submitted. A failed
`run` exchange has `execution: unknown`: it may already have caused external
effects, so losing a reply never authorizes replay. Other exchanges use
`execution: not_applicable`. Both text and structured MCP content carry the same
safe result; command arguments, bindings and raw peer diagnostics are excluded.

Recovery says `action: ask_user`, `automatic_retry: false`, and
`manage_shared_app: false`. The user checks whether the running app and client
builds are compatible. An agent must not stop, restart, replace or globally lock
the shared Ladon app to repair its own connection. CLI failures carry the same
human guidance. These instructions do not replace operating-system isolation;
they grant no new authority and do not automatically retry or restart anything.
