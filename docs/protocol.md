# Local protocol and MCP surface

## Local broker protocol

On Unix, `ladon-app` listens on an owner-only Unix socket under
`$XDG_RUNTIME_DIR/ladon/broker.sock` or an owner-specific temporary directory.
The directory is mode `0700`, the socket is `0600`, and both sides verify peer
UID credentials. Connections use one length-prefixed JSON request and response;
the maximum JSON payload is 4 MiB and nesting/duplicate keys are rejected.

Protocol version 1 supports four methods:

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
