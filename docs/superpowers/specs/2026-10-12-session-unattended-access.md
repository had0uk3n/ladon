# Session identification and unattended access

The approved conversation design gives each live MCP connection a useful local
session card and lets the human authorize that connection to use a snapshot of
all current secrets until a fixed deadline. MCP UUIDs remain the permission key;
reported labels, user aliases, notes and project paths never identify a principal.
No automatic Codex chat linking is claimed without a host-provided mapping.

Each connection is visible even with no grants. Show its reported name, editable
human alias and note, last project, last activity, pending/running/idle state,
secret grants and absolute expiration. Metadata is bounded, memory-only and
removed on disconnection. Renaming cannot renew or broaden permissions.

Unattended access requires fresh local Touch ID or session PIN confirmation.
The confirmation captures immutable secret IDs and the vault/lock context; new
secrets are excluded. Edits/deletions revoke affected permissions and invalidate
in-flight confirmations. Offer 30 minutes, 2, 8 and 12 hours and a local HH:MM
deadline within the next 24 hours. Display the exact expiry and snapshot names.

Automatic interface locking preserves only explicitly confirmed unattended
grants and permits their supervised secret use while the UI is locked. Other
clients still need local unlock. Manual app lock, hard vault lock, revoke,
deadline, connection loss and application exit revoke access. A manual lock
while the UI is already automatically locked must also revoke retained grants.
Missing permissions while locked cannot be approved silently. Metadata listing
while locked is limited to that connection's authorized snapshot.

No secret values enter RPC or activity metadata. Existing command supervision,
output redaction, mutation serialization, local authentication and safe lock
failure behavior remain required. Support the existing platform feature gates.

Delivery requires local formatting, clippy, full tests, smoke verification and a
release build, followed by independent review and synchronization with current
main. The user explicitly exempted Ladon from merge requests; publish the
verified candidate directly to main and confirm the remote contains it.
