# Agent Access Observability and Secret UX Design

## Status

Approved in conversation on 2026-09-17. This document defines the design to be
implemented; it does not describe already shipped behavior.

## Goal

Make active agent access understandable and revocable without exposing secret
values, while correcting the remaining compactness, alignment, reveal, edit,
copy, and destructive-action defects in the desktop UI.

Ladon remains a small local tool. This change adds no persistent audit log, no
remote service, no trusted chat identity, and no plaintext-returning protocol.

## User-visible outcomes

The desktop app shows every unexpired agent grant with:

- the client-reported name, explicitly marked as reported;
- an eight-character prefix of the random MCP client-session UUID;
- the secret name;
- a countdown to the fixed grant deadline;
- a `Running` marker only while the current supervised command uses that exact
  client/secret pair; and
- a `Revoke` action that affects only that client/secret pair.

The full client-session UUID is available only as hover text. The existing
`Revoke all` action remains available. Empty and expired access lists disappear
without leaving an empty panel.

The selected-secret workspace also changes as follows:

1. Revealed text fields have a `Copy` button.
2. Text values remain visible while editing.
3. `Unlock this secret` and `Delete` share one stable action row.
4. `Show`, `Edit`, and `Delete` share one stable action row. Revealed mode uses
   `Hide`, `Edit`, and `Delete` in the same positions.
5. Field-removal buttons match the height of their adjacent text inputs.
6. Secret names in the left rail are left-aligned.
7. Secret rows in the left rail use one consistent font size, weight, and line
   height; selection is communicated by background and color rather than a
   typography change.
8. The unlocked-state marker is a vector-drawn circle rather than a font glyph,
   preventing a missing-glyph square.

## Non-goals

- Persisting access history or an audit log.
- Identifying or authenticating a logical Codex or Claude chat.
- Trusting the client-reported name as a security principal.
- Exposing grants, session IDs, or revocation through CLI, local RPC, or MCP.
- Copying or editing binary fields as text.
- Changing the fixed 30-minute grant lifetime.
- Changing field-removal semantics: the add form keeps its required first row;
  the edit form may remove any row while at least one field remains.
- Adding a new runtime service or OS-installed dependency.

## Identity and naming

Every `ladon mcp` process already creates one random `client_session_id` and
reuses it for that process lifetime. That UUID remains the only grant-scoping
identity. It is not exposed as an MCP tool argument or result.

The MCP server records the untrusted `clientInfo.name` supplied during MCP
initialization as its base label when it is present and valid. The new local MCP
tool `ladon_identify_session` accepts one `display_name` string and updates the
reported label for that MCP process. Its description instructs the agent to use
a short, non-secret task label before its first secret-bearing run. The MCP
server instructions make the same recommendation, but identification remains
optional because a model is not guaranteed to call the tool.

Names are trimmed, limited to 64 UTF-8 bytes, and rejected if empty, invalidly
encoded, or containing control/NUL characters. An invalid rename leaves the
previous label unchanged. The fallback label is `MCP client`. The broker treats
every label as untrusted display metadata and sanitizes it before rendering.

The GUI always displays `(reported)` with a supplied name and always displays
the UUID prefix. A later valid rename by the same MCP process updates the
display name of that process's active rows on its next broker request, including
a status request. The broker observes that label as display metadata only; it
does not change the grant key, deadline, or authorization. A different process
has a different random UUID and therefore cannot rename those rows through
ordinary MCP use.

## In-memory grant snapshot

`GrantStore` remains the authority for `(client_session_id, secret_id)`
deadlines and continues to use the monotonic clock. It gains read-only
enumeration of unexpired entries and targeted revocation of one exact pair.
Enumeration purges expired entries first and returns identifiers plus remaining
duration; it never returns secret values or display labels.

`ApprovalCoordinator` owns the untrusted session-label map because names are an
application concern, not a core grant concern. It updates a session label on a
valid request and removes labels that are no longer referenced by any grant or
pending request. Vault lock, app lock, shutdown, and full revoke clear both
grants and associated labels.

`LocalBrokerHandle` exposes a GUI-only snapshot that combines:

- unexpired grant entries from `ApprovalCoordinator`;
- current run metadata from `RunCoordinator`; and
- immutable secret metadata from `VaultController`.

The resulting GUI view contains only:

```text
reported_client_label
client_session_id
secret_id
secret_name
remaining
running
```

This snapshot is not added to `RpcMethod`, the socket protocol, CLI, or MCP.
Debug implementations redact or omit any sensitive buffers; snapshot types
contain no secret field values by construction.

## Current-run tracking

Grant existence and command execution are separate states. `RunCoordinator`
therefore records metadata for its single reserved run:

- client-session UUID, recorded when the lease is reserved;
- resolved immutable secret IDs, attached after the approval plan is built; and
- phase: preparing or running.

The lease is reserved before approval as today. Once the approval plan resolves
the immutable IDs, the lease receives its client/secret context. It changes to
`running` only immediately before the supervisor starts the child. Dropping the
lease clears all metadata after child cleanup.

The GUI sets `Running` only when the coordinator phase is running and the row's
client/secret pair is in that run. A pending approval remains represented by
the existing approval modal, not by a grant row. If a run is in the short
pre-context phase, the UI does not guess which grant it may use.

## Targeted revocation and concurrency

Targeted revocation is a local GUI operation. It is never callable by an agent.
It follows the existing lock order used for full revocation:

1. Acquire the local-UI operation guard so an external hard lock wins cleanly.
2. Atomically block admission of new runs.
3. Inspect the one reserved run while admission remains blocked.
4. If its metadata matches the requested client/secret pair, cancel the run and
   wait for child cleanup and lease release.
5. If a run from the same client is still in the pre-secret-context phase,
   cancel it fail-closed because a safe secret non-match cannot yet be proven.
   A pre-context run from another client is provably unrelated and continues.
6. Cancel a matching pending approval; a multi-secret pending request is
   cancelled as a whole.
7. Revoke only the requested `(client_session_id, secret_id)` grant.
8. Release the admission block.

An active unrelated run is not cancelled. Its grant remains unchanged. Once a
child has received plaintext, revocation cannot erase bytes already retained or
transmitted by that child; cancellation and awaited cleanup preserve the
existing documented boundary.

The UI keeps the row visible until revocation succeeds. On failure it displays
the existing safe error notice and does not pretend that access disappeared.

## Access-list layout

The existing navy/cobalt/canvas palette and native egui typography remain. No
new card language or font dependency is introduced.

The left rail order is:

```text
LADON                                      LOCAL
●  UNLOCKED
28:14 remaining

Agent access · 2
Codex — deploy payments (reported)      a31f92c4
gitlab-prod                    Running      23:41
Revoke

MCP client                               781c06d1
openai-test                                  08:12
Revoke

Revoke all

Secrets
+ New secret
gitlab-prod
openai-test
```

The vector status circle is aligned to the status text baseline. Agent access
has a bounded-height vertical scroll region so it cannot consume the secret
list. Full labels, names, and UUIDs are available as hover text. The section is
absent when there are no grants. While grants exist, the UI requests a repaint
at most once per second for countdown updates rather than repainting
continuously.

Secret navigation rows reserve the same leading inset and use one text style.
Their text is left-aligned even when the selection background spans the rail.

## Selected-secret action layout

The action row is rendered before fields so field count cannot move it.
Actions retain stable positions across states:

```text
unauthorized:  [Unlock this secret]                    [Delete]
hidden:        [Show] [Edit]                           [Delete]
revealed:      [Hide] [Edit]                           [Delete]
```

Delete confirmation replaces only the right-hand destructive action with
`Cancel` and `Delete`; it does not create a second row. Editing continues to
place `Save changes` and `Cancel` below the editable fields, because those
actions apply to the draft rather than visibility. Deleting while editing is
not added by this change; dirty-navigation protection remains authoritative.

## Reveal, edit, and copy

Revealed text values are rendered as non-editable visible text controls with a
same-row `Copy` button. Editing uses the existing visible-sensitive-text helper
so the value is readable but egui's persistent undo state is cleared. Each text
row is:

```text
[field name input] [visible value input] [Copy] [remove]
```

The remove control is sized from the text-edit row height. In the add form the
required first row has no remove action. In the edit form any row may be
removed while at least one remains, preserving current semantics.

Binary fields continue to display `Binary · N bytes`. They get neither a copy
button nor an editable text control.

Copying uses the system clipboard through `arboard`, which is already in the
compiled dependency graph through `eframe`; declaring it directly introduces
no separately installed runtime requirement. A copied text value is held in a
`ClipboardLease` as sensitive bytes. After 30 seconds, Ladon reads the current
clipboard and clears it only if it still equals that leased value. Temporary
clipboard strings used for comparison are zeroized after use. If the user has
copied something else, Ladon leaves the newer clipboard untouched and drops its
lease.

The copy button in edit mode copies the current draft value, including unsaved
changes. Cancelling the edit does not immediately clear the clipboard; the
same 30-second lease applies. A subsequent secret copy replaces the previous
lease and clipboard content. Clipboard managers, OS history, swap, and bytes
already read by another process remain outside Ladon's security boundary and
are documented accordingly.

Clipboard initialization, read, or write failures produce a safe GUI error and
never include the value. App/vault lock drops Ladon's in-memory lease; it also
attempts the same conditional clipboard clear without delaying lock completion
if the platform clipboard is unavailable.

## Error handling and cleanup

- Invalid session names return a normal MCP tool error and preserve the old
  label.
- Snapshot lock failures display a safe notice and leave the previous frame
  unchanged; they do not unlock or revoke anything implicitly.
- Expired grants disappear on the next one-second refresh.
- Secret edit or delete removes all rows for that immutable secret ID, as
  existing grant revocation already requires.
- Full revoke, soft app lock, hard vault lock, shutdown, and a new vault session
  clear the access snapshot.
- A failed targeted revoke keeps its row and reports failure.
- No error, log, debug output, MCP response, or notification includes a secret
  value.

## Documentation changes

README and protocol documentation will describe:

- the GUI-only active-access view and exact-pair revoke;
- the reported/untrusted nature of names;
- the optional `ladon_identify_session` MCP tool;
- the lack of durable history or trusted chat identity; and
- clipboard lifetime and clipboard-manager limitations.

The threat model will explicitly retain same-user impersonation and clipboard
history as out-of-scope risks.

## Test strategy

All behavior changes follow red-green-refactor.

### Core grant tests

- Enumerating active pairs returns exact remaining durations.
- Enumeration purges expired entries.
- Targeted revoke removes one pair without affecting the same secret for another
  client or another secret for the same client.
- Snapshot/debug output contains no secret value type.

### MCP tests

- Initialization captures a valid reported client name.
- `ladon_identify_session` changes the label used by later broker requests.
- Invalid and control-containing names are rejected without changing the old
  label.
- Omitted identification uses `MCP client`.
- The private client-session UUID remains stable per process and absent from MCP
  responses.
- Tool listings and server instructions describe identification without asking
  for secret material.

### Approval and broker tests

- Active snapshots contain label, IDs, remaining time, and no values.
- A later label from the same client updates display metadata without extending
  deadlines.
- Running metadata marks every grant pair used by the active command.
- Targeted revoke cancels and waits for a matching pending or running command.
- It does not cancel an unrelated active command or revoke unrelated grants.
- A pre-context reserved run is cancelled fail-closed.
- Full revoke and all lock paths still clear every grant and label.
- Secret edit/delete removes corresponding access rows.

### GUI-state and layout tests

- Active-grant view models sort deterministically by client label, session ID,
  and secret name.
- Countdown formatting and eight-character UUID formatting are stable.
- The action-set helper produces unlock/delete, show/edit/delete, and
  hide/edit/delete states without depending on field count.
- Visible sensitive edits continue to clear egui undo state.
- Copy uses revealed or current draft text and never exposes binary data.
- Conditional clipboard clearing preserves a newer clipboard value.
- Lock cleanup drops clipboard and access-view state.
- Pure layout constants keep remove controls at text-row height and secret-row
  typography consistent.

### Final verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features`
- `scripts/smoke-test.sh`
- `cargo build --workspace --all-features --release`
- Manual macOS verification of copy/clear, Touch ID approval, countdown,
  scrolling, alignment, and targeted revoke against a real MCP client.

## Acceptance criteria

The work is complete when a user can see every active in-memory grant, distinguish
reported MCP processes, see exact remaining access time and actual execution,
revoke one pair without disturbing unrelated access, and revoke everything at
once. Text secrets can be copied after reveal and remain visible while editing,
with conditional 30-second clipboard clearing. All requested action, sizing,
alignment, typography, and unlocked-indicator defects are corrected without
adding plaintext APIs, persistent history, trusted-chat claims, or new runtime
installation requirements.
