# Security preview review

An independent read-only review covered commits `354c90a..abd54be` against the
design specification. It found three release-blocking boundary failures and
seven important hardening gaps. A second pass over `abd54be..333aac7` found no
critical issue and six remaining important state/recovery/temp-root gaps. The
follow-up fixes below are part of the same security-preview delivery.

The subsequent session-grant change adds a memory-only authorization boundary:
protocol-v2 clients receive a random process-lifetime UUID; the broker resolves
requested metadata before plaintext, blocks before process launch, and grants
only the displayed `(client session, secret ID)` pairs for a fixed 30 minutes.
PIN and strict macOS Touch ID both gate that same transition.

An independent review of that change found three important race/lifetime gaps:
grant revocation before plaintext resolution, stale grants after a persistence-
error lock, and PIN buffers surviving a pending-request change. The fixes add
grant tickets revalidated through resolution, per-unlock epochs, cancel-and-wait
revocation, and transition-triggered PIN clearing. A follow-up review found no
remaining Critical or Important issue in the change.

## Resolved release blockers

- Redaction output now uses a metadata-free marker and performs a final
  fail-closed scan of the rendered output. Marker, UUID/field, truncation-word,
  and encoded-pattern collisions have regression coverage.
- RPC, GUI, idle, and shutdown locking now coordinate through the live run
  state. Entering a lock transition atomically blocks new runs, publishes or
  cancels the active token, and waits for process-tree termination and temporary
  cleanup before the controller drops the unlocked session or returns `locked`.
- Unix supervision now terminates descendants that remain after the direct
  child exits and confirms the process group is empty after TERM-to-KILL
  escalation. Regression fixtures cover background and TERM-ignoring children.

## Resolved important findings

- Vault copies are size-checked from metadata and read through a hard byte cap
  before cryptographic parsing.
- A newer authenticated backup is offered only for the same vault ID. Recovery
  retains the authoritative primary, offers explicit keep/restore choices, and
  applies the 30-minute plaintext lifetime to both decrypted candidates.
- Dropping the Unix IPC client cancels its active secret-bearing run.
- A vault-scoped native file lock prevents a second GUI process from writing
  the same vault on Unix and Windows.
- Sensitive widgets clear egui undo state after every update. Every observed
  transition out of the unlocked GUI, including RPC lock and persistence
  failure, replaces unsaved drafts and passphrase buffers.
- Marked stale temporary directories are scavenged only after the
  single-instance endpoint is acquired. Ownership and modes are validated on
  Unix, with existing roots inspected without following symlinks before any
  mode change; Windows cleanup is limited to marked directories under the
  user's temp directory. Cleanup runs after the cross-platform instance lock.
  Graceful per-run cleanup failures are returned as a non-sensitive result flag.
- Error text distinguishes a healthy locked vault from an unreadable vault and
  states both passphrase character and byte bounds.
- The session PIN retains only a random salt and Argon2id verifier in zeroizing
  memory. Touch ID uses the biometric-only LocalAuthentication policy without
  password fallback or authentication reuse. Neither method uses a native
  credential store.
- Approval denial, timeout, disconnect, lock, and shutdown fail closed before
  child launch. Lock and shutdown clear every grant; manual revocation clears
  future use. Session and secret isolation, fixed non-sliding expiry, and the
  no-launch-before-approval boundary have regression tests.
- Selected-secret viewing and editing are locally authenticated actions. A
  4–12 digit optional session PIN and strict Touch ID can both be used where
  available; five consecutive PIN failures lock the vault. Authorization is
  tied to the vault session, selected immutable secret ID, and selection epoch,
  so stale Touch ID completions are rejected. The GUI uses an explicit
  show/hide lifecycle and performs validated whole-record edits atomically.
  Inline binary replacement is unsupported. Saving or deleting invalidates all
  agent grants for that secret ID, while CLI, MCP, and local IPC remain
  value-free.

## Deliberately deferred preview work

Windows agent IPC and SID validation, tray/background behavior, screen-lock
notifications, binary-field GUI import, signed installers, and cross-platform
runtime packaging remain stable-v1 gates. The README and threat model do not
present them as implemented.

The GUI framework and operating-system input stack may make transient copies of
typed text. Ladon removes its own persistent undo history and zeroizes owned
buffers, but protection from same-user memory inspection remains outside the
primary threat boundary.

The client-session UUID is not a trusted chat identity and is not a defense
against a malicious process already running as the same OS user. A process that
has received a secret may retain or transform it after Ladon's grant expires;
revocation controls future resolutions only.
