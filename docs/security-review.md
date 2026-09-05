# Security preview review

An independent read-only review covered commits `354c90a..abd54be` against the
design specification. It found three release-blocking boundary failures and
seven important hardening gaps. A second pass over `abd54be..333aac7` found no
critical issue and six remaining important state/recovery/temp-root gaps. The
follow-up fixes below are part of the same security-preview delivery.

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

## Deliberately deferred preview work

Windows agent IPC and SID validation, tray/background behavior, native quick
PIN storage, screen-lock notifications, binary-field GUI import, signed
installers, and cross-platform runtime packaging remain stable-v1 gates. The
README and threat model do not present them as implemented.

The GUI framework and operating-system input stack may make transient copies of
typed text. Ladon removes its own persistent undo history and zeroizes owned
buffers, but protection from same-user memory inspection remains outside the
primary threat boundary.
