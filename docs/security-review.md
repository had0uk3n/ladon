# Security preview review

An independent read-only review covered commits `354c90a..abd54be` against the
design specification. It found three release-blocking boundary failures and
seven important hardening gaps. The follow-up fixes below are part of the same
security-preview delivery.

## Resolved release blockers

- Redaction output now uses a metadata-free marker and performs a final
  fail-closed scan of the rendered output. Marker, UUID/field, truncation-word,
  and encoded-pattern collisions have regression coverage.
- RPC, GUI, idle, and shutdown locking now coordinate through the live run
  gate. Cancellation waits for process-tree termination and temporary cleanup
  before the controller drops the unlocked session or returns `locked`.
- Unix supervision now terminates descendants that remain after the direct
  child exits and confirms the process group is empty after TERM-to-KILL
  escalation. Regression fixtures cover background and TERM-ignoring children.

## Resolved important findings

- Vault copies are size-checked from metadata and read through a hard byte cap
  before cryptographic parsing.
- A newer authenticated backup enters the explicit recovery flow instead of
  being silently ignored.
- Dropping the Unix IPC client cancels its active secret-bearing run.
- A vault-scoped native file lock prevents a second GUI process from writing
  the same vault on Unix and Windows.
- Sensitive widgets clear egui undo state after every update; manual, idle, and
  exit locking also replace unsaved drafts and passphrase buffers.
- Marked stale temporary directories are scavenged only after the
  single-instance endpoint is acquired. Ownership and modes are validated on
  Unix; Windows cleanup is limited to marked directories under the user's temp
  directory. Graceful cleanup failures are returned as a non-sensitive result
  flag.
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
