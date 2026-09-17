# Task 5 Report: Conditionally Clearing System Clipboard

## Implementation

- Added a GUI-only `clipboard` adapter with a lazy `arboard::Clipboard` backend.
- Added `SecretClipboard::copy`, `poll_clear`, and `clear_if_owned`; the adapter
  retains a `ClipboardLease` only after a successful clipboard write.
- Expired leases avoid a clipboard read before their deadline. When a lease is
  eligible to clear, the readback `String` is wrapped in `Zeroizing`, compared
  against the lease, dropped, and only then is the system clipboard cleared.
- A read or write failure returns the sole safe display message, `Clipboard is
  unavailable`, and leaves the lease in place for a later retry.
- Made `arboard` a direct optional dependency of the `gui` feature only.
- Added `ClipboardLease::is_expired` and retained the original conditional
  clearing semantics.

## TDD evidence

RED was observed before production implementation:

```text
cargo test -p ladon-app --all-features clipboard
error[E0432]: unresolved imports ClipboardBackend, ClipboardError, SecretClipboard

cargo test -p ladon-app --test ui_state clipboard
error[E0599]: no method named is_expired found for ClipboardLease
```

The fake backend uses `Zeroizing<String>`. GREEN tests cover expiry clearing,
preservation of newer user content, immediate lock cleanup, and retrying a
failed clear after retaining its lease.

## Verification

Passed:

```text
cargo test -p ladon-app --all-features clipboard
3 passed; 0 failed

cargo test -p ladon-app --test ui_state clipboard
1 passed; 0 failed

cargo clippy --workspace --all-targets --all-features -- -D warnings
Finished successfully

rustfmt --edition 2024 --check crates/ladon-app/src/clipboard.rs
Finished successfully
```

`cargo fmt --check` still reports pre-existing formatting in
`crates/ladon-core/src/grants.rs`; Task 5 leaves that unrelated file unchanged.

A broader `cargo test --workspace --all-features` run was also attempted but
fails outside this task at `agent_broker::tests::app_lock_fails_closed_over_the_socket_and_keeps_hard_lock_callable` with `EndpointUnavailable`, before the
dependent lock/desktop tests. The focused Task 5 tests and required strict lint
gate pass.

## Secret lifecycle reasoning

Secret bytes remain in `SensitiveBytes` until the successful copy operation
moves them into `ClipboardLease`. The adapter exposes bytes only as a borrowed
UTF-8 `&str` to the system write; it does not create an additional secret
`String`. Clipboard readback is immediately placed in `Zeroizing<String>` and
dropped before the clearing write. The lease and all associated sensitive bytes
are dropped when Ladon no longer owns the clipboard or after a successful
conditional clear; failures retain the lease to permit retry. The error type
has no source payload and renders only the safe fixed message. Neither the
clipboard adapter nor its lease has a secret-bearing `Debug` implementation.

## Files

- `Cargo.lock`
- `crates/ladon-app/Cargo.toml`
- `crates/ladon-app/src/clipboard.rs`
- `crates/ladon-app/src/lib.rs`
- `crates/ladon-app/src/ui.rs`
- `crates/ladon-app/tests/ui_state.rs`

## Self-review and concerns

Reviewed the scoped diff for direct optional GUI dependency wiring, lazy backend
initialization, ownership equality before clearing, zeroized readback, fixed
safe errors, and absence of RPC/protocol changes. No Task 5 implementation
concerns remain. The unrelated workspace-test and formatting findings above are
recorded for follow-up and are not included in this commit.
