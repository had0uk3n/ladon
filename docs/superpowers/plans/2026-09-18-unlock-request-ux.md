# Unlock request UX implementation plan

Spec: ../specs/2026-09-18-unlock-request-ux-design.md

## Global constraints
Rust 1.85; existing vault format and value-free IPC; five wrong PIN attempts hard-lock; no real user-file scan during development; preserve concurrent main changes; land verified work on origin/main.

## Tasks
1. Broker request coordinator: add bounded local unlock wait before list/run; regression tests for resume, denied/cancelled requests, and no launch before approval.
2. Desktop locking: idle soft-lock, refresh activity after authenticated unlock, request presentation/focus and PIN input focus. Retain stale-auth rejection and fifth-failure hard lock tests.
3. Native macOS tray module: main-thread menu callbacks, wake event loop, focus helper and explicit quit; desktop integrates hide/lock only when tray creation succeeds.
4. Local exposure scanner module: synthetic filesystem tests first, bounded cancellable traversal and metadata-only findings; desktop background scan dialog and directory input.
5. Update README/security/protocol. Run fmt, clippy, workspace tests, release build and smoke test on current upstream-integrated tree; review; commit and fast-forward origin/main and confirm SHA.
