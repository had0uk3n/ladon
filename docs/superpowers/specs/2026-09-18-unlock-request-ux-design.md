# Request-driven unlock and local exposure audit

Agent list/run requests received by the desktop while locked open a local unlock request and wait, with cancellation, denial and a bounded timeout. No child starts and no metadata is returned before local authentication. Status stays non-interactive. Hard lock, disconnect and shutdown cancel waiting requests. A run still needs its explicit existing secret/command approval after unlocking.

Normal idle locking becomes app locking while a confirmation method exists. PIN and Touch ID remain memory-only; five failed PIN attempts force a hard lock. Successful app unlock starts a fresh idle interval. Explicit hard lock and exit still erase keys. Recovery/setup without confirmation retains the hard idle limit.

On macOS, a native menu-bar item supports Open Ladon, Lock app, Lock vault completely and Quit. Closing the window hides it and locks the app. Incoming unlock/approval requests restore, unminimize and focus the window once per request. Other platforms keep their existing close lifecycle.

A user-triggered local exposure audit scans a chosen directory off the UI thread, reporting candidate counts and file/line/rule metadata, never values or source snippets. Skip symlinks, binary/large files, build/vendor/git directories, enforce traversal/byte/time limits and cancellation. Counts mean likely plaintext secrets, not verified working credentials or internet leaks. Results explicitly indicate incomplete coverage.

Persistent keychain unlock and internet leak checks await clarification and are not inferred. No scan is run against user files as part of implementation.
