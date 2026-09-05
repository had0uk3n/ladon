# Ladon

Ladon is a small local secret vault and process runner for coding agents. You
store a named value in the GUI; Codex, Claude Code, or the CLI can ask Ladon to
run a local command with that value injected through an environment variable,
standard input, or a temporary file. The secret itself is never returned over
MCP or local IPC and does not need to appear in chat or command arguments.

Ladon is an early security preview, not a general-purpose password manager or a
data-loss-prevention system. The currently usable end-to-end agent bridge is
macOS/Linux only. The Windows GUI and process supervisor compile, but the
owner-authenticated named-pipe transport is not implemented yet.

## What works now

- encrypted, portable, passphrase-protected vault;
- native GUI for first run, unlock, add/list/delete, explicit backup recovery,
  and 30-minute activity locking;
- generic direct process execution without a shell added by Ladon;
- environment, stdin, and temporary-file injection by secret name or ID;
- bounded stdout/stderr capture and redaction of common raw/encoded forms;
- same-user Unix socket with peer credential checks;
- `ladon status`, `list`, `lock`, `run`, and stdio `mcp`;
- preview-before-write `ladon integrate codex|claude`, with a timestamped
  configuration backup and idempotent updates.

Quick PIN, tray/background lifecycle, OS screen-lock handling, Windows named
pipes, binary file drag-and-drop, and signed installers remain release work.

## Build and run

Ladon requires Rust 1.85 or newer.

```sh
cargo build --release
./target/release/ladon-app
```

On first launch, create a passphrase of at least 12 Unicode characters, then add
a secret. Keep the app open and the vault unlocked while an agent uses it.

In a second terminal:

```sh
./target/release/ladon status
./target/release/ladon list
```

Configure a local coding agent after reviewing the displayed change:

```sh
./target/release/ladon integrate codex
./target/release/ladon integrate claude
```

The generated configuration contains only the absolute path to `ladon mcp`.
It never contains vault values or credentials. Codex is configured with a
16-minute MCP tool timeout so Ladon's bounded 15-minute MCP run can report
cleanup and redaction results.

## Generic runner

The default field is named `value`:

```sh
ladon run --env API_TOKEN=my-service -- curl https://example.test/api
```

For a multi-field secret, use `name::field`:

```sh
ladon run \
  --env ACCESS_KEY=object-store::access_key \
  --env SECRET_KEY=object-store::secret_key \
  -- your-local-program
```

Other bindings:

```sh
ladon run --stdin signing-key::pem -- your-local-program
ladon run --file-env CERT_FILE=client-cert::pem -- your-local-program
```

Ladon resolves the executable on the client, sends an absolute path to the app,
starts it directly, supplies a minimal environment, and returns only bounded,
redacted output. Ladon does not provide service-specific adapters.

## Agent use

After MCP setup, a useful request is:

> Run the local command using the Ladon secret named `my-service` in the
> `API_TOKEN` environment variable. Do not ask me to paste the value.

Secret names, field names, executable paths, arguments, and working directories
are metadata visible to the agent. Do not put secret material in those names or
arguments.

The current preview does not open an approval dialog for a locked agent request.
It returns `vault_locked`; unlock Ladon in the local GUI and retry the request.

## Security boundary

Ladon primarily prevents accidental disclosure into chat, shell history,
process arguments, logs, and ordinary command output. It encrypts the vault at
rest and rejects other OS users at the local Unix endpoint.

It cannot protect a secret from malware already running as your user, a
malicious authorized child process, screen/keyboard capture, or deliberate
transformation and exfiltration by a child. Redaction recognizes common exact
representations; it is not semantic DLP. Read [SECURITY.md](SECURITY.md) and the
[threat model](docs/threat-model.md) before using real credentials.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

The detailed [design specification](docs/superpowers/specs/2026-09-04-ladon-design.md),
[implementation plan](docs/superpowers/plans/2026-09-04-ladon-v1-implementation.md),
[file format](docs/file-format.md), and [protocol](docs/protocol.md) are kept in
the repository so the security design is reviewable alongside the code.

## License

Apache-2.0.
