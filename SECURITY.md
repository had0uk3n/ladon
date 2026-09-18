# Security policy

Ladon is a security preview. Do not rely on it as the only control for
high-impact production credentials until the stable-v1 review gates and native
platform tests are complete.

## Supported security scope

The current preview is intended to reduce accidental secret disclosure when a
local coding agent needs to run a local program. The encrypted vault, Unix peer
authentication, strict protocol bounds, direct process launch, output limits,
and redaction are in scope.

Windows agent access is not supported yet because the named-pipe transport and
SID verification are unfinished. Session PIN and macOS menu-bar persistence are
implemented. Persistent quick unlock after restart, tray support on other
platforms, screen-lock notifications, signed packages, and automatic updates
remain unfinished.

Ordinary idle locking retains the vault key in process memory for PIN/Touch ID
unlock. Use **Lock vault completely** or **Quit** to erase that session. Local
file audits cover the user's home and configured assistant folders, report
heuristic candidate locations rather than verified leaks, and do not transmit
file contents. Configuration is read as data; helpers, imports and environment
expansion are not executed. Counts exclude ambiguous high-entropy values,
which are shown separately for review. Scan coverage and partial results are
explicit; this is not a guarantee that all plaintext secrets were found.

## Reporting a vulnerability

Do not open a public issue containing a real secret, exploit payload, private
path, or sensitive log. Until a dedicated private reporting channel is
published, open a minimal public issue asking the maintainer for a private
contact channel. Use only fake values in reproductions.

Include the Ladon commit/version, operating system, affected boundary, expected
behavior, and the smallest non-sensitive reproduction. Please state whether the
issue can reveal vault plaintext, bypass same-user authorization, escape output
redaction, leave temporary material behind, or corrupt the vault.

## Operational guidance

- Use scoped, revocable credentials with the least permissions possible.
- Keep secret names and field names non-sensitive; agents can list them.
- Review the executable, arguments, working directory, and bindings before use.
- Treat any authorized child as able to read and transmit injected values.
- Lock Ladon when finished and revoke credentials after suspected compromise.
- Keep an encrypted backup. A forgotten passphrase cannot be recovered.
- Never paste a vault value into an issue, chat, test, fixture, or CI variable.

See [docs/threat-model.md](docs/threat-model.md) for the complete boundary.
