# Soft App Lock and One-Step Unlock Design

**Date:** 2026-09-07

**Status:** Proposed addendum

**Amends:** `2026-09-04-ladon-design.md`

## 1. Purpose

Ladon's current **Lock now** action performs a full cryptographic vault lock.
That is the right boundary for expiry and shutdown, but it makes a short UI
lock unnecessarily expensive: returning to the manager requires the vault
passphrase and another temporary-confirmation setup step.

This addendum separates a reversible, in-process **app lock** from the existing
**vault lock**. It also removes one click from biometric app unlock and records
two small manager polish changes requested during manual testing.

The change optimizes for Ladon's primary threat model: preventing accidental
display or use of secrets and preventing an agent from using them while the
user considers the app locked. It does not claim to protect secrets from a
process that can read Ladon's memory.

## 2. Goals

- Let the user temporarily hide and disable Ladon without re-entering the vault
  passphrase.
- Unlock that temporary state with Touch ID or the current session PIN.
- Make a click on **Unlock** start Touch ID immediately when it is available.
- Keep the existing 30-minute cryptographic idle limit and hard-lock behavior.
- Keep agent access closed for the entire app-locked interval.
- Avoid new runtime dependencies, platform credential stores, or vault-format
  changes.
- Highlight the selected secret clearly and make destructive button styling
  consistent.

## 3. Non-goals

- The PIN does not encrypt or unwrap the vault key.
- Touch ID does not become a key-storage mechanism.
- No Keychain, Secure Enclave, DPAPI, Credential Manager, Secret Service, or
  equivalent persistent credential integration is added.
- No remote, per-provider, or secret-type adapter is introduced.
- No agent-facing API may unlock the app, submit a PIN, or initiate Touch ID.
- This does not defend an unlocked process against memory inspection or control
  by another process running with equivalent privileges.

## 4. Lock states

The desktop process has three explicit states:

| State | Vault key in memory | GUI values | Agent secret access | Way out |
| --- | --- | --- | --- | --- |
| `HardLocked` | no | cleared | denied | vault passphrase |
| `Active` | yes | allowed by existing per-secret confirmation | allowed by existing grants | app or vault lock |
| `AppLocked` | yes, until the original idle deadline | cleared | denied | Touch ID or configured session PIN |

`AppLocked` is a presentation and access-control boundary inside the already
unlocked process. It retains the vault controller's decrypted session key and
the in-memory `SessionConfirmation` capability. It clears all GUI plaintext and
closes both GUI and broker access to secret material.

The existing 30-minute idle deadline belongs to the unlocked vault session.
Entering or leaving `AppLocked` neither resets nor extends it. Agent requests
received while app-locked also do not count as secret use.

## 5. State transitions

### 5.1 App lock

The manager and tray action previously labelled **Lock now** becomes **Lock
app**. It performs a coordinated transition from `Active` to `AppLocked`:

1. Under the approval coordinator, enter an internal `AppLocking` transition,
   increment the lock epoch, close broker admission, cancel a pending approval,
   revoke every grant, and signal cancellation to any active run.
2. Immediately clear the selected-secret authorization, revealed value, edit
   buffers, unsaved draft, local PIN-entry buffer, approval UI, and pending
   Touch ID attempt. Show a value-free **Locking** screen rather than leaving a
   secret visible while process cleanup finishes.
3. In background coordination, wait for the active supervised process tree to
   terminate. New broker work remains closed throughout the wait.
4. Finish in `AppLocked`, retaining the vault controller's unlocked session and
   the current `SessionConfirmation` verifier/capability.

The transition never asks whether to discard an unsaved edit. If coordination
or cleanup fails, Ladon fails closed by completing a hard vault lock rather than
returning to `Active` with ambiguous access state. The **Unlock** action is not
available during the internal `AppLocking` transition.

If neither strict Touch ID nor a session PIN is available when **Lock app** is
chosen, Ladon performs a hard vault lock directly rather than creating a soft
lock that has no usable local unlock method.

### 5.2 App unlock

The app-locked screen has one primary **Unlock** button. Activating it:

- immediately starts a fresh asynchronous Touch ID request when strict Touch ID
  is available at that moment;
- otherwise displays and focuses the PIN field when a session PIN exists; or
- offers **Use PIN instead** while a Touch ID attempt is available and a PIN is
  configured.

No biometric prompt is opened merely because the locked window appears. The
single explicit **Unlock** click is the user gesture that starts it.

Successful Touch ID or PIN confirmation returns to `Active`, reopens broker
admission, and resets the shared PIN failure counter. It does not restore
selection, reveal, edit state, approvals, grants, or an interrupted run.

A cancellation or failure leaves Ladon in `AppLocked`. A Touch ID result is
bound to a monotonically increasing app-lock epoch and is ignored if it arrives
after another lock transition, hard lock, timeout, or process-state change.

If neither strict Touch ID nor a session PIN is available, Ladon cannot soft
unlock and offers the passphrase path after a hard vault lock.

### 5.3 Hard vault lock

The following always transition `Active` or `AppLocked` to `HardLocked`, wipe
the vault key and `SessionConfirmation`, and require the passphrase again:

- expiry of the existing 30-minute idle deadline;
- process exit;
- operating-system screen lock, logout, or suspend when detectable;
- **Lock vault completely** on the app-locked screen;
- the fifth consecutive incorrect session-PIN submission;
- an emergency lock after persistence, coordination, or recovery failure; and
- the agent-facing MCP `lock` operation.

The external `lock` operation remains deliberately hard. An agent cannot choose
a weaker lock state or later unlock Ladon.

## 6. Broker and coordination boundary

The existing approval coordinator gains a value-free desktop-access gate and
lock epoch. This avoids adding another independent lock domain. Every
vault-facing broker operation checks the gate. While it is closed, list and run
requests fail with the existing locked-vault error contract and never open an
approval dialog. Status remains callable but reports the existing `locked`
state without an idle-time value, so no protocol or client migration is needed.
The MCP `lock` operation also remains callable and upgrades either soft state to
a hard vault lock.

The local GUI asks the broker coordinator to enter `AppLocked` before clearing
its own view state. Reopening the gate is the final step after successful local
authentication. The established lock order remains approval coordinator, run
coordinator, then vault controller when a hard-lock fallback also needs the
controller. No plaintext is stored in the access gate, epoch, or error path.

The GUI locking and locked screens display no secret metadata.

## 7. PIN and Touch ID behavior

The existing 4--12 digit session PIN and strict Touch ID rules remain. Either
method is sufficient when available. Touch ID is preferred only in the UI flow,
not treated as stronger key protection.

The incorrect-PIN counter is shared across secret confirmation, agent approval,
and app unlock. Five consecutive incorrect PIN attempts trigger the hard lock
described above. Touch ID success resets the counter; cancelling or failing a
Touch ID prompt does not increment it.

Every Touch ID request uses the existing fresh-context, biometric-only adapter.
App-unlock authentication is bound to the current vault-session UUID, the
`unlock_app` action, and the app-lock epoch. Late or duplicated results cannot
open the broker gate.

## 8. Manager UI polish

- The selected row in the left secret rail uses a filled cobalt selection
  background across the compact row, while retaining readable metadata text.
- The first **Delete** action uses the same filled danger-red button treatment
  as **Confirm delete**. The two-step confirmation and cancellation behavior do
  not change.
- The compact dimensions, inline first field, `+N` hover details, and stable
  show/hide/edit card widths from the preceding UI pass remain unchanged.

## 9. Compatibility and migration

There is no vault schema, encrypted payload, IPC message, CLI, or MCP-tool
migration. Existing vaults open unchanged. Existing clients see the same hard
behavior from MCP `lock` and the same value-free locked error while app access
is closed.

Platforms without strict Touch ID use the configured PIN. No additional OS
package, service, daemon, or credential store is required.

## 10. Verification

Automated coverage must demonstrate:

- all allowed and forbidden transitions among `HardLocked`, `Active`, and
  `AppLocked`;
- app lock preserves the unlocked vault session and confirmation capability but
  clears GUI value/edit/authorization buffers;
- app lock cancels approvals and runs, revokes grants, and closes admission
  before returning success;
- secret-bearing broker requests cannot resolve or obtain approval while
  app-locked;
- app lock and app unlock do not extend the vault idle deadline;
- one **Unlock** action starts Touch ID when available, with PIN fallback;
- stale Touch ID completion cannot unlock a later epoch;
- a fifth incorrect PIN and every external MCP `lock` perform a hard lock;
- coordination failure falls back to a hard lock;
- the selected rail row and both delete steps use their intended visual style.

The exact tree to land must pass formatting, strict linting, the complete test
suite, and a release build. Manual macOS verification must cover Touch ID
success, cancellation, PIN fallback, timeout while app-locked, and an agent
request attempted during app lock.

## 11. Security tradeoff

While `AppLocked`, the vault key and temporary confirmation verifier remain in
Ladon's memory until the original idle deadline. This is intentionally weaker
than `HardLocked` against process-memory compromise, but it makes short locks
usable and directly addresses accidental disclosure and unintended agent use.
The UI names the stronger action **Lock vault completely** so the distinction is
visible rather than implied.
