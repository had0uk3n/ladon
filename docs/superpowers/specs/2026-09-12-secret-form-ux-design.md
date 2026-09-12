# Stable Secret Form UX Design

## Goal

Make adding and unlocking secrets compact and predictable without changing Ladon's vault format, agent protocol, authentication model, or runtime dependencies.

## Selected-secret actions

The selected-secret card keeps its title and destructive action at the top. Directly below them it has a stable action row rendered before any secret fields:

- an unauthorized secret shows `Unlock this secret`;
- an authorized hidden secret shows `Show` and `Edit`;
- an authorized revealed secret shows its existing `Hide` action;
- edit mode keeps its existing save and cancel flow.

Switching between unauthorized secrets with different field counts therefore never moves the unlock action. Field count may change the card height, but not the action position.

## Add-secret fields

The add form starts with its existing primary `value` field. Its value is visible while the user types and uses the short placeholder `Secret value`. Visibility is limited to the add form; existing saved-secret reveal and edit authorization rules do not change.

The visible input continues to use `SensitiveText`, immediately clears egui's undo history, and is cleared by the existing save, app-lock, vault-lock, and exit paths. Plaintext visibility necessarily permits shoulder surfing, screenshots, screen sharing, and accessibility inspection; this is an accepted tradeoff requested for entry usability.

`+ Add field` appends an optional row. Each optional row has a right-side `×` control with the tooltip `Remove field`. The primary row cannot be removed. Removing an optional row immediately clears its `SensitiveText` before dropping the row; no confirmation is shown for unsaved form data.

The form never displays more than the core limit of 64 field rows. At that limit, the add control is disabled.

## Empty optional rows

An optional row is ignored only when its field name is exactly empty and its value contains zero bytes. The primary row is always included. Whitespace is data: neither field names nor values are trimmed, and a whitespace-only field name remains invalid.

Ignored rows are filtered through an immutable view while preparing the record. Saving must not remove or reorder rows in the visible draft before persistence succeeds. On success, the existing complete draft reset remains authoritative. On persistence failure, every visible row and value remains available for retry unless the failure hard-locks the vault under existing rules.

## Validation and errors

Add-form validation runs before persistence and reuses core `FieldName` parsing and size constants. It returns a form-local error target plus safe display text:

- empty optional name with a non-empty value: `Field N: enter a name or remove this field`;
- syntactically invalid name: `Field N: start with a letter; then use letters, numbers, _ or -`;
- duplicate name: `Field N: this name is already used`;
- oversized value: `Field N: value exceeds 1 MiB`.

`N` is the row's current one-based display position, including any earlier blank rows. Messages do not echo user-provided names, avoiding control-character and bidirectional-text confusion.

The error is rendered immediately below its target row. Any edit, add, remove, successful save, app lock, vault lock, or applied navigation clears it. A failed save must never leave a validation error visible on another screen. Storage, authentication, and vault errors remain card-level notices; applied navigation clears stale card notices.

## Non-goals

- No change to the 30-minute vault or grant timing.
- No change to PIN or Touch ID behavior.
- No new confirmation dialog for removing an unsaved optional field.
- No inline validation while typing; validation occurs on Save and clears on the next mutation.
- No change to existing saved-secret values, encryption, file format, CLI, MCP, or broker behavior.

## Acceptance checks

1. Switching between locked secrets with one and several fields leaves `Unlock this secret` at the same vertical position.
2. A newly typed secret value is readable and uses `Secret value` as its placeholder.
3. Saving with untouched optional rows persists only the non-empty rows.
4. Removing an optional row removes only that row; the primary row has no remove control.
5. Invalid and duplicate field names identify the displayed row and disappear after the form changes or navigation succeeds.
6. Locking or exiting clears all add-form sensitive buffers.
7. Existing agent access, authorization, reveal, edit, delete, and full workspace checks remain green.
