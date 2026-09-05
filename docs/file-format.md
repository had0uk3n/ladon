# Vault file format

This document summarizes the implemented v1 envelope. The normative details and
limits live in `ladon-core` tests and the design specification.

The vault is a versioned binary envelope containing an authenticated fixed
header, Argon2id parameters and salt, an XChaCha20-Poly1305-wrapped random data
encryption key (DEK), a payload nonce, and an encrypted canonical CBOR payload.
Header bytes are included as associated data so algorithm identifiers, KDF
parameters, lengths, salts, and nonces cannot be changed undetected.

Current algorithms:

- KDF: Argon2id, 64 MiB memory, 3 iterations, parallelism 4;
- wrapping and payload cipher: XChaCha20-Poly1305;
- random DEK, salt, and nonces from the operating system CSPRNG;
- payload: deterministic canonical CBOR with integer keys.

The decoded payload is limited to 64 MiB, 10,000 records, 64 fields per record,
and 1 MiB per field. Names and fields are revalidated after decoding. Unknown
canonical payload keys are retained for compatible evolution; unknown required
or non-canonical structures are rejected.

Writes use two separately synced candidates, then install an authenticated
backup and primary copy. On open, Ladon authenticates both independently and
never silently promotes an unauthenticated file. Recovery from a valid backup
requires an explicit GUI action.

The stable test vector is
`crates/ladon-core/tests/fixtures/v1-empty-vault.hex`. Production randomness
cannot be replaced by fixture inputs through the public API.

This format provides confidentiality and integrity, not rollback prevention.
Copying an older valid vault file back into place can restore its older state.
