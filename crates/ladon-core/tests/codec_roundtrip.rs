use std::fmt::Display;

use ladon_core::{
    FieldName, LadonError, MAX_VAULT_PAYLOAD_BYTES, SecretField, SecretId, SecretRecord,
    SensitiveBytes, TextHint, VaultPayload, decode_payload, encode_payload,
};
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(SensitiveBytes: Clone, Display, serde::Serialize);

#[test]
fn sensitive_bytes_are_redacted_and_explicitly_exposed() {
    let bytes = SensitiveBytes::new(vec![0x00, 0xff, 0x41]);

    assert!(!bytes.is_empty());
    assert_eq!(format!("{bytes:?}"), "SensitiveBytes([REDACTED; 3 bytes])");
    assert_eq!(bytes.expose(|value| value.to_vec()), vec![0x00, 0xff, 0x41]);
}

#[test]
fn empty_payload_has_one_canonical_encoding() {
    let vault_id = SecretId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let payload = VaultPayload::new(vault_id, 7, vec![]).unwrap();

    let encoded = encode_payload(&payload).unwrap();

    let mut expected = vec![0xa4, 0x00, 0x50];
    expected.extend_from_slice(&[0x11; 16]);
    expected.extend_from_slice(&[0x01, 0x07, 0x02, 0x80, 0x03, 0xa1, 0x00, 0x19, 0x07, 0x08]);
    assert_eq!(encoded, expected);
    assert_eq!(
        encode_payload(&decode_payload(&encoded).unwrap()).unwrap(),
        expected
    );
}

#[test]
fn round_trips_binary_and_text_hinted_fields() {
    let binary = SecretField::new(
        FieldName::parse("certificate").unwrap(),
        vec![0x00, 0xff, 0x10],
        TextHint::Binary,
    )
    .unwrap();
    let text = SecretField::new(
        FieldName::parse("value").unwrap(),
        b"fake-test-value".to_vec(),
        TextHint::Text,
    )
    .unwrap();
    let record = SecretRecord::new("example", vec![binary, text]).unwrap();
    let original_id = record.id();
    let vault_id = SecretId::parse("22222222-2222-2222-2222-222222222222").unwrap();
    let payload = VaultPayload::new(vault_id, 42, vec![record]).unwrap();

    let decoded = decode_payload(&encode_payload(&payload).unwrap()).unwrap();

    assert_eq!(decoded.vault_id(), vault_id);
    assert_eq!(decoded.revision(), 42);
    assert_eq!(decoded.records()[0].id(), original_id);
    assert_eq!(decoded.records()[0].name(), "example");
    assert_eq!(
        decoded.records()[0].fields()[0].text_hint(),
        TextHint::Binary
    );
    assert_eq!(
        decoded.records()[0].fields()[0]
            .value()
            .expose(|value| value.to_vec()),
        vec![0x00, 0xff, 0x10]
    );
}

#[test]
fn rejects_payload_before_allocating_past_the_global_limit() {
    let oversized = vec![0; MAX_VAULT_PAYLOAD_BYTES + 1];

    assert_eq!(
        decode_payload(&oversized).unwrap_err(),
        LadonError::VaultPayloadTooLarge
    );
}

#[test]
fn rejects_non_canonical_or_trailing_payload_bytes() {
    let vault_id = SecretId::parse("33333333-3333-3333-3333-333333333333").unwrap();
    let canonical = encode_payload(&VaultPayload::new(vault_id, 0, vec![]).unwrap()).unwrap();
    let mut trailing = canonical;
    trailing.push(0x00);

    assert_eq!(
        decode_payload(&trailing).unwrap_err(),
        LadonError::InvalidVaultPayload
    );
}

#[test]
fn rejects_non_canonical_encoding_inside_preserved_unknown_values() {
    let vault_id = SecretId::parse("44444444-4444-4444-4444-444444444444").unwrap();
    let mut encoded = encode_payload(&VaultPayload::new(vault_id, 0, vec![]).unwrap()).unwrap();
    encoded[0] = 0xa5;
    encoded.extend_from_slice(&[0x04, 0x18, 0x00]);

    assert_eq!(
        decode_payload(&encoded).unwrap_err(),
        LadonError::InvalidVaultPayload
    );
}

#[test]
fn rejects_unsorted_maps_inside_preserved_unknown_values() {
    let vault_id = SecretId::parse("55555555-5555-5555-5555-555555555555").unwrap();
    let mut encoded = encode_payload(&VaultPayload::new(vault_id, 0, vec![]).unwrap()).unwrap();
    encoded[0] = 0xa5;
    encoded.extend_from_slice(&[0x04, 0xa2, 0x01, 0x00, 0x00, 0x00]);

    assert_eq!(
        decode_payload(&encoded).unwrap_err(),
        LadonError::InvalidVaultPayload
    );
}
