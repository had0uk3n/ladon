use ladon_core::{
    FieldName, LadonError, MAX_FIELD_BYTES, SecretField, SecretId, SecretRecord, SecretRef,
    TextHint,
};

#[test]
fn normalizes_secret_names_to_nfc() {
    let parsed = SecretRef::parse("Cafe\u{301}").expect("valid decomposed name");

    assert_eq!(parsed.to_string(), "Café");
}

#[test]
fn rejects_ambiguous_or_unsafe_secret_names() {
    for input in [
        "",
        "id:not-a-uuid",
        "api::token",
        "line\nfeed",
        "a\u{202e}b",
    ] {
        let error = SecretRef::parse(input).expect_err("name must be rejected");
        assert_eq!(error.code(), "invalid_secret_ref", "input: {input:?}");
    }

    let too_long = "x".repeat(129);
    assert_eq!(
        SecretRef::parse(&too_long)
            .expect_err("129-byte name must fail")
            .code(),
        "invalid_secret_ref"
    );
}

#[test]
fn parses_explicit_uuid_references_without_heuristics() {
    let uuid = "018f6f65-1f16-7c5a-9b52-6cf413b9db65";

    assert!(matches!(
        SecretRef::parse(uuid).unwrap(),
        SecretRef::Name(_)
    ));
    assert_eq!(
        SecretRef::parse(&format!("id:{uuid}")).unwrap().to_string(),
        format!("id:{uuid}")
    );
    assert_eq!(
        SecretRef::parse("id:broken").unwrap_err(),
        LadonError::InvalidSecretRef
    );
}

#[test]
fn enforces_field_name_grammar() {
    for valid in ["value", "A", "client_id", "token-2"] {
        assert_eq!(FieldName::parse(valid).unwrap().as_str(), valid);
    }

    for invalid in ["", "2token", "has space", "å", "a.b"] {
        assert_eq!(
            FieldName::parse(invalid).unwrap_err().code(),
            "invalid_field_name",
            "input: {invalid:?}"
        );
    }

    assert_eq!(
        FieldName::parse(&format!("a{}", "0".repeat(64)))
            .unwrap_err()
            .code(),
        "invalid_field_name"
    );
}

#[test]
fn bounds_field_values_without_assuming_text() {
    let accepted = SecretField::new(
        FieldName::parse("value").unwrap(),
        vec![0xff; MAX_FIELD_BYTES],
        TextHint::Binary,
    );
    assert!(accepted.is_ok());

    let rejected = SecretField::new(
        FieldName::parse("value").unwrap(),
        vec![0; MAX_FIELD_BYTES + 1],
        TextHint::Text,
    );
    assert_eq!(rejected.unwrap_err().code(), "field_too_large");
}

#[test]
fn record_ids_survive_rename_and_fields_are_unique() {
    let field = SecretField::new(
        FieldName::parse("value").unwrap(),
        b"test-value".to_vec(),
        TextHint::Text,
    )
    .unwrap();
    let mut record = SecretRecord::new("service-token", vec![field]).unwrap();
    let original_id: SecretId = record.id();

    record.rename("renamed-token").unwrap();

    assert_eq!(record.id(), original_id);
    assert_eq!(record.name(), "renamed-token");

    let duplicate_a = SecretField::new(
        FieldName::parse("value").unwrap(),
        vec![1],
        TextHint::Binary,
    )
    .unwrap();
    let duplicate_b = SecretField::new(
        FieldName::parse("value").unwrap(),
        vec![2],
        TextHint::Binary,
    )
    .unwrap();
    assert_eq!(
        SecretRecord::new("duplicate-fields", vec![duplicate_a, duplicate_b])
            .unwrap_err()
            .code(),
        "duplicate_field"
    );
}

#[test]
fn records_require_at_least_one_field() {
    assert_eq!(
        SecretRecord::new("empty", vec![]).unwrap_err().code(),
        "empty_record"
    );
}

#[test]
fn records_reject_more_than_sixty_four_fields() {
    let fields = (0..65)
        .map(|index| {
            SecretField::new(
                FieldName::parse(&format!("f{index}")).unwrap(),
                vec![],
                TextHint::Binary,
            )
            .unwrap()
        })
        .collect();

    assert_eq!(
        SecretRecord::new("too-many-fields", fields)
            .unwrap_err()
            .code(),
        "too_many_fields"
    );
}
