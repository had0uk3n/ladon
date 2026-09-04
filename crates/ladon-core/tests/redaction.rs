use base64::{Engine, engine::general_purpose};
use ladon_core::{
    DEFAULT_OUTPUT_LIMIT_BYTES, FieldName, RedactionSecret, SecretId, SensitiveBytes,
    StreamingRedactor,
};
use proptest::prelude::*;

fn secret(id: &str, field: &str, value: &[u8]) -> RedactionSecret {
    RedactionSecret::new(
        SecretId::parse(id).unwrap(),
        FieldName::parse(field).unwrap(),
        SensitiveBytes::new(value.to_vec()),
    )
}

fn redact(chunks: &[&[u8]], secrets: Vec<RedactionSecret>) -> ladon_core::RedactedOutput {
    let mut redactor = StreamingRedactor::new(secrets, DEFAULT_OUTPUT_LIMIT_BYTES).unwrap();
    for chunk in chunks {
        redactor.push(chunk);
    }
    redactor.finish()
}

#[test]
fn redacts_raw_json_percent_hex_and_base64_representations() {
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let value = b"ab\" /z";
    let json_string = serde_json::to_string("ab\" /z").unwrap();
    let json = &json_string[1..json_string.len() - 1];
    let percent_upper = "ab%22%20%2Fz";
    let percent_lower = "ab%22%20%2fz";
    let hex_lower = "616222202f7a";
    let hex_upper = "616222202F7A";
    let base64 = general_purpose::STANDARD.encode(value);
    let base64_unpadded = general_purpose::STANDARD_NO_PAD.encode(value);
    let base64_url = general_purpose::URL_SAFE.encode(value);
    let input = format!(
        "raw={} json={} percent={percent_upper}/{percent_lower} hex={hex_lower}/{hex_upper} b64={base64}/{base64_unpadded}/{base64_url}",
        String::from_utf8_lossy(value),
        json,
    );

    let output = redact(&[input.as_bytes()], vec![secret(id, "value", value)]);

    assert!(!output.text.contains("ab\" /z"));
    assert!(!output.text.contains("616222202f7a"));
    assert!(!output.text.contains(&base64));
    assert!(
        output
            .text
            .contains("[REDACTED:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa.value]")
    );
    assert!(output.redaction_count >= 7);
}

#[test]
fn finds_secrets_split_across_every_chunk_boundary() {
    let value = b"boundary-secret";
    for split in 1..value.len() {
        let output = redact(
            &[&value[..split], &value[split..]],
            vec![secret(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "token",
                value,
            )],
        );
        assert_eq!(
            output.text, "[REDACTED:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.token]",
            "split {split}"
        );
    }
}

#[test]
fn chooses_longest_overlapping_secret_at_the_same_position() {
    let output = redact(
        &[b"abcde"],
        vec![
            secret("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "short", b"abcd"),
            secret("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "long", b"abcde"),
        ],
    );

    assert_eq!(
        output.text,
        "[REDACTED:dddddddd-dddd-4ddd-8ddd-dddddddddddd.long]"
    );
    assert_eq!(output.redaction_count, 1);
}

#[test]
fn suppresses_all_output_when_any_injected_value_is_short() {
    let output = redact(
        &[b"otherwise harmless output"],
        vec![secret(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "pin",
            b"abc",
        )],
    );

    assert!(output.suppressed);
    assert!(output.text.is_empty());
}

#[test]
fn escapes_invalid_utf8_only_after_redaction() {
    let output = redact(
        &[b"ok:\xff secret=fake-secret"],
        vec![secret(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "value",
            b"fake-secret",
        )],
    );

    assert_eq!(
        output.text,
        "ok:\\xff secret=[REDACTED:ffffffff-ffff-4fff-8fff-ffffffffffff.value]"
    );
}

#[test]
fn bounds_rendered_output_and_retains_head_and_tail() {
    let mut redactor = StreamingRedactor::new(vec![], 128).unwrap();
    redactor.push(&vec![b'h'; 300]);
    redactor.push(b"TAIL");

    let output = redactor.finish();

    assert!(output.truncated);
    assert!(output.omitted_bytes > 0);
    assert!(output.text.len() <= 128);
    assert!(output.text.starts_with("hhhh"));
    assert!(output.text.ends_with("TAIL"));
}

proptest! {
    #[test]
    fn arbitrary_binary_secrets_never_survive_chunked_output(
        value in prop::collection::vec(any::<u8>(), 4..64),
        prefix in prop::collection::vec(any::<u8>(), 0..64),
        suffix in prop::collection::vec(any::<u8>(), 0..64),
        chunk_size in 1_usize..32,
    ) {
        let mut input = prefix;
        input.extend_from_slice(&value);
        input.extend_from_slice(&suffix);
        let mut redactor = StreamingRedactor::new(
            vec![secret(
                "99999999-9999-4999-8999-999999999999",
                "value",
                &value,
            )],
            256,
        ).unwrap();
        for chunk in input.chunks(chunk_size) {
            redactor.push(chunk);
        }

        let output = redactor.finish();

        prop_assert!(output.redaction_count >= 1);
        prop_assert!(output.text.len() <= 256);
        if let Ok(text) = std::str::from_utf8(&value) {
            prop_assert!(!output.text.contains(text));
        }
    }
}
