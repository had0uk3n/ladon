use ladon_core::{
    BindingTarget, LadonError, RpcMethod, RpcRequest, RpcResponse, RpcResult, SecretBindingRequest,
    SecretFieldSummary, SecretSummary, decode_request_frame, encode_request_frame,
    encode_response_frame,
};
use uuid::Uuid;

fn status_request() -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: Uuid::parse_str("018f6f65-1f16-7c5a-9b52-6cf413b9db65").unwrap(),
        client_label: "Codex".to_owned(),
        method: RpcMethod::Status,
    }
}

#[test]
fn responses_echo_request_id_without_a_plaintext_value_shape() {
    let request_id = Uuid::parse_str("018f6f65-1f16-7c5a-9b52-6cf413b9db65").unwrap();
    let response = RpcResponse::success(
        request_id,
        RpcResult::List {
            secrets: vec![SecretSummary {
                id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                name: "example".to_owned(),
                fields: vec![SecretFieldSummary {
                    name: "value".to_owned(),
                    text: true,
                }],
            }],
        },
    );

    let frame = encode_response_frame(&response).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();

    assert_eq!(json["request_id"], request_id.to_string());
    assert_eq!(json["result"]["type"], "list");
    let serialized = serde_json::to_string(&json).unwrap();
    assert!(!serialized.contains("fake-test-value"));
    assert!(!serialized.contains("\"value\":"));
}

#[test]
fn error_responses_are_stable_and_redacted() {
    let request_id = Uuid::parse_str("018f6f65-1f16-7c5a-9b52-6cf413b9db65").unwrap();
    let response = RpcResponse::error(request_id, LadonError::VaultAuthenticationFailed);

    let frame = encode_response_frame(&response).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&frame[4..]).unwrap();

    assert_eq!(json["error"]["code"], "vault_authentication_failed");
    assert_eq!(json["error"]["message"], "vault authentication failed");
}

fn framed(json: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&(json.len() as u32).to_be_bytes());
    frame.extend_from_slice(json);
    frame
}

#[test]
fn request_round_trip_has_version_uuid_label_method_and_typed_params() {
    let request = RpcRequest {
        method: RpcMethod::Run {
            executable: "/usr/bin/env".to_owned(),
            arguments: vec!["--help".to_owned()],
            working_directory: "/tmp".to_owned(),
            bindings: vec![SecretBindingRequest {
                secret_ref: "example".to_owned(),
                field: "value".to_owned(),
                target: BindingTarget::Environment {
                    name: "EXAMPLE_TOKEN".to_owned(),
                },
            }],
            timeout_ms: 300_000,
            output_limit_bytes: 524_288,
        },
        ..status_request()
    };

    let decoded = decode_request_frame(&encode_request_frame(&request).unwrap()).unwrap();

    assert_eq!(decoded, request);
}

#[test]
fn rejects_zero_partial_oversized_and_trailing_frames() {
    assert_eq!(
        decode_request_frame(&0_u32.to_be_bytes()).unwrap_err(),
        LadonError::InvalidFrame
    );
    assert_eq!(
        decode_request_frame(&[0, 0, 0, 8, b'{', b'}']).unwrap_err(),
        LadonError::InvalidFrame
    );
    assert_eq!(
        decode_request_frame(&(4_u32 * 1024 * 1024 + 1).to_be_bytes()).unwrap_err(),
        LadonError::FrameTooLarge
    );

    let mut valid = encode_request_frame(&status_request()).unwrap();
    valid.push(0);
    assert_eq!(
        decode_request_frame(&valid).unwrap_err(),
        LadonError::InvalidFrame
    );
}

#[test]
fn rejects_duplicate_keys_unknown_methods_and_incompatible_versions() {
    let duplicate = br#"{"version":1,"version":1,"request_id":"018f6f65-1f16-7c5a-9b52-6cf413b9db65","client_label":"Codex","method":"status","params":{}}"#;
    assert_eq!(
        decode_request_frame(&framed(duplicate)).unwrap_err(),
        LadonError::InvalidRequest
    );

    let unknown = br#"{"version":1,"request_id":"018f6f65-1f16-7c5a-9b52-6cf413b9db65","client_label":"Codex","method":"reveal","params":{}}"#;
    assert_eq!(
        decode_request_frame(&framed(unknown)).unwrap_err(),
        LadonError::InvalidRequest
    );

    let mut incompatible = status_request();
    incompatible.version = 2;
    assert_eq!(
        decode_request_frame(&encode_request_frame(&incompatible).unwrap()).unwrap_err(),
        LadonError::UnsupportedProtocolVersion
    );
}

#[test]
fn rejects_excessive_nesting_and_client_labels() {
    let nested_value = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    let nested = format!(
        "{{\"version\":1,\"request_id\":\"018f6f65-1f16-7c5a-9b52-6cf413b9db65\",\"client_label\":\"Codex\",\"method\":\"status\",\"params\":{{\"nested\":{nested_value}}}}}"
    );
    assert_eq!(
        decode_request_frame(&framed(nested.as_bytes())).unwrap_err(),
        LadonError::InvalidRequest
    );

    let mut long_label = status_request();
    long_label.client_label = "x".repeat(65);
    assert_eq!(
        decode_request_frame(&encode_request_frame(&long_label).unwrap()).unwrap_err(),
        LadonError::InvalidRequest
    );
}
