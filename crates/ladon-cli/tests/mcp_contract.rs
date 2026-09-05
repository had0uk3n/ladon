use std::cell::RefCell;

use ladon::{RpcTransport, serve_mcp};
use ladon_core::{RpcMethod, RpcRequest, RpcResponse, RpcResult};

struct FakeTransport {
    seen: RefCell<Vec<RpcRequest>>,
}

impl FakeTransport {
    fn new() -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl RpcTransport for FakeTransport {
    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, ladon_core::LadonError> {
        self.seen.borrow_mut().push(request.clone());
        let result = match request.method {
            RpcMethod::List => RpcResult::List { secrets: vec![] },
            _ => RpcResult::Status {
                state: "locked".to_owned(),
                idle_remaining_ms: None,
            },
        };
        Ok(RpcResponse::success(request.request_id, result))
    }
}

#[test]
fn exposes_only_status_list_lock_and_generic_run_tools() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("ladon_status"));
    assert!(output.contains("ladon_list_secrets"));
    assert!(output.contains("ladon_lock"));
    assert!(output.contains("ladon_run"));
    assert!(!output.contains("ladon_reveal"));
    assert!(!output.contains("ladon_add"));
}

#[test]
fn mcp_caps_run_timeout_and_never_accepts_plaintext_values() {
    let transport = FakeTransport::new();
    let executable = std::env::current_exe().unwrap();
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "ladon_run",
            "arguments": {
                "executable": executable,
                "arguments": [],
                "working_directory": std::env::temp_dir(),
                "timeout_seconds": 901,
                "bindings": [{
                    "secret_ref": "example",
                    "field": "value",
                    "target": "environment",
                    "name": "TOKEN"
                }]
            }
        }
    });
    let input = format!("{request}\n");
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("invalid_timeout"));
    assert!(!output.contains("fake-plaintext-value"));
    assert!(transport.seen.borrow().is_empty());
}

#[test]
fn list_tool_returns_metadata_only() {
    let transport = FakeTransport::new();
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_list_secrets\",\"arguments\":{}}}\n";
    let mut output = Vec::new();

    serve_mcp(input.as_slice(), &mut output, &transport).unwrap();

    let output = String::from_utf8(output).unwrap();
    assert!(!output.contains("fake-plaintext-value"));
    assert!(matches!(transport.seen.borrow()[0].method, RpcMethod::List));
}

#[test]
fn one_mcp_process_reuses_one_private_client_session_id() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_list_secrets\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].version, 2);
    assert_eq!(seen[0].client_session_id, seen[1].client_session_id);
    let rendered = String::from_utf8(output).unwrap();
    assert!(!rendered.contains(&seen[0].client_session_id.to_string()));
}

#[test]
fn a_new_mcp_process_gets_a_different_client_session_id() {
    let first = FakeTransport::new();
    let second = FakeTransport::new();
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n";

    serve_mcp(input.as_slice(), &mut Vec::new(), &first).unwrap();
    serve_mcp(input.as_slice(), &mut Vec::new(), &second).unwrap();

    assert_ne!(
        first.seen.borrow()[0].client_session_id,
        second.seen.borrow()[0].client_session_id
    );
}
