use std::cell::RefCell;

use ladon::{RpcSessionLease, RpcTransport, serve_mcp};
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
fn exposes_ladon_tools_without_secret_or_session_identifier_leaks() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("ladon_status"));
    assert!(output.contains("ladon_list_secrets"));
    assert!(output.contains("ladon_lock"));
    assert!(output.contains("ladon_run"));
    assert!(output.contains("ladon_identify_session"));
    assert!(!output.contains("ladon_reveal"));
    assert!(!output.contains("ladon_add"));
    assert!(!output.contains("fake-plaintext-value"));
    assert!(!output.contains(&transport.seen.borrow()[0].client_session_id.to_string()));
}

#[test]
fn identify_session_changes_the_reported_label_without_exposing_the_private_id() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"Codex\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_identify_session\",\"arguments\":{\"display_name\":\"Codex — deploy payments\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    let seen = transport.seen.borrow();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].client_label, "Codex — deploy payments");
    assert!(
        !String::from_utf8(output)
            .unwrap()
            .contains(&seen[0].client_session_id.to_string())
    );
}

#[test]
fn invalid_identification_preserves_the_initialized_client_name() {
    let transport = FakeTransport::new();
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"Codex\",\"version\":\"1\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_identify_session\",\"arguments\":{\"display_name\":\"bad\\nname\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n",
    );
    let mut output = Vec::new();

    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();

    assert_eq!(transport.seen.borrow()[0].client_label, "Codex");
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("invalid_request")
    );
}

#[test]
fn absent_identification_uses_the_mcp_client_fallback() {
    let transport = FakeTransport::new();
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\",\"arguments\":{}}}\n";

    serve_mcp(input.as_slice(), &mut Vec::new(), &transport).unwrap();

    assert_eq!(transport.seen.borrow()[0].client_label, "MCP client");
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

struct SessionGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl RpcSessionLease for SessionGuard {
    fn is_connected(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

struct LifetimeTransport {
    active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    opened: RefCell<Vec<uuid::Uuid>>,
    fail_open: bool,
    calls: std::cell::Cell<usize>,
    disconnect_after_call: bool,
    fail_reopen: bool,
}

impl LifetimeTransport {
    fn new(fail_open: bool) -> Self {
        Self {
            active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            opened: RefCell::new(Vec::new()),
            fail_open,
            calls: std::cell::Cell::new(0),
            disconnect_after_call: false,
            fail_reopen: false,
        }
    }
}

impl RpcTransport for LifetimeTransport {
    fn open_session(
        &self,
        id: uuid::Uuid,
        _: &str,
    ) -> Result<Box<dyn RpcSessionLease>, ladon_core::LadonError> {
        if self.fail_open || (self.fail_reopen && !self.opened.borrow().is_empty()) {
            return Err(ladon_core::LadonError::EndpointUnavailable);
        }
        self.opened.borrow_mut().push(id);
        self.active.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(SessionGuard(self.active.clone())))
    }

    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, ladon_core::LadonError> {
        if matches!(request.method, RpcMethod::List | RpcMethod::Run { .. }) {
            assert!(self.active.load(std::sync::atomic::Ordering::SeqCst));
        }
        assert!(
            self.opened
                .borrow()
                .iter()
                .all(|id| *id == request.client_session_id)
        );
        self.calls.set(self.calls.get() + 1);
        if self.disconnect_after_call {
            self.active
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(RpcResponse::success(request.request_id, RpcResult::Locked))
    }
}

const LIST_CALL: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_list_secrets\"}}\n";

#[test]
fn lifetime_registration_is_lazy_and_held_across_calls_until_mcp_eof() {
    let transport = LifetimeTransport::new(false);
    let local_messages = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_identify_session\",\"arguments\":{\"display_name\":\"test\"}}}\n"
    );
    serve_mcp(local_messages.as_bytes(), &mut Vec::new(), &transport).unwrap();
    assert!(transport.opened.borrow().is_empty());

    serve_mcp(
        format!("{LIST_CALL}{LIST_CALL}").as_bytes(),
        &mut Vec::new(),
        &transport,
    )
    .unwrap();
    assert_eq!(transport.opened.borrow().len(), 1);
    assert_eq!(transport.calls.get(), 2);
    assert!(!transport.active.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn registration_failure_prevents_the_tool_rpc() {
    let transport = LifetimeTransport::new(true);
    let mut output = Vec::new();
    serve_mcp(LIST_CALL.as_bytes(), &mut output, &transport).unwrap();
    assert_eq!(transport.calls.get(), 0);
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("endpoint_unavailable")
    );
}

#[test]
fn mcp_output_error_drops_the_lifetime_connection() {
    struct BrokenOutput;
    impl std::io::Write for BrokenOutput {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let transport = LifetimeTransport::new(false);
    assert!(serve_mcp(LIST_CALL.as_bytes(), &mut BrokenOutput, &transport).is_err());
    assert_eq!(transport.calls.get(), 1);
    assert!(!transport.active.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn one_shot_cli_holds_registration_through_the_rpc_and_drops_it_afterward() {
    let transport = LifetimeTransport::new(false);
    let exit = ladon::execute_cli(
        ["ladon".into(), "list".into()],
        &transport,
        &mut Vec::new(),
        &mut Vec::new(),
    );
    assert_eq!(exit, 0);
    assert_eq!(transport.calls.get(), 1);
    assert!(!transport.active.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn one_shot_cli_fails_closed_when_lifetime_registration_fails() {
    let transport = LifetimeTransport::new(true);
    let mut stderr = Vec::new();
    let exit = ladon::execute_cli(
        ["ladon".into(), "list".into()],
        &transport,
        &mut Vec::new(),
        &mut stderr,
    );
    assert_ne!(exit, 0);
    assert_eq!(transport.calls.get(), 0);
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("endpoint_unavailable")
    );
}

#[test]
fn disconnected_lifetime_lease_is_reacquired_before_the_next_mcp_rpc() {
    let mut transport = LifetimeTransport::new(false);
    transport.disconnect_after_call = true;
    serve_mcp(
        format!("{LIST_CALL}{LIST_CALL}").as_bytes(),
        &mut Vec::new(),
        &transport,
    )
    .unwrap();
    assert_eq!(transport.calls.get(), 2);
    let opened = transport.opened.borrow();
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0], opened[1]);
    assert!(!transport.active.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn disconnected_lifetime_lease_fails_closed_when_broker_is_unavailable() {
    let mut transport = LifetimeTransport::new(false);
    transport.disconnect_after_call = true;
    transport.fail_reopen = true;
    let mut output = Vec::new();
    serve_mcp(
        format!("{LIST_CALL}{LIST_CALL}").as_bytes(),
        &mut output,
        &transport,
    )
    .unwrap();
    assert_eq!(transport.calls.get(), 1);
    assert_eq!(transport.opened.borrow().len(), 1);
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("endpoint_unavailable")
    );
}

#[test]
fn status_and_lock_remain_available_when_lifecycle_registration_is_unavailable() {
    let transport = LifetimeTransport::new(true);
    for command in ["status", "lock"] {
        assert_eq!(
            ladon::execute_cli(
                ["ladon".into(), command.into()],
                &transport,
                &mut Vec::new(),
                &mut Vec::new()
            ),
            0
        );
    }
    let mut output = Vec::new();
    serve_mcp(
        concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_status\"}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ladon_lock\"}}\n"
        ).as_bytes(),
        &mut output, &transport
    ).unwrap();
    assert_eq!(transport.calls.get(), 4);
    assert!(transport.opened.borrow().is_empty());
    assert!(
        !String::from_utf8(output)
            .unwrap()
            .contains("endpoint_unavailable")
    );
}
