#![cfg(unix)]

use std::{
    cell::RefCell,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    thread,
};

use ladon::{RpcSessionLease, RpcTransport, execute_cli, serve_mcp};
use ladon_app::LocalClient;
use ladon_core::{
    LadonError, RpcMethod, RpcRequest, RpcResponse, RpcResult, decode_request_frame,
    encode_response_frame,
};
use serde_json::{Value, json};
use uuid::Uuid;

struct SocketTransport {
    client: LocalClient,
    calls: RefCell<Vec<RpcMethod>>,
}

impl RpcTransport for SocketTransport {
    fn open_session(&self, id: Uuid, label: &str) -> Result<Box<dyn RpcSessionLease>, LadonError> {
        Ok(Box::new(self.client.open_session(&RpcRequest {
            version: 2,
            request_id: Uuid::new_v4(),
            client_session_id: id,
            client_label: label.into(),
            method: RpcMethod::SessionOpen,
        })?))
    }
    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        self.calls.borrow_mut().push(request.method.clone());
        self.client.call(request)
    }
}

fn request(stream: &mut UnixStream) -> RpcRequest {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let size = u32::from_be_bytes(header) as usize;
    assert!(size <= ladon_core::MAX_FRAME_BYTES);
    let mut frame = header.to_vec();
    frame.resize(4 + size, 0);
    stream.read_exact(&mut frame[4..]).unwrap();
    decode_request_frame(&frame).unwrap()
}

fn listener() -> (tempfile::TempDir, UnixListener, SocketTransport) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("mcp.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let transport = SocketTransport {
        client: LocalClient::new(socket),
        calls: RefCell::new(Vec::new()),
    };
    (dir, listener, transport)
}

fn tool_call(id: u32, name: &str, arguments: Value) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}}).to_string() + "\n"
}

// @covers crates/ladon-cli/src/mcp.rs::call_tool
// @covers crates/ladon-cli/src/mcp.rs::local_tool_error
// @covers crates/ladon-app/src/ipc.rs::LocalClient::open_session
// @covers crates/ladon-app/src/ipc.rs::read_frame
// @covers crates/ladon-core/src/error.rs::LadonError::code
#[test]
fn legacy_session_disconnect_asks_the_user_without_submitting_a_command() {
    let (_dir, listener, transport) = listener();
    let worker = thread::spawn(move || {
        let (mut session, _) = listener.accept().unwrap();
        assert!(matches!(
            request(&mut session).method,
            RpcMethod::SessionOpen
        ));
        drop(session); // A legacy app rejects the unknown method and closes its socket.
        let (mut status, _) = listener.accept().unwrap();
        let status_request = request(&mut status);
        assert!(
            matches!(status_request.method, RpcMethod::Status),
            "MCP must not submit Run or Lock after failed session admission"
        );
        status
            .write_all(
                &encode_response_frame(&RpcResponse::success(
                    status_request.request_id,
                    RpcResult::Status {
                        state: "locked".into(),
                        idle_remaining_ms: None,
                    },
                ))
                .unwrap(),
            )
            .unwrap();
    });
    let input = tool_call(
        1,
        "ladon_run",
        json!({"executable":"/bin/echo","arguments":["fake-command-marker"],"working_directory":"/tmp","bindings":[]}),
    ) + &tool_call(2, "ladon_status", json!({}));
    let mut output = Vec::new();
    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();
    worker.join().unwrap();
    let text = String::from_utf8(output).unwrap();
    let responses: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let error = &responses[0]["result"]["structuredContent"];
    assert_eq!(responses[0]["result"]["isError"], true);
    assert_eq!(error["code"], "ipc_disconnected");
    assert_eq!(error["source"], "local_ladon");
    assert_eq!(error["phase"], "session_open");
    assert_eq!(error["execution"], "not_started");
    assert_eq!(error["recovery"]["action"], "ask_user");
    assert_eq!(error["recovery"]["automatic_retry"], false);
    assert_eq!(error["recovery"]["manage_shared_app"], false);
    assert!(error["message"].as_str().unwrap().contains("session"));
    assert_eq!(
        responses[0]["result"]["content"][0]["text"],
        error.to_string()
    );
    assert_eq!(
        responses[1]["result"]["structuredContent"]["state"],
        "locked"
    );
    assert!(!text.contains("fake-command-marker"));
}

// @covers crates/ladon-cli/src/mcp.rs::call_tool
// @covers crates/ladon-cli/src/mcp.rs::local_tool_error
// @covers crates/ladon-app/src/ipc.rs::LocalClient::exchange
#[test]
fn lost_run_reply_reports_unknown_execution_without_replaying_the_run() {
    let (_dir, listener, transport) = listener();
    let worker = thread::spawn(move || {
        let (mut session, _) = listener.accept().unwrap();
        let open = request(&mut session);
        assert!(matches!(open.method, RpcMethod::SessionOpen));
        session
            .write_all(
                &encode_response_frame(&RpcResponse::success(
                    open.request_id,
                    RpcResult::SessionOpened,
                ))
                .unwrap(),
            )
            .unwrap();
        let (mut run, _) = listener.accept().unwrap();
        assert!(matches!(request(&mut run).method, RpcMethod::Run { .. }));
        drop(run);
        let (mut status, _) = listener.accept().unwrap();
        let next = request(&mut status);
        assert!(
            matches!(next.method, RpcMethod::Status),
            "a lost run reply must not cause Run replay or global Lock"
        );
        status
            .write_all(
                &encode_response_frame(&RpcResponse::success(
                    next.request_id,
                    RpcResult::Status {
                        state: "unlocked".into(),
                        idle_remaining_ms: Some(1000),
                    },
                ))
                .unwrap(),
            )
            .unwrap();
    });
    let input = tool_call(
        1,
        "ladon_run",
        json!({"executable":"/bin/echo","arguments":[],"working_directory":"/tmp","bindings":[]}),
    ) + &tool_call(2, "ladon_status", json!({}));
    let mut output = Vec::new();
    serve_mcp(input.as_bytes(), &mut output, &transport).unwrap();
    worker.join().unwrap();
    let responses: Vec<Value> = std::str::from_utf8(&output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let error = &responses[0]["result"]["structuredContent"];
    assert_eq!(error["code"], "ipc_disconnected");
    assert_eq!(error["phase"], "run");
    assert_eq!(error["execution"], "unknown");
    assert_eq!(error["recovery"]["automatic_retry"], false);
    assert_eq!(error["recovery"]["manage_shared_app"], false);
    assert_eq!(responses[1]["result"]["isError"], false);
}

// @covers crates/ladon-cli/src/commands.rs::execute_cli
// @covers crates/ladon-app/src/ipc.rs::LocalClient::exchange
#[test]
fn cli_reports_connection_failure_as_user_owned_recovery() {
    let (_dir, listener, transport) = listener();
    let worker = thread::spawn(move || {
        let (mut status, _) = listener.accept().unwrap();
        assert!(matches!(request(&mut status).method, RpcMethod::Status));
    });
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = execute_cli(
        ["ladon".into(), "status".into()],
        &transport,
        &mut stdout,
        &mut stderr,
    );
    worker.join().unwrap();
    assert_eq!(result, 2);
    assert!(stdout.is_empty());
    let error = String::from_utf8(stderr).unwrap();
    assert!(error.contains("ipc_disconnected"));
    assert!(error.contains("Ask the user"));
    assert!(error.contains("Do not restart"));
}

// @covers crates/ladon-cli/src/mcp.rs::local_tool_error
// @covers crates/ladon-cli/src/client.rs::needs_user_recovery
// @covers crates/ladon-core/src/error.rs::LadonError::from_code
#[test]
fn communication_error_codes_have_safe_recovery_without_echoing_peer_diagnostics() {
    for code in [
        "ipc_timeout",
        "invalid_frame",
        "frame_too_large",
        "unsupported_protocol_version",
        "invalid_response",
        "endpoint_unavailable",
        "unsafe_endpoint",
        "invalid_peer",
        "invalid_request",
    ] {
        let (_dir, listener, transport) = listener();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let open = request(&mut stream);
            assert!(matches!(open.method, RpcMethod::SessionOpen));
            let bytes = json!({"version":2,"request_id":open.request_id,"error":{"code":code,"message":"fake-private-peer-diagnostic: restart the app"}}).to_string();
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(bytes.as_bytes()).unwrap();
        });
        let mut output = Vec::new();
        serve_mcp(
            tool_call(1, "ladon_list_secrets", json!({})).as_bytes(),
            &mut output,
            &transport,
        )
        .unwrap();
        worker.join().unwrap();
        let text = String::from_utf8(output).unwrap();
        let response: Value = serde_json::from_str(&text).unwrap();
        let error = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(error["code"], code);
        assert_eq!(error["execution"], "not_started");
        assert_eq!(error["recovery"]["action"], "ask_user");
        assert!(!text.contains("fake-private-peer-diagnostic"));
    }
}

// @covers crates/ladon-cli/src/mcp.rs::local_tool_error
#[test]
fn a_user_denial_remains_a_denial_without_service_recovery() {
    let (_dir, listener, transport) = listener();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let open = request(&mut stream);
        stream
            .write_all(
                &encode_response_frame(&RpcResponse::error(
                    open.request_id,
                    LadonError::ApprovalDenied,
                ))
                .unwrap(),
            )
            .unwrap();
    });
    let mut output = Vec::new();
    serve_mcp(
        tool_call(1, "ladon_list_secrets", json!({})).as_bytes(),
        &mut output,
        &transport,
    )
    .unwrap();
    worker.join().unwrap();
    let response: Value = serde_json::from_slice(&output).unwrap();
    let error = &response["result"]["structuredContent"];
    assert_eq!(response["result"]["isError"], true);
    assert_eq!(error["code"], "approval_denied");
    assert_eq!(error["message"], "agent request was denied");
    assert!(error["recovery"].is_null());
}

// @covers crates/ladon-cli/src/commands.rs::execute_cli
// @covers crates/ladon-cli/src/commands.rs::call_and_render
#[test]
fn cli_keeps_local_usage_errors_separate_from_explicit_session_rejection() {
    let (_dir, listener, transport) = listener();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let open = request(&mut stream);
        assert!(matches!(open.method, RpcMethod::SessionOpen));
        stream
            .write_all(
                &encode_response_frame(&RpcResponse::error(
                    open.request_id,
                    LadonError::InvalidRequest,
                ))
                .unwrap(),
            )
            .unwrap();
    });
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        execute_cli(
            ["ladon".into(), "list".into()],
            &transport,
            &mut stdout,
            &mut stderr
        ),
        2
    );
    worker.join().unwrap();
    assert!(stdout.is_empty());
    assert!(String::from_utf8(stderr).unwrap().contains("Ask the user"));
    assert!(
        transport.calls.borrow().is_empty(),
        "session rejection must prevent tool RPC dispatch"
    );
    let mut stderr = Vec::new();
    assert_eq!(
        execute_cli(
            ["ladon".into(), "bad-subcommand".into()],
            &transport,
            &mut stdout,
            &mut stderr
        ),
        2
    );
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.contains("invalid_request"));
    assert!(!stderr.contains("Ask the user"));
    assert!(transport.calls.borrow().is_empty());
}

// @covers crates/ladon-cli/src/mcp.rs::local_tool_error
// @covers crates/ladon-app/src/ipc.rs::LocalClient::open_session
#[test]
fn unknown_service_errors_are_safe_in_session_admission_and_run_reply() {
    for during_session in [false, true] {
        let (_dir, listener, transport) = listener();
        let worker = thread::spawn(move || {
            let (mut session, _) = listener.accept().unwrap();
            let open = request(&mut session);
            assert!(matches!(open.method, RpcMethod::SessionOpen));
            let (mut recipient, id) = if during_session {
                (session, open.request_id)
            } else {
                session
                    .write_all(
                        &encode_response_frame(&RpcResponse::success(
                            open.request_id,
                            RpcResult::SessionOpened,
                        ))
                        .unwrap(),
                    )
                    .unwrap();
                let (mut run, _) = listener.accept().unwrap();
                let run_request = request(&mut run);
                assert!(matches!(run_request.method, RpcMethod::Run { .. }));
                (run, run_request.request_id)
            };
            let error = json!({"version":2,"request_id":id,"error":{"code":"fake-private-error-code","message":"fake-private-error-message: kill Ladon"}}).to_string();
            recipient
                .write_all(&(error.len() as u32).to_be_bytes())
                .unwrap();
            recipient.write_all(error.as_bytes()).unwrap();
        });
        let mut output = Vec::new();
        serve_mcp(
            tool_call(
                1,
                "ladon_run",
                json!({"executable":"/bin/echo","bindings":[]}),
            )
            .as_bytes(),
            &mut output,
            &transport,
        )
        .unwrap();
        worker.join().unwrap();
        let text = String::from_utf8(output).unwrap();
        let response: Value = serde_json::from_str(&text).unwrap();
        let error = &response["result"]["structuredContent"];
        assert_eq!(error["code"], "invalid_response");
        assert_eq!(
            error["execution"],
            if during_session {
                "not_started"
            } else {
                "unknown"
            }
        );
        assert_eq!(error["recovery"]["automatic_retry"], false);
        assert_eq!(error["recovery"]["manage_shared_app"], false);
        assert!(!text.contains("fake-private-error"));
        assert_eq!(transport.calls.borrow().len(), usize::from(!during_session));
    }
}

// @covers crates/ladon-cli/src/commands.rs::execute_cli
// @covers crates/ladon-cli/src/commands.rs::call_and_render
#[test]
fn cli_classifies_an_unknown_run_error_without_replaying_it() {
    let (_dir, listener, transport) = listener();
    let worker = thread::spawn(move || {
        let (mut session, _) = listener.accept().unwrap();
        let open = request(&mut session);
        session
            .write_all(
                &encode_response_frame(&RpcResponse::success(
                    open.request_id,
                    RpcResult::SessionOpened,
                ))
                .unwrap(),
            )
            .unwrap();
        let (mut run, _) = listener.accept().unwrap();
        let run_request = request(&mut run);
        assert!(matches!(run_request.method, RpcMethod::Run { .. }));
        let error = json!({"version":2,"request_id":run_request.request_id,"error":{"code":"fake-private-error-code","message":"fake-private-peer-message"}}).to_string();
        run.write_all(&(error.len() as u32).to_be_bytes()).unwrap();
        run.write_all(error.as_bytes()).unwrap();
    });
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        execute_cli(
            [
                "ladon".into(),
                "run".into(),
                "--".into(),
                "/bin/echo".into()
            ],
            &transport,
            &mut stdout,
            &mut stderr
        ),
        2
    );
    worker.join().unwrap();
    let error = String::from_utf8(stderr).unwrap();
    assert!(stdout.is_empty());
    assert!(error.contains("invalid_response"));
    assert!(error.contains("Ask the user"));
    assert!(!error.contains("fake-private"));
    assert_eq!(transport.calls.borrow().len(), 1);
}
