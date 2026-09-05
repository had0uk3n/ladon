use std::{cell::RefCell, path::Path};

use ladon::{RpcTransport, execute_cli};
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
        Ok(RpcResponse::success(
            request.request_id,
            RpcResult::Run {
                exit_code: Some(0),
                termination: "exited".to_owned(),
                stdout: "ok [REDACTED]".to_owned(),
                stderr: String::new(),
                duration_ms: 10,
                redaction_count: 1,
                output_truncated: false,
                temp_cleanup_warning: false,
            },
        ))
    }
}

#[test]
fn run_sends_only_references_and_an_absolute_executable() {
    let transport = FakeTransport::new();
    let executable = std::env::current_exe().unwrap();
    let arguments = vec![
        "ladon".to_owned(),
        "run".to_owned(),
        "--env".to_owned(),
        "TOKEN=example::value".to_owned(),
        "--".to_owned(),
        executable.to_str().unwrap().to_owned(),
        "--version".to_owned(),
    ];
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = execute_cli(arguments, &transport, &mut stdout, &mut stderr);

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    assert!(
        !String::from_utf8(stdout)
            .unwrap()
            .contains("fake-plaintext-value")
    );
    let requests = transport.seen.borrow();
    let RpcMethod::Run {
        executable,
        bindings,
        ..
    } = &requests[0].method
    else {
        panic!("expected run request");
    };
    assert!(Path::new(executable).is_absolute());
    assert_eq!(bindings[0].secret_ref, "example");
    assert_eq!(bindings[0].field, "value");
}

#[test]
fn cli_rejects_timeouts_above_two_hours_before_ipc() {
    let transport = FakeTransport::new();
    let executable = std::env::current_exe().unwrap();
    let arguments = vec![
        "ladon".to_owned(),
        "run".to_owned(),
        "--timeout-seconds".to_owned(),
        "7201".to_owned(),
        "--".to_owned(),
        executable.to_str().unwrap().to_owned(),
    ];

    let exit = execute_cli(arguments, &transport, &mut Vec::new(), &mut Vec::new());

    assert_ne!(exit, 0);
    assert!(transport.seen.borrow().is_empty());
}

struct LockedTransport;

impl RpcTransport for LockedTransport {
    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, ladon_core::LadonError> {
        Ok(RpcResponse::error(
            request.request_id,
            ladon_core::LadonError::VaultUnavailable,
        ))
    }
}

#[test]
fn cli_preserves_safe_remote_error_codes() {
    let mut stderr = Vec::new();
    let exit = execute_cli(
        ["ladon".to_owned(), "list".to_owned()],
        &LockedTransport,
        &mut Vec::new(),
        &mut stderr,
    );

    assert_ne!(exit, 0);
    assert_eq!(
        String::from_utf8(stderr).unwrap(),
        "vault_unavailable: neither managed vault copy can be opened\n"
    );
}
