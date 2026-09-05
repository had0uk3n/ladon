#![cfg(unix)]

use std::{
    fs,
    io::Write,
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    thread,
};

use ladon_app::{LocalClient, LocalServer};
use ladon_core::{LadonError, MAX_FRAME_BYTES, RpcMethod, RpcRequest, RpcResponse, RpcResult};
use tempfile::tempdir;
use uuid::Uuid;

fn request() -> RpcRequest {
    RpcRequest {
        version: 2,
        request_id: Uuid::new_v4(),
        client_session_id: Uuid::new_v4(),
        client_label: "test-client".to_owned(),
        method: RpcMethod::Status,
    }
}

fn socket_path(root: &tempfile::TempDir) -> std::path::PathBuf {
    root.path().join("runtime").join("broker.sock")
}

#[test]
fn creates_owner_only_runtime_directory_and_socket() {
    let root = tempdir().unwrap();
    let runtime = root.path().join("runtime");
    let socket = socket_path(&root);

    let server = LocalServer::bind(&socket).unwrap();

    assert_eq!(
        fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(server);
    assert!(!socket.exists());
}

#[test]
fn round_trips_one_bounded_request_and_response() {
    let root = tempdir().unwrap();
    let socket = socket_path(&root);
    let server = LocalServer::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        server
            .serve_once(|request| {
                RpcResponse::success(
                    request.request_id,
                    RpcResult::Status {
                        state: "locked".to_owned(),
                        idle_remaining_ms: None,
                    },
                )
            })
            .unwrap();
    });

    let response = LocalClient::new(&socket).call(&request()).unwrap();

    assert!(matches!(
        response.result(),
        Some(RpcResult::Status { state, .. }) if state == "locked"
    ));
    worker.join().unwrap();
}

#[test]
fn refuses_a_live_second_instance_but_recovers_a_stale_socket() {
    let root = tempdir().unwrap();
    let socket = socket_path(&root);
    let first = LocalServer::bind(&socket).unwrap();
    assert_eq!(
        LocalServer::bind(&socket).unwrap_err(),
        LadonError::AlreadyRunning
    );
    drop(first);

    let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    drop(stale);
    assert!(socket.exists());
    let recovered = LocalServer::bind(&socket).unwrap();
    drop(recovered);
}

#[test]
fn never_removes_a_non_socket_collision() {
    let root = tempdir().unwrap();
    let socket = socket_path(&root);
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    fs::set_permissions(socket.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&socket, b"keep me").unwrap();

    assert_eq!(
        LocalServer::bind(&socket).unwrap_err(),
        LadonError::UnsafeEndpoint
    );
    assert_eq!(fs::read(&socket).unwrap(), b"keep me");
}

#[test]
fn rejects_partial_and_oversized_frames_before_allocating_payloads() {
    let root = tempdir().unwrap();
    let socket = socket_path(&root);
    let server = LocalServer::bind(&socket).unwrap();
    let worker = thread::spawn(move || server.serve_once(|_| unreachable!()));
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream.write_all(&[0, 0]).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        worker.join().unwrap().unwrap_err(),
        LadonError::InvalidFrame
    );
    drop(stream);

    let server = LocalServer::bind(&socket).unwrap();
    let worker = thread::spawn(move || server.serve_once(|_| unreachable!()));
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .unwrap();
    assert_eq!(
        worker.join().unwrap().unwrap_err(),
        LadonError::FrameTooLarge
    );
    drop(stream);
}
