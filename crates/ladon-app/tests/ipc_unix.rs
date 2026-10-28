#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    thread,
};

use ladon_app::{LocalClient, LocalServer};
use ladon_core::{
    LadonError, MAX_FRAME_BYTES, RpcMethod, RpcRequest, RpcResponse, RpcResult,
    decode_response_frame,
};
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

// @covers crates/ladon-app/src/ipc.rs::LocalServer::serve_once
// @covers crates/ladon-app/src/ipc.rs::read_frame
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
        LadonError::IpcDisconnected
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

// @covers crates/ladon-app/src/ipc.rs::LocalServer::serve_once
// @covers crates/ladon-app/src/ipc.rs::LocalServer::try_serve_once
// @covers crates/ladon-core/src/protocol.rs::request_error_response
#[test]
fn both_server_entry_points_reply_to_rejected_versions_without_dispatch() {
    for nonblocking in [false, true] {
        let root = tempdir().unwrap();
        let socket = socket_path(&root);
        let server = LocalServer::bind(&socket).unwrap();
        let mut stream = UnixStream::connect(&socket).unwrap();
        let worker = thread::spawn(move || {
            if nonblocking {
                server
                    .try_serve_once(|_| panic!("unsupported request dispatched"))
                    .map(|_| ())
            } else {
                server.serve_once(|_| panic!("unsupported request dispatched"))
            }
        });
        let id = Uuid::new_v4();
        let payload = format!(
            r#"{{"version":65535,"request_id":"{id}","client_session_id":"{id}","client_label":"fixture","method":"status"}}"#
        );
        stream
            .write_all(&(payload.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(payload.as_bytes()).unwrap();
        let mut frame = Vec::new();
        stream.read_to_end(&mut frame).unwrap();
        assert_eq!(
            worker.join().unwrap(),
            Err(LadonError::UnsupportedProtocolVersion)
        );
        let response = decode_response_frame(&frame).unwrap();
        assert_eq!(response.request_id, id);
        assert_eq!(
            response.error_details().unwrap().0,
            "unsupported_protocol_version"
        );
    }
}

#[test]
fn local_session_guard_keeps_authenticated_socket_open_until_drop() {
    use std::io::Read;
    use std::sync::mpsc;
    use std::time::Duration;

    let root = tempdir().unwrap();
    let socket = socket_path(&root);
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    fs::set_permissions(socket.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let server = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let (finished_tx, finished_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        let mut header = [0_u8; 4];
        stream.read_exact(&mut header).unwrap();
        let mut frame = header.to_vec();
        frame.resize(4 + u32::from_be_bytes(header) as usize, 0);
        stream.read_exact(&mut frame[4..]).unwrap();
        let request = ladon_core::decode_request_frame(&frame).unwrap();
        assert_eq!(request.method, RpcMethod::SessionOpen);
        let response = RpcResponse::success(request.request_id, RpcResult::SessionOpened);
        stream
            .write_all(&ladon_core::encode_response_frame(&response).unwrap())
            .unwrap();
        assert_eq!(stream.read(&mut [0_u8; 1]).unwrap(), 0);
        finished_tx.send(()).unwrap();
    });
    let mut registration = request();
    registration.method = RpcMethod::SessionOpen;
    let guard = LocalClient::new(&socket)
        .open_session(&registration)
        .unwrap();
    assert!(
        finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err()
    );
    drop(guard);
    finished_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
}

// @covers crates/ladon-app/src/ipc.rs::LocalClient::open_session
// @covers crates/ladon-app/src/ipc.rs::LocalClient::exchange
#[test]
fn local_session_rejects_wrong_method_response_or_request_id() {
    let root = tempdir().unwrap();
    let socket = socket_path(&root);
    assert_eq!(
        LocalClient::new(&socket)
            .open_session(&request())
            .unwrap_err(),
        LadonError::InvalidRequest
    );
    for mismatched_id in [false, true] {
        let server = LocalServer::bind(&socket).unwrap();
        let worker = thread::spawn(move || {
            server
                .serve_once(|request| {
                    if mismatched_id {
                        RpcResponse::success(Uuid::new_v4(), RpcResult::SessionOpened)
                    } else {
                        RpcResponse::success(request.request_id, RpcResult::Locked)
                    }
                })
                .unwrap()
        });
        let mut registration = request();
        registration.method = RpcMethod::SessionOpen;
        assert_eq!(
            LocalClient::new(&socket)
                .open_session(&registration)
                .unwrap_err(),
            LadonError::InvalidResponse
        );
        worker.join().unwrap();
    }
}
