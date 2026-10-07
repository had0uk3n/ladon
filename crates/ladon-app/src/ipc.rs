use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use ladon_core::{
    LadonError, MAX_FRAME_BYTES, RpcMethod, RpcRequest, RpcResponse, RpcResult,
    decode_request_frame, decode_response_frame, encode_request_frame, encode_response_frame,
};

use crate::RunCancellation;

#[derive(Debug)]
pub struct LocalServer {
    listener: UnixListener,
    path: PathBuf,
}

pub(crate) struct LocalConnection {
    stream: UnixStream,
}

impl LocalServer {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self, LadonError> {
        let path = path.as_ref();
        prepare_parent(path)?;
        recover_stale_endpoint(path)?;
        let listener = UnixListener::bind(path).map_err(|error| {
            if error.kind() == io::ErrorKind::AddrInUse {
                LadonError::AlreadyRunning
            } else {
                LadonError::EndpointUnavailable
            }
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| LadonError::EndpointUnavailable)?;
        validate_endpoint(path)?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
        })
    }

    pub fn serve_once(
        &self,
        handler: impl FnOnce(RpcRequest) -> RpcResponse,
    ) -> Result<(), LadonError> {
        let (mut stream, _) = self
            .listener
            .accept()
            .map_err(|_| LadonError::EndpointUnavailable)?;
        configure_stream(&stream)?;
        verify_peer(stream.as_raw_fd())?;
        let frame = read_frame(&mut stream)?;
        let request = decode_request_frame(&frame)?;
        let response = handler(request);
        let frame = encode_response_frame(&response)?;
        stream
            .write_all(&frame)
            .map_err(|_| LadonError::EndpointUnavailable)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), LadonError> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|_| LadonError::EndpointUnavailable)
    }

    pub fn try_serve_once(
        &self,
        handler: impl FnOnce(RpcRequest) -> RpcResponse,
    ) -> Result<bool, LadonError> {
        let (mut stream, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Err(LadonError::EndpointUnavailable),
        };
        configure_stream(&stream)?;
        verify_peer(stream.as_raw_fd())?;
        let frame = read_frame(&mut stream)?;
        let request = decode_request_frame(&frame)?;
        let response = handler(request);
        let frame = encode_response_frame(&response)?;
        stream
            .write_all(&frame)
            .map_err(|_| LadonError::EndpointUnavailable)?;
        Ok(true)
    }

    pub(crate) fn try_accept(&self) -> Result<Option<LocalConnection>, LadonError> {
        let (stream, _) = match self.listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(_) => return Err(LadonError::EndpointUnavailable),
        };
        configure_stream(&stream)?;
        verify_peer(stream.as_raw_fd())?;
        Ok(Some(LocalConnection { stream }))
    }
}

impl LocalConnection {
    pub(crate) fn serve(
        mut self,
        handler: impl FnOnce(RpcRequest, RunCancellation) -> RpcResponse,
    ) -> Result<(), LadonError> {
        let frame = read_frame(&mut self.stream)?;
        let request = decode_request_frame(&frame)?;
        let cancellation = RunCancellation::new();
        let monitor_cancellation = cancellation.clone();
        let monitor_stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&monitor_stop);
        let mut monitor_stream = self
            .stream
            .try_clone()
            .map_err(|_| LadonError::EndpointUnavailable)?;
        monitor_stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|_| LadonError::EndpointUnavailable)?;
        let monitor = thread::spawn(move || {
            let mut byte = [0_u8; 1];
            while !worker_stop.load(Ordering::Acquire) {
                match monitor_stream.read(&mut byte) {
                    Ok(0) | Ok(_) => {
                        monitor_cancellation.cancel();
                        break;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        monitor_cancellation.cancel();
                        break;
                    }
                }
            }
        });
        let is_session_open = matches!(request.method, RpcMethod::SessionOpen);
        let response = handler(request, cancellation.clone());
        let session_opened =
            is_session_open && response.result() == Some(&RpcResult::SessionOpened);
        let write_result = encode_response_frame(&response).and_then(|frame| {
            self.stream
                .write_all(&frame)
                .map_err(|_| LadonError::EndpointUnavailable)
        });
        if is_session_open {
            if session_opened && write_result.is_ok() {
                while !cancellation.is_cancelled() {
                    thread::sleep(Duration::from_millis(20));
                }
            } else {
                cancellation.cancel();
            }
        }
        monitor_stop.store(true, Ordering::Release);
        let _ = monitor.join();
        write_result
    }
}

fn configure_stream(stream: &UnixStream) -> Result<(), LadonError> {
    let timeout = Some(Duration::from_secs(5));
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(timeout))
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|_| LadonError::EndpointUnavailable)
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        if validate_endpoint(&self.path).is_ok() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalClient {
    path: PathBuf,
}

/// Keeps the authenticated session connection open until this guard is dropped.
#[derive(Debug)]
pub struct LocalSession {
    _stream: UnixStream,
}

impl LocalSession {
    /// Checks the dedicated session socket without consuming bytes or blocking.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        let mut byte = [0_u8; 1];
        // SAFETY: the stream owns an open fd and byte is writable for its full length.
        // MSG_DONTWAIT avoids changing socket-wide flags or blocking this health check.
        let received = unsafe {
            libc::recv(
                self._stream.as_raw_fd(),
                byte.as_mut_ptr().cast(),
                byte.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        received < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock
    }
}

#[must_use]
pub fn default_endpoint_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        if runtime.is_absolute() {
            return runtime.join("ladon").join("broker.sock");
        }
    }
    std::env::temp_dir()
        .join(format!("ladon-{}", effective_uid()))
        .join("broker.sock")
}

impl LocalClient {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn open_session(&self, request: &RpcRequest) -> Result<LocalSession, LadonError> {
        if !matches!(request.method, RpcMethod::SessionOpen) {
            return Err(LadonError::InvalidRequest);
        }
        let (stream, response) = self.exchange(request)?;
        if response.request_id != request.request_id {
            return Err(LadonError::InvalidRequest);
        }
        if let Some((code, _)) = response.error_details() {
            return Err(LadonError::from_code(code).unwrap_or(LadonError::InvalidRequest));
        }
        if response.result() != Some(&RpcResult::SessionOpened) {
            return Err(LadonError::InvalidRequest);
        }
        Ok(LocalSession { _stream: stream })
    }

    pub fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        self.exchange(request).map(|(_, response)| response)
    }

    fn exchange(&self, request: &RpcRequest) -> Result<(UnixStream, RpcResponse), LadonError> {
        validate_endpoint(&self.path)?;
        let mut stream =
            UnixStream::connect(&self.path).map_err(|_| LadonError::EndpointUnavailable)?;
        verify_peer(stream.as_raw_fd())?;
        let frame = encode_request_frame(request)?;
        stream
            .write_all(&frame)
            .map_err(|_| LadonError::EndpointUnavailable)?;
        let response = read_frame(&mut stream)?;
        Ok((stream, decode_response_frame(&response)?))
    }
}

fn prepare_parent(path: &Path) -> Result<(), LadonError> {
    let parent = path.parent().ok_or(LadonError::UnsafeEndpoint)?;
    let existed = parent.exists();
    fs::create_dir_all(parent).map_err(|_| LadonError::EndpointUnavailable)?;
    if !existed {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| LadonError::EndpointUnavailable)?;
    }
    let metadata = fs::symlink_metadata(parent).map_err(|_| LadonError::UnsafeEndpoint)?;
    if !metadata.is_dir()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LadonError::UnsafeEndpoint);
    }
    Ok(())
}

fn recover_stale_endpoint(path: &Path) -> Result<(), LadonError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() || metadata.uid() != effective_uid() {
        return Err(LadonError::UnsafeEndpoint);
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(LadonError::AlreadyRunning),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            fs::remove_file(path).map_err(|_| LadonError::EndpointUnavailable)
        }
        Err(_) => Err(LadonError::EndpointUnavailable),
    }
}

fn validate_endpoint(path: &Path) -> Result<(), LadonError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LadonError::EndpointUnavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LadonError::UnsafeEndpoint);
    }
    Ok(())
}

fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, LadonError> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| LadonError::InvalidFrame)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(LadonError::InvalidFrame);
    }
    if length > MAX_FRAME_BYTES {
        return Err(LadonError::FrameTooLarge);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    reader
        .read_exact(&mut frame[4..])
        .map_err(|_| LadonError::InvalidFrame)?;
    Ok(frame)
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and no side effects.
    unsafe { libc::geteuid() }
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn peer_uid(fd: RawFd) -> Result<u32, LadonError> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: uid/gid point to initialized storage and fd is an open Unix socket.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } == 0 {
        Ok(uid)
    } else {
        Err(LadonError::InvalidPeer)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(fd: RawFd) -> Result<u32, LadonError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials and length are valid writable buffers for getsockopt.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut length,
        )
    };
    if result == 0 && length as usize == std::mem::size_of::<libc::ucred>() {
        Ok(credentials.uid)
    } else {
        Err(LadonError::InvalidPeer)
    }
}

fn verify_peer(fd: RawFd) -> Result<(), LadonError> {
    if peer_uid(fd)? == effective_uid() {
        Ok(())
    } else {
        Err(LadonError::InvalidPeer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ladon_core::{PROTOCOL_VERSION, RpcMethod, RpcResult};
    use std::sync::mpsc;
    use uuid::Uuid;

    #[test]
    fn session_socket_remains_open_until_guard_disconnects() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let request = RpcRequest {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            client_session_id: Uuid::new_v4(),
            client_label: "MCP lifetime".to_owned(),
            method: RpcMethod::SessionOpen,
        };
        let (token_tx, token_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = LocalConnection { stream: server }.serve(|request, cancellation| {
                token_tx.send(cancellation).unwrap();
                RpcResponse::success(request.request_id, RpcResult::SessionOpened)
            });
            finished_tx.send(result).unwrap();
        });
        client
            .write_all(&encode_request_frame(&request).unwrap())
            .unwrap();
        let response = decode_response_frame(&read_frame(&mut client).unwrap()).unwrap();
        assert_eq!(response.result(), Some(&RpcResult::SessionOpened));
        let cancellation = token_rx.recv().unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(150))
                .is_err()
        );
        assert!(!cancellation.is_cancelled());
        drop(client);
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert!(cancellation.is_cancelled());
        worker.join().unwrap();
    }

    #[test]
    fn cancelling_session_token_releases_worker_with_client_still_connected() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let request = RpcRequest {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            client_session_id: Uuid::new_v4(),
            client_label: "MCP lifetime".to_owned(),
            method: RpcMethod::SessionOpen,
        };
        let (token_tx, token_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = LocalConnection { stream: server }.serve(|request, cancellation| {
                token_tx.send(cancellation).unwrap();
                RpcResponse::success(request.request_id, RpcResult::SessionOpened)
            });
            finished_tx.send(result).unwrap();
        });
        client
            .write_all(&encode_request_frame(&request).unwrap())
            .unwrap();
        read_frame(&mut client).unwrap();
        token_rx.recv().unwrap().cancel();
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        drop(client);
    }

    #[test]
    fn session_health_check_is_nonblocking_and_detects_peer_eof() {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let session = LocalSession { _stream: client };
        let started = std::time::Instant::now();
        assert!(session.is_connected());
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(server);
        assert!(!session.is_connected());
    }

    #[test]
    fn session_health_check_rejects_unexpected_incoming_bytes() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let session = LocalSession { _stream: client };
        server.write_all(b"unexpected").unwrap();
        assert!(!session.is_connected());
    }
}
