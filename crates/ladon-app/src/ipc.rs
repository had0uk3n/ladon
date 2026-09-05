use std::{
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use ladon_core::{
    LadonError, MAX_FRAME_BYTES, RpcRequest, RpcResponse, decode_request_frame,
    decode_response_frame, encode_request_frame, encode_response_frame,
};

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
        handler: impl FnOnce(RpcRequest) -> RpcResponse,
    ) -> Result<(), LadonError> {
        let frame = read_frame(&mut self.stream)?;
        let request = decode_request_frame(&frame)?;
        let response = handler(request);
        let frame = encode_response_frame(&response)?;
        self.stream
            .write_all(&frame)
            .map_err(|_| LadonError::EndpointUnavailable)
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

    pub fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        validate_endpoint(&self.path)?;
        let mut stream =
            UnixStream::connect(&self.path).map_err(|_| LadonError::EndpointUnavailable)?;
        verify_peer(stream.as_raw_fd())?;
        let frame = encode_request_frame(request)?;
        stream
            .write_all(&frame)
            .map_err(|_| LadonError::EndpointUnavailable)?;
        let response = read_frame(&mut stream)?;
        decode_response_frame(&response)
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
