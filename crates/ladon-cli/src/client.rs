use ladon_core::{LadonError, RpcRequest, RpcResponse};
use uuid::Uuid;

pub(crate) const LOCAL_SERVICE_RECOVERY_GUIDANCE: &str = "Ask the user to check Ladon and that its app and client builds are compatible. Do not restart, stop, replace, or globally lock the shared Ladon app. Do not automatically retry a command after losing its reply.";

pub(crate) const fn needs_user_recovery(error: ladon_core::LadonError) -> bool {
    matches!(
        error,
        ladon_core::LadonError::IpcDisconnected
            | ladon_core::LadonError::IpcTimeout
            | ladon_core::LadonError::InvalidFrame
            | ladon_core::LadonError::InvalidResponse
            | ladon_core::LadonError::FrameTooLarge
            | ladon_core::LadonError::UnsupportedProtocolVersion
            | ladon_core::LadonError::EndpointUnavailable
            | ladon_core::LadonError::UnsafeEndpoint
            | ladon_core::LadonError::InvalidPeer
    )
}

pub trait RpcSessionLease: Send {
    fn is_connected(&self) -> bool {
        true
    }
}

impl RpcSessionLease for () {}

#[cfg(unix)]
impl RpcSessionLease for ladon_app::LocalSession {
    fn is_connected(&self) -> bool {
        ladon_app::LocalSession::is_connected(self)
    }
}

pub trait RpcTransport {
    fn open_session(
        &self,
        _client_session_id: Uuid,
        _client_label: &str,
    ) -> Result<Box<dyn RpcSessionLease>, LadonError> {
        Ok(Box::new(()))
    }

    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError>;
}

#[derive(Clone, Debug, Default)]
pub struct LocalRpcTransport;

#[cfg(unix)]
impl RpcTransport for LocalRpcTransport {
    fn open_session(
        &self,
        client_session_id: Uuid,
        client_label: &str,
    ) -> Result<Box<dyn RpcSessionLease>, LadonError> {
        let request = RpcRequest {
            version: ladon_core::PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            client_session_id,
            client_label: client_label.to_owned(),
            method: ladon_core::RpcMethod::SessionOpen,
        };
        ladon_app::LocalClient::new(ladon_app::default_endpoint_path())
            .open_session(&request)
            .map(|session| Box::new(session) as Box<dyn RpcSessionLease>)
    }

    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        ladon_app::LocalClient::new(ladon_app::default_endpoint_path()).call(request)
    }
}

#[cfg(windows)]
impl RpcTransport for LocalRpcTransport {
    fn open_session(
        &self,
        _client_session_id: Uuid,
        _client_label: &str,
    ) -> Result<Box<dyn RpcSessionLease>, LadonError> {
        Err(LadonError::EndpointUnavailable)
    }

    fn call(&self, _request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        Err(LadonError::EndpointUnavailable)
    }
}
