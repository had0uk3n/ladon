use ladon_core::{LadonError, RpcRequest, RpcResponse};

pub trait RpcTransport {
    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError>;
}

#[derive(Clone, Debug, Default)]
pub struct LocalRpcTransport;

#[cfg(unix)]
impl RpcTransport for LocalRpcTransport {
    fn call(&self, request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        ladon_app::LocalClient::new(ladon_app::default_endpoint_path()).call(request)
    }
}

#[cfg(windows)]
impl RpcTransport for LocalRpcTransport {
    fn call(&self, _request: &RpcRequest) -> Result<RpcResponse, LadonError> {
        Err(LadonError::EndpointUnavailable)
    }
}
