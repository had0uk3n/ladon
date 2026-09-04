mod client;
mod commands;
mod mcp;

pub use client::{LocalRpcTransport, RpcTransport};
pub use commands::execute_cli;
pub use mcp::serve_mcp;
