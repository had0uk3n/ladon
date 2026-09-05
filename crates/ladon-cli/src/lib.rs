mod client;
mod commands;
mod integrate;
mod mcp;

pub use client::{LocalRpcTransport, RpcTransport};
pub use commands::execute_cli;
pub use integrate::{
    IntegrationOutcome, IntegrationTarget, apply_integration_config, integration_preview,
};
pub use mcp::serve_mcp;
