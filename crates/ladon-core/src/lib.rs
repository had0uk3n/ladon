mod broker;
mod codec;
mod crypto;
mod error;
mod model;
mod protocol;
mod redact;
mod runner;
mod sensitive;
mod store;
mod vault;

pub use broker::{
    ActivityEntry, ActivityOutcome, BrokerDecision, BrokerState, LockReason, MonotonicClock,
    ReferencedField, SessionStatus,
};
pub use codec::{MAX_VAULT_PAYLOAD_BYTES, VaultPayload, decode_payload, encode_payload};
pub use crypto::{UnlockedVault, create_vault, unlock_vault};
pub use error::LadonError;
pub use model::{
    FieldName, MAX_FIELD_BYTES, MAX_FIELDS_PER_RECORD, SecretField, SecretId, SecretName,
    SecretRecord, SecretRef, TextHint,
};
pub use protocol::{
    BindingTarget, MAX_FRAME_BYTES, RpcMethod, RpcRequest, RpcResponse, RpcResult,
    SecretBindingRequest, SecretFieldSummary, SecretSummary, decode_request_frame,
    encode_request_frame, encode_response_frame,
};
pub use redact::{
    DEFAULT_OUTPUT_LIMIT_BYTES, MAX_OUTPUT_LIMIT_BYTES, MIN_OUTPUT_LIMIT_BYTES, RedactedOutput,
    RedactionSecret, StreamingRedactor,
};
pub use runner::{
    DEFAULT_RUN_TIMEOUT, MAX_ARGUMENT_BYTES, MAX_ARGUMENTS, MAX_BINDINGS, MAX_CLI_TIMEOUT,
    MAX_INJECTED_BYTES, MAX_MCP_TIMEOUT, MAX_PATH_BYTES, PreparedBinding, PreparedRun,
    ResolvedSecretBinding, RunCaller, RunRequest, ValidatedBindingTarget, ValidatedRunRequest,
    ValidatedSecretBinding, validate_run_request,
};
pub use sensitive::SensitiveBytes;
pub use store::{VaultOpen, VaultStore};
pub use vault::{ActivitySink, SecretMetadata, VaultSession};
