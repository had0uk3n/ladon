use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LadonError {
    #[error("invalid secret reference")]
    InvalidSecretRef,
    #[error("invalid field name")]
    InvalidFieldName,
    #[error("field value exceeds the size limit")]
    FieldTooLarge,
    #[error("record contains duplicate field names")]
    DuplicateField,
    #[error("record must contain at least one field")]
    EmptyRecord,
    #[error("record contains too many fields")]
    TooManyFields,
    #[error("vault payload exceeds the size limit")]
    VaultPayloadTooLarge,
    #[error("invalid vault payload")]
    InvalidVaultPayload,
    #[error("invalid vault file")]
    InvalidVaultFile,
    #[error("unsupported vault version")]
    UnsupportedVaultVersion,
    #[error("vault authentication failed")]
    VaultAuthenticationFailed,
    #[error("cryptographic randomness is unavailable")]
    CryptoUnavailable,
    #[error("a secret with that name already exists")]
    DuplicateSecretName,
    #[error("secret not found")]
    SecretNotFound,
    #[error("secret field not found")]
    FieldNotFound,
    #[error("vault revision cannot be incremented")]
    RevisionOverflow,
    #[error("vault storage operation failed")]
    StorageFailure,
    #[error("neither managed vault copy can be opened")]
    VaultUnavailable,
    #[error("IPC frame is invalid")]
    InvalidFrame,
    #[error("IPC frame exceeds the size limit")]
    FrameTooLarge,
    #[error("IPC request is invalid")]
    InvalidRequest,
    #[error("unsupported protocol version")]
    UnsupportedProtocolVersion,
    #[error("output limit is outside the supported range")]
    InvalidOutputLimit,
    #[error("executable path is invalid")]
    InvalidExecutablePath,
    #[error("working directory is invalid")]
    InvalidWorkingDirectory,
    #[error("secret binding is invalid")]
    InvalidBinding,
    #[error("run contains too many secret bindings")]
    TooManyBindings,
    #[error("run timeout is outside the supported range")]
    InvalidTimeout,
    #[error("injected secret data exceeds the size limit")]
    InjectedDataTooLarge,
    #[error("managed secret data appears in command metadata")]
    SecretInCommand,
    #[error("another secret-bearing process is already running")]
    Busy,
    #[error("process execution failed")]
    ProcessFailure,
    #[error("another Ladon instance already owns the local endpoint")]
    AlreadyRunning,
    #[error("local endpoint failed its ownership or type checks")]
    UnsafeEndpoint,
    #[error("local Ladon endpoint is unavailable")]
    EndpointUnavailable,
    #[error("local IPC peer is not the current operating-system user")]
    InvalidPeer,
    #[error("passphrase does not meet the local vault requirements")]
    InvalidPassphrase,
}

impl LadonError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSecretRef => "invalid_secret_ref",
            Self::InvalidFieldName => "invalid_field_name",
            Self::FieldTooLarge => "field_too_large",
            Self::DuplicateField => "duplicate_field",
            Self::EmptyRecord => "empty_record",
            Self::TooManyFields => "too_many_fields",
            Self::VaultPayloadTooLarge => "vault_payload_too_large",
            Self::InvalidVaultPayload => "invalid_vault_payload",
            Self::InvalidVaultFile => "invalid_vault_file",
            Self::UnsupportedVaultVersion => "unsupported_vault_version",
            Self::VaultAuthenticationFailed => "vault_authentication_failed",
            Self::CryptoUnavailable => "crypto_unavailable",
            Self::DuplicateSecretName => "duplicate_secret_name",
            Self::SecretNotFound => "secret_not_found",
            Self::FieldNotFound => "field_not_found",
            Self::RevisionOverflow => "revision_overflow",
            Self::StorageFailure => "storage_failure",
            Self::VaultUnavailable => "vault_unavailable",
            Self::InvalidFrame => "invalid_frame",
            Self::FrameTooLarge => "frame_too_large",
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedProtocolVersion => "unsupported_protocol_version",
            Self::InvalidOutputLimit => "invalid_output_limit",
            Self::InvalidExecutablePath => "invalid_executable_path",
            Self::InvalidWorkingDirectory => "invalid_working_directory",
            Self::InvalidBinding => "invalid_binding",
            Self::TooManyBindings => "too_many_bindings",
            Self::InvalidTimeout => "invalid_timeout",
            Self::InjectedDataTooLarge => "injected_data_too_large",
            Self::SecretInCommand => "secret_in_command",
            Self::Busy => "busy",
            Self::ProcessFailure => "process_failure",
            Self::AlreadyRunning => "already_running",
            Self::UnsafeEndpoint => "unsafe_endpoint",
            Self::EndpointUnavailable => "endpoint_unavailable",
            Self::InvalidPeer => "invalid_peer",
            Self::InvalidPassphrase => "invalid_passphrase",
        }
    }

    #[must_use]
    pub const fn safe_message(self) -> &'static str {
        match self {
            Self::InvalidSecretRef => "invalid secret reference",
            Self::InvalidFieldName => "invalid field name",
            Self::FieldTooLarge => "field value exceeds the size limit",
            Self::DuplicateField => "record contains duplicate field names",
            Self::EmptyRecord => "record must contain at least one field",
            Self::TooManyFields => "record contains too many fields",
            Self::VaultPayloadTooLarge => "vault payload exceeds the size limit",
            Self::InvalidVaultPayload => "invalid vault payload",
            Self::InvalidVaultFile => "invalid vault file",
            Self::UnsupportedVaultVersion => "unsupported vault version",
            Self::VaultAuthenticationFailed => "vault authentication failed",
            Self::CryptoUnavailable => "cryptographic randomness is unavailable",
            Self::DuplicateSecretName => "a secret with that name already exists",
            Self::SecretNotFound => "secret not found",
            Self::FieldNotFound => "secret field not found",
            Self::RevisionOverflow => "vault revision cannot be incremented",
            Self::StorageFailure => "vault storage operation failed",
            Self::VaultUnavailable => "neither managed vault copy can be opened",
            Self::InvalidFrame => "IPC frame is invalid",
            Self::FrameTooLarge => "IPC frame exceeds the size limit",
            Self::InvalidRequest => "IPC request is invalid",
            Self::UnsupportedProtocolVersion => "unsupported protocol version",
            Self::InvalidOutputLimit => "output limit is outside the supported range",
            Self::InvalidExecutablePath => "executable path must be absolute",
            Self::InvalidWorkingDirectory => "working directory must be absolute",
            Self::InvalidBinding => "secret binding is invalid",
            Self::TooManyBindings => "run contains too many secret bindings",
            Self::InvalidTimeout => "run timeout is outside the supported range",
            Self::InjectedDataTooLarge => "injected secret data exceeds the size limit",
            Self::SecretInCommand => "managed secret data appears in command metadata",
            Self::Busy => "another secret-bearing process is already running",
            Self::ProcessFailure => "process execution failed",
            Self::AlreadyRunning => "another Ladon instance is already running",
            Self::UnsafeEndpoint => "local endpoint failed security checks",
            Self::EndpointUnavailable => "local Ladon endpoint is unavailable",
            Self::InvalidPeer => "local IPC peer is not the current user",
            Self::InvalidPassphrase => "passphrase must match and contain 12 to 1024 characters",
        }
    }
}
