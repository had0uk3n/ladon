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
        }
    }
}
