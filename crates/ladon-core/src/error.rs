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
        }
    }
}
