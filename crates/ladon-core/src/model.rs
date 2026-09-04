use std::{collections::HashSet, fmt};

use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::{LadonError, SensitiveBytes};

pub const MAX_FIELD_BYTES: usize = 1024 * 1024;
pub const MAX_FIELDS_PER_RECORD: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretId(Uuid);

impl SecretId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn parse(input: &str) -> Result<Self, LadonError> {
        Uuid::parse_str(input)
            .map(Self)
            .map_err(|_| LadonError::InvalidSecretRef)
    }

    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    pub(crate) fn as_bytes(self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretName(String);

impl SecretName {
    fn parse(input: &str) -> Result<Self, LadonError> {
        let normalized: String = input.nfc().collect();
        let valid_length = !normalized.is_empty() && normalized.len() <= 128;
        let valid_content = !normalized.contains("::")
            && !normalized.starts_with("id:")
            && !normalized.chars().any(is_forbidden_name_character);

        if valid_length && valid_content {
            Ok(Self(normalized))
        } else {
            Err(LadonError::InvalidSecretRef)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretRef {
    Name(SecretName),
    Id(SecretId),
}

impl SecretRef {
    pub fn parse(input: &str) -> Result<Self, LadonError> {
        if let Some(uuid) = input.strip_prefix("id:") {
            SecretId::parse(uuid).map(Self::Id)
        } else {
            SecretName::parse(input).map(Self::Name)
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => name.fmt(formatter),
            Self::Id(id) => write!(formatter, "id:{id}"),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FieldName(String);

impl FieldName {
    pub fn parse(input: &str) -> Result<Self, LadonError> {
        let mut bytes = input.bytes();
        let valid = input.len() <= 64
            && bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));

        if valid {
            Ok(Self(input.to_owned()))
        } else {
            Err(LadonError::InvalidFieldName)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextHint {
    Binary,
    Text,
}

#[derive(Eq, PartialEq)]
pub struct SecretField {
    name: FieldName,
    value: SensitiveBytes,
    text_hint: TextHint,
}

impl SecretField {
    pub fn new(name: FieldName, value: Vec<u8>, text_hint: TextHint) -> Result<Self, LadonError> {
        if value.len() > MAX_FIELD_BYTES {
            return Err(LadonError::FieldTooLarge);
        }

        Ok(Self {
            name,
            value: SensitiveBytes::new(value),
            text_hint,
        })
    }

    #[must_use]
    pub fn name(&self) -> &FieldName {
        &self.name
    }

    #[must_use]
    pub fn value(&self) -> &SensitiveBytes {
        &self.value
    }

    #[must_use]
    pub const fn text_hint(&self) -> TextHint {
        self.text_hint
    }
}

impl fmt::Debug for SecretField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretField")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("text_hint", &self.text_hint)
            .finish()
    }
}

#[derive(Eq, PartialEq)]
pub struct SecretRecord {
    id: SecretId,
    name: SecretName,
    fields: Vec<SecretField>,
}

impl SecretRecord {
    pub fn new(name: &str, fields: Vec<SecretField>) -> Result<Self, LadonError> {
        Self::from_parts(SecretId::new(), name, fields)
    }

    pub(crate) fn from_parts(
        id: SecretId,
        name: &str,
        fields: Vec<SecretField>,
    ) -> Result<Self, LadonError> {
        if fields.is_empty() {
            return Err(LadonError::EmptyRecord);
        }
        if fields.len() > MAX_FIELDS_PER_RECORD {
            return Err(LadonError::TooManyFields);
        }

        let mut names = HashSet::with_capacity(fields.len());
        if fields.iter().any(|field| !names.insert(field.name.clone())) {
            return Err(LadonError::DuplicateField);
        }

        Ok(Self {
            id,
            name: SecretName::parse(name)?,
            fields,
        })
    }

    #[must_use]
    pub const fn id(&self) -> SecretId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[must_use]
    pub fn fields(&self) -> &[SecretField] {
        &self.fields
    }

    pub fn rename(&mut self, name: &str) -> Result<(), LadonError> {
        self.name = SecretName::parse(name)?;
        Ok(())
    }
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretRecord")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("fields", &format_args!("[{} REDACTED]", self.fields.len()))
            .finish()
    }
}

fn is_forbidden_name_character(character: char) -> bool {
    let codepoint = character as u32;
    character.is_ascii_control()
        || matches!(
            codepoint,
            0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
        )
}
