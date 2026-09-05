use std::fmt;

use ladon_core::{
    FieldName, LadonError, MAX_FIELD_BYTES, SecretField, SecretId, SecretRecord, SensitiveBytes,
    TextHint,
};

use crate::ui::SensitiveText;

pub enum EditableValue {
    Text(SensitiveText),
    Binary {
        bytes: SensitiveBytes,
        original_hint: TextHint,
    },
}

impl fmt::Debug for EditableValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(_) => formatter.write_str("EditableValue::Text([REDACTED])"),
            Self::Binary {
                bytes,
                original_hint,
            } => formatter
                .debug_struct("EditableValue::Binary")
                .field("bytes", bytes)
                .field("original_hint", original_hint)
                .finish(),
        }
    }
}

pub struct EditableField {
    name: String,
    value: EditableValue,
}

impl EditableField {
    #[must_use]
    pub fn text(name: impl Into<String>, value: SensitiveText) -> Self {
        Self {
            name: name.into(),
            value: EditableValue::Text(value),
        }
    }

    #[must_use]
    pub fn binary(name: impl Into<String>, bytes: SensitiveBytes, original_hint: TextHint) -> Self {
        Self {
            name: name.into(),
            value: EditableValue::Binary {
                bytes,
                original_hint,
            },
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    #[must_use]
    pub fn name_mut(&mut self) -> &mut String {
        &mut self.name
    }

    #[must_use]
    pub const fn value(&self) -> &EditableValue {
        &self.value
    }

    #[must_use]
    pub fn value_mut(&mut self) -> &mut EditableValue {
        &mut self.value
    }
}

impl fmt::Debug for EditableField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EditableField")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

pub struct EditSecretDraft {
    id: SecretId,
    name: String,
    fields: Vec<EditableField>,
}

impl EditSecretDraft {
    #[must_use]
    pub fn from_parts(id: SecretId, name: impl Into<String>, fields: Vec<EditableField>) -> Self {
        Self {
            id,
            name: name.into(),
            fields,
        }
    }

    #[must_use]
    pub fn from_record(record: &SecretRecord) -> Self {
        let fields = record
            .fields()
            .iter()
            .map(|field| {
                field.value().expose(|bytes| {
                    if field.text_hint() == TextHint::Text {
                        if let Ok(value) = std::str::from_utf8(bytes) {
                            return EditableField::text(
                                field.name().as_str(),
                                SensitiveText::from(value),
                            );
                        }
                    }
                    EditableField::binary(
                        field.name().as_str(),
                        SensitiveBytes::new(bytes.to_vec()),
                        field.text_hint(),
                    )
                })
            })
            .collect();
        Self::from_parts(record.id(), record.name(), fields)
    }

    #[must_use]
    pub const fn id(&self) -> SecretId {
        self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    #[must_use]
    pub fn name_mut(&mut self) -> &mut String {
        &mut self.name
    }

    #[must_use]
    pub fn fields(&self) -> &[EditableField] {
        &self.fields
    }

    #[must_use]
    pub fn fields_mut(&mut self) -> &mut [EditableField] {
        &mut self.fields
    }

    pub fn add_text_field(&mut self) {
        self.fields
            .push(EditableField::text("", SensitiveText::default()));
    }

    pub fn remove_field(&mut self, index: usize) -> bool {
        if self.fields.len() <= 1 || index >= self.fields.len() {
            return false;
        }
        self.fields.remove(index);
        true
    }

    pub fn to_fields(&self) -> Result<Vec<SecretField>, LadonError> {
        self.fields
            .iter()
            .map(|field| {
                let (value_len, text_hint) = match field.value() {
                    EditableValue::Text(value) => (value.as_str().len(), TextHint::Text),
                    EditableValue::Binary {
                        bytes,
                        original_hint,
                    } => (bytes.len(), *original_hint),
                };
                let name = validate_field(field.name(), value_len)?;
                let value = match field.value() {
                    EditableValue::Text(value) => value.to_sensitive_bytes().expose(<[u8]>::to_vec),
                    EditableValue::Binary { bytes, .. } => bytes.expose(<[u8]>::to_vec),
                };
                Ok(SecretField::new(name, value, text_hint)
                    .expect("field name and byte length were validated before copying"))
            })
            .collect()
    }
}

fn validate_field(name: &str, value_len: usize) -> Result<FieldName, LadonError> {
    let name = FieldName::parse(name)?;
    if value_len > MAX_FIELD_BYTES {
        return Err(LadonError::FieldTooLarge);
    }
    Ok(name)
}

impl fmt::Debug for EditSecretDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EditSecretDraft")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("fields", &format_args!("[{} REDACTED]", self.fields.len()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::validate_field;
    use ladon_core::{LadonError, MAX_FIELD_BYTES};

    #[test]
    fn field_validation_rejects_an_invalid_name_before_an_oversized_value() {
        assert_eq!(
            validate_field("invalid name", MAX_FIELD_BYTES + 1).unwrap_err(),
            LadonError::InvalidFieldName
        );
    }
}
