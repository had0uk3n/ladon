use crate::{
    FieldName, LadonError, SecretField, SecretId, SecretRecord, SecretRef, UnlockedVault,
    VaultStore,
};

pub trait ActivitySink {
    fn secret_activity(&mut self);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretMetadata {
    pub id: SecretId,
    pub name: String,
    pub field_names: Vec<String>,
}

pub struct VaultSession<A> {
    vault: UnlockedVault,
    activity: A,
}

impl<A: ActivitySink> VaultSession<A> {
    #[must_use]
    pub const fn new(vault: UnlockedVault, activity: A) -> Self {
        Self { vault, activity }
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.vault.payload().revision()
    }

    #[must_use]
    pub const fn activity(&self) -> &A {
        &self.activity
    }

    pub fn record_activity(&mut self) {
        self.activity.secret_activity();
    }

    #[must_use]
    pub fn list(&self) -> Vec<SecretMetadata> {
        self.vault
            .payload()
            .records()
            .iter()
            .map(|record| SecretMetadata {
                id: record.id(),
                name: record.name().to_owned(),
                field_names: record
                    .fields()
                    .iter()
                    .map(|field| field.name().as_str().to_owned())
                    .collect(),
            })
            .collect()
    }

    pub fn add(&mut self, name: &str, fields: Vec<SecretField>) -> Result<SecretId, LadonError> {
        let record = SecretRecord::new(name, fields)?;
        if self
            .vault
            .payload()
            .records()
            .iter()
            .any(|existing| existing.name() == record.name())
        {
            return Err(LadonError::DuplicateSecretName);
        }
        let id = record.id();
        let payload = self.vault.payload_mut();
        payload.increment_revision()?;
        payload.records_mut().push(record);
        self.activity.secret_activity();
        Ok(id)
    }

    pub fn rename(&mut self, reference: &SecretRef, new_name: &str) -> Result<(), LadonError> {
        let normalized = match SecretRef::parse(new_name)? {
            SecretRef::Name(name) => name,
            SecretRef::Id(_) => return Err(LadonError::InvalidSecretRef),
        };
        let target = find_record_index(self.vault.payload().records(), reference)?;
        if self
            .vault
            .payload()
            .records()
            .iter()
            .enumerate()
            .any(|(index, record)| index != target && record.name() == normalized.as_str())
        {
            return Err(LadonError::DuplicateSecretName);
        }

        let payload = self.vault.payload_mut();
        payload.increment_revision()?;
        payload.records_mut()[target].set_name(normalized);
        self.activity.secret_activity();
        Ok(())
    }

    pub fn replace_fields(
        &mut self,
        reference: &SecretRef,
        fields: Vec<SecretField>,
    ) -> Result<(), LadonError> {
        let target = find_record_index(self.vault.payload().records(), reference)?;
        let current = &self.vault.payload().records()[target];
        let replacement = SecretRecord::from_parts(current.id(), current.name(), fields)?;
        let payload = self.vault.payload_mut();
        payload.increment_revision()?;
        payload.records_mut()[target] = replacement;
        self.activity.secret_activity();
        Ok(())
    }

    pub fn delete(&mut self, reference: &SecretRef) -> Result<(), LadonError> {
        let target = find_record_index(self.vault.payload().records(), reference)?;
        let payload = self.vault.payload_mut();
        payload.increment_revision()?;
        payload.records_mut().remove(target);
        self.activity.secret_activity();
        Ok(())
    }

    pub fn with_field<R>(
        &mut self,
        reference: &SecretRef,
        field_name: &FieldName,
        operation: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, LadonError> {
        let Self { vault, activity } = self;
        let target = find_record_index(vault.payload().records(), reference)?;
        let field = vault.payload().records()[target]
            .fields()
            .iter()
            .find(|field| field.name() == field_name)
            .ok_or(LadonError::FieldNotFound)?;
        activity.secret_activity();
        Ok(field.value().expose(operation))
    }

    pub fn seal(&self) -> Result<Vec<u8>, LadonError> {
        self.vault.seal()
    }

    pub fn commit_to(&self, store: &VaultStore) -> Result<(), LadonError> {
        let encrypted = self.seal()?;
        store.commit_encrypted(&encrypted)
    }
}

fn find_record_index(records: &[SecretRecord], reference: &SecretRef) -> Result<usize, LadonError> {
    records
        .iter()
        .position(|record| match reference {
            SecretRef::Name(name) => record.name() == name.as_str(),
            SecretRef::Id(id) => record.id() == *id,
        })
        .ok_or(LadonError::SecretNotFound)
}
