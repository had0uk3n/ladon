use std::{
    fmt, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use ladon_core::{
    ActivitySink, FieldName, LadonError, PreparedRecordReplacement, ResolvedSecretBinding,
    SecretField, SecretId, SecretMetadata, SecretRef, SensitiveBytes, TextHint,
    ValidatedSecretBinding, VaultOpen, VaultPayload, VaultSession, VaultStore, create_vault,
};
use zeroize::{Zeroize, Zeroizing};

use crate::ApprovalSecret;
use crate::EditSecretDraft;

const MIN_PASSPHRASE_SCALARS: usize = 12;
const MAX_PASSPHRASE_BYTES: usize = 1024;
const REVEAL_MILLIS: u64 = 10_000;
const CLIPBOARD_MILLIS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub struct SensitiveText(Zeroizing<String>);

impl SensitiveText {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn push_str(&mut self, value: &str) {
        self.0.push_str(value);
    }

    pub fn clear(&mut self) {
        self.0.zeroize();
        self.0.clear();
    }

    #[must_use]
    pub fn to_sensitive_bytes(&self) -> SensitiveBytes {
        SensitiveBytes::new(self.0.as_bytes().to_vec())
    }
}

#[cfg(feature = "gui")]
impl eframe::egui::TextBuffer for SensitiveText {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        SensitiveText::as_str(self)
    }

    fn insert_text(&mut self, text: &str, char_index: usize) -> usize {
        let byte_index = self
            .0
            .char_indices()
            .nth(char_index)
            .map_or(self.0.len(), |(index, _)| index);
        let mut replacement = String::with_capacity(self.0.len().saturating_add(text.len()));
        replacement.push_str(&self.0[..byte_index]);
        replacement.push_str(text);
        replacement.push_str(&self.0[byte_index..]);
        self.0 = Zeroizing::new(replacement);
        text.chars().count()
    }

    fn delete_char_range(&mut self, char_range: std::ops::Range<usize>) {
        let start = self
            .0
            .char_indices()
            .nth(char_range.start)
            .map_or(self.0.len(), |(index, _)| index);
        let end = self
            .0
            .char_indices()
            .nth(char_range.end)
            .map_or(self.0.len(), |(index, _)| index);
        let mut replacement = String::with_capacity(self.0.len().saturating_sub(end - start));
        replacement.push_str(&self.0[..start]);
        replacement.push_str(&self.0[end..]);
        self.0 = Zeroizing::new(replacement);
    }

    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Self>()
    }
}

impl From<&str> for SensitiveText {
    fn from(value: &str) -> Self {
        Self(Zeroizing::new(value.to_owned()))
    }
}

impl fmt::Debug for SensitiveText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SensitiveText([REDACTED; {} bytes])",
            self.0.len()
        )
    }
}

pub fn validate_new_passphrase(passphrase: &str, confirmation: &str) -> Result<(), LadonError> {
    let scalar_count = passphrase.chars().count();
    if passphrase == confirmation
        && (MIN_PASSPHRASE_SCALARS..=MAX_PASSPHRASE_BYTES).contains(&scalar_count)
        && passphrase.len() <= MAX_PASSPHRASE_BYTES
    {
        Ok(())
    } else {
        Err(LadonError::InvalidPassphrase)
    }
}

pub struct DraftField {
    name: String,
    value: SensitiveText,
}

impl DraftField {
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
    pub const fn value(&self) -> &SensitiveText {
        &self.value
    }

    #[must_use]
    pub const fn value_mut(&mut self) -> &mut SensitiveText {
        &mut self.value
    }
}

impl fmt::Debug for DraftField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DraftField")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub struct AddSecretDraft {
    name: String,
    fields: Vec<DraftField>,
}

impl AddSecretDraft {
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: String::new(),
            fields: vec![DraftField {
                name: "value".to_owned(),
                value: SensitiveText::default(),
            }],
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
    pub fn fields(&self) -> &[DraftField] {
        &self.fields
    }

    #[must_use]
    pub fn fields_mut(&mut self) -> &mut [DraftField] {
        &mut self.fields
    }

    pub fn add_field(&mut self) {
        self.fields.push(DraftField {
            name: String::new(),
            value: SensitiveText::default(),
        });
    }
}

impl Default for AddSecretDraft {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AddSecretDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AddSecretDraft")
            .field("name", &self.name)
            .field("fields", &format_args!("[{} REDACTED]", self.fields.len()))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultUiPhase {
    FirstRun,
    Locked,
    RecoveryRequired,
    Unlocked,
}

struct SessionActivity {
    last: Instant,
}

impl ActivitySink for SessionActivity {
    fn secret_activity(&mut self) {
        self.last = Instant::now();
    }
}

enum ManagedVault {
    FirstRun,
    Locked,
    RecoveryRequired {
        primary: Option<ladon_core::UnlockedVault>,
        backup: ladon_core::UnlockedVault,
        activity: SessionActivity,
    },
    Unlocked(VaultSession<SessionActivity>),
}

pub struct VaultController {
    store: VaultStore,
    state: ManagedVault,
    session_id: Option<uuid::Uuid>,
}

pub(crate) struct ApprovalPlan {
    pub(crate) vault_session_id: uuid::Uuid,
    pub(crate) secrets: Vec<ApprovalSecret>,
    pub(crate) binding_secret_ids: Vec<SecretId>,
}

impl VaultController {
    #[must_use]
    pub fn new(primary_path: PathBuf) -> Self {
        let store = VaultStore::new(primary_path.clone());
        let exists = primary_path.exists() || store.backup_path().exists();
        Self {
            store,
            state: if exists {
                ManagedVault::Locked
            } else {
                ManagedVault::FirstRun
            },
            session_id: None,
        }
    }

    #[must_use]
    pub const fn phase(&self) -> VaultUiPhase {
        match self.state {
            ManagedVault::FirstRun => VaultUiPhase::FirstRun,
            ManagedVault::Locked => VaultUiPhase::Locked,
            ManagedVault::RecoveryRequired { .. } => VaultUiPhase::RecoveryRequired,
            ManagedVault::Unlocked(_) => VaultUiPhase::Unlocked,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<uuid::Uuid> {
        self.session_id
    }

    pub fn load_secret(&mut self, id: SecretId) -> Result<EditSecretDraft, LadonError> {
        let ManagedVault::Unlocked(session) = &mut self.state else {
            return Err(LadonError::VaultLocked);
        };
        session.with_record(&SecretRef::Id(id), EditSecretDraft::from_record)
    }

    pub fn prepare_secret_update(
        &self,
        draft: &EditSecretDraft,
    ) -> Result<PreparedRecordReplacement, LadonError> {
        let ManagedVault::Unlocked(session) = &self.state else {
            return Err(LadonError::VaultLocked);
        };
        session.prepare_record_replacement(
            &SecretRef::Id(draft.id()),
            draft.name(),
            draft.to_fields()?,
        )
    }

    pub fn apply_secret_update(
        &mut self,
        update: PreparedRecordReplacement,
    ) -> Result<(), LadonError> {
        let ManagedVault::Unlocked(session) = &mut self.state else {
            return Err(LadonError::VaultLocked);
        };
        session.apply_record_replacement(update)?;
        if let Err(error) = session.commit_to(&self.store) {
            self.state = ManagedVault::Locked;
            self.session_id = None;
            return Err(error);
        }
        Ok(())
    }

    pub fn ensure_secret_exists(&self, id: SecretId) -> Result<(), LadonError> {
        let ManagedVault::Unlocked(session) = &self.state else {
            return Err(LadonError::VaultLocked);
        };
        session
            .list()
            .iter()
            .any(|secret| secret.id == id)
            .then_some(())
            .ok_or(LadonError::SecretNotFound)
    }

    pub fn create(
        &mut self,
        passphrase: &SensitiveText,
        confirmation: &SensitiveText,
    ) -> Result<(), LadonError> {
        if self.phase() != VaultUiPhase::FirstRun {
            return Err(LadonError::InvalidRequest);
        }
        validate_new_passphrase(passphrase.as_str(), confirmation.as_str())?;
        ensure_private_parent(self.store.backup_path())?;
        let sensitive = passphrase.to_sensitive_bytes();
        let payload = VaultPayload::new(SecretId::new(), 0, Vec::new())?;
        let (vault, _) = create_vault(payload, &sensitive)?;
        self.store.commit(&vault)?;
        self.state = ManagedVault::Unlocked(VaultSession::new(
            vault,
            SessionActivity {
                last: Instant::now(),
            },
        ));
        self.session_id = Some(uuid::Uuid::new_v4());
        Ok(())
    }

    pub fn unlock(&mut self, passphrase: &SensitiveText) -> Result<(), LadonError> {
        if self.phase() != VaultUiPhase::Locked {
            return Err(LadonError::InvalidRequest);
        }
        match self.store.open(&passphrase.to_sensitive_bytes())? {
            VaultOpen::Primary {
                vault,
                newer_backup,
            } => {
                if let Some(backup) = newer_backup {
                    self.state = ManagedVault::RecoveryRequired {
                        primary: Some(vault),
                        backup,
                        activity: SessionActivity {
                            last: Instant::now(),
                        },
                    };
                } else {
                    self.state = ManagedVault::Unlocked(VaultSession::new(
                        vault,
                        SessionActivity {
                            last: Instant::now(),
                        },
                    ));
                    self.session_id = Some(uuid::Uuid::new_v4());
                }
            }
            VaultOpen::RestoreRequired { backup } => {
                self.state = ManagedVault::RecoveryRequired {
                    primary: None,
                    backup,
                    activity: SessionActivity {
                        last: Instant::now(),
                    },
                };
            }
        }
        Ok(())
    }

    pub fn restore_backup(&mut self) -> Result<(), LadonError> {
        let ManagedVault::RecoveryRequired {
            primary,
            backup,
            activity,
        } = std::mem::replace(&mut self.state, ManagedVault::Locked)
        else {
            return Err(LadonError::InvalidRequest);
        };
        if let Err(error) = self.store.commit(&backup) {
            self.state = ManagedVault::RecoveryRequired {
                primary,
                backup,
                activity,
            };
            return Err(error);
        }
        self.state = ManagedVault::Unlocked(VaultSession::new(
            backup,
            SessionActivity {
                last: Instant::now(),
            },
        ));
        self.session_id = Some(uuid::Uuid::new_v4());
        Ok(())
    }

    #[must_use]
    pub fn can_continue_with_primary(&self) -> bool {
        matches!(
            self.state,
            ManagedVault::RecoveryRequired {
                primary: Some(_),
                ..
            }
        )
    }

    pub fn continue_with_primary(&mut self) -> Result<(), LadonError> {
        let ManagedVault::RecoveryRequired {
            primary,
            backup,
            activity,
        } = std::mem::replace(&mut self.state, ManagedVault::Locked)
        else {
            return Err(LadonError::InvalidRequest);
        };
        let Some(primary) = primary else {
            self.state = ManagedVault::RecoveryRequired {
                primary: None,
                backup,
                activity,
            };
            return Err(LadonError::InvalidRequest);
        };
        self.state = ManagedVault::Unlocked(VaultSession::new(
            primary,
            SessionActivity {
                last: Instant::now(),
            },
        ));
        self.session_id = Some(uuid::Uuid::new_v4());
        Ok(())
    }

    pub fn add_secret(&mut self, draft: &mut AddSecretDraft) -> Result<SecretId, LadonError> {
        let fields = draft
            .fields()
            .iter()
            .map(|field| {
                SecretField::new(
                    FieldName::parse(field.name())?,
                    field.value().to_sensitive_bytes().expose(<[u8]>::to_vec),
                    TextHint::Text,
                )
            })
            .collect::<Result<Vec<_>, LadonError>>()?;
        let ManagedVault::Unlocked(session) = &mut self.state else {
            return Err(LadonError::InvalidRequest);
        };
        let id = session.add(draft.name(), fields)?;
        if let Err(error) = session.commit_to(&self.store) {
            self.state = ManagedVault::Locked;
            self.session_id = None;
            return Err(error);
        }
        *draft = AddSecretDraft::new();
        Ok(id)
    }

    pub fn delete_secret(&mut self, id: SecretId) -> Result<(), LadonError> {
        let ManagedVault::Unlocked(session) = &mut self.state else {
            return Err(LadonError::InvalidRequest);
        };
        session.delete(&ladon_core::SecretRef::Id(id))?;
        if let Err(error) = session.commit_to(&self.store) {
            self.state = ManagedVault::Locked;
            self.session_id = None;
            return Err(error);
        }
        Ok(())
    }

    pub fn resolve_bindings(
        &mut self,
        bindings: &[ValidatedSecretBinding],
    ) -> Result<Vec<ResolvedSecretBinding>, LadonError> {
        let secret_ids = self.binding_secret_ids(bindings)?;
        self.resolve_bindings_for_ids(bindings, &secret_ids)
    }

    pub(crate) fn resolve_bindings_for_ids(
        &mut self,
        bindings: &[ValidatedSecretBinding],
        expected_secret_ids: &[SecretId],
    ) -> Result<Vec<ResolvedSecretBinding>, LadonError> {
        if bindings.len() != expected_secret_ids.len() {
            return Err(LadonError::InvalidBinding);
        }
        let ManagedVault::Unlocked(session) = &mut self.state else {
            return Err(LadonError::VaultLocked);
        };
        let metadata = session.list();
        bindings
            .iter()
            .zip(expected_secret_ids)
            .map(|(binding, expected_id)| {
                let id = metadata
                    .iter()
                    .find(|secret| match binding.secret_ref() {
                        ladon_core::SecretRef::Name(name) => secret.name == name.as_str(),
                        ladon_core::SecretRef::Id(id) => secret.id == *id,
                    })
                    .map(|secret| secret.id)
                    .ok_or(LadonError::SecretNotFound)?;
                if id != *expected_id {
                    return Err(LadonError::InvalidBinding);
                }
                let value = session.with_field(binding.secret_ref(), binding.field(), |bytes| {
                    SensitiveBytes::new(bytes.to_vec())
                })?;
                ResolvedSecretBinding::new(&id.to_string(), binding.field().as_str(), value)
            })
            .collect()
    }

    pub(crate) fn approval_plan(
        &self,
        bindings: &[ValidatedSecretBinding],
    ) -> Result<ApprovalPlan, LadonError> {
        let binding_secret_ids = self.binding_secret_ids(bindings)?;
        let ManagedVault::Unlocked(session) = &self.state else {
            return Err(LadonError::VaultLocked);
        };
        let metadata = session.list();
        let mut requested = Vec::<ApprovalSecret>::new();
        for (binding, secret_id) in bindings.iter().zip(&binding_secret_ids) {
            let secret = metadata
                .iter()
                .find(|secret| secret.id == *secret_id)
                .ok_or(LadonError::SecretNotFound)?;
            let field = binding.field().as_str();
            if !secret.field_names.iter().any(|name| name == field) {
                return Err(LadonError::FieldNotFound);
            }
            if let Some(existing) = requested.iter_mut().find(|item| item.id() == secret.id) {
                if !existing.fields().iter().any(|name| name == field) {
                    let mut fields = existing.fields().to_vec();
                    fields.push(field.to_owned());
                    *existing = ApprovalSecret::new(secret.id, &secret.name, fields);
                }
            } else {
                requested.push(ApprovalSecret::new(secret.id, &secret.name, [field]));
            }
        }
        Ok(ApprovalPlan {
            vault_session_id: self.session_id.ok_or(LadonError::VaultLocked)?,
            secrets: requested,
            binding_secret_ids,
        })
    }

    fn binding_secret_ids(
        &self,
        bindings: &[ValidatedSecretBinding],
    ) -> Result<Vec<SecretId>, LadonError> {
        let ManagedVault::Unlocked(session) = &self.state else {
            return Err(LadonError::VaultLocked);
        };
        let metadata = session.list();
        bindings
            .iter()
            .map(|binding| {
                metadata
                    .iter()
                    .find(|secret| match binding.secret_ref() {
                        ladon_core::SecretRef::Name(name) => secret.name == name.as_str(),
                        ladon_core::SecretRef::Id(id) => secret.id == *id,
                    })
                    .map(|secret| secret.id)
                    .ok_or(LadonError::SecretNotFound)
            })
            .collect()
    }

    pub fn record_secret_activity(&mut self) {
        if let ManagedVault::Unlocked(session) = &mut self.state {
            session.record_activity();
        }
    }

    #[must_use]
    pub fn secrets(&self) -> Vec<SecretMetadata> {
        match &self.state {
            ManagedVault::Unlocked(session) => session.list(),
            _ => Vec::new(),
        }
    }

    pub fn lock(&mut self) {
        self.state = if matches!(self.state, ManagedVault::FirstRun) {
            ManagedVault::FirstRun
        } else {
            ManagedVault::Locked
        };
        self.session_id = None;
    }

    pub fn auto_lock_if_idle(&mut self) -> bool {
        let should_lock = matches!(
            &self.state,
            ManagedVault::Unlocked(session)
                if session.activity().last.elapsed() >= DEFAULT_IDLE_TIMEOUT
        ) || matches!(
            &self.state,
            ManagedVault::RecoveryRequired { activity, .. }
                if activity.last.elapsed() >= DEFAULT_IDLE_TIMEOUT
        );
        if should_lock {
            self.lock();
        }
        should_lock
    }

    #[must_use]
    pub fn remaining_unlocked(&self) -> Option<Duration> {
        match &self.state {
            ManagedVault::Unlocked(session) => {
                Some(DEFAULT_IDLE_TIMEOUT.saturating_sub(session.activity().last.elapsed()))
            }
            ManagedVault::RecoveryRequired { activity, .. } => {
                Some(DEFAULT_IDLE_TIMEOUT.saturating_sub(activity.last.elapsed()))
            }
            ManagedVault::FirstRun | ManagedVault::Locked => None,
        }
    }
}

fn ensure_private_parent(path: &Path) -> Result<(), LadonError> {
    let parent = path.parent().ok_or(LadonError::StorageFailure)?;
    fs::create_dir_all(parent).map_err(|_| LadonError::StorageFailure)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| LadonError::StorageFailure)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevealLease {
    deadline_millis: u64,
}

impl RevealLease {
    #[must_use]
    pub const fn new(now_millis: u64) -> Self {
        Self {
            deadline_millis: now_millis.saturating_add(REVEAL_MILLIS),
        }
    }

    #[must_use]
    pub const fn is_active(self, now_millis: u64) -> bool {
        now_millis < self.deadline_millis
    }
}

pub struct ClipboardLease {
    value: SensitiveBytes,
    deadline_millis: u64,
}

impl ClipboardLease {
    #[must_use]
    pub const fn new(value: SensitiveBytes, now_millis: u64) -> Self {
        Self {
            value,
            deadline_millis: now_millis.saturating_add(CLIPBOARD_MILLIS),
        }
    }

    #[must_use]
    pub fn should_clear(&self, now_millis: u64, current_clipboard: &[u8]) -> bool {
        now_millis >= self.deadline_millis
            && self.value.expose(|copied| copied == current_clipboard)
    }
}

impl fmt::Debug for ClipboardLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClipboardLease")
            .field("value", &"[REDACTED]")
            .field("deadline_millis", &self.deadline_millis)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRequestView {
    client_label: String,
    secrets: Vec<(String, Vec<String>)>,
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
    timeout: Duration,
}

impl PendingRequestView {
    #[must_use]
    pub fn new(
        client_label: &str,
        executable: &str,
        arguments: &[String],
        working_directory: &str,
        timeout: Duration,
    ) -> Self {
        Self {
            client_label: sanitize_untrusted(client_label),
            secrets: Vec::new(),
            executable: sanitize_untrusted(executable),
            arguments: arguments
                .iter()
                .map(|argument| sanitize_untrusted(argument))
                .collect(),
            working_directory: sanitize_untrusted(working_directory),
            timeout,
        }
    }

    #[must_use]
    pub fn from_approval(approval: &crate::PendingApproval, timeout: Duration) -> Self {
        let mut view = Self::new(
            approval.client_label(),
            approval.executable(),
            approval.arguments(),
            approval.working_directory(),
            timeout,
        );
        view.secrets = approval
            .secrets()
            .iter()
            .map(|secret| {
                (
                    sanitize_untrusted(secret.name()),
                    secret
                        .fields()
                        .iter()
                        .map(|field| sanitize_untrusted(field))
                        .collect(),
                )
            })
            .collect();
        view
    }

    #[must_use]
    pub fn client_label(&self) -> &str {
        &self.client_label
    }

    #[must_use]
    pub fn secrets(&self) -> &[(String, Vec<String>)] {
        &self.secrets
    }

    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn working_directory(&self) -> &str {
        &self.working_directory
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

fn sanitize_untrusted(input: &str) -> String {
    input
        .chars()
        .map(|character| {
            let codepoint = character as u32;
            if character.is_control()
                || matches!(
                    codepoint,
                    0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
                )
            {
                format!("\\u{{{codepoint:x}}}")
            } else {
                character.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_plaintext_obeys_the_same_idle_deadline_as_an_unlocked_vault() {
        let directory = tempfile::tempdir().unwrap();
        let password = SensitiveBytes::new(b"correct horse".to_vec());
        let payload = VaultPayload::new(SecretId::new(), 1, Vec::new()).unwrap();
        let (backup, _) = create_vault(payload, &password).unwrap();
        let mut controller = VaultController {
            store: VaultStore::new(directory.path().join("vault.ladon")),
            state: ManagedVault::RecoveryRequired {
                primary: None,
                backup,
                activity: SessionActivity {
                    last: Instant::now() - DEFAULT_IDLE_TIMEOUT,
                },
            },
            session_id: None,
        };

        assert!(controller.auto_lock_if_idle());
        assert_eq!(controller.phase(), VaultUiPhase::Locked);
        assert!(controller.remaining_unlocked().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn persistence_failure_clears_the_unlock_session_identity() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.ladon");
        let passphrase = SensitiveText::from("correct horse");
        let mut controller = VaultController::new(path);
        controller.create(&passphrase, &passphrase).unwrap();
        let first_session = controller.session_id.unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500)).unwrap();

        let mut draft = AddSecretDraft::new();
        draft.set_name("will-not-persist");
        draft.fields_mut()[0].value_mut().push_str("fake-value");
        let result = controller.add_secret(&mut draft);

        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(LadonError::StorageFailure));
        assert_eq!(controller.phase(), VaultUiPhase::Locked);
        assert!(controller.session_id.is_none());
        controller.unlock(&passphrase).unwrap();
        assert_ne!(controller.session_id, Some(first_session));
    }
}
