use std::{
    ffi::OsString,
    fmt, fs,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use uuid::Uuid;

use crate::{LadonError, SensitiveBytes, UnlockedVault, unlock_vault};

pub struct VaultStore {
    primary: PathBuf,
    backup: PathBuf,
}

pub enum VaultOpen {
    Primary {
        vault: UnlockedVault,
        newer_backup: Option<UnlockedVault>,
    },
    RestoreRequired {
        backup: UnlockedVault,
    },
}

impl fmt::Debug for VaultOpen {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary { newer_backup, .. } => formatter
                .debug_struct("Primary")
                .field("vault", &"[REDACTED]")
                .field("newer_backup", &newer_backup.is_some())
                .finish(),
            Self::RestoreRequired { .. } => formatter
                .debug_struct("RestoreRequired")
                .field("backup", &"[REDACTED]")
                .finish(),
        }
    }
}

impl VaultStore {
    #[must_use]
    pub fn new(primary: PathBuf) -> Self {
        let mut backup: OsString = primary.as_os_str().to_owned();
        backup.push(".bak");
        Self {
            primary,
            backup: PathBuf::from(backup),
        }
    }

    #[must_use]
    pub fn backup_path(&self) -> &Path {
        &self.backup
    }

    pub fn commit(&self, vault: &UnlockedVault) -> Result<(), LadonError> {
        let encrypted = vault.seal()?;
        self.commit_encrypted(&encrypted)
    }

    pub(crate) fn commit_encrypted(&self, encrypted: &[u8]) -> Result<(), LadonError> {
        let first = self.candidate_path();
        let second = self.candidate_path();

        let result = (|| {
            write_candidate(&first, encrypted)?;
            write_candidate(&second, encrypted)?;
            verify_candidate(&first, encrypted)?;
            verify_candidate(&second, encrypted)?;

            atomic_replace(&first, &self.backup)?;
            sync_parent(&self.primary)?;
            atomic_replace(&second, &self.primary)?;
            sync_parent(&self.primary)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&first);
            let _ = fs::remove_file(&second);
        }
        result
    }

    pub fn open(&self, passphrase: &SensitiveBytes) -> Result<VaultOpen, LadonError> {
        let primary = fs::read(&self.primary)
            .ok()
            .and_then(|bytes| unlock_vault(&bytes, passphrase).ok());
        let backup = fs::read(&self.backup)
            .ok()
            .and_then(|bytes| unlock_vault(&bytes, passphrase).ok());

        match (primary, backup) {
            (Some(vault), Some(backup)) => {
                let newer_backup =
                    (backup.payload().revision() > vault.payload().revision()).then_some(backup);
                Ok(VaultOpen::Primary {
                    vault,
                    newer_backup,
                })
            }
            (Some(vault), None) => Ok(VaultOpen::Primary {
                vault,
                newer_backup: None,
            }),
            (None, Some(backup)) => Ok(VaultOpen::RestoreRequired { backup }),
            (None, None) => Err(LadonError::VaultUnavailable),
        }
    }

    fn candidate_path(&self) -> PathBuf {
        let filename = self
            .primary
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("vault"))
            .to_string_lossy();
        self.primary.with_file_name(format!(
            ".{filename}.{}.candidate",
            Uuid::new_v4().as_simple()
        ))
    }
}

fn write_candidate(path: &Path, encrypted: &[u8]) -> Result<(), LadonError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| LadonError::StorageFailure)?;
    file.write_all(encrypted)
        .and_then(|()| file.sync_all())
        .map_err(|_| LadonError::StorageFailure)
}

fn verify_candidate(path: &Path, expected: &[u8]) -> Result<(), LadonError> {
    let actual = fs::read(path).map_err(|_| LadonError::StorageFailure)?;
    if actual == expected {
        Ok(())
    } else {
        Err(LadonError::StorageFailure)
    }
}

fn atomic_replace(candidate: &Path, destination: &Path) -> Result<(), LadonError> {
    fs::rename(candidate, destination).map_err(|_| LadonError::StorageFailure)
}

fn sync_parent(path: &Path) -> Result<(), LadonError> {
    let parent = path.parent().ok_or(LadonError::StorageFailure)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LadonError::StorageFailure)
}
