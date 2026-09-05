use std::{fs, fs::OpenOptions, path::Path};

use ladon_core::{
    LadonError, MAX_VAULT_FILE_BYTES, SecretId, SensitiveBytes, VaultOpen, VaultPayload,
    VaultStore, create_vault,
};
use tempfile::tempdir;

fn password() -> SensitiveBytes {
    SensitiveBytes::new(b"correct horse battery staple".to_vec())
}

fn unlocked() -> ladon_core::UnlockedVault {
    unlocked_at_revision(0)
}

fn unlocked_at_revision(revision: u64) -> ladon_core::UnlockedVault {
    let payload = VaultPayload::new(
        SecretId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap(),
        revision,
        vec![],
    )
    .unwrap();
    create_vault(payload, &password()).unwrap().0
}

#[test]
fn valid_primary_remains_authoritative_while_newer_backup_is_offered() {
    let directory = tempdir().unwrap();
    let primary = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary.clone());
    let old_primary = unlocked_at_revision(1).seal().unwrap();
    let newer_backup = unlocked_at_revision(2).seal().unwrap();
    fs::write(&primary, old_primary).unwrap();
    fs::write(store.backup_path(), newer_backup).unwrap();

    let VaultOpen::Primary {
        vault,
        newer_backup,
    } = store.open(&password()).unwrap()
    else {
        panic!("valid primary must remain authoritative");
    };

    assert_eq!(vault.payload().revision(), 1);
    assert_eq!(newer_backup.unwrap().payload().revision(), 2);
}

#[test]
fn backup_from_a_different_vault_is_never_offered_over_a_valid_primary() {
    let directory = tempfile::tempdir().unwrap();
    let primary_path = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary_path.clone());
    let password = SensitiveBytes::new(b"correct horse".to_vec());
    let primary = create_vault(
        VaultPayload::new(SecretId::new(), 1, vec![]).unwrap(),
        &password,
    )
    .unwrap()
    .1;
    let unrelated_backup = create_vault(
        VaultPayload::new(SecretId::new(), 99, vec![]).unwrap(),
        &password,
    )
    .unwrap()
    .1;
    fs::write(&primary_path, primary).unwrap();
    fs::write(store.backup_path(), unrelated_backup).unwrap();

    match store.open(&password).unwrap() {
        VaultOpen::Primary { newer_backup, .. } => assert!(newer_backup.is_none()),
        VaultOpen::RestoreRequired { .. } => panic!("valid primary must remain authoritative"),
    }
}

#[test]
fn commit_installs_two_identical_authenticated_copies() {
    let directory = tempdir().unwrap();
    let primary = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary.clone());

    store.commit(&unlocked()).unwrap();

    assert_eq!(
        fs::read(&primary).unwrap(),
        fs::read(store.backup_path()).unwrap()
    );
    assert!(matches!(
        store.open(&password()).unwrap(),
        VaultOpen::Primary { .. }
    ));
    assert_no_temporary_candidates(directory.path());
}

#[test]
fn corrupt_primary_requires_explicit_backup_restore() {
    let directory = tempdir().unwrap();
    let primary = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary.clone());
    store.commit(&unlocked()).unwrap();
    fs::write(&primary, b"corrupt").unwrap();

    let opened = store.open(&password()).unwrap();

    assert!(matches!(opened, VaultOpen::RestoreRequired { .. }));
}

#[test]
fn refuses_when_both_managed_copies_are_invalid() {
    let directory = tempdir().unwrap();
    let primary = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary.clone());
    fs::write(&primary, b"corrupt-primary").unwrap();
    fs::write(store.backup_path(), b"corrupt-backup").unwrap();

    assert_eq!(
        store.open(&password()).unwrap_err(),
        LadonError::VaultUnavailable
    );
}

#[test]
fn ignores_stale_candidates_and_uses_owner_only_permissions() {
    let directory = tempdir().unwrap();
    let primary = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary.clone());
    fs::write(directory.path().join(".vault.ladon.stale.tmp"), b"stale").unwrap();

    store.commit(&unlocked()).unwrap();

    assert_no_temporary_candidates(directory.path());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(primary).unwrap().permissions().mode() & 0o077,
            0
        );
    }
}

#[test]
fn rejects_oversized_sparse_copies_before_reading_their_contents() {
    let directory = tempdir().unwrap();
    let primary = directory.path().join("vault.ladon");
    let store = VaultStore::new(primary.clone());
    for path in [&primary, store.backup_path()] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .set_len((MAX_VAULT_FILE_BYTES + 1) as u64)
            .unwrap();
    }

    assert_eq!(
        store.open(&password()).unwrap_err(),
        LadonError::VaultUnavailable
    );
}

fn assert_no_temporary_candidates(directory: &Path) {
    let candidates = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".candidate"))
        .collect::<Vec<_>>();
    assert!(candidates.is_empty(), "leftover candidates: {candidates:?}");
}
