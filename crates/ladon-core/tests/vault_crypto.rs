use ladon_core::{LadonError, SecretId, SensitiveBytes, VaultPayload, create_vault, unlock_vault};

fn passphrase(value: &str) -> SensitiveBytes {
    SensitiveBytes::new(value.as_bytes().to_vec())
}

fn empty_payload() -> VaultPayload {
    VaultPayload::new(
        SecretId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
        0,
        vec![],
    )
    .unwrap()
}

fn wrapped_prefix_end(file: &[u8]) -> usize {
    let header_len = u32::from_be_bytes(file[10..14].try_into().unwrap()) as usize;
    14 + header_len + 24 + 32 + 16
}

fn payload_len_offset(file: &[u8]) -> usize {
    wrapped_prefix_end(file)
}

#[test]
fn creates_and_unlocks_portable_v1_vault() {
    let password = passphrase("correct horse battery staple");

    let (_, file) = create_vault(empty_payload(), &password).unwrap();
    let unlocked = unlock_vault(&file, &password).unwrap();

    assert_eq!(unlocked.payload().revision(), 0);
    assert_eq!(
        unlocked.payload().vault_id(),
        SecretId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    );
    assert_eq!(&file[..8], b"LADONV1\0");
    assert_eq!(u16::from_be_bytes(file[8..10].try_into().unwrap()), 1);
}

#[test]
fn wrong_password_and_authenticated_tampering_are_indistinguishable() {
    let password = passphrase("correct horse battery staple");
    let (_, file) = create_vault(empty_payload(), &password).unwrap();

    assert_eq!(
        unlock_vault(&file, &passphrase("this password is definitely wrong")).unwrap_err(),
        LadonError::VaultAuthenticationFailed
    );

    let header_len = u32::from_be_bytes(file[10..14].try_into().unwrap()) as usize;
    let wrapped_ciphertext = 14 + header_len + 24;
    let payload_ciphertext = payload_len_offset(&file) + 8 + 24;
    let salt = file
        .windows(4)
        .position(|window| window == b"salt")
        .unwrap()
        + 5;
    for index in [salt, wrapped_ciphertext, payload_ciphertext, file.len() - 1] {
        let mut tampered = file.clone();
        tampered[index] ^= 0x01;
        assert_eq!(
            unlock_vault(&tampered, &password).unwrap_err(),
            LadonError::VaultAuthenticationFailed,
            "tampered byte {index}"
        );
    }
}

#[test]
fn rejects_truncated_oversized_and_unsupported_framing_before_kdf() {
    let password = passphrase("correct horse battery staple");
    let (_, file) = create_vault(empty_payload(), &password).unwrap();

    for length in [0, 7, 21, file.len() - 1] {
        assert_eq!(
            unlock_vault(&file[..length], &password).unwrap_err(),
            LadonError::InvalidVaultFile,
            "truncated length {length}"
        );
    }

    let mut unsupported = file.clone();
    unsupported[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        unlock_vault(&unsupported, &password).unwrap_err(),
        LadonError::UnsupportedVaultVersion
    );

    let mut oversized = file.clone();
    let length_offset = payload_len_offset(&oversized);
    oversized[length_offset..length_offset + 8]
        .copy_from_slice(&(64_u64 * 1024 * 1024 + 1).to_be_bytes());
    assert_eq!(
        unlock_vault(&oversized, &password).unwrap_err(),
        LadonError::InvalidVaultFile
    );

    let mut hostile_kdf = file;
    let memory_name = hostile_kdf
        .windows(10)
        .position(|window| window == b"memory_kib")
        .unwrap();
    let memory_value = memory_name + 11;
    hostile_kdf[memory_value..memory_value + 4].copy_from_slice(&262_145_u32.to_be_bytes());
    assert_eq!(
        unlock_vault(&hostile_kdf, &password).unwrap_err(),
        LadonError::InvalidVaultFile
    );
}

#[test]
fn ordinary_reseal_keeps_wrapped_dek_but_changes_payload_nonce() {
    let password = passphrase("correct horse battery staple");
    let (unlocked, first) = create_vault(empty_payload(), &password).unwrap();

    let second = unlocked.seal().unwrap();
    let prefix_end = wrapped_prefix_end(&first);

    assert_eq!(&first[..prefix_end], &second[..prefix_end]);
    assert_ne!(&first[prefix_end..], &second[prefix_end..]);
}

#[test]
fn passphrase_rotation_replaces_all_key_material() {
    let old_password = passphrase("correct horse battery staple");
    let new_password = passphrase("a completely different secure phrase");
    let (mut unlocked, before) = create_vault(empty_payload(), &old_password).unwrap();

    let after = unlocked
        .rotate_passphrase(&old_password, &new_password)
        .unwrap();

    assert_ne!(
        &before[..wrapped_prefix_end(&before)],
        &after[..wrapped_prefix_end(&after)]
    );
    assert_eq!(
        unlock_vault(&after, &old_password).unwrap_err(),
        LadonError::VaultAuthenticationFailed
    );
    assert_eq!(
        unlock_vault(&after, &new_password)
            .unwrap()
            .payload()
            .revision(),
        0
    );
}

#[test]
fn failed_rotation_leaves_current_session_usable() {
    let password = passphrase("correct horse battery staple");
    let (mut unlocked, _) = create_vault(empty_payload(), &password).unwrap();

    assert_eq!(
        unlocked
            .rotate_passphrase(
                &passphrase("this is not the current password"),
                &passphrase("a completely different secure phrase"),
            )
            .unwrap_err(),
        LadonError::VaultAuthenticationFailed
    );

    let resealed = unlocked.seal().unwrap();
    assert_eq!(
        unlock_vault(&resealed, &password)
            .unwrap()
            .payload()
            .revision(),
        0
    );
}
