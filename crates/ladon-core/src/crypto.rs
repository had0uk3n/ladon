use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use minicbor::{Decoder, Encoder};

use crate::{
    LadonError, MAX_VAULT_PAYLOAD_BYTES, SensitiveBytes, VaultPayload, decode_payload,
    encode_payload,
};

const MAGIC: &[u8; 8] = b"LADONV1\0";
const VERSION: u16 = 1;
const FIXED_PREFIX_BYTES: usize = 14;
const MAX_HEADER_BYTES: usize = 4 * 1024;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const WRAPPED_DEK_BYTES: usize = KEY_BYTES + TAG_BYTES;
const WRAPPER_BYTES: usize = NONCE_BYTES + WRAPPED_DEK_BYTES;
const PAYLOAD_FIXED_BYTES: usize = 8 + NONCE_BYTES + TAG_BYTES;
pub const MAX_VAULT_FILE_BYTES: usize = FIXED_PREFIX_BYTES
    + MAX_HEADER_BYTES
    + WRAPPER_BYTES
    + PAYLOAD_FIXED_BYTES
    + MAX_VAULT_PAYLOAD_BYTES;
const DEK_DOMAIN: &[u8] = b"ladon/dek/v1";
const PAYLOAD_DOMAIN: &[u8] = b"ladon/payload/v1";

const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_PASSES: u32 = 3;
const DEFAULT_PARALLELISM: u32 = 4;
const DEFAULT_SALT_BYTES: usize = 16;

const MIN_MEMORY_KIB: u32 = 32 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MIN_PASSES: u32 = 1;
const MAX_PASSES: u32 = 10;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 16;
const MIN_SALT_BYTES: usize = 16;
const MAX_SALT_BYTES: usize = 64;

struct KdfHeader {
    memory_kib: u32,
    passes: u32,
    parallelism: u32,
    salt: Vec<u8>,
}

struct KeyMaterial {
    prefix_through_dek_tag: Vec<u8>,
    dek: SensitiveBytes,
}

trait RandomSource {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), LadonError>;
}

struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), LadonError> {
        getrandom::fill(bytes).map_err(|_| LadonError::CryptoUnavailable)
    }
}

pub struct UnlockedVault {
    payload: VaultPayload,
    key_material: KeyMaterial,
}

impl UnlockedVault {
    #[must_use]
    pub const fn payload(&self) -> &VaultPayload {
        &self.payload
    }

    pub(crate) fn payload_mut(&mut self) -> &mut VaultPayload {
        &mut self.payload
    }

    pub fn seal(&self) -> Result<Vec<u8>, LadonError> {
        seal_payload(&self.payload, &self.key_material, &mut OsRandom)
    }

    pub fn rotate_passphrase(
        &mut self,
        current_passphrase: &SensitiveBytes,
        new_passphrase: &SensitiveBytes,
    ) -> Result<Vec<u8>, LadonError> {
        verify_current_passphrase(&self.key_material, current_passphrase)?;

        let mut random = OsRandom;
        let new_material = new_key_material(new_passphrase, &mut random)?;
        let encrypted = seal_payload(&self.payload, &new_material, &mut random)?;
        self.key_material = new_material;
        Ok(encrypted)
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedVault")
            .field("payload", &self.payload)
            .field("key_material", &"[REDACTED]")
            .finish()
    }
}

pub fn create_vault(
    payload: VaultPayload,
    passphrase: &SensitiveBytes,
) -> Result<(UnlockedVault, Vec<u8>), LadonError> {
    create_vault_with_random(payload, passphrase, &mut OsRandom)
}

fn create_vault_with_random(
    payload: VaultPayload,
    passphrase: &SensitiveBytes,
    random: &mut impl RandomSource,
) -> Result<(UnlockedVault, Vec<u8>), LadonError> {
    let key_material = new_key_material(passphrase, random)?;
    let unlocked = UnlockedVault {
        payload,
        key_material,
    };
    let encrypted = seal_payload(&unlocked.payload, &unlocked.key_material, random)?;
    Ok((unlocked, encrypted))
}

pub fn unlock_vault(file: &[u8], passphrase: &SensitiveBytes) -> Result<UnlockedVault, LadonError> {
    let parsed = parse_file(file)?;
    let kek = derive_kek(passphrase, &parsed.header)?;
    let dek = decrypt(
        &kek,
        parsed.dek_nonce,
        parsed.wrapped_dek,
        &associated_data(DEK_DOMAIN, parsed.prefix_before_dek),
    )
    .map_err(|_| LadonError::VaultAuthenticationFailed)?;
    if dek.len() != KEY_BYTES {
        return Err(LadonError::VaultAuthenticationFailed);
    }
    let plaintext = decrypt(
        &dek,
        parsed.payload_nonce,
        parsed.encrypted_payload,
        &associated_data(PAYLOAD_DOMAIN, parsed.prefix_through_payload_len),
    )
    .map_err(|_| LadonError::VaultAuthenticationFailed)?;
    let payload = plaintext
        .expose(decode_payload)
        .map_err(|_| LadonError::VaultAuthenticationFailed)?;

    Ok(UnlockedVault {
        payload,
        key_material: KeyMaterial {
            prefix_through_dek_tag: parsed.prefix_through_dek_tag.to_vec(),
            dek,
        },
    })
}

fn new_key_material(
    passphrase: &SensitiveBytes,
    random: &mut impl RandomSource,
) -> Result<KeyMaterial, LadonError> {
    let mut salt = vec![0; DEFAULT_SALT_BYTES];
    random.fill(&mut salt)?;
    let header = KdfHeader {
        memory_kib: DEFAULT_MEMORY_KIB,
        passes: DEFAULT_PASSES,
        parallelism: DEFAULT_PARALLELISM,
        salt,
    };
    let encoded_header = encode_header(&header)?;
    let header_len =
        u32::try_from(encoded_header.len()).map_err(|_| LadonError::InvalidVaultFile)?;

    let mut prefix_before_dek = Vec::with_capacity(FIXED_PREFIX_BYTES + encoded_header.len());
    prefix_before_dek.extend_from_slice(MAGIC);
    prefix_before_dek.extend_from_slice(&VERSION.to_be_bytes());
    prefix_before_dek.extend_from_slice(&header_len.to_be_bytes());
    prefix_before_dek.extend_from_slice(&encoded_header);

    let mut dek = SensitiveBytes::new(vec![0; KEY_BYTES]);
    dek.expose_mut(|bytes| random.fill(bytes))?;
    let kek = derive_kek(passphrase, &header)?;
    let mut nonce = [0; NONCE_BYTES];
    random.fill(&mut nonce)?;
    let wrapped_dek = dek.expose(|bytes| {
        encrypt(
            &kek,
            &nonce,
            bytes,
            &associated_data(DEK_DOMAIN, &prefix_before_dek),
        )
    })?;

    let mut prefix_through_dek_tag = Vec::with_capacity(prefix_before_dek.len() + WRAPPER_BYTES);
    prefix_through_dek_tag.extend_from_slice(&prefix_before_dek);
    prefix_through_dek_tag.extend_from_slice(&nonce);
    prefix_through_dek_tag.extend_from_slice(&wrapped_dek);

    Ok(KeyMaterial {
        prefix_through_dek_tag,
        dek,
    })
}

fn seal_payload(
    payload: &VaultPayload,
    key_material: &KeyMaterial,
    random: &mut impl RandomSource,
) -> Result<Vec<u8>, LadonError> {
    let plaintext = SensitiveBytes::new(encode_payload(payload)?);
    let payload_len = u64::try_from(plaintext.len()).map_err(|_| LadonError::InvalidVaultFile)?;
    let mut output = Vec::with_capacity(
        key_material.prefix_through_dek_tag.len() + PAYLOAD_FIXED_BYTES + plaintext.len(),
    );
    output.extend_from_slice(&key_material.prefix_through_dek_tag);
    output.extend_from_slice(&payload_len.to_be_bytes());

    let mut nonce = [0; NONCE_BYTES];
    random.fill(&mut nonce)?;
    let encrypted = plaintext.expose(|bytes| {
        encrypt(
            &key_material.dek,
            &nonce,
            bytes,
            &associated_data(PAYLOAD_DOMAIN, &output),
        )
    })?;
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn verify_current_passphrase(
    key_material: &KeyMaterial,
    passphrase: &SensitiveBytes,
) -> Result<(), LadonError> {
    let prefix = &key_material.prefix_through_dek_tag;
    let header_len = read_u32(prefix, 10)? as usize;
    let header_end = FIXED_PREFIX_BYTES
        .checked_add(header_len)
        .ok_or(LadonError::InvalidVaultFile)?;
    if prefix.len() != header_end + WRAPPER_BYTES {
        return Err(LadonError::InvalidVaultFile);
    }
    let header = decode_header(&prefix[FIXED_PREFIX_BYTES..header_end])?;
    let nonce: &[u8; NONCE_BYTES] = prefix[header_end..header_end + NONCE_BYTES]
        .try_into()
        .map_err(|_| LadonError::InvalidVaultFile)?;
    let wrapped = &prefix[header_end + NONCE_BYTES..];
    let kek = derive_kek(passphrase, &header)?;
    let candidate = decrypt(
        &kek,
        nonce,
        wrapped,
        &associated_data(DEK_DOMAIN, &prefix[..header_end]),
    )
    .map_err(|_| LadonError::VaultAuthenticationFailed)?;
    if candidate.len() != KEY_BYTES {
        return Err(LadonError::VaultAuthenticationFailed);
    }
    Ok(())
}

struct ParsedFile<'a> {
    header: KdfHeader,
    prefix_before_dek: &'a [u8],
    dek_nonce: &'a [u8; NONCE_BYTES],
    wrapped_dek: &'a [u8],
    prefix_through_dek_tag: &'a [u8],
    prefix_through_payload_len: &'a [u8],
    payload_nonce: &'a [u8; NONCE_BYTES],
    encrypted_payload: &'a [u8],
}

fn parse_file(file: &[u8]) -> Result<ParsedFile<'_>, LadonError> {
    if file.len() < FIXED_PREFIX_BYTES + WRAPPER_BYTES + PAYLOAD_FIXED_BYTES {
        return Err(LadonError::InvalidVaultFile);
    }
    if file.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(LadonError::InvalidVaultFile);
    }
    let version = read_u16(file, 8)?;
    if version != VERSION {
        return Err(LadonError::UnsupportedVaultVersion);
    }

    let header_len = read_u32(file, 10)? as usize;
    if header_len > MAX_HEADER_BYTES {
        return Err(LadonError::InvalidVaultFile);
    }
    let header_end = FIXED_PREFIX_BYTES
        .checked_add(header_len)
        .ok_or(LadonError::InvalidVaultFile)?;
    let prefix_end = header_end
        .checked_add(WRAPPER_BYTES)
        .ok_or(LadonError::InvalidVaultFile)?;
    let payload_len_end = prefix_end
        .checked_add(8)
        .ok_or(LadonError::InvalidVaultFile)?;
    if payload_len_end > file.len() {
        return Err(LadonError::InvalidVaultFile);
    }

    let header = decode_header(&file[FIXED_PREFIX_BYTES..header_end])?;
    let payload_len = read_u64(file, prefix_end)?;
    if payload_len > MAX_VAULT_PAYLOAD_BYTES as u64 {
        return Err(LadonError::InvalidVaultFile);
    }
    let payload_len = usize::try_from(payload_len).map_err(|_| LadonError::InvalidVaultFile)?;
    let expected_len = payload_len_end
        .checked_add(NONCE_BYTES)
        .and_then(|value| value.checked_add(payload_len))
        .and_then(|value| value.checked_add(TAG_BYTES))
        .ok_or(LadonError::InvalidVaultFile)?;
    if expected_len != file.len() {
        return Err(LadonError::InvalidVaultFile);
    }

    let dek_nonce = file[header_end..header_end + NONCE_BYTES]
        .try_into()
        .map_err(|_| LadonError::InvalidVaultFile)?;
    let wrapped_dek = &file[header_end + NONCE_BYTES..prefix_end];
    let payload_nonce = file[payload_len_end..payload_len_end + NONCE_BYTES]
        .try_into()
        .map_err(|_| LadonError::InvalidVaultFile)?;
    let encrypted_payload = &file[payload_len_end + NONCE_BYTES..];

    Ok(ParsedFile {
        header,
        prefix_before_dek: &file[..header_end],
        dek_nonce,
        wrapped_dek,
        prefix_through_dek_tag: &file[..prefix_end],
        prefix_through_payload_len: &file[..payload_len_end],
        payload_nonce,
        encrypted_payload,
    })
}

fn encode_header(header: &KdfHeader) -> Result<Vec<u8>, LadonError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(5)
        .and_then(|encoder| encoder.str("kdf"))
        .and_then(|encoder| encoder.str("argon2id"))
        .and_then(|encoder| encoder.str("salt"))
        .and_then(|encoder| encoder.bytes(&header.salt))
        .and_then(|encoder| encoder.str("passes"))
        .and_then(|encoder| encoder.u32(header.passes))
        .and_then(|encoder| encoder.str("memory_kib"))
        .and_then(|encoder| encoder.u32(header.memory_kib))
        .and_then(|encoder| encoder.str("parallelism"))
        .and_then(|encoder| encoder.u32(header.parallelism))
        .map_err(|_| LadonError::InvalidVaultFile)?;
    let encoded = encoder.into_writer();
    if encoded.len() > MAX_HEADER_BYTES {
        Err(LadonError::InvalidVaultFile)
    } else {
        Ok(encoded)
    }
}

fn decode_header(input: &[u8]) -> Result<KdfHeader, LadonError> {
    if input.len() > MAX_HEADER_BYTES {
        return Err(LadonError::InvalidVaultFile);
    }
    let mut decoder = Decoder::new(input);
    if decoder.map().ok().flatten() != Some(5) {
        return Err(LadonError::InvalidVaultFile);
    }
    expect_key(&mut decoder, "kdf")?;
    if decoder.str().ok() != Some("argon2id") {
        return Err(LadonError::InvalidVaultFile);
    }
    expect_key(&mut decoder, "salt")?;
    let salt = decoder
        .bytes()
        .map_err(|_| LadonError::InvalidVaultFile)?
        .to_vec();
    expect_key(&mut decoder, "passes")?;
    let passes = decoder.u32().map_err(|_| LadonError::InvalidVaultFile)?;
    expect_key(&mut decoder, "memory_kib")?;
    let memory_kib = decoder.u32().map_err(|_| LadonError::InvalidVaultFile)?;
    expect_key(&mut decoder, "parallelism")?;
    let parallelism = decoder.u32().map_err(|_| LadonError::InvalidVaultFile)?;

    let header = KdfHeader {
        memory_kib,
        passes,
        parallelism,
        salt,
    };
    let valid_bounds = (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&header.memory_kib)
        && (MIN_PASSES..=MAX_PASSES).contains(&header.passes)
        && (MIN_PARALLELISM..=MAX_PARALLELISM).contains(&header.parallelism)
        && (MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&header.salt.len());
    if !valid_bounds || decoder.position() != input.len() || encode_header(&header)? != input {
        return Err(LadonError::InvalidVaultFile);
    }
    Ok(header)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: &str) -> Result<(), LadonError> {
    if decoder.str().ok() == Some(expected) {
        Ok(())
    } else {
        Err(LadonError::InvalidVaultFile)
    }
}

fn derive_kek(
    passphrase: &SensitiveBytes,
    header: &KdfHeader,
) -> Result<SensitiveBytes, LadonError> {
    let params = Params::new(
        header.memory_kib,
        header.passes,
        header.parallelism,
        Some(KEY_BYTES),
    )
    .map_err(|_| LadonError::InvalidVaultFile)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = SensitiveBytes::new(vec![0; KEY_BYTES]);
    passphrase
        .expose(|bytes| {
            output.expose_mut(|derived| argon2.hash_password_into(bytes, &header.salt, derived))
        })
        .map_err(|_| LadonError::InvalidVaultFile)?;
    Ok(output)
}

fn encrypt(
    key: &SensitiveBytes,
    nonce: &[u8; NONCE_BYTES],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, LadonError> {
    key.expose(|bytes| {
        let cipher =
            XChaCha20Poly1305::new_from_slice(bytes).map_err(|_| LadonError::InvalidVaultFile)?;
        cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| LadonError::InvalidVaultFile)
    })
}

fn decrypt(
    key: &SensitiveBytes,
    nonce: &[u8; NONCE_BYTES],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<SensitiveBytes, LadonError> {
    key.expose(|bytes| {
        let cipher = XChaCha20Poly1305::new_from_slice(bytes)
            .map_err(|_| LadonError::VaultAuthenticationFailed)?;
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext_and_tag,
                    aad,
                },
            )
            .map(SensitiveBytes::new)
            .map_err(|_| LadonError::VaultAuthenticationFailed)
    })
}

fn associated_data(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut associated = Vec::with_capacity(domain.len() + bytes.len());
    associated.extend_from_slice(domain);
    associated.extend_from_slice(bytes);
    associated
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, LadonError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(LadonError::InvalidVaultFile)
}

fn read_u32(input: &[u8], offset: usize) -> Result<u32, LadonError> {
    input
        .get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(LadonError::InvalidVaultFile)
}

fn read_u64(input: &[u8], offset: usize) -> Result<u64, LadonError> {
    input
        .get(offset..offset + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(LadonError::InvalidVaultFile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretId;

    struct CounterRandom(u8);

    impl RandomSource for CounterRandom {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), LadonError> {
            for byte in bytes {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn complete_v1_file_matches_fixed_vector() {
        use std::fmt::Write as _;

        let payload = VaultPayload::new(
            SecretId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            0,
            vec![],
        )
        .unwrap();
        let passphrase = SensitiveBytes::new(b"correct horse battery staple".to_vec());
        let mut random = CounterRandom(0);

        let (_, file) = create_vault_with_random(payload, &passphrase, &mut random).unwrap();
        let mut actual = String::with_capacity(file.len() * 2);
        for byte in file {
            write!(&mut actual, "{byte:02x}").unwrap();
        }

        assert_eq!(
            actual,
            include_str!("../tests/fixtures/v1-empty-vault.hex").trim()
        );
    }
}
