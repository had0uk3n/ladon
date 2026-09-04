use std::{cmp::Ordering, collections::BTreeMap, fmt};

use minicbor::{Decoder, Encoder, data::Type, encode::Write};

use crate::{
    FieldName, LadonError, MAX_FIELDS_PER_RECORD, SecretField, SecretId, SecretRecord, TextHint,
};

pub const MAX_VAULT_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;
const DEFAULT_IDLE_TIMEOUT_SECONDS: u32 = 30 * 60;

pub struct VaultPayload {
    vault_id: SecretId,
    revision: u64,
    records: Vec<SecretRecord>,
    idle_timeout_seconds: u32,
    unknown: BTreeMap<u64, Vec<u8>>,
}

impl VaultPayload {
    pub fn new(
        vault_id: SecretId,
        revision: u64,
        records: Vec<SecretRecord>,
    ) -> Result<Self, LadonError> {
        if records.len() > MAX_RECORDS {
            return Err(LadonError::InvalidVaultPayload);
        }

        Ok(Self {
            vault_id,
            revision,
            records,
            idle_timeout_seconds: DEFAULT_IDLE_TIMEOUT_SECONDS,
            unknown: BTreeMap::new(),
        })
    }

    #[must_use]
    pub const fn vault_id(&self) -> SecretId {
        self.vault_id
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub fn records(&self) -> &[SecretRecord] {
        &self.records
    }
}

impl fmt::Debug for VaultPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPayload")
            .field("vault_id", &self.vault_id)
            .field("revision", &self.revision)
            .field(
                "records",
                &format_args!("[{} REDACTED]", self.records.len()),
            )
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .finish_non_exhaustive()
    }
}

pub fn encode_payload(payload: &VaultPayload) -> Result<Vec<u8>, LadonError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map((4 + payload.unknown.len()) as u64)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.bytes(&payload.vault_id.as_bytes()))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u64(payload.revision))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.array(payload.records.len() as u64))
        .map_err(|_| LadonError::InvalidVaultPayload)?;

    for record in &payload.records {
        encode_record(&mut encoder, record)?;
    }

    encoder
        .u8(3)
        .and_then(|encoder| encoder.map(1))
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u32(payload.idle_timeout_seconds))
        .map_err(|_| LadonError::InvalidVaultPayload)?;

    for (key, raw_value) in &payload.unknown {
        encoder
            .u64(*key)
            .map_err(|_| LadonError::InvalidVaultPayload)?;
        encoder
            .writer_mut()
            .write_all(raw_value)
            .map_err(|_| LadonError::InvalidVaultPayload)?;
    }

    let encoded = encoder.into_writer();
    if encoded.len() > MAX_VAULT_PAYLOAD_BYTES {
        Err(LadonError::VaultPayloadTooLarge)
    } else {
        Ok(encoded)
    }
}

pub fn decode_payload(input: &[u8]) -> Result<VaultPayload, LadonError> {
    if input.len() > MAX_VAULT_PAYLOAD_BYTES {
        return Err(LadonError::VaultPayloadTooLarge);
    }

    let mut decoder = Decoder::new(input);
    let entries = definite_len(decoder.map(), 4 + MAX_RECORDS)?;
    let mut vault_id = None;
    let mut revision = None;
    let mut records = None;
    let mut idle_timeout_seconds = None;
    let mut unknown = BTreeMap::new();
    let mut previous_key = None;

    for _ in 0..entries {
        let key = decoder.u64().map_err(|_| LadonError::InvalidVaultPayload)?;
        if previous_key.is_some_and(|previous| key <= previous) {
            return Err(LadonError::InvalidVaultPayload);
        }
        previous_key = Some(key);

        match key {
            0 if vault_id.is_none() => vault_id = Some(decode_id(&mut decoder)?),
            1 if revision.is_none() => {
                revision = Some(decoder.u64().map_err(|_| LadonError::InvalidVaultPayload)?);
            }
            2 if records.is_none() => records = Some(decode_records(&mut decoder)?),
            3 if idle_timeout_seconds.is_none() => {
                idle_timeout_seconds = Some(decode_settings(&mut decoder)?);
            }
            0..=3 => return Err(LadonError::InvalidVaultPayload),
            _ => {
                let start = decoder.position();
                decoder
                    .skip()
                    .map_err(|_| LadonError::InvalidVaultPayload)?;
                let raw_value = &input[start..decoder.position()];
                if !is_canonical_unknown_value(raw_value) {
                    return Err(LadonError::InvalidVaultPayload);
                }
                unknown.insert(key, raw_value.to_vec());
            }
        }
    }

    if decoder.position() != input.len() {
        return Err(LadonError::InvalidVaultPayload);
    }

    let payload = VaultPayload {
        vault_id: vault_id.ok_or(LadonError::InvalidVaultPayload)?,
        revision: revision.ok_or(LadonError::InvalidVaultPayload)?,
        records: records.ok_or(LadonError::InvalidVaultPayload)?,
        idle_timeout_seconds: idle_timeout_seconds.ok_or(LadonError::InvalidVaultPayload)?,
        unknown,
    };

    if encode_payload(&payload)? != input {
        return Err(LadonError::InvalidVaultPayload);
    }

    Ok(payload)
}

fn is_canonical_unknown_value(input: &[u8]) -> bool {
    let mut decoder = Decoder::new(input);
    let mut canonical = Vec::with_capacity(input.len());
    canonicalize_item(&mut decoder, &mut canonical, 0).is_ok()
        && decoder.position() == input.len()
        && canonical == input
}

fn canonicalize_item(
    decoder: &mut Decoder<'_>,
    output: &mut Vec<u8>,
    depth: usize,
) -> Result<(), LadonError> {
    if depth >= 16 {
        return Err(LadonError::InvalidVaultPayload);
    }

    let data_type = decoder
        .datatype()
        .map_err(|_| LadonError::InvalidVaultPayload)?;
    let mut encoder = Encoder::new(&mut *output);
    match data_type {
        Type::Bool => encoder
            .bool(
                decoder
                    .bool()
                    .map_err(|_| LadonError::InvalidVaultPayload)?,
            )
            .map(|_| ()),
        Type::Null => {
            decoder
                .null()
                .map_err(|_| LadonError::InvalidVaultPayload)?;
            encoder.null().map(|_| ())
        }
        Type::Undefined => {
            decoder
                .undefined()
                .map_err(|_| LadonError::InvalidVaultPayload)?;
            encoder.undefined().map(|_| ())
        }
        Type::U8 => encoder
            .u8(decoder.u8().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::U16 => encoder
            .u16(decoder.u16().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::U32 => encoder
            .u32(decoder.u32().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::U64 => encoder
            .u64(decoder.u64().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::I8 => encoder
            .i8(decoder.i8().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::I16 => encoder
            .i16(decoder.i16().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::I32 => encoder
            .i32(decoder.i32().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::I64 => encoder
            .i64(decoder.i64().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::Int => encoder
            .int(decoder.int().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::Simple => encoder
            .simple(
                decoder
                    .simple()
                    .map_err(|_| LadonError::InvalidVaultPayload)?,
            )
            .map(|_| ()),
        Type::Bytes => encoder
            .bytes(
                decoder
                    .bytes()
                    .map_err(|_| LadonError::InvalidVaultPayload)?,
            )
            .map(|_| ()),
        Type::String => encoder
            .str(decoder.str().map_err(|_| LadonError::InvalidVaultPayload)?)
            .map(|_| ()),
        Type::Tag => {
            let tag = decoder.tag().map_err(|_| LadonError::InvalidVaultPayload)?;
            encoder
                .tag(tag)
                .map_err(|_| LadonError::InvalidVaultPayload)?;
            canonicalize_item(decoder, output, depth + 1)?;
            return Ok(());
        }
        Type::Array => {
            let length = decoder
                .array()
                .map_err(|_| LadonError::InvalidVaultPayload)?
                .ok_or(LadonError::InvalidVaultPayload)?;
            if length > input_item_limit(decoder) {
                return Err(LadonError::InvalidVaultPayload);
            }
            encoder
                .array(length)
                .map_err(|_| LadonError::InvalidVaultPayload)?;
            for _ in 0..length {
                canonicalize_item(decoder, output, depth + 1)?;
            }
            return Ok(());
        }
        Type::Map => {
            let length = decoder
                .map()
                .map_err(|_| LadonError::InvalidVaultPayload)?
                .ok_or(LadonError::InvalidVaultPayload)?;
            if length > input_item_limit(decoder) / 2 {
                return Err(LadonError::InvalidVaultPayload);
            }
            encoder
                .map(length)
                .map_err(|_| LadonError::InvalidVaultPayload)?;
            let mut previous_key: Option<Vec<u8>> = None;
            for _ in 0..length {
                let key_start = output.len();
                canonicalize_item(decoder, output, depth + 1)?;
                let current_key = &output[key_start..];
                if previous_key.as_deref().is_some_and(|previous| {
                    canonical_key_order(previous, current_key) != Ordering::Less
                }) {
                    return Err(LadonError::InvalidVaultPayload);
                }
                previous_key = Some(current_key.to_vec());
                canonicalize_item(decoder, output, depth + 1)?;
            }
            return Ok(());
        }
        Type::F16
        | Type::F32
        | Type::F64
        | Type::BytesIndef
        | Type::StringIndef
        | Type::ArrayIndef
        | Type::MapIndef
        | Type::Break
        | Type::Unknown(_) => return Err(LadonError::InvalidVaultPayload),
    }
    .map_err(|_| LadonError::InvalidVaultPayload)
}

fn input_item_limit(decoder: &Decoder<'_>) -> u64 {
    decoder.input().len().saturating_sub(decoder.position()) as u64
}

fn canonical_key_order(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn encode_record(encoder: &mut Encoder<Vec<u8>>, record: &SecretRecord) -> Result<(), LadonError> {
    encoder
        .map(3)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.bytes(&record.id().as_bytes()))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.str(record.name()))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.array(record.fields().len() as u64))
        .map_err(|_| LadonError::InvalidVaultPayload)?;

    for field in record.fields() {
        encoder
            .map(3)
            .and_then(|encoder| encoder.u8(0))
            .and_then(|encoder| encoder.str(field.name().as_str()))
            .and_then(|encoder| encoder.u8(1))
            .map_err(|_| LadonError::InvalidVaultPayload)?;
        field
            .value()
            .expose(|value| encoder.bytes(value))
            .map_err(|_| LadonError::InvalidVaultPayload)?;
        encoder
            .u8(2)
            .and_then(|encoder| {
                encoder.u8(match field.text_hint() {
                    TextHint::Binary => 0,
                    TextHint::Text => 1,
                })
            })
            .map_err(|_| LadonError::InvalidVaultPayload)?;
    }

    Ok(())
}

fn decode_records(decoder: &mut Decoder<'_>) -> Result<Vec<SecretRecord>, LadonError> {
    let count = definite_len(decoder.array(), MAX_RECORDS)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(decode_record(decoder)?);
    }
    Ok(records)
}

fn decode_record(decoder: &mut Decoder<'_>) -> Result<SecretRecord, LadonError> {
    if definite_len(decoder.map(), 3)? != 3 || decoder.u8().ok() != Some(0) {
        return Err(LadonError::InvalidVaultPayload);
    }
    let id = decode_id(decoder)?;
    if decoder.u8().ok() != Some(1) {
        return Err(LadonError::InvalidVaultPayload);
    }
    let name = decoder
        .str()
        .map_err(|_| LadonError::InvalidVaultPayload)?
        .to_owned();
    if decoder.u8().ok() != Some(2) {
        return Err(LadonError::InvalidVaultPayload);
    }
    let field_count = definite_len(decoder.array(), MAX_FIELDS_PER_RECORD)?;
    if field_count == 0 {
        return Err(LadonError::InvalidVaultPayload);
    }
    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        fields.push(decode_field(decoder)?);
    }
    SecretRecord::from_parts(id, &name, fields).map_err(|_| LadonError::InvalidVaultPayload)
}

fn decode_field(decoder: &mut Decoder<'_>) -> Result<SecretField, LadonError> {
    if definite_len(decoder.map(), 3)? != 3 || decoder.u8().ok() != Some(0) {
        return Err(LadonError::InvalidVaultPayload);
    }
    let name = FieldName::parse(decoder.str().map_err(|_| LadonError::InvalidVaultPayload)?)
        .map_err(|_| LadonError::InvalidVaultPayload)?;
    if decoder.u8().ok() != Some(1) {
        return Err(LadonError::InvalidVaultPayload);
    }
    let value = decoder
        .bytes()
        .map_err(|_| LadonError::InvalidVaultPayload)?;
    if decoder.u8().ok() != Some(2) {
        return Err(LadonError::InvalidVaultPayload);
    }
    let text_hint = match decoder.u8().map_err(|_| LadonError::InvalidVaultPayload)? {
        0 => TextHint::Binary,
        1 => TextHint::Text,
        _ => return Err(LadonError::InvalidVaultPayload),
    };
    SecretField::new(name, value.to_vec(), text_hint).map_err(|_| LadonError::InvalidVaultPayload)
}

fn decode_id(decoder: &mut Decoder<'_>) -> Result<SecretId, LadonError> {
    let bytes = decoder
        .bytes()
        .map_err(|_| LadonError::InvalidVaultPayload)?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| LadonError::InvalidVaultPayload)?;
    Ok(SecretId::from_bytes(bytes))
}

fn decode_settings(decoder: &mut Decoder<'_>) -> Result<u32, LadonError> {
    if definite_len(decoder.map(), 1)? != 1 || decoder.u8().ok() != Some(0) {
        return Err(LadonError::InvalidVaultPayload);
    }
    decoder.u32().map_err(|_| LadonError::InvalidVaultPayload)
}

fn definite_len(
    result: Result<Option<u64>, minicbor::decode::Error>,
    maximum: usize,
) -> Result<usize, LadonError> {
    let length = result
        .map_err(|_| LadonError::InvalidVaultPayload)?
        .ok_or(LadonError::InvalidVaultPayload)?;
    let length = usize::try_from(length).map_err(|_| LadonError::InvalidVaultPayload)?;
    if length > maximum {
        Err(LadonError::InvalidVaultPayload)
    } else {
        Ok(length)
    }
}
