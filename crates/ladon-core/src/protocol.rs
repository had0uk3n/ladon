use std::{collections::HashSet, fmt};

use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
};
use uuid::Uuid;

use crate::LadonError;

pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const PROTOCOL_VERSION: u16 = 2;
const MAX_JSON_DEPTH: usize = 16;
const MAX_CLIENT_LABEL_BYTES: usize = 64;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 256 * 1024;
const MAX_PATH_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RpcRequest {
    pub version: u16,
    pub request_id: Uuid,
    pub client_session_id: Uuid,
    pub client_label: String,
    #[serde(flatten)]
    pub method: RpcMethod,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum RpcMethod {
    Status,
    List,
    Lock,
    Run {
        executable: String,
        arguments: Vec<String>,
        working_directory: String,
        bindings: Vec<SecretBindingRequest>,
        timeout_ms: u64,
        output_limit_bytes: usize,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretBindingRequest {
    pub secret_ref: String,
    pub field: String,
    pub target: BindingTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BindingTarget {
    Environment {
        name: String,
    },
    StandardInput,
    TemporaryFileEnvironment {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suggested_filename: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RpcResponse {
    pub version: u16,
    pub request_id: Uuid,
    #[serde(flatten)]
    outcome: RpcOutcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum RpcOutcome {
    Success { result: RpcResult },
    Failure { error: RpcErrorBody },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RpcErrorBody {
    code: String,
    message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RpcResult {
    Status {
        state: String,
        idle_remaining_ms: Option<u64>,
    },
    List {
        secrets: Vec<SecretSummary>,
    },
    Locked,
    Run {
        exit_code: Option<i32>,
        termination: String,
        stdout: String,
        stderr: String,
        duration_ms: u64,
        redaction_count: u64,
        output_truncated: bool,
        #[serde(default)]
        temp_cleanup_warning: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretSummary {
    pub id: Uuid,
    pub name: String,
    pub fields: Vec<SecretFieldSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretFieldSummary {
    pub name: String,
    pub text: bool,
}

impl RpcResponse {
    #[must_use]
    pub const fn success(request_id: Uuid, result: RpcResult) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            outcome: RpcOutcome::Success { result },
        }
    }

    #[must_use]
    pub fn error(request_id: Uuid, error: LadonError) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request_id,
            outcome: RpcOutcome::Failure {
                error: RpcErrorBody {
                    code: error.code().to_owned(),
                    message: error.safe_message().to_owned(),
                },
            },
        }
    }

    #[must_use]
    pub const fn result(&self) -> Option<&RpcResult> {
        match &self.outcome {
            RpcOutcome::Success { result } => Some(result),
            RpcOutcome::Failure { .. } => None,
        }
    }

    #[must_use]
    pub fn error_details(&self) -> Option<(&str, &str)> {
        match &self.outcome {
            RpcOutcome::Success { .. } => None,
            RpcOutcome::Failure { error } => Some((&error.code, &error.message)),
        }
    }
}

pub fn encode_request_frame(request: &RpcRequest) -> Result<Vec<u8>, LadonError> {
    encode_frame(request)
}

pub fn encode_response_frame(response: &RpcResponse) -> Result<Vec<u8>, LadonError> {
    encode_frame(response)
}

pub fn decode_response_frame(frame: &[u8]) -> Result<RpcResponse, LadonError> {
    let json = checked_frame_payload(frame)?;
    validate_json_document(json)?;
    let response: RpcResponse =
        serde_json::from_slice(json).map_err(|_| LadonError::InvalidRequest)?;
    if response.version != PROTOCOL_VERSION {
        return Err(LadonError::UnsupportedProtocolVersion);
    }
    Ok(response)
}

fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, LadonError> {
    let json = serde_json::to_vec(value).map_err(|_| LadonError::InvalidRequest)?;
    if json.is_empty() {
        return Err(LadonError::InvalidFrame);
    }
    if json.len() > MAX_FRAME_BYTES {
        return Err(LadonError::FrameTooLarge);
    }
    let length = u32::try_from(json.len()).map_err(|_| LadonError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

pub fn decode_request_frame(frame: &[u8]) -> Result<RpcRequest, LadonError> {
    let json = checked_frame_payload(frame)?;
    validate_json_document(json)?;
    let request: RpcRequest =
        serde_json::from_slice(json).map_err(|_| LadonError::InvalidRequest)?;
    validate_request(&request)?;
    Ok(request)
}

fn checked_frame_payload(frame: &[u8]) -> Result<&[u8], LadonError> {
    let declared = frame
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(LadonError::InvalidFrame)? as usize;
    if declared == 0 {
        return Err(LadonError::InvalidFrame);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(LadonError::FrameTooLarge);
    }
    if frame.len() != 4 + declared {
        return Err(LadonError::InvalidFrame);
    }

    Ok(&frame[4..])
}

fn validate_request(request: &RpcRequest) -> Result<(), LadonError> {
    if request.version != PROTOCOL_VERSION {
        return Err(LadonError::UnsupportedProtocolVersion);
    }
    if request.client_label.is_empty()
        || request.client_label.len() > MAX_CLIENT_LABEL_BYTES
        || request.client_label.contains('\0')
    {
        return Err(LadonError::InvalidRequest);
    }
    if let RpcMethod::Run {
        executable,
        arguments,
        working_directory,
        ..
    } = &request.method
    {
        let argument_bytes = arguments
            .iter()
            .try_fold(0_usize, |total, argument| total.checked_add(argument.len()));
        let invalid = executable.is_empty()
            || executable.len() > MAX_PATH_BYTES
            || executable.contains('\0')
            || working_directory.is_empty()
            || working_directory.len() > MAX_PATH_BYTES
            || working_directory.contains('\0')
            || arguments.len() > MAX_ARGUMENTS
            || arguments.iter().any(|argument| argument.contains('\0'))
            || argument_bytes.is_none_or(|bytes| bytes > MAX_ARGUMENT_BYTES);
        if invalid {
            return Err(LadonError::InvalidRequest);
        }
    }
    Ok(())
}

pub fn validate_json_document(input: &[u8]) -> Result<(), LadonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    CheckedSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|_| LadonError::InvalidRequest)?;
    deserializer.end().map_err(|_| LadonError::InvalidRequest)
}

struct CheckedSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for CheckedSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(CheckedVisitor { depth: self.depth })
    }
}

struct CheckedVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for CheckedVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting limit exceeded"));
        }
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(CheckedSeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(de::Error::custom("JSON nesting limit exceeded"));
        }
        while sequence
            .next_element_seed(CheckedSeed {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        IgnoredAny::deserialize(deserializer).map(|_| ())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
}
