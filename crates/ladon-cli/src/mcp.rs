use std::io::{BufRead, BufReader, Read, Write};

use ladon_core::{
    BindingTarget, DEFAULT_OUTPUT_LIMIT_BYTES, DEFAULT_RUN_TIMEOUT, LadonError, MAX_FRAME_BYTES,
    PROTOCOL_VERSION, RpcMethod, RpcRequest, RunCaller, RunRequest, SecretBindingRequest,
    validate_json_document, validate_run_request,
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{RpcTransport, commands::resolve_executable};

const MCP_LEGACY_VERSION: &str = "2025-11-25";
const MCP_MODERN_VERSION: &str = "2026-07-28";
const MAX_REPORTED_NAME_BYTES: usize = 64;

struct McpSession {
    id: Uuid,
    initialized_name: Option<String>,
    display_name: Option<String>,
}

impl McpSession {
    fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            initialized_name: None,
            display_name: None,
        }
    }

    fn label(&self) -> &str {
        self.display_name
            .as_deref()
            .or(self.initialized_name.as_deref())
            .unwrap_or("MCP client")
    }

    fn validate_name(value: &str) -> Result<String, LadonError> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_REPORTED_NAME_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(LadonError::InvalidRequest);
        }
        Ok(value.to_owned())
    }

    fn identify(&mut self, value: &str) -> Result<(), LadonError> {
        self.display_name = Some(Self::validate_name(value)?);
        Ok(())
    }

    fn record_initialized_name(&mut self, value: &str) {
        if let Ok(name) = Self::validate_name(value) {
            self.initialized_name = Some(name);
        }
    }
}

pub fn serve_mcp(
    input: impl Read,
    output: &mut impl Write,
    transport: &impl RpcTransport,
) -> Result<(), LadonError> {
    let mut input = BufReader::new(input);
    let mut session = McpSession::new();
    loop {
        let mut line = String::new();
        let read = input
            .by_ref()
            .take((MAX_FRAME_BYTES + 1) as u64)
            .read_line(&mut line)
            .map_err(|_| LadonError::InvalidFrame)?;
        if read == 0 {
            return Ok(());
        }
        if line.len() > MAX_FRAME_BYTES {
            return Err(LadonError::FrameTooLarge);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }
        let response = handle_message(trimmed.as_bytes(), &mut session, transport);
        if let Some(response) = response {
            serde_json::to_writer(&mut *output, &response)
                .map_err(|_| LadonError::InvalidRequest)?;
            output
                .write_all(b"\n")
                .map_err(|_| LadonError::InvalidRequest)?;
            output.flush().map_err(|_| LadonError::InvalidRequest)?;
        }
    }
}

fn handle_message(
    input: &[u8],
    session: &mut McpSession,
    transport: &impl RpcTransport,
) -> Option<Value> {
    if validate_json_document(input).is_err() {
        return Some(jsonrpc_error(Value::Null, -32700, "invalid JSON"));
    }
    let request: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => return Some(jsonrpc_error(Value::Null, -32700, "invalid JSON")),
    };
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || method.is_none() {
        return id.map(|id| jsonrpc_error(id, -32600, "invalid request"));
    }
    let method = method.unwrap_or_default();
    let id = id?;
    match method {
        "initialize" => {
            if let Some(name) = request
                .get("params")
                .and_then(|params| params.get("clientInfo"))
                .and_then(|client_info| client_info.get("name"))
                .and_then(Value::as_str)
            {
                session.record_initialized_name(name);
            }
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": MCP_LEGACY_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "ladon", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "Use named secret references with Ladon tools. Never ask the user to paste a secret value. When useful, call ladon_identify_session once with a short non-secret task name before a secret-bearing run."
                }
            }))
        }
        "server/discover" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "resultType": "complete",
                "supportedVersions": [MCP_MODERN_VERSION, MCP_LEGACY_VERSION],
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "ladon", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Use named secret references with Ladon tools. Never ask the user to paste a secret value."
            }
        })),
        "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tools() }
        })),
        "tools/call" => Some(call_tool(id, request.get("params"), session, transport)),
        _ => Some(jsonrpc_error(id, -32601, "method not found")),
    }
}

fn call_tool(
    id: Value,
    params: Option<&Value>,
    session: &mut McpSession,
    transport: &impl RpcTransport,
) -> Value {
    let Some(params) = params else {
        return jsonrpc_error(id, -32602, "invalid params");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return jsonrpc_error(id, -32602, "invalid params");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if name == "ladon_identify_session" {
        return identify_session(id, arguments, session);
    }
    let method = match name {
        "ladon_status" if empty_object(&arguments) => Ok(RpcMethod::Status),
        "ladon_list_secrets" if empty_object(&arguments) => Ok(RpcMethod::List),
        "ladon_lock" if empty_object(&arguments) => Ok(RpcMethod::Lock),
        "ladon_run" => parse_mcp_run(arguments),
        _ => Err(LadonError::InvalidRequest),
    };
    let method = match method {
        Ok(method) => method,
        Err(error) => return tool_error(id, error.code(), error.safe_message()),
    };
    let request = RpcRequest {
        version: PROTOCOL_VERSION,
        request_id: Uuid::new_v4(),
        client_session_id: session.id,
        client_label: session.label().to_owned(),
        method,
    };
    match transport.call(&request) {
        Ok(response) => {
            if let Some((code, message)) = response.error_details() {
                tool_error(id, code, message)
            } else if let Some(result) = response.result() {
                let structured = serde_json::to_value(result).unwrap_or_else(|_| json!({}));
                let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".to_owned());
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": text }],
                        "structuredContent": structured,
                        "isError": false
                    }
                })
            } else {
                tool_error(id, "invalid_response", "local Ladon response is invalid")
            }
        }
        Err(error) => tool_error(id, error.code(), error.safe_message()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentifySessionArguments {
    display_name: String,
}

fn identify_session(id: Value, arguments: Value, session: &mut McpSession) -> Value {
    let arguments: IdentifySessionArguments = match serde_json::from_value(arguments) {
        Ok(arguments) => arguments,
        Err(_) => return tool_error(id, "invalid_request", "invalid request"),
    };
    match session.identify(&arguments.display_name) {
        Ok(()) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{ "type": "text", "text": "session name recorded" }],
                "structuredContent": { "identified": true },
                "isError": false
            }
        }),
        Err(error) => tool_error(id, error.code(), error.safe_message()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpRunArguments {
    executable: String,
    #[serde(default)]
    arguments: Vec<String>,
    working_directory: Option<String>,
    #[serde(default)]
    bindings: Vec<McpBinding>,
    timeout_seconds: Option<u64>,
    output_limit_bytes: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpBinding {
    secret_ref: String,
    #[serde(default = "default_field")]
    field: String,
    target: McpBindingTarget,
    name: Option<String>,
    suggested_filename: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum McpBindingTarget {
    Environment,
    StandardInput,
    TemporaryFileEnvironment,
}

fn default_field() -> String {
    "value".to_owned()
}

fn parse_mcp_run(arguments: Value) -> Result<RpcMethod, LadonError> {
    let arguments: McpRunArguments =
        serde_json::from_value(arguments).map_err(|_| LadonError::InvalidRequest)?;
    let working_directory = arguments.working_directory.unwrap_or_else(|| {
        std::env::current_dir()
            .ok()
            .and_then(|path| path.into_os_string().into_string().ok())
            .unwrap_or_default()
    });
    let working_directory = std::path::Path::new(&working_directory)
        .canonicalize()
        .map_err(|_| LadonError::InvalidWorkingDirectory)?
        .into_os_string()
        .into_string()
        .map_err(|_| LadonError::InvalidWorkingDirectory)?;
    let executable = resolve_executable(&arguments.executable, &working_directory)?;
    let bindings = arguments
        .bindings
        .into_iter()
        .map(|binding| {
            let target = match binding.target {
                McpBindingTarget::Environment => BindingTarget::Environment {
                    name: binding.name.ok_or(LadonError::InvalidBinding)?,
                },
                McpBindingTarget::StandardInput => {
                    if binding.name.is_some() || binding.suggested_filename.is_some() {
                        return Err(LadonError::InvalidBinding);
                    }
                    BindingTarget::StandardInput
                }
                McpBindingTarget::TemporaryFileEnvironment => {
                    BindingTarget::TemporaryFileEnvironment {
                        name: binding.name.ok_or(LadonError::InvalidBinding)?,
                        suggested_filename: binding.suggested_filename,
                    }
                }
            };
            Ok(SecretBindingRequest {
                secret_ref: binding.secret_ref,
                field: binding.field,
                target,
            })
        })
        .collect::<Result<Vec<_>, LadonError>>()?;
    let timeout_ms = arguments
        .timeout_seconds
        .unwrap_or(DEFAULT_RUN_TIMEOUT.as_secs())
        .checked_mul(1000)
        .ok_or(LadonError::InvalidTimeout)?;
    let output_limit_bytes = arguments
        .output_limit_bytes
        .unwrap_or(DEFAULT_OUTPUT_LIMIT_BYTES);
    let run = RunRequest {
        executable: executable.clone(),
        arguments: arguments.arguments.clone(),
        working_directory: working_directory.clone(),
        bindings: bindings.clone(),
        timeout_ms,
        output_limit_bytes,
    };
    validate_run_request(run, RunCaller::Mcp)?;
    Ok(RpcMethod::Run {
        executable,
        arguments: arguments.arguments,
        working_directory,
        bindings,
        timeout_ms,
        output_limit_bytes,
    })
}

fn empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn tool_error(id: Value, code: &str, message: &str) -> Value {
    let structured = json!({ "code": code, "message": message });
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{ "type": "text", "text": structured.to_string() }],
            "structuredContent": structured,
            "isError": true
        }
    })
}

fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

fn tools() -> Value {
    json!([
        {
            "name": "ladon_status",
            "description": "Read local Ladon lock/session status. No secret values are returned.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "destructiveHint": false }
        },
        {
            "name": "ladon_list_secrets",
            "description": "List secret names, IDs, and field names only. Never asks for or returns secret values.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "destructiveHint": false }
        },
        {
            "name": "ladon_lock",
            "description": "Lock the local Ladon vault and cancel any active secret-bearing run.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": true }
        },
        {
            "name": "ladon_identify_session",
            "description": "Set a short non-secret reported name for this MCP process, such as 'Codex — deploy payments'. Call once before the first secret-bearing run when a useful task name is known.",
            "inputSchema": {
                "type": "object",
                "required": ["display_name"],
                "additionalProperties": false,
                "properties": {
                    "display_name": { "type": "string", "minLength": 1, "maxLength": 64 }
                }
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": false }
        },
        {
            "name": "ladon_run",
            "description": "Run a local non-interactive program with named secret fields injected via environment, stdin, or a temporary file. Pass references only; never pass a secret value. The command may modify external state.",
            "inputSchema": {
                "type": "object",
                "required": ["executable"],
                "additionalProperties": false,
                "properties": {
                    "executable": { "type": "string", "description": "Absolute, working-directory-relative, or PATH-resolved local executable." },
                    "arguments": { "type": "array", "maxItems": 256, "items": { "type": "string" } },
                    "working_directory": { "type": "string" },
                    "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 900, "default": 300 },
                    "output_limit_bytes": { "type": "integer", "minimum": 128, "maximum": 2097152, "default": 524288 },
                    "bindings": {
                        "type": "array",
                        "maxItems": 16,
                        "items": {
                            "type": "object",
                            "required": ["secret_ref", "target"],
                            "additionalProperties": false,
                            "properties": {
                                "secret_ref": { "type": "string", "description": "Exact secret name or id:<uuid>." },
                                "field": { "type": "string", "default": "value" },
                                "target": { "type": "string", "enum": ["environment", "standard_input", "temporary_file_environment"] },
                                "name": { "type": "string", "description": "Required environment variable name for environment targets." },
                                "suggested_filename": { "type": "string", "description": "Optional safe basename used only to retain an extension for a temporary file." }
                            }
                        }
                    }
                }
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true }
        }
    ])
}
