use std::{
    env,
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
};

use ladon_core::{
    BindingTarget, DEFAULT_OUTPUT_LIMIT_BYTES, DEFAULT_RUN_TIMEOUT, LadonError, RpcMethod,
    RpcRequest, RpcResponse, RunCaller, RunRequest, SecretBindingRequest, validate_run_request,
};
use uuid::Uuid;

use crate::{RpcTransport, serve_mcp};

pub fn execute_cli(
    arguments: impl IntoIterator<Item = String>,
    transport: &impl RpcTransport,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> i32 {
    match execute(arguments, transport, stdout) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(stderr, "{}: {}", error.code(), error.safe_message());
            2
        }
    }
}

fn execute(
    arguments: impl IntoIterator<Item = String>,
    transport: &impl RpcTransport,
    stdout: &mut impl Write,
) -> Result<(), LadonError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let command = arguments.next().ok_or(LadonError::InvalidRequest)?;
    let rest: Vec<String> = arguments.collect();
    match command.as_str() {
        "status" if rest.is_empty() => call_and_render(RpcMethod::Status, transport, stdout),
        "list" if rest.is_empty() => call_and_render(RpcMethod::List, transport, stdout),
        "lock" if rest.is_empty() => call_and_render(RpcMethod::Lock, transport, stdout),
        "run" => call_and_render(parse_run(rest, RunCaller::Cli)?, transport, stdout),
        "mcp" if rest.is_empty() => serve_mcp(std::io::stdin(), stdout, transport),
        _ => Err(LadonError::InvalidRequest),
    }
}

fn call_and_render(
    method: RpcMethod,
    transport: &impl RpcTransport,
    stdout: &mut impl Write,
) -> Result<(), LadonError> {
    let request = RpcRequest {
        version: 1,
        request_id: Uuid::new_v4(),
        client_label: "Ladon CLI".to_owned(),
        method,
    };
    render_response(&transport.call(&request)?, stdout)
}

fn render_response(response: &RpcResponse, stdout: &mut impl Write) -> Result<(), LadonError> {
    if let Some((code, _)) = response.error_details() {
        return Err(LadonError::from_code(code).unwrap_or(LadonError::InvalidRequest));
    }
    let result = response.result().ok_or(LadonError::InvalidRequest)?;
    serde_json::to_writer_pretty(&mut *stdout, result).map_err(|_| LadonError::InvalidRequest)?;
    writeln!(stdout).map_err(|_| LadonError::InvalidRequest)
}

pub(crate) fn parse_run(
    arguments: Vec<String>,
    caller: RunCaller,
) -> Result<RpcMethod, LadonError> {
    let mut bindings = Vec::new();
    let mut timeout_ms = DEFAULT_RUN_TIMEOUT.as_millis() as u64;
    let mut output_limit_bytes = DEFAULT_OUTPUT_LIMIT_BYTES;
    let mut working_directory = env::current_dir().map_err(|_| LadonError::InvalidRequest)?;
    let mut index = 0;
    while index < arguments.len() && arguments[index] != "--" {
        let flag = &arguments[index];
        index += 1;
        let value = arguments.get(index).ok_or(LadonError::InvalidRequest)?;
        match flag.as_str() {
            "--env" => bindings.push(parse_named_binding(value, false)?),
            "--file-env" => bindings.push(parse_named_binding(value, true)?),
            "--stdin" => bindings.push(parse_stdin_binding(value)?),
            "--timeout-seconds" => {
                timeout_ms = value
                    .parse::<u64>()
                    .ok()
                    .and_then(|seconds| seconds.checked_mul(1000))
                    .ok_or(LadonError::InvalidTimeout)?;
            }
            "--output-limit-bytes" => {
                output_limit_bytes = value
                    .parse::<usize>()
                    .map_err(|_| LadonError::InvalidOutputLimit)?;
            }
            "--cwd" => working_directory = PathBuf::from(value),
            _ => return Err(LadonError::InvalidRequest),
        }
        index += 1;
    }
    if arguments.get(index).map(String::as_str) != Some("--") {
        return Err(LadonError::InvalidRequest);
    }
    index += 1;
    let executable = arguments
        .get(index)
        .ok_or(LadonError::InvalidExecutablePath)?;
    let working_directory = canonical_directory(&working_directory)?;
    let executable = resolve_executable(executable, &working_directory)?;
    let command_arguments = arguments[index + 1..].to_vec();

    let run = RunRequest {
        executable: executable.clone(),
        arguments: command_arguments.clone(),
        working_directory: working_directory.clone(),
        bindings: bindings.clone(),
        timeout_ms,
        output_limit_bytes,
    };
    validate_run_request(run, caller)?;
    Ok(RpcMethod::Run {
        executable,
        arguments: command_arguments,
        working_directory,
        bindings,
        timeout_ms,
        output_limit_bytes,
    })
}

fn parse_named_binding(value: &str, file: bool) -> Result<SecretBindingRequest, LadonError> {
    let (name, reference) = value.split_once('=').ok_or(LadonError::InvalidBinding)?;
    let (secret_ref, field) = parse_reference(reference)?;
    let target = if file {
        BindingTarget::TemporaryFileEnvironment {
            name: name.to_owned(),
            suggested_filename: None,
        }
    } else {
        BindingTarget::Environment {
            name: name.to_owned(),
        }
    };
    Ok(SecretBindingRequest {
        secret_ref,
        field,
        target,
    })
}

fn parse_stdin_binding(value: &str) -> Result<SecretBindingRequest, LadonError> {
    let (secret_ref, field) = parse_reference(value)?;
    Ok(SecretBindingRequest {
        secret_ref,
        field,
        target: BindingTarget::StandardInput,
    })
}

fn parse_reference(reference: &str) -> Result<(String, String), LadonError> {
    if let Some((secret_ref, field)) = reference.rsplit_once("::") {
        if secret_ref.is_empty() || field.is_empty() {
            return Err(LadonError::InvalidBinding);
        }
        Ok((secret_ref.to_owned(), field.to_owned()))
    } else if reference.is_empty() {
        Err(LadonError::InvalidBinding)
    } else {
        Ok((reference.to_owned(), "value".to_owned()))
    }
}

fn canonical_directory(path: &Path) -> Result<String, LadonError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| LadonError::InvalidWorkingDirectory)?;
    if !canonical.is_dir() {
        return Err(LadonError::InvalidWorkingDirectory);
    }
    canonical
        .into_os_string()
        .into_string()
        .map_err(|_| LadonError::InvalidWorkingDirectory)
}

pub(crate) fn resolve_executable(
    input: &str,
    working_directory: &str,
) -> Result<String, LadonError> {
    if input.contains('\0') {
        return Err(LadonError::InvalidExecutablePath);
    }
    let path = Path::new(input);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if has_path_separator(path.as_os_str()) {
        Path::new(working_directory).join(path)
    } else {
        find_in_path(path).ok_or(LadonError::InvalidExecutablePath)?
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|_| LadonError::InvalidExecutablePath)?;
    if !canonical.is_file() || !is_executable(&canonical) {
        return Err(LadonError::InvalidExecutablePath);
    }
    canonical
        .into_os_string()
        .into_string()
        .map_err(|_| LadonError::InvalidExecutablePath)
}

fn has_path_separator(value: &OsStr) -> bool {
    Path::new(value).components().count() > 1
}

fn find_in_path(executable: &Path) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(executable))
            .find(|candidate| candidate.is_file() && is_executable(candidate))
    })
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            ["exe", "com", "bat", "cmd"]
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
}
