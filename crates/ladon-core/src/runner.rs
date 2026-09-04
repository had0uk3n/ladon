use std::{collections::HashSet, fmt, path::Path, time::Duration};

use crate::{
    BindingTarget, FieldName, LadonError, MAX_OUTPUT_LIMIT_BYTES, MIN_OUTPUT_LIMIT_BYTES,
    SecretBindingRequest, SecretId, SecretRef, SensitiveBytes,
};

pub const MAX_BINDINGS: usize = 16;
pub const MAX_INJECTED_BYTES: usize = 1024 * 1024;
pub const MAX_ARGUMENTS: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 256 * 1024;
pub const MAX_PATH_BYTES: usize = 32 * 1024;
pub const DEFAULT_RUN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
pub const MAX_MCP_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const MAX_CLI_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunCaller {
    Mcp,
    Cli,
}

impl RunCaller {
    const fn maximum_timeout(self) -> Duration {
        match self {
            Self::Mcp => MAX_MCP_TIMEOUT,
            Self::Cli => MAX_CLI_TIMEOUT,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRequest {
    pub executable: String,
    pub arguments: Vec<String>,
    pub working_directory: String,
    pub bindings: Vec<SecretBindingRequest>,
    pub timeout_ms: u64,
    pub output_limit_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidatedBindingTarget {
    Environment {
        name: String,
    },
    StandardInput,
    TemporaryFileEnvironment {
        name: String,
        extension: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSecretBinding {
    secret_ref: SecretRef,
    field: FieldName,
    target: ValidatedBindingTarget,
}

impl ValidatedSecretBinding {
    #[must_use]
    pub const fn secret_ref(&self) -> &SecretRef {
        &self.secret_ref
    }

    #[must_use]
    pub const fn field(&self) -> &FieldName {
        &self.field
    }

    #[must_use]
    pub const fn target(&self) -> &ValidatedBindingTarget {
        &self.target
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedRunRequest {
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
    bindings: Vec<ValidatedSecretBinding>,
    timeout: Duration,
    output_limit_bytes: usize,
}

impl ValidatedRunRequest {
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
    pub fn bindings(&self) -> &[ValidatedSecretBinding] {
        &self.bindings
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub const fn output_limit_bytes(&self) -> usize {
        self.output_limit_bytes
    }

    pub fn resolve(self, resolved: Vec<ResolvedSecretBinding>) -> Result<PreparedRun, LadonError> {
        if resolved.len() != self.bindings.len() {
            return Err(LadonError::InvalidBinding);
        }

        let mut injected_bytes = 0_usize;
        let mut prepared = Vec::with_capacity(resolved.len());
        for (binding, resolved) in self.bindings.into_iter().zip(resolved) {
            if binding.field != resolved.field {
                return Err(LadonError::InvalidBinding);
            }
            if let SecretRef::Id(expected) = binding.secret_ref {
                if expected != resolved.secret_id {
                    return Err(LadonError::InvalidBinding);
                }
            }
            injected_bytes = injected_bytes
                .checked_add(resolved.value.len())
                .ok_or(LadonError::InjectedDataTooLarge)?;
            if injected_bytes > MAX_INJECTED_BYTES {
                return Err(LadonError::InjectedDataTooLarge);
            }
            if matches!(binding.target, ValidatedBindingTarget::Environment { .. })
                && resolved
                    .value
                    .expose(|value| std::str::from_utf8(value).is_err() || value.contains(&0))
            {
                return Err(LadonError::InvalidBinding);
            }
            if resolved.value.expose(|value| {
                contains(&self.executable, value)
                    || contains(&self.working_directory, value)
                    || self
                        .arguments
                        .iter()
                        .any(|argument| contains(argument, value))
            }) {
                return Err(LadonError::SecretInCommand);
            }
            prepared.push(PreparedBinding {
                secret_id: resolved.secret_id,
                field: resolved.field,
                target: binding.target,
                value: resolved.value,
            });
        }

        Ok(PreparedRun {
            executable: self.executable,
            arguments: self.arguments,
            working_directory: self.working_directory,
            bindings: prepared,
            timeout: self.timeout,
            output_limit_bytes: self.output_limit_bytes,
        })
    }
}

pub struct ResolvedSecretBinding {
    secret_id: SecretId,
    field: FieldName,
    value: SensitiveBytes,
}

impl ResolvedSecretBinding {
    pub fn new(secret_id: &str, field: &str, value: SensitiveBytes) -> Result<Self, LadonError> {
        Ok(Self {
            secret_id: SecretId::parse(secret_id)?,
            field: FieldName::parse(field)?,
            value,
        })
    }
}

impl fmt::Debug for ResolvedSecretBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedSecretBinding")
            .field("secret_id", &self.secret_id)
            .field("field", &self.field)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub struct PreparedBinding {
    secret_id: SecretId,
    field: FieldName,
    target: ValidatedBindingTarget,
    value: SensitiveBytes,
}

impl PreparedBinding {
    #[must_use]
    pub const fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    #[must_use]
    pub const fn field(&self) -> &FieldName {
        &self.field
    }

    #[must_use]
    pub const fn target(&self) -> &ValidatedBindingTarget {
        &self.target
    }

    #[must_use]
    pub const fn value(&self) -> &SensitiveBytes {
        &self.value
    }
}

impl fmt::Debug for PreparedBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBinding")
            .field("secret_id", &self.secret_id)
            .field("field", &self.field)
            .field("target", &self.target)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

pub struct PreparedRun {
    executable: String,
    arguments: Vec<String>,
    working_directory: String,
    bindings: Vec<PreparedBinding>,
    timeout: Duration,
    output_limit_bytes: usize,
}

impl PreparedRun {
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
    pub fn bindings(&self) -> &[PreparedBinding] {
        &self.bindings
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub const fn output_limit_bytes(&self) -> usize {
        self.output_limit_bytes
    }
}

impl fmt::Debug for PreparedRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRun")
            .field("executable", &self.executable)
            .field("arguments", &self.arguments)
            .field("working_directory", &self.working_directory)
            .field("bindings", &self.bindings)
            .field("timeout", &self.timeout)
            .field("output_limit_bytes", &self.output_limit_bytes)
            .finish()
    }
}

pub fn validate_run_request(
    request: RunRequest,
    caller: RunCaller,
) -> Result<ValidatedRunRequest, LadonError> {
    if !Path::new(&request.executable).is_absolute()
        || request.executable.contains('\0')
        || request.executable.len() > MAX_PATH_BYTES
    {
        return Err(LadonError::InvalidExecutablePath);
    }
    if !Path::new(&request.working_directory).is_absolute()
        || request.working_directory.contains('\0')
        || request.working_directory.len() > MAX_PATH_BYTES
    {
        return Err(LadonError::InvalidWorkingDirectory);
    }
    let argument_bytes = request
        .arguments
        .iter()
        .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
        .ok_or(LadonError::InvalidRequest)?;
    if request.arguments.len() > MAX_ARGUMENTS
        || argument_bytes > MAX_ARGUMENT_BYTES
        || request
            .arguments
            .iter()
            .any(|argument| argument.contains('\0'))
    {
        return Err(LadonError::InvalidRequest);
    }
    if request.bindings.len() > MAX_BINDINGS {
        return Err(LadonError::TooManyBindings);
    }
    let timeout = Duration::from_millis(request.timeout_ms);
    if timeout.is_zero() || timeout > caller.maximum_timeout() {
        return Err(LadonError::InvalidTimeout);
    }
    if !(MIN_OUTPUT_LIMIT_BYTES..=MAX_OUTPUT_LIMIT_BYTES).contains(&request.output_limit_bytes) {
        return Err(LadonError::InvalidOutputLimit);
    }

    let mut environment_names = HashSet::new();
    let mut has_standard_input = false;
    let mut bindings = Vec::with_capacity(request.bindings.len());
    for binding in request.bindings {
        let secret_ref = SecretRef::parse(&binding.secret_ref)?;
        let field = FieldName::parse(&binding.field)?;
        let target = match binding.target {
            BindingTarget::Environment { name } => {
                validate_environment_name(&name, &mut environment_names)?;
                ValidatedBindingTarget::Environment { name }
            }
            BindingTarget::StandardInput => {
                if has_standard_input {
                    return Err(LadonError::InvalidBinding);
                }
                has_standard_input = true;
                ValidatedBindingTarget::StandardInput
            }
            BindingTarget::TemporaryFileEnvironment {
                name,
                suggested_filename,
            } => {
                validate_environment_name(&name, &mut environment_names)?;
                let extension = suggested_filename
                    .as_deref()
                    .map(validate_suggested_filename)
                    .transpose()?;
                ValidatedBindingTarget::TemporaryFileEnvironment { name, extension }
            }
        };
        bindings.push(ValidatedSecretBinding {
            secret_ref,
            field,
            target,
        });
    }

    Ok(ValidatedRunRequest {
        executable: request.executable,
        arguments: request.arguments,
        working_directory: request.working_directory,
        bindings,
        timeout,
        output_limit_bytes: request.output_limit_bytes,
    })
}

fn validate_environment_name(name: &str, names: &mut HashSet<String>) -> Result<(), LadonError> {
    if name.is_empty() || name.len() > 256 || name.contains(['\0', '=']) {
        return Err(LadonError::InvalidBinding);
    }
    #[cfg(windows)]
    let comparison_name = name.to_lowercase();
    #[cfg(not(windows))]
    let comparison_name = name.to_owned();
    if !names.insert(comparison_name) {
        return Err(LadonError::InvalidBinding);
    }
    Ok(())
}

fn validate_suggested_filename(filename: &str) -> Result<String, LadonError> {
    if filename.is_empty()
        || filename.len() > 128
        || filename == "."
        || filename == ".."
        || filename.starts_with('.')
        || filename.ends_with(['.', ' '])
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(LadonError::InvalidBinding);
    }
    let extension = Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .ok_or(LadonError::InvalidBinding)?;
    if extension.is_empty()
        || extension.len() > 16
        || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(LadonError::InvalidBinding);
    }
    Ok(format!(".{extension}"))
}

fn contains(haystack: &str, needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window == needle)
}
