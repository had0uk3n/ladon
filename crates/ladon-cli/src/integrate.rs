use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ladon_core::LadonError;
use serde_json::{Map, Value, json};
use toml_edit::{Array, DocumentMut, Item, Table, value};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationTarget {
    Codex,
    Claude,
}

#[derive(Debug, Eq, PartialEq)]
pub struct IntegrationOutcome {
    pub changed: bool,
    pub backup_path: Option<PathBuf>,
}

pub fn integration_preview(
    target: IntegrationTarget,
    executable: &Path,
) -> Result<String, LadonError> {
    validate_executable(executable)?;
    match target {
        IntegrationTarget::Codex => {
            let mut document = DocumentMut::new();
            set_codex_entry(&mut document, executable)?;
            Ok(document.to_string())
        }
        IntegrationTarget::Claude => {
            let mut root = Map::new();
            root.insert("mcpServers".to_owned(), Value::Object(Map::new()));
            set_claude_entry(&mut root, executable)?;
            serde_json::to_string_pretty(&root).map_err(|_| LadonError::IntegrationFailure)
        }
    }
}

pub fn apply_integration_config(
    target: IntegrationTarget,
    config_path: &Path,
    executable: &Path,
) -> Result<IntegrationOutcome, LadonError> {
    validate_executable(executable)?;
    let existing = match fs::read(config_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(LadonError::IntegrationFailure),
    };
    let updated = match target {
        IntegrationTarget::Codex => render_codex(existing.as_deref(), executable)?,
        IntegrationTarget::Claude => render_claude(existing.as_deref(), executable)?,
    };
    if existing.as_deref() == Some(updated.as_slice()) {
        return Ok(IntegrationOutcome {
            changed: false,
            backup_path: None,
        });
    }

    let backup_path = if existing.is_some() {
        let backup = backup_path(config_path)?;
        fs::copy(config_path, &backup).map_err(|_| LadonError::IntegrationFailure)?;
        Some(backup)
    } else {
        None
    };
    write_private_atomic(config_path, &updated)?;
    verify_written_config(target, config_path, executable)?;
    Ok(IntegrationOutcome {
        changed: true,
        backup_path,
    })
}

pub(crate) fn execute_integration(
    arguments: &[String],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), LadonError> {
    let (target, assume_yes) = parse_arguments(arguments)?;
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| LadonError::IntegrationFailure)?;
    let config = default_config_path(target).ok_or(LadonError::IntegrationFailure)?;
    let preview = integration_preview(target, &executable)?;
    writeln!(stdout, "Ladon will configure a local stdio MCP server:")
        .and_then(|()| writeln!(stdout, "{preview}"))
        .and_then(|()| writeln!(stdout, "Config: {}", config.display()))
        .and_then(|()| {
            writeln!(
                stdout,
                "The coding agent and ladon-app must run locally as the same OS user."
            )
        })
        .map_err(|_| LadonError::IntegrationFailure)?;

    if !assume_yes {
        write!(stderr, "Apply this configuration? [y/N] ")
            .and_then(|()| stderr.flush())
            .map_err(|_| LadonError::IntegrationFailure)?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|_| LadonError::IntegrationFailure)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            writeln!(stdout, "No changes made.").map_err(|_| LadonError::IntegrationFailure)?;
            return Ok(());
        }
    }

    let outcome = apply_integration_config(target, &config, &executable)?;
    if outcome.changed {
        writeln!(stdout, "Ladon integration configured.")
            .map_err(|_| LadonError::IntegrationFailure)?;
        if let Some(backup) = outcome.backup_path {
            writeln!(stdout, "Backup: {}", backup.display())
                .map_err(|_| LadonError::IntegrationFailure)?;
        }
    } else {
        writeln!(stdout, "Ladon integration is already up to date.")
            .map_err(|_| LadonError::IntegrationFailure)?;
    }
    Ok(())
}

fn parse_arguments(arguments: &[String]) -> Result<(IntegrationTarget, bool), LadonError> {
    let target = match arguments.first().map(String::as_str) {
        Some("codex") => IntegrationTarget::Codex,
        Some("claude") => IntegrationTarget::Claude,
        _ => return Err(LadonError::InvalidRequest),
    };
    let assume_yes = match arguments.get(1).map(String::as_str) {
        None => false,
        Some("--yes") if arguments.len() == 2 => true,
        _ => return Err(LadonError::InvalidRequest),
    };
    Ok((target, assume_yes))
}

fn default_config_path(target: IntegrationTarget) -> Option<PathBuf> {
    match target {
        IntegrationTarget::Codex => std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(user_home)
            .map(|directory| {
                if std::env::var_os("CODEX_HOME").is_some() {
                    directory.join("config.toml")
                } else {
                    directory.join(".codex").join("config.toml")
                }
            }),
        IntegrationTarget::Claude => user_home().map(|home| home.join(".claude.json")),
    }
}

fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn render_codex(existing: Option<&[u8]>, executable: &Path) -> Result<Vec<u8>, LadonError> {
    let source = existing.unwrap_or_default();
    let text = std::str::from_utf8(source).map_err(|_| LadonError::IntegrationFailure)?;
    let mut document = if text.trim().is_empty() {
        DocumentMut::new()
    } else {
        text.parse::<DocumentMut>()
            .map_err(|_| LadonError::IntegrationFailure)?
    };
    set_codex_entry(&mut document, executable)?;
    Ok(document.to_string().into_bytes())
}

fn set_codex_entry(document: &mut DocumentMut, executable: &Path) -> Result<(), LadonError> {
    let command = path_text(executable)?;
    if !document.as_table().contains_key("mcp_servers") {
        document["mcp_servers"] = Item::Table(Table::new());
    }
    let servers = document["mcp_servers"]
        .as_table_mut()
        .ok_or(LadonError::IntegrationFailure)?;
    if !servers.contains_key("ladon") {
        servers["ladon"] = Item::Table(Table::new());
    }
    let ladon = servers["ladon"]
        .as_table_mut()
        .ok_or(LadonError::IntegrationFailure)?;
    ladon["command"] = value(command);
    let mut arguments = Array::new();
    arguments.push("mcp");
    ladon["args"] = value(arguments);
    ladon["tool_timeout_sec"] = value(1200);
    ladon.remove("url");
    ladon.remove("experimental_environment");
    Ok(())
}

fn render_claude(existing: Option<&[u8]>, executable: &Path) -> Result<Vec<u8>, LadonError> {
    let mut root = match existing {
        Some(bytes) if !bytes.is_empty() => serde_json::from_slice::<Value>(bytes)
            .map_err(|_| LadonError::IntegrationFailure)?
            .as_object()
            .cloned()
            .ok_or(LadonError::IntegrationFailure)?,
        _ => Map::new(),
    };
    set_claude_entry(&mut root, executable)?;
    let mut bytes = serde_json::to_vec_pretty(&root).map_err(|_| LadonError::IntegrationFailure)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn set_claude_entry(root: &mut Map<String, Value>, executable: &Path) -> Result<(), LadonError> {
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or(LadonError::IntegrationFailure)?;
    servers.insert(
        "ladon".to_owned(),
        json!({
            "type": "stdio",
            "command": path_text(executable)?,
            "args": ["mcp"],
            "env": {}
        }),
    );
    Ok(())
}

fn verify_written_config(
    target: IntegrationTarget,
    config: &Path,
    executable: &Path,
) -> Result<(), LadonError> {
    let bytes = fs::read(config).map_err(|_| LadonError::IntegrationFailure)?;
    let rendered = match target {
        IntegrationTarget::Codex => render_codex(Some(&bytes), executable)?,
        IntegrationTarget::Claude => render_claude(Some(&bytes), executable)?,
    };
    if rendered == bytes {
        Ok(())
    } else {
        Err(LadonError::IntegrationFailure)
    }
}

fn validate_executable(executable: &Path) -> Result<(), LadonError> {
    if executable.is_absolute() && executable.is_file() {
        Ok(())
    } else {
        Err(LadonError::InvalidExecutablePath)
    }
}

fn path_text(path: &Path) -> Result<&str, LadonError> {
    path.to_str().ok_or(LadonError::InvalidExecutablePath)
}

fn backup_path(config: &Path) -> Result<PathBuf, LadonError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LadonError::IntegrationFailure)?;
    let mut path: OsString = config.as_os_str().to_owned();
    path.push(format!(
        ".ladon-backup-{}-{}",
        elapsed.as_secs(),
        elapsed.subsec_nanos()
    ));
    Ok(PathBuf::from(path))
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), LadonError> {
    let parent = path.parent().ok_or(LadonError::IntegrationFailure)?;
    #[cfg(unix)]
    let parent_existed = parent.exists();
    fs::create_dir_all(parent).map_err(|_| LadonError::IntegrationFailure)?;
    #[cfg(unix)]
    if !parent_existed {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| LadonError::IntegrationFailure)?;
    }
    let candidate = path.with_file_name(format!(".ladon-config-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&candidate)
            .map_err(|_| LadonError::IntegrationFailure)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| LadonError::IntegrationFailure)?;
        atomic_replace(&candidate, path)?;
        sync_parent(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&candidate);
    }
    result
}

#[cfg(not(windows))]
fn atomic_replace(candidate: &Path, destination: &Path) -> Result<(), LadonError> {
    fs::rename(candidate, destination).map_err(|_| LadonError::IntegrationFailure)
}

#[cfg(windows)]
fn atomic_replace(candidate: &Path, destination: &Path) -> Result<(), LadonError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let candidate: Vec<u16> = candidate.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both vectors are NUL-terminated UTF-16 paths and remain alive for the call.
    if unsafe {
        MoveFileExW(
            candidate.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(LadonError::IntegrationFailure)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), LadonError> {
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LadonError::IntegrationFailure)
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), LadonError> {
    Ok(())
}
