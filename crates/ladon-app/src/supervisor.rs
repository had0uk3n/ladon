use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use ladon_core::{
    LadonError, MIN_OUTPUT_LIMIT_BYTES, PreparedBinding, PreparedRun, RedactedOutput,
    RedactionSecret, ResolvedSecretBinding, SensitiveBytes, StreamingRedactor,
    ValidatedBindingTarget, ValidatedRunRequest, ValidatedSecretBinding,
};
use tempfile::{Builder as TempBuilder, TempDir};
use uuid::Uuid;
use zeroize::Zeroizing;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const RUN_DIRECTORY_PREFIX: &str = "run-";
const RUN_DIRECTORY_MARKER: &str = ".ladon-owner";
#[cfg(unix)]
const TERMINATION_GRACE: Duration = Duration::from_millis(500);
#[cfg(unix)]
const TERMINATION_CONFIRMATION: Duration = Duration::from_secs(2);

#[derive(Clone, Default)]
pub struct RunCancellation(Arc<AtomicBool>);

impl RunCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunTermination {
    Exited,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Eq, PartialEq)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub termination: RunTermination,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
    pub redaction_count: u64,
    pub output_truncated: bool,
    pub omitted_bytes: u64,
    pub output_suppressed: bool,
    pub temp_cleanup_warning: bool,
}

#[derive(Default)]
pub struct Supervisor {
    running: AtomicBool,
}

impl Supervisor {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
        }
    }

    #[cfg(feature = "gui")]
    pub(crate) fn temporary_root_path() -> PathBuf {
        temporary_root()
    }

    #[cfg(feature = "gui")]
    pub(crate) fn cleanup_stale_temp_directories_at(root: &Path) -> Result<(), LadonError> {
        cleanup_stale_temp_directories_in(root)
    }

    pub fn run<F>(
        &self,
        request: ValidatedRunRequest,
        cancellation: RunCancellation,
        resolve: F,
    ) -> Result<RunResult, LadonError>
    where
        F: FnOnce(&[ValidatedSecretBinding]) -> Result<Vec<ResolvedSecretBinding>, LadonError>,
    {
        let _guard = RunningGuard::acquire(&self.running)?;
        validate_filesystem(&request)?;
        let resolved = resolve(request.bindings())?;
        let run = request.resolve(resolved)?;
        execute(run, cancellation)
    }
}

struct RunningGuard<'a>(&'a AtomicBool);

impl<'a> RunningGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Result<Self, LadonError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| LadonError::Busy)?;
        Ok(Self(flag))
    }
}

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn validate_filesystem(run: &ValidatedRunRequest) -> Result<(), LadonError> {
    let executable = Path::new(run.executable());
    let metadata = executable
        .metadata()
        .map_err(|_| LadonError::InvalidExecutablePath)?;
    if !metadata.is_file() {
        return Err(LadonError::InvalidExecutablePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(LadonError::InvalidExecutablePath);
        }
    }
    if !Path::new(run.working_directory()).is_dir() {
        return Err(LadonError::InvalidWorkingDirectory);
    }
    Ok(())
}

fn execute(run: PreparedRun, cancellation: RunCancellation) -> Result<RunResult, LadonError> {
    let started = Instant::now();
    let mut temporary_directory: Option<TempDir> = None;
    let stdout_redactor = make_redactor(run.bindings(), run.output_limit_bytes())?;
    let stderr_redactor = make_redactor(run.bindings(), run.output_limit_bytes())?;
    let mut command = Command::new(run.executable());
    command
        .args(run.arguments())
        .current_dir(run.working_directory())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_minimal_environment(&mut command, Path::new(run.executable()));

    let mut stdin_value: Option<Zeroizing<Vec<u8>>> = None;
    for binding in run.bindings() {
        match binding.target() {
            ValidatedBindingTarget::Environment { name } => {
                let value = binding.value().expose(|bytes| {
                    std::str::from_utf8(bytes)
                        .ok()
                        .filter(|value| !value.contains('\0'))
                        .map(ToOwned::to_owned)
                });
                let value = value.ok_or(LadonError::InvalidBinding)?;
                command.env(name, Zeroizing::new(value).as_str());
            }
            ValidatedBindingTarget::StandardInput => {
                stdin_value = Some(
                    binding
                        .value()
                        .expose(|value| Zeroizing::new(value.to_vec())),
                );
            }
            ValidatedBindingTarget::TemporaryFileEnvironment { name, extension } => {
                let directory = ensure_temp_directory(&mut temporary_directory)?;
                let path = write_temporary_secret(directory.path(), extension.as_deref(), binding)?;
                command.env(name, &path);
            }
        }
    }

    configure_process_group(&mut command);
    let mut child = command.spawn().map_err(|_| LadonError::ProcessFailure)?;
    drop(command);
    let process_tree = match PlatformProcessTree::attach(&mut child) {
        Ok(process_tree) => process_tree,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };

    let stdout = child.stdout.take().ok_or(LadonError::ProcessFailure)?;
    let stderr = child.stderr.take().ok_or(LadonError::ProcessFailure)?;
    let stdout_worker = thread::spawn(move || redact_reader(stdout, stdout_redactor));
    let stderr_worker = thread::spawn(move || redact_reader(stderr, stderr_redactor));
    let mut child_stdin = child.stdin.take().ok_or(LadonError::ProcessFailure)?;
    let stdin_worker = thread::spawn(move || -> std::io::Result<()> {
        if let Some(value) = stdin_value {
            child_stdin.write_all(value.as_slice())?;
        }
        Ok(())
    });

    let (status, termination) = wait_for_child(
        &mut child,
        &process_tree,
        started,
        run.timeout(),
        &cancellation,
    )?;
    let stdout = stdout_worker
        .join()
        .map_err(|_| LadonError::ProcessFailure)??;
    let stderr = stderr_worker
        .join()
        .map_err(|_| LadonError::ProcessFailure)??;
    let stdin_result = stdin_worker
        .join()
        .map_err(|_| LadonError::ProcessFailure)?;
    if let Err(error) = stdin_result {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(LadonError::ProcessFailure);
        }
    }
    let temp_cleanup_warning = temporary_directory
        .take()
        .is_some_and(|directory| directory.close().is_err());
    let (stdout_text, stderr_text, combined_truncated, combined_omitted) =
        enforce_combined_limit(stdout.text, stderr.text, run.output_limit_bytes());

    Ok(RunResult {
        exit_code: status.code(),
        termination,
        stdout: stdout_text,
        stderr: stderr_text,
        duration: started.elapsed(),
        redaction_count: stdout
            .redaction_count
            .saturating_add(stderr.redaction_count),
        output_truncated: stdout.truncated || stderr.truncated || combined_truncated,
        omitted_bytes: stdout
            .omitted_bytes
            .saturating_add(stderr.omitted_bytes)
            .saturating_add(combined_omitted),
        output_suppressed: stdout.suppressed || stderr.suppressed,
        temp_cleanup_warning,
    })
}

fn make_redactor(
    bindings: &[PreparedBinding],
    limit: usize,
) -> Result<StreamingRedactor, LadonError> {
    let secrets = bindings
        .iter()
        .map(|binding| {
            RedactionSecret::new(
                binding.secret_id(),
                binding.field().clone(),
                binding
                    .value()
                    .expose(|value| SensitiveBytes::new(value.to_vec())),
            )
        })
        .collect();
    StreamingRedactor::new(secrets, limit)
}

fn ensure_temp_directory(directory: &mut Option<TempDir>) -> Result<&TempDir, LadonError> {
    if directory.is_none() {
        let root = temporary_root();
        prepare_temporary_root(&root)?;
        let created = TempBuilder::new()
            .prefix(RUN_DIRECTORY_PREFIX)
            .tempdir_in(root)
            .map_err(|_| LadonError::ProcessFailure)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(created.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|_| LadonError::ProcessFailure)?;
        }
        write_run_marker(created.path())?;
        *directory = Some(created);
    }
    directory.as_ref().ok_or(LadonError::ProcessFailure)
}

fn temporary_root() -> PathBuf {
    #[cfg(unix)]
    let suffix = {
        // SAFETY: geteuid has no preconditions and no side effects.
        unsafe { libc::geteuid() }.to_string()
    };
    #[cfg(not(unix))]
    let suffix = "user".to_owned();
    env::temp_dir().join(format!("ladon-runs-{suffix}"))
}

fn prepare_temporary_root(root: &Path) -> Result<(), LadonError> {
    #[cfg(unix)]
    {
        use std::io::ErrorKind;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        match fs::symlink_metadata(root) {
            Ok(metadata) => validate_temporary_root_metadata(&metadata)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                if let Err(error) = builder.create(root) {
                    if error.kind() != ErrorKind::AlreadyExists {
                        return Err(LadonError::ProcessFailure);
                    }
                }
            }
            Err(_) => return Err(LadonError::ProcessFailure),
        }
        let metadata = fs::symlink_metadata(root).map_err(|_| LadonError::ProcessFailure)?;
        validate_temporary_root_metadata(&metadata)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|_| LadonError::ProcessFailure)?;
    }
    {
        #[cfg(not(unix))]
        {
            fs::create_dir_all(root).map_err(|_| LadonError::ProcessFailure)?;
            if !fs::symlink_metadata(root)
                .map_err(|_| LadonError::ProcessFailure)?
                .file_type()
                .is_dir()
            {
                return Err(LadonError::ProcessFailure);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_temporary_root_metadata(metadata: &fs::Metadata) -> Result<(), LadonError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no preconditions and no side effects.
    let owner = unsafe { libc::geteuid() };
    if metadata.file_type().is_dir()
        && metadata.uid() == owner
        && metadata.permissions().mode() & 0o077 == 0
    {
        Ok(())
    } else {
        Err(LadonError::ProcessFailure)
    }
}

fn write_run_marker(directory: &Path) -> Result<(), LadonError> {
    let path = directory.join(RUN_DIRECTORY_MARKER);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut marker = options.open(path).map_err(|_| LadonError::ProcessFailure)?;
    marker
        .write_all(Uuid::new_v4().to_string().as_bytes())
        .and_then(|()| marker.sync_all())
        .map_err(|_| LadonError::ProcessFailure)
}

#[cfg(any(feature = "gui", test))]
fn cleanup_stale_temp_directories_in(root: &Path) -> Result<(), LadonError> {
    prepare_temporary_root(root)?;
    for entry in fs::read_dir(root).map_err(|_| LadonError::ProcessFailure)? {
        let entry = entry.map_err(|_| LadonError::ProcessFailure)?;
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with(RUN_DIRECTORY_PREFIX)
        {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| LadonError::ProcessFailure)?;
        if !metadata.file_type().is_dir() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no preconditions and no side effects.
            if metadata.uid() != unsafe { libc::geteuid() } {
                continue;
            }
        }
        let marker_path = path.join(RUN_DIRECTORY_MARKER);
        let Ok(marker_metadata) = fs::symlink_metadata(&marker_path) else {
            continue;
        };
        if !marker_metadata.file_type().is_file() || marker_metadata.len() != 36 {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: geteuid has no preconditions and no side effects.
            if marker_metadata.uid() != unsafe { libc::geteuid() }
                || marker_metadata.permissions().mode() & 0o077 != 0
            {
                continue;
            }
        }
        let Ok(marker) = fs::read_to_string(&marker_path) else {
            continue;
        };
        if Uuid::parse_str(&marker).is_err() {
            continue;
        }
        fs::remove_dir_all(path).map_err(|_| LadonError::ProcessFailure)?;
    }
    Ok(())
}

fn write_temporary_secret(
    directory: &Path,
    extension: Option<&str>,
    binding: &PreparedBinding,
) -> Result<PathBuf, LadonError> {
    let filename = format!("secret-{}{}", Uuid::new_v4(), extension.unwrap_or_default());
    let path = directory.join(filename);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| LadonError::ProcessFailure)?;
    binding
        .value()
        .expose(|value| file.write_all(value))
        .map_err(|_| LadonError::ProcessFailure)?;
    file.flush().map_err(|_| LadonError::ProcessFailure)?;
    Ok(path)
}

fn apply_minimal_environment(command: &mut Command, executable: &Path) {
    let executable_directory = executable.parent().unwrap_or_else(|| Path::new("/"));
    let mut path_entries = vec![executable_directory.to_path_buf()];
    #[cfg(unix)]
    path_entries.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
    #[cfg(windows)]
    if let Some(system_root) = env::var_os("SystemRoot") {
        path_entries.push(PathBuf::from(system_root).join("System32"));
    }
    if let Ok(path) = env::join_paths(path_entries) {
        command.env("PATH", path);
    }
    command.env("TMPDIR", env::temp_dir());
    for name in ["HOME", "LANG", "LC_ALL", "LC_CTYPE"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    for name in ["SystemRoot", "USERPROFILE", "TEMP", "TMP"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    // SAFETY: the closure invokes only async-signal-safe setrlimit before exec.
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
}

#[cfg(windows)]
fn configure_process_group(_command: &mut Command) {}

trait ProcessTreeControl: Sized {
    fn attach(child: &mut Child) -> Result<Self, LadonError>;
    fn finish(
        &self,
        child: &mut Child,
        status: std::process::ExitStatus,
    ) -> Result<std::process::ExitStatus, LadonError>;
    fn terminate(&self, child: &mut Child) -> Result<std::process::ExitStatus, LadonError>;
}

#[cfg(unix)]
struct UnixProcessGroup {
    id: i32,
}

#[cfg(unix)]
type PlatformProcessTree = UnixProcessGroup;

#[cfg(unix)]
impl ProcessTreeControl for UnixProcessGroup {
    fn attach(child: &mut Child) -> Result<Self, LadonError> {
        Ok(Self {
            id: i32::try_from(child.id()).map_err(|_| LadonError::ProcessFailure)?,
        })
    }

    fn finish(
        &self,
        child: &mut Child,
        status: std::process::ExitStatus,
    ) -> Result<std::process::ExitStatus, LadonError> {
        if self.exists()? {
            self.terminate_with_status(child, Some(status))
        } else {
            Ok(status)
        }
    }

    fn terminate(&self, child: &mut Child) -> Result<std::process::ExitStatus, LadonError> {
        self.terminate_with_status(child, None)
    }
}

#[cfg(unix)]
impl UnixProcessGroup {
    fn terminate_with_status(
        &self,
        child: &mut Child,
        mut status: Option<std::process::ExitStatus>,
    ) -> Result<std::process::ExitStatus, LadonError> {
        self.signal(libc::SIGTERM)?;
        let grace_started = Instant::now();
        while grace_started.elapsed() < TERMINATION_GRACE {
            if status.is_none() {
                status = child.try_wait().map_err(|_| LadonError::ProcessFailure)?;
            }
            if status.is_some() && !self.exists()? {
                return status.ok_or(LadonError::ProcessFailure);
            }
            thread::sleep(POLL_INTERVAL);
        }
        self.signal(libc::SIGKILL)?;
        if status.is_none() {
            status = Some(child.wait().map_err(|_| LadonError::ProcessFailure)?);
        }
        let confirmation_started = Instant::now();
        while self.exists()? {
            if confirmation_started.elapsed() >= TERMINATION_CONFIRMATION {
                return Err(LadonError::ProcessFailure);
            }
            thread::sleep(POLL_INTERVAL);
        }
        status.ok_or(LadonError::ProcessFailure)
    }

    fn signal(&self, signal: i32) -> Result<(), LadonError> {
        // SAFETY: a negative PID targets only the private process group created for this child.
        if unsafe { libc::kill(-self.id, signal) } == 0 {
            return Ok(());
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(()),
            _ => Err(LadonError::ProcessFailure),
        }
    }

    fn exists(&self) -> Result<bool, LadonError> {
        // SAFETY: signal 0 performs an existence/permission check without sending a signal.
        if unsafe { libc::kill(-self.id, 0) } == 0 {
            return Ok(true);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(LadonError::ProcessFailure),
        }
    }
}

#[cfg(windows)]
struct WindowsJob(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
type PlatformProcessTree = WindowsJob;

#[cfg(windows)]
impl ProcessTreeControl for WindowsJob {
    fn attach(child: &mut Child) -> Result<Self, LadonError> {
        use std::{mem::size_of, os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: null attributes/name request an unnamed job with the caller's defaults.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(LadonError::ProcessFailure);
        }
        let job = Self(handle);
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: pointers reference initialized values for the duration of the calls; the child
        // handle is owned by std::process::Child and has process-assignment rights.
        let configured = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(LadonError::ProcessFailure);
        }
        // SAFETY: the raw handle remains owned by Child and valid for this call.
        let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle().cast()) };
        if assigned == 0 {
            return Err(LadonError::ProcessFailure);
        }
        Ok(job)
    }

    fn finish(
        &self,
        _child: &mut Child,
        status: std::process::ExitStatus,
    ) -> Result<std::process::ExitStatus, LadonError> {
        self.terminate_job()?;
        Ok(status)
    }

    fn terminate(&self, child: &mut Child) -> Result<std::process::ExitStatus, LadonError> {
        self.terminate_job()?;
        child.wait().map_err(|_| LadonError::ProcessFailure)
    }
}

#[cfg(windows)]
impl WindowsJob {
    fn terminate_job(&self) -> Result<(), LadonError> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: self owns a valid job handle until Drop and the exit code is application-defined.
        if unsafe { TerminateJobObject(self.0, 1) } == 0 {
            Err(LadonError::ProcessFailure)
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // SAFETY: this is the final owner of the job handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn wait_for_child<T: ProcessTreeControl>(
    child: &mut Child,
    process_tree: &T,
    started: Instant,
    timeout: Duration,
    cancellation: &RunCancellation,
) -> Result<(std::process::ExitStatus, RunTermination), LadonError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| LadonError::ProcessFailure)? {
            let status = process_tree.finish(child, status)?;
            return Ok((status, RunTermination::Exited));
        }
        if cancellation.is_cancelled() {
            let status = process_tree.terminate(child)?;
            return Ok((status, RunTermination::Cancelled));
        }
        if started.elapsed() >= timeout {
            let status = process_tree.terminate(child)?;
            return Ok((status, RunTermination::TimedOut));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn redact_reader(
    mut reader: impl Read,
    mut redactor: StreamingRedactor,
) -> Result<RedactedOutput, LadonError> {
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| LadonError::ProcessFailure)?;
        if read == 0 {
            break;
        }
        redactor.push(&buffer[..read]);
    }
    Ok(redactor.finish())
}

fn enforce_combined_limit(
    mut stdout: String,
    mut stderr: String,
    limit: usize,
) -> (String, String, bool, u64) {
    if stdout.len().saturating_add(stderr.len()) <= limit {
        return (stdout, stderr, false, 0);
    }
    let original_bytes = stdout.len().saturating_add(stderr.len());
    let stdout_budget = limit / 2;
    let stderr_budget = limit - stdout_budget;
    truncate_utf8(&mut stdout, stdout_budget.max(MIN_OUTPUT_LIMIT_BYTES / 2));
    truncate_utf8(&mut stderr, stderr_budget.max(MIN_OUTPUT_LIMIT_BYTES / 2));
    while stdout.len().saturating_add(stderr.len()) > limit {
        if stdout.len() >= stderr.len() && !stdout.is_empty() {
            stdout.pop();
            while !stdout.is_char_boundary(stdout.len()) {
                stdout.pop();
            }
        } else if !stderr.is_empty() {
            stderr.pop();
            while !stderr.is_char_boundary(stderr.len()) {
                stderr.pop();
            }
        } else {
            break;
        }
    }
    let retained_bytes = stdout.len().saturating_add(stderr.len());
    (
        stdout,
        stderr,
        true,
        original_bytes.saturating_sub(retained_bytes) as u64,
    )
}

fn truncate_utf8(value: &mut String, limit: usize) {
    if value.len() <= limit {
        return;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_temp_cleanup_requires_a_valid_private_marker() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("runtime");
        prepare_temporary_root(&root).unwrap();
        let valid = root.join("run-valid");
        fs::create_dir(&valid).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&valid, fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_run_marker(&valid).unwrap();
        fs::write(valid.join("secret"), b"fake-value").unwrap();
        let unmarked = root.join("run-unmarked");
        fs::create_dir(&unmarked).unwrap();
        fs::write(unmarked.join("keep"), b"not-owned-by-ladon").unwrap();

        cleanup_stale_temp_directories_in(&root).unwrap();

        assert!(!valid.exists());
        assert!(unmarked.join("keep").exists());
    }

    #[cfg(unix)]
    #[test]
    fn temporary_root_validation_never_follows_a_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let root = parent.path().join("runtime");
        symlink(&target, &root).unwrap();

        assert_eq!(
            prepare_temporary_root(&root),
            Err(LadonError::ProcessFailure)
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
