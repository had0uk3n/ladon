use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExposureRule {
    CredentialAssignment,
    PrivateKeyHeader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScanFinding {
    pub(crate) path: PathBuf,
    pub(crate) line: usize,
    pub(crate) rule: ExposureRule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScanReport {
    pub(crate) findings: Vec<ScanFinding>,
    pub(crate) files_scanned: usize,
    pub(crate) skipped_files: usize,
    pub(crate) incomplete: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanLimits {
    pub(crate) max_file_bytes: u64,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_files: usize,
    pub(crate) max_entries: usize,
    pub(crate) max_depth: usize,
    pub(crate) max_duration: Duration,
    pub(crate) max_findings: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 2 * 1024 * 1024,
            max_total_bytes: 100 * 1024 * 1024,
            max_files: 20_000,
            max_entries: 100_000,
            max_depth: 32,
            max_duration: Duration::from_secs(30),
            max_findings: 1_000,
        }
    }
}

struct Scanner<'a> {
    root: &'a Path,
    cancel: &'a AtomicBool,
    limits: &'a ScanLimits,
    started: Instant,
    entries_seen: usize,
    total_bytes: u64,
    report: ScanReport,
}

pub(crate) fn scan_directory(
    root: &Path,
    cancel: &AtomicBool,
    limits: &ScanLimits,
) -> io::Result<ScanReport> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scan root must be a directory and must not be a symlink",
        ));
    }

    let mut scanner = Scanner {
        root,
        cancel,
        limits,
        started: Instant::now(),
        entries_seen: 0,
        total_bytes: 0,
        report: ScanReport {
            findings: Vec::new(),
            files_scanned: 0,
            skipped_files: 0,
            incomplete: false,
        },
    };
    scanner.walk(root, 0);
    Ok(scanner.report)
}

impl Scanner<'_> {
    fn stopped(&mut self) -> bool {
        if self.cancel.load(Ordering::Relaxed) || self.started.elapsed() >= self.limits.max_duration
        {
            self.report.incomplete = true;
            true
        } else {
            false
        }
    }

    fn walk(&mut self, directory: &Path, depth: usize) {
        if self.stopped() {
            return;
        }
        if depth > self.limits.max_depth {
            self.report.incomplete = true;
            return;
        }
        match fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            _ => {
                self.report.incomplete = true;
                return;
            }
        }

        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(_) => {
                self.report.incomplete = true;
                return;
            }
        };

        for entry in entries {
            if self.stopped() {
                return;
            }
            if self.entries_seen >= self.limits.max_entries {
                self.report.incomplete = true;
                return;
            }
            self.entries_seen += 1;

            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    self.report.incomplete = true;
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    self.report.incomplete = true;
                    continue;
                }
            };
            if file_type.is_symlink() {
                self.report.skipped_files += 1;
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                if !ignored_directory(&entry.file_name()) {
                    self.walk(&path, depth + 1);
                }
            } else if file_type.is_file() {
                self.scan_file(&path);
            } else {
                self.report.skipped_files += 1;
            }
        }
    }

    fn scan_file(&mut self, path: &Path) {
        if self.report.files_scanned >= self.limits.max_files {
            self.report.incomplete = true;
            self.report.skipped_files += 1;
            return;
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.report.incomplete = true;
                self.report.skipped_files += 1;
                return;
            }
        };
        if !metadata.file_type().is_file() {
            self.report.skipped_files += 1;
            return;
        }
        let length = metadata.len();
        if length > self.limits.max_file_bytes
            || self.total_bytes.saturating_add(length) > self.limits.max_total_bytes
        {
            self.report.incomplete = true;
            self.report.skipped_files += 1;
            return;
        }
        let file = match open_regular_file(path) {
            Ok(Some(file)) => file,
            Ok(None) => {
                self.report.skipped_files += 1;
                return;
            }
            Err(_) => {
                self.report.incomplete = true;
                self.report.skipped_files += 1;
                return;
            }
        };
        let remaining_total = self.limits.max_total_bytes.saturating_sub(self.total_bytes);
        let read_cap = self.limits.max_file_bytes.min(remaining_total);
        let mut bytes = Zeroizing::new(Vec::new());
        let read_result = file
            .take(read_cap.saturating_add(1))
            .read_to_end(&mut bytes);
        if read_result.is_err() {
            self.report.incomplete = true;
            self.report.skipped_files += 1;
            return;
        }
        if bytes.len() as u64 > read_cap {
            self.report.incomplete = true;
            self.report.skipped_files += 1;
            return;
        }
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u64);
        if bytes.contains(&0) {
            self.report.skipped_files += 1;
            return;
        }
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                self.report.skipped_files += 1;
                return;
            }
        };
        self.report.files_scanned += 1;
        let relative = path.strip_prefix(self.root).unwrap_or(path).to_path_buf();
        for (index, line) in text.lines().enumerate() {
            if self.stopped() {
                return;
            }
            let Some(rule) = classify_line(line) else {
                continue;
            };
            if self.report.findings.len() >= self.limits.max_findings {
                self.report.incomplete = true;
                return;
            }
            self.report.findings.push(ScanFinding {
                path: relative.clone(),
                line: index + 1,
                rule,
            });
        }
    }
}

fn open_regular_file(path: &Path) -> io::Result<Option<fs::File>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if file.metadata()?.is_file() {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

fn ignored_directory(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
            ".git"
                | ".hg"
                | ".svn"
                | "target"
                | "node_modules"
                | "vendor"
                | ".venv"
                | "venv"
                | "dist"
                | "build"
        )
    )
}

fn classify_line(line: &str) -> Option<ExposureRule> {
    let trimmed = line.trim();
    if trimmed == "-----BEGIN ENCRYPTED PRIVATE KEY-----" {
        return None;
    }
    if trimmed.starts_with("-----BEGIN ") && trimmed.ends_with("PRIVATE KEY-----") {
        return Some(ExposureRule::PrivateKeyHeader);
    }

    let separator = trimmed.find('=').or_else(|| trimmed.find(':'))?;
    let key = trimmed[..separator]
        .trim()
        .trim_matches(|character: char| character == '"' || character == '\'')
        .to_ascii_lowercase()
        .replace('-', "_");
    if !credential_key(&key) {
        return None;
    }
    let value = trimmed[separator + 1..]
        .trim()
        .trim_end_matches(',')
        .trim()
        .trim_matches(|character: char| character == '"' || character == '\'')
        .trim();
    if plausible_value(value) {
        Some(ExposureRule::CredentialAssignment)
    } else {
        None
    }
}

fn credential_key(key: &str) -> bool {
    key == "password"
        || key == "passwd"
        || key.ends_with("_password")
        || key.ends_with("_passwd")
        || key == "secret"
        || key.ends_with("_secret")
        || key == "token"
        || key.ends_with("_token")
        || key == "api_key"
        || key.ends_with("_api_key")
        || key.ends_with("apikey")
        || key == "access_key"
        || key.ends_with("_access_key")
        || key.ends_with("accesstoken")
        || key.ends_with("clientsecret")
        || key.ends_with("authtoken")
        || key == "private_key"
        || key.ends_with("_private_key")
}

fn plausible_value(value: &str) -> bool {
    if value.len() < 12 || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        return false;
    }
    let lower = Zeroizing::new(value.to_ascii_lowercase());
    let placeholder = lower.contains("${")
        || lower.contains("{{")
        || (lower.starts_with('<') && lower.ends_with('>'))
        || lower.contains("your_")
        || lower.contains("your-")
        || lower.contains("your ")
        || lower.contains("changeme")
        || lower.contains("change_me")
        || lower.contains("placeholder")
        || lower.contains("replace_me")
        || lower.contains("insert_")
        || lower.contains("example")
        || lower.contains("dummy")
        || lower.contains("redacted")
        || lower
            .chars()
            .all(|character| matches!(character, 'x' | '*' | '-'));
    !placeholder && value.chars().any(char::is_alphanumeric)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ladon-exposure-scan-{name}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scan(root: &std::path::Path) -> ScanReport {
        scan_directory(root, &AtomicBool::new(false), &ScanLimits::default()).unwrap()
    }

    #[test]
    fn reports_only_metadata_for_plausible_credentials_and_private_keys() {
        let root = TestDir::new("findings");
        fs::write(
            root.0.join("settings.env"),
            "API_TOKEN=0123456789abcdef0123456789abcdef\n\
             password: correct-horse-battery-staple\n\
             -----BEGIN PRIVATE KEY-----\n",
        )
        .unwrap();

        let report = scan(&root.0);

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.skipped_files, 0);
        assert!(!report.incomplete);
        assert_eq!(report.findings.len(), 3);
        assert_eq!(
            report.findings[0].path,
            std::path::Path::new("settings.env")
        );
        assert_eq!(report.findings[0].line, 1);
        assert_eq!(report.findings[0].rule, ExposureRule::CredentialAssignment);
        assert_eq!(report.findings[1].line, 2);
        assert_eq!(report.findings[2].rule, ExposureRule::PrivateKeyHeader);
    }

    #[test]
    fn filters_placeholders_and_ordinary_configuration() {
        let root = TestDir::new("placeholders");
        fs::write(
            root.0.join("example.env"),
            "API_KEY=your_api_key_here\nPASSWORD=${PASSWORD}\ntoken=changeme\nport=8080\n\
             -----BEGIN ENCRYPTED PRIVATE KEY-----\n",
        )
        .unwrap();

        assert!(scan(&root.0).findings.is_empty());
    }

    #[test]
    fn recognizes_common_camel_case_and_npm_credential_keys() {
        let root = TestDir::new("config-keys");
        fs::write(
            root.0.join("config"),
            "apiKey: 0123456789abcdef\naccessToken=0123456789abcdef\n\
             clientSecret: 0123456789abcdef\n_authToken=0123456789abcdef\n",
        )
        .unwrap();

        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 4);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule == ExposureRule::CredentialAssignment)
        );
    }

    #[test]
    fn skips_symlinks_ignored_directories_binary_and_oversized_files() {
        let root = TestDir::new("skips");
        let outside = TestDir::new("outside");
        fs::write(
            outside.0.join("secret.env"),
            "TOKEN=0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        fs::create_dir(root.0.join(".git")).unwrap();
        fs::write(
            root.0.join(".git/config"),
            "TOKEN=0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        fs::write(root.0.join("binary"), b"TOKEN=abc\0def").unwrap();
        fs::write(root.0.join("large.env"), vec![b'x'; 33]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.0.join("secret.env"), root.0.join("link.env")).unwrap();

        let limits = ScanLimits {
            max_file_bytes: 32,
            ..ScanLimits::default()
        };
        let report = scan_directory(&root.0, &AtomicBool::new(false), &limits).unwrap();

        assert!(report.findings.is_empty());
        assert_eq!(report.files_scanned, 0);
        assert!(report.skipped_files >= 3);
    }

    #[test]
    fn marks_reports_incomplete_when_cancelled_or_a_limit_is_hit() {
        let root = TestDir::new("limits");
        fs::write(root.0.join("one.env"), "TOKEN=0123456789abcdef\n").unwrap();
        fs::write(root.0.join("two.env"), "PASSWORD=0123456789abcdef\n").unwrap();

        let limits = ScanLimits {
            max_files: 1,
            ..ScanLimits::default()
        };
        let limited = scan_directory(&root.0, &AtomicBool::new(false), &limits).unwrap();
        assert!(limited.incomplete);
        assert_eq!(limited.files_scanned, 1);

        let cancelled = AtomicBool::new(true);
        let cancelled_report = scan_directory(&root.0, &cancelled, &ScanLimits::default()).unwrap();
        assert!(cancelled_report.incomplete);
        assert_eq!(cancelled_report.files_scanned, 0);
    }

    #[test]
    fn enforces_findings_and_time_limits() {
        let root = TestDir::new("finding-limit");
        fs::write(
            root.0.join("many.env"),
            "TOKEN=0123456789abcdef\nPASSWORD=0123456789abcdef\n",
        )
        .unwrap();
        let limits = ScanLimits {
            max_findings: 1,
            ..ScanLimits::default()
        };
        let report = scan_directory(&root.0, &AtomicBool::new(false), &limits).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert!(report.incomplete);

        let expired = ScanLimits {
            max_duration: Duration::ZERO,
            ..ScanLimits::default()
        };
        assert!(
            scan_directory(&root.0, &AtomicBool::new(false), &expired)
                .unwrap()
                .incomplete
        );
    }

    #[test]
    fn enforces_total_byte_entry_and_depth_limits() {
        let root = TestDir::new("other-limits");
        fs::write(root.0.join("one.env"), "TOKEN=0123456789abcdef\n").unwrap();
        fs::write(root.0.join("two.env"), "PASSWORD=0123456789abcdef\n").unwrap();

        let bytes = ScanLimits {
            max_total_bytes: 24,
            ..ScanLimits::default()
        };
        let byte_report = scan_directory(&root.0, &AtomicBool::new(false), &bytes).unwrap();
        assert!(byte_report.incomplete);
        assert_eq!(byte_report.files_scanned, 1);

        let entries = ScanLimits {
            max_entries: 1,
            ..ScanLimits::default()
        };
        let entry_report = scan_directory(&root.0, &AtomicBool::new(false), &entries).unwrap();
        assert!(entry_report.incomplete);

        let nested = root.0.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("secret.env"), "TOKEN=0123456789abcdef\n").unwrap();
        let depth = ScanLimits {
            max_depth: 0,
            ..ScanLimits::default()
        };
        let depth_report = scan_directory(&root.0, &AtomicBool::new(false), &depth).unwrap();
        assert!(depth_report.incomplete);
        assert!(
            !depth_report
                .findings
                .iter()
                .any(|finding| finding.path == std::path::Path::new("nested/secret.env"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_as_the_scan_root() {
        let root = TestDir::new("root-link-target");
        let holder = TestDir::new("root-link-holder");
        let link = holder.0.join("link");
        std::os::unix::fs::symlink(&root.0, &link).unwrap();

        let error =
            scan_directory(&link, &AtomicBool::new(false), &ScanLimits::default()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_open_rejects_a_fifo_without_blocking() {
        let root = TestDir::new("fifo");
        let fifo = root.0.join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());

        assert!(open_regular_file(&fifo).unwrap().is_none());
    }
}
