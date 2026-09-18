use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod detection;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExposureRule {
    CredentialAssignment,
    PrivateKeyHeader,
    TokenPattern,
    ConnectionString,
    HighEntropyValue,
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
    pub(crate) roots: Vec<PathBuf>,
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
            max_file_bytes: 8 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_files: 100_000,
            max_entries: 500_000,
            max_depth: 32,
            max_duration: Duration::from_secs(120),
            max_findings: 5_000,
        }
    }
}

struct Scanner<'a> {
    display_root: Option<&'a Path>,
    cancel: &'a AtomicBool,
    limits: &'a ScanLimits,
    started: Instant,
    entries_seen: usize,
    total_bytes: u64,
    report: ScanReport,
    seen_files: HashSet<PathBuf>,
    seen_directories: HashSet<PathBuf>,
}

#[cfg(test)]
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

    let mut scanner = Scanner::new(Some(root), cancel, limits);
    scanner.report.roots.push(root.to_owned());
    scanner.walk(root, 0);
    Ok(scanner.report)
}

pub(crate) fn scan_user_files(
    home: &Path,
    extra_roots: &[PathBuf],
    cancel: &AtomicBool,
    limits: &ScanLimits,
) -> io::Result<ScanReport> {
    if !home.is_absolute() || !fs::symlink_metadata(home)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "home must be an absolute directory",
        ));
    }
    let mut scanner = Scanner::new(None, cancel, limits);
    let mut roots = vec![home.to_path_buf()];
    for root in extra_roots {
        if !roots.contains(root) {
            roots.push(root.clone());
        }
    }
    scanner.report.roots = roots.clone();
    // Check credential files across ALL roots before traversing any large tree.
    for root in &roots {
        if !root.is_absolute() {
            scanner.report.incomplete = true;
            continue;
        }
        scanner.priority_files(root);
    }
    for root in &roots {
        if root.is_absolute() {
            scanner.walk(root, 0);
        }
    }
    Ok(scanner.report)
}

impl Scanner<'_> {
    fn new<'a>(
        display_root: Option<&'a Path>,
        cancel: &'a AtomicBool,
        limits: &'a ScanLimits,
    ) -> Scanner<'a> {
        Scanner {
            display_root,
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
                roots: Vec::new(),
            },
            seen_files: HashSet::new(),
            seen_directories: HashSet::new(),
        }
    }

    fn priority_files(&mut self, root: &Path) {
        const PRIORITY: &[&str] = &[
            ".codex/auth.json",
            ".codex/config.toml",
            ".codex/.credentials.json",
            ".claude/.credentials.json",
            ".claude/settings.json",
            ".claude.json",
            "auth.json",
            "config.toml",
            ".credentials.json",
            "settings.json",
            ".env",
            ".env.local",
            ".env.production",
            ".mcp.json",
            ".npmrc",
            ".pypirc",
            ".netrc",
            ".git-credentials",
            ".aws/credentials",
            ".config/gcloud/application_default_credentials.json",
            ".docker/config.json",
            "Library/Application Support/Claude/claude_desktop_config.json",
            ".zshrc",
            ".zprofile",
            ".bashrc",
            ".bash_profile",
            ".profile",
        ];
        for relative in PRIORITY {
            if self.stopped() {
                return;
            }
            let mut candidate = root.to_path_buf();
            // Explicit priority paths must not bypass the traversal's symlink rule.
            let mut safe = fs::symlink_metadata(root).is_ok_and(|meta| meta.is_dir());
            for part in Path::new(relative).components() {
                candidate.push(part);
                if fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.file_type().is_symlink())
                {
                    safe = false;
                    break;
                }
            }
            if safe && candidate.is_file() {
                self.scan_file(&candidate);
            }
        }
    }

    fn stopped(&mut self) -> bool {
        if self.cancel.load(Ordering::Relaxed)
            || self.started.elapsed() >= self.limits.max_duration
            || self.report.files_scanned >= self.limits.max_files
            || self.report.findings.len() >= self.limits.max_findings
        {
            self.report.incomplete = true;
            true
        } else {
            false
        }
    }

    fn walk(&mut self, directory: &Path, depth: usize) {
        if self.seen_directories.contains(directory) {
            return;
        }
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
        self.seen_directories.insert(directory.to_path_buf());

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
        if !self.seen_files.insert(path.to_path_buf()) {
            return;
        }
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
        let relative = self
            .display_root
            .and_then(|root| path.strip_prefix(root).ok())
            .unwrap_or(path)
            .to_path_buf();
        let remaining = self
            .limits
            .max_findings
            .saturating_sub(self.report.findings.len());
        let (detections, incomplete) = detection::detect(text, remaining, &mut || {
            self.cancel.load(Ordering::Relaxed)
                || self.started.elapsed() >= self.limits.max_duration
        });
        self.report.incomplete |= incomplete;
        let mut previous_offset = 0;
        let mut line = 1;
        for found in detections {
            line += text[previous_offset..found.range.start]
                .bytes()
                .filter(|&byte| byte == b'\n')
                .count();
            previous_offset = found.range.start;
            self.report.findings.push(ScanFinding {
                path: relative.clone(),
                line,
                rule: found.rule,
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
    fn reads_hidden_dotenv_files_including_ignored_project_secrets() {
        let root = TestDir::new("dotenv");
        fs::create_dir_all(root.0.join("project/.config")).unwrap();
        fs::write(root.0.join("project/.gitignore"), ".env*\n.config/\n").unwrap();
        fs::write(root.0.join("project/.env"), "DB_PASSWORD=p4ss!\n").unwrap();
        fs::write(
            root.0.join("project/.env.local"),
            "export DATABASE_URL='postgres://alice:s3cr3t@localhost/app'\n",
        )
        .unwrap();
        fs::write(
            root.0.join("project/.config/.env.production"),
            "UNUSUAL_NAME=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n",
        )
        .unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 3);
        for name in [
            "project/.env",
            "project/.env.local",
            "project/.config/.env.production",
        ] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.path == Path::new(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn reads_multiple_credentials_on_one_line_of_assistant_json() {
        let root = TestDir::new("assistant-json");
        fs::write(root.0.join("auth.json"),
            "{\"tokens\":{\"access_token\":\"first-token-value==\",\"refresh_token\":\"second-token-value==\"}}\n").unwrap();
        fs::write(root.0.join(".mcp.json"),
            "{\"mcpServers\":{\"db\":{\"env\":{\"DB_PASSWORD\":\"short!\"},\"headers\":{\"Authorization\":\"Bearer third-token-value\"}}}}\n").unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 4);
        assert!(report.findings.iter().all(|finding| finding.line == 1));
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.path == Path::new("auth.json"))
                .count(),
            2
        );
        let debug = format!("{report:?}");
        for secret in [
            "first-token-value",
            "second-token-value",
            "short!",
            "third-token-value",
        ] {
            assert!(!debug.contains(secret));
        }
    }

    #[test]
    fn reads_toml_yaml_npmrc_and_escaped_json_values() {
        let root = TestDir::new("config-formats");
        fs::write(
            root.0.join("config.toml"),
            "[mcp_servers.demo.env]\nPASSWORD = 'short!'\n",
        )
        .unwrap();
        fs::write(
            root.0.join("secrets.yaml"),
            "service:\n  password: \"short!\"\n  clientSecret: 'abc=123'\n",
        )
        .unwrap();
        fs::write(
            root.0.join(".npmrc"),
            "//registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnopqrstuvwxyz\n",
        )
        .unwrap();
        fs::write(
            root.0.join("settings.json"),
            r#"{"api\u004bey":"abc\u003d123"}"#,
        )
        .unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 5);
    }

    #[test]
    fn detects_token_formats_and_connection_passwords_without_helpful_names() {
        let root = TestDir::new("value-formats");
        fs::write(
            root.0.join("notes.txt"),
            "unrelated: ghp_1234567890abcdefghijklmnopqrstuvwxyz\n\
             connect to postgres://alice:p4ss@db.local/app\n\
             curl -H 'Authorization: Bearer abcDEF1234567890' https://host.invalid\n",
        )
        .unwrap();
        assert_eq!(scan(&root.0).findings.len(), 3);
    }

    #[test]
    fn rejects_references_empty_values_and_public_connection_urls() {
        let root = TestDir::new("non-secrets");
        fs::write(
            root.0.join(".env.example"),
            "TOKEN=${REAL_TOKEN}\nTOKEN=$REAL_TOKEN\nPASSWORD=\"\"\nPASSWORD=null\n\
             API_KEY=your_api_key_here\nPASSWORD={{secrets.DB_PASSWORD}}\n\
             ENDPOINT=https://public.example/path\nDATABASE_URL=postgres://user@db.local/app\n\
             DATABASE_URL=postgres://user:${PASSWORD}@db.local/app\n",
        )
        .unwrap();
        assert!(scan(&root.0).findings.is_empty());
    }

    #[test]
    fn finds_opaque_values_without_counting_checksums_and_identifiers() {
        let root = TestDir::new("opaque-values");
        fs::write(
            root.0.join(".env"),
            "MYSTERY=aZ8!kP2@vQ6#rN4$xT9%wB3&yL7*\n\
             COMMIT=0123456789abcdef0123456789abcdef01234567\n\
             ID=550e8400-e29b-41d4-a716-446655440000\n",
        )
        .unwrap();
        assert_eq!(scan(&root.0).findings.len(), 1);
    }

    #[test]
    fn encrypted_pem_and_multiple_rules_do_not_inflate_the_count() {
        let root = TestDir::new("deduplication");
        fs::write(
            root.0.join(".env"),
            "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz\n",
        )
        .unwrap();
        fs::write(root.0.join("encrypted.pem"),
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,123456\n\nYWJj\n-----END RSA PRIVATE KEY-----\n").unwrap();
        assert_eq!(scan(&root.0).findings.len(), 1);
    }

    #[test]
    fn automatic_scan_covers_external_assistant_roots_without_duplicate_files() {
        let home = TestDir::new("home");
        let external = TestDir::new("external-codex");
        fs::create_dir(home.0.join(".claude")).unwrap();
        fs::write(
            home.0.join(".claude/.credentials.json"),
            "{\"accessToken\":\"local-token\"}",
        )
        .unwrap();
        fs::write(
            external.0.join("auth.json"),
            "{\"tokens\":{\"refresh_token\":\"remote-token\"}}",
        )
        .unwrap();
        let report = scan_user_files(
            &home.0,
            &[
                home.0.join(".claude"),
                external.0.clone(),
                external.0.clone(),
            ],
            &AtomicBool::new(false),
            &ScanLimits::default(),
        )
        .unwrap();
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.files_scanned, 2);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.path.is_absolute())
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.path == external.0.join("auth.json"))
        );
        assert!(!report.incomplete);
    }

    #[test]
    fn automatic_scan_prioritizes_credentials_before_general_home_contents() {
        let home = TestDir::new("priority");
        fs::create_dir(home.0.join(".codex")).unwrap();
        for number in 0..30 {
            fs::write(home.0.join(format!("notes-{number}.txt")), "ordinary text").unwrap();
        }
        fs::write(
            home.0.join(".codex/auth.json"),
            "{\"OPENAI_API_KEY\":\"local-token\"}",
        )
        .unwrap();
        let limits = ScanLimits {
            max_files: 1,
            ..ScanLimits::default()
        };
        let report = scan_user_files(&home.0, &[], &AtomicBool::new(false), &limits).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, home.0.join(".codex/auth.json"));
        assert!(report.incomplete);
    }

    #[test]
    fn automatic_scan_reports_missing_explicit_roots_as_partial() {
        let home = TestDir::new("missing-root");
        let report = scan_user_files(
            &home.0,
            &[home.0.join("does-not-exist")],
            &AtomicBool::new(false),
            &ScanLimits::default(),
        )
        .unwrap();
        assert!(report.incomplete);
    }

    #[test]
    fn reads_multiline_scalars_without_counting_format_markers() {
        let root = TestDir::new("multiline");
        fs::write(
            root.0.join("secrets.yaml"),
            "password: |\n  first-line\n  second-line\nclient_secret: short!\n",
        )
        .unwrap();
        fs::write(
            root.0.join("config.toml"),
            "password = \"\"\"\nmultiline-password\n\"\"\"\n",
        )
        .unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 3);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.path == Path::new("secrets.yaml") && f.line == 4)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.path == Path::new("config.toml"))
        );
    }

    #[test]
    fn empty_assignments_with_comments_are_not_secrets() {
        let root = TestDir::new("comment-values");
        fs::write(
            root.0.join(".env"),
            "API_KEY= # paste API key here\nPASSWORD=\"#\"\n",
        )
        .unwrap();
        fs::write(root.0.join("config.yaml"), "password: # from environment\n").unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, Path::new(".env"));
        assert_eq!(report.findings[0].line, 2);
    }

    #[test]
    fn literal_dollar_passwords_are_not_environment_references() {
        let root = TestDir::new("dollar-passwords");
        fs::write(
            root.0.join("settings.json"),
            r#"{"password":"$3cr3t!","token":"$REAL_TOKEN"}"#,
        )
        .unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn decodes_pem_strings_before_classifying_encryption() {
        let root = TestDir::new("escaped-pem");
        fs::write(root.0.join("encrypted.json"),
            r#"{"private_key":"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,123456\n\nYWJj\n-----END RSA PRIVATE KEY-----\n"}"#).unwrap();
        fs::write(
            root.0.join("plain.json"),
            r#"{"material":"-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n"}"#,
        )
        .unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, Path::new("plain.json"));
    }

    #[test]
    fn encrypted_openssh_keys_are_not_plaintext_findings() {
        let root = TestDir::new("openssh-encryption");
        // Synthetic OpenSSH magic + cipher name, sufficient for classifying
        // storage encryption. These are not usable private keys.
        fs::write(root.0.join("encrypted"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHI=\n-----END OPENSSH PRIVATE KEY-----\n").unwrap();
        fs::write(root.0.join("plain"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU=\n-----END OPENSSH PRIVATE KEY-----\n").unwrap();
        let report = scan(&root.0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].path, Path::new("plain"));
    }

    #[cfg(unix)]
    #[test]
    fn priority_locations_do_not_follow_symlinked_assistant_folders() {
        let home = TestDir::new("linked-assistant");
        let outside = TestDir::new("outside-assistant");
        fs::write(
            outside.0.join("auth.json"),
            "{\"access_token\":\"outside-token\"}",
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside.0, home.0.join(".codex")).unwrap();
        let report = scan_user_files(
            &home.0,
            &[],
            &AtomicBool::new(false),
            &ScanLimits::default(),
        )
        .unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.skipped_files, 1);
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
        // Binary + oversized file on every platform; the symlink fixture
        // above is created only on Unix.
        assert_eq!(report.skipped_files, if cfg!(unix) { 3 } else { 2 });
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
