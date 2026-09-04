use std::{
    env, fs,
    io::{self, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use ladon_app::{RunCancellation, RunTermination, Supervisor};
use ladon_core::{
    BindingTarget, ResolvedSecretBinding, RunCaller, RunRequest, SecretBindingRequest,
    SensitiveBytes, validate_run_request,
};

const ENV_VALUE: &[u8] = b"environment-secret";
const STDIN_VALUE: &[u8] = b"standard-input-secret";
const FILE_VALUE: &[u8] = b"temporary-file-secret";

fn fixture_arguments(name: &str) -> Vec<String> {
    vec![
        "--ignored".to_owned(),
        "--exact".to_owned(),
        name.to_owned(),
        "--nocapture".to_owned(),
    ]
}

fn binding(secret_ref: &str, field: &str, target: BindingTarget) -> SecretBindingRequest {
    SecretBindingRequest {
        secret_ref: secret_ref.to_owned(),
        field: field.to_owned(),
        target,
    }
}

fn validated(
    fixture: &str,
    bindings: Vec<SecretBindingRequest>,
    values: Vec<(&str, &str, &[u8])>,
    timeout_ms: u64,
) -> (ladon_core::ValidatedRunRequest, Vec<ResolvedSecretBinding>) {
    let executable = env::current_exe().unwrap();
    let working_directory = env::temp_dir();
    let request = RunRequest {
        executable: executable.to_str().unwrap().to_owned(),
        arguments: fixture_arguments(fixture),
        working_directory: working_directory.to_str().unwrap().to_owned(),
        bindings,
        timeout_ms,
        output_limit_bytes: 512 * 1024,
    };
    let validated = validate_run_request(request, RunCaller::Mcp).unwrap();
    let resolved = values
        .into_iter()
        .enumerate()
        .map(|(index, (id, field, value))| {
            let uuid = format!("{index:08x}-0000-4000-8000-000000000000");
            ResolvedSecretBinding::new(
                if id.is_empty() { &uuid } else { id },
                field,
                SensitiveBytes::new(value.to_vec()),
            )
            .unwrap()
        })
        .collect();
    (validated, resolved)
}

#[test]
fn injects_env_stdin_and_temp_file_without_inheriting_parent_environment() {
    assert!(env::var_os("PWD").is_some());
    let bindings = vec![
        binding(
            "env-secret",
            "value",
            BindingTarget::Environment {
                name: "LADON_TEST_ENV".to_owned(),
            },
        ),
        binding("stdin-secret", "value", BindingTarget::StandardInput),
        binding(
            "file-secret",
            "value",
            BindingTarget::TemporaryFileEnvironment {
                name: "LADON_TEST_FILE".to_owned(),
                suggested_filename: Some("credential.json".to_owned()),
            },
        ),
    ];
    let (run, resolved) = validated(
        "fixture_injection",
        bindings,
        vec![
            ("", "value", ENV_VALUE),
            ("", "value", STDIN_VALUE),
            ("", "value", FILE_VALUE),
        ],
        5_000,
    );

    let result = Supervisor::new()
        .run(run, RunCancellation::new(), |_| Ok(resolved))
        .unwrap();

    assert_eq!(result.termination, RunTermination::Exited);
    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("env-ok=true"));
    assert!(result.stdout.contains("stdin-ok=true"));
    assert!(result.stdout.contains("file-ok=true"));
    assert!(result.stdout.contains("inherited=false"));
    let temp_path = result
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("temp-path="))
        .unwrap();
    assert!(temp_path.ends_with(".json"));
    assert!(!std::path::Path::new(temp_path).exists());
    assert!(!result.temp_cleanup_warning);
}

#[test]
fn redacts_all_child_output_before_returning_it() {
    let (run, resolved) = validated(
        "fixture_output",
        vec![binding(
            "output-secret",
            "value",
            BindingTarget::Environment {
                name: "LADON_TEST_ENV".to_owned(),
            },
        )],
        vec![("", "value", ENV_VALUE)],
        5_000,
    );

    let result = Supervisor::new()
        .run(run, RunCancellation::new(), |_| Ok(resolved))
        .unwrap();

    assert!(!result.stdout.contains("environment-secret"));
    assert!(!result.stderr.contains("environment-secret"));
    assert!(result.stdout.contains("[REDACTED:"));
    assert!(result.stderr.contains("[REDACTED:"));
    assert!(result.redaction_count >= 2);
}

#[test]
fn timeout_terminates_the_process_group() {
    let (run, resolved) = validated("fixture_sleep", vec![], vec![], 100);

    let result = Supervisor::new()
        .run(run, RunCancellation::new(), |_| Ok(resolved))
        .unwrap();

    assert_eq!(result.termination, RunTermination::TimedOut);
    assert!(result.duration < Duration::from_secs(3));
}

#[test]
fn explicit_cancellation_terminates_the_process_group() {
    let supervisor = Arc::new(Supervisor::new());
    let cancellation = RunCancellation::new();
    let worker_control = cancellation.clone();
    let worker_supervisor = Arc::clone(&supervisor);
    let worker = thread::spawn(move || {
        let (run, resolved) = validated("fixture_sleep", vec![], vec![], 5_000);
        worker_supervisor
            .run(run, worker_control, |_| Ok(resolved))
            .unwrap()
    });
    thread::sleep(Duration::from_millis(100));
    cancellation.cancel();

    let result = worker.join().unwrap();
    assert_eq!(result.termination, RunTermination::Cancelled);
}

#[test]
fn a_second_concurrent_run_is_rejected_instead_of_queued() {
    let supervisor = Arc::new(Supervisor::new());
    let first_control = RunCancellation::new();
    let worker_control = first_control.clone();
    let worker_supervisor = Arc::clone(&supervisor);
    let worker = thread::spawn(move || {
        let (run, resolved) = validated("fixture_sleep", vec![], vec![], 5_000);
        worker_supervisor.run(run, worker_control, |_| Ok(resolved))
    });
    thread::sleep(Duration::from_millis(100));

    let (second_run, second_resolved) = validated("fixture_output", vec![], vec![], 5_000);
    let second = supervisor.run(second_run, RunCancellation::new(), |_| Ok(second_resolved));
    assert_eq!(second.unwrap_err(), ladon_core::LadonError::Busy);

    first_control.cancel();
    worker.join().unwrap().unwrap();
}

#[test]
fn invalid_filesystem_target_is_rejected_before_secret_resolution() {
    let run = validate_run_request(
        RunRequest {
            executable: env::temp_dir()
                .join("ladon-path-that-does-not-exist")
                .to_str()
                .unwrap()
                .to_owned(),
            arguments: vec![],
            working_directory: env::temp_dir().to_str().unwrap().to_owned(),
            bindings: vec![],
            timeout_ms: 5_000,
            output_limit_bytes: 512 * 1024,
        },
        RunCaller::Mcp,
    )
    .unwrap();
    let resolver_called = AtomicBool::new(false);

    let result = Supervisor::new().run(run, RunCancellation::new(), |_| {
        resolver_called.store(true, Ordering::Release);
        Ok(vec![])
    });

    assert_eq!(
        result.unwrap_err(),
        ladon_core::LadonError::InvalidExecutablePath
    );
    assert!(!resolver_called.load(Ordering::Acquire));
}

#[test]
fn large_stdin_and_stdout_do_not_deadlock_each_other() {
    let stdin_value = vec![b's'; 256 * 1024];
    let (run, resolved) = validated(
        "fixture_duplex_io",
        vec![binding(
            "stdin-secret",
            "value",
            BindingTarget::StandardInput,
        )],
        vec![("", "value", &stdin_value)],
        5_000,
    );

    let result = Supervisor::new()
        .run(run, RunCancellation::new(), |_| Ok(resolved))
        .unwrap();

    assert_eq!(result.termination, RunTermination::Exited);
    assert!(result.stdout.contains("stdin-len=262144"));
}

#[test]
#[ignore]
fn fixture_injection() {
    let environment = env::var_os("LADON_TEST_ENV")
        .map(|value| value.as_encoded_bytes() == ENV_VALUE)
        .unwrap_or(false);
    let mut stdin = Vec::new();
    io::stdin().read_to_end(&mut stdin).unwrap();
    let file_path = env::var("LADON_TEST_FILE").unwrap();
    let file = fs::read(&file_path).unwrap();
    println!("env-ok={environment}");
    println!("stdin-ok={}", stdin == STDIN_VALUE);
    println!("file-ok={}", file == FILE_VALUE);
    println!("inherited={}", env::var_os("PWD").is_some());
    println!("temp-path={file_path}");
}

#[test]
#[ignore]
fn fixture_output() {
    let value = env::var("LADON_TEST_ENV").unwrap_or_default();
    println!("stdout={value}");
    eprintln!("stderr={value}");
}

#[test]
#[ignore]
fn fixture_sleep() {
    thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore]
fn fixture_duplex_io() {
    io::stdout().write_all(&vec![b'o'; 256 * 1024]).unwrap();
    let mut stdin = Vec::new();
    io::stdin().read_to_end(&mut stdin).unwrap();
    println!("\nstdin-len={}", stdin.len());
}
