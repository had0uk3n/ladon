use ladon_core::{
    BindingTarget, LadonError, ResolvedSecretBinding, RunCaller, RunRequest, SecretBindingRequest,
    SensitiveBytes, validate_run_request,
};

fn request() -> RunRequest {
    RunRequest {
        executable: std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned(),
        arguments: vec!["--help".to_owned()],
        working_directory: std::env::temp_dir().to_str().unwrap().to_owned(),
        bindings: vec![],
        timeout_ms: 300_000,
        output_limit_bytes: 512 * 1024,
    }
}

fn binding(target: BindingTarget) -> SecretBindingRequest {
    SecretBindingRequest {
        secret_ref: "example".to_owned(),
        field: "value".to_owned(),
        target,
    }
}

#[test]
fn rejects_relative_executable_and_working_directory() {
    let mut relative_executable = request();
    relative_executable.executable = "tool".to_owned();
    assert_eq!(
        validate_run_request(relative_executable, RunCaller::Mcp).unwrap_err(),
        LadonError::InvalidExecutablePath
    );

    let mut relative_directory = request();
    relative_directory.working_directory = "tmp".to_owned();
    assert_eq!(
        validate_run_request(relative_directory, RunCaller::Mcp).unwrap_err(),
        LadonError::InvalidWorkingDirectory
    );
}

#[test]
fn rejects_duplicate_environment_targets_and_multiple_stdin_bindings() {
    let mut duplicate_environment = request();
    duplicate_environment.bindings = vec![
        binding(BindingTarget::Environment {
            name: "TOKEN".to_owned(),
        }),
        binding(BindingTarget::TemporaryFileEnvironment {
            name: "TOKEN".to_owned(),
            suggested_filename: None,
        }),
    ];
    assert_eq!(
        validate_run_request(duplicate_environment, RunCaller::Mcp).unwrap_err(),
        LadonError::InvalidBinding
    );

    let mut duplicate_stdin = request();
    duplicate_stdin.bindings = vec![
        binding(BindingTarget::StandardInput),
        binding(BindingTarget::StandardInput),
    ];
    assert_eq!(
        validate_run_request(duplicate_stdin, RunCaller::Mcp).unwrap_err(),
        LadonError::InvalidBinding
    );
}

#[test]
fn rejects_invalid_environment_names_and_temp_file_suggestions() {
    for name in ["", "A=B", "BAD\0NAME"] {
        let mut invalid = request();
        invalid.bindings = vec![binding(BindingTarget::Environment {
            name: name.to_owned(),
        })];
        assert_eq!(
            validate_run_request(invalid, RunCaller::Mcp).unwrap_err(),
            LadonError::InvalidBinding
        );
    }

    for filename in [
        "../token.json",
        "nested/token.json",
        "token.long-extension-name",
    ] {
        let mut invalid = request();
        invalid.bindings = vec![binding(BindingTarget::TemporaryFileEnvironment {
            name: "TOKEN_FILE".to_owned(),
            suggested_filename: Some(filename.to_owned()),
        })];
        assert_eq!(
            validate_run_request(invalid, RunCaller::Mcp).unwrap_err(),
            LadonError::InvalidBinding
        );
    }
}

#[test]
fn enforces_binding_timeout_and_output_limits() {
    let mut too_many = request();
    too_many.bindings = (0..17)
        .map(|index| {
            binding(BindingTarget::Environment {
                name: format!("TOKEN_{index}"),
            })
        })
        .collect();
    assert_eq!(
        validate_run_request(too_many, RunCaller::Mcp).unwrap_err(),
        LadonError::TooManyBindings
    );

    let mut long_mcp = request();
    long_mcp.timeout_ms = 15 * 60 * 1000 + 1;
    assert_eq!(
        validate_run_request(long_mcp, RunCaller::Mcp).unwrap_err(),
        LadonError::InvalidTimeout
    );

    let mut long_cli = request();
    long_cli.timeout_ms = 2 * 60 * 60 * 1000;
    assert!(validate_run_request(long_cli, RunCaller::Cli).is_ok());

    for output_limit_bytes in [127, 2 * 1024 * 1024 + 1] {
        let mut invalid = request();
        invalid.output_limit_bytes = output_limit_bytes;
        assert_eq!(
            validate_run_request(invalid, RunCaller::Mcp).unwrap_err(),
            LadonError::InvalidOutputLimit
        );
    }
}

#[test]
fn resolves_only_after_validation_and_rejects_secret_in_command_metadata() {
    let mut raw = request();
    raw.arguments = vec!["prefix-super-secret-suffix".to_owned()];
    raw.bindings = vec![binding(BindingTarget::Environment {
        name: "TOKEN".to_owned(),
    })];
    let validated = validate_run_request(raw, RunCaller::Mcp).unwrap();

    assert_eq!(
        validated
            .resolve(vec![
                ResolvedSecretBinding::new(
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "value",
                    SensitiveBytes::new(b"super-secret".to_vec()),
                )
                .unwrap()
            ])
            .unwrap_err(),
        LadonError::SecretInCommand
    );
}

#[test]
fn rejects_more_than_one_mebibyte_of_resolved_binding_data() {
    let mut raw = request();
    raw.bindings = vec![binding(BindingTarget::Environment {
        name: "TOKEN".to_owned(),
    })];
    let validated = validate_run_request(raw, RunCaller::Mcp).unwrap();

    assert_eq!(
        validated
            .resolve(vec![
                ResolvedSecretBinding::new(
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    "value",
                    SensitiveBytes::new(vec![b'x'; 1024 * 1024 + 1]),
                )
                .unwrap()
            ])
            .unwrap_err(),
        LadonError::InjectedDataTooLarge
    );
}
