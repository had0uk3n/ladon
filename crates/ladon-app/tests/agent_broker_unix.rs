#![cfg(unix)]

use std::{
    io::Write,
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use ladon_app::{
    AddSecretDraft, EditableValue, LocalBrokerHandle, LocalClient, SensitiveText, VaultController,
};
use ladon_core::{
    BindingTarget, RpcMethod, RpcRequest, RpcResult, SecretBindingRequest, encode_request_frame,
};
use uuid::Uuid;

#[test]
fn gui_broker_runs_with_a_secret_without_returning_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(directory.path().join("vault.ladon"));
    controller.create(&passphrase, &passphrase).unwrap();
    let mut draft = AddSecretDraft::new();
    draft.set_name("test-token");
    draft.fields_mut()[0]
        .value_mut()
        .push_str("fake-broker-secret");
    controller.add_secret(&mut draft).unwrap();

    let endpoint = directory.path().join("broker.sock");
    let server = LocalBrokerHandle::start_at(Arc::new(Mutex::new(controller)), &endpoint).unwrap();
    let client = LocalClient::new(&endpoint);
    let client_session_id = Uuid::new_v4();

    let list = client
        .call(&request_for(client_session_id, RpcMethod::List))
        .unwrap();
    let Some(RpcResult::List { secrets }) = list.result() else {
        panic!("expected list response");
    };
    assert_eq!(secrets[0].name, "test-token");

    let marker = directory.path().join("started");
    let run_client = client.clone();
    let run_directory = directory.path().to_string_lossy().into_owned();
    let running = thread::spawn(move || {
        run_client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "printf started > started; printf %s \"$TOKEN\"".to_owned(),
                ],
                working_directory: run_directory,
                bindings: vec![SecretBindingRequest {
                    secret_ref: "test-token".to_owned(),
                    field: "value".to_owned(),
                    target: BindingTarget::Environment {
                        name: "TOKEN".to_owned(),
                    },
                }],
                timeout_ms: 5_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    let approval = wait_for_pending(&server);
    assert!(!marker.exists(), "child process started before approval");
    assert_eq!(approval.secrets()[0].name(), "test-token");
    assert_eq!(approval.secrets()[0].fields(), &["value"]);
    for (method, label) in [
        (RpcMethod::Status, "status label"),
        (RpcMethod::List, "list label"),
    ] {
        let mut observed = request_for(client_session_id, method);
        observed.client_label = label.to_owned();
        assert!(client.call(&observed).unwrap().result().is_some());
        assert_eq!(
            server.pending_approval().unwrap().unwrap().client_label(),
            label
        );
    }
    server.approve(approval.id()).unwrap();
    let run = running.join().unwrap().unwrap();
    let Some(RpcResult::Run {
        stdout,
        redaction_count,
        ..
    }) = run.result()
    else {
        panic!("expected run response: {:?}", run.error_details());
    };
    assert!(!stdout.contains("fake-broker-secret"));
    assert!(stdout.contains("[REDACTED]"));
    assert!(*redaction_count >= 1);

    let run_client = client.clone();
    let running = thread::spawn(move || {
        run_client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "trap '' TERM; while :; do sleep 1; done".to_owned(),
                ],
                working_directory: "/tmp".to_owned(),
                bindings: vec![SecretBindingRequest {
                    secret_ref: "test-token".to_owned(),
                    field: "value".to_owned(),
                    target: BindingTarget::Environment {
                        name: "TOKEN".to_owned(),
                    },
                }],
                timeout_ms: 1_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    thread::sleep(Duration::from_millis(100));
    let revoke_started = Instant::now();
    server.revoke_grants().unwrap();
    assert!(revoke_started.elapsed() >= Duration::from_millis(400));
    let run = running.join().unwrap().unwrap();
    let Some(RpcResult::Run { termination, .. }) = run.result() else {
        panic!("expected cancelled run response");
    };
    assert_eq!(termination, "cancelled");

    let lock = client
        .call(&request_for(client_session_id, RpcMethod::Lock))
        .unwrap();
    assert!(matches!(lock.result(), Some(RpcResult::Locked)));

    let locked_use = client
        .call(&request_for(client_session_id, RpcMethod::List))
        .unwrap();
    assert_eq!(
        locked_use.error_details(),
        Some(("vault_locked", "vault is locked"))
    );
}

#[test]
fn disconnecting_the_client_cancels_its_secret_bearing_run() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(directory.path().join("vault.ladon"));
    controller.create(&passphrase, &passphrase).unwrap();
    let mut draft = AddSecretDraft::new();
    draft.set_name("test-token");
    draft.fields_mut()[0].value_mut().push_str("fake-secret");
    controller.add_secret(&mut draft).unwrap();

    let endpoint = directory.path().join("broker.sock");
    let server = LocalBrokerHandle::start_at(Arc::new(Mutex::new(controller)), &endpoint).unwrap();
    let client_session_id = Uuid::new_v4();
    let runaway = request_for(
        client_session_id,
        RpcMethod::Run {
            executable: "/bin/sh".to_owned(),
            arguments: vec![
                "-c".to_owned(),
                "trap '' TERM; while :; do sleep 1; done".to_owned(),
            ],
            working_directory: "/tmp".to_owned(),
            bindings: vec![SecretBindingRequest {
                secret_ref: "test-token".to_owned(),
                field: "value".to_owned(),
                target: BindingTarget::Environment {
                    name: "TOKEN".to_owned(),
                },
            }],
            timeout_ms: 5_000,
            output_limit_bytes: 64 * 1024,
        },
    );
    let mut abandoned = UnixStream::connect(&endpoint).unwrap();
    abandoned
        .write_all(&encode_request_frame(&runaway).unwrap())
        .unwrap();
    wait_for_pending(&server);
    drop(abandoned);
    wait_for_no_pending(&server);

    let client = LocalClient::new(&endpoint);
    let replacement_client = client.clone();
    let replacement = thread::spawn(move || {
        replacement_client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), "printf replacement-finished".to_owned()],
                working_directory: "/tmp".to_owned(),
                bindings: vec![SecretBindingRequest {
                    secret_ref: "test-token".to_owned(),
                    field: "value".to_owned(),
                    target: BindingTarget::Environment {
                        name: "TOKEN".to_owned(),
                    },
                }],
                timeout_ms: 5_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    let approval = wait_for_pending(&server);
    server.approve(approval.id()).unwrap();
    let replacement = replacement.join().unwrap().unwrap();
    assert!(matches!(replacement.result(), Some(RpcResult::Run { .. })));
}

#[test]
fn approved_name_cannot_switch_to_a_replacement_secret_before_launch() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut controller = VaultController::new(directory.path().join("vault.ladon"));
    controller.create(&passphrase, &passphrase).unwrap();
    let mut original = AddSecretDraft::new();
    original.set_name("rotating-token");
    original.fields_mut()[0]
        .value_mut()
        .push_str("fake-original-secret");
    let original_id = controller.add_secret(&mut original).unwrap();
    let controller = Arc::new(Mutex::new(controller));

    let endpoint = directory.path().join("broker.sock");
    let server = LocalBrokerHandle::start_at(Arc::clone(&controller), &endpoint).unwrap();
    let marker = directory.path().join("started");
    let client = LocalClient::new(&endpoint);
    let client_session_id = Uuid::new_v4();
    let run_directory = directory.path().to_string_lossy().into_owned();
    let running = thread::spawn(move || {
        client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), "printf started > started".to_owned()],
                working_directory: run_directory,
                bindings: vec![SecretBindingRequest {
                    secret_ref: "rotating-token".to_owned(),
                    field: "value".to_owned(),
                    target: BindingTarget::Environment {
                        name: "TOKEN".to_owned(),
                    },
                }],
                timeout_ms: 5_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    let pending = wait_for_pending(&server);

    {
        let mut controller = controller.lock().unwrap();
        controller.delete_secret(original_id).unwrap();
        let mut replacement = AddSecretDraft::new();
        replacement.set_name("rotating-token");
        replacement.fields_mut()[0]
            .value_mut()
            .push_str("fake-replacement-secret");
        controller.add_secret(&mut replacement).unwrap();
    }
    server.approve(pending.id()).unwrap();

    let response = running.join().unwrap().unwrap();
    assert_eq!(
        response.error_details(),
        Some(("invalid_binding", "secret binding is invalid"))
    );
    assert!(
        !marker.exists(),
        "replacement secret reached a child process"
    );
}

#[test]
fn edit_revokes_the_old_grant_before_future_use() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut initial = VaultController::new(directory.path().join("vault.ladon"));
    initial.create(&passphrase, &passphrase).unwrap();
    let mut added = AddSecretDraft::new();
    added.set_name("test-token");
    added.fields_mut()[0]
        .value_mut()
        .push_str("fake-broker-secret");
    let secret_id = initial.add_secret(&mut added).unwrap();
    let controller = Arc::new(Mutex::new(initial));
    let endpoint = directory.path().join("broker.sock");
    let server = LocalBrokerHandle::start_at(Arc::clone(&controller), &endpoint).unwrap();
    let client = LocalClient::new(&endpoint);
    let client_session_id = Uuid::new_v4();
    let run = || RpcMethod::Run {
        executable: "/bin/sh".to_owned(),
        arguments: vec!["-c".to_owned(), "printf %s \"$TOKEN\"".to_owned()],
        working_directory: directory.path().to_string_lossy().into_owned(),
        bindings: vec![SecretBindingRequest {
            secret_ref: "test-token".to_owned(),
            field: "value".to_owned(),
            target: BindingTarget::Environment {
                name: "TOKEN".to_owned(),
            },
        }],
        timeout_ms: 5_000,
        output_limit_bytes: 64 * 1024,
    };

    let first_client = client.clone();
    let first_method = run();
    let first =
        thread::spawn(move || first_client.call(&request_for(client_session_id, first_method)));
    let pending = wait_for_pending(&server);
    server.approve(pending.id()).unwrap();
    assert!(matches!(
        first.join().unwrap().unwrap().result(),
        Some(RpcResult::Run { .. })
    ));

    let mut edit = controller.lock().unwrap().load_secret(secret_id).unwrap();
    let EditableValue::Text(value) = edit.fields_mut()[0].value_mut() else {
        panic!("expected text field");
    };
    value.clear();
    value.push_str("fake-replacement-secret");
    server.update_secret(&controller, &edit).unwrap();

    let retry_client = client.clone();
    let retry_method = run();
    let retry =
        thread::spawn(move || retry_client.call(&request_for(client_session_id, retry_method)));
    let pending = wait_for_pending(&server);
    server.deny(pending.id()).unwrap();
    let response = retry.join().unwrap().unwrap();
    assert_eq!(
        response.error_details(),
        Some(("approval_denied", "agent request was denied"))
    );
    let debug = format!("{response:?}");
    assert!(!debug.contains("fake-broker-secret"));
    assert!(!debug.contains("fake-replacement-secret"));
}

#[test]
fn delete_cancels_mixed_pending_and_replacement_requires_reapproval_without_leakage() {
    let directory = tempfile::tempdir().unwrap();
    let passphrase = SensitiveText::from("correct horse");
    let mut initial = VaultController::new(directory.path().join("vault.ladon"));
    initial.create(&passphrase, &passphrase).unwrap();
    let mut deleted = AddSecretDraft::new();
    deleted.set_name("delete-target");
    deleted.fields_mut()[0]
        .value_mut()
        .push_str("fake-deleted-secret");
    let deleted_id = initial.add_secret(&mut deleted).unwrap();
    let mut other = AddSecretDraft::new();
    other.set_name("other-target");
    other.fields_mut()[0]
        .value_mut()
        .push_str("fake-other-secret");
    initial.add_secret(&mut other).unwrap();
    let controller = Arc::new(Mutex::new(initial));
    let endpoint = directory.path().join("broker.sock");
    let server = LocalBrokerHandle::start_at(Arc::clone(&controller), &endpoint).unwrap();
    let client = LocalClient::new(&endpoint);
    let client_session_id = Uuid::new_v4();
    let working_directory = directory.path().to_string_lossy().into_owned();
    let target_binding = || SecretBindingRequest {
        secret_ref: "delete-target".to_owned(),
        field: "value".to_owned(),
        target: BindingTarget::Environment {
            name: "TARGET".to_owned(),
        },
    };
    let other_binding = || SecretBindingRequest {
        secret_ref: "other-target".to_owned(),
        field: "value".to_owned(),
        target: BindingTarget::Environment {
            name: "OTHER".to_owned(),
        },
    };

    let first_client = client.clone();
    let first_directory = working_directory.clone();
    let first = thread::spawn(move || {
        first_client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), "printf %s \"$TARGET\"".to_owned()],
                working_directory: first_directory,
                bindings: vec![target_binding()],
                timeout_ms: 5_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    let pending = wait_for_pending(&server);
    server.approve(pending.id()).unwrap();
    let first_response = first.join().unwrap().unwrap();
    assert!(matches!(
        first_response.result(),
        Some(RpcResult::Run { .. })
    ));
    assert!(!format!("{first_response:?}").contains("fake-deleted-secret"));

    let mixed_client = client.clone();
    let mixed_directory = working_directory.clone();
    let mixed = thread::spawn(move || {
        mixed_client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec![
                    "-c".to_owned(),
                    "printf %s%s \"$TARGET\" \"$OTHER\"".to_owned(),
                ],
                working_directory: mixed_directory,
                bindings: vec![target_binding(), other_binding()],
                timeout_ms: 5_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    let pending = wait_for_pending(&server);
    assert_eq!(pending.secrets().len(), 1);
    assert_eq!(pending.secrets()[0].name(), "other-target");

    server.delete_secret(&controller, deleted_id).unwrap();

    let approval_remained_pending = server.pending_approval().unwrap().is_some();
    if approval_remained_pending {
        server.deny(pending.id()).unwrap();
    }
    let cancelled = mixed.join().unwrap().unwrap();
    assert!(
        !approval_remained_pending,
        "delete did not cancel a mixed request that included the deleted ID"
    );
    assert_eq!(
        cancelled.error_details(),
        Some(("approval_cancelled", "approval request was cancelled"))
    );
    let mut replacement = AddSecretDraft::new();
    replacement.set_name("delete-target");
    replacement.fields_mut()[0]
        .value_mut()
        .push_str("fake-replacement-after-delete");
    controller
        .lock()
        .unwrap()
        .add_secret(&mut replacement)
        .unwrap();

    let retry_client = client.clone();
    let retry = thread::spawn(move || {
        retry_client.call(&request_for(
            client_session_id,
            RpcMethod::Run {
                executable: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), "printf %s \"$TARGET\"".to_owned()],
                working_directory,
                bindings: vec![target_binding()],
                timeout_ms: 5_000,
                output_limit_bytes: 64 * 1024,
            },
        ))
    });
    let pending = wait_for_pending(&server);
    server.deny(pending.id()).unwrap();
    let denied = retry.join().unwrap().unwrap();
    assert_eq!(
        denied.error_details(),
        Some(("approval_denied", "agent request was denied"))
    );
    let debug = format!("{cancelled:?}{denied:?}");
    assert!(!debug.contains("fake-deleted-secret"));
    assert!(!debug.contains("fake-other-secret"));
    assert!(!debug.contains("fake-replacement-after-delete"));
}

fn request_for(client_session_id: Uuid, method: RpcMethod) -> RpcRequest {
    RpcRequest {
        version: 2,
        request_id: Uuid::new_v4(),
        client_session_id,
        client_label: "integration test".to_owned(),
        method,
    }
}

fn wait_for_pending(server: &LocalBrokerHandle) -> ladon_app::PendingApproval {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(pending) = server.pending_approval().unwrap() {
            return pending;
        }
        assert!(Instant::now() < deadline, "approval never became pending");
        thread::yield_now();
    }
}

fn wait_for_no_pending(server: &LocalBrokerHandle) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if server.pending_approval().unwrap().is_none() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "cancelled approval remained pending"
        );
        thread::yield_now();
    }
}
