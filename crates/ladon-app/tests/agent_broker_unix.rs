#![cfg(unix)]

use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use ladon_app::{AddSecretDraft, LocalBrokerHandle, LocalClient, SensitiveText, VaultController};
use ladon_core::{BindingTarget, RpcMethod, RpcRequest, RpcResult, SecretBindingRequest};
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
    let _server = LocalBrokerHandle::start_at(Arc::new(Mutex::new(controller)), &endpoint).unwrap();
    let client = LocalClient::new(&endpoint);

    let list = client.call(&request(RpcMethod::List)).unwrap();
    let Some(RpcResult::List { secrets }) = list.result() else {
        panic!("expected list response");
    };
    assert_eq!(secrets[0].name, "test-token");

    let run = client
        .call(&request(RpcMethod::Run {
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
        }))
        .unwrap();
    let Some(RpcResult::Run {
        stdout,
        redaction_count,
        ..
    }) = run.result()
    else {
        panic!("expected run response: {:?}", run.error_details());
    };
    assert!(!stdout.contains("fake-broker-secret"));
    assert!(stdout.contains("[REDACTED:"));
    assert!(*redaction_count >= 1);

    let run_client = client.clone();
    let running = thread::spawn(move || {
        run_client.call(&request(RpcMethod::Run {
            executable: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 5".to_owned()],
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
        }))
    });
    thread::sleep(Duration::from_millis(100));
    let lock = client.call(&request(RpcMethod::Lock)).unwrap();
    assert!(matches!(lock.result(), Some(RpcResult::Locked)));
    let run = running.join().unwrap().unwrap();
    let Some(RpcResult::Run { termination, .. }) = run.result() else {
        panic!("expected cancelled run response");
    };
    assert_eq!(termination, "cancelled");

    let locked_use = client.call(&request(RpcMethod::List)).unwrap();
    assert_eq!(
        locked_use.error_details(),
        Some(("vault_locked", "vault is locked"))
    );
}

fn request(method: RpcMethod) -> RpcRequest {
    RpcRequest {
        version: 1,
        request_id: Uuid::new_v4(),
        client_label: "integration test".to_owned(),
        method,
    }
}
