use std::fs;

use ladon::{IntegrationTarget, apply_integration_config, integration_preview};

#[test]
fn previews_contain_only_an_absolute_local_command() {
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
    let expected = executable.to_str().unwrap();
    for target in [IntegrationTarget::Codex, IntegrationTarget::Claude] {
        let preview = integration_preview(target, &executable).unwrap();
        match target {
            IntegrationTarget::Codex => {
                let document = preview.parse::<toml_edit::DocumentMut>().unwrap();
                assert_eq!(
                    document["mcp_servers"]["ladon"]["command"].as_str(),
                    Some(expected)
                );
            }
            IntegrationTarget::Claude => {
                let document: serde_json::Value = serde_json::from_str(&preview).unwrap();
                assert_eq!(document["mcpServers"]["ladon"]["command"], expected);
            }
        }
        assert!(preview.contains("mcp"));
        assert!(!preview.contains("fake-plaintext-value"));
        assert!(!preview.contains("remote"));
    }
}

#[test]
fn codex_edit_is_backed_up_scoped_and_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    fs::write(
        &config,
        "model = \"keep-me\"\n\n[mcp_servers.other]\ncommand = \"other\"\n",
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();

    let first = apply_integration_config(IntegrationTarget::Codex, &config, &executable).unwrap();
    assert!(first.changed);
    assert!(first.backup_path.as_ref().unwrap().exists());
    let updated = fs::read_to_string(&config).unwrap();
    assert!(updated.contains("model = \"keep-me\""));
    assert!(updated.contains("[mcp_servers.other]"));
    assert!(updated.contains("[mcp_servers.ladon]"));
    assert!(updated.contains("tool_timeout_sec = 1200"));
    assert!(!updated.contains("experimental_environment"));

    let second = apply_integration_config(IntegrationTarget::Codex, &config, &executable).unwrap();
    assert!(!second.changed);
    assert!(second.backup_path.is_none());
}

#[test]
fn claude_edit_preserves_other_servers_and_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("claude.json");
    fs::write(
        &config,
        r#"{"theme":"dark","mcpServers":{"other":{"type":"stdio","command":"other","args":[]}}}"#,
    )
    .unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();

    let first = apply_integration_config(IntegrationTarget::Claude, &config, &executable).unwrap();
    assert!(first.changed);
    assert!(first.backup_path.as_ref().unwrap().exists());
    let updated: serde_json::Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    assert_eq!(updated["theme"], "dark");
    assert_eq!(updated["mcpServers"]["other"]["command"], "other");
    assert_eq!(
        updated["mcpServers"]["ladon"]["command"],
        executable.to_str().unwrap()
    );
    assert_eq!(updated["mcpServers"]["ladon"]["args"][0], "mcp");

    let second = apply_integration_config(IntegrationTarget::Claude, &config, &executable).unwrap();
    assert!(!second.changed);
}
