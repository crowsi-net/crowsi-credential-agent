use std::process::Command;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn readiness_is_closed_and_metadata_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential-agent"))
        .arg("sample-readiness")
        .output()
        .expect("run readiness");
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(document["state"], "unavailable");
    assert_eq!(document["external_actions"], false);
    assert_eq!(document["contains_secret_values"], false);
}

#[test]
fn enrollment_requires_the_complete_file_only_boundary() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let draft = root.path().join("draft.json");
    fs::write(&draft, valid_draft()).expect("draft");
    fs::set_permissions(&draft, fs::Permissions::from_mode(0o600)).expect("private draft");
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential-agent"))
        .args(["credential", "enroll", "--draft"])
        .arg(&draft)
        .output()
        .expect("run enrollment entry");
    assert_eq!(output.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--authorization"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("adapter-required"));
}

#[test]
fn stdin_enrollment_requires_the_complete_native_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential-agent"))
        .args([
            "credential",
            "enroll-stdin",
            "--config",
            "/missing/runtime.json",
        ])
        .output()
        .expect("run stdin enrollment entry");
    assert_eq!(output.status.code(), Some(64));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--authorization"));
    let stdin_usage = error
        .lines()
        .find(|line| line.contains("enroll-stdin"))
        .expect("stdin usage");
    assert!(!stdin_usage.contains("secret-file"));
}

#[test]
fn server_rejects_a_missing_platform_custody_runtime() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential-agent"))
        .args(["serve", "--config", "/missing/runtime.json"])
        .output()
        .expect("run server entry");
    assert_eq!(output.status.code(), Some(65));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "crowsi-credential-agent: invalid-owner-input"
    );
}

#[test]
fn validated_draft_builds_the_future_ipc_request_without_a_fake_secret() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("draft.json");
    fs::write(&path, valid_draft()).expect("draft");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private draft");
    let draft = crowsi_credential_agent::load_enrollment_draft(&path).expect("valid draft");
    let secret = b"TEST-ONLY-SIGNING-MATERIAL";
    let request = draft
        .enrollment_request("request-native-001", secret)
        .expect("closed enrollment request");

    assert_eq!(request.request_id(), "request-native-001");
    assert_eq!(request.secret_length(), secret.len() as u64);
    assert_ne!(
        request.secret_sha256(),
        crowsi_credential_broker::EnrollmentRequestV1::new(
            "request-native-001",
            request.credential().clone(),
            "Coela GitHub App",
            "github",
            ["api.github.com"],
            &[1],
        )
        .expect("old validation sentinel")
        .secret_sha256()
    );
}

#[test]
fn prepare_emits_the_exact_metadata_only_control_request() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let draft = root.path().join("draft.json");
    fs::write(&draft, valid_draft()).expect("draft");
    fs::set_permissions(&draft, fs::Permissions::from_mode(0o600)).expect("private draft");
    let digest = format!("sha256:{}", "a".repeat(64));
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential-agent"))
        .args(["credential", "prepare", "--draft"])
        .arg(&draft)
        .args([
            "--request-id",
            "request-browser-001",
            "--secret-length",
            "128",
            "--secret-sha256",
            &digest,
        ])
        .output()
        .expect("prepare request");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request: serde_json::Value = serde_json::from_slice(&output.stdout).expect("request");
    assert_eq!(request["request_id"], "request-browser-001");
    assert_eq!(request["purpose"], "credential-enrollment");
    assert_eq!(request["action"], "enroll-credential");
    assert_eq!(request["body_sha256"].as_str().map(str::len), Some(71));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret_sha256"));
}

fn valid_draft() -> &'static str {
    r#"{
      "schema":"crowsi://credentials/enrollment-draft/v1",
      "operation":"credential-enroll",
      "execution_channel":"native-ipc",
      "information_band":"local",
      "contains_secret_values":false,
      "credential":{
        "template_id":"github-app",
        "credential_id":"github-app",
        "label":"Coela GitHub App",
        "tenant":"coela",
        "provider":"github",
        "service":"coela-github-app",
        "purpose":"repository-read",
        "audience":"github",
        "allowed_hosts":["api.github.com"]
      }
    }"#
}
