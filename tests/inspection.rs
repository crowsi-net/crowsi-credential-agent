use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_agent::{inspect_credential, load_enrollment_draft};
use crowsi_credential_broker::{CredentialEntry, CredentialStore, MemoryStore, SecretValue};

#[test]
fn inspection_distinguishes_absent_and_registered_without_secret_values() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("draft.json");
    fs::write(&path, draft()).expect("draft");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private draft");
    let draft = load_enrollment_draft(&path).expect("validated draft");
    let store = MemoryStore::default();

    let absent = inspect_credential(&store, &draft).expect("absent state");
    assert_eq!(absent.state, "not-registered");
    assert!(!absent.contains_secret_values);

    store
        .put(
            CredentialEntry::new(
                draft.secret_ref().expect("reference"),
                ["api.github.com".to_owned()],
                SecretValue::new(b"test-only-secret".to_vec()).expect("secret"),
            )
            .expect("entry"),
        )
        .expect("store credential");
    let ready = inspect_credential(&store, &draft).expect("registered state");
    assert_eq!(ready.state, "registered");
    assert_eq!(ready.allowed_hosts, ["api.github.com"]);
    assert!(!ready.contains_secret_values);
}

fn draft() -> &'static str {
    r#"{
      "schema":"crowsi://credentials/enrollment-draft/v1",
      "operation":"credential-enroll","execution_channel":"native-ipc",
      "information_band":"local","contains_secret_values":false,
      "credential":{"template_id":"github-repository-observer",
        "credential_id":"github-repository-observer-coela","label":"GitHub App key",
        "tenant":"coela","provider":"github","service":"coela-github-app",
        "purpose":"github-app-signing","audience":"coela-github-app",
        "allowed_hosts":["api.github.com"]}}
    "#
}
