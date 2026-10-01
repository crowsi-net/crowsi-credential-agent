use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

use crowsi_credential_agent::load_runtime_config;
use ed25519_dalek::SigningKey;

#[test]
fn owner_only_absolute_runtime_config_loads_closed_trust_inputs() {
    let root = private_root();
    let path = write_config(root.path(), 0o600, &root.path().join("agent.sock"));
    let config = load_runtime_config(&path).expect("valid runtime config");

    assert_eq!(config.workload_id(), "spiffe://crowsi/local/credential-agent");
    assert_eq!(config.custody_path(), root.path().join("custody.json"));
    assert_eq!(config.socket_path(), root.path().join("agent.sock"));
}

#[test]
fn legacy_config_without_identity_status_provisioning_fails_closed() {
    let root = private_root();
    let key = SigningKey::from_bytes(&[42; 32]).verifying_key();
    let path = root.path().join("legacy-runtime.json");
    let document = serde_json::json!({
        "schema": "crowsi://credential-agent/runtime-config/v3",
        "pa_public_key_hex": hex::encode(key.as_bytes()),
        "allowed_uid": nix::unistd::Uid::effective().as_raw(),
        "allowed_gid": nix::unistd::Gid::effective().as_raw(),
        "workload_id": "spiffe://crowsi/local/credential-agent",
        "caller_executable_sha256": format!("sha256:{}", "1".repeat(64)),
        "socket_path": root.path().join("agent.sock"),
        "state_path": root.path().join("state.sqlite3"),
        "custody_path": root.path().join("custody.json"),
        "rate_limit_per_minute": 20,
        "request_timeout_ms": 1000
    });
    fs::write(&path, serde_json::to_vec(&document).expect("JSON")).expect("runtime config");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private config");
    assert!(load_runtime_config(&path).is_err());
}

#[test]
fn identity_status_consumer_context_is_fixed_by_runtime_and_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/runtime-config-v4.schema.json"))
            .expect("runtime schema");
    assert_eq!(
        schema["properties"]["identity_status"]["properties"]["audience"]["const"],
        "crowsi://credential-agent/current-status"
    );
    assert_eq!(
        schema["properties"]["identity_status"]["properties"]["service_id"]["const"],
        "service:crowsi"
    );
    let provisioning: serde_json::Value = serde_json::from_str(include_str!(
        "../schemas/current-device-status-provisioning-v2.schema.json"
    ))
    .expect("provisioning schema");
    assert_eq!(
        provisioning["properties"]["audience"]["const"],
        "crowsi://credential-agent/current-status"
    );
    assert_eq!(
        provisioning["properties"]["service_id"]["const"],
        "service:crowsi"
    );

    for (field, substituted) in [
        ("audience", "crowsi://attacker/current-status"),
        ("service_id", "service:attacker"),
    ] {
        let root = private_root();
        let path = write_config(root.path(), 0o600, &root.path().join("agent.sock"));
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("runtime bytes")).expect("runtime JSON");
        document["identity_status"][field] = substituted.into();
        fs::write(&path, serde_json::to_vec(&document).expect("runtime JSON"))
            .expect("substituted runtime");
        assert!(load_runtime_config(&path).is_err(), "accepted {field}");
    }
}

#[test]
fn broad_relative_and_symlinked_configs_fail_closed() {
    let root = private_root();
    let broad = write_config(root.path(), 0o640, &root.path().join("agent.sock"));
    assert!(load_runtime_config(&broad).is_err());
    assert!(load_runtime_config(std::path::Path::new("runtime.json")).is_err());

    fs::set_permissions(&broad, fs::Permissions::from_mode(0o600)).expect("private config");
    let link = root.path().join("runtime-link.json");
    symlink(&broad, &link).expect("config symlink");
    assert!(load_runtime_config(&link).is_err());
}

#[test]
fn overlong_linux_socket_paths_fail_before_runtime_startup() {
    let root = private_root();
    let path = write_config(root.path(), 0o600, &root.path().join("s".repeat(108)));

    assert!(load_runtime_config(&path).is_err());
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    root
}

fn write_config(root: &std::path::Path, mode: u32, socket: &std::path::Path) -> std::path::PathBuf {
    let key = SigningKey::from_bytes(&[42; 32]).verifying_key();
    let status_key = SigningKey::from_bytes(&[43; 32]).verifying_key();
    let path = root.join("runtime.json");
    let document = serde_json::json!({
        "schema": "crowsi://credential-agent/runtime-config/v4",
        "pa_public_key_hex": hex::encode(key.as_bytes()),
        "allowed_uid": nix::unistd::Uid::effective().as_raw(),
        "allowed_gid": nix::unistd::Gid::effective().as_raw(),
        "workload_id": "spiffe://crowsi/local/credential-agent",
        "caller_executable_sha256": format!("sha256:{}", "1".repeat(64)),
        "socket_path": socket,
        "state_path": root.join("state.sqlite3"),
        "custody_path": root.join("custody.json"),
        "identity_status": {
            "public_key_hex": hex::encode(status_key.as_bytes()),
            "key_id": "ihat-status-key:credential-agent:1",
            "issuer": "ihat://identity-authority",
            "audience": "crowsi://credential-agent/current-status",
            "service_id": "service:crowsi",
            "path": root.join("current-device-status.json"),
            "pairwise_subject": "pairwise:crowsi:credential-agent",
            "device_id": "device:workstation-a",
            "device_proof_key_ref": "keyref:workstation-a",
            "session_ref": "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "rate_limit_per_minute": 20,
        "request_timeout_ms": 1000
    });
    fs::write(&path, serde_json::to_vec(&document).expect("JSON")).expect("runtime config");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("config mode");
    path
}
