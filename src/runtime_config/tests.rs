use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

use crowsi_local_control_bridge::{DurableSecurityStore, LocalControlBridge, SystemTrustedClock};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
    canonical_current_status_payload,
};

use super::load_runtime_config;

#[test]
fn signed_status_for_the_exact_device_is_applied() {
    let fixture = Fixture::new("service:crowsi", "device:workstation-a");
    assert!(fixture.apply().is_ok());
}

#[test]
fn signed_status_for_another_service_is_rejected() {
    let fixture = Fixture::new("service:other", "device:workstation-a");
    assert!(fixture.apply().is_err());
}

#[test]
fn device_b_status_cannot_be_applied_to_device_a_bridge() {
    let fixture = Fixture::new("service:crowsi", "device:workstation-b");
    assert!(fixture.apply().is_err());
}

#[test]
fn missing_status_file_fails_closed() {
    let fixture = Fixture::new("service:crowsi", "device:workstation-a");
    fs::remove_file(fixture.root.path().join("current-device-status.json")).expect("remove status");
    assert!(fixture.apply().is_err());
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new(status_service: &str, status_device: &str) -> Self {
        let root = tempfile::tempdir().expect("temporary directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
        let pa = SigningKey::from_bytes(&[42; 32]);
        let status_key = SigningKey::from_bytes(&[43; 32]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let mut status = CurrentDeviceStatusV1 {
            schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
            issuer: "ihat://identity-authority".into(),
            audience: "crowsi://credential-agent/current-status".into(),
            service_id: status_service.into(),
            pairwise_subject: "pairwise:crowsi:credential-agent".into(),
            device_id: status_device.into(),
            device_proof_key_ref: if status_device.ends_with('a') {
                "keyref:workstation-a"
            } else {
                "keyref:workstation-b"
            }
            .into(),
            session_ref: "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            device_posture: DevicePostureV1 {
                state: "compliant".into(),
                revision: 4,
            },
            revocation_epochs: RevocationEpochsV1 {
                subject: 3,
                service: 2,
                device: 4,
                session: 5,
            },
            issued_at_epoch_s: now.saturating_sub(1),
            expires_at_epoch_s: now + 20,
            nonce: format!("status:{status_service}:{status_device}"),
            key_id: "ihat-status-key:credential-agent:1".into(),
            signature: String::new(),
        };
        status.signature = hex::encode(
            status_key
                .sign(&canonical_current_status_payload(&status))
                .to_bytes(),
        );
        write_private(
            &root.path().join("current-device-status.json"),
            &serde_json::to_vec(&status).expect("status JSON"),
        );
        let config = serde_json::json!({
            "schema": "crowsi://credential-agent/runtime-config/v4",
            "pa_public_key_hex": hex::encode(pa.verifying_key().as_bytes()),
            "allowed_uid": nix::unistd::Uid::effective().as_raw(),
            "allowed_gid": nix::unistd::Gid::effective().as_raw(),
            "workload_id": "spiffe://crowsi/local/credential-agent",
            "caller_executable_sha256": format!("sha256:{}", "1".repeat(64)),
            "socket_path": root.path().join("agent.sock"),
            "state_path": root.path().join("state.sqlite3"),
            "custody_path": root.path().join("custody.json"),
            "identity_status": {
                "public_key_hex": hex::encode(status_key.verifying_key().as_bytes()),
                "key_id": "ihat-status-key:credential-agent:1",
                "issuer": "ihat://identity-authority",
                "audience": "crowsi://credential-agent/current-status",
                "service_id": "service:crowsi",
                "path": root.path().join("current-device-status.json"),
                "pairwise_subject": "pairwise:crowsi:credential-agent",
                "device_id": "device:workstation-a",
                "device_proof_key_ref": "keyref:workstation-a",
                "session_ref": "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "rate_limit_per_minute": 20,
            "request_timeout_ms": 1000
        });
        write_private(
            &root.path().join("runtime.json"),
            &serde_json::to_vec(&config).expect("config JSON"),
        );
        Self { root }
    }

    fn apply(&self) -> Result<(), crowsi_credential_broker::IpcError> {
        let config = load_runtime_config(&self.root.path().join("runtime.json"))?;
        let store = DurableSecurityStore::open(config.state_path(), 20)
            .map_err(|_| crowsi_credential_broker::IpcError::StoreUnavailable)?;
        let mut bridge = LocalControlBridge::new(
            config.trust()?,
            store,
            SystemTrustedClock::new()
                .map_err(|_| crowsi_credential_broker::IpcError::AuthorizationRejected)?,
        );
        config.apply_identity_status(&mut bridge)
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("owner file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner mode");
}
