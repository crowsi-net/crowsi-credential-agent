pub fn identity_status_trust() -> IdentityStatusTrust {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    IdentityStatusTrust::new(
        signer.verifying_key().to_bytes(),
        "ihat-status-key:credential-fixture:1",
        "ihat://identity-authority",
        "crowsi://credential-agent/current-status",
        "service:crowsi",
    )
    .expect("identity status trust")
}

pub fn apply_material_status<C: TrustedClock>(
    bridge: &mut LocalControlBridge<C>,
    material: &Material,
) {
    let status = &material.status;
    let binding = CurrentStatusBinding::new(
        &status.pairwise_subject,
        &status.service_id,
        &status.device_id,
        &status.device_proof_key_ref,
        &status.session_ref,
    )
    .expect("status binding");
    bridge
        .apply_current_device_status(&serde_json::to_vec(status).expect("status JSON"), &binding)
        .expect("status anchor");
}

pub fn private_root() -> TempDir {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private directory");
    root
}

pub fn executable_digest() -> String {
    sha256_digest(&fs::read("/proc/self/exe").expect("current executable"))
}

pub fn identity_status_config(root: &std::path::Path) -> serde_json::Value {
    let status_key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    serde_json::json!({
        "public_key_hex": hex::encode(status_key.verifying_key().as_bytes()),
        "key_id": "ihat-status-key:credential-agent:1",
        "issuer": "ihat://identity-authority",
        "audience": "crowsi://credential-agent/current-status",
        "service_id": "service:crowsi",
        "path": root.join("current-device-status.json"),
        "pairwise_subject": "pairwise-crowsi-credential-fixture",
        "device_id": "device-credential-workstation-a",
        "device_proof_key_ref": "keyref-device-credential-workstation-a",
        "session_ref": "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    })
}

fn write_authorization(stream: &mut UnixStream, material: &Material) {
    let encoded = serde_json::to_vec(&material.envelope).expect("authorization envelope");
    let length = u32::try_from(encoded.len()).expect("authorization length");
    stream.write_all(&length.to_be_bytes()).expect("length");
    stream.write_all(&encoded).expect("authorization");
}
