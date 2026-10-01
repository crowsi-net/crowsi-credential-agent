fn current_status(document: &ControlAuthorizationV2) -> CurrentDeviceStatusV1 {
    let mut value = CurrentDeviceStatusV1 {
        schema: CURRENT_DEVICE_STATUS_SCHEMA.into(),
        issuer: "ihat://identity-authority".into(),
        audience: "crowsi://credential-agent/current-status".into(),
        service_id: document.service_id.clone(),
        pairwise_subject: document.pairwise_subject.clone(),
        device_id: document.device_id.clone(),
        device_proof_key_ref: document.device_proof_key_ref.clone(),
        session_ref: document.session_ref.clone(),
        device_posture: DevicePostureV1 {
            state: document.device_posture.clone(),
            revision: document.device_posture_revision,
        },
        revocation_epochs: RevocationEpochsV1 {
            subject: document.subject_revocation_epoch,
            service: document.service_revocation_epoch,
            device: document.device_revocation_epoch,
            session: document.session_revocation_epoch,
        },
        issued_at_epoch_s: u64::try_from(document.issued_at_epoch_s).expect("status time"),
        expires_at_epoch_s: u64::try_from(document.expires_at_epoch_s).expect("status expiry"),
        nonce: "status-credential-fixture-001".into(),
        key_id: "ihat-status-key:credential-fixture:1".into(),
        signature: String::new(),
    };
    let signer = SigningKey::from_bytes(&[9; 32]);
    value.signature = hex::encode(
        signer
            .sign(&canonical_current_status_payload(&value))
            .to_bytes(),
    );
    value
}
