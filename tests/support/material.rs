use std::time::{SystemTime, UNIX_EPOCH};

use crowsi_credential_agent::CREDENTIAL_ENROLLMENT_PURPOSE;
use crowsi_credential_broker::{
    CredentialReferenceV1, EnrollmentRequestV1, credential_resource, enrollment_body_sha256,
};
use crowsi_local_control_bridge::{
    BridgeAction, ControlAuthorizationV2, ControlRequestV1, IpcAuthorizationEnvelopeV2,
    SenderProof, SignedAuthorization, canonical_authorization, canonical_request,
};
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    CURRENT_DEVICE_STATUS_SCHEMA, CurrentDeviceStatusV1, DevicePostureV1, RevocationEpochsV1,
    canonical_current_status_payload,
};

pub const SECRET_MARKER: &[u8] = b"TEST-ONLY-CROWSI-CREDENTIAL-MARKER";
pub const WORKLOAD: &str = "spiffe://crowsi/local/credential-client";

#[derive(Clone)]
pub struct AuthorizationOptions {
    pub action: BridgeAction,
    pub purpose: String,
    pub workload: String,
    pub body_sha256: Option<String>,
    pub reservation_id: String,
}

impl Default for AuthorizationOptions {
    fn default() -> Self {
        Self {
            action: BridgeAction::EnrollCredential,
            purpose: CREDENTIAL_ENROLLMENT_PURPOSE.into(),
            workload: WORKLOAD.into(),
            body_sha256: None,
            reservation_id: "reservation-credential-001".into(),
        }
    }
}

pub struct Material {
    pub request: EnrollmentRequestV1,
    pub envelope: IpcAuthorizationEnvelopeV2,
    pub pa_public_key: [u8; 32],
    pub status: CurrentDeviceStatusV1,
}

impl Material {
    pub fn new(options: &AuthorizationOptions) -> Self {
        let request = enrollment_request();
        let resource = credential_resource(request.credential()).expect("credential resource");
        let body_sha256 = options
            .body_sha256
            .clone()
            .unwrap_or_else(|| enrollment_body_sha256(&request).expect("body digest"));
        let control = ControlRequestV1 {
            schema: "crowsi://local-control/request/v1".into(),
            request_id: request.request_id().into(),
            action: options.action,
            resource,
            purpose: options.purpose.clone(),
            body_sha256,
        };
        let pa = SigningKey::from_bytes(&[7; 32]);
        let sender = SigningKey::from_bytes(&[8; 32]);
        let document = authorization_document(&control, options, &sender);
        let status = current_status(&document);
        let authorization = SignedAuthorization {
            signature_hex: hex::encode(pa.sign(&canonical_authorization(&document)).to_bytes()),
            document,
        };
        let sender_proof = SenderProof {
            signature_hex: hex::encode(sender.sign(&canonical_request(&control)).to_bytes()),
        };
        Self {
            request,
            envelope: IpcAuthorizationEnvelopeV2 {
                schema: "crowsi://local-control/ipc-envelope/v2".into(),
                request: control,
                authorization,
                sender_proof,
            },
            pa_public_key: pa.verifying_key().to_bytes(),
            status,
        }
    }
}

fn enrollment_request() -> EnrollmentRequestV1 {
    let reference = CredentialReferenceV1::new(
        "github-app",
        "coela",
        "coela-github-app",
        "repository-read",
        "github",
    )
    .expect("reference");
    EnrollmentRequestV1::new(
        "request-credential-001",
        reference,
        "Coela GitHub App",
        "github",
        ["api.github.com"],
        SECRET_MARKER,
    )
    .expect("request")
}

fn authorization_document(
    control: &ControlRequestV1,
    options: &AuthorizationOptions,
    sender: &SigningKey,
) -> ControlAuthorizationV2 {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("representable clock");
    ControlAuthorizationV2 {
        schema: "crowsi://local-control/authorization/v2".into(),
        issuer: "crowsi-policy-administrator".into(),
        audience: "crowsi-local-control-bridge".into(),
        service_id: "service:crowsi".into(),
        pairwise_subject: "pairwise-crowsi-credential-fixture".into(),
        device_id: "device-credential-workstation-a".into(),
        device_proof_key_ref: "keyref-device-credential-workstation-a".into(),
        session_ref: "sref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        device_posture: "compliant".into(),
        device_posture_revision: 4,
        subject_revocation_epoch: 3,
        service_revocation_epoch: 2,
        device_revocation_epoch: 4,
        session_revocation_epoch: 5,
        workload_id: options.workload.clone(),
        actor_profile_id: "profile-credential-operator".into(),
        assurance: "phishing-resistant".into(),
        user_verification: true,
        sender_public_key_hex: hex::encode(sender.verifying_key().to_bytes()),
        request_id: control.request_id.clone(),
        action: control.action,
        resource: control.resource.clone(),
        purpose: control.purpose.clone(),
        body_sha256: control.body_sha256.clone(),
        reservation_id: options.reservation_id.clone(),
        issued_at_epoch_s: now - 1,
        expires_at_epoch_s: now + 20,
    }
}

include!("material_status.rs");
