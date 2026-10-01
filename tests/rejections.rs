use crate::support;

use crowsi_credential_agent::CREDENTIAL_ENROLLMENT_PURPOSE;
use crowsi_credential_broker::IpcError;
use crowsi_local_control_bridge::{BridgeAction, sha256_digest};
use support::{AuthorizationOptions, RuntimeFixture, SECRET_MARKER};

#[test]
fn consumed_reservation_cannot_be_replayed() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let mut fixture = RuntimeFixture::new(&AuthorizationOptions::default());
    assert!(fixture.exchange(SECRET_MARKER).server.is_ok());
    assert_eq!(
        fixture.exchange(SECRET_MARKER).server,
        Err(IpcError::AuthorizationRejected)
    );
}

#[test]
fn wrong_action_and_purpose_are_rejected_before_secret_storage() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let action = AuthorizationOptions {
        action: BridgeAction::ObserveProvider,
        ..AuthorizationOptions::default()
    };
    let purpose = AuthorizationOptions {
        purpose: "provider-observation".into(),
        ..AuthorizationOptions::default()
    };
    for options in [action, purpose] {
        let mut fixture = RuntimeFixture::new(&options);
        assert_eq!(
            fixture.exchange(SECRET_MARKER).server,
            Err(IpcError::AuthorizationRejected)
        );
    }
}

#[test]
fn enrollment_body_digest_is_bound_to_the_secret_metadata() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let options = AuthorizationOptions {
        body_sha256: Some(sha256_digest(b"different enrollment")),
        purpose: CREDENTIAL_ENROLLMENT_PURPOSE.into(),
        ..AuthorizationOptions::default()
    };
    let mut fixture = RuntimeFixture::new(&options);
    assert_eq!(
        fixture
            .exchange_without_client_preflight(SECRET_MARKER)
            .server,
        Err(IpcError::BindingRejected)
    );
}

#[test]
fn workload_and_kernel_peer_mismatches_fail_closed() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let options = AuthorizationOptions {
        workload: "spiffe://crowsi/local/other-client".into(),
        ..AuthorizationOptions::default()
    };
    let mut workload = RuntimeFixture::new(&options);
    assert_eq!(
        workload.exchange(SECRET_MARKER).server,
        Err(IpcError::AuthorizationRejected)
    );

    let uid = nix::unistd::Uid::effective().as_raw().saturating_add(1);
    let mut peer = RuntimeFixture::with_peer_uid(&AuthorizationOptions::default(), uid);
    assert_eq!(
        peer.exchange(SECRET_MARKER).server,
        Err(IpcError::AuthorizationRejected)
    );
}

#[test]
fn tampered_signed_request_is_not_authorized() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let mut fixture = RuntimeFixture::new(&AuthorizationOptions::default());
    fixture.material.envelope.request.resource = "credential-tampered".into();
    assert_eq!(
        fixture.exchange(SECRET_MARKER).server,
        Err(IpcError::AuthorizationRejected)
    );
}
