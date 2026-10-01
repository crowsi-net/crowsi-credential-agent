use crate::support;

use crowsi_credential_broker::CredentialStore;
use support::{AuthorizationOptions, RuntimeFixture, SECRET_MARKER};

#[test]
fn signed_authorization_and_enrollment_share_one_stream() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let mut fixture = RuntimeFixture::new(&AuthorizationOptions::default());
    let exchange = fixture.exchange(SECRET_MARKER);
    assert!(
        exchange.server.is_ok(),
        "server={:?}, client={:?}",
        exchange.server,
        exchange.client
    );
    let server = exchange.server.expect("server receipt");
    let client = exchange.client.expect("client receipt");

    assert_eq!(client.status(), "ready");
    assert_eq!(server.status(), "ready");
    assert!(!client.contains_secret_values());
    let reference = fixture.material.request.to_secret_ref().expect("reference");
    let metadata = fixture.store.metadata(&reference).expect("stored metadata");
    assert_eq!(metadata.reference(), &reference);
}

#[test]
fn receipts_and_debug_output_never_contain_secret_material() {
    if !support::kernel_peer_attestation_available() {
        return;
    }
    let mut fixture = RuntimeFixture::new(&AuthorizationOptions::default());
    let exchange = fixture.exchange(SECRET_MARKER);
    assert!(exchange.server.is_ok(), "server must complete enrollment");
    let receipt = exchange.client.expect("receipt");
    let marker = String::from_utf8_lossy(SECRET_MARKER);

    assert!(
        !serde_json::to_string(&receipt)
            .expect("JSON")
            .contains(marker.as_ref())
    );
    assert!(!format!("{receipt:?}").contains(marker.as_ref()));
    assert!(!format!("{:?}", exchange.server).contains(marker.as_ref()));
}
