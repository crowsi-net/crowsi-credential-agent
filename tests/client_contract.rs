use std::{io::Read, os::unix::net::UnixStream, time::Duration};

use crowsi_credential_agent::CredentialAgentClient;
use crowsi_credential_broker::IpcError;
use support::{AuthorizationOptions, Material, SECRET_MARKER};

use crate::support;

#[test]
fn native_client_requires_a_finite_authorization_window() {
    assert!(matches!(
        CredentialAgentClient::new(Duration::ZERO),
        Err(IpcError::Timeout)
    ));
    assert!(matches!(
        CredentialAgentClient::new(Duration::from_secs(31)),
        Err(IpcError::Timeout)
    ));
    assert!(CredentialAgentClient::new(Duration::from_secs(15)).is_ok());
}

#[test]
fn mismatched_metadata_is_rejected_before_any_authorization_bytes_are_sent() {
    let mut material = Material::new(&AuthorizationOptions::default());
    material.envelope.request.body_sha256 = format!("sha256:{}", "0".repeat(64));
    let (mut client_stream, mut server_stream) = UnixStream::pair().expect("Unix stream");
    let client = CredentialAgentClient::new(Duration::from_secs(1)).expect("client");
    assert_eq!(
        client.enroll(
            &mut client_stream,
            &material.envelope,
            &material.request,
            SECRET_MARKER,
        ),
        Err(IpcError::BindingRejected)
    );
    server_stream
        .set_nonblocking(true)
        .expect("nonblocking peer");
    let mut byte = [0_u8; 1];
    assert_eq!(
        server_stream
            .read(&mut byte)
            .expect_err("no authorization bytes")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
}
