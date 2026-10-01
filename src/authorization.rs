use std::{os::unix::net::UnixStream, time::Duration};

use crowsi_credential_broker::{
    AuthorizationVerifier, IpcError, LeaseBinding, VerifiedAuthorization,
};
use crowsi_local_control_bridge::{
    BridgeAction, DispatchTicket, LocalControlBridge, TrustedClock, sha256_digest,
};

pub const CREDENTIAL_ENROLLMENT_ACTION: &str = "credential-enroll";
pub const CREDENTIAL_ENROLLMENT_PURPOSE: &str = "credential-enrollment";

/// Converts a consumed bridge ticket into the broker's private authorization.
pub struct BridgeAuthorizationVerifier<C> {
    bridge: LocalControlBridge<C>,
    timeout: Duration,
}

impl<C: TrustedClock> BridgeAuthorizationVerifier<C> {
    /// Creates a verifier with an authorization deadline no longer than 30 seconds.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive timeouts.
    pub fn new(bridge: LocalControlBridge<C>, timeout: Duration) -> Result<Self, IpcError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(IpcError::Timeout);
        }
        Ok(Self { bridge, timeout })
    }

    fn consume(&mut self, stream: &mut UnixStream) -> Result<DispatchTicket, IpcError> {
        let result = self.consume_blocking(stream);
        if stream.set_nonblocking(true).is_err() {
            return Err(IpcError::TransportUnavailable);
        }
        result
    }

    fn consume_blocking(&mut self, stream: &mut UnixStream) -> Result<DispatchTicket, IpcError> {
        self.bridge
            .authorize_unix_stream_with_timeout(stream, self.timeout)
            .map_err(|_| IpcError::AuthorizationRejected)
    }
}

impl<C: TrustedClock> AuthorizationVerifier for BridgeAuthorizationVerifier<C> {
    fn verify(&mut self, stream: &mut UnixStream) -> Result<VerifiedAuthorization, IpcError> {
        ticket_authorization(&self.consume(stream)?)
    }
}

fn ticket_authorization(ticket: &DispatchTicket) -> Result<VerifiedAuthorization, IpcError> {
    if ticket.action != BridgeAction::EnrollCredential
        || ticket.purpose != CREDENTIAL_ENROLLMENT_PURPOSE
    {
        return Err(IpcError::AuthorizationRejected);
    }
    let proof_key_ref = sender_key_reference(&ticket.sender_public_key_hex);
    let binding = LeaseBinding::new(
        &ticket.pairwise_subject,
        &ticket.device_id,
        &ticket.workload_id,
        &ticket.reservation_id,
        &ticket.resource,
        CREDENTIAL_ENROLLMENT_ACTION,
        &proof_key_ref,
    )
    .map_err(|_| IpcError::AuthorizationRejected)?;
    VerifiedAuthorization::new(
        &ticket.pairwise_subject,
        &ticket.device_id,
        &ticket.workload_id,
        &ticket.reservation_id,
        &ticket.resource,
        CREDENTIAL_ENROLLMENT_ACTION,
        &ticket.body_sha256,
        binding,
    )
}

fn sender_key_reference(sender_public_key_hex: &str) -> String {
    let mut domain_bound = b"crowsi:sender-proof-key:v1\0".to_vec();
    domain_bound.extend_from_slice(sender_public_key_hex.as_bytes());
    sha256_digest(&domain_bound).replacen(':', "-", 1)
}
