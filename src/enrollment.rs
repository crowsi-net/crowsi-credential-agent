use std::{os::unix::net::UnixStream, sync::Arc, time::Duration};

use crowsi_credential_broker::{CredentialStore, EnrollmentReceiptV1, EnrollmentService, IpcError};
use crowsi_local_control_bridge::{LocalControlBridge, TrustedClock};

use crate::BridgeAuthorizationVerifier;

/// Owns the single-stream authorization and enrollment composition.
pub struct CredentialEnrollment<S, C> {
    service: EnrollmentService<S, BridgeAuthorizationVerifier<C>>,
}

impl<S: CredentialStore, C: TrustedClock> CredentialEnrollment<S, C> {
    /// Creates the exact bridge-to-broker composition.
    ///
    /// # Errors
    ///
    /// Rejects invalid timeout or store metadata.
    pub fn new(
        store: Arc<S>,
        bridge: LocalControlBridge<C>,
        timeout: Duration,
        store_kind: &str,
    ) -> Result<Self, IpcError> {
        let verifier = BridgeAuthorizationVerifier::new(bridge, timeout)?;
        let service = EnrollmentService::new(store, verifier, timeout, store_kind)?;
        Ok(Self { service })
    }

    /// Consumes authorization before receiving or persisting a secret.
    ///
    /// # Errors
    ///
    /// Rejects authorization, framing, secret integrity, and storage failures.
    pub fn handle_stream(
        &mut self,
        stream: &mut UnixStream,
    ) -> Result<EnrollmentReceiptV1, IpcError> {
        self.service.handle(stream)
    }
}
