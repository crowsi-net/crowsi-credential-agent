use std::{
    io::{ErrorKind, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

use crowsi_credential_broker::{
    EnrollmentClient, EnrollmentReceiptV1, EnrollmentRequestV1, IpcError, credential_resource,
    enrollment_body_sha256,
};
use crowsi_local_control_bridge::{BridgeAction, IpcAuthorizationEnvelopeV2};

use crate::CREDENTIAL_ENROLLMENT_PURPOSE;

const MAX_AUTHORIZATION_BYTES: usize = 65_536;

/// Writes one signed authorization before enrollment on the same Unix stream.
pub struct CredentialAgentClient {
    enrollment: EnrollmentClient,
    timeout: Duration,
}

impl CredentialAgentClient {
    /// Creates a client with a finite end-to-end authorization window.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive timeouts.
    pub fn new(timeout: Duration) -> Result<Self, IpcError> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) {
            return Err(IpcError::Timeout);
        }
        Ok(Self {
            enrollment: EnrollmentClient::new(timeout),
            timeout,
        })
    }

    /// Sends a bound authorization and secret enrollment on one stream.
    ///
    /// # Errors
    ///
    /// Rejects mismatched metadata, framing, authorization, or transport state.
    pub fn enroll(
        &self,
        stream: &mut UnixStream,
        authorization: &IpcAuthorizationEnvelopeV2,
        request: &EnrollmentRequestV1,
        secret: &[u8],
    ) -> Result<EnrollmentReceiptV1, IpcError> {
        validate_binding(authorization, request)?;
        let encoded = serde_json::to_vec(authorization).map_err(|_| IpcError::InvalidFrame)?;
        if encoded.is_empty() || encoded.len() > MAX_AUTHORIZATION_BYTES {
            return Err(IpcError::FrameOversized);
        }
        stream
            .set_write_timeout(Some(self.timeout))
            .and_then(|()| stream.set_read_timeout(Some(self.timeout)))
            .map_err(|error| map_io(&error))?;
        let length = u32::try_from(encoded.len()).map_err(|_| IpcError::FrameOversized)?;
        stream
            .write_all(&length.to_be_bytes())
            .map_err(|error| map_io(&error))?;
        stream.write_all(&encoded).map_err(|error| map_io(&error))?;
        self.enrollment
            .exchange_after_authorization(stream, request, secret)
    }
}

fn validate_binding(
    envelope: &IpcAuthorizationEnvelopeV2,
    request: &EnrollmentRequestV1,
) -> Result<(), IpcError> {
    let control = &envelope.request;
    let exact = envelope.schema == "crowsi://local-control/ipc-envelope/v2"
        && control.request_id == request.request_id()
        && control.action == BridgeAction::EnrollCredential
        && control.resource == credential_resource(request.credential())?
        && control.purpose == CREDENTIAL_ENROLLMENT_PURPOSE
        && control.body_sha256 == enrollment_body_sha256(request)?;
    exact.then_some(()).ok_or(IpcError::BindingRejected)
}

fn map_io(error: &std::io::Error) -> IpcError {
    match error.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => IpcError::Timeout,
        _ => IpcError::TransportUnavailable,
    }
}
