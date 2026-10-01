use std::path::Path;

use crowsi_credential_broker::{
    CredentialReferenceV1, EnrollmentRequestV1, IpcError, credential_resource,
    enrollment_body_sha256,
};
use crowsi_local_control_bridge::{BridgeAction, ControlRequestV1};
use serde::Deserialize;

use crate::private_file::read_owner_file;

const SCHEMA: &str = "crowsi://credentials/enrollment-draft/v1";
const MAX_DRAFT_BYTES: u64 = 65_536;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentDraftV1 {
    schema: String,
    operation: String,
    execution_channel: String,
    information_band: String,
    contains_secret_values: bool,
    credential: DraftCredential,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftCredential {
    template_id: String,
    credential_id: String,
    label: String,
    tenant: String,
    provider: String,
    service: String,
    purpose: String,
    audience: String,
    allowed_hosts: Vec<String>,
}

impl EnrollmentDraftV1 {
    fn validate(self) -> Result<Self, IpcError> {
        let closed = self.schema == SCHEMA
            && self.operation == "credential-enroll"
            && self.execution_channel == "native-ipc"
            && self.information_band == "local"
            && !self.contains_secret_values;
        if !closed {
            return Err(IpcError::InvalidFrame);
        }
        self.enrollment_request(&self.credential.template_id, &[1])?;
        Ok(self)
    }

    /// Builds the exact broker request after the native authority supplies a request ID.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers, hosts, or secret bounds.
    pub fn enrollment_request(
        &self,
        request_id: &str,
        secret: &[u8],
    ) -> Result<EnrollmentRequestV1, IpcError> {
        EnrollmentRequestV1::new(
            request_id,
            self.reference()?,
            &self.credential.label,
            &self.credential.provider,
            &self.credential.allowed_hosts,
            secret,
        )
    }

    /// Prepares the exact authorization request without receiving secret bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid request identifiers, secret metadata, or draft fields.
    pub fn control_request(
        &self,
        request_id: &str,
        secret_length: u64,
        secret_sha256: &str,
    ) -> Result<ControlRequestV1, IpcError> {
        let request = EnrollmentRequestV1::from_secret_metadata(
            request_id,
            self.reference()?,
            &self.credential.label,
            &self.credential.provider,
            &self.credential.allowed_hosts,
            secret_length,
            secret_sha256,
        )?;
        Ok(ControlRequestV1 {
            schema: "crowsi://local-control/request/v1".into(),
            request_id: request_id.into(),
            action: BridgeAction::EnrollCredential,
            resource: credential_resource(request.credential())?,
            purpose: crate::CREDENTIAL_ENROLLMENT_PURPOSE.into(),
            body_sha256: enrollment_body_sha256(&request)?,
        })
    }

    fn reference(&self) -> Result<CredentialReferenceV1, IpcError> {
        CredentialReferenceV1::new(
            &self.credential.credential_id,
            &self.credential.tenant,
            &self.credential.service,
            &self.credential.purpose,
            &self.credential.audience,
        )
    }

    /// Resolves the validated, secret-free store reference for inspection.
    ///
    /// # Errors
    ///
    /// Rejects invalid scope components instead of probing a different slot.
    pub fn secret_ref(&self) -> Result<crowsi_credential_broker::SecretRef, IpcError> {
        self.reference()?.to_secret_ref()
    }
}

/// Loads only an owner-readable, absolute, regular metadata-only draft.
///
/// # Errors
///
/// Rejects ambiguous paths, broad permissions, oversized data, and invalid schema.
pub fn load_enrollment_draft(path: &Path) -> Result<EnrollmentDraftV1, IpcError> {
    let encoded = read_owner_file(path, MAX_DRAFT_BYTES)?;
    serde_json::from_slice::<EnrollmentDraftV1>(&encoded)
        .map_err(|_| IpcError::InvalidFrame)?
        .validate()
}
