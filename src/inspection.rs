use crowsi_credential_broker::{BrokerError, CredentialStore, IpcError, SecretRef};
use serde::Serialize;

use crate::EnrollmentDraftV1;

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CredentialInspectionV1 {
    pub schema: &'static str,
    pub state: &'static str,
    pub credential_ref: String,
    pub allowed_hosts: Vec<String>,
    pub store_kind: &'static str,
    pub contains_secret_values: bool,
}

/// Reads only the metadata for one exact credential reference.
///
/// # Errors
///
/// Fails closed when the credential backend cannot prove its state.
pub fn inspect_credential<S: CredentialStore>(
    store: &S,
    draft: &EnrollmentDraftV1,
) -> Result<CredentialInspectionV1, IpcError> {
    let reference = draft.secret_ref()?;
    match store.metadata(&reference) {
        Ok(metadata) => Ok(report(
            "registered",
            &reference,
            metadata.allowed_hosts().to_vec(),
        )),
        Err(BrokerError::NotFound) => Ok(report("not-registered", &reference, Vec::new())),
        Err(_) => Err(IpcError::StoreUnavailable),
    }
}

fn report(
    state: &'static str,
    reference: &SecretRef,
    allowed_hosts: Vec<String>,
) -> CredentialInspectionV1 {
    CredentialInspectionV1 {
        schema: "crowsi://credential-agent/inspection/v1",
        state,
        credential_ref: reference.canonical_id(),
        allowed_hosts,
        store_kind: "windows-dpapi-user",
        contains_secret_values: false,
    }
}
