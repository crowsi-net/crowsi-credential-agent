use std::path::Path;

use crowsi_credential_broker::IpcError;
use crowsi_local_control_bridge::IpcAuthorizationEnvelopeV2;

use crate::private_file::read_owner_file;

const MAX_AUTHORIZATION_BYTES: u64 = 65_536;

/// Loads one external PA envelope without accepting caller identity fields separately.
///
/// # Errors
///
/// Rejects relative, linked, broad, oversized, or malformed envelope files.
pub fn load_authorization_envelope(path: &Path) -> Result<IpcAuthorizationEnvelopeV2, IpcError> {
    let bytes = read_owner_file(path, MAX_AUTHORIZATION_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| IpcError::InvalidFrame)
}
