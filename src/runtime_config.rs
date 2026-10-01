use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use crowsi_credential_broker::IpcError;
use crowsi_local_control_bridge::{
    BridgeTrust, CurrentStatusBinding, IdentityStatusTrust, LocalControlBridge, TrustedClock,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::private_file::read_owner_file;

#[cfg(test)]
mod tests;
mod validation;

const SCHEMA: &str = "crowsi://credential-agent/runtime-config/v4";
const IDENTITY_STATUS_AUDIENCE: &str = "crowsi://credential-agent/current-status";
const IDENTITY_STATUS_SERVICE: &str = "service:crowsi";
const MAX_CONFIG_BYTES: u64 = 65_536;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigV4 {
    schema: String,
    pa_public_key_hex: String,
    allowed_uid: u32,
    allowed_gid: u32,
    workload_id: String,
    caller_executable_sha256: String,
    socket_path: PathBuf,
    state_path: PathBuf,
    custody_path: PathBuf,
    identity_status: IdentityStatusProvisioningV2,
    rate_limit_per_minute: u32,
    request_timeout_ms: u64,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityStatusProvisioningV2 {
    public_key_hex: String,
    key_id: String,
    issuer: String,
    audience: String,
    service_id: String,
    path: PathBuf,
    pairwise_subject: String,
    device_id: String,
    device_proof_key_ref: String,
    session_ref: String,
}

impl RuntimeConfigV4 {
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    #[must_use]
    pub fn custody_path(&self) -> &Path {
        &self.custody_path
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub(crate) fn state_path(&self) -> &Path {
        &self.state_path
    }

    pub(crate) const fn rate_limit(&self) -> u32 {
        self.rate_limit_per_minute
    }

    pub(crate) const fn timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    pub(crate) fn trust(&self) -> Result<BridgeTrust, IpcError> {
        let status = IdentityStatusTrust::new(
            decode_key(&self.identity_status.public_key_hex)?,
            &self.identity_status.key_id,
            &self.identity_status.issuer,
            &self.identity_status.audience,
            &self.identity_status.service_id,
        )
        .map_err(|_| IpcError::AuthorizationRejected)?;
        BridgeTrust::new(
            decode_key(&self.pa_public_key_hex)?,
            self.allowed_uid,
            self.allowed_gid,
            &self.workload_id,
            &self.caller_executable_sha256,
            status,
        )
        .map_err(|_| IpcError::AuthorizationRejected)
    }

    pub(crate) fn apply_identity_status<C: TrustedClock>(
        &self,
        bridge: &mut LocalControlBridge<C>,
    ) -> Result<(), IpcError> {
        let (wire, binding) = self.identity_status_input()?;
        bridge
            .apply_current_device_status(&wire, &binding)
            .map_err(|_| IpcError::AuthorizationRejected)
    }

    pub(crate) fn verify_identity_status<C: TrustedClock>(
        &self,
        bridge: &LocalControlBridge<C>,
    ) -> Result<(), IpcError> {
        let (wire, binding) = self.identity_status_input()?;
        bridge
            .verify_current_device_status(&wire, &binding)
            .map_err(|_| IpcError::AuthorizationRejected)
    }

    fn identity_status_input(
        &self,
    ) -> Result<(Zeroizing<Vec<u8>>, CurrentStatusBinding), IpcError> {
        let wire = read_owner_file(&self.identity_status.path, 16_384)?;
        let binding = CurrentStatusBinding::new(
            &self.identity_status.pairwise_subject,
            &self.identity_status.service_id,
            &self.identity_status.device_id,
            &self.identity_status.device_proof_key_ref,
            &self.identity_status.session_ref,
        )
        .map_err(|_| IpcError::AuthorizationRejected)?;
        Ok((wire, binding))
    }
}

/// Loads the complete owner-only runtime trust and custody configuration.
///
/// # Errors
///
/// Rejects relative, linked, broad, unknown, or invalid configuration.
pub fn load_runtime_config(path: &Path) -> Result<RuntimeConfigV4, IpcError> {
    let bytes = read_owner_file(path, MAX_CONFIG_BYTES)?;
    serde_json::from_slice::<RuntimeConfigV4>(&bytes)
        .map_err(|_| IpcError::InvalidFrame)?
        .validate()
}

fn decode_key(value: &str) -> Result<[u8; 32], IpcError> {
    let lowercase_hex = value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
    if value.len() != 64 || !lowercase_hex {
        return Err(IpcError::InvalidFrame);
    }
    let mut bytes = [0_u8; 32];
    for (target, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let encoded = std::str::from_utf8(pair).map_err(|_| IpcError::InvalidFrame)?;
        *target = u8::from_str_radix(encoded, 16).map_err(|_| IpcError::InvalidFrame)?;
    }
    Ok(bytes)
}
