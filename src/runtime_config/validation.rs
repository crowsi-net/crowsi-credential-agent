use std::{
    fs::symlink_metadata,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
};

use crowsi_credential_broker::IpcError;

use super::{IDENTITY_STATUS_AUDIENCE, IDENTITY_STATUS_SERVICE, RuntimeConfigV4, SCHEMA};

impl RuntimeConfigV4 {
    pub(super) fn validate(self) -> Result<Self, IpcError> {
        let closed = self.schema == SCHEMA
            && self.identity_status.audience == IDENTITY_STATUS_AUDIENCE
            && self.identity_status.service_id == IDENTITY_STATUS_SERVICE
            && self.custody_path.is_absolute()
            && self.rate_limit_per_minute > 0
            && (1..=30_000).contains(&self.request_timeout_ms)
            && self.socket_path.as_os_str().as_bytes().len() <= 107
            && self.socket_path != self.state_path
            && self.socket_path != self.custody_path
            && self.state_path != self.custody_path
            && ![&self.socket_path, &self.state_path, &self.custody_path]
                .contains(&&self.identity_status.path);
        if !closed {
            return Err(IpcError::InvalidFrame);
        }
        validate_managed_parent(&self.socket_path)?;
        validate_managed_parent(&self.state_path)?;
        validate_managed_parent(&self.custody_path)?;
        validate_managed_parent(&self.identity_status.path)?;
        self.trust()?;
        Ok(self)
    }
}

fn validate_managed_parent(path: &Path) -> Result<(), IpcError> {
    if !path.is_absolute() {
        return Err(IpcError::InvalidFrame);
    }
    let parent = path.parent().ok_or(IpcError::InvalidFrame)?;
    if parent.canonicalize().map_err(|_| IpcError::InvalidFrame)? != parent {
        return Err(IpcError::InvalidFrame);
    }
    let metadata = symlink_metadata(parent).map_err(|_| IpcError::InvalidFrame)?;
    let private = metadata.is_dir()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o700;
    private.then_some(()).ok_or(IpcError::InvalidFrame)
}
