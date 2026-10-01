use std::{
    fs::symlink_metadata,
    io::Read,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
};

use crowsi_credential_broker::{EnrollmentReceiptV1, IpcError};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use crate::{
    CredentialAgentClient, SecretInput, load_authorization_envelope, load_enrollment_draft,
    load_runtime_config, read_secret, read_secret_stream,
};

/// Enrolls one owner-file secret through the authenticated local stream.
///
/// # Errors
///
/// Rejects unsafe files, socket substitution, binding mismatch, or failed custody.
pub fn enroll_from_owner_files(
    config_path: &Path,
    draft_path: &Path,
    authorization_path: &Path,
    secret_path: &Path,
) -> Result<EnrollmentReceiptV1, IpcError> {
    let config = load_runtime_config(config_path)?;
    let draft = load_enrollment_draft(draft_path)?;
    let authorization = load_authorization_envelope(authorization_path)?;
    let mut stream = connect_private_socket(config.socket_path())?;
    let secret = read_secret(&SecretInput::OwnerOnlyFile(secret_path.to_owned()))?;
    let request = draft.enrollment_request(&authorization.request.request_id, &secret)?;
    CredentialAgentClient::new(config.timeout())?.enroll(
        &mut stream,
        &authorization,
        &request,
        &secret,
    )
}

/// Enrolls bytes received over a managed native client's standard input.
///
/// # Errors
///
/// Rejects unsafe control files, untrusted sockets, or failed authorization.
pub fn enroll_from_owner_stream(
    config_path: &Path,
    draft_path: &Path,
    authorization_path: &Path,
    source: impl Read,
) -> Result<EnrollmentReceiptV1, IpcError> {
    let config = load_runtime_config(config_path)?;
    let draft = load_enrollment_draft(draft_path)?;
    let authorization = load_authorization_envelope(authorization_path)?;
    let mut stream = connect_private_socket(config.socket_path())?;
    let secret = read_secret_stream(source)?;
    let request = draft.enrollment_request(&authorization.request.request_id, &secret)?;
    CredentialAgentClient::new(config.timeout())?.enroll(
        &mut stream,
        &authorization,
        &request,
        &secret,
    )
}

fn connect_private_socket(path: &Path) -> Result<UnixStream, IpcError> {
    let before = private_socket_metadata(path)?;
    let stream = UnixStream::connect(path).map_err(|_| IpcError::TransportUnavailable)?;
    let peer = getsockopt(&stream, PeerCredentials).map_err(|_| IpcError::TransportUnavailable)?;
    if peer.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(IpcError::AuthorizationRejected);
    }
    let after = private_socket_metadata(path)?;
    let stable = before.dev() == after.dev() && before.ino() == after.ino();
    stable
        .then_some(stream)
        .ok_or(IpcError::TransportUnavailable)
}

fn private_socket_metadata(path: &Path) -> Result<std::fs::Metadata, IpcError> {
    if !path.is_absolute() {
        return Err(IpcError::TransportUnavailable);
    }
    let metadata = symlink_metadata(path).map_err(|_| IpcError::TransportUnavailable)?;
    let private = metadata.file_type().is_socket()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.permissions().mode() & 0o777 == 0o600;
    private
        .then_some(metadata)
        .ok_or(IpcError::TransportUnavailable)
}
