use std::{io::Read, path::PathBuf};

use crowsi_credential_broker::IpcError;
use zeroize::Zeroizing;

use crate::private_file::read_owner_file;

const MAX_SECRET_BYTES: u64 = 65_536;

/// A local secret source; its value is never accepted through argv or env.
pub enum SecretInput {
    OwnerOnlyFile(PathBuf),
}

/// Reads an owner-only secret file into zeroizing memory.
///
/// # Errors
///
/// Rejects ambiguous paths, non-private files, empty values, and oversized data.
pub fn read_secret(source: &SecretInput) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    match source {
        SecretInput::OwnerOnlyFile(path) => read_owner_file(path, MAX_SECRET_BYTES),
    }
}

/// Reads a managed native-client stream into bounded zeroizing memory.
///
/// # Errors
///
/// Rejects empty, oversized, or unreadable streams.
pub fn read_secret_stream(mut source: impl Read) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let mut secret = Zeroizing::new(Vec::new());
    source
        .by_ref()
        .take(MAX_SECRET_BYTES + 1)
        .read_to_end(&mut secret)
        .map_err(|_| IpcError::InvalidFrame)?;
    if secret.is_empty() {
        return Err(IpcError::InvalidFrame);
    }
    if secret.len() as u64 > MAX_SECRET_BYTES {
        return Err(IpcError::FrameOversized);
    }
    Ok(secret)
}
