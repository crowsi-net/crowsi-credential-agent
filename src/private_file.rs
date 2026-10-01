use std::{
    fs::{OpenOptions, symlink_metadata},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use crowsi_credential_broker::IpcError;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    changed_s: i64,
    changed_ns: i64,
    modified_s: i64,
    modified_ns: i64,
}

#[cfg(test)]
mod tests;

pub(crate) fn read_owner_file(path: &Path, maximum: u64) -> Result<Zeroizing<Vec<u8>>, IpcError> {
    let before_metadata = owner_metadata(path, maximum)?;
    let before = file_identity(&before_metadata);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| IpcError::InvalidFrame)?;
    let opened = file_identity(&file.metadata().map_err(|_| IpcError::InvalidFrame)?);
    if before != opened {
        return Err(IpcError::InvalidFrame);
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before_metadata.len()).unwrap_or(0));
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IpcError::InvalidFrame)?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err(IpcError::FrameOversized);
    }
    let opened_after = file_identity(&file.metadata().map_err(|_| IpcError::InvalidFrame)?);
    let path_after = file_identity(&owner_metadata(path, maximum)?);
    if before != opened_after || before != path_after {
        return Err(IpcError::InvalidFrame);
    }
    Ok(Zeroizing::new(bytes))
}

fn owner_metadata(path: &Path, maximum: u64) -> Result<std::fs::Metadata, IpcError> {
    if !path.is_absolute() {
        return Err(IpcError::InvalidFrame);
    }
    let parent = path.parent().ok_or(IpcError::InvalidFrame)?;
    if parent.canonicalize().map_err(|_| IpcError::InvalidFrame)? != parent {
        return Err(IpcError::InvalidFrame);
    }
    let parent_metadata = symlink_metadata(parent).map_err(|_| IpcError::InvalidFrame)?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != effective_uid
        || parent_metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(IpcError::InvalidFrame);
    }
    let metadata = symlink_metadata(path).map_err(|_| IpcError::InvalidFrame)?;
    let private = metadata.is_file()
        && metadata.uid() == effective_uid
        && metadata.permissions().mode() & 0o777 == 0o600
        && (1..=maximum).contains(&metadata.len());
    private.then_some(metadata).ok_or(IpcError::InvalidFrame)
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        changed_s: metadata.ctime(),
        changed_ns: metadata.ctime_nsec(),
        modified_s: metadata.mtime(),
        modified_ns: metadata.mtime_nsec(),
    }
}
