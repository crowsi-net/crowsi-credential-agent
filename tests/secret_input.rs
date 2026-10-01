use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_agent::{SecretInput, read_secret, read_secret_stream};

#[test]
fn owner_only_secret_file_is_read_into_zeroizing_memory() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("secret");
    fs::write(&path, b"local-only-secret").expect("secret file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private secret");
    let secret = read_secret(&SecretInput::OwnerOnlyFile(path)).expect("read secret");
    assert_eq!(secret.as_slice(), b"local-only-secret");
}

#[test]
fn broad_or_relative_secret_files_are_rejected() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private root");
    let path = root.path().join("secret");
    fs::write(&path, b"secret").expect("secret file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("broad secret");
    assert!(read_secret(&SecretInput::OwnerOnlyFile(path)).is_err());
    assert!(read_secret(&SecretInput::OwnerOnlyFile("relative".into())).is_err());
}

#[test]
fn secret_file_is_rejected_below_a_group_accessible_parent() {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o750)).expect("broad root");
    let path = root.path().join("secret");
    fs::write(&path, b"secret").expect("secret file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private file");

    assert!(read_secret(&SecretInput::OwnerOnlyFile(path)).is_err());
}

#[test]
fn managed_stream_secret_is_bounded_and_zeroizing() {
    let secret = read_secret_stream(&b"ui-entered-secret"[..]).expect("stream secret");
    assert_eq!(secret.as_slice(), b"ui-entered-secret");
    assert!(read_secret_stream(&b""[..]).is_err());
    assert!(read_secret_stream(&vec![b'x'; 65_537][..]).is_err());
}
