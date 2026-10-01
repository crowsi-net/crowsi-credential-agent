use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    thread,
    time::Duration,
};

use tempfile::tempdir;

use super::file_identity;

#[test]
fn fingerprint_detects_same_inode_content_replacement() {
    let root = tempdir().expect("private root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("root mode");
    let path = root.path().join("secret");
    fs::write(&path, b"original").expect("initial secret");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secret mode");
    let before_metadata = fs::metadata(&path).expect("before metadata");
    let before = file_identity(&before_metadata);

    thread::sleep(Duration::from_millis(2));
    let mut writer = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("same inode writer");
    writer.write_all(b"replaced").expect("replacement");
    writer.sync_all().expect("replacement sync");

    let after_metadata = fs::metadata(&path).expect("after metadata");
    assert_eq!(before_metadata.dev(), after_metadata.dev());
    assert_eq!(before_metadata.ino(), after_metadata.ino());
    assert!(before != file_identity(&after_metadata));
}
