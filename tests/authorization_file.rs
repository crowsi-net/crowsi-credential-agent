use crate::support;

use std::{fs, os::unix::fs::PermissionsExt};

use crowsi_credential_agent::load_authorization_envelope;
use support::{AuthorizationOptions, Material};

#[test]
fn external_pa_envelope_requires_an_owner_only_absolute_file() {
    let root = support::private_root();
    let material = Material::new(&AuthorizationOptions::default());
    let path = root.path().join("authorization.json");
    fs::write(
        &path,
        serde_json::to_vec(&material.envelope).expect("authorization JSON"),
    )
    .expect("authorization file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("broad mode");
    assert!(load_authorization_envelope(&path).is_err());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    let envelope = load_authorization_envelope(&path).expect("owner envelope");
    assert_eq!(envelope.request.request_id, material.request.request_id());
    assert!(load_authorization_envelope(std::path::Path::new("authorization.json")).is_err());
}

#[test]
fn unknown_envelope_fields_fail_closed() {
    let root = support::private_root();
    let path = root.path().join("authorization.json");
    fs::write(&path, br#"{"schema":"unknown","extra":"field"}"#).expect("authorization file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");

    assert!(load_authorization_envelope(&path).is_err());
}
