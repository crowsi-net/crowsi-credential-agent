use crate::support;

use std::{fs, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

use crowsi_credential_agent::{CredentialAgent, enroll_from_owner_files, enroll_from_owner_stream};
use crowsi_credential_broker::{CredentialStore, MemoryStore};
use crowsi_local_control_bridge::{
    BridgeTrust, DurableSecurityStore, LocalControlBridge, PrivateUnixListener, SystemTrustedClock,
};
use support::{AuthorizationOptions, Material, SECRET_MARKER, WORKLOAD};

#[test]
fn owner_files_complete_one_authenticated_socket_enrollment() {
    if !support::local_unix_listener_available() || !support::kernel_peer_attestation_available() {
        return;
    }
    let root = support::private_root();
    let material = Material::new(&AuthorizationOptions::default());
    let paths = write_inputs(root.path(), &material);
    let socket = PrivateUnixListener::bind(&paths.socket).expect("private socket");
    let trust = BridgeTrust::new(
        material.pa_public_key,
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        WORKLOAD,
        &support::executable_digest(),
        support::identity_status_trust(),
    )
    .expect("trust");
    let state =
        DurableSecurityStore::open(root.path().join("server-state.sqlite3"), 20).expect("state");
    let mut bridge =
        LocalControlBridge::new(trust, state, SystemTrustedClock::new().expect("clock"));
    support::apply_material_status(&mut bridge, &material);
    let store = Arc::new(MemoryStore::default());
    let mut agent = CredentialAgent::new(
        socket,
        Arc::clone(&store),
        bridge,
        Duration::from_secs(15),
        "memory",
    )
    .expect("agent");
    let server = std::thread::spawn(move || agent.serve_one());
    let receipt = enroll_from_owner_files(
        &paths.config,
        &paths.draft,
        &paths.authorization,
        &paths.secret,
    )
    .expect("client receipt");
    assert_eq!(receipt.status(), "ready");
    assert!(!receipt.contains_secret_values());
    assert!(server.join().expect("server thread").is_ok());
    assert!(
        store
            .metadata(&material.request.to_secret_ref().expect("reference"))
            .is_ok()
    );
}

#[test]
fn managed_stream_completes_one_authenticated_socket_enrollment() {
    if !support::local_unix_listener_available() || !support::kernel_peer_attestation_available() {
        return;
    }
    let root = support::private_root();
    let material = Material::new(&AuthorizationOptions::default());
    let paths = write_inputs(root.path(), &material);
    let socket = PrivateUnixListener::bind(&paths.socket).expect("private socket");
    let trust = BridgeTrust::new(
        material.pa_public_key,
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        WORKLOAD,
        &support::executable_digest(),
        support::identity_status_trust(),
    )
    .expect("trust");
    let state =
        DurableSecurityStore::open(root.path().join("server-state.sqlite3"), 20).expect("state");
    let mut bridge =
        LocalControlBridge::new(trust, state, SystemTrustedClock::new().expect("clock"));
    support::apply_material_status(&mut bridge, &material);
    let store = Arc::new(MemoryStore::default());
    let mut agent = CredentialAgent::new(
        socket,
        Arc::clone(&store),
        bridge,
        Duration::from_secs(15),
        "memory",
    )
    .expect("agent");
    let server = std::thread::spawn(move || agent.serve_one());
    let receipt = enroll_from_owner_stream(
        &paths.config,
        &paths.draft,
        &paths.authorization,
        SECRET_MARKER,
    )
    .expect("stream receipt");
    assert_eq!(receipt.status(), "ready");
    assert!(!receipt.contains_secret_values());
    assert!(server.join().expect("server thread").is_ok());
}

include!("file_enrollment_inputs.rs");
