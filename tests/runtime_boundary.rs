use crate::support;

use std::{
    fs::{self, symlink_metadata},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    sync::Arc,
    time::{Duration, Instant},
};

use crowsi_credential_agent::{CredentialAgent, CredentialEnrollment};
use crowsi_credential_broker::{IpcError, MemoryStore};
use crowsi_local_control_bridge::{
    BridgeTrust, DurableSecurityStore, LocalControlBridge, PrivateUnixListener, SystemTrustedClock,
};
use support::{AuthorizationOptions, Material};

#[test]
fn runtime_owns_a_private_socket_and_removes_it_on_drop() {
    if !support::local_unix_listener_available() {
        return;
    }
    let root = support::private_root();
    let material = Material::new(&AuthorizationOptions::default());
    let trust = trust(&material);
    let state = DurableSecurityStore::open(root.path().join("state.sqlite3"), 20).expect("state");
    let bridge = LocalControlBridge::new(trust, state, SystemTrustedClock::new().expect("clock"));
    let socket_path = root.path().join("credential-agent.sock");
    let listener = PrivateUnixListener::bind(&socket_path).expect("private listener");
    let agent = CredentialAgent::new(
        listener,
        Arc::new(MemoryStore::default()),
        bridge,
        Duration::from_secs(1),
        "memory",
    )
    .expect("agent");
    let metadata = symlink_metadata(agent.socket_path()).expect("socket metadata");
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    drop(agent);
    assert!(!socket_path.exists());
}

#[test]
fn private_listener_recovers_a_killed_serve_one_socket() {
    if !support::local_unix_listener_available() {
        return;
    }
    let root = support::private_root();
    let socket_path = root.path().join("credential-agent.sock");
    let killed = std::os::unix::net::UnixListener::bind(&socket_path).expect("stale socket");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .expect("private stale socket");
    drop(killed);

    let recovered = PrivateUnixListener::bind_recovering_stale(&socket_path)
        .expect("recovered credential listener");
    assert!(std::os::unix::net::UnixStream::connect(&socket_path).is_ok());
    drop(recovered);
    assert!(fs::symlink_metadata(socket_path).is_err());
}

#[test]
fn preexisting_socket_path_is_rejected_without_removing_the_replacement() {
    if !support::local_unix_listener_available() {
        return;
    }
    let root = support::private_root();
    let socket_path = root.path().join("credential-agent.sock");
    fs::write(&socket_path, b"replacement").expect("replacement");
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .expect("private replacement");

    assert!(PrivateUnixListener::bind(&socket_path).is_err());
    assert_eq!(
        fs::read(socket_path).expect("replacement remains"),
        b"replacement"
    );
}

#[test]
fn authorization_wait_has_a_finite_deadline() {
    let root = support::private_root();
    let material = Material::new(&AuthorizationOptions::default());
    let state = DurableSecurityStore::open(root.path().join("state.sqlite3"), 20).expect("state");
    let bridge = LocalControlBridge::new(
        trust(&material),
        state,
        SystemTrustedClock::new().expect("clock"),
    );
    let mut enrollment = CredentialEnrollment::new(
        Arc::new(MemoryStore::default()),
        bridge,
        Duration::from_millis(20),
        "memory",
    )
    .expect("enrollment");
    let (_client, mut server) = std::os::unix::net::UnixStream::pair().expect("stream");
    let started = Instant::now();
    assert_eq!(
        enrollment.handle_stream(&mut server),
        Err(IpcError::AuthorizationRejected)
    );
    // Peer executable hashing is intentionally part of attestation and can
    // dominate tiny read deadlines in an all-features test binary.
    assert!(started.elapsed() < Duration::from_secs(10));
}

fn trust(material: &Material) -> BridgeTrust {
    BridgeTrust::new(
        material.pa_public_key,
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        support::WORKLOAD,
        &support::executable_digest(),
        support::identity_status_trust(),
    )
    .expect("trust")
}
