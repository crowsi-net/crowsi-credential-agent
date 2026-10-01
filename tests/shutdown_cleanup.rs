use crate::support;

use std::{fs, sync::Arc, thread, time::Duration};

use crowsi_credential_agent::{CredentialAgent, install_shutdown_flag};
use crowsi_credential_broker::MemoryStore;
use crowsi_local_control_bridge::{
    BridgeTrust, DurableSecurityStore, LocalControlBridge, PrivateUnixListener, SystemTrustedClock,
};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use support::{AuthorizationOptions, Material, WORKLOAD};

#[test]
fn sigint_stops_the_agent_and_drop_removes_its_owned_socket() {
    if !support::local_unix_listener_available() {
        return;
    }
    let root = support::private_root();
    let material = Material::new(&AuthorizationOptions::default());
    let trust = BridgeTrust::new(
        material.pa_public_key,
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        WORKLOAD,
        &support::executable_digest(),
        support::identity_status_trust(),
    )
    .expect("trust");
    let state = DurableSecurityStore::open(root.path().join("state.sqlite3"), 20).expect("state");
    let bridge = LocalControlBridge::new(trust, state, SystemTrustedClock::new().expect("clock"));
    let socket_path = root.path().join("agent.sock");
    let socket = PrivateUnixListener::bind(&socket_path).expect("socket");
    let mut agent = CredentialAgent::new(
        socket,
        Arc::new(MemoryStore::default()),
        bridge,
        Duration::from_secs(1),
        "memory",
    )
    .expect("agent");
    let shutdown = install_shutdown_flag().expect("signal handlers");
    let signal = thread::spawn(|| {
        thread::sleep(Duration::from_millis(30));
        kill(Pid::this(), Signal::SIGINT).expect("SIGINT");
    });

    agent.serve_until(&shutdown).expect("bounded shutdown");
    signal.join().expect("signal thread");
    drop(agent);
    assert!(fs::symlink_metadata(socket_path).is_err());
}
