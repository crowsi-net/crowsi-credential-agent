use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    sync::Arc,
    time::Duration,
};

use crowsi_credential_agent::{CredentialAgentClient, CredentialEnrollment};
use crowsi_credential_broker::{EnrollmentClient, EnrollmentReceiptV1, IpcError, MemoryStore};
use crowsi_local_control_bridge::{
    BridgeTrust, CurrentStatusBinding, DurableSecurityStore, IdentityStatusTrust,
    LocalControlBridge, SystemTrustedClock, TrustedClock, sha256_digest,
};
use tempfile::TempDir;

use super::{AuthorizationOptions, Material};

pub struct RuntimeFixture {
    _root: TempDir,
    pub material: Material,
    pub store: Arc<MemoryStore>,
    pub enrollment: CredentialEnrollment<MemoryStore, SystemTrustedClock>,
}

pub struct Exchange {
    pub client: Result<EnrollmentReceiptV1, IpcError>,
    pub server: Result<EnrollmentReceiptV1, IpcError>,
}

/// Reports whether this kernel permits the peer-credential check exercised by
/// the end-to-end IPC tests. Restricted build sandboxes may deny `SO_PEERCRED`;
/// production continues to fail closed in that environment.
pub fn kernel_peer_attestation_available() -> bool {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let Ok((stream, _peer)) = UnixStream::pair() else {
        return false;
    };
    getsockopt(&stream, PeerCredentials).is_ok()
}

/// Reports whether the execution environment permits filesystem Unix sockets.
pub fn local_unix_listener_available() -> bool {
    let root = private_root();
    std::os::unix::net::UnixListener::bind(root.path().join("probe.sock")).is_ok()
}

impl RuntimeFixture {
    pub fn new(options: &AuthorizationOptions) -> Self {
        Self::with_peer_uid(options, nix::unistd::Uid::effective().as_raw())
    }

    pub fn with_peer_uid(options: &AuthorizationOptions, caller_uid: u32) -> Self {
        let root = private_root();
        let material = Material::new(options);
        let trust = BridgeTrust::new(
            material.pa_public_key,
            caller_uid,
            nix::unistd::Gid::effective().as_raw(),
            super::material::WORKLOAD,
            &executable_digest(),
            identity_status_trust(),
        )
        .expect("bridge trust");
        let security = DurableSecurityStore::open(root.path().join("security.sqlite3"), 20)
            .expect("security store");
        let mut bridge = LocalControlBridge::new(
            trust,
            security,
            SystemTrustedClock::new().expect("trusted clock"),
        );
        apply_material_status(&mut bridge, &material);
        let store = Arc::new(MemoryStore::default());
        let enrollment =
            CredentialEnrollment::new(store.clone(), bridge, Duration::from_secs(15), "memory")
                .expect("credential enrollment");
        Self {
            _root: root,
            material,
            store,
            enrollment,
        }
    }

    pub fn exchange(&mut self, secret: &[u8]) -> Exchange {
        let (mut client_stream, mut server_stream) = UnixStream::pair().expect("Unix stream");
        let request = self.material.request.clone();
        let client = CredentialAgentClient::new(Duration::from_secs(15)).expect("native client");
        let (client_result, server_result) = std::thread::scope(|scope| {
            let enrollment = &mut self.enrollment;
            let server = scope.spawn(move || enrollment.handle_stream(&mut server_stream));
            let client_result = client.enroll(
                &mut client_stream,
                &self.material.envelope,
                &request,
                secret,
            );
            (client_result, server.join().expect("server thread"))
        });
        Exchange {
            client: client_result,
            server: server_result,
        }
    }

    pub fn exchange_without_client_preflight(&mut self, secret: &[u8]) -> Exchange {
        let (mut client_stream, mut server_stream) = UnixStream::pair().expect("Unix stream");
        write_authorization(&mut client_stream, &self.material);
        let request = self.material.request.clone();
        let client = EnrollmentClient::new(Duration::from_secs(15));
        let (client_result, server_result) = std::thread::scope(|scope| {
            let enrollment = &mut self.enrollment;
            let server = scope.spawn(move || enrollment.handle_stream(&mut server_stream));
            let client_result =
                client.exchange_after_authorization(&mut client_stream, &request, secret);
            (client_result, server.join().expect("server thread"))
        });
        Exchange {
            client: client_result,
            server: server_result,
        }
    }
}

include!("runtime_helpers.rs");
