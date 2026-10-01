use std::{
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use crowsi_credential_broker::{CredentialStore, EnrollmentReceiptV1, IpcError};
use crowsi_local_control_bridge::{
    LocalControlBridge, PrivateUnixListener, SystemTrustedClock, TrustedClock,
};

use crate::CredentialEnrollment;

/// Owner-only Unix socket runtime for credential enrollment.
pub struct CredentialAgent<S, C = SystemTrustedClock> {
    socket: PrivateUnixListener,
    enrollment: CredentialEnrollment<S, C>,
}

impl<S: CredentialStore, C: TrustedClock> CredentialAgent<S, C> {
    /// Creates a private-socket credential runtime.
    ///
    /// # Errors
    ///
    /// Rejects invalid timeout or store metadata.
    pub fn new(
        socket: PrivateUnixListener,
        store: Arc<S>,
        bridge: LocalControlBridge<C>,
        timeout: Duration,
        store_kind: &str,
    ) -> Result<Self, IpcError> {
        Ok(Self {
            socket,
            enrollment: CredentialEnrollment::new(store, bridge, timeout, store_kind)?,
        })
    }

    /// Accepts one client and fails closed on any boundary error.
    ///
    /// # Errors
    ///
    /// Rejects transport, authorization, framing, and storage failures.
    pub fn serve_one(&mut self) -> Result<EnrollmentReceiptV1, IpcError> {
        let (mut stream, _) = self
            .socket
            .listener()
            .accept()
            .map_err(|_| IpcError::TransportUnavailable)?;
        self.enrollment.handle_stream(&mut stream)
    }

    /// Serves until a signal-safe flag requests bounded shutdown.
    ///
    /// # Errors
    ///
    /// Stops on the first transport, authorization, framing, or storage failure.
    pub fn serve_until(&mut self, shutdown: &AtomicBool) -> Result<(), IpcError> {
        self.socket
            .listener()
            .set_nonblocking(true)
            .map_err(|_| IpcError::TransportUnavailable)?;
        while !shutdown.load(Ordering::Acquire) {
            match self.socket.listener().accept() {
                Ok((mut stream, _)) => {
                    self.enrollment.handle_stream(&mut stream)?;
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return Err(IpcError::TransportUnavailable),
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        self.socket.path()
    }
}
