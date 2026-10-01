use std::sync::{Arc, atomic::AtomicBool};

use crowsi_credential_broker::IpcError;
use signal_hook::consts::{SIGINT, SIGTERM};

/// Installs bounded process shutdown flags for the credential socket owner.
///
/// # Errors
///
/// Returns an error when either signal handler cannot be registered.
pub fn install_shutdown_flag() -> Result<Arc<AtomicBool>, IpcError> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown))
        .map_err(|_| IpcError::TransportUnavailable)?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown))
        .map_err(|_| IpcError::TransportUnavailable)?;
    Ok(shutdown)
}
