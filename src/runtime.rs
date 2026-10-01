use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};

use crate::private_file::read_owner_file;
use crate::{CredentialAgent, RuntimeConfigV4, load_runtime_config};
use crate::{CredentialInspectionV1, inspect_credential, load_enrollment_draft};
use crowsi_credential_broker::{
    EnrollmentReceiptV1, IpcError, PlatformCustodyConfigV1, PlatformCustodyStore,
};
use crowsi_local_control_bridge::{
    DurableSecurityStore, LocalControlBridge, PrivateUnixListener, SystemTrustedClock,
};

type PlatformCredentialAgent = CredentialAgent<PlatformCustodyStore, SystemTrustedClock>;
type AuthorizationBridge = LocalControlBridge<SystemTrustedClock>;

/// Inspects one exact custody slot without returning its secret.
///
/// # Errors
///
/// Rejects unsafe runtime/draft files and unavailable platform custody.
pub fn inspect_platform_custody_credential(
    config_path: &Path,
    draft_path: &Path,
) -> Result<CredentialInspectionV1, IpcError> {
    let config = load_runtime_config(config_path)?;
    let draft = load_enrollment_draft(draft_path)?;
    let store = platform_store(&config)?;
    store
        .require_available()
        .map_err(|_| IpcError::StoreUnavailable)?;
    inspect_credential(&store, &draft)
}

/// Composes the production local credential custody path without fallbacks.
///
/// # Errors
///
/// Rejects unavailable trust, state, socket, clock, or platform custody.
pub fn compose_platform_custody_agent(
    config: &RuntimeConfigV4,
) -> Result<PlatformCredentialAgent, IpcError> {
    let store = platform_store(config)?;
    store
        .require_available()
        .map_err(|_| IpcError::StoreUnavailable)?;
    let bridge = authorization_bridge(config)?;
    let socket = PrivateUnixListener::bind_recovering_stale(config.socket_path())
        .map_err(|_| IpcError::TransportUnavailable)?;
    CredentialAgent::new(
        socket,
        Arc::new(store),
        bridge,
        config.timeout(),
        "windows-dpapi-user",
    )
}

pub(crate) fn authorization_bridge(
    config: &RuntimeConfigV4,
) -> Result<AuthorizationBridge, IpcError> {
    let mut bridge = authorization_bridge_base(config)?;
    config.apply_identity_status(&mut bridge)?;
    Ok(bridge)
}

pub(crate) fn inspect_authorization_bridge(config: &RuntimeConfigV4) -> Result<(), IpcError> {
    let bridge = authorization_bridge_base(config)?;
    config.verify_identity_status(&bridge)
}

fn authorization_bridge_base(config: &RuntimeConfigV4) -> Result<AuthorizationBridge, IpcError> {
    let trust = config.trust()?;
    let state = DurableSecurityStore::open(config.state_path(), config.rate_limit())
        .map_err(|_| IpcError::StoreUnavailable)?;
    let clock = SystemTrustedClock::new().map_err(|_| IpcError::AuthorizationRejected)?;
    Ok(LocalControlBridge::new(trust, state, clock))
}

/// Handles exactly one authorized enrollment before releasing the socket.
///
/// # Errors
///
/// Propagates fail-closed composition, authorization, transport, and custody failures.
pub fn serve_platform_custody_once(
    config: &RuntimeConfigV4,
) -> Result<EnrollmentReceiptV1, IpcError> {
    compose_platform_custody_agent(config)?.serve_one()
}

/// Serves until a signal-owned shutdown flag is set.
///
/// # Errors
///
/// Stops on composition or request-boundary failure.
pub fn serve_platform_custody_until(
    config: &RuntimeConfigV4,
    shutdown: &AtomicBool,
) -> Result<(), IpcError> {
    compose_platform_custody_agent(config)?.serve_until(shutdown)
}

pub(crate) fn platform_store(config: &RuntimeConfigV4) -> Result<PlatformCustodyStore, IpcError> {
    let bytes = read_owner_file(config.custody_path(), 65_536)?;
    let custody = PlatformCustodyConfigV1::parse(&bytes).map_err(|_| IpcError::InvalidFrame)?;
    PlatformCustodyStore::new(&custody).map_err(|_| IpcError::StoreUnavailable)
}
