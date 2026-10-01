use std::path::Path;

use crowsi_credential_broker::CustodyAvailabilityError;
use crowsi_local_control_bridge::PrivateUnixListener;
use serde::Serialize;

use crate::{
    load_runtime_config,
    runtime::{inspect_authorization_bridge, platform_store},
};

#[derive(Serialize)]
pub struct RuntimeDiagnosisV1 {
    schema: &'static str,
    state: &'static str,
    reason_code: &'static str,
    checks: RuntimeDiagnosisChecksV1,
    contains_secret_values: bool,
}

#[derive(Serialize)]
struct RuntimeDiagnosisChecksV1 {
    runtime_config: &'static str,
    authorization_bridge: &'static str,
    custody: &'static str,
    socket: &'static str,
}

#[must_use]
pub fn diagnose_platform_custody_runtime(path: &Path) -> RuntimeDiagnosisV1 {
    let Ok(config) = load_runtime_config(path) else {
        return diagnosis("runtime-config-invalid", 0);
    };
    if inspect_authorization_bridge(&config).is_err() {
        return diagnosis("credential-current-identity-status-unavailable", 1);
    }
    let Ok(store) = platform_store(&config) else {
        return diagnosis("credential-custody-provider-unavailable", 2);
    };
    if let Err(error) = store.availability() {
        let reason = match error {
            CustodyAvailabilityError::Denied => "credential-custody-access-denied",
            CustodyAvailabilityError::Unavailable => "credential-custody-provider-unavailable",
        };
        return diagnosis(reason, 2);
    }
    if PrivateUnixListener::bind_recovering_stale(config.socket_path()).is_err() {
        return diagnosis("credential-socket-unavailable", 3);
    }
    diagnosis("ready", 4)
}

fn diagnosis(reason: &'static str, completed: usize) -> RuntimeDiagnosisV1 {
    let status = |index| match (index < completed, index == completed && reason != "ready") {
        (true, _) => "ready",
        (_, true) => "blocked",
        _ => "not-evaluated",
    };
    RuntimeDiagnosisV1 {
        schema: "crowsi://credential-agent/diagnosis/v1",
        state: if reason == "ready" {
            "ready"
        } else {
            "blocked"
        },
        reason_code: reason,
        checks: RuntimeDiagnosisChecksV1 {
            runtime_config: status(0),
            authorization_bridge: status(1),
            custody: status(2),
            socket: status(3),
        },
        contains_secret_values: false,
    }
}
