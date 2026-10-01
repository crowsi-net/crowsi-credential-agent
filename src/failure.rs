use crowsi_credential_broker::IpcError;

#[derive(Clone, Copy, Debug)]
pub enum Failure {
    Usage,
    ResponseEncoding,
    Ipc(IpcError),
}

/// Maps internal variants to stable codes without exposing native diagnostics.
#[must_use]
pub const fn reason(error: IpcError) -> (&'static str, i32) {
    match error {
        IpcError::InvalidFrame | IpcError::FrameOversized => ("invalid-owner-input", 65),
        IpcError::AuthorizationRejected => ("credential-authorization-rejected", 70),
        IpcError::BindingRejected => ("credential-authorization-binding-rejected", 70),
        IpcError::PartialFrame | IpcError::TrailingData => ("credential-ipc-frame-rejected", 70),
        IpcError::Timeout => ("credential-authorization-or-ipc-timeout", 70),
        IpcError::TransportUnavailable => ("credential-agent-transport-unavailable", 78),
        IpcError::SecretDigest => ("credential-secret-digest-rejected", 70),
        IpcError::StoreUnavailable => ("credential-custody-or-security-state-unavailable", 78),
    }
}

#[cfg(test)]
mod tests {
    use super::reason;
    use crowsi_credential_broker::IpcError;

    #[test]
    fn public_reasons_preserve_the_non_secret_failure_stage() {
        assert_eq!(
            reason(IpcError::AuthorizationRejected).0,
            "credential-authorization-rejected"
        );
        assert_eq!(
            reason(IpcError::BindingRejected).0,
            "credential-authorization-binding-rejected"
        );
        assert_eq!(
            reason(IpcError::StoreUnavailable).0,
            "credential-custody-or-security-state-unavailable"
        );
        assert_eq!(
            reason(IpcError::TransportUnavailable).0,
            "credential-agent-transport-unavailable"
        );
    }
}
