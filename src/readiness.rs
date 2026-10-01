use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CredentialAgentReadiness {
    pub schema: &'static str,
    pub state: &'static str,
    pub transport: &'static str,
    pub authorization: &'static str,
    pub external_actions: bool,
    pub contains_secret_values: bool,
}

/// A source-tree sample cannot attest a production deployment.
#[must_use]
pub const fn sample_readiness() -> CredentialAgentReadiness {
    CredentialAgentReadiness {
        schema: "crowsi://credential-agent/readiness/v1",
        state: "unavailable",
        transport: "owner-only-unix-socket",
        authorization: "local-control-bridge",
        external_actions: false,
        contains_secret_values: false,
    }
}
