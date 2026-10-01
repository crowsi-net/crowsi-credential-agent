//! Purpose-specific local credential enrollment boundary.
//!
//! This crate deliberately exposes no HTTP transport and never accepts a
//! caller-asserted identity. Authorization and secret enrollment share one
//! kernel-attested Unix stream.

mod agent;
mod authorization;
mod authorization_file;
mod client;
mod draft;
mod enrollment;
mod file_enrollment;
mod inspection;
mod private_file;
mod readiness;
mod runtime;
mod runtime_config;
mod runtime_diagnosis;
mod secret_input;
mod shutdown;

pub use agent::CredentialAgent;
pub use authorization::{
    BridgeAuthorizationVerifier, CREDENTIAL_ENROLLMENT_ACTION, CREDENTIAL_ENROLLMENT_PURPOSE,
};
pub use authorization_file::load_authorization_envelope;
pub use client::CredentialAgentClient;
pub use draft::{EnrollmentDraftV1, load_enrollment_draft};
pub use enrollment::CredentialEnrollment;
pub use file_enrollment::{enroll_from_owner_files, enroll_from_owner_stream};
pub use inspection::{CredentialInspectionV1, inspect_credential};
pub use readiness::{CredentialAgentReadiness, sample_readiness};
pub use runtime::{
    compose_platform_custody_agent, inspect_platform_custody_credential,
    serve_platform_custody_once, serve_platform_custody_until,
};
pub use runtime_config::{RuntimeConfigV4, load_runtime_config};
pub use runtime_diagnosis::{RuntimeDiagnosisV1, diagnose_platform_custody_runtime};
pub use secret_input::{SecretInput, read_secret, read_secret_stream};
pub use shutdown::install_shutdown_flag;
