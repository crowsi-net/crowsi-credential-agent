#![allow(dead_code, unused_imports)]

mod material;
mod runtime;

pub use material::{AuthorizationOptions, Material, SECRET_MARKER, WORKLOAD};
pub use runtime::{
    Exchange, RuntimeFixture, apply_material_status, executable_digest, identity_status_config,
    identity_status_trust, kernel_peer_attestation_available, local_unix_listener_available,
    private_root,
};
