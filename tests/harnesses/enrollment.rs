//! Credential enrollment contracts share one platform-custody test executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../authorization_file.rs"]
mod authorization_file;
#[path = "../client_contract.rs"]
mod client_contract;
#[path = "../enrollment.rs"]
mod enrollment;
#[path = "../file_enrollment.rs"]
mod file_enrollment;
#[path = "../rejections.rs"]
mod rejections;
#[path = "../secret_input.rs"]
mod secret_input;
