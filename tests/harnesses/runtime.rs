//! Runtime process boundaries share one integration-test executable.

#[path = "../support/mod.rs"]
mod support;

#[path = "../cli.rs"]
mod cli;
#[path = "../inspection.rs"]
mod inspection;
#[path = "../runtime_boundary.rs"]
mod runtime_boundary;
#[path = "../runtime_config.rs"]
mod runtime_config;
#[path = "../shutdown_cleanup.rs"]
mod shutdown_cleanup;
