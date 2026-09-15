#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

//! # P2WLAN Daemon
//!
//! The main client daemon that runs the P2P virtual network.

use clap::Parser;
use p2pnet_daemon::config::ControlProxyMode;
use p2pnet_daemon::{Config, Daemon, DaemonError, PathPolicy};
use std::fs::OpenOptions;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

// The daemon never chooses a control plane.  The user or provisioning tool
// must provide one explicitly in the config or with --control.
const DEFAULT_CONTROL_SERVER: &str = "";
const DEFAULT_NETWORK_ID: &str = "default";

include!("main/cli.rs");
include!("main/validation.rs");
include!("main/instance_lock.rs");
include!("main/diagnostics_auth.rs");
include!("main/lifecycle_probe.rs");
include!("main/windows_lifecycle.rs");
include!("main/runtime.rs");
include!("main/overrides.rs");
include!("main/windows_elevation.rs");

#[cfg(test)]
mod tests {
    include!("main/tests.rs");
}
