//! # P2WLAN Daemon
//!
//! The main client daemon that runs the P2P virtual network.

use clap::Parser;
use p2pnet_daemon::config::ControlProxyMode;
use p2pnet_daemon::{Config, Daemon, DaemonError};
use std::fs::OpenOptions;
use std::path::PathBuf;
use tracing::{error, info, warn};

const DEFAULT_CONTROL_SERVER: &str = "http://47.109.40.237:18080";
const DEFAULT_NETWORK_ID: &str = "default";

include!("main/cli.rs");
include!("main/validation.rs");
include!("main/instance_lock.rs");
include!("main/diagnostics_auth.rs");
include!("main/runtime.rs");
include!("main/overrides.rs");

#[cfg(test)]
mod tests {
    include!("main/tests.rs");
}
