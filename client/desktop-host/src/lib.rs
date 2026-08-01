//! Read-only desktop host helpers shared by P2WLAN desktop shells.
//!
//! This crate is the narrow P2.1 extraction surface. It contains data types,
//! diagnostics URL helpers, read-only local diagnostics clients, path helpers,
//! and log-tail helpers. It intentionally does not include daemon lifecycle,
//! privilege prompts, process control, or system network changes.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

include!("lib/types.rs");
include!("lib/client.rs");
include!("lib/url.rs");
include!("lib/paths.rs");
#[cfg(test)]
include!("lib/tests.rs");
