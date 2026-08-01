//! Peer doctor/diagnostics formatting helpers.
//!
//! Renders peer connection health, path/direct event timelines, candidate
//! pairs, and traversal history for the `p2wlan doctor` output. Split out of
//! `formatting.rs`.

use std::net::{IpAddr, SocketAddr};

use serde_json::Value;

use super::relay::relay_path_reason;

include!("peer/diagnostics.rs");
include!("peer/suggestions.rs");
include!("peer/path.rs");
include!("peer/direct.rs");
include!("peer/candidates.rs");
include!("peer/traversal.rs");
include!("peer/utils.rs");
