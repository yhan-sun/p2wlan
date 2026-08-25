//! Data plane packet pump.
//!
//! This module is the seam between the virtual interface and the peer routing
//! table. It reads raw IP packets from TUN, resolves the destination virtual IP
//! to a peer, and emits outbound peer packets. The outbound side is intentionally
//! a channel today; the next layer can consume it with WireGuard + UDP/relay
//! transport without changing TUN packet handling.

use std::net::Ipv4Addr;
use std::sync::Arc;

use p2pnet_tun::{IpPacket, VirtualInterface};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use crate::acl::AclEngine;
use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;

include!("dataplane/core.rs");
include!("dataplane/normalization.rs");
include!("dataplane/logging.rs");
include!("dataplane/profiling.rs");

#[cfg(test)]
mod tests {
    include!("dataplane/tests.rs");
}
