//! Relay transport adapter for encrypted peer packets.
//!
//! This layer bridges the daemon's WireGuard packet model to the DERP-like
//! relay client. Relay payloads remain encrypted WireGuard datagrams; the relay
//! server only sees source/destination node IDs and opaque bytes.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_relay::{RelayClient, RelayClientConfig, RelayMessage};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::control::ControlClient;
use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

const RELAY_INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const RELAY_TICKET_REFRESH_MARGIN_SECS: i64 = 60;

include!("relay/core.rs");
include!("relay/transport.rs");

#[cfg(test)]
mod tests {
    include!("relay/tests.rs");
}
