//! Relay transport adapter for encrypted peer packets.
//!
//! This layer bridges the daemon's WireGuard packet model to the DERP-like
//! relay client. Relay payloads remain encrypted WireGuard datagrams; the relay
//! server only sees source/destination node IDs and opaque bytes.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_relay::{
    OriginalRelayDelivery, OriginalRelayFrameRead, RelayClient, RelayClientConfig, RelayMessage,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::control::ControlClient;
use crate::dataplane::global_dataplane_profiler;
use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

const RELAY_INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const RELAY_TICKET_REFRESH_MARGIN_SECS: i64 = 60;

mod original_member;
pub(crate) use original_member::RelayMemberFailure;
mod read_origin;
pub(crate) use read_origin::RelayReadItem;
mod send_origin;
#[cfg(test)]
pub(crate) use send_origin::publication_test_support;
pub(crate) use send_origin::{RelayCaptureOutcome, RelayFullSendFact, RelaySendCapture};

include!("relay/core.rs");
include!("relay/transport.rs");
include!("relay/rendezvous.rs");

#[cfg(test)]
mod tests {
    include!("relay/tests.rs");
}
