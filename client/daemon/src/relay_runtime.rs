//! Relay runtime helpers: default relay inference, candidate assembly, the

//! relay supervisor task, and proactive relay peer validation.

//!

//! Split out of the crate root to keep `lib.rs` focused on daemon orchestration.

use std::collections::HashMap;

use std::net::Ipv4Addr;

use std::pin::Pin;

use std::sync::Arc;

use std::time::{Duration, Instant};

use futures_util::future::join_all;

use p2pnet_relay::RelayMessage;

use p2pnet_tun::Ipv4Packet;

use tokio::sync::{mpsc, oneshot, watch, RwLock};

use tokio::time::{interval, sleep};

use tracing::{debug, info, warn};

use crate::control::RelayCatalogEntry;

use crate::dataplane::OutboundPacket;

use crate::error::{DaemonError, Result};

use crate::peer::PeerManager;

use crate::relay::{
    select_relay_with_cooldowns, RelayCandidateConfig, RelaySelectionDiagnostics,
    RelaySelectionOutcome, RelayTicketCache, RelayTransport,
};

#[cfg(test)]
use crate::transport::build_relay_validation_payload;

use crate::transport::{ReceivedEncryptedPacket, WireGuardTransport};

use super::{is_stun_clear_value, unix_time_millis};

/// Short cooldown after a selected Relay fails at runtime before trying it again.
const RELAY_RUNTIME_FAILURE_COOLDOWN: Duration = Duration::from_secs(10);

const RELAY_ROUTE_POLL_INTERVAL: Duration = Duration::from_secs(1);

const RELAY_ROUTE_STABILITY_SAMPLES: u8 = 2;

/// Confirm relay peer reachability proactively instead of waiting for user traffic.
const RELAY_PEER_VALIDATION_INTERVAL: Duration = Duration::from_secs(5);

const RELAY_PEER_VALIDATION_READY_POLL_INTERVAL: Duration = Duration::from_millis(250);

const RELAY_PEER_VALIDATION_MAX_AGE: Duration = Duration::from_secs(15);

use write_boundary::RelayWriteBoundaryPermit;

pub(crate) use configuration::infer_default_relay_servers;

pub(crate) use configuration::effective_relay_allow_insecure_plaintext;

#[cfg(test)]
pub(crate) use configuration::relay_spec_is_plaintext;

pub(crate) use configuration::relay_candidates_from_sources;

pub(crate) use configuration::udp_observers_from_sources;

pub(super) struct RelaySupervisor {
    pub(super) relay_candidates: Vec<RelayCandidateConfig>,
    pub(super) preferred_regions: Vec<String>,
    pub(super) selection_timeout: Duration,
    pub(super) node_id: String,
    pub(super) peers: Arc<PeerManager>,
    pub(super) relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    pub(super) relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    pub(super) inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    /// Android's physical-network callback stream. `None` on desktop, where
    /// the existing stable route monitor remains the authority.
    pub(super) android_network_change_rx: Option<crate::AndroidNetworkChangeReceiver>,
    /// Watch flipped whenever the shared relay transport slot is set/cleared,
    /// so the outbound path can wait event-driven for relay availability.
    pub(super) relay_available_tx: watch::Sender<bool>,
    /// Per-process connection timeline.
    pub(super) timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
    // A2 fields
    pub(super) ticket_cache: Option<Arc<RelayTicketCache>>,
    pub(super) relay_ticket: Option<String>,
    pub(super) allow_insecure_plaintext: bool,
    pub(super) ca_cert_path: Option<String>,
}

/// How long before ticket expiry (unix seconds) the make-before-break renewal
/// connects the replacement.  The server's ticket-expiry close fires exactly
/// at expiry, so renewing well before the deadline leaves a full data-path
/// margin.
const RELAY_TICKET_RENEWAL_MARGIN_SECS: i64 = 60;

/// Retry cadence for a failed renewal fetch.
const RELAY_TICKET_RENEWAL_RETRY: Duration = Duration::from_secs(5);

#[cfg(test)]
pub(crate) use connection::relay_renewal_deadline;

use connection::spawn_relay_renewal_task_impl;

#[cfg(test)]
use supervisor::relay_retry_delay_with_jitter;

pub(crate) use validation::run_relay_peer_validation_loop;

#[cfg(test)]
pub(crate) use validation::RelayValidationPacket;

/// Cadence of the forced-relay probe loop while any peer still needs a relay
/// confirmation.  Fast enough that the first business packet's wait (bounded
/// by `relay_startup_timeout_ms`) is not materially extended by probe latency,
/// and it is kicked event-driven by the outbound actor when a packet actually
/// waits.
const RELAY_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Cadence of re-sending a forced-relay probe to an unconfirmed peer. The
/// first send is event-driven/250ms polled; a lost ACK gets a second chance
/// inside the 1s relay-first target instead of waiting 5s. The token is stable
/// per peer (never overwritten), and the expectation is refreshed every tick,
/// so this only bounds wire sends, not ACK validity.
const RELAY_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(750);

/// Relay control traffic is not a reason to hold the probe/validation loop (or
/// another peer's control packet) behind a stalled relay writer. If this
/// boundary is reached the encrypted counter is terminal and the relay writer
/// is invalidated; the next attempt allocates a fresh counter from plaintext.
const RELAY_CONTROL_SEND_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) use probes::run_relay_peer_probe_loop;

#[cfg(test)]
pub(crate) use validation::send_relay_validation_packet;
mod configuration;
mod connection;
mod probes;
mod supervisor;
mod validation;
mod write_boundary;

#[cfg(test)]
mod test_support;
