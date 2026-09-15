//! WireGuard transport adapter for daemon data plane packets.

//!

//! `DataPlane` resolves raw TUN packets to a peer ID. This module is the next

//! hop: it takes routed peer packets, encrypts them with an established

//! WireGuard transport session, and emits encrypted wire bytes for the UDP or

//! relay transport layer.

use std::collections::{HashMap, VecDeque};

use std::future::Future;

use std::net::SocketAddr;

use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::{Arc, Weak};

use std::time::{Duration, Instant};

use p2pnet_tun::{Ipv4Packet, Protocol};

use p2pnet_wireguard::{MessageTransport, TransportSession, WireGuardError};

use tokio::sync::{mpsc, watch, Mutex, OwnedMutexGuard, RwLock};

use tracing::{debug, info, warn};

use crate::dataplane::{
    global_dataplane_profiler, DataplaneRxTrace, InboundPacket, OutboundPacket,
};

use crate::error::{DaemonError, Result};

use crate::peer::{PeerManager, PeerSessionGeneration, PendingProbeBindingCommitOutcome};

use crate::relay::RelayTransport;

pub(crate) use wire::wire_fingerprint;

pub(crate) use wire::wire_counter;

const RELAY_VALIDATION_PAYLOAD_PREFIX: &[u8] = b"p2wlan-relay-validation";

const RELAY_VALIDATION_TIMESTAMP_BYTES: usize = 8;

/// Keep a short startup/rekey cushion for user traffic that reaches the TUN
/// before the WireGuard session is installed. The queue is deliberately small
/// and per-peer so a not-ready peer cannot build unbounded memory pressure.
const PENDING_OUTBOUND_TTL: Duration = Duration::from_secs(8);

const MAX_PENDING_OUTBOUND_PER_PEER: usize = 256;

/// Bound how long a synthetic control/probe packet (`encrypt_and_emit_outbound`)
/// may wait for the peer's outbound emit lock.  A burst of user traffic holding
/// the lock (encrypted_tx backpressure) must never block the relay probe /
/// direct-validation control lane indefinitely: on timeout the attempt is
/// skipped and the probe loop retries on its next tick.  The ordering lock is
/// still respected — the control packet only skips a locked-out attempt, it
/// never bypasses the counter ordering.
const CONTROL_EMIT_LOCK_TIMEOUT: Duration = Duration::from_millis(500);

/// Direct validation has a stricter lock budget than ordinary relay/control
/// probes. If it waits behind live TUN traffic for hundreds of milliseconds,
/// the resulting ACK latency is a measurement of local counter contention,
/// not of the candidate path, and the relay-retention guard will correctly
/// reject it. A failed attempt is retried by the bounded validation scheduler.
pub(crate) const DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT: Duration = Duration::from_millis(100);

/// Result of the bounded per-peer counter-ordering gate used by synthetic
/// control packets.  A lock timeout is deliberately distinct from an absent
/// WireGuard session: the former is a retryable local scheduling condition,
/// while the latter means there is no encrypted transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoundedEmitOutcome {
    Sent,
    LockTimeout,
    SessionUnavailable,
}

/// Continue accepting packets encrypted with the prior receive key briefly
/// after a successful rekey. The control-plane answer and UDP data plane are
/// delivered independently, so either side can observe a few packets from the
/// old session while the peer installs the replacement.
const PREVIOUS_SESSION_GRACE: Duration = Duration::from_secs(90);

/// Cover the full wide NAT-scatter window. Exact authenticated adoption can
/// promote earlier; this is only the maximum receive-only pending lifetime.
const PENDING_RESPONDER_SESSION_GRACE: Duration = Duration::from_secs(60);

const RESPONDER_SESSION_REPLAY_GRACE: Duration = Duration::from_secs(120);

const MAX_PENDING_RESPONDER_SESSIONS_PER_PEER: usize = 5;

/// One atomic snapshot of the active transport session for maintenance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportSessionStatus {
    pub has_active: bool,
    pub needs_rekey: bool,
    pub expired: bool,
    pub expires_in: Option<Duration>,
    pub has_pending_responder: bool,
    /// Process-local identity of the active receive/send session.  This is
    /// deliberately not a WireGuard receiver index: indexes may overlap
    /// during rekey, while this value lets diagnostics distinguish a stale
    /// worker from the currently installed session.
    pub active_session_instance: Option<u64>,
    /// Process-local identity retained for the bounded previous-session
    /// receive overlap.  A packet accepted through this slot is useful for
    /// diagnosing rekey races, but must not be treated as current-session
    /// relay/direct evidence.
    pub previous_session_instance: Option<u64>,
    /// Number of responder sessions still waiting for authenticated adoption.
    /// A non-zero value explains why a peer can have no active session while
    /// the handshake path is still intentionally alive.
    pub pending_responder_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderSessionStage {
    Staged { had_active: bool },
    ReplayableDuplicate { had_active: bool },
    StaleDuplicate,
    Busy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderSessionCommit {
    PendingConfirmation,
    ActivatedInitial,
    AlreadyPromoted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderSessionConfirmation {
    Promoted,
    AlreadyActive,
    Expired,
    Missing,
}

struct PendingOutboundPacket {
    queued_at: Instant,
    packet: OutboundPacket,
}

#[derive(Clone)]
struct OutboundLossContext {
    peers: Weak<PeerManager>,
    timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
}

struct PromotedResponderToken {
    token: String,
    expires_at: Instant,
}

#[cfg(test)]
pub(crate) use wire::build_relay_validation_payload;

#[cfg(test)]
use wire::is_relay_validation_packet;

use wire::is_rekey_confirmation_packet;

use wire::should_request_direct_validation_after_decrypt;

use wire::dplpmtud_ack_destination;

/// Kind of a daemon-internal direct-validation packet parsed from a decrypted
/// WireGuard datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectValidationKind {
    /// A validation request: the sender asks us to confirm the direct path.
    Request,
    /// A validation acknowledgement: the peer confirms OUR request.
    Ack,
}

/// Token carried by every direct-validation packet: the network generation
/// the request was built in, the request id, attempt sequence, and the
/// process-wide validation-session owner that originated the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectValidationToken {
    pub(crate) kind: DirectValidationKind,
    pub(crate) generation: u64,
    pub(crate) request_id: u16,
    pub(crate) sequence: u8,
    pub(crate) owner_token: u64,
}

const DIRECT_VALIDATION_TOKEN_BYTES: usize = 8 + 2 + 1 + 8;

pub(crate) use wire::build_direct_validation_payload;

pub(crate) use wire::parse_direct_validation_token;

/// A WireGuard transport packet addressed to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPeerPacket {
    /// Authorization captured before queueing; checked again at the socket writer.
    pub room_authorization: Option<crate::rooms::RoomSendPermit>,
    /// Destination peer node ID.
    pub peer_id: String,
    /// Destination virtual IP, retained for diagnostics.
    pub dst_ip: String,
    /// Serialized WireGuard transport message.
    pub wire_bytes: Vec<u8>,
    /// Whether this ciphertext came from a normal packet read from the
    /// production TUN data plane.  Synthetic relay/direct validation and
    /// rekey packets are deliberately false: a writer completion for one of
    /// those packets is not a real business ingress proof and must not open
    /// the relay-first promotion gate.
    pub is_business: bool,
}

/// Why a FastPath session-bound encryption attempt could not use its cached
/// session. These reasons are intentionally narrower than a generic
/// "unavailable" result so lifecycle churn can be correlated with Android
/// daemon restarts and remote-incarnation cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionUnavailableReason {
    PeerSessionsMissing,
    ActiveMissing,
    SessionInstanceMismatch,
    SessionExpired,
}

impl SessionUnavailableReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PeerSessionsMissing => "peer_sessions_missing",
            Self::ActiveMissing => "active_missing",
            Self::SessionInstanceMismatch => "session_instance_mismatch",
            Self::SessionExpired => "session_expired",
        }
    }
}

/// Result of an encryption attempt that is bound to one cached session
/// instance. Returning the plaintext on a stale-session miss avoids a
/// per-packet clone on the successful LAN fast path while preserving the
/// existing slow-path FIFO fallback.
pub(crate) enum SessionBoundEncryption {
    Encrypted {
        packet: EncryptedPeerPacket,
        session_lock_wait_us: u64,
        crypto_us: u64,
    },
    Unavailable {
        packet: OutboundPacket,
        reason: SessionUnavailableReason,
    },
    Failed {
        packet: OutboundPacket,
        error: DaemonError,
    },
}

/// An encrypted WireGuard packet received from UDP or relay transport.
#[derive(Debug, Clone)]
pub struct ReceivedEncryptedPacket {
    /// Source socket address when known.
    pub source: Option<SocketAddr>,
    /// Local UDP socket address that received this packet, when known.
    pub local_endpoint: Option<SocketAddr>,
    /// Relay endpoint that delivered this packet, when received through Relay.
    pub relay_endpoint: Option<String>,
    /// Local relay transport incarnation that queued this packet.  This is
    /// required to reject a late probe ACK from a superseded same-endpoint
    /// relay connection. Direct UDP packets leave it unset.
    pub relay_connection_id: Option<u64>,
    /// Relay-authenticated source node ID, checked against the decrypted session owner.
    pub relay_peer_id: Option<String>,
    /// Local UDP socket index that received this packet.  Only set for direct
    /// UDP delivery; the affinity adoption after successful WireGuard
    /// decryption uses it so the decrypting peer is pinned to the socket that
    /// actually carried its traffic.
    pub socket_index: Option<usize>,
    /// Exact socket handle that received a dynamic-socket datagram, when the
    /// reader had one. The handle is carried with the envelope because the
    /// dynamic entry may be removed before the WireGuard worker reaches a
    /// direct-validation request. Keeping this Arc alive lets the responder
    /// send the encrypted ACK on the original NAT mapping instead of trying
    /// to resolve an index that is already detached. Pool sockets do not need
    /// this: their fixed index remains valid for the publication.
    pub(crate) direct_socket: Option<Arc<tokio::net::UdpSocket>>,
    /// Owner of the UDP publication that queued this envelope. Direct UDP
    /// readers always set this (zero means their transport was already
    /// unpublished); relay packets keep it `None`. Live inbound compares it
    /// against the post-decrypt UDP watch snapshot before accepting Direct
    /// evidence or affinity ownership.
    pub udp_transport_owner: Option<u64>,
    /// Local network generation stamped at the encrypted-ingress boundary.
    /// Direct UDP and relay readers set this before queueing the datagram, so
    /// a packet that waits across a network handover cannot be decrypted and
    /// then mislabeled as evidence for the newer generation. Standalone unit
    /// callers may leave it unset for backwards-compatible transport tests.
    pub network_generation: Option<u64>,
    /// Whether this envelope is part of the low-overhead dataplane sample.
    /// UDP/relay readers stamp it once so the same sample follows both
    /// encrypted-ingress queues and the final TUN write without incrementing
    /// the global sampler at every boundary.
    pub(crate) profile_sampled: bool,
    /// Completed UDP/relay receive boundary. UDP sets this immediately after
    /// the socket read; relay packets use the same field at frame receipt.
    pub(crate) udp_received: Option<Instant>,
    /// Timestamp immediately before this envelope enters the transport
    /// decrypt queue. A send that waits for capacity is intentionally included
    /// in the queue/scheduler measurement.
    pub(crate) transport_queue_send_started: Option<Instant>,
    /// Serialized WireGuard transport message.
    pub wire_bytes: Vec<u8>,
}

// The socket handle is an in-process lifetime guard, not packet identity.
// Keep equality useful for transport tests without treating two envelopes
// that carry the same wire bytes differently merely because one was queued
// by a dynamic UDP reader.
impl PartialEq for ReceivedEncryptedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.local_endpoint == other.local_endpoint
            && self.relay_endpoint == other.relay_endpoint
            && self.relay_connection_id == other.relay_connection_id
            && self.relay_peer_id == other.relay_peer_id
            && self.socket_index == other.socket_index
            && self.udp_transport_owner == other.udp_transport_owner
            && self.network_generation == other.network_generation
            && self.wire_bytes == other.wire_bytes
    }
}

impl Eq for ReceivedEncryptedPacket {}

/// Real ingress path of one decrypted inbound overlay payload, derived from
/// the `ReceivedEncryptedPacket` metadata at the transport layer — never
/// back-inferred from the current `active_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayIngress {
    /// The packet decrypted from a datagram owned by the published direct UDP
    /// transport.
    Direct,
    /// The packet arrived through a relay; carries the relay endpoint.
    Relay(String),
}

/// A decrypted inbound overlay candidate forwarded to the independent overlay
/// validation harness with its REAL ingress metadata.
#[derive(Debug, Clone)]
pub struct OverlayIngressEvent {
    pub peer_id: String,
    pub packet: Vec<u8>,
    pub ingress: OverlayIngress,
    /// Generation observed after decryption. The overlay validator rejects a
    /// queued event that crossed an Air/network restart before it can echo or
    /// confirm first_usable.
    pub connection_generation: u64,
}

/// Optional evidence feed the daemon hands to the WireGuard inbound path:
/// the shared relay transport (to answer forced-relay probe requests over the
/// relay) and, when the independent overlay harness is active, the overlay
/// ingress channel (real relay/direct ingress metadata for decrypted overlay
/// payloads).  Production daemons always carry the relay transport; the
/// overlay channel is `None` unless `--validate-overlay` is set.
#[derive(Clone)]
pub(crate) struct InboundEvidenceFeed {
    pub(crate) relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    /// Production timeline sink. This is populated for real TUN and mock-TUN
    /// dataplanes alike; the latter additionally gets the nonce-aware harness
    /// feed below. A decrypted non-control packet is therefore recorded as
    /// first-usable evidence on the normal production path too.
    pub(crate) timeline: Option<Arc<crate::connection_timeline::ConnectionTimeline>>,
    pub(crate) overlay_ingress_tx: Option<mpsc::Sender<OverlayIngressEvent>>,
}

struct RelayProbeIngress<'a> {
    peer_id: &'a str,
    packet: &'a [u8],
    relay_endpoint: &'a str,
    relay_connection_id: Option<u64>,
    wireguard_session_instance: Option<u64>,
    token: crate::relay_probe::RelayProbeToken,
}

/// An inbound synthetic path-commit packet (request or ack) that arrived over
/// the relay transport.  Mirrors [`RelayProbeIngress`]; see
/// [`UdpTransport::handle_path_commit_packet`].
struct PathCommitIngress<'a> {
    peer_id: &'a str,
    packet: &'a [u8],
    relay_endpoint: &'a str,
    relay_connection_id: Option<u64>,
    token: crate::path_commit::PathCommitToken,
}

enum CurrentSessionEvidenceGuardOutcome {
    Current(OwnedMutexGuard<()>),
    Contended,
    Stale,
}

pub(crate) use wire::is_overlay_payload_candidate;

pub(crate) use wire::is_real_overlay_business_packet;

/// Source of the UDP transport used by WireGuard inbound after decryption.
///
/// The static variant preserves the standalone/test API.  Daemon inbound uses
/// the watch variant: it snapshots the currently published transport for each
/// packet so a delayed UDP bind, failure recovery, or replacement is observed
/// without restarting the WireGuard reader.
enum InboundUdpTransport {
    Static(Box<Option<crate::udp::UdpTransport>>),
    Watch(watch::Receiver<Option<crate::udp::UdpTransport>>),
}

impl InboundUdpTransport {
    fn snapshot(&self) -> Option<crate::udp::UdpTransport> {
        match self {
            Self::Static(udp) => (**udp).clone(),
            Self::Watch(updates) => updates.borrow().clone(),
        }
    }

    /// Whether a decrypted envelope still belongs to the currently published
    /// UDP instance. The live path deliberately checks this after decryption,
    /// because that await can let a failed reader be withdrawn or replaced
    /// while an already queued datagram is waiting to be handled.
    ///
    /// The static API remains useful for standalone callers and unit tests;
    /// it has no publication authority and therefore retains its historical
    /// behavior.
    fn owns_direct_packet(
        &self,
        packet_owner: Option<u64>,
        udp: Option<&crate::udp::UdpTransport>,
    ) -> bool {
        match self {
            Self::Static(_) => true,
            Self::Watch(_) => match (packet_owner, udp) {
                (Some(owner), Some(udp)) if owner != 0 => udp.inbound_publication_owner() == owner,
                _ => false,
            },
        }
    }
}

/// Encrypts routed TUN packets with peer WireGuard sessions.
#[derive(Clone)]
pub struct WireGuardTransport {
    sessions: Arc<Mutex<HashMap<String, PeerTransportSessions>>>,
    /// Monotonic local identity for every installed transport session. This
    /// is not exposed on the wire and is never used as a WireGuard counter.
    next_session_instance: Arc<AtomicU64>,
    pending_outbound: Arc<Mutex<HashMap<String, VecDeque<PendingOutboundPacket>>>>,
    /// Serializes every producer that can feed the network-outbound worker
    /// for one peer. This is deliberately separate from the WireGuard emit
    /// lock: raw session-backlog/live-TUN ordering must be established before
    /// encryption, while the emit lock is held only from counter allocation
    /// through the actual transport handoff.
    outbound_ingress_locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    outbound_emit_locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    promoted_responder_tokens:
        Arc<std::sync::Mutex<HashMap<String, VecDeque<PromotedResponderToken>>>>,
    hedge_replay_counters: Arc<std::sync::Mutex<HashMap<String, HedgeReplayCounter>>>,
    /// Feed of RAW (not yet encrypted) outbound packets handed to the network
    /// outbound worker.  The worker — not the transport — decides whether the
    /// peer's path is usable and only then encrypts (allocating a WireGuard
    /// counter) under the per-peer emit lock, holding it through the actual
    /// send.  Parking plaintext while a path is unavailable means a queued
    /// business packet can never hold the emit lock, occupy a counter, or be
    /// overtaken on the wire by a higher-counter control packet.
    outbound_tx: mpsc::Sender<OutboundPacket>,
    /// Shared structural outbound-loss counters (terminal drops + send
    /// failures), wired by the daemon to the peer manager's map so `/status`
    /// reports the transport-level session queue loss together with the
    /// worker-level loss in one place.  `None` (unit tests) skips counting.
    outbound_loss_sink:
        Arc<std::sync::Mutex<Option<Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>>>>>,
    /// Context for the legacy session backlog's structured loss events. The
    /// weak peer reference avoids making the transport/peer-manager lifetime
    /// cyclic while still letting teardown events use the current generation
    /// and the daemon's monotonic timeline correlation.
    outbound_loss_context: Arc<std::sync::Mutex<Option<OutboundLossContext>>>,
}

/// Stable reason code for a packet dropped from the transport-level
/// session-not-ready queue because it outlived [`PENDING_OUTBOUND_TTL`].
pub(crate) const REASON_SESSION_QUEUE_STALE: &str = "session_queue_ttl_expired";

/// Stable reason code for a packet dropped from the transport-level
/// session-not-ready queue because the per-peer bound was exceeded.
pub(crate) const REASON_SESSION_QUEUE_FULL: &str = "session_queue_full";

pub(crate) const REASON_SESSION_QUEUE_REMOVED: &str = "session_queue_removed";

/// Whether a WireGuard decrypt failure is WireGuard's counter-based replay
/// protection rejecting a duplicate copy of an already-decrypted ciphertext
/// (the relay-hedge duplicate case).
fn is_replay_decrypt_error(error: &WireGuardError) -> bool {
    matches!(error, WireGuardError::ReplayDetected(_))
}

#[derive(Debug, thiserror::Error)]
enum InboundDecryptError {
    #[error("WireGuard packet parse failed: {0}")]
    Parse(WireGuardError),
    #[error("WireGuard decrypt failed: {0}")]
    Decrypt(WireGuardError),
}

impl InboundDecryptError {
    fn is_replay(&self) -> bool {
        matches!(self, Self::Decrypt(error) if is_replay_decrypt_error(error))
    }
}

/// Per-peer hedge duplicate replay counter and last loud-notice time.
#[derive(Default)]
struct HedgeReplayCounter {
    count: u64,
    last_loud_at: Option<Instant>,
}

/// How often a hedge duplicate replay warning is emitted per peer.  The
/// duplicates themselves are counted on every occurrence; only the WARN log
/// level is rate limited.
const HEDGE_REPLAY_WARN_INTERVAL: Duration = Duration::from_secs(30);

#[cfg(test)]
include!("transport/tests.rs");

mod accounting;
mod direct_validation;
mod dplpmtud;
mod inbound;
mod relay_control;
mod sessions;
mod wire;
use sessions::PeerTransportSessions;
