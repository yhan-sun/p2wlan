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
use p2pnet_wireguard::{MessageTransport, TransportSession};
use tokio::sync::{mpsc, watch, Mutex, OwnedMutexGuard, RwLock};
use tracing::{debug, info, warn};

use crate::dataplane::{
    global_dataplane_profiler, DataplaneRxTrace, InboundPacket, OutboundPacket,
};
use crate::error::{DaemonError, Result};
use crate::peer::{PeerManager, PeerSessionGeneration};
use crate::relay::RelayTransport;

/// Stable, non-reversible diagnostic fingerprint for an opaque encrypted
/// datagram. This is only used in local debug traces to correlate the same
/// ciphertext at transport boundaries; it is not exposed in status/metrics.
pub(crate) fn wire_fingerprint(bytes: &[u8]) -> u64 {
    // FNV-1a is adequate for correlation, not authentication. Keeping this
    // allocation-free also makes the diagnostic safe on the hot path.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Extract the WireGuard transport counter from an already serialized
/// transport message for local diagnostics.  The counter is authenticated by
/// WireGuard and is never sent as a separate diagnostic field on the network;
/// this helper only avoids putting opaque `wire_fp` values in a trace where a
/// replay/order incident needs to be reconstructed.
pub(crate) fn wire_counter(bytes: &[u8]) -> Option<u64> {
    // MessageTransport::to_bytes() starts with the little-endian type-4
    // header, then receiver_index (4 bytes), then counter (8 bytes).
    if bytes.len() < 16 || bytes.get(..4) != Some(&[4, 0, 0, 0]) {
        return None;
    }
    Some(u64::from_le_bytes(bytes.get(8..16)?.try_into().ok()?))
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponderTokenDisposition {
    /// The exact cached answer may be re-staged after its receive-only slot
    /// expires without authenticated adoption.
    Restageable,
    /// This transaction was promoted, superseded, or explicitly rolled back.
    /// Replaying its cached keys could roll the peer back from a newer session.
    Terminal,
}

struct ResponderTokenState {
    disposition: ResponderTokenDisposition,
    expires_at: Instant,
}

struct TransportSessionSlot {
    session: TransportSession,
    token: Option<String>,
    awaiting_confirmation: bool,
    /// Local identity for this installed receive key. It is deliberately
    /// independent of the WireGuard receiver index and of the network
    /// generation: receiver indexes can overlap during rekey, while this
    /// process-local instance lets the inbound worker detect removal or
    /// replacement between decrypt and evidence processing.
    session_instance: u64,
}

impl TransportSessionSlot {
    fn new(session: TransportSession, token: Option<String>, session_instance: u64) -> Self {
        Self {
            session,
            token,
            awaiting_confirmation: false,
            session_instance,
        }
    }
}

struct RetainedTransportSession {
    slot: TransportSessionSlot,
    expires_at: Instant,
}

struct PendingTransportSession {
    slot: TransportSessionSlot,
    expires_at: Instant,
    answer_committed: bool,
}

struct PeerTransportSessions {
    active: Option<TransportSessionSlot>,
    previous: Option<RetainedTransportSession>,
    pending: HashMap<String, PendingTransportSession>,
    responder_token_states: HashMap<String, ResponderTokenState>,
}

impl PeerTransportSessions {
    fn new(active: TransportSessionSlot) -> Self {
        Self {
            active: Some(active),
            previous: None,
            pending: HashMap::new(),
            responder_token_states: HashMap::new(),
        }
    }

    fn pending_only(pending: PendingTransportSession) -> Self {
        let token = pending
            .slot
            .token
            .clone()
            .expect("pending responder session must have a token");
        Self {
            active: None,
            previous: None,
            pending: HashMap::from([(token, pending)]),
            responder_token_states: HashMap::new(),
        }
    }

    fn remember_responder_token(
        &mut self,
        token: impl Into<String>,
        disposition: ResponderTokenDisposition,
        now: Instant,
    ) {
        self.responder_token_states.insert(
            token.into(),
            ResponderTokenState {
                disposition,
                expires_at: now + RESPONDER_SESSION_REPLAY_GRACE,
            },
        );
    }

    fn clear_pending_as_terminal(&mut self, now: Instant) {
        let tokens = self.pending.keys().cloned().collect::<Vec<_>>();
        self.pending.clear();
        for token in tokens {
            self.remember_responder_token(token, ResponderTokenDisposition::Terminal, now);
        }
    }

    fn mark_all_responder_tokens_terminal(&mut self, now: Instant) {
        for state in self.responder_token_states.values_mut() {
            state.disposition = ResponderTokenDisposition::Terminal;
            state.expires_at = now + RESPONDER_SESSION_REPLAY_GRACE;
        }
    }

    fn install_with_overlap(&mut self, active: TransportSessionSlot, now: Instant) -> bool {
        let replaced_existing = self.active.is_some();
        if let Some(previous) = self.active.replace(active) {
            self.previous = Some(RetainedTransportSession {
                slot: previous,
                expires_at: now + PREVIOUS_SESSION_GRACE,
            });
        }
        // Installing an initiator answer selects one handshake outcome. Any
        // concurrent responder offers are crossing attempts and must not be
        // allowed to promote later under a different token.
        self.mark_all_responder_tokens_terminal(now);
        self.clear_pending_as_terminal(now);
        replaced_existing
    }

    fn prune_expired(&mut self, now: Instant) {
        if self.previous.as_ref().is_some_and(|previous| {
            previous.expires_at <= now || previous.slot.session.is_expired()
        }) {
            self.previous = None;
        }
        self.pending
            .retain(|_, pending| pending.expires_at > now && !pending.slot.session.is_expired());
        self.responder_token_states
            .retain(|_, state| state.expires_at > now);
    }

    fn promote_pending(&mut self, token: &str, now: Instant) -> bool {
        let Some(pending) = self.pending.remove(token) else {
            return false;
        };
        self.mark_all_responder_tokens_terminal(now);
        self.remember_responder_token(token, ResponderTokenDisposition::Terminal, now);
        if let Some(previous) = self.active.replace(pending.slot) {
            if !previous.session.is_expired() {
                self.previous = Some(RetainedTransportSession {
                    slot: previous,
                    expires_at: now + PREVIOUS_SESSION_GRACE,
                });
            }
        }
        // A peer can only adopt one responder answer at a time. Any other
        // bounded in-flight tokens are now obsolete and must not roll the
        // active session forward again if their delayed packets arrive.
        self.clear_pending_as_terminal(now);
        true
    }

    fn prepare_active(&mut self, now: Instant) {
        self.prune_expired(now);
    }

    fn status(&self) -> TransportSessionStatus {
        let active = self.active.as_ref();
        TransportSessionStatus {
            has_active: active.is_some(),
            needs_rekey: active.is_some_and(|active| active.session.needs_rekey()),
            expired: active.is_some_and(|active| active.session.is_expired()),
            expires_in: active.map(|active| active.session.expires_in()),
            has_pending_responder: !self.pending.is_empty(),
            active_session_instance: active.map(|active| active.session_instance),
            previous_session_instance: self
                .previous
                .as_ref()
                .map(|previous| previous.slot.session_instance),
            pending_responder_count: self.pending.len(),
        }
    }

    fn has_session_instance(&self, session_instance: u64) -> bool {
        self.active
            .as_ref()
            .is_some_and(|slot| slot.session_instance == session_instance)
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| previous.slot.session_instance == session_instance)
            || self
                .pending
                .values()
                .any(|pending| pending.slot.session_instance == session_instance)
    }
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
pub(crate) fn build_relay_validation_payload(sent_at_ms: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        RELAY_VALIDATION_PAYLOAD_PREFIX.len() + RELAY_VALIDATION_TIMESTAMP_BYTES,
    );
    payload.extend_from_slice(RELAY_VALIDATION_PAYLOAD_PREFIX);
    payload.extend_from_slice(&sent_at_ms.to_be_bytes());
    payload
}

/// Recognize the daemon-internal relay health echo in either direction.  It
/// is encrypted and may traverse the relay, but it is not user/TUN business
/// traffic and must never become `first_usable` evidence.
fn is_relay_validation_packet(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Icmp {
        return false;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 + RELAY_VALIDATION_PAYLOAD_PREFIX.len() + RELAY_VALIDATION_TIMESTAMP_BYTES {
        return false;
    }
    if !matches!(icmp[0], 0 | 8) || icmp[1] != 0 {
        return false;
    }
    let payload = &icmp[8..];
    payload
        .strip_prefix(RELAY_VALIDATION_PAYLOAD_PREFIX)
        .and_then(|payload| payload.get(..RELAY_VALIDATION_TIMESTAMP_BYTES))
        .is_some()
}

fn is_rekey_confirmation_packet(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Icmp {
        return false;
    }
    let icmp = ip.payload();
    icmp.len() >= 8
        && icmp[0] == 8
        && icmp[1] == 0
        && icmp.get(8..) == Some(crate::REKEY_CONFIRMATION_PAYLOAD)
}

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

/// Build the ICMP echo-request payload of one direct-validation packet: the
/// fixed prefix plus the big-endian token (generation, request id, sequence,
/// owner token).
/// The prefix length is fixed so the parser can slice the token deterministically.
pub(crate) fn build_direct_validation_payload(
    kind: DirectValidationKind,
    generation: u64,
    request_id: u16,
    sequence: u8,
    owner_token: u64,
) -> Vec<u8> {
    let prefix = match kind {
        DirectValidationKind::Request => crate::DIRECT_VALIDATION_REQUEST_PAYLOAD,
        DirectValidationKind::Ack => crate::DIRECT_VALIDATION_ACK_PAYLOAD,
    };
    let mut payload = Vec::with_capacity(prefix.len() + DIRECT_VALIDATION_TOKEN_BYTES);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&request_id.to_be_bytes());
    payload.push(sequence);
    payload.extend_from_slice(&owner_token.to_be_bytes());
    payload
}

/// Parse the direct-validation token out of a decrypted WireGuard datagram,
/// or `None` when the packet is not a daemon-internal validation packet.
///
/// The framing mirrors the rekey-confirmation packets: an ICMP echo request
/// (type 8) carrying the validation prefix — the daemon consumes these
/// packets, so neither the TUN device nor an OS echo reply is ever involved.
pub(crate) fn parse_direct_validation_token(packet: &[u8]) -> Option<DirectValidationToken> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Icmp {
        return None;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 {
        return None;
    }
    if icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    let payload = &icmp[8..];
    let kind = if payload.starts_with(crate::DIRECT_VALIDATION_REQUEST_PAYLOAD) {
        DirectValidationKind::Request
    } else if payload.starts_with(crate::DIRECT_VALIDATION_ACK_PAYLOAD) {
        DirectValidationKind::Ack
    } else {
        return None;
    };
    let prefix_len = match kind {
        DirectValidationKind::Request => crate::DIRECT_VALIDATION_REQUEST_PAYLOAD.len(),
        DirectValidationKind::Ack => crate::DIRECT_VALIDATION_ACK_PAYLOAD.len(),
    };
    // The full token must follow the prefix: a truncated payload is not a
    // validation packet.
    let token_start = payload
        .len()
        .checked_sub(DIRECT_VALIDATION_TOKEN_BYTES)
        .filter(|start| *start >= prefix_len)?;
    let token = payload.get(token_start..)?;
    let generation = u64::from_be_bytes(token[..8].try_into().ok()?);
    let request_id = u16::from_be_bytes(token[8..10].try_into().ok()?);
    let sequence = *token.get(10)?;
    let owner_token = u64::from_be_bytes(token[11..19].try_into().ok()?);
    Some(DirectValidationToken {
        kind,
        generation,
        request_id,
        sequence,
        owner_token,
    })
}

/// A WireGuard transport packet addressed to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPeerPacket {
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

/// Result of an encryption attempt that is bound to one cached session
/// instance.  Returning the plaintext on a stale-session miss avoids a
/// per-packet clone on the successful LAN fast path while preserving the
/// existing slow-path FIFO fallback.
pub(crate) enum SessionBoundEncryption {
    Encrypted {
        packet: EncryptedPeerPacket,
        session_lock_wait_us: u64,
        crypto_us: u64,
    },
    Unavailable(OutboundPacket),
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

/// Whether a decrypted IP packet looks like an overlay business payload (UDP
/// with the overlay magic right after the UDP header).  The overlay validation
/// loop re-verifies fully (magic, checksum, nonce/seq, sender); this is only a
/// cheap transport-layer pre-filter so ordinary keepalive/user traffic is not
/// forwarded to the harness.
pub(crate) fn is_overlay_payload_candidate(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Udp {
        return false;
    }
    let payload = ip.payload();
    payload.len() > 8 + crate::OVERLAY_PAYLOAD_MAGIC.len()
        && payload[8..8 + crate::OVERLAY_PAYLOAD_MAGIC.len()] == crate::OVERLAY_PAYLOAD_MAGIC[..]
}

/// A decrypted WireGuard keepalive has no inner IP packet.  Only a valid
/// overlay IPv4 packet is production business ingress evidence; otherwise the
/// initial session/rekey traffic could falsely set `first_usable` before the
/// TUN has delivered a real packet.  This predicate intentionally accepts all
/// IPv4 protocols (ICMP, TCP, UDP, etc.) so it is not tied to the harness-only
/// overlay echo format.
pub(crate) fn is_real_overlay_business_packet(packet: &[u8]) -> bool {
    Ipv4Packet::new(packet).is_ok()
        && !is_relay_validation_packet(packet)
        && !is_rekey_confirmation_packet(packet)
        && parse_direct_validation_token(packet).is_none()
        && crate::relay_probe::parse_relay_probe_token(packet).is_none()
        && crate::path_commit::parse_path_commit_token(packet).is_none()
}

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
    promoted_responder_tokens: Arc<Mutex<HashMap<String, VecDeque<PromotedResponderToken>>>>,
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
fn is_replay_decrypt_error(error: &str) -> bool {
    error.contains("replay detected")
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

impl WireGuardTransport {
    /// Create a transport adapter and a receiver for RAW routed outbound
    /// packets.  The network outbound worker consumes the receiver and is the
    /// only place that encrypts business packets (under the per-peer emit
    /// lock, holding it through the actual send).
    pub fn new() -> (Self, mpsc::Receiver<OutboundPacket>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        (
            Self {
                sessions: Arc::new(Mutex::new(HashMap::new())),
                next_session_instance: Arc::new(AtomicU64::new(1)),
                pending_outbound: Arc::new(Mutex::new(HashMap::new())),
                outbound_ingress_locks: Arc::new(Mutex::new(HashMap::new())),
                outbound_emit_locks: Arc::new(Mutex::new(HashMap::new())),
                promoted_responder_tokens: Arc::new(Mutex::new(HashMap::new())),
                hedge_replay_counters: Arc::new(std::sync::Mutex::new(HashMap::new())),
                outbound_tx,
                outbound_loss_sink: Arc::new(std::sync::Mutex::new(None)),
                outbound_loss_context: Arc::new(std::sync::Mutex::new(None)),
            },
            outbound_rx,
        )
    }

    fn allocate_session_instance(&self) -> u64 {
        // Zero is reserved for “unset” in diagnostics. A wrapping process is
        // not expected, but skip zero if an extremely long-lived daemon ever
        // exhausts the counter.
        let instance = self.next_session_instance.fetch_add(1, Ordering::Relaxed);
        if instance == 0 {
            self.next_session_instance.fetch_add(1, Ordering::Relaxed)
        } else {
            instance
        }
    }

    /// Return `(retained, current)` for the exact session which authenticated
    /// an inbound datagram. This second lookup intentionally happens after the
    /// decrypt await: control-plane teardown may remove or replace the session
    /// while the datagram is waiting in the inbound worker. A retained
    /// previous key is acceptable only for delivery overlap, never as current
    /// path evidence.
    async fn session_instance_state(&self, peer_id: &str, session_instance: u64) -> (bool, bool) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let Some(peer_sessions) = sessions.get_mut(peer_id) else {
            return (false, false);
        };
        peer_sessions.prune_expired(now);
        let retained = peer_sessions.has_session_instance(session_instance);
        let current = peer_sessions
            .active
            .as_ref()
            .is_some_and(|slot| slot.session_instance == session_instance)
            || peer_sessions
                .pending
                .values()
                .any(|pending| pending.slot.session_instance == session_instance);
        (retained, current)
    }

    /// Re-check a decrypted packet's session immediately before it is allowed
    /// to mutate path/evidence state.  The initial check in the inbound loop
    /// only protects the decrypt-to-dispatch boundary; relay-slot and UDP
    /// validation awaits can otherwise let a rekey/remove publish a new
    /// session in between.
    async fn session_instance_is_current(
        &self,
        peer_id: &str,
        session_instance: Option<u64>,
    ) -> bool {
        let Some(session_instance) = session_instance else {
            // Legacy standalone callers do not attach a process-local session
            // instance. Preserve their historical behavior; production
            // daemon packets always carry one.
            return true;
        };
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        let (_, current) = self.session_instance_state(peer_id, session_instance).await;
        current
    }

    /// Acquire the per-peer emit guard and verify that a decrypted packet was
    /// authenticated by the currently published session. The guard remains
    /// held for the caller's evidence commit, so session replacement/removal
    /// cannot cross the check and the corresponding path-state mutation.
    async fn acquire_current_session_evidence_guard(
        &self,
        peer_id: &str,
        session_instance: Option<u64>,
    ) -> Option<OwnedMutexGuard<()>> {
        let session_instance = session_instance?;
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let emit_guard = emit_lock.lock_owned().await;
        let (_, current) = self.session_instance_state(peer_id, session_instance).await;
        current.then_some(emit_guard)
    }

    /// Share the peer manager's outbound-loss counters with this transport so
    /// session-not-ready queue loss lands in `/status.stats.outbound_drops`
    /// under the same map as the worker's drops.  Installed once by the
    /// daemon before any traffic flows.
    pub fn set_outbound_loss_sink(
        &self,
        sink: Option<Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>>>,
    ) {
        *self
            .outbound_loss_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = sink;
    }

    /// Install the daemon timeline and peer-generation source used by the
    /// transport-level session backlog. This queue is retained for handshake
    /// handoff compatibility, so its losses must carry the same audit fields
    /// as the network-outbound actor's losses.
    pub(crate) fn set_outbound_loss_context(
        &self,
        peers: &Arc<PeerManager>,
        timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
    ) {
        *self
            .outbound_loss_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(OutboundLossContext {
            peers: Arc::downgrade(peers),
            timeline,
        });
    }

    /// The shared loss sink, if the daemon installed one.
    fn outbound_loss_registry(
        &self,
    ) -> Option<Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>>> {
        self.outbound_loss_sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Record TERMINAL dropped business packets against the shared sink, if
    /// installed.
    pub(crate) async fn record_outbound_drop(
        &self,
        reason_code: &str,
        packets: usize,
        bytes: usize,
    ) {
        if packets == 0 {
            return;
        }
        if let Some(sink) = self.outbound_loss_registry() {
            let mut loss = sink.lock().await;
            let entry = loss.drops.entry(reason_code.to_string()).or_default();
            entry.packets = entry.packets.saturating_add(packets as u64);
            entry.bytes = entry.bytes.saturating_add(bytes as u64);
        }
    }

    /// Record a transient outbound send-failure ATTEMPT against the shared
    /// sink (never counted as a terminal drop).
    pub(crate) async fn record_outbound_send_failure(
        &self,
        reason_code: &str,
        attempts: usize,
        bytes: usize,
    ) {
        if attempts == 0 {
            return;
        }
        if let Some(sink) = self.outbound_loss_registry() {
            let mut loss = sink.lock().await;
            let entry = loss
                .send_failures
                .entry(reason_code.to_string())
                .or_default();
            entry.packets = entry.packets.saturating_add(attempts as u64);
            entry.bytes = entry.bytes.saturating_add(bytes as u64);
        }
    }

    /// Record a loss event emitted by the legacy session queue. Production
    /// relay-first traffic is owned by `network_outbound`, but this queue is
    /// still reachable during session teardown; it must not disappear from
    /// the same queryable event ledger. The daemon installs a weak generation
    /// source and the shared monotonic timeline during construction, so these
    /// events have the same audit fields as actor-owned losses.
    async fn record_outbound_queue_event(
        &self,
        kind: &str,
        peer_id: &str,
        reason_code: &str,
        packets: usize,
        bytes: usize,
    ) {
        if packets == 0 {
            return;
        }
        let Some(sink) = self.outbound_loss_registry() else {
            return;
        };
        let context = self
            .outbound_loss_context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let (generation, correlation_id, at_ms, timeline) = match context {
            Some(context) => {
                let generation = context
                    .peers
                    .upgrade()
                    .map(|peers| peers.current_network_generation_sync())
                    .unwrap_or(0);
                let correlation_id = context.timeline.correlation_id().to_string();
                let at_ms = context.timeline.uptime_ms();
                (generation, correlation_id, at_ms, Some(context.timeline))
            }
            None => (0, "transport-session-queue".to_string(), 0, None),
        };
        let mut loss = sink.lock().await;
        const MAX_OUTBOUND_LOSS_EVENTS: usize = 512;
        if loss.events.len() >= MAX_OUTBOUND_LOSS_EVENTS {
            loss.events.remove(0);
        }
        loss.events.push(crate::peer::OutboundLossEvent {
            kind: kind.to_string(),
            peer_id: peer_id.to_string(),
            generation,
            reason_code: reason_code.to_string(),
            packets: packets as u64,
            bytes: bytes as u64,
            correlation_id: correlation_id.clone(),
            at_ms,
        });
        drop(loss);
        if let Some(timeline) = timeline {
            timeline.emit(
                "outbound_session_queue_event",
                None,
                Some(reason_code),
                Some(format!(
                    "kind={kind} peer={peer_id} generation={generation} packets={packets} bytes={bytes}"
                )),
            );
        }
    }

    /// Install or replace an established transport session for a peer.
    pub async fn add_session(&self, peer_id: impl Into<String>, session: TransportSession) -> bool {
        self.install_active_session(peer_id, None, session).await
    }

    /// Install the initiator side of a completed handshake as the active
    /// outbound session while retaining the former receive key briefly.
    pub async fn install_active_session(
        &self,
        peer_id: impl Into<String>,
        token: Option<String>,
        session: TransportSession,
    ) -> bool {
        let peer_id = peer_id.into();
        let token_present = token.is_some();
        // Session replacement is a lifecycle boundary for the same counter
        // stream.  Wait for any in-flight business/control emission before
        // publishing the new active key; otherwise an old-key ciphertext can
        // be handed to the network after the new key is visible and become a
        // previous-session packet with no current-path evidence.
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let emit_lock_started = Instant::now();
        let emit_guard = emit_lock.lock_owned().await;
        let replaced_existing = self
            .install_active_session_locked(&peer_id, token, session)
            .await;
        debug!(
            event = "wireguard_session_installed",
            peer_id = %peer_id,
            replaced_existing,
            token_present,
            emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64,
            "active WireGuard session published after the per-peer emit lock boundary"
        );
        drop(emit_guard);
        self.flush_pending_outbound_for_peer(&peer_id).await;
        replaced_existing
    }

    /// Publish an active session while the caller already owns the peer emit
    /// guard. Callers may compose this with the network-generation gate, but
    /// must acquire locks in the canonical order `emit -> generation ->
    /// sessions`.
    pub(crate) async fn install_active_session_locked(
        &self,
        peer_id: &str,
        token: Option<String>,
        session: TransportSession,
    ) -> bool {
        let now = Instant::now();
        let session_instance = self.allocate_session_instance();
        let replaced_existing = {
            let mut sessions = self.sessions.lock().await;
            if let Some(existing) = sessions.get_mut(peer_id) {
                existing.prune_expired(now);
                existing.install_with_overlap(
                    TransportSessionSlot::new(session, token, session_instance),
                    now,
                )
            } else {
                sessions.insert(
                    peer_id.to_string(),
                    PeerTransportSessions::new(TransportSessionSlot::new(
                        session,
                        token,
                        session_instance,
                    )),
                );
                false
            }
        };
        debug!(
            event = "wireguard_session_install_locked",
            peer_id = %peer_id,
            session_instance,
            replaced_existing,
            "active WireGuard session published under the caller-owned emit boundary"
        );
        replaced_existing
    }

    /// Stage responder keys before publishing the answer.  Staged keys can
    /// decrypt the initiator's first new-session packet but never replace a
    /// usable active outbound key until that packet confirms peer adoption.
    pub async fn stage_responder_session(
        &self,
        peer_id: impl Into<String>,
        token: String,
        session: TransportSession,
    ) -> ResponderSessionStage {
        self.stage_responder_session_inner(peer_id.into(), token, session, false)
            .await
    }

    /// Re-stage the exact cached responder keys after a committed pending
    /// session expired without receiving adoption traffic. The cache lookup
    /// has already verified identical handshake bytes, so removing the
    /// replay marker and installing the same key is safe and lets a delayed
    /// initiator retry recover instead of waiting for cache eviction.
    pub async fn restage_cached_responder_session(
        &self,
        peer_id: impl Into<String>,
        token: String,
        session: TransportSession,
    ) -> ResponderSessionStage {
        self.stage_responder_session_inner(peer_id.into(), token, session, true)
            .await
    }

    async fn stage_responder_session_inner(
        &self,
        peer_id: String,
        token: String,
        session: TransportSession,
        allow_seen_restage: bool,
    ) -> ResponderSessionStage {
        // Staging is a session-lifecycle mutation even though it does not
        // publish an outbound key yet. Serialize it with remove/flush/live
        // ingress so a late responder answer cannot recreate a pending
        // session after the peer was removed.
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let now = Instant::now();
        let session_instance = self.allocate_session_instance();
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get_mut(&peer_id) {
            existing.prune_expired(now);
            let had_active = existing.active.is_some();
            if existing
                .active
                .as_ref()
                .and_then(|active| active.token.as_deref())
                == Some(token.as_str())
            {
                return ResponderSessionStage::ReplayableDuplicate { had_active };
            }
            if let Some(pending) = existing.pending.get_mut(&token) {
                // Give an exact cached-answer replay a fresh delivery window.
                // The cached key is still installed, so replaying the same
                // answer remains safe and can recover an ambiguous send.
                pending.expires_at = now + PENDING_RESPONDER_SESSION_GRACE;
                return ResponderSessionStage::ReplayableDuplicate { had_active };
            }
            let token_disposition = existing
                .responder_token_states
                .get(&token)
                .map(|state| state.disposition);
            if existing
                .previous
                .as_ref()
                .and_then(|previous| previous.slot.token.as_deref())
                == Some(token.as_str())
            {
                // Never replay an answer whose receive key is no longer the
                // active or staged responder session. Doing so can make the
                // initiator install a key that this responder has discarded.
                return ResponderSessionStage::StaleDuplicate;
            }
            if let Some(disposition) = token_disposition {
                if disposition == ResponderTokenDisposition::Terminal || !allow_seen_restage {
                    return ResponderSessionStage::StaleDuplicate;
                }
                if existing.pending.len() >= MAX_PENDING_RESPONDER_SESSIONS_PER_PEER {
                    return ResponderSessionStage::Busy;
                }
            }
            if existing.pending.len() >= MAX_PENDING_RESPONDER_SESSIONS_PER_PEER {
                return ResponderSessionStage::Busy;
            }
            let pending_session_instance = session_instance;
            existing.pending.insert(
                token.clone(),
                PendingTransportSession {
                    slot: TransportSessionSlot::new(
                        session,
                        Some(token.clone()),
                        pending_session_instance,
                    ),
                    expires_at: now + PENDING_RESPONDER_SESSION_GRACE,
                    answer_committed: false,
                },
            );
            existing.remember_responder_token(token, ResponderTokenDisposition::Restageable, now);
            ResponderSessionStage::Staged { had_active }
        } else {
            let mut peer_sessions = PeerTransportSessions::pending_only(PendingTransportSession {
                slot: TransportSessionSlot::new(session, Some(token.clone()), session_instance),
                expires_at: now + PENDING_RESPONDER_SESSION_GRACE,
                answer_committed: false,
            });
            peer_sessions.remember_responder_token(
                token,
                ResponderTokenDisposition::Restageable,
                now,
            );
            sessions.insert(peer_id, peer_sessions);
            ResponderSessionStage::Staged { had_active: false }
        }
    }

    /// Extend the receive-only responder window after the control-plane
    /// answer delivery attempt completes. Signaling latency must not consume
    /// the authenticated adoption window.
    pub async fn refresh_responder_session_grace(&self, peer_id: &str, token: &str) -> bool {
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let mut sessions = self.sessions.lock().await;
        let Some(existing) = sessions.get_mut(peer_id) else {
            return false;
        };
        let Some(pending) = existing.pending.get_mut(token) else {
            return false;
        };
        pending.expires_at = Instant::now() + PENDING_RESPONDER_SESSION_GRACE;
        true
    }

    /// Mark a staged responder answer as durably published.  Initial
    /// handshakes have no old path to preserve and become active now; rekeys
    /// remain pending until authenticated new-session traffic arrives.
    pub async fn commit_responder_session(
        &self,
        peer_id: &str,
        token: &str,
    ) -> ResponderSessionCommit {
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let emit_guard = emit_lock.lock_owned().await;
        let result = self.commit_responder_session_locked(peer_id, token).await;
        let flush_pending = result == ResponderSessionCommit::ActivatedInitial;
        drop(emit_guard);
        if flush_pending {
            self.flush_pending_outbound_for_peer(peer_id).await;
        }
        result
    }

    /// Commit a staged responder session while the caller already owns the
    /// peer emit guard. This lets a handshake compose the operation with the
    /// network-generation gate without ever waiting for emit while holding
    /// that gate.
    pub(crate) async fn commit_responder_session_locked(
        &self,
        peer_id: &str,
        token: &str,
    ) -> ResponderSessionCommit {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let Some(existing) = sessions.get_mut(peer_id) else {
            return ResponderSessionCommit::Missing;
        };
        existing.prune_expired(now);
        if existing
            .active
            .as_ref()
            .and_then(|active| active.token.as_deref())
            == Some(token)
        {
            ResponderSessionCommit::AlreadyPromoted
        } else if existing.pending.contains_key(token) {
            let activate_initial = existing.active.is_none();
            {
                let pending = existing
                    .pending
                    .get_mut(token)
                    .expect("pending responder token checked above");
                pending.answer_committed = true;
                if activate_initial {
                    pending.slot.awaiting_confirmation = true;
                }
            }
            existing.remember_responder_token(token, ResponderTokenDisposition::Restageable, now);
            if activate_initial {
                existing.promote_pending(token, now);
                ResponderSessionCommit::ActivatedInitial
            } else {
                ResponderSessionCommit::PendingConfirmation
            }
        } else {
            ResponderSessionCommit::Missing
        }
    }

    /// Discard an unpublished responder session. Returns false when the token
    /// was already promoted by authenticated traffic, which proves the answer
    /// reached the peer despite a control-plane response error.
    pub async fn discard_responder_session(&self, peer_id: &str, token: &str) -> bool {
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let mut sessions = self.sessions.lock().await;
        let Some(existing) = sessions.get_mut(peer_id) else {
            return true;
        };
        if existing
            .active
            .as_ref()
            .and_then(|active| active.token.as_deref())
            == Some(token)
        {
            return false;
        }
        existing.pending.remove(token);
        existing.remember_responder_token(
            token,
            ResponderTokenDisposition::Terminal,
            Instant::now(),
        );
        true
    }

    /// Confirm a responder session from an authenticated Probe-v2 packet.
    /// Probe authentication is bound to the same handshake token and therefore
    /// proves that the peer received and adopted the corresponding WireGuard
    /// answer. Promote WireGuard first; the UDP layer then promotes Probe-v2.
    #[cfg(test)]
    pub async fn confirm_responder_session(
        &self,
        peer_id: &str,
        token: &str,
    ) -> ResponderSessionConfirmation {
        let emit_guard = self.acquire_outbound_emit_guard(peer_id).await;
        self.confirm_responder_session_with_emit_guard(peer_id, token, &emit_guard)
            .await
    }

    /// Confirm a responder session while the caller already owns the peer's
    /// counter-ordering guard. Cross-layer UDP adoption uses this form so its
    /// lock order stays `emit -> adoption -> epoch -> sessions`; acquiring
    /// emit after the global epoch gate would invert the outbound data path.
    pub(crate) async fn confirm_responder_session_with_emit_guard(
        &self,
        peer_id: &str,
        token: &str,
        _emit_guard: &OwnedMutexGuard<()>,
    ) -> ResponderSessionConfirmation {
        let now = Instant::now();
        let (result, flush_pending) = {
            let mut sessions = self.sessions.lock().await;
            let Some(existing) = sessions.get_mut(peer_id) else {
                return ResponderSessionConfirmation::Missing;
            };
            // The caller has already authenticated a Probe-v2 packet under
            // this exact token's pending key. Treat that proof as authoritative
            // even at the TTL boundary; pruning first would discard the WG key
            // a few microseconds before the matching transaction can commit.
            let active_matches = existing
                .active
                .as_ref()
                .is_some_and(|active| active.token.as_deref() == Some(token));
            if active_matches {
                if existing
                    .active
                    .as_ref()
                    .is_some_and(|active| active.session.is_expired())
                {
                    (ResponderSessionConfirmation::Expired, false)
                } else {
                    if let Some(active) = existing.active.as_mut() {
                        active.awaiting_confirmation = false;
                    }
                    (ResponderSessionConfirmation::AlreadyActive, false)
                }
            } else if existing
                .pending
                .get(token)
                .is_some_and(|pending| pending.slot.session.is_expired())
            {
                existing.pending.remove(token);
                existing.remember_responder_token(
                    token,
                    ResponderTokenDisposition::Restageable,
                    now,
                );
                (ResponderSessionConfirmation::Expired, false)
            } else if existing.pending.contains_key(token) {
                existing.promote_pending(token, now);
                (ResponderSessionConfirmation::Promoted, true)
            } else {
                existing.prune_expired(now);
                (ResponderSessionConfirmation::Missing, false)
            }
        };
        if flush_pending {
            // Probe-v2 still has to commit the matching key before the caller
            // can ACK or learn Direct. Do not make that cross-layer commit
            // wait behind queued user traffic or a slow network egress retry.
            let transport = self.clone();
            let peer_id = peer_id.to_string();
            tokio::spawn(async move {
                transport.flush_pending_outbound_for_peer(&peer_id).await;
            });
        }
        if matches!(
            result,
            ResponderSessionConfirmation::Promoted | ResponderSessionConfirmation::AlreadyActive
        ) {
            self.remember_promoted_responder_token(peer_id, token.to_string())
                .await;
        }
        result
    }

    async fn remember_promoted_responder_token(&self, peer_id: &str, token: String) {
        const MAX_PENDING_CONFIRMATIONS: usize = 8;
        let now = Instant::now();
        let mut promoted = self.promoted_responder_tokens.lock().await;
        let queue = promoted.entry(peer_id.to_string()).or_default();
        queue.retain(|item| item.expires_at > now);
        if queue.iter().any(|item| item.token == token) {
            return;
        }
        while queue.len() >= MAX_PENDING_CONFIRMATIONS {
            queue.pop_front();
        }
        queue.push_back(PromotedResponderToken {
            token,
            expires_at: now + RESPONDER_SESSION_REPLAY_GRACE,
        });
    }

    async fn pending_promoted_responder_tokens(&self, peer_id: &str) -> Vec<String> {
        let now = Instant::now();
        let mut promoted = self.promoted_responder_tokens.lock().await;
        let Some(queue) = promoted.get_mut(peer_id) else {
            return Vec::new();
        };
        queue.retain(|item| item.expires_at > now);
        let tokens = queue
            .iter()
            .map(|item| item.token.clone())
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            promoted.remove(peer_id);
        }
        tokens
    }

    pub(crate) async fn acknowledge_promoted_responder_token(&self, peer_id: &str, token: &str) {
        let mut promoted = self.promoted_responder_tokens.lock().await;
        if let Some(queue) = promoted.get_mut(peer_id) {
            queue.retain(|item| item.token != token);
            if queue.is_empty() {
                promoted.remove(peer_id);
            }
        }
    }

    /// Encrypt and emit one packet while holding the peer's counter-ordering
    /// lock through the actual send. Synthetic confirmation packets use this
    /// path so a delayed low counter cannot fall behind a 64-packet burst.
    ///
    /// The lock wait is BOUNDED: if a burst of user traffic is holding the
    /// per-peer emit lock (encrypted_tx backpressure) the attempt is skipped
    /// and the caller's loop retries, so relay probes / direct-validation
    /// control packets are never blocked behind user traffic indefinitely.
    pub async fn encrypt_and_emit_outbound<F, Fut>(
        &self,
        packet: OutboundPacket,
        emit: F,
    ) -> Result<bool>
    where
        F: FnOnce(EncryptedPeerPacket) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        match self
            .encrypt_and_emit_outbound_with_lock_timeout(packet, CONTROL_EMIT_LOCK_TIMEOUT, emit)
            .await?
        {
            BoundedEmitOutcome::Sent => Ok(true),
            BoundedEmitOutcome::LockTimeout | BoundedEmitOutcome::SessionUnavailable => Ok(false),
        }
    }

    /// Encrypt and emit a synthetic packet with an explicit bounded wait for
    /// the per-peer counter-ordering lock. This keeps Direct validation from
    /// turning a busy live-TUN queue into a false high RTT while retaining the
    /// same FIFO/counter invariant as the ordinary control lane.
    pub(crate) async fn encrypt_and_emit_outbound_with_lock_timeout<F, Fut>(
        &self,
        packet: OutboundPacket,
        lock_timeout: Duration,
        emit: F,
    ) -> Result<BoundedEmitOutcome>
    where
        F: FnOnce(EncryptedPeerPacket) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let peer_id = packet.peer_id.clone();
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let lock_wait_started = Instant::now();
        let _emit_guard = match tokio::time::timeout(lock_timeout, emit_lock.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                debug!(
                    event = "control_emit_lock_timeout",
                    peer_id = %peer_id,
                    lock_timeout_ms = lock_timeout.as_millis() as u64,
                    lock_wait_ms = lock_wait_started.elapsed().as_millis() as u64,
                    bytes = packet.packet.len(),
                    "control/probe packet skipped: the outbound emit lock is held by busy user traffic; retrying on the next bounded tick"
                );
                return Ok(BoundedEmitOutcome::LockTimeout);
            }
        };
        debug!(
            event = "control_emit_lock_acquired",
            peer_id = %peer_id,
            lock_wait_ms = lock_wait_started.elapsed().as_millis() as u64,
            bytes = packet.packet.len(),
            "control/probe packet acquired the same per-peer counter-ordering lock as business traffic"
        );
        let packet_bytes = packet.packet.len();
        let Some(encrypted) = self.encrypt_outbound_inner(packet, false, false).await? else {
            return Ok(BoundedEmitOutcome::SessionUnavailable);
        };
        let counter = wire_counter(&encrypted.wire_bytes);
        let wire_fp = wire_fingerprint(&encrypted.wire_bytes);
        let encrypted_bytes = encrypted.wire_bytes.len();
        debug!(
            event = "control_transport_handoff_started",
            peer_id = %peer_id,
            counter = ?counter,
            bytes = encrypted_bytes,
            plaintext_bytes = packet_bytes,
            wire_fp = format_args!("{wire_fp:016x}"),
            "encrypted control packet entered its caller-provided transport handoff"
        );
        emit(encrypted).await?;
        debug!(
            event = "control_transport_handoff_completed",
            peer_id = %peer_id,
            counter = ?counter,
            bytes = encrypted_bytes,
            wire_fp = format_args!("{wire_fp:016x}"),
            "control packet handoff completed locally; peer delivery still requires its matching ACK"
        );
        Ok(BoundedEmitOutcome::Sent)
    }

    /// Replace a session and return the previous value for transactional rollback.
    pub async fn replace_session(
        &self,
        peer_id: impl Into<String>,
        session: TransportSession,
    ) -> Option<TransportSession> {
        let peer_id = peer_id.into();
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get_mut(&peer_id) {
            existing.previous = None;
            existing.mark_all_responder_tokens_terminal(now);
            existing.clear_pending_as_terminal(now);
            existing
                .active
                .replace(TransportSessionSlot::new(
                    session,
                    None,
                    self.allocate_session_instance(),
                ))
                .map(|previous| previous.session)
        } else {
            sessions.insert(
                peer_id,
                PeerTransportSessions::new(TransportSessionSlot::new(
                    session,
                    None,
                    self.allocate_session_instance(),
                )),
            );
            None
        }
    }

    /// Restore the session state captured before a transactional replacement.
    pub async fn restore_session(&self, peer_id: &str, previous: Option<TransportSession>) {
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        let restored_previous = previous.is_some();
        let mut sessions = self.sessions.lock().await;
        if let Some(previous) = previous {
            sessions.insert(
                peer_id.to_string(),
                PeerTransportSessions::new(TransportSessionSlot::new(
                    previous,
                    None,
                    self.allocate_session_instance(),
                )),
            );
        } else {
            sessions.remove(peer_id);
        }
        drop(sessions);
        drop(_emit_guard);
        drop(emit_lock);
        if restored_previous {
            self.flush_pending_outbound_for_peer(peer_id).await;
        } else {
            self.remove_idle_outbound_emit_lock(peer_id).await;
        }
    }

    /// Remove a peer session.
    pub async fn remove_session(&self, peer_id: &str) {
        // A session flush may already have removed its queue and be forwarding
        // raw packets. Wait for that per-peer ingress turn before clearing the
        // session/backlog, so a live packet cannot be inserted behind a
        // removal and later resurrect an obsolete session queue.
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        // Keep active-session removal and the legacy pending queue removal
        // behind the same per-peer emit lock used by encryption.  A packet
        // that already owns the lock is allowed to finish; after this point
        // no old-key packet can be created or handed to a transport.
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let emit_lock_started = Instant::now();
        let _emit_guard = emit_lock.lock().await;
        let removed_session = self.sessions.lock().await.remove(peer_id).is_some();
        let removed = self.pending_outbound.lock().await.remove(peer_id);
        let removed_queue_packets = removed.as_ref().map_or(0, |queue| queue.len());
        let removed_queue_bytes = removed.as_ref().map_or(0, |queue| {
            queue
                .iter()
                .map(|item| item.packet.packet.len())
                .sum::<usize>()
        });
        debug!(
            event = "wireguard_session_removed",
            peer_id = %peer_id,
            removed_session,
            removed_queue_packets,
            removed_queue_bytes,
            emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64,
            "WireGuard session and legacy session backlog were removed at one per-peer lifecycle boundary"
        );
        drop(_emit_guard);
        drop(emit_lock);
        if let Some(queue) = removed {
            let bytes = queue
                .iter()
                .map(|item| item.packet.packet.len())
                .sum::<usize>();
            self.record_outbound_drop(REASON_SESSION_QUEUE_REMOVED, queue.len(), bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                peer_id,
                REASON_SESSION_QUEUE_REMOVED,
                queue.len(),
                bytes,
            )
            .await;
        }
        self.promoted_responder_tokens.lock().await.remove(peer_id);
        self.remove_idle_outbound_emit_lock(peer_id).await;
    }

    /// Return whether a peer has an encrypting session.
    pub async fn has_session(&self, peer_id: &str) -> bool {
        self.session_status(peer_id).await.has_active
    }

    /// Return one consistent active/pending snapshot under a single lock.
    pub async fn session_status(&self, peer_id: &str) -> TransportSessionStatus {
        let now = Instant::now();
        let (status, remove_idle_emit_lock) = {
            let mut sessions = self.sessions.lock().await;
            let Some(existing) = sessions.get_mut(peer_id) else {
                drop(sessions);
                self.remove_idle_outbound_emit_lock(peer_id).await;
                return TransportSessionStatus::default();
            };
            existing.prepare_active(now);
            let status = existing.status();
            let remove_empty = !status.has_active
                && !status.has_pending_responder
                && existing.previous.is_none()
                && existing.responder_token_states.is_empty();
            if remove_empty {
                sessions.remove(peer_id);
            }
            (status, remove_empty)
        };
        if remove_idle_emit_lock {
            self.remove_idle_outbound_emit_lock(peer_id).await;
        }
        status
    }

    /// Return whether a peer's session needs rekey.
    pub async fn session_needs_rekey(&self, peer_id: &str) -> bool {
        self.session_status(peer_id).await.needs_rekey
    }

    /// Return whether a peer's session has expired (reject threshold exceeded).
    pub async fn session_is_expired(&self, peer_id: &str) -> bool {
        self.session_status(peer_id).await.expired
    }

    /// Encrypt one outbound packet.
    pub async fn encrypt_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let emit_lock = self.outbound_emit_lock(&packet.peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        self.encrypt_outbound_inner(packet, false, false).await
    }

    /// Encrypt one outbound user packet, or queue it briefly if the session is
    /// not installed yet. This is used only by the TUN data path; synthetic
    /// validation/probe packets continue to use encrypt_outbound so they do not
    /// fill the startup queue while polling for readiness.
    pub async fn encrypt_or_queue_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let peer_id = packet.peer_id.clone();
        // Reserve the raw per-peer ingress turn before checking session state.
        // If a responder is being installed concurrently, the session-ready
        // flush and a live packet cannot cross each other at this boundary.
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let emit_guard = emit_lock.lock().await;
        let queued_packet = packet.clone();
        // Do not let this legacy convenience API create a second producer
        // ordering domain while the production network-outbound worker owns
        // plaintext parking. If the session is absent, park the raw packet in
        // the same transport backlog under the ingress guard below.
        let encrypted = self.encrypt_outbound_inner(packet, false, true).await?;
        drop(emit_guard);
        if encrypted.is_none() {
            self.queue_pending_outbound_locked(queued_packet, "session not ready")
                .await;
        }
        Ok(encrypted)
    }

    #[cfg(test)]
    /// Test-only compatibility wrapper that returns the guard with the
    /// encrypted packet for counter-ordering unit tests.
    pub(crate) async fn encrypt_outbound_with_guard(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<(EncryptedPeerPacket, Arc<OwnedMutexGuard<()>>)>> {
        let peer_id = packet.peer_id.clone();
        let emit_guard = Arc::new(self.acquire_outbound_emit_guard(&peer_id).await);
        let Some(encrypted) = self.encrypt_outbound_with_emit_guard(packet).await? else {
            return Ok(None);
        };
        Ok(Some((encrypted, emit_guard)))
    }

    /// Acquire the per-peer counter-ordering guard without doing any session
    /// work.  Callers that must compose this guard with another lifecycle
    /// transaction (for example the network-generation gate) acquire it
    /// first, so every production path uses the lock order
    /// `emit -> epoch -> sessions`.
    pub(crate) async fn acquire_outbound_emit_guard(&self, peer_id: &str) -> OwnedMutexGuard<()> {
        self.outbound_emit_lock(peer_id).await.lock_owned().await
    }

    /// Encrypt while the caller already owns the peer's emit guard.  Keeping
    /// this separate prevents a caller from taking the global epoch gate and
    /// then waiting for emit: inbound relay ACK/business evidence takes emit
    /// first and then commits generation-bound state, so the opposite order
    /// would create an ABBA deadlock.
    pub(crate) async fn encrypt_outbound_with_emit_guard(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        // The network-outbound actor owns the sole production plaintext FIFO.
        // Do not enter the legacy session backlog while holding emit_lock:
        // remove_session takes ingress_lock before emit_lock, so queueing
        // here would create an emit -> ingress wait against its ingress ->
        // emit teardown order.  Returning None lets the actor re-park the
        // plaintext without allocating a WireGuard counter.
        self.encrypt_outbound_inner(packet, false, true).await
    }

    /// Encrypt a business packet only if the cached active session instance
    /// is still installed.  The caller owns the per-peer emit guard and the
    /// network-epoch gate, so this method takes only the short sessions lock;
    /// it never performs network I/O while either ordering guard is held.
    pub(crate) async fn encrypt_outbound_with_emit_guard_for_session(
        &self,
        packet: OutboundPacket,
        expected_session_instance: u64,
    ) -> SessionBoundEncryption {
        let profiler = global_dataplane_profiler();
        let sampled = packet.trace.as_ref().map(|trace| trace.sampled);
        let session_lock_started = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let session_lock_acquired = Instant::now();
        let session_lock_wait_us = session_lock_acquired
            .duration_since(session_lock_started)
            .as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_wait_us",
                Duration::from_micros(session_lock_wait_us),
            );
        }
        let now = Instant::now();
        let Some(peer_sessions) = sessions.get_mut(&packet.peer_id) else {
            return SessionBoundEncryption::Unavailable(packet);
        };
        peer_sessions.prepare_active(now);
        let Some(active) = peer_sessions.active.as_mut() else {
            return SessionBoundEncryption::Unavailable(packet);
        };
        if active.session_instance != expected_session_instance || active.session.is_expired() {
            return SessionBoundEncryption::Unavailable(packet);
        }

        let session_instance = active.session_instance;
        let crypto_started = Instant::now();
        let wire_bytes = match active.session.encrypt_to_bytes(&packet.packet) {
            Ok(wire_bytes) => wire_bytes,
            Err(error) => {
                return SessionBoundEncryption::Failed {
                    packet,
                    error: DaemonError::Peer(format!("WireGuard encrypt failed: {error}")),
                };
            }
        };
        let crypto_us = crypto_started.elapsed().as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_crypto_exec_us",
                Duration::from_micros(crypto_us),
            );
        }
        debug!(
            event = "wireguard_outbound_counter_allocated",
            peer_id = %packet.peer_id,
            session_instance,
            counter = ?wire_counter(&wire_bytes),
            bytes = wire_bytes.len(),
            is_business = true,
            wire_fp = format_args!("{:016x}", wire_fingerprint(&wire_bytes)),
            "WireGuard counter allocated under the LAN Direct fast-path ordering lock"
        );
        let encrypted = EncryptedPeerPacket {
            peer_id: packet.peer_id,
            dst_ip: packet.dst_ip,
            wire_bytes,
            is_business: true,
        };
        let session_lock_hold_us = session_lock_acquired.elapsed().as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_hold_us",
                Duration::from_micros(session_lock_hold_us),
            );
        }
        drop(sessions);
        SessionBoundEncryption::Encrypted {
            packet: encrypted,
            session_lock_wait_us,
            crypto_us,
        }
    }

    async fn outbound_emit_lock(&self, peer_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.outbound_emit_locks.lock().await;
        if let Some(lock) = locks.get(peer_id).and_then(Weak::upgrade) {
            return lock;
        }

        // A missing/dead target means this is a new lock incarnation. Prune
        // other dead weak entries at the same time so ongoing peer churn
        // cannot grow the registry without adding O(peer_count) work to every
        // ordinary packet on an already-active peer.
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(peer_id.to_string(), Arc::downgrade(&lock));
        lock
    }

    async fn outbound_ingress_lock(&self, peer_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.outbound_ingress_locks.lock().await;
        if let Some(lock) = locks.get(peer_id).and_then(Weak::upgrade) {
            return lock;
        }

        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        locks.insert(peer_id.to_string(), Arc::downgrade(&lock));
        lock
    }

    async fn remove_idle_outbound_emit_lock(&self, peer_id: &str) {
        let mut locks = self.outbound_emit_locks.lock().await;
        if locks
            .get(peer_id)
            .is_some_and(|lock| lock.upgrade().is_none())
        {
            locks.remove(peer_id);
        }
    }

    async fn encrypt_outbound_inner(
        &self,
        packet: OutboundPacket,
        queue_if_unavailable: bool,
        is_business: bool,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let profiler = global_dataplane_profiler();
        let sampled = packet.trace.as_ref().map(|trace| trace.sampled);
        let session_lock_started = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let session_lock_acquired = Instant::now();
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_wait_us",
                session_lock_acquired.duration_since(session_lock_started),
            );
        }
        let now = Instant::now();
        let Some(peer_sessions) = sessions.get_mut(&packet.peer_id) else {
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session not ready")
                    .await;
            } else {
                debug!(
                    "No WireGuard session for peer {}; dropping {} byte packet",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        };
        peer_sessions.prepare_active(now);
        let Some(active) = peer_sessions.active.as_mut() else {
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session expired before rekey")
                    .await;
            } else {
                debug!(
                    "No usable WireGuard session for peer {}; dropping {} byte packet until rekey completes",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        };
        if active.session.is_expired() {
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session expired before rekey")
                    .await;
            } else {
                debug!(
                    "WireGuard session for peer {} expired; dropping {} byte packet until authenticated rekey confirmation",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        }

        let session_instance = active.session_instance;
        let crypto_started = Instant::now();
        let wire_result = active.session.encrypt_to_bytes(&packet.packet);
        let crypto_us = crypto_started.elapsed().as_micros() as u64;
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_crypto_exec_us",
                Duration::from_micros(crypto_us),
            );
        }
        let wire_bytes =
            wire_result.map_err(|e| DaemonError::Peer(format!("WireGuard encrypt failed: {e}")))?;
        debug!(
            event = "wireguard_outbound_counter_allocated",
            peer_id = %packet.peer_id,
            session_instance,
            counter = ?wire_counter(&wire_bytes),
            bytes = wire_bytes.len(),
            is_business,
            wire_fp = format_args!("{:016x}", wire_fingerprint(&wire_bytes)),
            "WireGuard counter allocated under the per-peer emit ordering lock"
        );
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_session_lock_hold_us",
                session_lock_acquired.elapsed(),
            );
        }
        drop(sessions);

        Ok(Some(EncryptedPeerPacket {
            peer_id: packet.peer_id,
            dst_ip: packet.dst_ip,
            wire_bytes,
            is_business,
        }))
    }

    async fn queue_pending_outbound(&self, packet: OutboundPacket, reason: &'static str) {
        let peer_id = packet.peer_id.clone();
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        self.queue_pending_outbound_locked(packet, reason).await;
    }

    /// Queue a raw packet while the caller owns the peer's ingress turn.
    /// Keeping the mutation and the flush/removal boundary under the same
    /// lock prevents a live producer from racing an in-flight session flush.
    async fn queue_pending_outbound_locked(&self, packet: OutboundPacket, reason: &'static str) {
        let now = Instant::now();
        let peer_id = packet.peer_id.clone();
        let packet_len = packet.packet.len();
        let (stale_dropped, stale_bytes, overflow_dropped, overflow_bytes, depth) = {
            let mut pending = self.pending_outbound.lock().await;
            let queue = pending.entry(peer_id.clone()).or_default();
            let stale_before = queue.len();
            let mut stale_bytes = 0usize;
            queue.retain(|queued| {
                let fresh = now.saturating_duration_since(queued.queued_at) <= PENDING_OUTBOUND_TTL;
                if !fresh {
                    stale_bytes = stale_bytes.saturating_add(queued.packet.packet.len());
                }
                fresh
            });
            let stale_dropped = stale_before.saturating_sub(queue.len());
            let mut overflow_dropped = 0usize;
            let mut overflow_bytes = 0usize;
            while queue.len() >= MAX_PENDING_OUTBOUND_PER_PEER {
                if let Some(old) = queue.pop_front() {
                    overflow_dropped = overflow_dropped.saturating_add(1);
                    overflow_bytes = overflow_bytes.saturating_add(old.packet.packet.len());
                }
            }
            queue.push_back(PendingOutboundPacket {
                queued_at: now,
                packet,
            });
            (
                stale_dropped,
                stale_bytes,
                overflow_dropped,
                overflow_bytes,
                queue.len(),
            )
        };
        if stale_dropped > 0 {
            self.record_outbound_drop(REASON_SESSION_QUEUE_STALE, stale_dropped, stale_bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                &peer_id,
                REASON_SESSION_QUEUE_STALE,
                stale_dropped,
                stale_bytes,
            )
            .await;
        }
        if overflow_dropped > 0 {
            self.record_outbound_drop(REASON_SESSION_QUEUE_FULL, overflow_dropped, overflow_bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                &peer_id,
                REASON_SESSION_QUEUE_FULL,
                overflow_dropped,
                overflow_bytes,
            )
            .await;
        }
        debug!(
            "Queued outbound packet for peer {} until WireGuard session is ready ({} bytes, reason={}, depth={}, stale_dropped={}, overflow_dropped={})",
            peer_id,
            packet_len,
            reason,
            depth,
            stale_dropped,
            overflow_dropped
        );
    }

    /// Forward a live raw TUN packet through the same per-peer ingress turn as
    /// session-ready backlog flushing. If a backlog exists, append behind it;
    /// otherwise hand the packet to the network-outbound worker immediately.
    async fn forward_raw_outbound(&self, mut packet: OutboundPacket) -> Result<()> {
        let peer_id = packet.peer_id.clone();
        let profiler = global_dataplane_profiler();
        let sampled = packet.trace.as_ref().map(|trace| trace.sampled);
        let ingress_wait_started = Instant::now();
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let ingress_guard_acquired = Instant::now();
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_outbound_ingress_lock_wait_us",
                ingress_wait_started.elapsed(),
            );
        }
        let pending_lock_started = Instant::now();
        let has_pending = self.pending_outbound.lock().await.contains_key(&peer_id);
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_pending_queue_lock_wait_us",
                pending_lock_started.elapsed(),
            );
        }
        if has_pending {
            self.queue_pending_outbound_locked(packet, "session backlog flush in progress")
                .await;
            if let Some(sampled) = sampled {
                profiler.record(
                    sampled,
                    "tx_outbound_ingress_lock_hold_us",
                    ingress_guard_acquired.elapsed(),
                );
            }
            return Ok(());
        }
        let queue_send_started = Instant::now();
        if let Some(trace) = packet.trace.as_mut() {
            trace.transport_queue_send_started = Some(queue_send_started);
        }
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record_value(
                trace.sampled,
                "tx_network_outbound_queue_depth_before_send",
                self.outbound_tx
                    .max_capacity()
                    .saturating_sub(self.outbound_tx.capacity()) as u64,
            );
        }
        let result = self
            .outbound_tx
            .send(packet)
            .await
            .map_err(|_| DaemonError::Network("outbound packet channel closed".to_string()));
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_outbound_ingress_lock_hold_us",
                ingress_guard_acquired.elapsed(),
            );
        }
        result
    }

    pub(crate) async fn flush_pending_outbound_for_peer(&self, peer_id: &str) {
        // Hold the ingress turn for the entire raw FIFO handoff. Live TUN
        // packets arriving during this operation either wait and follow the
        // flushed backlog, or are appended before this turn begins.
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let now = Instant::now();
        let (packets, expired_count, expired_bytes) = {
            let mut pending = self.pending_outbound.lock().await;
            let Some(queue) = pending.get_mut(peer_id) else {
                return;
            };
            let mut packets = Vec::with_capacity(queue.len());
            let mut expired_count = 0usize;
            let mut expired_bytes = 0usize;
            while let Some(queued) = queue.pop_front() {
                if now.saturating_duration_since(queued.queued_at) <= PENDING_OUTBOUND_TTL {
                    packets.push(queued.packet);
                } else {
                    expired_count = expired_count.saturating_add(1);
                    expired_bytes = expired_bytes.saturating_add(queued.packet.packet.len());
                }
            }
            pending.remove(peer_id);
            (packets, expired_count, expired_bytes)
        };

        if expired_count > 0 {
            self.record_outbound_drop(REASON_SESSION_QUEUE_STALE, expired_count, expired_bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                peer_id,
                REASON_SESSION_QUEUE_STALE,
                expired_count,
                expired_bytes,
            )
            .await;
            debug!(
                "Discarded {} expired pending outbound packets for peer {}",
                expired_count, peer_id
            );
        }
        if packets.is_empty() {
            return;
        }

        // Forward the RAW packets to the network outbound worker in FIFO
        // order.  The worker owns encryption: it holds the peer's emit lock
        // from encryption through the actual send, so counters are allocated
        // and transmitted strictly in queue order (never a relay probe /
        // direct-validation control packet jumping ahead of a queued business
        // packet's counter).
        let total_packets = packets.len();
        let total_bytes = packets
            .iter()
            .map(|packet| packet.packet.len())
            .sum::<usize>();
        let mut forwarded = 0usize;
        let mut forwarded_bytes = 0usize;
        for packet in packets {
            let packet_bytes = packet.packet.len();
            if let Err(err) = self.outbound_tx.send(packet).await {
                warn!(
                    "Pending outbound packet channel closed while flushing peer {}: {err}",
                    peer_id
                );
                let remaining = total_packets.saturating_sub(forwarded + 1);
                // The failed send owns the packet; count it and every item
                // still held locally instead of silently losing the session
                // queue during actor shutdown.
                self.record_outbound_drop(
                    REASON_SESSION_QUEUE_REMOVED,
                    remaining + 1,
                    total_bytes.saturating_sub(forwarded_bytes),
                )
                .await;
                self.record_outbound_queue_event(
                    "drop",
                    peer_id,
                    REASON_SESSION_QUEUE_REMOVED,
                    remaining + 1,
                    total_bytes.saturating_sub(forwarded_bytes),
                )
                .await;
                break;
            }
            forwarded = forwarded.saturating_add(1);
            forwarded_bytes = forwarded_bytes.saturating_add(packet_bytes);
        }
        debug!(
            "Forwarded pending outbound packets for peer {} (forwarded={}, expired={})",
            peer_id, forwarded, expired_count
        );
    }

    /// Decrypt one inbound WireGuard transport packet.
    pub async fn decrypt_inbound(&self, wire_bytes: &[u8]) -> Result<Option<InboundPacket>> {
        let msg = MessageTransport::from_bytes(wire_bytes)
            .map_err(|e| DaemonError::Peer(format!("WireGuard packet parse failed: {e}")))?;
        let receiver_index = msg.receiver_index;

        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();
        for peer_sessions in sessions.values_mut() {
            peer_sessions.prune_expired(now);
        }

        let mut first_decrypt_error = None;
        // Peers whose session produced a replay-classified decrypt failure.
        // The same WireGuard ciphertext is legitimately delivered twice during
        // the Direct trial window (once per Direct path, once per relay hedge);
        // WireGuard's replay protection then rejects the second copy.  These
        // duplicates are counted and logged rate-limited instead of emitting a
        // warning storm, and they never touch path state.
        let mut replay_attributed_peers: Vec<String> = Vec::new();

        // Prefer the active session if an extremely unlikely receiver-index
        // collision occurs. Successfully receiving the new key confirms the
        // peer has completed the rekey, so the prior key can be retired early.
        let mut confirmed_active = None;
        for (peer_id, peer_sessions) in sessions.iter_mut() {
            let Some(active) = peer_sessions.active.as_mut() else {
                continue;
            };
            if active.session.our_index() != receiver_index {
                continue;
            }
            match active.session.decrypt(&msg) {
                Ok(packet) => {
                    let token = active
                        .awaiting_confirmation
                        .then(|| active.token.clone())
                        .flatten();
                    active.awaiting_confirmation = false;
                    confirmed_active =
                        Some((peer_id.clone(), packet, token, active.session_instance));
                    break;
                }
                Err(error) => {
                    first_decrypt_error.get_or_insert_with(|| error.to_string());
                    if is_replay_decrypt_error(&error.to_string())
                        && !replay_attributed_peers.contains(peer_id)
                    {
                        replay_attributed_peers.push(peer_id.clone());
                    }
                }
            }
        }
        if let Some((peer_id, packet, token, session_instance)) = confirmed_active {
            drop(sessions);
            if let Some(token) = token {
                self.remember_promoted_responder_token(&peer_id, token)
                    .await;
            }
            return Ok(Some(InboundPacket {
                peer_id,
                packet,
                session_instance: Some(session_instance),
                from_previous_session: false,
                trace: None,
            }));
        }

        // A responder stages the new receive key before publishing its answer.
        // The first authenticated packet under that key is the peer's commit
        // acknowledgement and atomically promotes it for outbound traffic.
        let mut promoted = None;
        for (peer_id, peer_sessions) in sessions.iter_mut() {
            let pending_token = peer_sessions.pending.iter().find_map(|(token, pending)| {
                (pending.slot.session.our_index() == receiver_index).then(|| token.clone())
            });
            let Some(pending_token) = pending_token else {
                continue;
            };
            let mut pending = peer_sessions
                .pending
                .remove(&pending_token)
                .expect("pending responder token checked above");
            match pending.slot.session.decrypt(&msg) {
                Ok(packet) => {
                    let session_instance = pending.slot.session_instance;
                    peer_sessions.pending.insert(pending_token.clone(), pending);
                    promoted = Some((
                        peer_id.clone(),
                        packet,
                        Some(pending_token),
                        session_instance,
                    ));
                    break;
                }
                Err(error) => {
                    first_decrypt_error.get_or_insert_with(|| error.to_string());
                    if is_replay_decrypt_error(&error.to_string())
                        && !replay_attributed_peers.contains(peer_id)
                    {
                        replay_attributed_peers.push(peer_id.clone());
                    }
                    peer_sessions.pending.insert(pending_token, pending);
                }
            }
        }
        if let Some((peer_id, packet, token, session_instance)) = promoted {
            drop(sessions);
            let Some(token) = token else {
                return Ok(None);
            };

            // The first packet under a staged responder key promotes that key
            // to active.  Do not perform that replacement while only the
            // sessions mutex is held: an outbound packet for the old active
            // key may already own the per-peer emit lock.  Recheck the exact
            // session instance after acquiring the lock; a concurrent
            // remove/replace is then a terminal stale packet rather than an
            // old-key packet published after the new key.
            let emit_lock = self.outbound_emit_lock(&peer_id).await;
            let _emit_guard = emit_lock.lock().await;
            let (promoted_now, still_retained) = {
                let mut sessions = self.sessions.lock().await;
                match sessions.get_mut(&peer_id) {
                    None => (false, false),
                    Some(existing) => {
                        if existing.pending.get(&token).is_some_and(|pending| {
                            pending.slot.session_instance == session_instance
                        }) {
                            existing.promote_pending(&token, now);
                            (true, true)
                        } else {
                            (false, existing.has_session_instance(session_instance))
                        }
                    }
                }
            };
            drop(_emit_guard);
            drop(emit_lock);
            if !still_retained {
                debug!(
                    peer_id = %peer_id,
                    session_instance,
                    "dropping responder packet whose staged session was replaced before promotion"
                );
                return Ok(None);
            }
            self.remember_promoted_responder_token(&peer_id, token)
                .await;
            if promoted_now {
                self.flush_pending_outbound_for_peer(&peer_id).await;
            }
            return Ok(Some(InboundPacket {
                peer_id,
                packet,
                session_instance: Some(session_instance),
                from_previous_session: false,
                trace: None,
            }));
        }

        for (peer_id, peer_sessions) in sessions.iter_mut() {
            let Some(previous) = peer_sessions.previous.as_mut() else {
                continue;
            };
            if previous.slot.session.our_index() != receiver_index {
                continue;
            }
            match previous.slot.session.decrypt(&msg) {
                Ok(packet) => {
                    return Ok(Some(InboundPacket {
                        peer_id: peer_id.clone(),
                        packet,
                        session_instance: Some(previous.slot.session_instance),
                        from_previous_session: true,
                        trace: None,
                    }));
                }
                Err(error) => {
                    first_decrypt_error.get_or_insert_with(|| error.to_string());
                    if is_replay_decrypt_error(&error.to_string())
                        && !replay_attributed_peers.contains(peer_id)
                    {
                        replay_attributed_peers.push(peer_id.clone());
                    }
                }
            }
        }

        if let Some(error) = first_decrypt_error {
            let replay_peers = std::mem::take(&mut replay_attributed_peers);
            if !replay_peers.is_empty() {
                self.note_hedge_duplicate_replay(&replay_peers, msg.counter);
            }
            return Err(DaemonError::Peer(format!(
                "WireGuard decrypt failed: {error}"
            )));
        }

        debug!(
            "No WireGuard session for receiver index {}; dropping inbound packet",
            receiver_index
        );
        Ok(None)
    }

    /// Number of replay-classified decrypt duplicates attributed to a peer.
    #[cfg(test)]
    pub(crate) fn hedge_replay_count(&self, peer_id: &str) -> u64 {
        self.hedge_replay_counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .map_or(0, |counter| counter.count)
    }

    /// Count a relay-hedge attributable replay for each peer and log
    /// rate-limited.
    ///
    /// WireGuard's counter-based replay protection already drops the duplicate
    /// copy of a ciphertext delivered on both the Direct and the relay hedge
    /// path.  The duplicate is a proof of duplicate delivery, not of an
    /// attack: it never changes Direct/Relay path state, never establishes
    /// affinity and never triggers validation (the decryption itself failed
    /// before any observation was created).  Counting it keeps the storm out
    /// of the WARN log while security-class errors (parse failures, unknown
    /// receiver index, wrong key) still log at WARN through the ordinary
    /// error path.
    fn note_hedge_duplicate_replay(&self, peers: &[String], counter: u64) {
        let mut counters = self
            .hedge_replay_counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for peer_id in peers {
            let replay_counter = counters.entry(peer_id.clone()).or_default();
            replay_counter.count = replay_counter.count.saturating_add(1);
            let loud = replay_counter
                .last_loud_at
                .is_none_or(|at| at.elapsed() >= HEDGE_REPLAY_WARN_INTERVAL);
            if loud {
                replay_counter.last_loud_at = Some(Instant::now());
                warn!(
                    event = "hedge_duplicate_replay",
                    peer_id = %peer_id,
                    wireguard_counter = counter,
                    total = replay_counter.count,
                    "WireGuard replay protection dropped a duplicate copy of an already-decrypted ciphertext; no path state changes"
                );
            } else {
                debug!(
                    event = "hedge_duplicate_replay",
                    peer_id = %peer_id,
                    wireguard_counter = counter,
                    total = replay_counter.count,
                    "duplicate ciphertext copy dropped; no path state changes"
                );
            }
        }
    }

    /// Forward routed packets from the dataplane to the network outbound
    /// worker WITHOUT encrypting them.
    ///
    /// The worker is the only place that encrypts business packets: it checks
    /// path usability first, parks PLAINTEXT packets for a not-yet-usable
    /// peer, and only then — once the path is confirmed — acquires the
    /// per-peer emit lock and encrypts + sends each packet in FIFO order
    /// holding the lock through the actual send.  A parked packet therefore
    /// never holds the emit lock, never occupies a WireGuard counter, and can
    /// never be overtaken on the wire by a higher-counter control packet.
    pub async fn run_outbound(
        &self,
        mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    ) -> Result<()> {
        while let Some(mut packet) = outbound_rx.recv().await {
            let profiler = global_dataplane_profiler();
            let transport_dequeued = Instant::now();
            if let Some(trace) = packet.trace.as_mut() {
                trace.transport_queue_dequeued = Some(transport_dequeued);
                profiler.record_value(
                    trace.sampled,
                    "tx_dataplane_queue_depth",
                    outbound_rx.len() as u64,
                );
                if let Some(enqueued) = trace.dataplane_queue_send_started {
                    profiler.record(
                        trace.sampled,
                        "tx_dataplane_queue_wait_us",
                        transport_dequeued.duration_since(enqueued),
                    );
                }
            }
            self.forward_raw_outbound(packet).await?;
        }
        Ok(())
    }

    /// Consume encrypted network packets, decrypt them, and emit raw inbound IP packets.
    pub async fn run_inbound(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
    ) -> Result<()> {
        self.run_inbound_with_peers(encrypted_rx, inbound_tx, None, None)
            .await
    }

    /// Consume encrypted network packets and confirm direct UDP only after
    /// successful WireGuard decryption.
    ///
    /// `udp` optionally carries the direct UDP transport: a decrypted packet
    /// whose receive socket is known adopts the socket as the peer's fresh
    /// affinity evidence — raw encrypted UDP is never affinity evidence
    /// before decryption proves the datagram belongs to the peer.
    pub async fn run_inbound_with_peers(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp: Option<crate::udp::UdpTransport>,
    ) -> Result<()> {
        self.run_inbound_with_udp_source(
            encrypted_rx,
            inbound_tx,
            peers,
            InboundUdpTransport::Static(Box::new(udp)),
            None,
        )
        .await
    }

    /// Consume encrypted packets while resolving the UDP transport from the
    /// latest daemon publication for every packet.  `evidence` optionally
    /// carries the shared relay transport (for forced-relay probe ACKs) and the
    /// overlay ingress channel (real ingress metadata for decrypted overlay
    /// payloads).  This is intentionally separate from the static API above so
    /// unit tests and non-daemon users retain their simple
    /// `Option<UdpTransport>` setup.
    pub(crate) async fn run_inbound_with_peers_live_udp_and_relay(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp_updates: watch::Receiver<Option<crate::udp::UdpTransport>>,
        evidence: Option<InboundEvidenceFeed>,
    ) -> Result<()> {
        self.run_inbound_with_udp_source(
            encrypted_rx,
            inbound_tx,
            peers,
            InboundUdpTransport::Watch(udp_updates),
            evidence,
        )
        .await
    }

    /// Consume encrypted packets while resolving the UDP transport from the
    /// latest daemon publication for every packet.  This is intentionally
    /// separate from the static API above so unit tests and non-daemon users
    /// retain their simple `Option<UdpTransport>` setup.
    #[cfg(test)]
    pub(crate) async fn run_inbound_with_peers_live_udp(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp_updates: watch::Receiver<Option<crate::udp::UdpTransport>>,
    ) -> Result<()> {
        self.run_inbound_with_peers_live_udp_and_relay(
            encrypted_rx,
            inbound_tx,
            peers,
            udp_updates,
            None,
        )
        .await
    }

    async fn run_inbound_with_udp_source(
        &self,
        mut encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp_source: InboundUdpTransport,
        evidence: Option<InboundEvidenceFeed>,
    ) -> Result<()> {
        while let Some(packet) = encrypted_rx.recv().await {
            let profiler = global_dataplane_profiler();
            let sampled = packet.profile_sampled;
            let transport_dequeued = Instant::now();
            profiler.record_value(
                sampled,
                "rx_transport_inbound_queue_depth",
                encrypted_rx.len() as u64,
            );
            if let Some(enqueued) = packet.transport_queue_send_started {
                profiler.record(
                    sampled,
                    "rx_transport_queue_wait_us",
                    transport_dequeued.duration_since(enqueued),
                );
            }
            if let Some(udp_received) = packet.udp_received {
                profiler.record(
                    sampled,
                    "rx_udp_receive_to_decrypt_us",
                    Instant::now().duration_since(udp_received),
                );
            }
            let source = packet.source;
            let local_endpoint = packet.local_endpoint;
            let relay_endpoint = packet.relay_endpoint;
            let relay_connection_id = packet.relay_connection_id;
            let relay_peer_id = packet.relay_peer_id;
            let socket_index = packet.socket_index;
            let direct_socket = packet.direct_socket;
            let udp_transport_owner = packet.udp_transport_owner;
            let packet_network_generation = packet.network_generation;
            debug!(
                event = "wireguard_inbound_envelope_received",
                bytes = packet.wire_bytes.len(),
                counter = ?wire_counter(&packet.wire_bytes),
                wire_fp = format_args!("{:016x}", wire_fingerprint(&packet.wire_bytes)),
                source = ?source,
                local_endpoint = ?local_endpoint,
                socket_index = ?socket_index,
                relay_endpoint = ?relay_endpoint,
                relay_connection_id = ?relay_connection_id,
                relay_peer_id = ?relay_peer_id,
                network_generation = ?packet_network_generation,
                "encrypted datagram reached the daemon transport decrypt boundary"
            );
            let decrypt_started = Instant::now();
            match self.decrypt_inbound(&packet.wire_bytes).await {
                Ok(Some(mut inbound)) => {
                    let decrypt_completed = Instant::now();
                    profiler.record(
                        sampled,
                        "rx_decrypt_us",
                        decrypt_completed.duration_since(decrypt_started),
                    );
                    profiler.record(
                        sampled,
                        "transport_queue_to_decrypt_us",
                        decrypt_started.duration_since(transport_dequeued),
                    );
                    profiler.record(
                        sampled,
                        "decrypt_us",
                        decrypt_completed.duration_since(decrypt_started),
                    );
                    inbound.trace = Some(DataplaneRxTrace {
                        sampled,
                        udp_received: packet.udp_received,
                        transport_queue_send_started: packet.transport_queue_send_started,
                        transport_dequeued,
                        decrypt_started,
                        decrypt_completed,
                        inbound_queue_send_started: None,
                        inbound_queue_dequeued: None,
                    });
                    debug!(
                        event = "wireguard_inbound_decrypt_succeeded",
                        peer_id = %inbound.peer_id,
                        counter = ?wire_counter(&packet.wire_bytes),
                        wire_fp = format_args!("{:016x}", wire_fingerprint(&packet.wire_bytes)),
                        session_instance = ?inbound.session_instance,
                        from_previous_session = inbound.from_previous_session,
                        source = ?source,
                        relay_endpoint = ?relay_endpoint,
                        relay_connection_id = ?relay_connection_id,
                        network_generation = ?packet_network_generation,
                        "WireGuard authenticated and decrypted the envelope before lifecycle/path evidence gates"
                    );
                    if let (Some(packet_generation), Some(peer_manager)) =
                        (packet_network_generation, peers.as_ref())
                    {
                        let current_generation = peer_manager.current_network_generation_sync();
                        if packet_generation != current_generation {
                            if let Some(feed) = evidence.as_ref() {
                                if let Some(timeline) = feed.timeline.as_ref() {
                                    timeline.emit(
                                        "stale_network_generation_packet",
                                        None,
                                        Some("stale_network_generation"),
                                        Some(format!(
                                            "peer={} packet_generation={packet_generation} current_generation={current_generation}",
                                            inbound.peer_id
                                        )),
                                    );
                                }
                            }
                            debug!(
                                peer_id = %inbound.peer_id,
                                packet_generation,
                                current_generation,
                                "dropping encrypted packet queued before the current network generation"
                            );
                            continue;
                        }
                    }
                    if let Some(session_instance) = inbound.session_instance {
                        let (retained, current) = self
                            .session_instance_state(&inbound.peer_id, session_instance)
                            .await;
                        if !retained || (!inbound.from_previous_session && !current) {
                            if let Some(feed) = evidence.as_ref() {
                                if let Some(timeline) = feed.timeline.as_ref() {
                                    timeline.emit(
                                        "stale_session_packet",
                                        None,
                                        Some("session_replaced_or_removed"),
                                        Some(format!(
                                            "peer={} session_instance={session_instance}",
                                            inbound.peer_id
                                        )),
                                    );
                                }
                            }
                            debug!(
                                peer_id = %inbound.peer_id,
                                session_instance,
                                "dropping packet decrypted by a removed or replaced transport session"
                            );
                            continue;
                        }
                    }
                    // The previous receive key is retained only as a bounded
                    // WireGuard rekey grace period. It may deliver an
                    // in-flight user packet, but it must never confirm a
                    // relay/direct path, advance affinity, or create current
                    // generation first-usable evidence.
                    let session_evidence_eligible = !inbound.from_previous_session;
                    // Do not retain a UDP watch snapshot across decrypt. A
                    // datagram can sit in the channel while its reader fails
                    // or its socket is rebound; only the current owner after
                    // decrypt may provide Direct evidence or affinity.
                    let udp = udp_source.snapshot();
                    let owns_direct_packet =
                        udp_source.owns_direct_packet(udp_transport_owner, udp.as_ref());
                    if relay_peer_id
                        .as_deref()
                        .is_some_and(|relay_peer_id| relay_peer_id != inbound.peer_id)
                    {
                        warn!(
                            "Dropping relay packet whose registered source {:?} does not match decrypted peer {}",
                            relay_peer_id, inbound.peer_id
                        );
                        continue;
                    }
                    // The relay probe loop is intentionally paced and can
                    // lose a scheduling race with the first encrypted frame
                    // arriving from a newly published relay reader.  Publish
                    // the per-peer transport-ready milestone at the decrypt
                    // boundary as well, before any probe/business evidence is
                    // processed.  Bind every relay envelope—not only probe
                    // ACKs—to the current transport incarnation: a draining
                    // old reader with the same endpoint must not deliver a
                    // user packet or create first-usable evidence for the new
                    // relay session.
                    let relay_ingress_is_current = if relay_endpoint.is_some() {
                        match evidence.as_ref() {
                            Some(feed) => {
                                let current_connection_id = feed
                                    .relay_transport
                                    .read()
                                    .await
                                    .as_ref()
                                    .map(RelayTransport::connection_id);
                                match (relay_connection_id, current_connection_id) {
                                    (Some(packet_id), Some(current_id)) => packet_id == current_id,
                                    (None, None) => true,
                                    _ => false,
                                }
                            }
                            // Standalone transport tests may not install a
                            // shared relay slot; without that owner there is
                            // no incarnation claim to compare.
                            None => true,
                        }
                    } else {
                        true
                    };
                    if !relay_ingress_is_current {
                        if let Some(feed) = evidence.as_ref() {
                            if let Some(timeline) = feed.timeline.as_ref() {
                                timeline.emit(
                                    "stale_relay_transport_packet",
                                    Some("relay"),
                                    Some("relay_transport_replaced"),
                                    Some(format!(
                                        "peer={} packet_connection_id={relay_connection_id:?}",
                                        inbound.peer_id
                                    )),
                                );
                            }
                        }
                        debug!(
                            peer_id = %inbound.peer_id,
                            relay_endpoint = ?relay_endpoint,
                            relay_connection_id = ?relay_connection_id,
                            "dropping encrypted relay packet from a superseded transport incarnation"
                        );
                        continue;
                    }
                    if let (Some(relay_endpoint), Some(peer_manager)) =
                        (relay_endpoint.as_deref(), peers.as_ref())
                    {
                        let generation = packet_network_generation
                            .unwrap_or_else(|| peer_manager.current_network_generation_sync());
                        // A relay frame can decrypt successfully just before
                        // a rekey publishes a replacement session.  Keep the
                        // old packet deliverable during receive overlap, but
                        // do not let it recreate the new generation's
                        // relay-ready milestone.
                        let session_guard = self
                            .acquire_current_session_evidence_guard(
                                &inbound.peer_id,
                                inbound.session_instance,
                            )
                            .await;
                        let session_current =
                            inbound.session_instance.is_none() || session_guard.is_some();
                        if session_current {
                            peer_manager
                                .mark_relay_transport_ready_with_transport(
                                    &inbound.peer_id,
                                    relay_endpoint,
                                    generation,
                                    relay_connection_id,
                                )
                                .await;
                        }
                        let business_ingress_session_current = session_current;
                        drop(session_guard);
                        // A real encrypted overlay packet arriving through
                        // the current relay is itself an end-to-end relay
                        // proof.  It is legal for it to win the race against
                        // the forced path-probe ACK; waiting for the ACK in
                        // that case used to reject the packet as
                        // `first_relay_before_peer_confirmation`, lose the
                        // only WireGuard delivery evidence to replay
                        // protection, and leave the generation without a
                        // first-usable path.  Promote the relay confirmation
                        // from this business ingress before the evidence
                        // markers below are committed.  Direct remains
                        // independently gated by encrypted Direct validation
                        // and the bidirectional relay-business exchange.
                        if business_ingress_session_current
                            && session_evidence_eligible
                            && is_real_overlay_business_packet(&inbound.packet)
                        {
                            peer_manager
                                .confirm_relay_peer_from_business_ingress(
                                    &inbound.peer_id,
                                    relay_endpoint,
                                    generation,
                                    relay_connection_id,
                                )
                                .await;
                        }
                    }
                    // A decrypted relay datagram keeps the relay health
                    // bookkeeping fresh below, but it does NOT set
                    // RelayPeerConfirmed: per the relay-first contract that
                    // milestone is only reached by a matching forced-relay
                    // probe ACK whose real ingress was relay.  A local
                    // TCP/TLS connect or a command-queue accept is never
                    // delivery.
                    let internal_rekey_confirmation = is_rekey_confirmation_packet(&inbound.packet);
                    let direct_validation = parse_direct_validation_token(&inbound.packet);
                    let relay_probe = crate::relay_probe::parse_relay_probe_token(&inbound.packet);
                    let path_commit = crate::path_commit::parse_path_commit_token(&inbound.packet);
                    if session_evidence_eligible {
                        if let Some(peers) = peers.as_ref() {
                            // Forced-relay path-probe / path-ack: consumed here and
                            // never forwarded to TUN.  Only a probe that ACTUALLY
                            // arrived over the relay may confirm the relay path (or
                            // be answered over it); a probe that somehow decrypted
                            // on a non-relay ingress is ignored.
                            if let Some(token) = relay_probe {
                                if relay_endpoint.is_some() {
                                    let token_kind = token.kind;
                                    // ACK consumption changes relay path state,
                                    // so keep the emit guard through the
                                    // manager commit. A request only sends an
                                    // idempotent response; its handler must
                                    // acquire the emit lock itself, therefore
                                    // it uses a final check without retaining
                                    // the guard here.
                                    let session_guard =
                                        if token_kind == crate::relay_probe::RelayProbeKind::Ack {
                                            self.acquire_current_session_evidence_guard(
                                                &inbound.peer_id,
                                                inbound.session_instance,
                                            )
                                            .await
                                        } else {
                                            None
                                        };
                                    let session_current = if inbound.session_instance.is_none() {
                                        true
                                    } else if token_kind == crate::relay_probe::RelayProbeKind::Ack
                                    {
                                        session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    if session_current {
                                        self.handle_relay_probe_packet(
                                            peers,
                                            evidence.as_ref().map(|feed| &feed.relay_transport),
                                            RelayProbeIngress {
                                                peer_id: &inbound.peer_id,
                                                packet: &inbound.packet,
                                                relay_endpoint: relay_endpoint
                                                    .as_deref()
                                                    .unwrap_or("unknown"),
                                                relay_connection_id,
                                                token,
                                            },
                                        )
                                        .await;
                                    } else {
                                        peers.emit_timeline(
                                            "stale_session_evidence",
                                            Some("relay"),
                                            Some("session_replaced_or_removed"),
                                            Some(format!(
                                                "peer={} session_instance={:?} relay_probe={:?}",
                                                inbound.peer_id,
                                                inbound.session_instance,
                                                token_kind,
                                            )),
                                        );
                                    }
                                    drop(session_guard);
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        "ignored relay probe {} that arrived without relay ingress",
                                        if token.kind == crate::relay_probe::RelayProbeKind::Ack {
                                            "ack"
                                        } else {
                                            "request"
                                        }
                                    );
                                }
                            }
                            // Synthetic path-commit probe/ack: a business-shaped
                            // authenticated packet round-tripped over the confirmed
                            // relay.  A matching ack closes the relay-first
                            // business gate for one-directional traffic (P0-4);
                            // a request is answered idempotently, exactly like the
                            // relay path-probe.
                            if let Some(path_token) = path_commit {
                                if relay_endpoint.is_some() {
                                    let path_kind = path_token.kind;
                                    let path_session_guard =
                                        if path_kind == crate::path_commit::PathCommitKind::Ack {
                                            self.acquire_current_session_evidence_guard(
                                                &inbound.peer_id,
                                                inbound.session_instance,
                                            )
                                            .await
                                        } else {
                                            None
                                        };
                                    let path_session_current = if inbound.session_instance.is_none()
                                    {
                                        true
                                    } else if path_kind == crate::path_commit::PathCommitKind::Ack {
                                        path_session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    if path_session_current {
                                        self.handle_path_commit_packet(
                                            peers,
                                            evidence.as_ref().map(|feed| &feed.relay_transport),
                                            PathCommitIngress {
                                                peer_id: &inbound.peer_id,
                                                packet: &inbound.packet,
                                                relay_endpoint: relay_endpoint
                                                    .as_deref()
                                                    .unwrap_or("unknown"),
                                                relay_connection_id,
                                                token: path_token,
                                            },
                                        )
                                        .await;
                                    }
                                    drop(path_session_guard);
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        "ignored path-commit packet that arrived without relay ingress"
                                    );
                                }
                            }
                            let binding_guard = self
                                .acquire_current_session_evidence_guard(
                                    &inbound.peer_id,
                                    inbound.session_instance,
                                )
                                .await;
                            let binding_session_current =
                                inbound.session_instance.is_none() || binding_guard.is_some();
                            if binding_session_current {
                                let promoted_tokens = self
                                    .pending_promoted_responder_tokens(&inbound.peer_id)
                                    .await;
                                for token in promoted_tokens {
                                    if peers
                                        .confirm_pending_probe_session_binding(
                                            &inbound.peer_id,
                                            &token,
                                        )
                                        .await
                                    {
                                        self.acknowledge_promoted_responder_token(
                                            &inbound.peer_id,
                                            &token,
                                        )
                                        .await;
                                        debug!(
                                        "Promoted Probe v2 binding for peer {} after WireGuard rekey confirmation",
                                        inbound.peer_id
                                    );
                                    }
                                }
                            } else {
                                peers.emit_timeline(
                                    "stale_session_evidence",
                                    Some("relay"),
                                    Some("session_replaced_or_removed"),
                                    Some(format!(
                                        "peer={} session_instance={:?} responder_binding=stale",
                                        inbound.peer_id, inbound.session_instance,
                                    )),
                                );
                            }
                            drop(binding_guard);
                            if let Some(token) = direct_validation {
                                // Daemon-internal direct-validation packets are
                                // consumed here and never forwarded to TUN: the
                                // request/ACK protocol proves the direct UDP path
                                // with the WireGuard session alone, without an OS
                                // ICMP echo reply or user traffic.
                                if owns_direct_packet {
                                    let token_kind = token.kind;
                                    // Snapshot the peer lifecycle before the
                                    // transport-session check awaits.  A
                                    // same-ID remove/re-add after this point
                                    // must not let the old authenticated
                                    // request enqueue work for the replacement
                                    // peer incarnation.
                                    let peer_session_generation =
                                        peers.peer_session_generation_sync(&inbound.peer_id);
                                    let session_guard = if token_kind == DirectValidationKind::Ack {
                                        self.acquire_current_session_evidence_guard(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    } else {
                                        None
                                    };
                                    let session_current = if inbound.session_instance.is_none() {
                                        true
                                    } else if token_kind == DirectValidationKind::Ack {
                                        session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    if let (true, Some(peer_session_generation)) =
                                        (session_current, peer_session_generation)
                                    {
                                        self.handle_direct_validation_packet(
                                            peers,
                                            udp.as_ref(),
                                            &inbound.peer_id,
                                            &inbound.packet,
                                            source,
                                            local_endpoint,
                                            socket_index,
                                            direct_socket,
                                            peer_session_generation,
                                            token,
                                        )
                                        .await;
                                    } else {
                                        peers.emit_timeline(
                                            "stale_session_evidence",
                                            Some("direct"),
                                            Some("session_replaced_or_removed"),
                                            Some(format!(
                                                "peer={} session_instance={:?} direct_validation={:?}",
                                                inbound.peer_id,
                                                inbound.session_instance,
                                                token_kind,
                                            )),
                                        );
                                    }
                                    drop(session_guard);
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        packet_owner = ?udp_transport_owner,
                                        "ignored direct-validation packet from retired or unpublished UDP transport"
                                    );
                                }
                            } else if internal_rekey_confirmation {
                                debug!(
                                "Consumed internal WireGuard rekey confirmation from peer {} without changing path health",
                                inbound.peer_id
                            );
                            } else if let Some(source) = source {
                                let session_guard = self
                                    .acquire_current_session_evidence_guard(
                                        &inbound.peer_id,
                                        inbound.session_instance,
                                    )
                                    .await;
                                let session_current =
                                    inbound.session_instance.is_none() || session_guard.is_some();
                                if !session_current {
                                    peers.emit_timeline(
                                        "stale_session_evidence",
                                        Some("direct"),
                                        Some("session_replaced_or_removed"),
                                        Some(format!(
                                            "peer={} session_instance={:?} direct_ingress=stale",
                                            inbound.peer_id, inbound.session_instance,
                                        )),
                                    );
                                } else if !owns_direct_packet {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        packet_owner = ?udp_transport_owner,
                                        "forwarding decrypted data from retired or unpublished UDP transport without Direct evidence"
                                    );
                                } else {
                                    peers
                                        .learn_authenticated_endpoint(&inbound.peer_id, source)
                                        .await;
                                    // A decrypted UDP payload is authenticated
                                    // endpoint evidence, not a Direct proof.  Feed
                                    // it into the same owned request/ACK worker as
                                    // peer-reflexive evidence; do not adopt socket
                                    // affinity or promote from this path alone.
                                    if let Some(udp) = udp.as_ref() {
                                        let generation =
                                            packet_network_generation.unwrap_or_else(|| {
                                                peers.current_network_generation_sync()
                                            });
                                        peers
                                        .record_direct_event_for_generation_with_socket(
                                            &inbound.peer_id,
                                            generation,
                                            "direct_validation_ingress_requested",
                                            Some(source),
                                            socket_index,
                                            None,
                                            None,
                                            "decrypted direct UDP payload requested owned encrypted validation",
                                        )
                                        .await;
                                        if let Some(socket_index) = socket_index {
                                            // Decryption is sufficient to remember
                                            // the receiving socket as evidence for
                                            // the next owned validation request,
                                            // but not to promote the path.
                                            udp.remember_peer_socket(
                                                &inbound.peer_id,
                                                socket_index,
                                                crate::udp::SocketEvidence::Fresh,
                                            )
                                            .await;
                                        }
                                        udp.enqueue_direct_validation_observation(
                                            crate::udp::PeerReflexiveObservation {
                                                peer_id: inbound.peer_id.clone(),
                                                observed_endpoint: source,
                                            },
                                        );
                                    }
                                    debug!(
                                        "Confirmed direct UDP data path from {source} for peer {}",
                                        inbound.peer_id
                                    );
                                }
                                drop(session_guard);
                            } else if let Some(relay_endpoint) = relay_endpoint.as_deref() {
                                let session_guard = self
                                    .acquire_current_session_evidence_guard(
                                        &inbound.peer_id,
                                        inbound.session_instance,
                                    )
                                    .await;
                                let session_current =
                                    inbound.session_instance.is_none() || session_guard.is_some();
                                if session_current {
                                    // Every authenticated relay packet is a
                                    // liveness observation.  RTT is committed
                                    // only by the matching relay-probe ACK,
                                    // whose process-local Instant is bound to
                                    // the actual relay handoff.  The legacy
                                    // wall-clock validation payload remains
                                    // recognizable for wire compatibility but
                                    // is never interpreted as a timing sample.
                                    peers
                                        .record_relay_observation(&inbound.peer_id, relay_endpoint)
                                        .await;
                                    debug!(
                                    "Observed decrypted relay ingress through {relay_endpoint} for peer {}; relay confirmation still requires a matching encrypted ACK",
                                    inbound.peer_id
                                );
                                } else {
                                    peers.emit_timeline(
                                        "stale_session_evidence",
                                        Some("relay"),
                                        Some("session_replaced_or_removed"),
                                        Some(format!(
                                            "peer={} session_instance={:?} relay_observation=stale",
                                            inbound.peer_id, inbound.session_instance,
                                        )),
                                    );
                                }
                                drop(session_guard);
                            }
                        }
                    }
                    if internal_rekey_confirmation
                        || direct_validation.is_some()
                        || relay_probe.is_some()
                        || path_commit.is_some()
                    {
                        continue;
                    }
                    // A normal decrypted packet is the production ingress
                    // proof. The mock overlay validator adds a stronger
                    // nonce/echo check, but production must not depend on
                    // that harness to ever emit first_usable. The ingress is
                    // taken from this packet's envelope and never inferred
                    // from the current selected path.
                    if session_evidence_eligible && is_real_overlay_business_packet(&inbound.packet)
                    {
                        if let Some(feed) = evidence.as_ref() {
                            let ingress = if let Some(relay_endpoint) = relay_endpoint.as_ref() {
                                Some((
                                    crate::peer::NetworkPath::Relay,
                                    format!("relay:{relay_endpoint}"),
                                    Some(relay_endpoint.as_str()),
                                ))
                            } else if owns_direct_packet && source.is_some() {
                                Some((crate::peer::NetworkPath::Direct, "direct".to_string(), None))
                            } else {
                                None
                            };
                            if let (Some(peer_manager), Some((path, ingress_label, relay_id))) =
                                (peers.as_ref(), ingress)
                            {
                                // The packet was decrypted before this point,
                                // but path evidence is a separate commit. Hold
                                // the same per-peer lifecycle fence through
                                // both relay-business and first-usable writes
                                // so a rekey cannot turn an old-session packet
                                // into evidence for the new session.
                                let session_guard = self
                                    .acquire_current_session_evidence_guard(
                                        &inbound.peer_id,
                                        inbound.session_instance,
                                    )
                                    .await;
                                let session_current =
                                    inbound.session_instance.is_none() || session_guard.is_some();
                                if session_current {
                                    let generation =
                                        packet_network_generation.unwrap_or_else(|| {
                                            peer_manager.current_network_generation_sync()
                                        });
                                    if path == crate::peer::NetworkPath::Relay {
                                        peer_manager
                                            .mark_relay_first_business_received_for_generation_with_transport(
                                                &inbound.peer_id,
                                                relay_id.unwrap_or("unknown"),
                                                generation,
                                                relay_connection_id,
                                            )
                                            .await;
                                    }
                                    let first_usable_recorded = peer_manager
                                        .record_verified_first_usable(
                                            &inbound.peer_id,
                                            generation,
                                            path,
                                            &ingress_label,
                                        )
                                        .await;
                                    // This is an ingress observation, not the
                                    // same milestone as first_usable_path.
                                    // Keep the first ingress event for backwards
                                    // compatibility, and also retain one event
                                    // for each meaningful path/transport/result
                                    // identity.  If a too-early Direct packet
                                    // is rejected and a later Relay packet is
                                    // accepted, the second event must remain
                                    // visible; a single first-event key would
                                    // otherwise hide the actual relay proof.
                                    if let Some(timeline) = feed.timeline.as_ref() {
                                        let scope =
                                            format!("peer:{}:{generation}", inbound.peer_id);
                                        let path_label = match path {
                                            crate::peer::NetworkPath::Relay => "relay",
                                            crate::peer::NetworkPath::Direct => "direct",
                                        };
                                        let first_usable_result = if first_usable_recorded {
                                            "first_usable_recorded"
                                        } else {
                                            "first_usable_not_recorded"
                                        };
                                        let relay_transport_key = relay_connection_id.map_or_else(
                                            || "none".to_string(),
                                            |id| id.to_string(),
                                        );
                                        let packet_identity = Ipv4Packet::new(&inbound.packet)
                                            .map(|packet| {
                                                format!(
                                                    "protocol={} src={} dst={}",
                                                    packet.protocol(),
                                                    packet.src_addr(),
                                                    packet.dst_addr(),
                                                )
                                            })
                                            .unwrap_or_else(|_| {
                                                "protocol=unknown src=unknown dst=unknown"
                                                    .to_string()
                                            });
                                        let detail = format!(
                                            "peer={} generation={generation} path_id={} relay_id={} relay_connection_id={} counter={} bytes={} {} overlay_fp={:016x} usable_recorded={first_usable_recorded}",
                                            inbound.peer_id,
                                            ingress_label,
                                            relay_id.unwrap_or("none"),
                                            relay_transport_key,
                                            wire_counter(&packet.wire_bytes).map_or_else(
                                                || "none".to_string(),
                                                |counter| counter.to_string(),
                                            ),
                                            inbound.packet.len(),
                                            packet_identity,
                                            wire_fingerprint(&inbound.packet),
                                        );
                                        timeline.emit_first_scoped_with_key(
                                            &scope,
                                            &format!(
                                                "path={path_label} relay_connection_id={relay_transport_key} usable={first_usable_recorded}"
                                            ),
                                            "business_ingress_observed",
                                            Some(path_label),
                                            Some(first_usable_result),
                                            Some(detail.clone()),
                                        );
                                        timeline.emit_first_scoped(
                                            &scope,
                                            "first_real_business_ingress",
                                            Some(path_label),
                                            (!first_usable_recorded)
                                                .then_some("first_usable_gate_rejected"),
                                            Some(detail),
                                        );
                                    }
                                } else if let Some(timeline) = feed.timeline.as_ref() {
                                    timeline.emit(
                                        "stale_session_evidence",
                                        Some(match path {
                                            crate::peer::NetworkPath::Relay => "relay",
                                            crate::peer::NetworkPath::Direct => "direct",
                                        }),
                                        Some("session_replaced_or_removed"),
                                        Some(format!(
                                            "peer={} session_instance={:?} business_ingress=stale",
                                            inbound.peer_id, inbound.session_instance,
                                        )),
                                    );
                                }
                                drop(session_guard);
                            }
                        }
                    }
                    // Forward a decrypted overlay candidate to the independent
                    // overlay validation harness WITH its real ingress (derived
                    // from this envelope, never from the active path).
                    if session_evidence_eligible {
                        if let Some(feed) = evidence.as_ref() {
                            if is_overlay_payload_candidate(&inbound.packet) {
                                let ingress = if let Some(relay_endpoint) = relay_endpoint.as_ref()
                                {
                                    Some(OverlayIngress::Relay(relay_endpoint.clone()))
                                } else if owns_direct_packet && source.is_some() {
                                    Some(OverlayIngress::Direct)
                                } else {
                                    // No attributable ingress (relay nor owned
                                    // direct): do not guess.
                                    None
                                };
                                if let Some(ingress) = ingress {
                                    if let Some(tx) = &feed.overlay_ingress_tx {
                                        let connection_generation = packet_network_generation
                                            .or_else(|| {
                                                peers.as_ref().map(|manager| {
                                                    manager.current_network_generation_sync()
                                                })
                                            })
                                            .unwrap_or_default();
                                        let _ = tx
                                            .send(OverlayIngressEvent {
                                                peer_id: inbound.peer_id.clone(),
                                                packet: inbound.packet.clone(),
                                                ingress,
                                                connection_generation,
                                            })
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                    let validation_completed = Instant::now();
                    profiler.record(
                        sampled,
                        "rx_generation_session_validation_us",
                        validation_completed.duration_since(decrypt_completed),
                    );
                    if let Some(trace) = inbound.trace.as_mut() {
                        trace.inbound_queue_send_started = Some(Instant::now());
                        profiler.record_value(
                            trace.sampled,
                            "rx_dataplane_inbound_queue_depth_before_send",
                            inbound_tx
                                .max_capacity()
                                .saturating_sub(inbound_tx.capacity())
                                as u64,
                        );
                    }
                    inbound_tx.send(inbound).await.map_err(|_| {
                        DaemonError::Network("inbound packet channel closed".to_string())
                    })?;
                }
                Ok(None) => {
                    debug!("Inbound encrypted packet has no matching WireGuard session");
                }
                Err(err) => {
                    let classified = err.to_string();
                    if is_replay_decrypt_error(&classified) {
                        // The per-peer hedge-duplicate counter was already
                        // attributed and logged rate-limited inside
                        // `decrypt_inbound`; per-datagram WARNs would only
                        // recreate the storm this classification removes.
                        debug!("Dropping inbound encrypted packet from {:?}: {err}", source);
                    } else {
                        warn!("Dropping inbound encrypted packet from {:?}: {err}", source);
                    }
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    /// Handle one daemon-internal direct-validation packet after successful
    /// WireGuard decryption.
    ///
    /// Request (responder role): the initiator's encrypted request reached us
    /// through the direct UDP path.  It is validation ingress evidence only:
    /// record it, enqueue the local worker and return an idempotent ACK.  The
    /// request itself never promotes Direct or adopts socket affinity.
    ///
    /// ACK (initiator role): the peer answers our outstanding validation
    /// request.  The ACK is only trusted when its token matches the
    /// expectation the validation task registered (request id AND network
    /// generation): a stale request can never confirm a new session.  On a
    /// match the initiator promotes to Direct and consumes the expectation, so
    /// duplicate or late ACKs are no-ops.
    async fn handle_direct_validation_packet(
        &self,
        peers: &Arc<PeerManager>,
        udp: Option<&crate::udp::UdpTransport>,
        peer_id: &str,
        packet: &[u8],
        source: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        direct_socket: Option<Arc<tokio::net::UdpSocket>>,
        peer_session_generation: PeerSessionGeneration,
        token: crate::transport::DirectValidationToken,
    ) {
        match token.kind {
            crate::transport::DirectValidationKind::Request => {
                let Some(source) = source else {
                    let generation = peers.current_network_generation().await;
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            generation,
                            crate::peer::DirectValidationEventMetadata {
                                remote_validation_owner: Some(token.owner_token),
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_request_dropped",
                            None,
                            socket_index,
                            None,
                            Some(0),
                            format!(
                                "reason_code=direct_validation_request_missing_source remote_generation={} local_generation={} request_id={} seq={}",
                                token.generation, generation, token.request_id, token.sequence
                            ),
                        )
                        .await;
                    return;
                };
                let Some(udp) = udp else {
                    // A direct-validation request without the owning UDP
                    // transport cannot be serialized with peer lifecycle
                    // cleanup or safely answered on the receiving socket.
                    let generation = peers.current_network_generation().await;
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            generation,
                            crate::peer::DirectValidationEventMetadata {
                                remote_validation_owner: Some(token.owner_token),
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_request_dropped",
                            Some(source),
                            socket_index,
                            None,
                            Some(0),
                            format!(
                                "reason_code=direct_validation_udp_transport_unavailable remote_generation={} local_generation={} request_id={} seq={}",
                                token.generation, generation, token.request_id, token.sequence
                            ),
                        )
                        .await;
                    return;
                };
                // No REMOTE network-generation comparison here: network
                // generations are PER-SIDE
                // counters (each daemon advances its own on candidate
                // refreshes), so the initiator's generation can never be
                // compared with the responder's.  The request is already
                // authenticated — it decrypted under the peer's current
                // WireGuard session — and the ACK's token is strictly
                // verified against the initiator's own expectation, which is
                // the real security boundary.  A stale request can only
                // trigger a benign idempotent ACK.

                // The request is authenticated (decrypted under the peer's
                // WireGuard session) and arrived over the direct path. Make
                // its validation ingress one transaction with PeerLeft/key
                // cleanup: adoption -> network epoch -> lifecycle re-check ->
                // generation snapshot -> scheduler enqueue.
                // The token generation is remote-local and therefore cannot
                // be compared with `local_generation`; it is echoed only for
                // the initiator's owned ACK expectation.
                // Revalidate the local peer lifecycle at the same
                // adoption -> network-epoch boundary used by lifecycle
                // cleanup.  The outer transport-session check deliberately
                // released its emit guard so this request can later acquire
                // that guard to encrypt its ACK without self-deadlocking.
                let adoption_guard = udp.lock_peer_adoption_for_direct_validation(peer_id).await;
                let epoch_gate = peers.network_epoch_gate();
                let epoch_guard = epoch_gate.lock().await;
                if !peers.peer_session_is_current_sync(peer_id, peer_session_generation) {
                    drop(epoch_guard);
                    drop(adoption_guard);
                    peers.emit_timeline(
                        "stale_session_evidence",
                        Some("direct"),
                        Some("peer_lifecycle_replaced_or_removed"),
                        Some(format!(
                            "peer={peer_id} direct_validation={:?} request_id={}",
                            token.kind, token.request_id,
                        )),
                    );
                    return;
                }

                // An authenticated request is evidence for the local
                // validation worker, not proof of the local path. Enqueue it
                // newest-wins and let the worker send our own request. This
                // keeps an inbound request from cancelling the local
                // request/ACK transaction in the R7/R8 cross-over race.
                let local_generation = peers.current_network_generation_sync();

                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        local_generation,
                        crate::peer::DirectValidationEventMetadata {
                            remote_validation_owner: Some(token.owner_token),
                            request_id: Some(token.request_id),
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_request_received",
                        Some(source),
                        socket_index,
                        None,
                        Some(0),
                        format!(
                            "received authenticated encrypted validation request remote_generation={} local_generation={} request_id={} seq={}",
                            token.generation,
                            local_generation,
                            token.request_id,
                            token.sequence,
                        ),
                    )
                    .await;
                udp.enqueue_direct_validation_observation(crate::udp::PeerReflexiveObservation {
                    peer_id: peer_id.to_string(),
                    observed_endpoint: source,
                });
                // ACK encryption takes the per-peer WireGuard emit guard.
                // Release the UDP lifecycle transaction first to preserve the
                // canonical emit -> adoption -> epoch order used by teardown
                // and ACK evidence commits.
                drop(epoch_guard);
                drop(adoption_guard);
                info!(
                    event = "direct_validation_request_received",
                    peer_id = %peer_id,
                    remote_endpoint = %source,
                    request_id = token.request_id,
                    "received authenticated encrypted validation request request_id={}",
                    token.request_id
                );
                // Answer idempotently — also when already Direct — so the
                // initiator always gets the confirmation it needs.  The ACK
                // uses the request's own IP header with source/destination
                // swapped: no virtual IP state required.
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            local_generation,
                            crate::peer::DirectValidationEventMetadata {
                                remote_validation_owner: Some(token.owner_token),
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_send_failed",
                            Some(source),
                            socket_index,
                            None,
                            Some(0),
                            format!(
                                "reason_code=direct_validation_request_invalid_ipv4 request_id={} seq={}",
                                token.request_id, token.sequence
                            ),
                        )
                        .await;
                    return;
                };
                let ack_payload = crate::transport::build_direct_validation_payload(
                    crate::transport::DirectValidationKind::Ack,
                    token.generation,
                    token.request_id,
                    token.sequence,
                    token.owner_token,
                );
                let ack_packet = Ipv4Packet::build_icmp_echo_request(
                    ip.dst_addr(),
                    ip.src_addr(),
                    token.request_id,
                    u16::from(token.sequence),
                    &ack_payload,
                );
                let send_udp = udp.clone();
                let peer_id_owned = peer_id.to_string();
                let receive_socket_index = socket_index;
                let receive_socket = direct_socket;
                match self
                    .encrypt_and_emit_outbound_with_lock_timeout(
                        OutboundPacket {
                            peer_id: peer_id_owned.clone(),
                            dst_ip: ip.src_addr().to_string(),
                            packet: ack_packet,
                            trace: None,
                        },
                        DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT,
                        move |encrypted| async move {
                            let Some(receive_socket_index) = receive_socket_index else {
                                return Err(crate::error::DaemonError::Network(
                                    "direct validation request had no receiving UDP socket index"
                                        .to_string(),
                                ));
                            };
                            if let Some(receive_socket) = receive_socket {
                                send_udp
                                    .send_encrypted_packet_on_socket(
                                        &receive_socket,
                                        receive_socket_index,
                                        &encrypted,
                                        source,
                                    )
                                    .await
                                    .map(|_| ())
                            } else {
                                send_udp
                                    .send_packet_on_socket_index(
                                        &encrypted,
                                        receive_socket_index,
                                        source,
                                    )
                                    .await
                                    .map(|_| ())
                            }
                        },
                    )
                    .await
                {
                    Ok(BoundedEmitOutcome::Sent) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_sent",
                                Some(source),
                                socket_index,
                                None,
                                Some(1),
                                format!(
                                    "sent encrypted validation ACK request_id={} seq={}",
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        info!(
                            event = "direct_validation_ack_sent",
                            peer_id = %peer_id,
                            remote_endpoint = %source,
                            request_id = token.request_id,
                            "sent encrypted validation ACK request_id={} seq={}",
                            token.request_id,
                            token.sequence
                        );
                        debug!(
                            "Answered direct-validation request from peer {peer_id_owned} at {source} with an ACK"
                        );
                    }
                    Ok(BoundedEmitOutcome::LockTimeout) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_send_failed",
                                Some(source),
                                socket_index,
                                None,
                                Some(0),
                                format!(
                                    "reason_code=direct_validation_ack_emit_lock_timeout lock_timeout_ms={} request_id={} seq={}; ACK was not encrypted or sent",
                                    DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis(),
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        debug!(
                            "Could not answer direct-validation request from {peer_id_owned}: outbound emit lock timed out after {}ms",
                            DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis()
                        );
                    }
                    Ok(BoundedEmitOutcome::SessionUnavailable) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_send_failed",
                                Some(source),
                                socket_index,
                                None,
                                Some(0),
                                format!(
                                    "reason_code=direct_validation_ack_session_unavailable request_id={} seq={}",
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        debug!(
                            "Could not answer direct-validation request from {peer_id_owned}: WireGuard session is no longer ready"
                        );
                    }
                    Err(err) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_send_failed",
                                Some(source),
                                socket_index,
                                None,
                                Some(0),
                                format!(
                                    "failed to send ACK for request_id={} seq={}: {err}",
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        debug!(
                            "Failed to answer direct-validation request from {peer_id_owned} at {source}: {err}"
                        );
                    }
                }
            }
            crate::transport::DirectValidationKind::Ack => {
                let Some(udp) = udp else {
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            peers.current_network_generation().await,
                            crate::peer::DirectValidationEventMetadata {
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_unmatched",
                            source,
                            socket_index,
                            None,
                            None,
                            format!(
                                "reason_code=direct_validation_ack_udp_transport_unavailable request_id={} token_generation={}",
                                token.request_id, token.generation
                            ),
                        )
                        .await;
                    return;
                };
                let Some(source) = source else {
                    // An ACK without a direct UDP source cannot establish a
                    // path.  Keep the owned expectation alive for a real ACK
                    // rather than consuming it merely because the packet
                    // decrypted through a non-UDP transport.
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            peers.current_network_generation().await,
                            crate::peer::DirectValidationEventMetadata {
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_unmatched",
                            None,
                            socket_index,
                            None,
                            None,
                            format!(
                                "reason_code=direct_validation_ack_missing_source request_id={} token_generation={}",
                                token.request_id, token.generation
                            ),
                        )
                        .await;
                    return;
                };
                // Serialize this encrypted ACK transaction with PeerLeft /
                // identity cleanup before taking the shared epoch gate. The
                // UDP lifecycle uses the same per-peer lock, so it cannot
                // remove a peer between token consumption and Direct/affinity
                // adoption.
                let adoption_guard = udp.lock_peer_adoption_for_direct_validation(peer_id).await;
                // Only an ACK matching the outstanding request token (request
                // id, generation AND validation-session owner) confirms the
                // path.
                // The epoch transaction below additionally proves the
                // expectation owner is still active and that the local
                // network generation has not advanced.  A stale ACK can
                // therefore neither promote Direct nor adopt socket affinity.
                let epoch_gate = peers.network_epoch_gate();
                let epoch_guard = epoch_gate.lock().await;
                let current_generation = peers.current_network_generation_sync();
                let endpoint_authenticated = udp
                    .is_authenticated_direct_endpoint(peer_id, source, current_generation)
                    .await;
                let expectation = match udp
                    .consume_direct_validation_ack(
                        peer_id,
                        token.request_id,
                        token.generation,
                        token.owner_token,
                        current_generation,
                        source,
                        socket_index,
                        endpoint_authenticated,
                    )
                    .await
                {
                    Ok(expectation) => expectation,
                    Err(rejection) => {
                        let reason_code = rejection.reason_code();
                        debug!(
                            event = "direct_validation_ack_unmatched",
                            peer_id = %peer_id,
                            remote_endpoint = %source,
                            request_id = token.request_id,
                            token_generation = token.generation,
                            current_generation,
                            socket_index = ?socket_index,
                            endpoint_authenticated,
                            reason_code,
                            "direct-validation ACK rejected before promotion"
                        );
                        peers
                            .record_direct_event_for_generation_with_socket(
                                peer_id,
                                current_generation,
                                "direct_validation_ack_unmatched",
                                Some(source),
                                socket_index,
                                None,
                                None,
                                format!(
                                    "reason_code={reason_code} request_id={} token_generation={} current_generation={} socket_index={} endpoint_authenticated={endpoint_authenticated}",
                                    token.request_id,
                                    token.generation,
                                    current_generation,
                                    socket_index.map_or_else(
                                        || "none".to_string(),
                                        |index| index.to_string()
                                    ),
                                ),
                            )
                            .await;
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                current_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    request_id: Some(token.request_id),
                                    observed_ack_endpoint: Some(source),
                                    ack_endpoint_authenticated: Some(endpoint_authenticated),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_unmatched",
                                Some(source),
                                socket_index,
                                None,
                                None,
                                format!(
                                    "reason_code={reason_code} rejected encrypted validation ACK request_id={} token_generation={} current_generation={} socket_index={}",
                                    token.request_id,
                                    token.generation,
                                    current_generation,
                                    socket_index.map_or_else(
                                        || "none".to_string(),
                                        |index| index.to_string()
                                    ),
                                ),
                            )
                            .await;
                        return;
                    }
                };

                let validation_latency = expectation.sent_at.map(|sent_at| sent_at.elapsed());
                let validation_rtt_ms =
                    validation_latency.map(|latency| latency.as_millis() as u64);

                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        expectation.generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(expectation.owner_token),
                            request_id: Some(token.request_id),
                            expected_endpoint: expectation.endpoint,
                            observed_ack_endpoint: Some(source),
                            ack_endpoint_authenticated: Some(endpoint_authenticated),
                            validation_rtt_ms,
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_ack_received",
                        Some(source),
                        socket_index,
                        None,
                        Some(1),
                        format!(
                            "consumed encrypted validation ACK request_id={} generation={} socket_index={} expected_endpoint={} observed_endpoint={} authenticated_endpoint_drift={}",
                            token.request_id,
                            expectation.generation,
                            socket_index
                                .map_or_else(|| "none".to_string(), |index| index.to_string()),
                            expectation
                                .endpoint
                                .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            source,
                            expectation.endpoint != Some(source),
                        ),
                    )
                    .await;
                info!(
                    event = "direct_validation_ack_received",
                    peer_id = %peer_id,
                    remote_endpoint = %source,
                    request_id = token.request_id,
                    generation = expectation.generation,
                    validation_rtt_ms = ?expectation
                        .sent_at
                        .map(|sent_at| sent_at.elapsed().as_millis() as u64),
                    "consumed encrypted validation ACK request_id={}",
                    token.request_id
                );

                // Do not re-read the generation here.  The consumed
                // expectation is the proof that this exact generation and
                // owner initiated the request, and the promotion remains
                // inside the epoch guard that made the check atomic.
                let promoted = peers
                    .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
                        &epoch_guard,
                        peer_id,
                        Some(source),
                        expectation.generation,
                        local_endpoint,
                        validation_latency,
                        Some(expectation.remote_candidate_epoch),
                    )
                    .await;
                let affinity_adopted = if promoted {
                    match socket_index {
                        Some(socket_index) => {
                            udp.remember_peer_socket_for_generation_in_epoch(
                                &epoch_guard,
                                peer_id,
                                socket_index,
                                expectation.generation,
                                crate::udp::SocketEvidence::Fresh,
                            )
                            .await
                        }
                        None => false,
                    }
                } else {
                    false
                };

                // A slow encrypted ACK is still useful evidence that the
                // candidate can reach the peer, but it is not a reason to
                // keep starting new validation owners while the confirmed
                // relay is healthy. The candidate-level quarantine in the
                // peer manager cannot cover peer-reflexive endpoint churn, so
                // retain a peer/generation cooldown in the shared UDP
                // validation registry before the current owner is finished.
                let slow_relay_retained = !promoted
                    && validation_latency.is_some_and(|latency| {
                        latency.as_millis() as u64
                            >= crate::peer::SLOW_DIRECT_RELAY_VALIDATION_RTT_MS
                    })
                    && peers
                        .is_relay_peer_confirmed_for_generation(peer_id, expectation.generation)
                        .await
                    && !peers
                        .is_direct_for_generation(peer_id, expectation.generation)
                        .await;
                if slow_relay_retained {
                    udp.suppress_direct_validation_for_slow_relay(peer_id, expectation.generation)
                        .await;
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            expectation.generation,
                            crate::peer::DirectValidationEventMetadata {
                                local_validation_session_id: Some(expectation.owner_token),
                                request_id: Some(token.request_id),
                                expected_endpoint: expectation.endpoint,
                                observed_ack_endpoint: Some(source),
                                ack_endpoint_authenticated: Some(endpoint_authenticated),
                                validation_rtt_ms,
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_suppressed",
                            Some(source),
                            socket_index,
                            None,
                            Some(1),
                            format!(
                                "reason_code=direct_validation_slow_relay_cooldown generation={} validation_rtt_ms={} relay_retained=true",
                                expectation.generation,
                                validation_rtt_ms.unwrap_or_default()
                            ),
                        )
                        .await;
                }

                // `record_direct_success...` normally revoked this owner on
                // promotion.  Keep the owner-conditional finish for a peer
                // disappearing between token consumption and promotion: it
                // can never erase a newer session installed for the same ID.
                let _ = udp
                    .finish_direct_validation_session(peer_id, expectation.owner_token)
                    .await;
                drop(epoch_guard);
                drop(adoption_guard);

                if !promoted {
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            expectation.generation,
                            crate::peer::DirectValidationEventMetadata {
                                local_validation_session_id: Some(expectation.owner_token),
                                request_id: Some(token.request_id),
                                expected_endpoint: expectation.endpoint,
                                observed_ack_endpoint: Some(source),
                                ack_endpoint_authenticated: Some(endpoint_authenticated),
                                validation_rtt_ms,
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_not_promoted",
                            Some(source),
                            socket_index,
                            None,
                            Some(1),
                            format!(
                                "reason_code=direct_validation_promotion_rejected request_id={} generation={} expected_endpoint={} observed_endpoint={} endpoint_authenticated={endpoint_authenticated}",
                                token.request_id,
                                expectation.generation,
                                expectation
                                    .endpoint
                                    .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                                source,
                            ),
                        )
                        .await;
                    debug!(
                        "Ignored direct-validation ACK from {peer_id}: owned expectation could not promote generation {}",
                        expectation.generation
                    );
                    return;
                }

                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        expectation.generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(expectation.owner_token),
                            request_id: Some(token.request_id),
                            expected_endpoint: expectation.endpoint,
                            observed_ack_endpoint: Some(source),
                            selected_endpoint: Some(source),
                            ack_endpoint_authenticated: Some(endpoint_authenticated),
                            validation_rtt_ms,
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_promoted",
                        Some(source),
                        socket_index,
                        None,
                        Some(1),
                        format!(
                            "promoted after owned request/ACK request_id={} generation={} socket_index={} expected_endpoint={} observed_endpoint={} local_endpoint={} authenticated_endpoint_drift={} affinity_adopted={affinity_adopted}",
                            token.request_id,
                            expectation.generation,
                            socket_index.map_or_else(|| "none".to_string(), |index| index.to_string()),
                            expectation
                                .endpoint
                                .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            source,
                            local_endpoint.map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            expectation.endpoint != Some(source),
                        ),
                    )
                    .await;
                info!(
                    event = "direct_validation_promoted",
                    peer_id = %peer_id,
                    remote_endpoint = %source,
                    request_id = token.request_id,
                    generation = expectation.generation,
                    "promoted after owned request/ACK request_id={}",
                    token.request_id
                );
                peers.emit_timeline(
                    "direct_promoted",
                    Some("direct"),
                    None,
                    Some(format!(
                        "peer={peer_id} endpoint={source} generation={} request_id={:?}",
                        expectation.generation, token.request_id
                    )),
                );
                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        expectation.generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(expectation.owner_token),
                            request_id: Some(token.request_id),
                            expected_endpoint: expectation.endpoint,
                            observed_ack_endpoint: Some(source),
                            selected_endpoint: Some(source),
                            ack_endpoint_authenticated: Some(endpoint_authenticated),
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_path_promoted",
                        Some(source),
                        socket_index,
                        None,
                        Some(1),
                        format!(
                            "selected endpoint after owned validation ACK request_id={} expected_endpoint={} observed_ack_endpoint={} selected_endpoint={} affinity_adopted={affinity_adopted}",
                            token.request_id,
                            expectation
                                .endpoint
                                .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            source,
                            source,
                        ),
                    )
                    .await;
                debug!(
                    "Direct UDP path confirmed for peer {peer_id} at {source} by validation ACK"
                );
            }
        }
    }

    /// Handle one forced-relay path-probe / path-ack packet after successful
    /// WireGuard decryption and a confirmed relay ingress (`relay_endpoint` is
    /// `Some` at the call site).
    ///
    /// Request (responder role): the initiator's encrypted probe reached us
    /// through the relay.  Answer idempotently over the SAME relay transport
    /// (never the path selector) with the mirrored token, so the initiator can
    /// confirm the relay path.  The request itself never changes local path
    /// state.
    ///
    /// ACK (initiator role): the peer answers our outstanding forced-relay
    /// probe.  The ACK is trusted only when its token mirrors the expectation
    /// the probe loop registered (request id AND network generation AND owner
    /// token) AND the ACK arrived over the relay.  On a match the peer manager
    /// sets RelayPeerConfirmed and consumes the expectation, so duplicate or
    /// late ACKs are no-ops.
    async fn handle_relay_probe_packet(
        &self,
        peers: &Arc<PeerManager>,
        relay_transport: Option<&Arc<RwLock<Option<RelayTransport>>>>,
        probe: RelayProbeIngress<'_>,
    ) {
        let RelayProbeIngress {
            peer_id,
            packet,
            relay_endpoint,
            relay_connection_id,
            token,
        } = probe;
        // A relay renewal can leave an old reader draining briefly after the
        // shared slot publishes its replacement.  Reject that reader before
        // either answering a request or consuming an ACK; endpoint and
        // network generation are intentionally not enough to identify the
        // current transport.
        if let Some(relay_transport) = relay_transport {
            let current_connection_id = relay_transport
                .read()
                .await
                .as_ref()
                .map(RelayTransport::connection_id);
            if relay_connection_id != current_connection_id {
                peers.emit_timeline(
                    "relay_probe_packet_stale",
                    Some("relay"),
                    Some("relay_transport_replaced"),
                    Some(format!(
                        "peer={peer_id} relay_endpoint={relay_endpoint} packet_connection_id={relay_connection_id:?} current_connection_id={current_connection_id:?}"
                    )),
                );
                return;
            }
        }
        if !peers.peer_online(peer_id).await {
            debug!(
                peer_id = %peer_id,
                "ignored relay probe for offline or closed peer {peer_id}"
            );
            return;
        }
        match token.kind {
            crate::relay_probe::RelayProbeKind::Request => {
                // Without a live relay transport there is nothing to answer
                // over; drop silently (the initiator retries its probe).
                let Some(relay_transport) = relay_transport else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored relay probe request from {peer_id}: no relay transport to answer on"
                    );
                    return;
                };
                let Some(relay) = relay_transport.read().await.clone() else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored relay probe request from {peer_id}: relay slot is empty"
                    );
                    return;
                };
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    return;
                };
                // Answer with the request's own IP header, source/destination
                // swapped; the token mirrors the request exactly.  Sending the
                // ACK over the relay (forced, not the path selector) is what
                // lets the initiator confirm the real relay ingress.
                let ack_payload = crate::relay_probe::build_relay_probe_payload(
                    crate::relay_probe::RelayProbeKind::Ack,
                    token.generation,
                    token.request_id,
                    token.owner_token,
                );
                let ack_packet = Ipv4Packet::build_icmp_echo_request(
                    ip.dst_addr(),
                    ip.src_addr(),
                    token.request_id,
                    1,
                    &ack_payload,
                );
                let relay_send = relay.clone();
                match self
                    .encrypt_and_emit_outbound(
                        OutboundPacket {
                            peer_id: peer_id.to_string(),
                            dst_ip: ip.src_addr().to_string(),
                            packet: ack_packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            relay_send.send_packet(&encrypted).await.map(|_| ())
                        },
                    )
                    .await
                {
                    Ok(true) => {
                        info!(
                            event = "relay_probe_ack_sent",
                            peer_id = %peer_id,
                            relay_endpoint = %relay_endpoint,
                            request_id = token.request_id,
                            "relay_probe_ack_sent peer_id={peer_id} relay_endpoint={relay_endpoint} request_id={}",
                            token.request_id,
                        );
                    }
                    Ok(false) => {
                        debug!(
                            "Could not answer relay probe from {peer_id}: WireGuard session is no longer ready"
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to answer relay probe from {peer_id} over {relay_endpoint}: {err}"
                        );
                    }
                }
            }
            crate::relay_probe::RelayProbeKind::Ack => {
                // The caller guaranteed the ACK's real ingress was relay.  The
                // peer manager verifies the token against the outstanding
                // expectation (request id + generation + owner, within TTL)
                // AND that the ACK arrived over the SAME relay the probe was
                // sent on (real ingress binding); only then does it set
                // RelayPeerConfirmed.
                let confirmed = peers
                    .consume_relay_probe_ack_with_transport(
                        peer_id,
                        token,
                        relay_endpoint,
                        relay_connection_id,
                    )
                    .await;
                if !confirmed {
                    debug!(
                        peer_id = %peer_id,
                        "relay probe ACK from {peer_id} did not match a fresh outstanding expectation, or arrived over a different relay (or was already consumed)"
                    );
                }
            }
        }
    }

    /// Handle one inbound synthetic path-commit packet (request or ack).
    ///
    /// Mirrors [`Self::handle_relay_probe_packet`]: a request is answered
    /// idempotently over the same relay, and an ack is verified against the
    /// outstanding expectation before it commits the relay-first business gate
    /// for one-directional traffic.  A relay renewal rejects this reader the
    /// same way, so a stale transport can neither answer nor consume.
    async fn handle_path_commit_packet(
        &self,
        peers: &Arc<PeerManager>,
        relay_transport: Option<&Arc<RwLock<Option<RelayTransport>>>>,
        probe: PathCommitIngress<'_>,
    ) {
        let PathCommitIngress {
            peer_id,
            packet,
            relay_endpoint,
            relay_connection_id,
            token,
        } = probe;
        if let Some(relay_transport) = relay_transport {
            let current_connection_id = relay_transport
                .read()
                .await
                .as_ref()
                .map(RelayTransport::connection_id);
            if relay_connection_id != current_connection_id {
                peers.emit_timeline(
                    "path_commit_packet_stale",
                    Some("relay"),
                    Some("relay_transport_replaced"),
                    Some(format!(
                        "peer={peer_id} relay_endpoint={relay_endpoint} packet_connection_id={relay_connection_id:?} current_connection_id={current_connection_id:?}"
                    )),
                );
                return;
            }
        }
        if !peers.peer_online(peer_id).await {
            debug!(
                peer_id = %peer_id,
                "ignored path-commit packet for offline or closed peer {peer_id}"
            );
            return;
        }
        match token.kind {
            crate::path_commit::PathCommitKind::Request => {
                let Some(relay_transport) = relay_transport else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored path-commit request from {peer_id}: no relay transport to answer on"
                    );
                    return;
                };
                let Some(relay) = relay_transport.read().await.clone() else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored path-commit request from {peer_id}: relay slot is empty"
                    );
                    return;
                };
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    return;
                };
                let ack_payload = crate::path_commit::build_path_commit_payload(
                    crate::path_commit::PathCommitKind::Ack,
                    token.generation,
                    token.request_id,
                    token.owner_token,
                );
                let ack_packet = Ipv4Packet::build_icmp_echo_request(
                    ip.dst_addr(),
                    ip.src_addr(),
                    token.request_id,
                    1,
                    &ack_payload,
                );
                let relay_send = relay.clone();
                match self
                    .encrypt_and_emit_outbound(
                        OutboundPacket {
                            peer_id: peer_id.to_string(),
                            dst_ip: ip.src_addr().to_string(),
                            packet: ack_packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            relay_send.send_packet(&encrypted).await.map(|_| ())
                        },
                    )
                    .await
                {
                    Ok(true) => {
                        info!(
                            event = "path_commit_ack_sent",
                            peer_id = %peer_id,
                            relay_endpoint = %relay_endpoint,
                            request_id = token.request_id,
                            "path_commit_ack_sent peer_id={peer_id} relay_endpoint={relay_endpoint} request_id={}",
                            token.request_id,
                        );
                    }
                    Ok(false) => {
                        debug!(
                            "Could not answer path-commit from {peer_id}: WireGuard session is no longer ready"
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to answer path-commit from {peer_id} over {relay_endpoint}: {err}"
                        );
                    }
                }
            }
            crate::path_commit::PathCommitKind::Ack => {
                // The caller guaranteed the ACK's real ingress was relay.  The
                // peer manager verifies the token against the outstanding
                // expectation (request id + generation + owner, within TTL)
                // AND that the ACK arrived over the SAME relay the request was
                // sent on; only then does it commit the relay-first business
                // path-commit marker (P0-4 one-way liveness).
                let confirmed = peers
                    .consume_path_commit_ack_with_transport(
                        peer_id,
                        token,
                        relay_endpoint,
                        relay_connection_id,
                    )
                    .await;
                if !confirmed {
                    debug!(
                        peer_id = %peer_id,
                        "path-commit ACK from {peer_id} did not match a fresh outstanding expectation, or arrived over a different relay (or was already consumed)"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
include!("transport/tests.rs");
