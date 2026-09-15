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
use crate::peer::{PeerManager, PeerSessionGeneration, PendingProbeBindingCommitOutcome};
use crate::relay::RelayTransport;

mod direct_validation;
mod dplpmtud;
mod inbound;
mod outbound;
mod relay_validation;
mod sessions;

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

/// Decide whether a successfully decrypted UDP packet should schedule the
/// owned encrypted Direct request/ACK validation worker.
///
/// A rekey confirmation is authenticated endpoint evidence, but never Direct
/// proof on its own. It therefore follows this path exactly like ordinary
/// decrypted UDP data: learn/remember the endpoint and ask the bounded
/// validation worker to prove the reverse direction. Direct-validation packets
/// are excluded so their request/ACK exchange cannot recursively enqueue more
/// validation sessions.
fn should_request_direct_validation_after_decrypt(
    owns_direct_packet: bool,
    source: Option<SocketAddr>,
    direct_validation: Option<DirectValidationToken>,
) -> bool {
    owns_direct_packet && source.is_some() && direct_validation.is_none()
}

/// Pick the reverse destination for one authenticated DPLPMTUD Probe.
///
/// A port-dependent NAT can expose a different source mapping for the Probe
/// than the endpoint which the peer previously authenticated. Replying to that
/// transient source would make the ACK originate from another transient
/// mapping and the initiator would correctly reject it as the wrong exact
/// path. When this UDP publication still owns an exact current path on the
/// receiving socket, send the ACK to the session-bound endpoint recorded from
/// the peer's authenticated Direct-validation Request. This makes the reverse
/// datagram originate from the responder mapping the initiator already
/// committed, while preserving strict ACK ingress matching. Without both
/// bindings, retain the historical reply-to-source behavior; it is safe but
/// may be rejected fail-closed by the initiator.
fn dplpmtud_ack_destination(
    current_path: Option<&crate::dplpmtud::DplpmtudPathIdentity>,
    authenticated_reverse_endpoint: Option<SocketAddr>,
    transport_instance_id: u64,
    probe_source: SocketAddr,
    local_endpoint: SocketAddr,
    socket_index: usize,
) -> SocketAddr {
    current_path
        .filter(|identity| {
            identity.local_endpoint == local_endpoint
                && identity.socket.transport_instance_id == transport_instance_id
                && identity.socket.socket_index == socket_index
                && identity.authenticated_remote_endpoint.is_ipv4() == probe_source.is_ipv4()
        })
        .and(authenticated_reverse_endpoint)
        .filter(|endpoint| endpoint.is_ipv4() == probe_source.is_ipv4())
        .unwrap_or(probe_source)
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
    let capability = crate::dplpmtud::direct_validation_capability_extension();
    let mut payload =
        Vec::with_capacity(prefix.len() + capability.len() + DIRECT_VALIDATION_TOKEN_BYTES);
    payload.extend_from_slice(prefix);
    payload.extend_from_slice(&capability);
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
        && crate::dplpmtud::parse_control_packet(packet).is_none()
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
                promoted_responder_tokens: Arc::new(std::sync::Mutex::new(HashMap::new())),
                hedge_replay_counters: Arc::new(std::sync::Mutex::new(HashMap::new())),
                outbound_tx,
                outbound_loss_sink: Arc::new(std::sync::Mutex::new(None)),
                outbound_loss_context: Arc::new(std::sync::Mutex::new(None)),
            },
            outbound_rx,
        )
    }
}

#[cfg(test)]
include!("transport/tests.rs");
