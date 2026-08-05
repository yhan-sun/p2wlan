//! WireGuard transport adapter for daemon data plane packets.
//!
//! `DataPlane` resolves raw TUN packets to a peer ID. This module is the next
//! hop: it takes routed peer packets, encrypts them with an established
//! WireGuard transport session, and emits encrypted wire bytes for the UDP or
//! relay transport layer.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_tun::{Ipv4Packet, Protocol};
use p2pnet_wireguard::{MessageTransport, TransportSession};
use tokio::sync::{mpsc, Mutex, OwnedMutexGuard};
use tracing::{debug, warn};

use crate::dataplane::{InboundPacket, OutboundPacket};
use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;

const RELAY_VALIDATION_PAYLOAD_PREFIX: &[u8] = b"p2wlan-relay-validation";
const RELAY_VALIDATION_TIMESTAMP_BYTES: usize = 8;
const RELAY_VALIDATION_MAX_RTT: Duration = Duration::from_secs(600);
/// Keep a short startup/rekey cushion for user traffic that reaches the TUN
/// before the WireGuard session is installed. The queue is deliberately small
/// and per-peer so a not-ready peer cannot build unbounded memory pressure.
const PENDING_OUTBOUND_TTL: Duration = Duration::from_secs(8);
const MAX_PENDING_OUTBOUND_PER_PEER: usize = 256;
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
}

impl TransportSessionSlot {
    fn new(session: TransportSession, token: Option<String>) -> Self {
        Self {
            session,
            token,
            awaiting_confirmation: false,
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
        }
    }
}

struct PendingOutboundPacket {
    queued_at: Instant,
    packet: OutboundPacket,
}

struct PromotedResponderToken {
    token: String,
    expires_at: Instant,
}

pub(crate) fn build_relay_validation_payload(sent_at_ms: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(
        RELAY_VALIDATION_PAYLOAD_PREFIX.len() + RELAY_VALIDATION_TIMESTAMP_BYTES,
    );
    payload.extend_from_slice(RELAY_VALIDATION_PAYLOAD_PREFIX);
    payload.extend_from_slice(&sent_at_ms.to_be_bytes());
    payload
}

fn relay_validation_rtt(packet: &[u8]) -> Option<Duration> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Icmp {
        return None;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 + RELAY_VALIDATION_PAYLOAD_PREFIX.len() + RELAY_VALIDATION_TIMESTAMP_BYTES {
        return None;
    }
    if icmp[0] != 0 || icmp[1] != 0 {
        return None;
    }
    let payload = &icmp[8..];
    let timestamp = payload
        .strip_prefix(RELAY_VALIDATION_PAYLOAD_PREFIX)?
        .get(..RELAY_VALIDATION_TIMESTAMP_BYTES)?;
    let sent_at_ms = u64::from_be_bytes(timestamp.try_into().ok()?);
    let now_ms = unix_time_millis();
    if sent_at_ms > now_ms {
        return None;
    }
    let rtt = Duration::from_millis(now_ms.saturating_sub(sent_at_ms));
    (rtt <= RELAY_VALIDATION_MAX_RTT).then_some(rtt)
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

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
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
}

/// An encrypted packet that retains its peer's ordering lock until the
/// network worker has completed the real UDP/relay send.
///
/// WireGuard replay protection is counter based. Keeping this guard inside
/// the egress queue prevents a later synthetic confirmation packet from being
/// encrypted and sent ahead of an earlier user packet that is still queued.
pub struct OrderedEncryptedPeerPacket {
    packet: EncryptedPeerPacket,
    _send_order_guard: Arc<OwnedMutexGuard<()>>,
}

impl OrderedEncryptedPeerPacket {
    fn new(packet: EncryptedPeerPacket, send_order_guard: Arc<OwnedMutexGuard<()>>) -> Self {
        Self {
            packet,
            _send_order_guard: send_order_guard,
        }
    }

    #[cfg(test)]
    pub(crate) async fn for_test(packet: EncryptedPeerPacket) -> Self {
        let lock = Arc::new(Mutex::new(()));
        Self::new(packet, Arc::new(lock.lock_owned().await))
    }
}

impl Deref for OrderedEncryptedPeerPacket {
    type Target = EncryptedPeerPacket;

    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}

/// An encrypted WireGuard packet received from UDP or relay transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedEncryptedPacket {
    /// Source socket address when known.
    pub source: Option<SocketAddr>,
    /// Local UDP socket address that received this packet, when known.
    pub local_endpoint: Option<SocketAddr>,
    /// Relay endpoint that delivered this packet, when received through Relay.
    pub relay_endpoint: Option<String>,
    /// Relay-authenticated source node ID, checked against the decrypted session owner.
    pub relay_peer_id: Option<String>,
    /// Serialized WireGuard transport message.
    pub wire_bytes: Vec<u8>,
}

/// Encrypts routed TUN packets with peer WireGuard sessions.
#[derive(Clone)]
pub struct WireGuardTransport {
    sessions: Arc<Mutex<HashMap<String, PeerTransportSessions>>>,
    pending_outbound: Arc<Mutex<HashMap<String, VecDeque<PendingOutboundPacket>>>>,
    outbound_emit_locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    promoted_responder_tokens: Arc<Mutex<HashMap<String, VecDeque<PromotedResponderToken>>>>,
    encrypted_tx: mpsc::Sender<OrderedEncryptedPeerPacket>,
}

impl WireGuardTransport {
    /// Create a transport adapter and a receiver for encrypted peer packets.
    pub fn new() -> (Self, mpsc::Receiver<OrderedEncryptedPeerPacket>) {
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1024);
        (
            Self {
                sessions: Arc::new(Mutex::new(HashMap::new())),
                pending_outbound: Arc::new(Mutex::new(HashMap::new())),
                outbound_emit_locks: Arc::new(Mutex::new(HashMap::new())),
                promoted_responder_tokens: Arc::new(Mutex::new(HashMap::new())),
                encrypted_tx,
            },
            encrypted_rx,
        )
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
        let now = Instant::now();
        let replaced_existing = {
            let mut sessions = self.sessions.lock().await;
            if let Some(existing) = sessions.get_mut(&peer_id) {
                existing.prune_expired(now);
                existing.install_with_overlap(TransportSessionSlot::new(session, token), now)
            } else {
                sessions.insert(
                    peer_id.clone(),
                    PeerTransportSessions::new(TransportSessionSlot::new(session, token)),
                );
                false
            }
        };
        self.flush_pending_outbound_for_peer(&peer_id).await;
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
        let now = Instant::now();
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
            existing.pending.insert(
                token.clone(),
                PendingTransportSession {
                    slot: TransportSessionSlot::new(session, Some(token.clone())),
                    expires_at: now + PENDING_RESPONDER_SESSION_GRACE,
                    answer_committed: false,
                },
            );
            existing.remember_responder_token(token, ResponderTokenDisposition::Restageable, now);
            ResponderSessionStage::Staged { had_active }
        } else {
            let mut peer_sessions = PeerTransportSessions::pending_only(PendingTransportSession {
                slot: TransportSessionSlot::new(session, Some(token.clone())),
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
        let now = Instant::now();
        let (result, flush_pending) = {
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
                (ResponderSessionCommit::AlreadyPromoted, false)
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
                existing.remember_responder_token(
                    token,
                    ResponderTokenDisposition::Restageable,
                    now,
                );
                if activate_initial {
                    existing.promote_pending(token, now);
                    (ResponderSessionCommit::ActivatedInitial, true)
                } else {
                    (ResponderSessionCommit::PendingConfirmation, false)
                }
            } else {
                (ResponderSessionCommit::Missing, false)
            }
        };
        if flush_pending {
            self.flush_pending_outbound_for_peer(peer_id).await;
        }
        result
    }

    /// Discard an unpublished responder session. Returns false when the token
    /// was already promoted by authenticated traffic, which proves the answer
    /// reached the peer despite a control-plane response error.
    pub async fn discard_responder_session(&self, peer_id: &str, token: &str) -> bool {
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
    pub async fn confirm_responder_session(
        &self,
        peer_id: &str,
        token: &str,
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
    pub async fn encrypt_and_emit_outbound<F, Fut>(
        &self,
        packet: OutboundPacket,
        emit: F,
    ) -> Result<bool>
    where
        F: FnOnce(EncryptedPeerPacket) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let peer_id = packet.peer_id.clone();
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        let Some(encrypted) = self.encrypt_outbound_inner(packet, false).await? else {
            return Ok(false);
        };
        emit(encrypted).await?;
        Ok(true)
    }

    /// Replace a session and return the previous value for transactional rollback.
    pub async fn replace_session(
        &self,
        peer_id: impl Into<String>,
        session: TransportSession,
    ) -> Option<TransportSession> {
        let peer_id = peer_id.into();
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get_mut(&peer_id) {
            existing.previous = None;
            existing.mark_all_responder_tokens_terminal(now);
            existing.clear_pending_as_terminal(now);
            existing
                .active
                .replace(TransportSessionSlot::new(session, None))
                .map(|previous| previous.session)
        } else {
            sessions.insert(
                peer_id,
                PeerTransportSessions::new(TransportSessionSlot::new(session, None)),
            );
            None
        }
    }

    /// Restore the session state captured before a transactional replacement.
    pub async fn restore_session(&self, peer_id: &str, previous: Option<TransportSession>) {
        let restored_previous = previous.is_some();
        let mut sessions = self.sessions.lock().await;
        if let Some(previous) = previous {
            sessions.insert(
                peer_id.to_string(),
                PeerTransportSessions::new(TransportSessionSlot::new(previous, None)),
            );
        } else {
            sessions.remove(peer_id);
        }
        drop(sessions);
        if restored_previous {
            self.flush_pending_outbound_for_peer(peer_id).await;
        } else {
            self.remove_idle_outbound_emit_lock(peer_id).await;
        }
    }

    /// Remove a peer session.
    pub async fn remove_session(&self, peer_id: &str) {
        self.sessions.lock().await.remove(peer_id);
        self.pending_outbound.lock().await.remove(peer_id);
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
        self.encrypt_outbound_inner(packet, false).await
    }

    /// Encrypt and enqueue a synthetic packet into the same ordered channel
    /// used by normal TUN traffic. Holding the per-peer lock through enqueue
    /// keeps its counter ahead of no packet that is already queued for send.
    pub async fn enqueue_outbound(&self, packet: OutboundPacket) -> Result<bool> {
        let peer_id = packet.peer_id.clone();
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let emit_guard = Arc::new(emit_lock.lock_owned().await);
        let Some(encrypted) = self.encrypt_outbound_inner(packet, false).await? else {
            return Ok(false);
        };
        self.encrypted_tx
            .send(OrderedEncryptedPeerPacket::new(encrypted, emit_guard))
            .await
            .map_err(|_| DaemonError::Network("encrypted packet channel closed".to_string()))?;
        Ok(true)
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
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let emit_guard = emit_lock.lock().await;
        let encrypted = self.encrypt_outbound_inner(packet, true).await?;
        drop(emit_guard);
        if encrypted.is_none() {
            let status = self.session_status(&peer_id).await;
            if status.has_active && !status.expired {
                self.flush_pending_outbound_for_peer(&peer_id).await;
            }
        }
        Ok(encrypted)
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
    ) -> Result<Option<EncryptedPeerPacket>> {
        let mut sessions = self.sessions.lock().await;
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

        let wire_bytes = active
            .session
            .encrypt_to_bytes(&packet.packet)
            .map_err(|e| DaemonError::Peer(format!("WireGuard encrypt failed: {e}")))?;
        drop(sessions);

        Ok(Some(EncryptedPeerPacket {
            peer_id: packet.peer_id,
            dst_ip: packet.dst_ip,
            wire_bytes,
        }))
    }

    async fn queue_pending_outbound(&self, packet: OutboundPacket, reason: &'static str) {
        let now = Instant::now();
        let peer_id = packet.peer_id.clone();
        let packet_len = packet.packet.len();
        let mut pending = self.pending_outbound.lock().await;
        let queue = pending.entry(peer_id.clone()).or_default();
        let stale_before = queue.len();
        queue.retain(|queued| {
            now.saturating_duration_since(queued.queued_at) <= PENDING_OUTBOUND_TTL
        });
        let stale_dropped = stale_before.saturating_sub(queue.len());
        let mut overflow_dropped = 0usize;
        while queue.len() >= MAX_PENDING_OUTBOUND_PER_PEER {
            queue.pop_front();
            overflow_dropped = overflow_dropped.saturating_add(1);
        }
        queue.push_back(PendingOutboundPacket {
            queued_at: now,
            packet,
        });
        debug!(
            "Queued outbound packet for peer {} until WireGuard session is ready ({} bytes, reason={}, depth={}, stale_dropped={}, overflow_dropped={})",
            peer_id,
            packet_len,
            reason,
            queue.len(),
            stale_dropped,
            overflow_dropped
        );
    }

    pub(crate) async fn flush_pending_outbound_for_peer(&self, peer_id: &str) {
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let emit_guard = Arc::new(emit_lock.lock_owned().await);
        self.flush_pending_outbound_for_peer_inner(peer_id, emit_guard)
            .await;
    }

    async fn flush_pending_outbound_for_peer_inner(
        &self,
        peer_id: &str,
        emit_guard: Arc<OwnedMutexGuard<()>>,
    ) {
        let now = Instant::now();
        let (packets, expired_count) = {
            let mut pending = self.pending_outbound.lock().await;
            let Some(queue) = pending.get_mut(peer_id) else {
                return;
            };
            let mut packets = Vec::with_capacity(queue.len());
            let mut expired_count = 0usize;
            while let Some(queued) = queue.pop_front() {
                if now.saturating_duration_since(queued.queued_at) <= PENDING_OUTBOUND_TTL {
                    packets.push(queued.packet);
                } else {
                    expired_count = expired_count.saturating_add(1);
                }
            }
            pending.remove(peer_id);
            (packets, expired_count)
        };

        if packets.is_empty() {
            if expired_count > 0 {
                debug!(
                    "Discarded {} expired pending outbound packets for peer {}",
                    expired_count, peer_id
                );
            }
            return;
        }

        let mut encrypted_packets = Vec::with_capacity(packets.len());
        let mut encrypt_failed = 0usize;
        {
            let mut sessions = self.sessions.lock().await;
            let Some(peer_sessions) = sessions.get_mut(peer_id) else {
                debug!(
                    "WireGuard session for peer {} disappeared before pending packet flush; re-queueing {} packets",
                    peer_id,
                    packets.len()
                );
                drop(sessions);
                for packet in packets {
                    self.queue_pending_outbound(packet, "session disappeared before flush")
                        .await;
                }
                return;
            };
            peer_sessions.prepare_active(now);
            let Some(active) = peer_sessions.active.as_mut() else {
                drop(sessions);
                for packet in packets {
                    self.queue_pending_outbound(packet, "session not ready before flush")
                        .await;
                }
                return;
            };
            if active.session.is_expired() {
                drop(sessions);
                for packet in packets {
                    self.queue_pending_outbound(packet, "session expired before flush")
                        .await;
                }
                return;
            }

            for packet in packets {
                match active.session.encrypt_to_bytes(&packet.packet) {
                    Ok(wire_bytes) => encrypted_packets.push(EncryptedPeerPacket {
                        peer_id: packet.peer_id,
                        dst_ip: packet.dst_ip,
                        wire_bytes,
                    }),
                    Err(err) => {
                        encrypt_failed = encrypt_failed.saturating_add(1);
                        warn!(
                            "Dropping pending outbound packet for peer {} after WireGuard encrypt failed: {err}",
                            peer_id
                        );
                    }
                }
            }
        }

        let mut sent_count = 0usize;
        for encrypted in encrypted_packets {
            if let Err(err) = self
                .encrypted_tx
                .send(OrderedEncryptedPeerPacket::new(
                    encrypted,
                    emit_guard.clone(),
                ))
                .await
            {
                warn!(
                    "Pending outbound packet channel closed while flushing peer {}: {err}",
                    peer_id
                );
                break;
            }
            sent_count = sent_count.saturating_add(1);
        }
        debug!(
            "Flushed pending outbound packets for peer {} (sent={}, expired={}, encrypt_failed={})",
            peer_id, sent_count, expired_count, encrypt_failed
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
                    confirmed_active = Some((peer_id.clone(), packet, token));
                    break;
                }
                Err(error) => {
                    first_decrypt_error.get_or_insert_with(|| error.to_string());
                }
            }
        }
        if let Some((peer_id, packet, token)) = confirmed_active {
            drop(sessions);
            if let Some(token) = token {
                self.remember_promoted_responder_token(&peer_id, token)
                    .await;
            }
            return Ok(Some(InboundPacket { peer_id, packet }));
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
                    peer_sessions.pending.insert(pending_token.clone(), pending);
                    peer_sessions.promote_pending(&pending_token, now);
                    promoted = Some((peer_id.clone(), packet, Some(pending_token)));
                    break;
                }
                Err(error) => {
                    first_decrypt_error.get_or_insert_with(|| error.to_string());
                    peer_sessions.pending.insert(pending_token, pending);
                }
            }
        }
        if let Some((peer_id, packet, token)) = promoted {
            drop(sessions);
            if let Some(token) = token {
                self.remember_promoted_responder_token(&peer_id, token)
                    .await;
            }
            self.flush_pending_outbound_for_peer(&peer_id).await;
            return Ok(Some(InboundPacket { peer_id, packet }));
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
                    }));
                }
                Err(error) => {
                    first_decrypt_error.get_or_insert_with(|| error.to_string());
                }
            }
        }

        if let Some(error) = first_decrypt_error {
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

    /// Consume routed packets and emit encrypted WireGuard packets.
    pub async fn run_outbound(
        &self,
        mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    ) -> Result<()> {
        while let Some(packet) = outbound_rx.recv().await {
            let peer_id = packet.peer_id.clone();
            let emit_lock = self.outbound_emit_lock(&peer_id).await;
            let emit_guard = Arc::new(emit_lock.lock_owned().await);
            if let Some(encrypted) = self.encrypt_outbound_inner(packet, true).await? {
                self.encrypted_tx
                    .send(OrderedEncryptedPeerPacket::new(encrypted, emit_guard))
                    .await
                    .map_err(|_| {
                        DaemonError::Network("encrypted packet channel closed".to_string())
                    })?;
            } else {
                drop(emit_guard);
                let status = self.session_status(&peer_id).await;
                if status.has_active && !status.expired {
                    self.flush_pending_outbound_for_peer(&peer_id).await;
                }
            }
        }

        Ok(())
    }

    /// Consume encrypted network packets, decrypt them, and emit raw inbound IP packets.
    pub async fn run_inbound(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
    ) -> Result<()> {
        self.run_inbound_with_peers(encrypted_rx, inbound_tx, None)
            .await
    }

    /// Consume encrypted network packets and confirm direct UDP only after
    /// successful WireGuard decryption.
    pub async fn run_inbound_with_peers(
        &self,
        mut encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
    ) -> Result<()> {
        while let Some(packet) = encrypted_rx.recv().await {
            let source = packet.source;
            let local_endpoint = packet.local_endpoint;
            let relay_endpoint = packet.relay_endpoint;
            let relay_peer_id = packet.relay_peer_id;
            match self.decrypt_inbound(&packet.wire_bytes).await {
                Ok(Some(inbound)) => {
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
                    let internal_rekey_confirmation = is_rekey_confirmation_packet(&inbound.packet);
                    if let Some(peers) = peers.as_ref() {
                        let promoted_tokens = self
                            .pending_promoted_responder_tokens(&inbound.peer_id)
                            .await;
                        for token in promoted_tokens {
                            if peers
                                .confirm_pending_probe_session_binding(&inbound.peer_id, &token)
                                .await
                            {
                                self.acknowledge_promoted_responder_token(&inbound.peer_id, &token)
                                    .await;
                                debug!(
                                    "Promoted Probe v2 binding for peer {} after WireGuard rekey confirmation",
                                    inbound.peer_id
                                );
                            }
                        }
                        if internal_rekey_confirmation {
                            debug!(
                                "Consumed internal WireGuard rekey confirmation from peer {} without changing path health",
                                inbound.peer_id
                            );
                        } else if let Some(source) = source {
                            peers
                                .learn_authenticated_endpoint(&inbound.peer_id, source)
                                .await;
                            peers
                                .record_direct_success_with_local_endpoint(
                                    &inbound.peer_id,
                                    Some(source),
                                    local_endpoint,
                                )
                                .await;
                            debug!(
                                "Confirmed direct UDP data path from {source} for peer {}",
                                inbound.peer_id
                            );
                        } else if let Some(relay_endpoint) = relay_endpoint {
                            if let Some(rtt) = relay_validation_rtt(&inbound.packet) {
                                peers
                                    .record_relay_success_with_latency(
                                        &inbound.peer_id,
                                        &relay_endpoint,
                                        true,
                                        rtt,
                                    )
                                    .await;
                            } else {
                                peers
                                    .record_relay_success(&inbound.peer_id, &relay_endpoint, true)
                                    .await;
                            }
                            debug!(
                                "Confirmed relay data path through {relay_endpoint} for peer {}",
                                inbound.peer_id
                            );
                        }
                    }
                    if internal_rekey_confirmation {
                        continue;
                    }
                    inbound_tx.send(inbound).await.map_err(|_| {
                        DaemonError::Network("inbound packet channel closed".to_string())
                    })?;
                }
                Ok(None) => {
                    debug!("Inbound encrypted packet has no matching WireGuard session");
                }
                Err(err) => {
                    warn!("Dropping inbound encrypted packet from {:?}: {err}", source);
                }
            }
        }

        Ok(())
    }
}

/// Drain and log encrypted packets until UDP/relay transport is attached.
pub async fn log_encrypted_packets(mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
    while let Some(packet) = encrypted_rx.recv().await {
        debug!(
            "Encrypted packet ready for peer {} (dst={}, {} bytes)",
            packet.peer_id,
            packet.dst_ip,
            packet.wire_bytes.len()
        );
    }
}

#[cfg(test)]
include!("transport/tests.rs");
