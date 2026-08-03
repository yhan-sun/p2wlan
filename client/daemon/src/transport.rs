//! WireGuard transport adapter for daemon data plane packets.
//!
//! `DataPlane` resolves raw TUN packets to a peer ID. This module is the next
//! hop: it takes routed peer packets, encrypts them with an established
//! WireGuard transport session, and emits encrypted wire bytes for the UDP or
//! relay transport layer.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_tun::{Ipv4Packet, Protocol};
use p2pnet_wireguard::{MessageTransport, TransportSession};
use tokio::sync::{mpsc, Mutex};
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

struct PendingOutboundPacket {
    queued_at: Instant,
    packet: OutboundPacket,
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
    sessions: Arc<Mutex<HashMap<String, TransportSession>>>,
    pending_outbound: Arc<Mutex<HashMap<String, VecDeque<PendingOutboundPacket>>>>,
    encrypted_tx: mpsc::Sender<EncryptedPeerPacket>,
}

impl WireGuardTransport {
    /// Create a transport adapter and a receiver for encrypted peer packets.
    pub fn new() -> (Self, mpsc::Receiver<EncryptedPeerPacket>) {
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1024);
        (
            Self {
                sessions: Arc::new(Mutex::new(HashMap::new())),
                pending_outbound: Arc::new(Mutex::new(HashMap::new())),
                encrypted_tx,
            },
            encrypted_rx,
        )
    }

    /// Install or replace an established transport session for a peer.
    pub async fn add_session(&self, peer_id: impl Into<String>, session: TransportSession) {
        let peer_id = peer_id.into();
        self.sessions.lock().await.insert(peer_id.clone(), session);
        self.flush_pending_outbound_for_peer(&peer_id).await;
    }

    /// Replace a session and return the previous value for transactional rollback.
    pub async fn replace_session(
        &self,
        peer_id: impl Into<String>,
        session: TransportSession,
    ) -> Option<TransportSession> {
        self.sessions.lock().await.insert(peer_id.into(), session)
    }

    /// Restore the session state captured before a transactional replacement.
    pub async fn restore_session(&self, peer_id: &str, previous: Option<TransportSession>) {
        let restored_previous = previous.is_some();
        let mut sessions = self.sessions.lock().await;
        if let Some(previous) = previous {
            sessions.insert(peer_id.to_string(), previous);
        } else {
            sessions.remove(peer_id);
        }
        drop(sessions);
        if restored_previous {
            self.flush_pending_outbound_for_peer(peer_id).await;
        }
    }

    /// Remove a peer session.
    pub async fn remove_session(&self, peer_id: &str) {
        self.sessions.lock().await.remove(peer_id);
        self.pending_outbound.lock().await.remove(peer_id);
    }

    /// Return whether a peer has an encrypting session.
    pub async fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.lock().await.contains_key(peer_id)
    }

    /// Return whether a peer's session needs rekey.
    pub async fn session_needs_rekey(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .await
            .get(peer_id)
            .map(|s| s.needs_rekey())
            .unwrap_or(false)
    }

    /// Return whether a peer's session has expired (reject threshold exceeded).
    pub async fn session_is_expired(&self, peer_id: &str) -> bool {
        self.sessions
            .lock()
            .await
            .get(peer_id)
            .map(|s| s.is_expired())
            .unwrap_or(false)
    }

    /// Encrypt one outbound packet.
    pub async fn encrypt_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        self.encrypt_outbound_inner(packet, false).await
    }

    /// Encrypt one outbound user packet, or queue it briefly if the session is
    /// not installed yet. This is used only by the TUN data path; synthetic
    /// validation/probe packets continue to use encrypt_outbound so they do not
    /// fill the startup queue while polling for readiness.
    pub async fn encrypt_or_queue_outbound(
        &self,
        packet: OutboundPacket,
    ) -> Result<Option<EncryptedPeerPacket>> {
        self.encrypt_outbound_inner(packet, true).await
    }

    async fn encrypt_outbound_inner(
        &self,
        packet: OutboundPacket,
        queue_if_unavailable: bool,
    ) -> Result<Option<EncryptedPeerPacket>> {
        let mut sessions = self.sessions.lock().await;
        // Session expiry is an expected boundary during a rekey.  It must not
        // terminate the long-lived TUN-to-WireGuard worker: the handshake
        // maintenance loop will notice the missing session and establish a
        // replacement.  Dropping this one packet is preferable to tearing
        // down the entire overlay (and the diagnostics endpoint) while a
        // replacement handshake is in flight.
        if sessions
            .get(&packet.peer_id)
            .is_some_and(TransportSession::is_expired)
        {
            sessions.remove(&packet.peer_id);
            drop(sessions);
            if queue_if_unavailable {
                self.queue_pending_outbound(packet, "session expired before rekey")
                    .await;
            } else {
                debug!(
                    "WireGuard session for peer {} expired; dropping {} byte packet until rekey completes",
                    packet.peer_id,
                    packet.packet.len()
                );
            }
            return Ok(None);
        }
        let Some(session) = sessions.get_mut(&packet.peer_id) else {
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

        let wire_bytes = session
            .encrypt_to_bytes(&packet.packet)
            .map_err(|e| DaemonError::Peer(format!("WireGuard encrypt failed: {e}")))?;

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
            let Some(session) = sessions.get_mut(peer_id) else {
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

            for packet in packets {
                match session.encrypt_to_bytes(&packet.packet) {
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
            if let Err(err) = self.encrypted_tx.send(encrypted).await {
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
        let Some((peer_id, session)) = sessions
            .iter_mut()
            .find(|(_, session)| session.our_index() == receiver_index)
        else {
            debug!(
                "No WireGuard session for receiver index {}; dropping inbound packet",
                receiver_index
            );
            return Ok(None);
        };

        let packet = session
            .decrypt(&msg)
            .map_err(|e| DaemonError::Peer(format!("WireGuard decrypt failed: {e}")))?;

        Ok(Some(InboundPacket {
            peer_id: peer_id.clone(),
            packet,
        }))
    }

    /// Consume routed packets and emit encrypted WireGuard packets.
    pub async fn run_outbound(
        &self,
        mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    ) -> Result<()> {
        while let Some(packet) = outbound_rx.recv().await {
            if let Some(encrypted) = self.encrypt_or_queue_outbound(packet).await? {
                self.encrypted_tx.send(encrypted).await.map_err(|_| {
                    DaemonError::Network("encrypted packet channel closed".to_string())
                })?;
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
                    if let Some(peers) = peers.as_ref() {
                        if let Some(source) = source {
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
