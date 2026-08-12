//! Network outbound path selection: choose direct UDP vs relay fallback for
//! each encrypted peer packet and forward it over the selected path.
//!
//! The outbound worker is a bounded, event-driven PER-PEER actor: a packet for
//! a peer that is not yet usable (no confirmed Direct, no confirmed relay
//! path) is parked in that peer's bounded queue, NOT in a blocking loop on the
//! shared worker.  Every peer with a queued first packet shares ONE startup
//! deadline for its current generation — N packets never pay N * timeout.  The
//! queue is flushed the moment RelayPeerConfirmed or DirectConfirmed lands
//! (event-driven via the peer manager's notify/sequence API), and cancellable
//! on peer offline, generation change, relay 404, queue overflow or TTL
//! expiry without breaking per-peer ordering or leaking tasks.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, warn};

use crate::connection_timeline::ConnectionTimeline;
use crate::peer::{
    NetworkPath, PathSelection, PeerManager, REASON_DIRECT_SEND_FAILED, REASON_PATH_DIRECT_TRIAL,
};
use crate::relay::RelayTransport;
use crate::transport::{EncryptedPeerPacket, OrderedEncryptedPeerPacket};
use crate::udp::UdpTransport;

const OUTBOUND_RETRY_DELAY: Duration = Duration::from_millis(50);
/// Bound a single path send so a stalled relay TCP write can never block the
/// shared outbound worker (per-peer waits are already event-driven; this
/// bounds the per-packet SEND).
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// Cadence of the outbound maintenance ticker (deadline expiry, peer
/// offline / generation-change cancellation, paced retries).
const OUTBOUND_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
/// Per-peer pending queue bounds.  A not-yet-usable peer cannot build
/// unbounded memory pressure while it waits for a path.
const MAX_PENDING_PACKETS_PER_PEER: usize = 256;
const MAX_PENDING_BYTES_PER_PEER: usize = 512 * 1024;
/// Maximum packets sent from ONE peer's queue in a single flush pass.  The
/// outbound worker is a single loop over all peers; a slow send (e.g. a
/// stalled relay write) must not let one peer's large queue starve every other
/// peer, so each peer's drain is bounded per tick and the rest waits for the
/// next maintenance tick.
const MAX_FLUSH_PER_PEER_PER_TICK: usize = 8;

/// Stable reason code emitted when the first business packet has no usable
/// path because the daemon is configured direct-only (no relay candidates are
/// configured or expected).  Kept distinct from a relay startup timeout so the
/// operator can tell "relay not configured" apart from "relay not up in time".
pub(crate) const REASON_DIRECT_ONLY_NO_RELAY: &str = "direct_only_no_relay";
/// Stable reason code emitted when a packet is dropped because the peer's
/// shared relay/direct startup deadline expired with no usable path.
pub(crate) const REASON_RELAY_STARTUP_WAIT_EXPIRED: &str = "relay_startup_wait_expired";
/// Stable reason code for a pending packet dropped because the per-peer queue
/// exceeded its packet/byte bound.
pub(crate) const REASON_OUTBOUND_QUEUE_FULL: &str = "outbound_queue_full";
/// Stable reason code for a waiting peer that went offline.
pub(crate) const REASON_OUTBOUND_PEER_OFFLINE: &str = "outbound_peer_offline";
/// Stable reason code for a waiting peer whose local network generation
/// advanced mid-wait (old NAT mappings are invalid; the wait restarts fresh).
pub(crate) const REASON_OUTBOUND_GENERATION_CHANGED: &str = "outbound_generation_changed";

enum OutboundSendResult {
    Sent,
    Retryable(RetryableOutboundFailure),
}

enum RetryableOutboundFailure {
    NoSelectedPath {
        reason: String,
        reason_code: &'static str,
    },
    RelaySendFailed {
        err: String,
    },
}

/// Bounded, event-driven first-packet wait policy.
///
/// `Some(timeout)` means a relay transport may still become available (relay
/// candidates are configured) and the first packet of a peer waits up to
/// `timeout` — SHARED across every queued packet of the same peer + generation
/// — for RelayPeerConfirmed or DirectConfirmed before being dropped with a
/// stable reason.  `None` means relay is not configured/expected: packets
/// degrade to direct-only immediately.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayStartupWait {
    pub(crate) timeout: Option<Duration>,
}

/// One per-peer pending queue.  Packets are sent strictly in arrival order
/// (FIFO), so a drop or retry never reorders a peer's stream.
struct PeerPendingQueue {
    queue: VecDeque<OrderedEncryptedPeerPacket>,
    bytes: usize,
    /// When the peer's FIRST packet started waiting (None = not waiting).
    wait_started: Option<Instant>,
    /// Shared startup deadline for this peer + generation.
    wait_deadline: Option<Instant>,
    /// Network generation the current wait belongs to.
    wait_generation: Option<u64>,
    /// Next time a paced retry of this peer is allowed (after a transient
    /// send failure), so the maintenance ticker does not hot-loop a failed
    /// relay.
    retry_after: Option<Instant>,
}

impl PeerPendingQueue {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            wait_started: None,
            wait_deadline: None,
            wait_generation: None,
            retry_after: None,
        }
    }

    /// Park a packet in the bounded queue, dropping oldest packets first when
    /// the packet/byte bound is exceeded.  Returns the number of packets
    /// dropped for the overflow.
    fn enqueue(
        &mut self,
        packet: OrderedEncryptedPeerPacket,
        _now: Instant,
        peer_id: &str,
        timeline: &ConnectionTimeline,
    ) -> usize {
        let packet_len = packet.wire_bytes.len();
        let mut dropped = 0usize;
        while !self.queue.is_empty()
            && (self.queue.len() >= MAX_PENDING_PACKETS_PER_PEER
                || self.bytes.saturating_add(packet_len) > MAX_PENDING_BYTES_PER_PEER)
        {
            if let Some(old) = self.queue.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.wire_bytes.len());
                dropped = dropped.saturating_add(1);
            }
        }
        if dropped > 0 {
            timeline.emit(
                "outbound_packet_dropped",
                None,
                Some(REASON_OUTBOUND_QUEUE_FULL),
                Some(format!(
                    "peer={peer_id} dropped={dropped} reason={REASON_OUTBOUND_QUEUE_FULL} queued={} bytes={}",
                    self.queue.len(),
                    self.bytes
                )),
            );
        }
        self.bytes = self.bytes.saturating_add(packet_len);
        self.queue.push_back(packet);
        dropped
    }

    fn pop_front(&mut self) -> Option<OrderedEncryptedPeerPacket> {
        let packet = self.queue.pop_front()?;
        self.bytes = self.bytes.saturating_sub(packet.wire_bytes.len());
        Some(packet)
    }

    fn push_front(&mut self, packet: OrderedEncryptedPeerPacket) {
        self.bytes = self.bytes.saturating_add(packet.wire_bytes.len());
        self.queue.push_front(packet);
    }
}

/// Bump the relay probe kick so the forced-relay probe loop fires immediately
/// for any peer whose first business packet is now waiting.
fn bump_probe_kick(kick: &mut u64, relay_probe_kick_tx: &watch::Sender<u64>) {
    *kick = kick.wrapping_add(1);
    let _ = relay_probe_kick_tx.send(*kick);
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_network_outbound(
    mut encrypted_rx: mpsc::Receiver<OrderedEncryptedPeerPacket>,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_available_rx: watch::Receiver<bool>,
    relay_startup_wait: RelayStartupWait,
    relay_probe_kick_tx: watch::Sender<u64>,
    timeline: Arc<ConnectionTimeline>,
) {
    let mut pending: HashMap<String, PeerPendingQueue> = HashMap::new();
    let direct_notify = peers.direct_commit_notify();
    let relay_notify = peers.relay_confirm_notify();
    let mut relay_available_rx = relay_available_rx;
    let mut ticker = interval(OUTBOUND_MAINTENANCE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut probe_kick = 0u64;
    let _ = relay_probe_kick_tx.send(probe_kick);

    loop {
        tokio::select! {
            packet = encrypted_rx.recv() => {
                let Some(packet) = packet else { break; };
                handle_ingress(
                    packet,
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    relay_startup_wait,
                    &mut probe_kick,
                    &relay_probe_kick_tx,
                    &timeline,
                ).await;
            }
            _ = direct_notify.notified() => {
                flush_ready_peers(
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    &timeline,
                ).await;
            }
            _ = relay_notify.notified() => {
                flush_ready_peers(
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    &timeline,
                ).await;
            }
            changed = relay_available_rx.changed() => {
                if changed.is_err() { break; }
                // A relay came up (or cleared): kick the probe loop so a
                // waiting peer's confirmation is not delayed by the probe
                // cadence, then flush whatever became usable.
                bump_probe_kick(&mut probe_kick, &relay_probe_kick_tx);
                flush_ready_peers(
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    &timeline,
                ).await;
            }
            _ = ticker.tick() => {
                maintenance(
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    &timeline,
                ).await;
            }
        }
    }
}

/// Route one encrypted packet: send it immediately when its peer already has a
/// usable path, otherwise park it in the peer's bounded queue and start the
/// peer's SHARED startup deadline (first packet of a peer + generation only).
#[allow(clippy::too_many_arguments)]
async fn handle_ingress(
    packet: OrderedEncryptedPeerPacket,
    peers: &PeerManager,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_startup_wait: RelayStartupWait,
    probe_kick: &mut u64,
    relay_probe_kick_tx: &watch::Sender<u64>,
    timeline: &ConnectionTimeline,
) {
    let peer_id = packet.peer_id.clone();
    let generation = peers.current_network_generation().await;
    let usable = peers.is_direct(&peer_id).await || peers.is_relay_peer_confirmed(&peer_id).await;
    if usable {
        match send_encrypted_packet_bounded(
            &packet,
            peers,
            prefer_direct,
            udp_transport,
            relay_transport,
        )
        .await
        {
            OutboundSendResult::Sent => return,
            // Transient send failure with a usable path: park in the queue and
            // let the paced retry flush it.
            OutboundSendResult::Retryable(_) => {}
        }
    }

    // A waiting queue whose generation advanced mid-wait is dropped first
    // (old NAT mappings are invalid); the packet below starts a fresh wait.
    if pending.get(&peer_id).is_some_and(|entry| {
        entry.wait_generation.is_some() && entry.wait_generation != Some(generation)
    }) {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_OUTBOUND_GENERATION_CHANGED,
            timeline,
        )
        .await;
    }

    // Park the packet.  The peer is NOT usable yet (relay not confirmed,
    // direct not confirmed): release the ordering guard BEFORE queuing so this
    // packet can never hold the peer's emit lock while it waits for a path.
    // The relay probe / direct-validation control packets that will make the
    // peer usable must not be blocked by queued business traffic.
    let mut packet = packet;
    packet.release_send_order_guard();
    let entry = pending
        .entry(peer_id.clone())
        .or_insert_with(PeerPendingQueue::new);
    let _ = entry.enqueue(packet, Instant::now(), &peer_id, timeline);

    if entry.wait_started.is_none() {
        match relay_startup_wait.timeout {
            None => {
                // Direct-only configuration: never wait for a relay that is
                // not configured/expected.  Drop every parked packet with a
                // stable reason code.
                drop_pending_queue(
                    peers,
                    pending.remove(&peer_id),
                    REASON_DIRECT_ONLY_NO_RELAY,
                    timeline,
                )
                .await;
                debug!(
                    "Encrypted packet for peer {} dropped: direct-only config has no relay and direct is not confirmed",
                    peer_id
                );
            }
            Some(timeout) => {
                entry.wait_started = Some(Instant::now());
                entry.wait_deadline = Some(Instant::now() + timeout);
                entry.wait_generation = Some(generation);
                // Kick the forced-relay probe loop: the peer's first business
                // packet is waiting and the relay path is not confirmed yet.
                bump_probe_kick(probe_kick, relay_probe_kick_tx);
                timeline.emit(
                    "outbound_first_packet_wait_started",
                    None,
                    None,
                    Some(format!(
                        "peer={peer_id} generation={generation} wait_timeout_ms={} queued={}",
                        timeout.as_millis(),
                        entry.queue.len()
                    )),
                );
            }
        }
    }
}

/// Send every queued packet of peers that became usable (DirectConfirmed or
/// RelayPeerConfirmed), strictly in FIFO order, re-parking a packet whose send
/// transiently failed so order is never broken.
async fn flush_ready_peers(
    peers: &PeerManager,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    timeline: &ConnectionTimeline,
) {
    let ready_ids: Vec<String> = {
        let mut ready = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if entry.queue.is_empty() {
                continue;
            }
            if entry.retry_after.is_some_and(|at| at > Instant::now()) {
                continue;
            }
            if peers.is_direct(peer_id).await || peers.is_relay_peer_confirmed(peer_id).await {
                ready.push(peer_id.clone());
            }
        }
        ready
    };
    for peer_id in ready_ids {
        let mut flushed = 0usize;
        let mut failed = false;
        // Bound this peer's drain so a large queue + a slow send cannot starve
        // the OTHER peers in the same worker loop; the remainder waits for the
        // next maintenance tick (and the notify-driven flush).
        while !failed && flushed < MAX_FLUSH_PER_PEER_PER_TICK {
            let Some(front) = pending
                .get_mut(&peer_id)
                .and_then(|entry| entry.pop_front())
            else {
                break;
            };
            match send_encrypted_packet_bounded(
                &front,
                peers,
                prefer_direct,
                udp_transport,
                relay_transport,
            )
            .await
            {
                OutboundSendResult::Sent => {
                    flushed = flushed.saturating_add(1);
                }
                OutboundSendResult::Retryable(failure) => {
                    // Re-park at the front; the next maintenance tick retries
                    // after the pacing delay.  Order preserved.
                    let entry = pending.get_mut(&peer_id).expect("queue exists");
                    entry.push_front(front);
                    entry.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
                    match failure {
                        RetryableOutboundFailure::NoSelectedPath {
                            reason,
                            reason_code,
                        } => {
                            debug!(
                                "Path for queued peer {} still unavailable: {} ({})",
                                peer_id, reason, reason_code
                            );
                        }
                        RetryableOutboundFailure::RelaySendFailed { err } => {
                            debug!(
                                "Relay send for queued peer {} transiently failed: {err}",
                                peer_id
                            );
                        }
                    }
                    failed = true;
                }
            }
        }
        if flushed > 0 {
            let entry = pending.get(&peer_id);
            let remaining = entry.map(|entry| entry.queue.len()).unwrap_or(0);
            let relay_confirm_seq = peers.relay_confirm_seq_sync(&peer_id);
            let direct_commit_seq = peers.direct_commit_seq_sync(&peer_id);
            timeline.emit(
                "outbound_first_packet_flushed",
                None,
                None,
                Some(format!(
                    "peer={peer_id} flushed={flushed} remaining={remaining} relay_confirm_seq={relay_confirm_seq:?} direct_commit_seq={direct_commit_seq:?}"
                )),
            );
            debug!("Flushed {flushed} queued packets for peer {peer_id}");
        }
        if pending
            .get(&peer_id)
            .is_some_and(|entry| entry.queue.is_empty())
        {
            pending.remove(&peer_id);
        }
    }
}

/// Periodic maintenance: expire startup deadlines, cancel waits on peer
/// offline / generation change, and flush what became usable.
async fn maintenance(
    peers: &PeerManager,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    timeline: &ConnectionTimeline,
) {
    let now = Instant::now();
    let generation = peers.current_network_generation().await;

    // 1. Startup-deadline expiry: every queued packet of a peer whose shared
    //    deadline passed is dropped with the stable reason code.  A peer that
    //    JUST became usable (RelayPeerConfirmed or DirectConfirmed) in the same
    //    tick is NOT dropped here: the confirmation races the deadline, and
    //    flush_ready_peers below must deliver its queued packets instead of the
    //    expiry dropping them as if the path never came up.
    let expired: Vec<String> = {
        let mut expired = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if !entry.wait_deadline.is_some_and(|deadline| now >= deadline) {
                continue;
            }
            let usable =
                peers.is_relay_peer_confirmed(peer_id).await || peers.is_direct(peer_id).await;
            if !usable {
                expired.push(peer_id.clone());
            }
        }
        expired
    };
    for peer_id in expired {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_RELAY_STARTUP_WAIT_EXPIRED,
            timeline,
        )
        .await;
    }

    // 2. Cancellation: peer offline or generation change invalidates the wait.
    let cancellations: Vec<(String, &'static str)> = pending
        .iter()
        .filter(|(_, entry)| entry.wait_started.is_some() && !entry.queue.is_empty())
        .filter_map(|(peer_id, entry)| {
            if entry.wait_generation != Some(generation) {
                return Some((peer_id.clone(), REASON_OUTBOUND_GENERATION_CHANGED));
            }
            None
        })
        .collect();
    for (peer_id, reason) in cancellations {
        drop_pending_queue(peers, pending.remove(&peer_id), reason, timeline).await;
    }
    let offline: Vec<String> = {
        let mut offline = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if entry.wait_started.is_some()
                && !entry.queue.is_empty()
                && !peers.peer_online(peer_id).await
            {
                offline.push(peer_id.clone());
            }
        }
        offline
    };
    for peer_id in offline {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_OUTBOUND_PEER_OFFLINE,
            timeline,
        )
        .await;
    }

    // 3. Flush what became usable (paced by each peer's retry_after).
    flush_ready_peers(
        peers,
        pending,
        prefer_direct,
        udp_transport,
        relay_transport,
        timeline,
    )
    .await;
}

/// Drop a pending queue, emitting a stable reason event with the peer detail
/// and recording the loss in the peer manager's structural drop counters.
async fn drop_pending_queue(
    peers: &PeerManager,
    queue: Option<PeerPendingQueue>,
    reason_code: &'static str,
    timeline: &ConnectionTimeline,
) {
    let Some(queue) = queue else { return };
    let dropped = queue.queue.len();
    if dropped == 0 {
        return;
    }
    let peer_id = queue
        .queue
        .front()
        .map(|packet| packet.peer_id.clone())
        .unwrap_or_default();
    timeline.emit(
        "relay_unavailable_or_first_packet_expired",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} dropped={dropped} bytes={} waited_ms={}",
            queue.bytes,
            queue
                .wait_started
                .map(|started| started.elapsed().as_millis())
                .unwrap_or(0)
        )),
    );
    peers
        .record_outbound_drop(reason_code, dropped, queue.bytes)
        .await;
    debug!(
        "Dropped {dropped} queued packets for peer {peer_id}: {reason_code} (bytes={})",
        queue.bytes
    );
}

/// Send one packet with a hard time bound so a stalled relay cannot block the
/// shared outbound worker.
async fn send_encrypted_packet_bounded(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
) -> OutboundSendResult {
    timeout(
        OUTBOUND_SEND_TIMEOUT,
        send_encrypted_packet_once(packet, peers, prefer_direct, udp_transport, relay_transport),
    )
    .await
    .unwrap_or_else(|_| {
        OutboundSendResult::Retryable(RetryableOutboundFailure::RelaySendFailed {
            err: "outbound send timed out".to_string(),
        })
    })
}

async fn send_encrypted_packet_once(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
) -> OutboundSendResult {
    let relay = relay_transport.read().await.clone();
    let relay_available = relay.is_some();
    let udp = udp_transport.read().await.clone();
    let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
    let selection = select_outbound_path(
        packet,
        peers,
        prefer_direct,
        relay_available,
        udp_local_endpoint,
    )
    .await;

    if selection.direct_confirmed {
        let sent_direct =
            send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint).await;

        if sent_direct && !selection.relay_hedged {
            return OutboundSendResult::Sent;
        }

        if let Some(relay) = relay {
            return match relay.send_packet(packet).await {
                Ok(_) => OutboundSendResult::Sent,
                Err(err) if sent_direct => {
                    debug!(
                        "Relay hedge send failed for peer {} after confirmed direct send: {err}",
                        packet.peer_id
                    );
                    OutboundSendResult::Sent
                }
                Err(err) => {
                    OutboundSendResult::Retryable(RetryableOutboundFailure::RelaySendFailed {
                        err: err.to_string(),
                    })
                }
            };
        }

        return if sent_direct {
            OutboundSendResult::Sent
        } else {
            OutboundSendResult::Retryable(RetryableOutboundFailure::NoSelectedPath {
                reason: selection.reason,
                reason_code: selection.reason_code,
            })
        };
    }

    // Until Direct is confirmed by decrypted traffic, Relay is the reliable
    // data-plane. A UDP send during Direct trial is only a hedge/probe: it must
    // never make the user packet look delivered if Relay is absent or fails.
    if let Some(relay) = relay {
        match relay.send_packet(packet).await {
            Ok(_) => {
                let _ = send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint)
                    .await;
                OutboundSendResult::Sent
            }
            Err(err) => {
                let _ = send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint)
                    .await;
                OutboundSendResult::Retryable(RetryableOutboundFailure::RelaySendFailed {
                    err: err.to_string(),
                })
            }
        }
    } else {
        let _ = send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint).await;
        OutboundSendResult::Retryable(RetryableOutboundFailure::NoSelectedPath {
            reason: selection.reason,
            reason_code: selection.reason_code,
        })
    }
}

async fn select_outbound_path(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    relay_available: bool,
    udp_local_endpoint: Option<SocketAddr>,
) -> PathSelection {
    let selection = peers
        .select_path_for_data_with_local_endpoint(
            &packet.peer_id,
            prefer_direct,
            relay_available,
            udp_local_endpoint,
        )
        .await;
    debug!(
        "Path selection for peer {}: path={:?} relay_hedged={} reason_code={} reason={}",
        packet.peer_id,
        selection.path,
        selection.relay_hedged,
        selection.reason_code,
        selection.reason
    );
    selection
}

async fn send_direct_if_selected(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    udp: Option<UdpTransport>,
    selection: &PathSelection,
    udp_local_endpoint: Option<SocketAddr>,
) -> bool {
    if selection.path != Some(NetworkPath::Direct) {
        return false;
    }

    match (udp, selection.direct_endpoint) {
        (Some(udp), Some(endpoint)) => {
            if !selection.direct_confirmed && selection.reason_code == REASON_PATH_DIRECT_TRIAL {
                if let Err(err) = udp.send_nomination_probe(&packet.peer_id, endpoint).await {
                    debug!(
                        "Failed to send nominated UDP connectivity check for peer {} at {}: {err}",
                        packet.peer_id, endpoint
                    );
                }
            }
            match udp.send_packet_to(packet, endpoint).await {
                Ok(_) => true,
                Err(err) => {
                    warn!(
                        "Direct UDP send failed for peer {}; trying relay fallback: {err}",
                        packet.peer_id
                    );
                    peers
                        .record_direct_failure_with_code_and_local_endpoint(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            err.to_string(),
                            udp_local_endpoint,
                        )
                        .await;
                    false
                }
            }
        }
        (None, _) => {
            peers
                .record_direct_failure_with_code_and_local_endpoint(
                    &packet.peer_id,
                    REASON_DIRECT_SEND_FAILED,
                    "UDP transport unavailable for encrypted packet",
                    udp_local_endpoint,
                )
                .await;
            false
        }
        (_, None) => {
            peers
                .record_direct_failure_with_code_and_local_endpoint(
                    &packet.peer_id,
                    REASON_DIRECT_SEND_FAILED,
                    "path selector chose direct without an endpoint",
                    udp_local_endpoint,
                )
                .await;
            false
        }
    }
}
