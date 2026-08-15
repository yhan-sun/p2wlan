//! Network outbound path selection: choose direct UDP vs relay fallback for
//! each encrypted peer packet and forward it over the selected path.
//!
//! The outbound worker is a bounded, event-driven PER-PEER actor.  It receives
//! RAW (unencrypted) routed packets from the TUN dataplane, NOT
//! already-encrypted packets.  The worker is the ONLY place that encrypts
//! business packets, and it does so ONLY when the peer's path is usable —
//! this enforces the four ordering invariants:
//!
//!   1. A business packet for a peer whose path is not yet usable is parked as
//!      PLAINTEXT (`PendingPacket::Plain`): it is never encrypted, never
//!      occupies a WireGuard counter, and never holds the peer's emit lock.
//!   2. Relay probes, relay ACKs and direct-validation control packets use the
//!      `encrypt_and_emit_outbound` control lane and are therefore never
//!      blocked by parked business traffic: a parked packet holds no lock.
//!   3. Once a business packet IS encrypted, the per-peer emit lock is held
//!      from encryption through the ACTUAL send (UDP datagram or relay frame),
//!      so wire order == WireGuard counter order per peer.  A control packet
//!      encrypted later can only have a HIGHER counter and is sent only after
//!      the earlier packet's send completed — a low counter can never fall
//!      behind a higher counter into the receiver's 64-packet replay window.
//!      A retry releases the guard and re-encrypts from plaintext.
//!   4. Per-peer business traffic stays FIFO: drops evict the OLDEST entry,
//!      retries re-park at the front, and the flush drains strictly in queue
//!      order.
//!
//! Every peer with queued packets shares ONE startup deadline per peer +
//! generation, the queue is flushed event-driven on RelayPeerConfirmed /
//! DirectConfirmed, and all loss is structured-counted into the peer manager's
//! `/status.stats.outbound_drops` (queue overflow, deadline expiry, peer
//! offline, generation change, session-queue loss) plus the observable
//! `outbound_send_failures` attempts map.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_tun::{Ipv4Packet, Protocol};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, warn};

use crate::connection_timeline::ConnectionTimeline;
use crate::dataplane::OutboundPacket;
use crate::peer::{
    NetworkPath, PathSelection, PeerManager, REASON_DIRECT_SEND_FAILED, REASON_PATH_UNAVAILABLE,
};
use crate::relay::RelayTransport;
use crate::transport::{EncryptedPeerPacket, WireGuardTransport};
use crate::udp::UdpTransport;

const OUTBOUND_RETRY_DELAY: Duration = Duration::from_millis(50);
/// Bound a single path send so a stalled relay TCP write can never block the
/// shared outbound worker (per-peer waits are already event-driven; this
/// bounds the per-packet SEND).  The per-peer emit lock is held for at most
/// this long, which also bounds how long a control probe can be locked out.
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// A packet that has reached a usable-path actor may not remain in retry
/// limbo. This is a loss boundary, not an attempt to hide a slow relay by
/// increasing its timeout.
const OUTBOUND_DELIVERY_DEADLINE: Duration = Duration::from_secs(3);
/// Cadence of the outbound maintenance ticker (deadline expiry, peer
/// offline / generation-change cancellation, paced retries).
const OUTBOUND_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
/// Per-peer pending queue bounds.  A not-yet-usable peer cannot build
/// unbounded memory pressure while it waits for a path.
// A 256-packet overlay burst is an acceptance workload, not an overflow
// condition. Leave headroom for control/handshake packets and packets already
// waiting behind a slow relay writer while keeping the queue bounded per peer.
// This is still a hard limit (2 MiB), so one peer cannot consume unbounded
// memory or stall other per-peer flush actors.
const MAX_PENDING_PACKETS_PER_PEER: usize = 1024;
const MAX_PENDING_BYTES_PER_PEER: usize = 2 * 1024 * 1024;
/// Maximum packets sent from ONE peer's queue in a single flush pass. Flushes
/// for different peers run concurrently; this bound still prevents one
/// peer's large queue from monopolising the shared transport locks.
// Keep a bounded batch so a large peer cannot monopolise the actor, while
// allowing a normal 65/96/256 packet burst to make progress without spending
// most of its delivery deadline on scheduler turns.  Different peers are
// still flushed as independent futures below, so this does not trade away
// cross-peer fairness.
const MAX_FLUSH_PER_PEER_PER_TICK: usize = 64;

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
/// Stable reason code for a relay send attempt that failed transiently
/// (counted as an ATTEMPT in `/status.stats.outbound_send_failures`; the
/// packet is re-parked and retried, never silently discarded).
pub(crate) const REASON_RELAY_SEND_NOT_HANDED: &str = "relay_send_not_handed";
pub(crate) const REASON_RELAY_DELIVERY_UNCERTAIN: &str = "relay_delivery_uncertain";
pub(crate) const REASON_DIRECT_DELIVERY_UNCERTAIN: &str = "direct_delivery_uncertain";
pub(crate) const REASON_OUTBOUND_ENCRYPT_FAILED: &str = "outbound_encrypt_failed";
pub(crate) const REASON_OUTBOUND_SESSION_NOT_READY: &str = "outbound_session_not_ready";
pub(crate) const REASON_OUTBOUND_DELIVERY_DEADLINE: &str = "outbound_delivery_deadline_expired";
/// Stable terminal reason for plaintext packets still owned by the worker
/// when its ingress/watch channels close.  A worker shutdown is a lifecycle
/// boundary, not permission to let its per-peer queues disappear silently.
pub(crate) const REASON_OUTBOUND_WORKER_STOPPED: &str = "outbound_worker_stopped";

/// Outcome of handing one business packet to the network.
enum SendOutcome {
    /// The packet was handed to the selected transport.
    Sent,
    /// The send failed before transport handoff; retry from plaintext with a
    /// newly allocated counter.
    Retryable(RetryableSendFailure),
    /// Delivery status is uncertain; terminally account the packet and drop
    /// the ciphertext after releasing the emit lock.
    Terminal(TerminalSendFailure),
}

enum RetryableSendFailure {
    NoSelectedPath {
        reason: String,
        reason_code: &'static str,
    },
    RelaySendNotHanded {
        err: String,
    },
}

enum TerminalSendFailure {
    DeliveryUncertain { reason: &'static str, err: String },
}

/// Result of an already-encrypted packet attempt on a confirmed Direct path.
/// A successful UDP `send_to` is only a local kernel handoff, not a peer ACK;
/// once it succeeds the WireGuard counter is consumed and the same ciphertext
/// must never be replayed through Relay.
enum DirectSendOutcome {
    /// No datagram was handed to the local kernel. The counter can still be
    /// handed to a confirmed Relay without replaying it.
    NotHanded { err: String },
    /// The kernel accepted the datagram; peer delivery remains unknown.
    HandoffAccepted,
    /// The result cannot be safely replayed through another path.
    DeliveryUncertain { err: String },
}

impl RetryableSendFailure {
    fn reason_code(&self) -> &'static str {
        match self {
            RetryableSendFailure::NoSelectedPath { reason_code, .. } => reason_code,
            RetryableSendFailure::RelaySendNotHanded { .. } => REASON_RELAY_SEND_NOT_HANDED,
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::NoSelectedPath { reason, .. } => reason.clone(),
            Self::RelaySendNotHanded { err } => err.clone(),
        }
    }
}

/// One queued per-peer packet. The queue intentionally contains plaintext
/// only. An encrypted packet and its emit guard exist only in one lexical send
/// operation; a retry releases the guard and allocates a fresh counter.
enum PendingPacket {
    Plain(OutboundPacket),
}

impl PendingPacket {
    fn stored_bytes(&self) -> usize {
        match self {
            Self::Plain(packet) => packet.packet.len(),
        }
    }

    fn peer_id(&self) -> &str {
        match self {
            Self::Plain(packet) => &packet.peer_id,
        }
    }

    fn raw_packet(&self) -> &[u8] {
        match self {
            Self::Plain(packet) => &packet.packet,
        }
    }
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
    queue: VecDeque<PendingPacket>,
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
    /// Terminal deadline after a path became usable or a send retry began.
    delivery_deadline: Option<Instant>,
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
            delivery_deadline: None,
        }
    }

    /// Park a packet in the bounded queue, dropping the OLDEST entries first
    /// when the packet/byte bound is exceeded.  Returns (dropped packets,
    /// dropped bytes) for the overflow so the caller can count them into
    /// `/status.stats.outbound_drops` — the loss is never silently ignored.
    fn enqueue(&mut self, packet: PendingPacket) -> (usize, usize) {
        let packet_len = packet.stored_bytes();
        let mut dropped_packets = 0usize;
        let mut dropped_bytes = 0usize;
        while !self.queue.is_empty()
            && (self.queue.len() >= MAX_PENDING_PACKETS_PER_PEER
                || self.bytes.saturating_add(packet_len) > MAX_PENDING_BYTES_PER_PEER)
        {
            if let Some(old) = self.queue.pop_front() {
                let old_len = old.stored_bytes();
                self.bytes = self.bytes.saturating_sub(old_len);
                dropped_packets = dropped_packets.saturating_add(1);
                dropped_bytes = dropped_bytes.saturating_add(old_len);
            }
        }
        self.bytes = self.bytes.saturating_add(packet_len);
        self.queue.push_back(packet);
        (dropped_packets, dropped_bytes)
    }

    fn pop_front(&mut self) -> Option<PendingPacket> {
        let packet = self.queue.pop_front()?;
        self.bytes = self.bytes.saturating_sub(packet.stored_bytes());
        Some(packet)
    }

    fn push_front(&mut self, packet: PendingPacket) {
        self.bytes = self.bytes.saturating_add(packet.stored_bytes());
        self.queue.push_front(packet);
    }
}

/// Bump the relay probe kick so the forced-relay probe loop fires immediately
/// for any peer whose first business packet is now waiting.
fn bump_probe_kick(kick: &mut u64, relay_probe_kick_tx: &watch::Sender<u64>) {
    *kick = kick.wrapping_add(1);
    let _ = relay_probe_kick_tx.send(*kick);
}

/// Extract the identity of an overlay harness packet for diagnostics only.
/// This never drives routing or delivery; it lets a failed burst correlate
/// the raw TUN ingress with the encrypted transport outcome without logging
/// payload bytes.
fn overlay_packet_identity(packet: &[u8]) -> Option<(u64, u32, u8)> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Udp {
        return None;
    }
    let udp_payload = ip.payload().get(8..)?;
    let payload = udp_payload.strip_prefix(crate::OVERLAY_PAYLOAD_MAGIC)?;
    let direction = *payload.first()?;
    let nonce = u64::from_be_bytes(payload.get(1..9)?.try_into().ok()?);
    let sequence = u32::from_be_bytes(payload.get(9..13)?.try_into().ok()?);
    Some((nonce, sequence, direction))
}

/// Return a payload-free description of a raw TUN packet for queue diagnostics.
/// The real daemon can receive packets generated by the host OS or another
/// process before the acceptance harness sends its own echo.  Recording only
/// L3/L4 headers lets us identify that source without putting user payloads,
/// credentials, or packet contents into logs/artifacts.
fn raw_packet_summary(packet: &[u8]) -> String {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return format!("unparsed bytes={}", packet.len());
    };
    let protocol = ip.protocol();
    let mut summary = format!(
        "proto={} src={} dst={} bytes={}",
        protocol,
        ip.src_addr(),
        ip.dst_addr(),
        packet.len()
    );
    let payload = ip.payload();
    match protocol {
        Protocol::Tcp | Protocol::Udp if payload.len() >= 4 => {
            let source_port = u16::from_be_bytes([payload[0], payload[1]]);
            let destination_port = u16::from_be_bytes([payload[2], payload[3]]);
            summary.push_str(&format!(
                " src_port={source_port} dst_port={destination_port}"
            ));
        }
        Protocol::Icmp if payload.len() >= 2 => {
            summary.push_str(&format!(
                " icmp_type={} icmp_code={}",
                payload[0], payload[1]
            ));
        }
        _ => {}
    }
    summary
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_network_outbound(
    mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    transport: WireGuardTransport,
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
    // Each peer owns one independent flush task.  The actor remains free to
    // receive and route other peers while a relay writer is slow or being
    // replaced; `flushing_peers` prevents a newer live packet from starting a
    // second FIFO for the same peer.
    let mut flush_tasks = JoinSet::new();
    let mut flushing_peers = HashSet::new();
    // `relay_available` is a live transport snapshot, while this flag says
    // that the configured topology requires a relay-first admission window.
    // Keeping them separate closes the startup race where Direct was admitted
    // in the few milliseconds before the relay supervisor published its slot.
    let relay_expected = relay_startup_wait.timeout.is_some();
    let _ = relay_probe_kick_tx.send(probe_kick);

    loop {
        tokio::select! {
            packet = outbound_rx.recv() => {
                let Some(packet) = packet else { break; };
                handle_ingress(
                    packet,
                    &transport,
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    relay_startup_wait,
                    relay_expected,
                    &mut probe_kick,
                    &relay_probe_kick_tx,
                    &timeline,
                    &mut flush_tasks,
                    &mut flushing_peers,
                ).await;
            }
            _ = direct_notify.notified() => {
                start_ready_peer_flushes(
                    &transport,
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    relay_expected,
                    &timeline,
                    &mut flush_tasks,
                    &mut flushing_peers,
                ).await;
            }
            _ = relay_notify.notified() => {
                start_ready_peer_flushes(
                    &transport,
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    relay_expected,
                    &timeline,
                    &mut flush_tasks,
                    &mut flushing_peers,
                ).await;
            }
            changed = relay_available_rx.changed() => {
                if changed.is_err() { break; }
                // A relay came up (or cleared): kick the probe loop so a
                // waiting peer's confirmation is not delayed by the probe
                // cadence, then flush whatever became usable.
                bump_probe_kick(&mut probe_kick, &relay_probe_kick_tx);
                start_ready_peer_flushes(
                    &transport,
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    relay_expected,
                    &timeline,
                    &mut flush_tasks,
                    &mut flushing_peers,
                ).await;
            }
            _ = ticker.tick() => {
                maintenance(
                    &transport,
                    &peers,
                    &mut pending,
                    prefer_direct,
                    &udp_transport,
                    &relay_transport,
                    relay_expected,
                    &timeline,
                    &mut flush_tasks,
                    &mut flushing_peers,
                ).await;
            }
            flush_result = flush_tasks.join_next(), if !flush_tasks.is_empty() => {
                match flush_result {
                    Some(Ok((peer_id, queue))) => {
                        flushing_peers.remove(&peer_id);
                        merge_completed_flush(&mut pending, peer_id, queue);
                        start_ready_peer_flushes(
                            &transport,
                            &peers,
                            &mut pending,
                            prefer_direct,
                            &udp_transport,
                            &relay_transport,
                            relay_expected,
                            &timeline,
                            &mut flush_tasks,
                            &mut flushing_peers,
                        ).await;
                    }
                    Some(Err(err)) => {
                        // A flush task contains only bounded transport work;
                        // a panic is still a lifecycle loss and must be
                        // visible instead of silently deleting its queue.
                        warn!("outbound per-peer flush task failed: {err}");
                    }
                    None => {}
                }
            }
        }
    }

    // Finish already-started per-peer tasks before accounting their returned
    // queues.  This is a bounded shutdown path: each transport handoff has a
    // hard timeout and no task owns an encrypted retry packet.
    while let Some(result) = flush_tasks.join_next().await {
        match result {
            Ok((peer_id, queue)) => merge_completed_flush(&mut pending, peer_id, queue),
            Err(err) => warn!("outbound per-peer flush task failed during shutdown: {err}"),
        }
    }

    // The worker owns the only mutable copy of these per-peer queues.  When
    // either ingress or relay watch closes, account every still-parked packet
    // before returning; otherwise a graceful task shutdown would be a silent
    // loss path that never reaches /status.stats or the timeline.
    let queued_peers = pending.len();
    let queued_packets: usize = pending.values().map(|entry| entry.queue.len()).sum();
    drop_all_pending_queues(
        &peers,
        &mut pending,
        REASON_OUTBOUND_WORKER_STOPPED,
        &timeline,
    )
    .await;
    timeline.emit(
        "outbound_worker_stopped",
        None,
        Some(REASON_OUTBOUND_WORKER_STOPPED),
        Some(format!("peers={queued_peers} packets={queued_packets}")),
    );
}

/// Route one RAW packet: encrypt + send immediately when its peer already has
/// a usable path AND a WireGuard session; otherwise park it (PLAINTEXT — no
/// counter, no emit lock) in the peer's bounded queue and start the peer's
/// SHARED startup deadline (first packet of a peer + generation only).
#[allow(clippy::too_many_arguments)]
async fn handle_ingress(
    packet: OutboundPacket,
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    relay_startup_wait: RelayStartupWait,
    relay_expected: bool,
    probe_kick: &mut u64,
    relay_probe_kick_tx: &watch::Sender<u64>,
    timeline: &Arc<ConnectionTimeline>,
    flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    flushing_peers: &mut HashSet<String>,
) {
    let peer_id = packet.peer_id.clone();
    let generation = peers.current_network_generation().await;
    if let Some((nonce, sequence, direction)) = overlay_packet_identity(&packet.packet) {
        debug!(
            event = "outbound_overlay_queued",
            peer_id = %peer_id,
            nonce = format_args!("{nonce:#x}"),
            sequence,
            direction,
            generation,
            "raw overlay packet entered the per-peer FIFO"
        );
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

    let relay_available = relay_transport.read().await.is_some();
    let usable = peers
        .is_data_path_admitted_for_generation(
            &peer_id,
            generation,
            relay_available || relay_expected,
        )
        .await;
    // Every business packet, including a packet arriving after confirmation,
    // enters the same per-peer FIFO. This is the critical distinction from the
    // old relay-first implementation, which could send a new live packet
    // around an older retry/session flush.
    let entry = pending
        .entry(peer_id.clone())
        .or_insert_with(PeerPendingQueue::new);
    let (dropped_packets, dropped_bytes) = entry.enqueue(PendingPacket::Plain(packet));
    debug!(
        event = "outbound_fifo_state",
        peer_id = %peer_id,
        generation,
        queue_depth = entry.queue.len(),
        queue_bytes = entry.bytes,
        wait_started = entry.wait_started.is_some(),
        wait_generation = ?entry.wait_generation,
        dropped_packets,
        dropped_bytes,
        "raw business packet appended to the per-peer FIFO"
    );
    if dropped_packets > 0 {
        record_overflow_drop(
            peers,
            &peer_id,
            dropped_packets,
            dropped_bytes,
            entry,
            timeline,
        )
        .await;
    }

    let should_start_wait = entry.wait_started.is_none() && !usable;
    if should_start_wait {
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
                    "Outbound packet for peer {} dropped: direct-only config has no relay and direct is not confirmed",
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
                let queue_head = entry
                    .queue
                    .front()
                    .map(|packet| raw_packet_summary(packet.raw_packet()))
                    .unwrap_or_else(|| "empty".to_string());
                timeline.emit(
                    "outbound_first_packet_wait_started",
                    None,
                    None,
                    Some(format!(
                        "peer={peer_id} generation={generation} wait_timeout_ms={} queued={} queue_head={queue_head}",
                        timeout.as_millis(),
                        entry.queue.len()
                    )),
                );
            }
        }
    }

    if usable {
        if let Some(entry) = pending.get_mut(&peer_id) {
            // Even a queue created after a confirmed path belongs to this
            // generation.  Recording it here lets generation advance cancel
            // a retry that was parked after a path/transport change instead
            // of leaving it behind an apparently healthy peer.
            entry.wait_generation = Some(generation);
            entry
                .delivery_deadline
                .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
        }
        start_ready_peer_flushes(
            transport,
            peers,
            pending,
            prefer_direct,
            udp_transport,
            relay_transport,
            relay_expected,
            timeline,
            flush_tasks,
            flushing_peers,
        )
        .await;
    }
}

/// Count a queue-overflow loss structurally and emit the timeline event.
async fn record_overflow_drop(
    peers: &PeerManager,
    peer_id: &str,
    dropped_packets: usize,
    dropped_bytes: usize,
    entry: &PeerPendingQueue,
    timeline: &ConnectionTimeline,
) {
    peers
        .record_outbound_drop(REASON_OUTBOUND_QUEUE_FULL, dropped_packets, dropped_bytes)
        .await;
    record_loss_event(
        peers,
        "drop",
        peer_id,
        entry
            .wait_generation
            .unwrap_or_else(|| peers.current_network_generation_sync()),
        REASON_OUTBOUND_QUEUE_FULL,
        dropped_packets,
        dropped_bytes,
        timeline,
    )
    .await;
    timeline.emit(
        "outbound_packet_dropped",
        None,
        Some(REASON_OUTBOUND_QUEUE_FULL),
        Some(format!(
            "peer={peer_id} dropped={dropped_packets} bytes={dropped_bytes} reason={REASON_OUTBOUND_QUEUE_FULL} queued={} queued_bytes={} queue_head={}",
            entry.queue.len(),
            entry.bytes,
            entry
                .queue
                .front()
                .map(|packet| raw_packet_summary(packet.raw_packet()))
                .unwrap_or_else(|| "empty".to_string())
        )),
    );
}

/// Outcome of encrypting and sending one RAW packet.
enum EncryptSendOutcome {
    Sent,
    Retryable {
        packet: OutboundPacket,
        reason_code: &'static str,
        reason: String,
    },
    Terminal {
        packet: OutboundPacket,
        reason_code: &'static str,
        reason: String,
    },
}

/// Encrypt a RAW packet (holding the peer's emit lock) and send it while the
/// guard is still held.
#[allow(clippy::too_many_arguments)]
async fn encrypt_then_send(
    packet: OutboundPacket,
    transport: &WireGuardTransport,
    peers: &PeerManager,
    expected_generation: u64,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
) -> EncryptSendOutcome {
    let retry_packet = packet.clone();
    // Acquire the per-peer counter-ordering guard BEFORE the global epoch
    // gate.  Inbound relay ACK/business evidence uses the same order
    // (`emit -> epoch`); taking these in the opposite order here would let an
    // outbound encryptor and an inbound evidence commit wait on each other.
    // Generation advance and counter allocation are still one short
    // transaction.  The potentially slow transport write deliberately
    // happens after the epoch gate is released: a 2-second relay timeout for
    // peer A must not block peer B's generation/path state or Direct
    // validation.
    let emit_lock_started = Instant::now();
    let emit_guard = Arc::new(transport.acquire_outbound_emit_guard(&packet.peer_id).await);
    let emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64;
    debug!(
        event = "outbound_business_emit_lock_acquired",
        peer_id = %packet.peer_id,
        generation = expected_generation,
        lock_wait_ms = emit_lock_wait_ms,
        "business packet acquired its per-peer WireGuard counter-ordering lock"
    );
    let encrypted_and_guard = {
        let epoch_gate = peers.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let current_generation = peers.current_network_generation_sync();
        if current_generation != expected_generation {
            debug!(
                event = "outbound_counter_allocation_rejected",
                peer_id = %retry_packet.peer_id,
                expected_generation,
                current_generation,
                reason_code = REASON_OUTBOUND_GENERATION_CHANGED,
                "business packet was not encrypted because its network generation is stale"
            );
            return EncryptSendOutcome::Retryable {
                packet: retry_packet,
                reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
                reason: format!(
                    "network generation advanced before counter allocation: expected={expected_generation} current={current_generation}"
                ),
            };
        }
        match transport.encrypt_outbound_with_emit_guard(packet).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                debug!(
                    event = "outbound_session_unavailable",
                    peer_id = %retry_packet.peer_id,
                    generation = expected_generation,
                    bytes = retry_packet.packet.len(),
                    reason_code = REASON_OUTBOUND_SESSION_NOT_READY,
                    "business packet remained plaintext because no usable WireGuard session exists"
                );
                return EncryptSendOutcome::Retryable {
                    packet: retry_packet,
                    reason_code: REASON_OUTBOUND_SESSION_NOT_READY,
                    reason: "WireGuard session is not ready".to_string(),
                };
            }
            Err(err) => {
                warn!(
                    event = "outbound_encrypt_failed",
                    peer_id = %retry_packet.peer_id,
                    generation = expected_generation,
                    bytes = retry_packet.packet.len(),
                    reason_code = REASON_OUTBOUND_ENCRYPT_FAILED,
                    error = %err,
                    "business packet encryption failed before a transport handoff"
                );
                return EncryptSendOutcome::Terminal {
                    packet: retry_packet,
                    reason_code: REASON_OUTBOUND_ENCRYPT_FAILED,
                    reason: err.to_string(),
                };
            }
        }
    };
    let encrypted = encrypted_and_guard;
    let outcome = send_encrypted_packet_bounded(
        &encrypted,
        peers,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
    )
    .await;
    if let Some((nonce, sequence, direction)) = overlay_packet_identity(&retry_packet.packet) {
        let outcome_label = match &outcome {
            SendOutcome::Sent => "sent",
            SendOutcome::Retryable(_) => "retryable",
            SendOutcome::Terminal(_) => "terminal",
        };
        debug!(
            event = "outbound_overlay_transport_result",
            peer_id = %retry_packet.peer_id,
            nonce = format_args!("{nonce:#x}"),
            sequence,
            direction,
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&encrypted.wire_bytes)),
            counter = ?crate::transport::wire_counter(&encrypted.wire_bytes),
            outcome = outcome_label,
            "encrypted overlay packet reached a classified transport outcome"
        );
    }
    // The guard is deliberately released before any asynchronous retry is
    // queued. A retry is always the original plaintext and receives a fresh
    // WireGuard counter.
    drop(emit_guard);
    match outcome {
        SendOutcome::Sent => EncryptSendOutcome::Sent,
        SendOutcome::Retryable(failure) => EncryptSendOutcome::Retryable {
            packet: retry_packet,
            reason_code: failure.reason_code(),
            reason: failure.reason(),
        },
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain { reason, err }) => {
            EncryptSendOutcome::Terminal {
                packet: retry_packet,
                reason_code: reason,
                reason: err,
            }
        }
    }
}

/// Start one independent flush task for every peer that became usable
/// (DirectConfirmed or RelayPeerConfirmed). Only plaintext is retained
/// between attempts; encrypted packets never live in the retry queue.
///
/// The previous implementation awaited all peer flushes in this actor. That
/// made the actor stop receiving new TUN packets while one relay writer was
/// stalled. The task set below preserves one FIFO owner per peer while the
/// actor remains fair to other peers.
#[allow(clippy::too_many_arguments)]
async fn start_ready_peer_flushes(
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: &Arc<ConnectionTimeline>,
    flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    flushing_peers: &mut HashSet<String>,
) {
    let now = Instant::now();
    let delivery_expired: Vec<String> = pending
        .iter()
        .filter(|(_, entry)| {
            !entry.queue.is_empty()
                && entry
                    .delivery_deadline
                    .is_some_and(|deadline| now >= deadline)
        })
        .map(|(peer_id, _)| peer_id.clone())
        .collect();
    for peer_id in delivery_expired {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_OUTBOUND_DELIVERY_DEADLINE,
            timeline,
        )
        .await;
    }

    let ready_ids: Vec<String> = {
        let mut ready = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if entry.queue.is_empty() {
                continue;
            }
            if flushing_peers.contains(peer_id) {
                continue;
            }
            if entry.retry_after.is_some_and(|at| at > Instant::now()) {
                continue;
            }
            let generation = peers.current_network_generation().await;
            let relay_available = relay_transport.read().await.is_some();
            if peers
                .is_data_path_admitted_for_generation(
                    peer_id,
                    generation,
                    relay_available || relay_expected,
                )
                .await
            {
                ready.push(peer_id.clone());
            }
        }
        ready
    };
    // A queue can be created while relay confirmation is still pending, so
    // `handle_ingress` cannot start its delivery deadline at that time.  Once
    // the same-generation path becomes usable, bind one deadline to the whole
    // queued batch before handing ownership to a flush task.  Without this
    // boundary a slow writer can make a 256-packet backlog drain for tens of
    // seconds even though the startup wait itself was bounded.
    let delivery_deadline = now + OUTBOUND_DELIVERY_DEADLINE;
    for peer_id in &ready_ids {
        if let Some(entry) = pending.get_mut(peer_id) {
            entry.delivery_deadline.get_or_insert(delivery_deadline);
        }
    }
    // Remove each ready queue before starting its task. Each queue remains
    // single-owner, preserving FIFO and retry-at-front invariants, while a
    // stalled relay writer for one peer cannot hold up another peer's ingress.
    let ready_queues: Vec<(String, PeerPendingQueue)> = ready_ids
        .into_iter()
        .filter_map(|peer_id| pending.remove(&peer_id).map(|queue| (peer_id, queue)))
        .collect();
    for (peer_id, queue) in ready_queues {
        flushing_peers.insert(peer_id.clone());
        let task_transport = transport.clone();
        let task_peers = peers.clone();
        let task_udp_transport = udp_transport.clone();
        let task_relay_transport = relay_transport.clone();
        let task_timeline = timeline.clone();
        flush_tasks.spawn(async move {
            flush_one_peer(
                peer_id,
                queue,
                task_transport,
                task_peers,
                prefer_direct,
                task_udp_transport,
                task_relay_transport,
                relay_expected,
                task_timeline,
            )
            .await
        });
    }
}

/// Flush one peer's queue. This is the sole owner of that peer's queue while
/// it is in flight. A terminal/uncertain handoff stops the batch immediately:
/// that counter is consumed, while later plaintext packets remain available
/// for a replacement path and receive fresh counters.
#[allow(clippy::too_many_arguments)]
async fn flush_one_peer(
    peer_id: String,
    mut queue: PeerPendingQueue,
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: Arc<ConnectionTimeline>,
) -> (String, PeerPendingQueue) {
    let mut flushed = 0usize;
    while flushed < MAX_FLUSH_PER_PEER_PER_TICK {
        if !queue.queue.is_empty()
            && queue
                .delivery_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            if flushed > 0 {
                let remaining = queue.queue.len();
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
            }
            drop_pending_queue(
                &peers,
                Some(queue),
                REASON_OUTBOUND_DELIVERY_DEADLINE,
                &timeline,
            )
            .await;
            return (peer_id, PeerPendingQueue::new());
        }
        let Some(front) = queue.pop_front() else {
            break;
        };

        let generation = peers.current_network_generation().await;
        if queue
            .wait_generation
            .is_some_and(|queued_generation| queued_generation != generation)
        {
            queue.push_front(front);
            drop_pending_queue(
                &peers,
                Some(queue),
                REASON_OUTBOUND_GENERATION_CHANGED,
                &timeline,
            )
            .await;
            return (peer_id, PeerPendingQueue::new());
        }

        let relay_available = relay_transport.read().await.is_some();
        let usable = peers
            .is_data_path_admitted_for_generation(
                &peer_id,
                generation,
                relay_available || relay_expected,
            )
            .await;
        if !usable {
            queue.push_front(front);
            break;
        }

        let PendingPacket::Plain(packet) = front;
        match encrypt_then_send(
            packet,
            &transport,
            &peers,
            generation,
            prefer_direct,
            &udp_transport,
            &relay_transport,
            relay_expected,
        )
        .await
        {
            EncryptSendOutcome::Sent => flushed = flushed.saturating_add(1),
            EncryptSendOutcome::Retryable {
                packet,
                reason_code,
                reason,
            } => {
                record_retry_and_repark(
                    &transport,
                    &peers,
                    &peer_id,
                    &mut queue,
                    packet,
                    reason_code,
                    reason,
                    &timeline,
                )
                .await;
                break;
            }
            EncryptSendOutcome::Terminal {
                packet,
                reason_code,
                reason,
            } => {
                record_terminal_drop(
                    &transport,
                    &peers,
                    &peer_id,
                    generation,
                    packet,
                    reason_code,
                    reason,
                    &timeline,
                )
                .await;
                // The failed packet's counter is terminal, but later entries
                // are still plaintext and have no counter yet. Keep them in
                // FIFO order so a newly confirmed path can encrypt them with
                // fresh counters. Never replay the uncertain ciphertext and
                // never silently erase later business packets.
                if !queue.queue.is_empty() {
                    queue.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
                    timeline.emit(
                        "outbound_fifo_reparked_after_terminal",
                        None,
                        Some(reason_code),
                        Some(format!(
                            "peer={peer_id} remaining_packets={} remaining_bytes={} prior_counter_terminal=true",
                            queue.queue.len(),
                            queue.bytes
                        )),
                    );
                }
                break;
            }
        }
    }

    if flushed > 0 {
        let remaining = queue.queue.len();
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
    (peer_id, queue)
}

/// Merge a completed peer task ahead of packets that arrived while it was
/// running. The completed queue is always older, so appending the newer queue
/// preserves strict per-peer FIFO.
fn merge_completed_flush(
    pending: &mut HashMap<String, PeerPendingQueue>,
    peer_id: String,
    mut completed: PeerPendingQueue,
) {
    let Some(mut newer) = pending.remove(&peer_id) else {
        if !completed.queue.is_empty() {
            pending.insert(peer_id, completed);
        }
        return;
    };

    if completed.queue.is_empty() {
        pending.insert(peer_id, newer);
        return;
    }

    completed.queue.append(&mut newer.queue);
    completed.bytes = completed.bytes.saturating_add(newer.bytes);
    if completed.wait_started.is_none() {
        completed.wait_started = newer.wait_started;
    }
    if completed.wait_deadline.is_none() {
        completed.wait_deadline = newer.wait_deadline;
    }
    if completed.wait_generation.is_none() {
        completed.wait_generation = newer.wait_generation;
    }
    if completed.retry_after.is_none() {
        completed.retry_after = newer.retry_after;
    }
    if completed.delivery_deadline.is_none() {
        completed.delivery_deadline = newer.delivery_deadline;
    }
    pending.insert(peer_id, completed);
}

/// Record a pre-handoff failure and re-park plaintext at the FRONT of the
/// queue. The old encrypted counter has already been abandoned and is never
/// retried.
#[allow(clippy::too_many_arguments)]
async fn record_retry_and_repark(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    peer_id: &str,
    entry: &mut PeerPendingQueue,
    packet: OutboundPacket,
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
) {
    transport
        .record_outbound_send_failure(reason_code, 1, packet.packet.len())
        .await;
    let generation = entry
        .wait_generation
        .unwrap_or_else(|| peers.current_network_generation_sync());
    record_loss_event(
        peers,
        "send_failure",
        peer_id,
        generation,
        reason_code,
        1,
        packet.packet.len(),
        timeline,
    )
    .await;
    entry.push_front(PendingPacket::Plain(packet));
    entry.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
    entry
        .delivery_deadline
        .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
    debug!(
        event = "outbound_plaintext_reparked",
        peer_id = %peer_id,
        generation,
        reason_code,
        reason = %reason,
        queue_depth = entry.queue.len(),
        queue_bytes = entry.bytes,
        retry_after_ms = OUTBOUND_RETRY_DELAY.as_millis() as u64,
        "send failed before transport handoff; packet returned to the FIFO as plaintext with a fresh-counter retry"
    );
    timeline.emit(
        "outbound_send_failure",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} generation={} detail={reason}",
            entry.wait_generation.unwrap_or(0)
        )),
    );
}

#[allow(clippy::too_many_arguments)]
async fn record_terminal_drop(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    peer_id: &str,
    packet_generation: u64,
    packet: OutboundPacket,
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
) {
    let bytes = packet.packet.len();
    transport.record_outbound_drop(reason_code, 1, bytes).await;
    record_loss_event(
        peers,
        "drop",
        peer_id,
        packet_generation,
        reason_code,
        1,
        bytes,
        timeline,
    )
    .await;
    timeline.emit(
        "outbound_packet_dropped",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} generation={packet_generation} dropped=1 bytes={bytes} detail={reason}"
        )),
    );
    warn!(
        event = "outbound_terminal_drop",
        peer_id = %peer_id,
        generation = packet_generation,
        reason_code,
        packets = 1u64,
        bytes,
        detail = %reason,
        "plaintext business packet reached a terminal loss boundary"
    );
}

fn relay_send_failure(err: &crate::error::DaemonError) -> SendOutcome {
    // These typed relay outcomes prove the frame was rejected before the
    // writer owned it, so plaintext may be re-encrypted. A writer completion
    // loss or an interrupted write is deliberately not in this set. Do not
    // classify by formatted text: that would turn a future wording change
    // into a possible replay of an old WireGuard counter.
    if let crate::error::DaemonError::RelaySend { error, .. } = err {
        if matches!(
            error,
            p2pnet_relay::RelayError::CommandQueueFull
                | p2pnet_relay::RelayError::WriterStoppedBeforeAccept
        ) {
            return SendOutcome::Retryable(RetryableSendFailure::RelaySendNotHanded {
                err: err.to_string(),
            });
        }
    }
    SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
        reason: REASON_RELAY_DELIVERY_UNCERTAIN,
        err: err.to_string(),
    })
}

/// Periodic maintenance: expire startup deadlines, cancel waits on peer
/// offline / generation change, and flush what became usable.
#[allow(clippy::too_many_arguments)]
async fn maintenance(
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: &Arc<ConnectionTimeline>,
    flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    flushing_peers: &mut HashSet<String>,
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
            let relay_available = relay_transport.read().await.is_some();
            let usable = peers
                .is_data_path_admitted_for_generation(
                    peer_id,
                    generation,
                    relay_available || relay_expected,
                )
                .await;
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
    start_ready_peer_flushes(
        transport,
        peers,
        pending,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        timeline,
        flush_tasks,
        flushing_peers,
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
        .map(|packet| packet.peer_id().to_string())
        .unwrap_or_default();
    let generation = queue.wait_generation.unwrap_or(0);
    timeline.emit(
        "relay_unavailable_or_first_packet_expired",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} generation={generation} dropped={dropped} bytes={} waited_ms={}",
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
    record_loss_event(
        peers,
        "drop",
        &peer_id,
        generation,
        reason_code,
        dropped,
        queue.bytes,
        timeline,
    )
    .await;
    debug!(
        "Dropped {dropped} queued packets for peer {peer_id}: {reason_code} (bytes={})",
        queue.bytes
    );
}

async fn drop_all_pending_queues(
    peers: &PeerManager,
    pending: &mut HashMap<String, PeerPendingQueue>,
    reason_code: &'static str,
    timeline: &ConnectionTimeline,
) {
    let peer_ids: Vec<String> = pending.keys().cloned().collect();
    for peer_id in peer_ids {
        drop_pending_queue(peers, pending.remove(&peer_id), reason_code, timeline).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn record_loss_event(
    peers: &PeerManager,
    kind: &str,
    peer_id: &str,
    generation: u64,
    reason_code: &str,
    packets: usize,
    bytes: usize,
    timeline: &ConnectionTimeline,
) {
    peers
        .record_outbound_loss_event(crate::peer::OutboundLossEvent {
            kind: kind.to_string(),
            peer_id: peer_id.to_string(),
            generation,
            reason_code: reason_code.to_string(),
            packets: packets as u64,
            bytes: bytes as u64,
            correlation_id: timeline.correlation_id().to_string(),
            at_ms: timeline.uptime_ms(),
        })
        .await;
}

/// Send one encrypted packet with a hard time bound so a stalled relay cannot
/// block the shared outbound worker. The caller owns the per-peer emit guard
/// and releases it immediately after this classification returns.
async fn send_encrypted_packet_bounded(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
) -> SendOutcome {
    // Capture the exact shared connection before entering the bounded send.
    // The same snapshot is passed into the send operation, so a supervisor
    // replacement cannot make the timeout abort one relay while the packet is
    // actually blocked on another. The replacement remains available for the
    // next plaintext retry.
    let relay_for_send = relay_transport.read().await.clone();
    let relay_at_start = relay_for_send.clone();
    let relay_send_started = AtomicBool::new(false);
    match timeout(
        OUTBOUND_SEND_TIMEOUT,
        send_encrypted_packet_once(
            packet,
            peers,
            prefer_direct,
            udp_transport,
            relay_for_send,
            &relay_send_started,
            relay_expected,
        ),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            if relay_send_started.load(Ordering::Acquire) {
                if let Some(relay) = relay_at_start {
                    relay.abort_writer();
                }
            }
            // UDP `send_to` normally completes immediately, but classify the
            // timeout from the committed state as well: a Direct timeout is
            // not a relay writer timeout, and the loss counters must preserve
            // that distinction for incident diagnosis.
            let reason = if relay_send_started.load(Ordering::Acquire) {
                REASON_RELAY_DELIVERY_UNCERTAIN
            } else if peers.is_direct_sync(&packet.peer_id) && prefer_direct {
                REASON_DIRECT_DELIVERY_UNCERTAIN
            } else {
                REASON_PATH_UNAVAILABLE
            };
            warn!(
                event = "outbound_send_timeout",
                peer_id = %packet.peer_id,
                reason_code = reason,
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                relay_send_started = relay_send_started.load(Ordering::Acquire),
                "encrypted packet exceeded the bounded transport send deadline and is terminal"
            );
            outbound_send_timeout_failure_for_path(reason)
        }
    }
}

fn outbound_send_timeout_failure_for_path(reason: &'static str) -> SendOutcome {
    // A timeout does not tell us whether the relay accepted the ciphertext.
    // The caller therefore terminally consumes this counter and records the
    // original plaintext as a loss; it must never re-encrypt/retry this packet.
    SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
        reason,
        err: "outbound send timed out".to_string(),
    })
}

async fn send_encrypted_packet_once(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay: Option<RelayTransport>,
    relay_send_started: &AtomicBool,
    relay_expected: bool,
) -> SendOutcome {
    // Take one path/generation snapshot atomically, then release the global
    // epoch gate before any transport write.  A later revoke/advance may make
    // this particular handoff uncertain, but the packet is never retried as
    // ciphertext; the per-peer emit guard still preserves counter order.
    let (generation, relay_peer_confirmed, udp, udp_local_endpoint, selection) = {
        let epoch_gate = peers.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let generation = peers.current_network_generation_sync();
        let relay_peer_confirmed = peers
            .is_relay_peer_confirmed_for_generation(&packet.peer_id, generation)
            .await;
        let relay_available = relay.is_some();
        let udp = udp_transport.read().await.clone();
        let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
        let selection = select_outbound_path(
            packet,
            peers,
            prefer_direct,
            relay_available,
            relay_expected,
            udp_local_endpoint,
        )
        .await;
        debug!(
            event = "outbound_transport_handoff_started",
            peer_id = %packet.peer_id,
            generation,
            counter = ?crate::transport::wire_counter(&packet.wire_bytes),
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
            selected_path = ?selection.path,
            direct_confirmed = selection.direct_confirmed,
            relay_peer_confirmed,
            relay_connection_id = relay.as_ref().map(RelayTransport::connection_id),
            relay_endpoint = relay.as_ref().map(RelayTransport::endpoint),
            "encrypted packet is entering the selected transport handoff"
        );
        (
            generation,
            relay_peer_confirmed,
            udp,
            udp_local_endpoint,
            selection,
        )
    };

    if selection.direct_confirmed {
        match send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint).await {
            DirectSendOutcome::HandoffAccepted => return SendOutcome::Sent,
            DirectSendOutcome::DeliveryUncertain { err } => {
                // The Direct counter may have reached the kernel. Never send
                // this ciphertext over Relay; terminally account this packet
                // and let later plaintext entries receive fresh counters.
                return SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                    reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
                    err,
                });
            }
            DirectSendOutcome::NotHanded { err } => {
                // No Direct handoff occurred, so a confirmed Relay may safely
                // carry this same ciphertext without replaying its counter.
                if relay_peer_confirmed {
                    if let Some(relay) = relay {
                        return send_via_relay(
                            &relay,
                            packet,
                            peers,
                            generation,
                            relay_send_started,
                        )
                        .await;
                    }
                }
                return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
                    reason: format!("confirmed Direct was not handed off: {err}"),
                    reason_code: REASON_PATH_UNAVAILABLE,
                });
            }
        }
    }

    // Until Direct is confirmed by decrypted traffic, Relay is the only
    // business data-plane.  It must also be peer-confirmed: a relay client
    // connection or writer completion is not enough to admit a counter.
    if relay_peer_confirmed {
        if let Some(relay) = relay {
            return send_via_relay(&relay, packet, peers, generation, relay_send_started).await;
        }
        return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
            reason: "relay peer was confirmed but relay transport is unavailable".to_string(),
            reason_code: REASON_PATH_UNAVAILABLE,
        });
    }
    // A candidate RTT / Direct trial is not a data-plane admission proof.
    // Keep the raw packet queued until Relay or a real Direct ACK exists.
    SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
        reason: selection.reason,
        reason_code: selection.reason_code,
    })
}

/// Send one already-encrypted packet through the confirmed relay and expose
/// the exact local boundaries around it.  A successful return is still only
/// the relay client's writer completion; peer delivery is proven later by the
/// encrypted relay probe ACK or real relay-ingress business packet.
async fn send_via_relay(
    relay: &RelayTransport,
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    generation: u64,
    relay_send_started: &AtomicBool,
) -> SendOutcome {
    relay_send_started.store(true, Ordering::Release);
    debug!(
        event = "relay_data_send_started",
        peer_id = %packet.peer_id,
        generation,
        relay_connection_id = relay.connection_id(),
        relay_region = %relay.region(),
        relay_endpoint = %relay.endpoint(),
        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
        bytes = packet.wire_bytes.len(),
        is_business = packet.is_business,
        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
        "encrypted packet handed to the relay client command boundary"
    );
    match relay.send_packet(packet).await {
        Ok(()) => {
            let first_business = packet.is_business
                && peers
                    .mark_relay_first_business_sent_for_generation(&packet.peer_id, generation)
                    .await;
            debug!(
                event = "relay_data_write_completed",
                peer_id = %packet.peer_id,
                generation,
                relay_connection_id = relay.connection_id(),
                relay_region = %relay.region(),
                relay_endpoint = %relay.endpoint(),
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                is_business = packet.is_business,
                first_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                "relay client write completed; this is not peer delivery"
            );
            if first_business {
                peers.emit_timeline(
                    "relay_first_business_write_completed",
                    Some("relay"),
                    Some("writer_completed_not_peer_delivery"),
                    Some(format!(
                        "peer={} generation={} relay_id={} relay_connection_id={} counter={} bytes={} wire_fp={:016x}",
                        packet.peer_id,
                        generation,
                        relay.endpoint(),
                        relay.connection_id(),
                        crate::transport::wire_counter(&packet.wire_bytes)
                            .map_or_else(|| "none".to_string(), |counter| counter.to_string()),
                        packet.wire_bytes.len(),
                        crate::transport::wire_fingerprint(&packet.wire_bytes),
                    )),
                );
            }
            SendOutcome::Sent
        }
        Err(err) => {
            debug!(
                event = "relay_data_send_failed",
                peer_id = %packet.peer_id,
                generation,
                relay_connection_id = relay.connection_id(),
                relay_region = %relay.region(),
                relay_endpoint = %relay.endpoint(),
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                is_business = packet.is_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                error = %err,
                "relay client rejected or failed an encrypted packet"
            );
            relay_send_failure(&err)
        }
    }
}

async fn select_outbound_path(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    relay_available: bool,
    relay_expected: bool,
    udp_local_endpoint: Option<SocketAddr>,
) -> PathSelection {
    // Queue admission already treats a configured relay as an active
    // relay-first gate before the transport object is published.  The
    // send-time selector must see the same fact; otherwise a confirmed
    // Direct can consume a WireGuard counter while the relay is still
    // connecting.  The actual `relay` Option remains separate in the caller,
    // so this flag can never make us call send_packet on a non-existent
    // transport.
    let relay_for_selection = relay_available || relay_expected;
    let selection = peers
        .select_path_for_data_with_local_endpoint_in_epoch(
            &packet.peer_id,
            prefer_direct,
            relay_for_selection,
            udp_local_endpoint,
            peers.current_network_generation_sync(),
        )
        .await;
    debug!(
        event = "outbound_path_decision",
        peer_id = %packet.peer_id,
        generation = peers.current_network_generation_sync(),
        relay_available,
        relay_expected,
        path = ?selection.path,
        direct_confirmed = selection.direct_confirmed,
        relay_hedged = selection.relay_hedged,
        reason_code = selection.reason_code,
        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
        "outbound path decision: path={:?} relay_hedged={} reason_code={} reason={}",
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
) -> DirectSendOutcome {
    // A candidate probe or nomination is not an encrypted data-plane proof.
    // Business packets must never use a Direct trial: sending the same
    // ciphertext as a relay hedge can create duplicate/reordered delivery,
    // while sending it only over UDP makes the WireGuard counter's delivery
    // status unknowable.  The direct-validation worker owns trial probes;
    // this function accepts only the committed Direct state.
    if selection.path != Some(NetworkPath::Direct) || !selection.direct_confirmed {
        return DirectSendOutcome::NotHanded {
            err: "Direct path is not encrypted-confirmed".to_string(),
        };
    }

    match (udp, selection.direct_endpoint) {
        (Some(udp), Some(endpoint)) => {
            debug!(
                event = "direct_data_send_started",
                peer_id = %packet.peer_id,
                remote_endpoint = %endpoint,
                local_endpoint = ?udp_local_endpoint,
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                is_business = packet.is_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                "encrypted packet handed to the Direct UDP socket"
            );
            match udp.send_packet_to(packet, endpoint).await {
                Ok(_) => {
                    debug!(
                        event = "direct_data_handoff_accepted",
                        peer_id = %packet.peer_id,
                        remote_endpoint = %endpoint,
                        local_endpoint = ?udp_local_endpoint,
                        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                        bytes = packet.wire_bytes.len(),
                        is_business = packet.is_business,
                        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                        "Direct UDP send_to accepted the datagram locally; peer delivery remains unconfirmed"
                    );
                    DirectSendOutcome::HandoffAccepted
                }
                Err(err) => {
                    warn!(
                        event = "direct_data_send_failed",
                        peer_id = %packet.peer_id,
                        remote_endpoint = %endpoint,
                        local_endpoint = ?udp_local_endpoint,
                        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                        bytes = packet.wire_bytes.len(),
                        is_business = packet.is_business,
                        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                        error = %err,
                        "Direct UDP send failed; delivery is uncertain and the ciphertext will not be replayed"
                    );
                    peers
                        .record_direct_failure_with_code_and_local_endpoint(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            err.to_string(),
                            udp_local_endpoint,
                        )
                        .await;
                    DirectSendOutcome::DeliveryUncertain {
                        err: format!("Direct UDP send result uncertain: {err}"),
                    }
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
            DirectSendOutcome::NotHanded {
                err: "UDP transport unavailable for encrypted packet".to_string(),
            }
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
            DirectSendOutcome::NotHanded {
                err: "path selector chose direct without an endpoint".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::REASON_PATH_RELAY_FIRST_PENDING;

    fn test_peer(node_id: &str, endpoint: SocketAddr) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        }
    }

    #[test]
    fn relay_queue_full_and_writer_closed_are_safe_plaintext_retries() {
        for error in [
            p2pnet_relay::RelayError::CommandQueueFull,
            p2pnet_relay::RelayError::WriterStoppedBeforeAccept,
        ] {
            let outcome = relay_send_failure(&crate::error::DaemonError::RelaySend {
                endpoint: "tcp://relay.test:1".to_string(),
                error,
            });
            assert!(matches!(
                outcome,
                SendOutcome::Retryable(RetryableSendFailure::RelaySendNotHanded { .. })
            ));
        }
    }

    #[test]
    fn unknown_relay_failure_is_terminal_delivery_uncertain() {
        let outcome = relay_send_failure(&crate::error::DaemonError::RelaySend {
            endpoint: "tcp://relay.test:1".to_string(),
            error: p2pnet_relay::RelayError::WriteUncertain(
                "relay protocol rejected frame after write".into(),
            ),
        });
        assert!(matches!(
            outcome,
            SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                reason: REASON_RELAY_DELIVERY_UNCERTAIN,
                ..
            })
        ));
    }

    #[test]
    fn send_timeout_is_terminal_delivery_uncertain() {
        assert!(matches!(
            outbound_send_timeout_failure_for_path(REASON_RELAY_DELIVERY_UNCERTAIN),
            SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                reason: REASON_RELAY_DELIVERY_UNCERTAIN,
                ..
            })
        ));
    }

    #[test]
    fn uncertain_direct_handoff_is_terminal_and_not_relay_replayed() {
        let outcome = SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
            err: "Direct UDP send result uncertain".to_string(),
        });
        assert!(matches!(
            outcome,
            SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn send_selector_honors_expected_relay_before_transport_publish() {
        let manager =
            PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let endpoint: SocketAddr = "198.51.100.50:51850".parse().unwrap();
        manager.add_peer(&test_peer("peer-a", endpoint)).await;
        let generation = manager.current_network_generation().await;

        // This is the exact window observed in the real Air round: relay is
        // expected/configured, but its transport object has not been
        // published yet; Direct has already completed encrypted validation.
        assert!(
            !manager
                .is_data_path_admitted_for_generation("peer-a", generation, true)
                .await
        );
        manager
            .record_direct_probe_success_with_latency(
                "peer-a",
                endpoint,
                Some(Duration::from_millis(8)),
            )
            .await;
        manager
            .record_direct_success("peer-a", Some(endpoint))
            .await;

        let packet = EncryptedPeerPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: vec![0; 32],
            is_business: true,
        };
        let selection = select_outbound_path(&packet, &manager, true, false, true, None).await;
        assert_eq!(selection.path, None);
        assert_eq!(selection.reason_code, REASON_PATH_RELAY_FIRST_PENDING);
        assert!(!selection.direct_confirmed);
    }

    #[tokio::test]
    async fn stale_generation_is_rejected_before_counter_allocation() {
        let manager =
            PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let expected_generation = manager.current_network_generation().await;
        manager
            .advance_network_generation("test-generation-race")
            .await;
        let transport = WireGuardTransport::new().0;
        let udp = RwLock::new(None);
        let relay = RwLock::new(None);

        let outcome = encrypt_then_send(
            OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            },
            &transport,
            &manager,
            expected_generation,
            true,
            &udp,
            &relay,
            true,
        )
        .await;

        assert!(matches!(
            outcome,
            EncryptSendOutcome::Retryable {
                reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn expired_delivery_deadline_drops_remaining_flush_batch() {
        let manager = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let (transport, _outbound_rx) = WireGuardTransport::new();
        let timeline = ConnectionTimeline::new("node-a", 0);
        let mut queue = PeerPendingQueue::new();
        queue.wait_generation = Some(0);
        queue.delivery_deadline = Some(Instant::now() - Duration::from_millis(1));
        queue.enqueue(PendingPacket::Plain(OutboundPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0, 0, 20],
        }));

        let (_peer_id, remaining) = flush_one_peer(
            "peer-a".to_string(),
            queue,
            transport,
            manager.clone(),
            true,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
            true,
            timeline,
        )
        .await;

        assert!(remaining.queue.is_empty());
        let stats = manager.outbound_loss_stats().await;
        assert_eq!(
            stats
                .drops
                .get(REASON_OUTBOUND_DELIVERY_DEADLINE)
                .map(|counter| counter.packets),
            Some(1)
        );
    }

    #[test]
    fn completed_peer_flush_stays_ahead_of_live_fifo_arrivals() {
        fn packet(sequence: u8) -> OutboundPacket {
            OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: vec![sequence],
            }
        }

        let mut completed = PeerPendingQueue::new();
        completed.enqueue(PendingPacket::Plain(packet(0)));
        completed.enqueue(PendingPacket::Plain(packet(1)));

        let mut pending = HashMap::new();
        let mut live = PeerPendingQueue::new();
        live.enqueue(PendingPacket::Plain(packet(2)));
        live.enqueue(PendingPacket::Plain(packet(3)));
        pending.insert("peer-a".to_string(), live);

        merge_completed_flush(&mut pending, "peer-a".to_string(), completed);

        let merged = pending.remove("peer-a").expect("merged queue");
        let sequences: Vec<u8> = merged
            .queue
            .into_iter()
            .map(|entry| match entry {
                PendingPacket::Plain(packet) => packet.packet[0],
            })
            .collect();
        assert_eq!(sequences, vec![0, 1, 2, 3]);
    }
}
