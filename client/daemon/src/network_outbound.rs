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

use p2pnet_tun::{IpPacket, Ipv4Packet, Protocol};
use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinSet;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{debug, warn};

use crate::connection_timeline::ConnectionTimeline;
use crate::dataplane::{global_dataplane_profiler, DataplaneTailMetrics, OutboundPacket};
use crate::peer::{
    ActiveBusinessPath, ActivePathSnapshot, NetworkPath, PathSelection, PeerManager,
    REASON_DIRECT_SEND_FAILED, REASON_PATH_UNAVAILABLE,
};
use crate::relay::RelayTransport;
use crate::transport::{EncryptedPeerPacket, SessionBoundEncryption, WireGuardTransport};
use crate::udp::{
    DirectBusinessBudgetGate, DirectBusinessUdpSendError, PreparedDirectBusinessSend, UdpTransport,
};

mod queue;
use queue::{
    drop_all_pending_queues, handle_ingress, maintenance, merge_completed_flush,
    start_ready_peer_flushes,
};
mod fast_path;
use fast_path::try_lan_direct_fast_path;
mod send;
use send::{direct_business_budget_ready_for_active_path, encrypt_then_send};
mod accounting;
use accounting::{
    complete_inner_ip_packet_len, overlay_packet_identity, raw_packet_summary, record_loss_event,
    record_overflow_drop, record_terminal_drop, record_terminal_drop_bytes,
};

const OUTBOUND_RETRY_DELAY: Duration = Duration::from_millis(50);
/// Bound a single path send so a stalled relay TCP write can never block the
/// shared outbound worker (per-peer waits are already event-driven; this
/// bounds the per-packet SEND).  The per-peer emit lock is held for at most
/// this long, which also bounds how long a control probe can be locked out.
const OUTBOUND_SEND_TIMEOUT: Duration = Duration::from_secs(2);
/// A packet that has reached a usable-path actor may not remain in retry
/// limbo. This is a loss boundary, not an attempt to hide a slow relay by
/// increasing its timeout.
pub(crate) const OUTBOUND_DELIVERY_DEADLINE: Duration = Duration::from_secs(3);
/// Cadence of the outbound maintenance ticker (deadline expiry, peer
/// offline / generation-change cancellation, paced retries).
pub(crate) const OUTBOUND_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(100);
/// Per-peer pending queue bounds.  A not-yet-usable peer cannot build
/// unbounded memory pressure while it waits for a path.
// A relay validation round can contain one 256-packet request burst and the
// matching 256-packet echo burst.  The flush task owns part of the FIFO while
// new TUN packets continue arriving, so the live ingress queue needs room for
// the complete bidirectional burst without evicting its tail. Control and
// handshake packets use a separate lane, so they consume none of this bound.
// The independent 2 MiB cap prevents a peer from filling the limit with
// maximum-size IP packets.
const MAX_PENDING_PACKETS_PER_PEER: usize = 512;
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
pub(crate) const REASON_DIRECT_BUDGET_PENDING: &str = "direct_business_budget_pending";
pub(crate) const REASON_DIRECT_BUDGET_STALE: &str = "direct_business_budget_stale";
pub(crate) const REASON_DIRECT_BUDGET_OVERSIZE: &str = "direct_business_budget_oversize";
pub(crate) const REASON_DIRECT_CIPHERTEXT_OVERSIZE: &str = "direct_business_ciphertext_oversize";
pub(crate) const REASON_DIRECT_BUSINESS_EMSGSIZE: &str = "direct_business_emsgsize";
pub(crate) const REASON_DIRECT_LOCAL_BACKPRESSURE: &str = "direct_business_local_backpressure";
pub(crate) const REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE: &str =
    "direct_business_local_backpressure_deadline_expired";
pub(crate) const REASON_DIRECT_BUDGET_REROUTE_EXHAUSTED: &str =
    "direct_business_budget_reroute_exhausted";
pub(crate) const REASON_DIRECT_BUSINESS_MALFORMED: &str = "direct_business_malformed_ip";
pub(crate) const REASON_IPV6_BUDGET_BELOW_MINIMUM_MTU: &str = "ipv6_budget_below_minimum_mtu";

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
    DirectBudgetStale {
        reason: String,
    },
    /// The exact nonblocking socket accepted no bytes because its local send
    /// queue is temporarily full. This is neither path/budget staleness nor a
    /// Direct-health signal, and it must never enter Relay fallback.
    RetryableLocalBackpressure {
        reason: String,
    },
    LocalMtuFailure {
        reason_code: &'static str,
        reason: String,
        inner_ip_mtu: u32,
    },
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
    /// The local kernel synchronously rejected the datagram with EMSGSIZE.
    /// No handoff occurred, but this must not count as path-health failure or
    /// trigger a Relay fallback.
    PacketTooLarge { err: String },
}

struct DirectBusinessSendPlan {
    udp: UdpTransport,
    prepared: PreparedDirectBusinessSend,
}

/// Sender-owned extension of [`ActivePathSnapshot`]. The peer manager owns
/// path/generation state; the outbound worker owns the exact session and UDP
/// publication/socket identity used for the handoff.
#[derive(Debug, Clone)]
struct DirectFastPathEntry {
    path: ActivePathSnapshot,
    session_instance: u64,
    udp_transport_instance_id: u64,
    publication_owner: u64,
    socket_index: usize,
}

#[derive(Debug, Clone, Copy)]
struct FastPathEligibilityToken {
    generation: u64,
    direct_commit_seq: u64,
    peer_session_generation: crate::peer::PeerSessionGeneration,
}

impl FastPathEligibilityToken {
    fn is_current(&self, peers: &PeerManager, peer_id: &str) -> bool {
        peers.current_network_generation_sync() == self.generation
            && peers.peer_session_is_current_sync(peer_id, self.peer_session_generation)
            && peers.direct_commit_seq_sync(peer_id) == Some(self.direct_commit_seq)
    }
}

enum FastPathAttempt {
    Sent,
    Fallback(OutboundPacket),
    Terminal {
        packet: OutboundPacket,
        generation: u64,
        reason_code: &'static str,
        reason: String,
    },
    TerminalBytes {
        peer_id: String,
        generation: u64,
        bytes: usize,
        reason_code: &'static str,
        reason: String,
    },
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
    Plain {
        packet: OutboundPacket,
        direct_budget_reroutes: u8,
        local_backpressure_retries: u32,
    },
}

impl PendingPacket {
    fn plain(packet: OutboundPacket) -> Self {
        Self::Plain {
            packet,
            direct_budget_reroutes: 0,
            local_backpressure_retries: 0,
        }
    }

    fn stored_bytes(&self) -> usize {
        match self {
            Self::Plain { packet, .. } => packet.packet.len(),
        }
    }

    fn peer_id(&self) -> &str {
        match self {
            Self::Plain { packet, .. } => &packet.peer_id,
        }
    }

    fn raw_packet(&self) -> &[u8] {
        match self {
            Self::Plain { packet, .. } => &packet.packet,
        }
    }

    fn experienced_local_backpressure(&self) -> bool {
        match self {
            Self::Plain {
                local_backpressure_retries,
                ..
            } => *local_backpressure_retries > 0,
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
    /// Prevent the maintenance tick from flooding diagnostics while the same
    /// queue remains behind one missing Direct business budget.
    budget_pending_reported: bool,
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
            budget_pending_reported: false,
        }
    }

    /// Park a packet in the bounded queue, dropping the OLDEST entries first
    /// when the packet/byte bound is exceeded.  Returns (dropped packets,
    /// dropped bytes) for the overflow so the caller can count them into
    /// `/status.stats.outbound_drops` — the loss is never silently ignored.
    fn enqueue(&mut self, packet: PendingPacket) -> (Vec<PendingPacket>, usize) {
        let packet_len = packet.stored_bytes();
        let mut dropped_packets = Vec::new();
        let mut dropped_bytes = 0usize;
        while !self.queue.is_empty()
            && (self.queue.len() >= MAX_PENDING_PACKETS_PER_PEER
                || self.bytes.saturating_add(packet_len) > MAX_PENDING_BYTES_PER_PEER)
        {
            if let Some(old) = self.queue.pop_front() {
                let old_len = old.stored_bytes();
                self.bytes = self.bytes.saturating_sub(old_len);
                dropped_bytes = dropped_bytes.saturating_add(old_len);
                dropped_packets.push(old);
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

    fn delivery_deadline_reason(&self) -> &'static str {
        if self
            .queue
            .front()
            .is_some_and(PendingPacket::experienced_local_backpressure)
        {
            REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE
        } else {
            REASON_OUTBOUND_DELIVERY_DEADLINE
        }
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
    let mut committed_path_change_rx = peers.subscribe_committed_business_path_changes();
    let mut direct_budget_change_rx = peers.subscribe_direct_business_budget_changes();
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
    // The cache is owned by this actor so a fast send can never run beside an
    // older per-peer flush. Negative eligibility tokens keep Public Direct,
    // Relay-only and otherwise ineligible peers on the existing path without
    // repeating a connection-map read for every packet.
    let mut fast_paths: HashMap<String, DirectFastPathEntry> = HashMap::new();
    let mut fast_path_ineligible: HashMap<String, FastPathEligibilityToken> = HashMap::new();
    // `relay_available` is a live transport snapshot, while this flag says
    // that the configured topology requires a relay-first admission window.
    // Keeping them separate closes the startup race where Direct was admitted
    // in the few milliseconds before the relay supervisor published its slot.
    let relay_expected = relay_startup_wait.timeout.is_some();
    let _ = relay_probe_kick_tx.send(probe_kick);

    loop {
        tokio::select! {
            packet = outbound_rx.recv() => {
                let Some(mut packet) = packet else { break; };
                let profiler = global_dataplane_profiler();
                let network_dequeued = Instant::now();
                if let Some(trace) = packet.trace.as_mut() {
                    trace.network_queue_dequeued = Some(network_dequeued);
                    profiler.record_value(
                        trace.sampled,
                        "tx_network_outbound_queue_depth",
                        outbound_rx.len() as u64,
                    );
                    if let Some(enqueued) = trace.transport_queue_send_started {
                        profiler.record(
                            trace.sampled,
                            "tx_network_outbound_queue_wait_us",
                            network_dequeued.duration_since(enqueued),
                        );
                    }
                }
                let peer_id = packet.peer_id.clone();
                let can_try_fast_path = prefer_direct
                    && peers.is_direct_sync(&peer_id)
                    && !pending.contains_key(&peer_id)
                    && !flushing_peers.contains(&peer_id);
                if can_try_fast_path {
                    match try_lan_direct_fast_path(
                        packet,
                        &transport,
                        &peers,
                        prefer_direct,
                        &udp_transport,
                        &mut fast_paths,
                        &mut fast_path_ineligible,
                    ).await {
                        FastPathAttempt::Sent => continue,
                        FastPathAttempt::Fallback(packet) => {
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
                        FastPathAttempt::Terminal { packet, generation, reason_code, reason } => {
                            record_terminal_drop(
                                &transport,
                                &peers,
                                &peer_id,
                                generation,
                                packet,
                                reason_code,
                                reason,
                                &timeline,
                            ).await;
                        }
                        FastPathAttempt::TerminalBytes { peer_id, generation, bytes, reason_code, reason } => {
                            record_terminal_drop_bytes(
                                &transport,
                                &peers,
                                &peer_id,
                                generation,
                                bytes,
                                reason_code,
                                reason,
                                &timeline,
                            ).await;
                        }
                    }
                } else {
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
            changed = committed_path_change_rx.changed() => {
                if changed.is_err() { break; }
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
            changed = direct_budget_change_rx.changed() => {
                if changed.is_err() { break; }
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

/// Outcome of encrypting and sending one RAW packet.
enum EncryptSendOutcome {
    Sent,
    BudgetPending {
        packet: OutboundPacket,
        reason: String,
    },
    Retryable {
        packet: OutboundPacket,
        reason_code: &'static str,
        reason: String,
    },
    RetryableLocalBackpressure {
        packet: OutboundPacket,
        reason: String,
    },
    Terminal {
        packet: OutboundPacket,
        reason_code: &'static str,
        reason: String,
    },
}

#[cfg(test)]
mod tests;
