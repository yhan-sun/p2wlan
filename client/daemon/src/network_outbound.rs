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

use fast_path::DirectFastPathEntry;

use fast_path::FastPathEligibilityToken;

use fast_path::FastPathAttempt;

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

pub(crate) use queue::RelayStartupWait;

use diagnostics::overlay_packet_identity;

use diagnostics::raw_packet_summary;

use diagnostics::complete_inner_ip_packet_len;

use fast_path::try_lan_direct_fast_path;

pub(crate) use queue::run_network_outbound;

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

use send::encrypt_then_send;

use direct::direct_business_budget_ready_for_active_path;

use direct::relay_make_before_break_fallback;

#[cfg(test)]
use relay::relay_send_failure;

use diagnostics::record_loss_event;

use relay::send_via_relay;

use direct::send_direct_if_selected;
mod diagnostics;
mod direct;
mod fast_path;
mod queue;
mod relay;
mod send;

#[cfg(test)]
mod test_support;
