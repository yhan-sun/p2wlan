//! Outbound probe budgets for UDP connectivity checks.
//!
//! The process-wide budget deliberately lives only in memory. Probe admission
//! is part of the async packet path, so file locking, rewriting, and fsync here
//! would stall traversal sessions on the daemon's Tokio workers.
//!
//! Two layers of admission run for every outbound connectivity probe:
//!
//! 1. A short per-second sliding window (burst shaping) per network, per peer
//!    and per peer remote IP.
//! 2. A persistent sliding window that spans retries: the short window refills
//!    every second, so repeated retry cycles could otherwise re-emit thousands
//!    of probes per minute. The persistent window bounds the *long-term* rate
//!    per network, per peer, per peer remote IP and per (peer, local socket)
//!    so a failing peer cannot keep flooding the shared NAT over many retries.
//!
//! Direct peers are protected by construction: consent keepalives and
//! encrypted data do not pass through `admit_outbound_connectivity_probe`.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum OutboundProbeBudgetKey {
    Network,
    Peer(String),
    PeerRemoteIp(String, IpAddr),
    /// Long-term budget that survives per-second window resets.
    NetworkPersistent,
    PeerPersistent(String),
    PeerRemoteIpPersistent(String, IpAddr),
    /// Per (peer, local NAT socket) long-term budget: one peer must not
    /// exhaust a shared NAT socket's mapping state for other peers.
    PeerSocketPersistent(String, usize),
}

pub(super) type OutboundProbeBudgetState =
    Arc<Mutex<HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>>>;

#[derive(Debug, Default)]
pub(super) struct GlobalOutboundProbeBudget {
    pub(super) state: Mutex<HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>>,
}

impl GlobalOutboundProbeBudget {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) async fn admit(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
        socket_index: usize,
    ) -> OutboundProbeAdmission {
        let now = Instant::now();
        let mut budget = self.state.lock().await;
        retain_live_budget_entries(&mut budget, now);

        if short_window_len(&budget, &OutboundProbeBudgetKey::Network)
            >= OUTBOUND_PROBE_BUDGET_PER_NETWORK
        {
            return OutboundProbeAdmission::GlobalNetworkRateLimited;
        }
        let peer_key = OutboundProbeBudgetKey::Peer(peer_id.to_string());
        if short_window_len(&budget, &peer_key) >= OUTBOUND_PROBE_BUDGET_PER_PEER {
            return OutboundProbeAdmission::GlobalPeerRateLimited;
        }
        let remote_ip_key =
            OutboundProbeBudgetKey::PeerRemoteIp(peer_id.to_string(), peer_addr.ip());
        if short_window_len(&budget, &remote_ip_key) >= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP {
            return OutboundProbeAdmission::GlobalRemoteIpRateLimited;
        }

        if long_window_len(&budget, &OutboundProbeBudgetKey::NetworkPersistent)
            >= OUTBOUND_PROBE_PERSISTENT_PER_NETWORK
        {
            return OutboundProbeAdmission::GlobalNetworkPersistentRateLimited;
        }
        let peer_persistent_key = OutboundProbeBudgetKey::PeerPersistent(peer_id.to_string());
        if long_window_len(&budget, &peer_persistent_key) >= OUTBOUND_PROBE_PERSISTENT_PER_PEER {
            return OutboundProbeAdmission::GlobalPeerPersistentRateLimited;
        }
        let remote_ip_persistent_key =
            OutboundProbeBudgetKey::PeerRemoteIpPersistent(peer_id.to_string(), peer_addr.ip());
        if long_window_len(&budget, &remote_ip_persistent_key)
            >= OUTBOUND_PROBE_PERSISTENT_PER_PEER_REMOTE_IP
        {
            return OutboundProbeAdmission::GlobalRemoteIpPersistentRateLimited;
        }
        let socket_persistent_key =
            OutboundProbeBudgetKey::PeerSocketPersistent(peer_id.to_string(), socket_index);
        if long_window_len(&budget, &socket_persistent_key)
            >= OUTBOUND_PROBE_PERSISTENT_PER_PEER_SOCKET
        {
            return OutboundProbeAdmission::GlobalPeerSocketPersistentRateLimited;
        }

        budget
            .entry(OutboundProbeBudgetKey::Network)
            .or_default()
            .push_back(now);
        budget.entry(peer_key).or_default().push_back(now);
        budget.entry(remote_ip_key).or_default().push_back(now);
        budget
            .entry(OutboundProbeBudgetKey::NetworkPersistent)
            .or_default()
            .push_back(now);
        budget
            .entry(peer_persistent_key)
            .or_default()
            .push_back(now);
        budget
            .entry(remote_ip_persistent_key)
            .or_default()
            .push_back(now);
        budget
            .entry(socket_persistent_key)
            .or_default()
            .push_back(now);
        OutboundProbeAdmission::Accepted
    }

    pub(super) async fn foreground_burst_active(&self) -> bool {
        let state = self.state.lock().await;
        short_window_len(&state, &OutboundProbeBudgetKey::Network)
            >= OUTBOUND_PROBE_BUDGET_PER_NETWORK
                .saturating_sub(RELAY_BACKOFF_HEARTBEAT_FOREGROUND_RESERVE)
    }
}

/// Low-priority process-wide budget for relay-backed heartbeat probes.
///
/// This is intentionally separate from recovery-epoch credit: a frozen epoch
/// must not silence a relay heartbeat, and the heartbeat must not consume the
/// foreground traversal allowance. It is still global and counts each actual
/// (socket, candidate) admission, so adding peers cannot multiply traffic
/// without bound.
#[derive(Debug)]
pub(crate) struct GlobalRelayBackoffHeartbeatBudget {
    /// One short-held synchronous mutex covers both committed packets and
    /// in-flight reservations.  A reservation must be visible to another
    /// heartbeat worker before its UDP send awaits, otherwise concurrent
    /// workers could each observe spare capacity and oversubscribe the cap.
    pub(super) state: StdMutex<RelayBackoffHeartbeatBudgetState>,
    next_reservation_id: AtomicU64,
}

#[derive(Debug)]
pub(super) struct RelayBackoffHeartbeatBudgetState {
    /// Only packets which actually entered the kernel send path live here.
    /// Diagnostics and the sliding limits are intentionally based on this
    /// map, not on attempted candidate/socket pairs.
    pub(super) committed: HashMap<RelayBackoffHeartbeatBudgetKey, VecDeque<Instant>>,
    /// Capacity temporarily held by a send that has not yet reported its
    /// actual datagram count.  Dropping the reservation releases it.
    reserved: HashMap<RelayBackoffHeartbeatBudgetKey, usize>,
    reservations: HashMap<u64, RelayBackoffHeartbeatPendingReservation>,
    /// A peer may receive at most one heartbeat endpoint group in one normal
    /// 3-second service slot.  This is both a storm guard and the basis for
    /// fair sharing when more than twelve relay peers are active.
    service_slots: HashMap<(String, u64), RelayBackoffHeartbeatServiceSlot>,
    active_peers: HashMap<String, u64>,
    scheduler: RelayBackoffHeartbeatScheduler,
    service_epoch: Instant,
}

impl Default for RelayBackoffHeartbeatBudgetState {
    fn default() -> Self {
        Self {
            committed: HashMap::new(),
            reserved: HashMap::new(),
            reservations: HashMap::new(),
            service_slots: HashMap::new(),
            active_peers: HashMap::new(),
            scheduler: RelayBackoffHeartbeatScheduler::default(),
            service_epoch: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct RelayBackoffHeartbeatPendingReservation {
    keys: [RelayBackoffHeartbeatBudgetKey; 3],
    packet_capacity: usize,
    peer_id: String,
    service_slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayBackoffHeartbeatServiceSlot {
    Reserved(u64),
    Committed,
}

/// A provisional heartbeat-budget allocation.  It reserves enough room for
/// the authenticated packet and, when required, its legacy compatibility
/// packet.  `commit` records only datagrams that were actually sent; dropping
/// an uncommitted reservation returns all of its capacity.
pub(super) struct RelayBackoffHeartbeatReservation {
    budget: Arc<GlobalRelayBackoffHeartbeatBudget>,
    id: Option<u64>,
}

impl RelayBackoffHeartbeatReservation {
    pub(super) fn commit(mut self, actual_packets: usize) {
        let Some(id) = self.id.take() else {
            return;
        };
        self.budget.finish_reservation(id, actual_packets);
    }
}

impl Drop for RelayBackoffHeartbeatReservation {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.budget.finish_reservation(id, 0);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelayBackoffHeartbeatReservationRejection {
    BudgetLimited,
    FairnessDeferred,
    ForegroundYield,
}

impl RelayBackoffHeartbeatReservationRejection {
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::BudgetLimited => "relay_backoff_heartbeat_budget_limited",
            Self::FairnessDeferred => "relay_backoff_heartbeat_fairness_deferred",
            Self::ForegroundYield => "relay_backoff_heartbeat_foreground_reserved",
        }
    }
}

/// A categorized endpoint selected for exactly one low-rate heartbeat send.
/// The endpoint group is chosen before a local socket, avoiding the old
/// candidate × all-sockets expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RelayBackoffHeartbeatTarget {
    pub(super) endpoint: SocketAddr,
    pub(super) socket_index: usize,
    pub(super) group: RelayBackoffHeartbeatTargetGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RelayBackoffHeartbeatTargetGroup {
    Priority,
    Predicted,
    Fallback,
}

impl RelayBackoffHeartbeatTargetGroup {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::Predicted => "predicted",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Debug, Default)]
struct RelayBackoffHeartbeatCursor {
    priority: usize,
    predicted: usize,
    fallback: usize,
    socket: usize,
    beat: u64,
}

/// One normal heartbeat cadence is three seconds.  A 60-second 240 packet
/// reserve therefore has twelve packet slots per cadence.  The rotating
/// roster only matters above that peer count; with Mini/Air's current eleven
/// peers every serviceable peer can receive one packet on every beat.
const RELAY_BACKOFF_HEARTBEAT_SERVICE_SLOT: Duration = Duration::from_secs(3);
const RELAY_BACKOFF_HEARTBEAT_PEERS_PER_SERVICE_SLOT: usize = 12;
const RELAY_BACKOFF_HEARTBEAT_ACTIVE_PEER_RETENTION_SLOTS: u64 = 40;

#[derive(Debug, Default)]
struct RelayBackoffHeartbeatScheduler {
    cursors: HashMap<(String, u64), RelayBackoffHeartbeatCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum RelayBackoffHeartbeatBudgetKey {
    Network,
    Peer(String),
    RemoteIp(IpAddr),
}

impl GlobalRelayBackoffHeartbeatBudget {
    #[cfg(test)]
    pub(super) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(super) fn set_service_slot_for_test(&self, slot: u64) {
        let elapsed = RELAY_BACKOFF_HEARTBEAT_SERVICE_SLOT
            .checked_mul(u32::try_from(slot).unwrap_or(u32::MAX))
            .unwrap_or(RELAY_BACKOFF_HEARTBEAT_BUDGET_WINDOW);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.service_epoch = Instant::now()
            .checked_sub(elapsed)
            .unwrap_or_else(Instant::now);
    }

    /// Select exactly one endpoint group and one local socket for a heartbeat
    /// beat.  The cursor belongs to `(peer, generation)`, not to a worker, so
    /// a cancellation/replacement handshake cannot reset a 96-port sweep back
    /// to its first few candidates.
    pub(super) fn next_target(
        &self,
        peer_id: &str,
        generation: u64,
        priority: &[SocketAddr],
        predicted: &[SocketAddr],
        fallback: &[SocketAddr],
        socket_count: usize,
    ) -> Option<RelayBackoffHeartbeatTarget> {
        if socket_count == 0 || (priority.is_empty() && predicted.is_empty() && fallback.is_empty())
        {
            return None;
        }

        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state
            .scheduler
            .cursors
            .retain(|(known_peer, known_generation), _| {
                known_peer != peer_id || *known_generation == generation
            });
        let cursor = state
            .scheduler
            .cursors
            .entry((peer_id.to_string(), generation))
            .or_default();

        // A current authenticated/selected endpoint gets the first chance,
        // while a five-beat cadence still spends most of its packets moving
        // through the predicted window and periodically reaches fallbacks.
        // This avoids a permanent priority-only loop after a port changes.
        let preferred_group = match cursor.beat % 5 {
            0 => RelayBackoffHeartbeatTargetGroup::Priority,
            4 => RelayBackoffHeartbeatTargetGroup::Fallback,
            _ => RelayBackoffHeartbeatTargetGroup::Predicted,
        };
        cursor.beat = cursor.beat.saturating_add(1);

        let group_order = [
            preferred_group,
            RelayBackoffHeartbeatTargetGroup::Priority,
            RelayBackoffHeartbeatTargetGroup::Predicted,
            RelayBackoffHeartbeatTargetGroup::Fallback,
        ];
        let mut selected = None;
        for group in group_order {
            let endpoints = match group {
                RelayBackoffHeartbeatTargetGroup::Priority => priority,
                RelayBackoffHeartbeatTargetGroup::Predicted => predicted,
                RelayBackoffHeartbeatTargetGroup::Fallback => fallback,
            };
            if endpoints.is_empty()
                || selected
                    .as_ref()
                    .is_some_and(|(_, selected_group)| *selected_group == group)
            {
                continue;
            }
            let endpoint = match group {
                RelayBackoffHeartbeatTargetGroup::Priority => {
                    let index = cursor.priority % endpoints.len();
                    cursor.priority = cursor.priority.saturating_add(1);
                    endpoints[index]
                }
                RelayBackoffHeartbeatTargetGroup::Predicted => {
                    let index = cursor.predicted % endpoints.len();
                    cursor.predicted = cursor.predicted.saturating_add(1);
                    endpoints[index]
                }
                RelayBackoffHeartbeatTargetGroup::Fallback => {
                    let index = cursor.fallback % endpoints.len();
                    cursor.fallback = cursor.fallback.saturating_add(1);
                    endpoints[index]
                }
            };
            selected = Some((endpoint, group));
            break;
        }

        let (endpoint, group) = selected?;
        let socket_index = cursor.socket % socket_count;
        cursor.socket = cursor.socket.saturating_add(1);
        Some(RelayBackoffHeartbeatTarget {
            endpoint,
            socket_index,
            group,
        })
    }

    /// Provisionally reserve room for one endpoint/socket heartbeat send.
    /// The send path commits the exact physical datagram count after the
    /// kernel accepted it.  A send error or cancelled owner drops this handle
    /// and leaves no phantom budget entry behind.
    pub(super) fn reserve(
        self: &Arc<Self>,
        peer_id: &str,
        remote_ip: IpAddr,
        packet_capacity: usize,
    ) -> std::result::Result<
        RelayBackoffHeartbeatReservation,
        RelayBackoffHeartbeatReservationRejection,
    > {
        if packet_capacity == 0 {
            return Err(RelayBackoffHeartbeatReservationRejection::BudgetLimited);
        }
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.committed.retain(|_, sent| {
            while sent.front().is_some_and(|sent_at| {
                now.duration_since(*sent_at) >= RELAY_BACKOFF_HEARTBEAT_BUDGET_WINDOW
            }) {
                sent.pop_front();
            }
            !sent.is_empty()
        });
        let service_slot = now
            .saturating_duration_since(state.service_epoch)
            .as_nanos()
            .checked_div(RELAY_BACKOFF_HEARTBEAT_SERVICE_SLOT.as_nanos())
            .and_then(|slot| u64::try_from(slot).ok())
            .unwrap_or(u64::MAX);
        state.active_peers.insert(peer_id.to_string(), service_slot);
        state.active_peers.retain(|_, last_seen| {
            service_slot.saturating_sub(*last_seen)
                <= RELAY_BACKOFF_HEARTBEAT_ACTIVE_PEER_RETENTION_SLOTS
        });
        state.service_slots.retain(|(_, slot), value| {
            *slot == service_slot || matches!(value, RelayBackoffHeartbeatServiceSlot::Reserved(_))
        });
        if state
            .service_slots
            .contains_key(&(peer_id.to_string(), service_slot))
        {
            return Err(RelayBackoffHeartbeatReservationRejection::FairnessDeferred);
        }

        let mut active_peers = state.active_peers.keys().collect::<Vec<_>>();
        active_peers.sort_unstable();
        if active_peers.len() > RELAY_BACKOFF_HEARTBEAT_PEERS_PER_SERVICE_SLOT {
            let start = (service_slot as usize) % active_peers.len();
            let selected = (0..RELAY_BACKOFF_HEARTBEAT_PEERS_PER_SERVICE_SLOT).any(|offset| {
                active_peers[(start + offset) % active_peers.len()].as_str() == peer_id
            });
            if !selected {
                return Err(RelayBackoffHeartbeatReservationRejection::FairnessDeferred);
            }
        }

        let network_key = RelayBackoffHeartbeatBudgetKey::Network;
        let peer_key = RelayBackoffHeartbeatBudgetKey::Peer(peer_id.to_string());
        let remote_ip_key = RelayBackoffHeartbeatBudgetKey::RemoteIp(remote_ip);
        if state
            .committed
            .get(&network_key)
            .map_or(0, VecDeque::len)
            .saturating_add(state.reserved.get(&network_key).copied().unwrap_or(0))
            .saturating_add(packet_capacity)
            > RELAY_BACKOFF_HEARTBEAT_GLOBAL_PER_WINDOW
            || state
                .committed
                .get(&peer_key)
                .map_or(0, VecDeque::len)
                .saturating_add(state.reserved.get(&peer_key).copied().unwrap_or(0))
                .saturating_add(packet_capacity)
                > RELAY_BACKOFF_HEARTBEAT_PER_PEER_PER_WINDOW
            || state
                .committed
                .get(&remote_ip_key)
                .map_or(0, VecDeque::len)
                .saturating_add(state.reserved.get(&remote_ip_key).copied().unwrap_or(0))
                .saturating_add(packet_capacity)
                > RELAY_BACKOFF_HEARTBEAT_PER_REMOTE_IP_PER_WINDOW
        {
            return Err(RelayBackoffHeartbeatReservationRejection::BudgetLimited);
        }

        let id = self
            .next_reservation_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .expect("relay-backoff heartbeat reservation ID space exhausted");
        let keys = [network_key, peer_key, remote_ip_key];
        for key in &keys {
            let current = state.reserved.get(key).copied().unwrap_or(0);
            state
                .reserved
                .insert(key.clone(), current.saturating_add(packet_capacity));
        }
        state.reservations.insert(
            id,
            RelayBackoffHeartbeatPendingReservation {
                keys,
                packet_capacity,
                peer_id: peer_id.to_string(),
                service_slot,
            },
        );
        state.service_slots.insert(
            (peer_id.to_string(), service_slot),
            RelayBackoffHeartbeatServiceSlot::Reserved(id),
        );
        Ok(RelayBackoffHeartbeatReservation {
            budget: self.clone(),
            id: Some(id),
        })
    }

    fn finish_reservation(&self, id: u64, actual_packets: usize) {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(reservation) = state.reservations.remove(&id) else {
            return;
        };
        let committed_packets = actual_packets.min(reservation.packet_capacity);
        for key in &reservation.keys {
            let remaining = state
                .reserved
                .get(key)
                .copied()
                .unwrap_or(0)
                .saturating_sub(reservation.packet_capacity);
            if remaining == 0 {
                state.reserved.remove(key);
            } else {
                state.reserved.insert(key.clone(), remaining);
            }
            for _ in 0..committed_packets {
                state
                    .committed
                    .entry(key.clone())
                    .or_default()
                    .push_back(now);
            }
        }
        let service_key = (reservation.peer_id, reservation.service_slot);
        match committed_packets {
            0 => {
                if matches!(
                    state.service_slots.get(&service_key),
                    Some(RelayBackoffHeartbeatServiceSlot::Reserved(owner)) if *owner == id
                ) {
                    state.service_slots.remove(&service_key);
                }
            }
            _ => {
                state
                    .service_slots
                    .insert(service_key, RelayBackoffHeartbeatServiceSlot::Committed);
            }
        }
    }
}

impl Default for GlobalRelayBackoffHeartbeatBudget {
    fn default() -> Self {
        Self {
            state: StdMutex::new(RelayBackoffHeartbeatBudgetState::default()),
            next_reservation_id: AtomicU64::new(1),
        }
    }
}

/// Heartbeats may use only the low-priority reserve while a foreground burst
/// is active. Foreground traversal never waits for or competes with this
/// budget.
pub(super) const RELAY_BACKOFF_HEARTBEAT_FOREGROUND_RESERVE: usize = 128;
pub(super) const RELAY_BACKOFF_HEARTBEAT_BUDGET_WINDOW: Duration = Duration::from_secs(60);
pub(super) const RELAY_BACKOFF_HEARTBEAT_GLOBAL_PER_WINDOW: usize = 240;
pub(super) const RELAY_BACKOFF_HEARTBEAT_PER_PEER_PER_WINDOW: usize = 24;
pub(super) const RELAY_BACKOFF_HEARTBEAT_PER_REMOTE_IP_PER_WINDOW: usize = 120;

pub(super) const OUTBOUND_PROBE_BUDGET_WINDOW: Duration = Duration::from_secs(1);
pub(super) const OUTBOUND_PROBE_BUDGET_PER_NETWORK: usize = 512;
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER: usize = 256;
// Symmetric NAT traversal often needs to sweep a short predicted port window
// against one public IP from multiple local sockets.  v0.1.116 bounded this to
// below the peer budget (256) so the remote-IP limit is the more granular
// binding constraint, while leaving the easy-side stable unique scatter (200
// distinct ports in its coverage test) and one 192-datagram ActivePool session
// room — all well under the 512 ceiling the task requires the per-session
// volume to stay below.
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP: usize = 224;

/// Persistent budgets span retries: they are only pruned every
/// `OUTBOUND_PROBE_PERSISTENT_WINDOW`, so repeated punch sessions share one
/// long-term allowance instead of each refilling its own 1-second window.
pub(super) const OUTBOUND_PROBE_PERSISTENT_WINDOW: Duration = Duration::from_secs(60);
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_NETWORK: usize = 6_000;
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_PEER: usize = 3_000;
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_PEER_REMOTE_IP: usize = 2_250;
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_PEER_SOCKET: usize = 1_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutboundProbeAdmission {
    Accepted,
    NetworkRateLimited,
    PeerRateLimited,
    RemoteIpRateLimited,
    GlobalNetworkRateLimited,
    GlobalPeerRateLimited,
    GlobalRemoteIpRateLimited,
    GlobalNetworkPersistentRateLimited,
    GlobalPeerPersistentRateLimited,
    GlobalRemoteIpPersistentRateLimited,
    GlobalPeerSocketPersistentRateLimited,
    /// The peer's recovery-epoch probe credit is exhausted: the hard
    /// per-`(peer_id, generation, epoch)` total was reached, so no further
    /// probes may be emitted until the epoch rotates (generation advance,
    /// Direct confirmation or the age-based re-arm).
    EpochCreditExhausted,
    /// The relay-backoff heartbeat's dedicated per-peer budget is exhausted;
    /// the next beat retries.
    HeartbeatBudgetLimited,
}

pub(super) fn outbound_probe_admission_reason(admission: OutboundProbeAdmission) -> &'static str {
    match admission {
        OutboundProbeAdmission::Accepted => "accepted",
        OutboundProbeAdmission::NetworkRateLimited => "network_rate_limited",
        OutboundProbeAdmission::PeerRateLimited => "peer_rate_limited",
        OutboundProbeAdmission::RemoteIpRateLimited => "remote_ip_rate_limited",
        OutboundProbeAdmission::GlobalNetworkRateLimited => "global_network_rate_limited",
        OutboundProbeAdmission::GlobalPeerRateLimited => "global_peer_rate_limited",
        OutboundProbeAdmission::GlobalRemoteIpRateLimited => "global_remote_ip_rate_limited",
        OutboundProbeAdmission::GlobalNetworkPersistentRateLimited => {
            "global_network_persistent_rate_limited"
        }
        OutboundProbeAdmission::GlobalPeerPersistentRateLimited => {
            "global_peer_persistent_rate_limited"
        }
        OutboundProbeAdmission::GlobalRemoteIpPersistentRateLimited => {
            "global_remote_ip_persistent_rate_limited"
        }
        OutboundProbeAdmission::GlobalPeerSocketPersistentRateLimited => {
            "global_peer_socket_persistent_rate_limited"
        }
        OutboundProbeAdmission::EpochCreditExhausted => "recovery_epoch_credit_exhausted",
        OutboundProbeAdmission::HeartbeatBudgetLimited => "relay_backoff_heartbeat_budget_limited",
    }
}

pub(super) fn default_global_outbound_probe_budget() -> Option<Arc<GlobalOutboundProbeBudget>> {
    if std::env::var("P2WLAN_DISABLE_GLOBAL_PROBE_BUDGET").as_deref() == Ok("1") {
        return None;
    }
    #[cfg(test)]
    {
        None
    }
    #[cfg(not(test))]
    {
        static PROCESS_BUDGET: OnceLock<Arc<GlobalOutboundProbeBudget>> = OnceLock::new();
        Some(
            PROCESS_BUDGET
                .get_or_init(|| Arc::new(GlobalOutboundProbeBudget::default()))
                .clone(),
        )
    }
}

pub(super) fn default_global_relay_backoff_heartbeat_budget(
) -> Arc<GlobalRelayBackoffHeartbeatBudget> {
    #[cfg(test)]
    {
        Arc::new(GlobalRelayBackoffHeartbeatBudget::default())
    }
    #[cfg(not(test))]
    {
        static PROCESS_BUDGET: OnceLock<Arc<GlobalRelayBackoffHeartbeatBudget>> = OnceLock::new();
        PROCESS_BUDGET
            .get_or_init(|| Arc::new(GlobalRelayBackoffHeartbeatBudget::default()))
            .clone()
    }
}

pub(super) fn retain_live_budget_entries(
    budget: &mut HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>,
    now: Instant,
) {
    budget.retain(|key, sent| {
        let window = match key {
            OutboundProbeBudgetKey::NetworkPersistent
            | OutboundProbeBudgetKey::PeerPersistent(_)
            | OutboundProbeBudgetKey::PeerRemoteIpPersistent(..)
            | OutboundProbeBudgetKey::PeerSocketPersistent(..) => OUTBOUND_PROBE_PERSISTENT_WINDOW,
            OutboundProbeBudgetKey::Network
            | OutboundProbeBudgetKey::Peer(_)
            | OutboundProbeBudgetKey::PeerRemoteIp(..) => OUTBOUND_PROBE_BUDGET_WINDOW,
        };
        while sent
            .front()
            .is_some_and(|sent_at| now.duration_since(*sent_at) >= window)
        {
            sent.pop_front();
        }
        !sent.is_empty()
    });
}

fn short_window_len(
    budget: &HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>,
    key: &OutboundProbeBudgetKey,
) -> usize {
    budget.get(key).map_or(0, VecDeque::len)
}

fn long_window_len(
    budget: &HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>,
    key: &OutboundProbeBudgetKey,
) -> usize {
    budget.get(key).map_or(0, VecDeque::len)
}
