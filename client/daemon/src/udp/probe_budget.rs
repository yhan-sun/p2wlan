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
use std::sync::Arc;
#[cfg(not(test))]
use std::sync::OnceLock;
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
}

pub(super) const OUTBOUND_PROBE_BUDGET_WINDOW: Duration = Duration::from_secs(1);
pub(super) const OUTBOUND_PROBE_BUDGET_PER_NETWORK: usize = 1024;
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER: usize = 512;
// Symmetric NAT traversal often needs to sweep a short predicted port window
// against one public IP from multiple local sockets. Keep this bounded, but
// wide enough that a 96-port predicted/birthday window can be tried from a
// four-socket pool during one synchronized punch.
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP: usize = 384;

/// Persistent budgets span retries: they are only pruned every
/// `OUTBOUND_PROBE_PERSISTENT_WINDOW`, so repeated punch sessions share one
/// long-term allowance instead of each refilling its own 1-second window.
pub(super) const OUTBOUND_PROBE_PERSISTENT_WINDOW: Duration = Duration::from_secs(60);
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_NETWORK: usize = 12_000;
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_PEER: usize = 6_000;
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_PEER_REMOTE_IP: usize = 4_500;
pub(super) const OUTBOUND_PROBE_PERSISTENT_PER_PEER_SOCKET: usize = 3_000;

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
