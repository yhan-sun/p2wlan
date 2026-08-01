//! Outbound probe budgets for UDP connectivity checks.
//!
//! The process-wide budget deliberately lives only in memory. Probe admission
//! is part of the async packet path, so file locking, rewriting, and fsync here
//! would stall traversal sessions on the daemon's Tokio workers.

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
}

pub(super) type OutboundProbeBudgetState =
    Arc<Mutex<HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>>>;

#[derive(Debug, Default)]
pub(super) struct GlobalOutboundProbeBudget {
    state: Mutex<HashMap<OutboundProbeBudgetKey, VecDeque<Instant>>>,
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
    ) -> OutboundProbeAdmission {
        let now = Instant::now();
        let network_key = OutboundProbeBudgetKey::Network;
        let peer_key = OutboundProbeBudgetKey::Peer(peer_id.to_string());
        let remote_ip_key =
            OutboundProbeBudgetKey::PeerRemoteIp(peer_id.to_string(), peer_addr.ip());
        let mut budget = self.state.lock().await;
        retain_live_budget_entries(&mut budget, now);

        if budget.get(&network_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_NETWORK {
            return OutboundProbeAdmission::GlobalNetworkRateLimited;
        }
        if budget.get(&peer_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_PEER {
            return OutboundProbeAdmission::GlobalPeerRateLimited;
        }
        if budget.get(&remote_ip_key).map_or(0, VecDeque::len)
            >= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP
        {
            return OutboundProbeAdmission::GlobalRemoteIpRateLimited;
        }

        budget.entry(network_key).or_default().push_back(now);
        budget.entry(peer_key).or_default().push_back(now);
        budget.entry(remote_ip_key).or_default().push_back(now);
        OutboundProbeAdmission::Accepted
    }
}

pub(super) const OUTBOUND_PROBE_BUDGET_WINDOW: Duration = Duration::from_secs(1);
pub(super) const OUTBOUND_PROBE_BUDGET_PER_NETWORK: usize = 768;
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER: usize = 256;
// Symmetric NAT traversal often needs to sweep a short predicted port window
// against one public IP. Keep this bounded, but wide enough that the first
// synchronized punch is not cut off before the predicted window is covered.
pub(super) const OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OutboundProbeAdmission {
    Accepted,
    NetworkRateLimited,
    PeerRateLimited,
    RemoteIpRateLimited,
    GlobalNetworkRateLimited,
    GlobalPeerRateLimited,
    GlobalRemoteIpRateLimited,
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
    budget.retain(|_, sent| {
        while sent
            .front()
            .is_some_and(|sent_at| now.duration_since(*sent_at) >= OUTBOUND_PROBE_BUDGET_WINDOW)
        {
            sent.pop_front();
        }
        !sent.is_empty()
    });
}
