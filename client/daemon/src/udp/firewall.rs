use super::*;
use p2pnet_nat::engine::{check_udp_reachability, UdpReachability};
use tokio::{sync::OnceCell, time::Instant as Clock};

const RECHECK: Duration = Duration::from_secs(10);
struct Observation {
    network: u64,
    started: Clock,
    previously_blocked: bool,
    verdict: Arc<OnceCell<UdpReachability>>,
}
#[derive(Default)]
pub(super) struct FirewallCache {
    entry: Option<Observation>,
}

impl UdpTransport {
    pub(super) fn blocked_recheck_at(&self, network: u64) -> Option<Clock> {
        let cache = self
            .firewall_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = cache.entry.as_ref()?;
        if entry.network != network {
            return None;
        }
        match entry.verdict.get() {
            Some(UdpReachability::Blocked) => Some(entry.started + RECHECK),
            Some(UdpReachability::Unknown) if entry.previously_blocked => {
                Some(entry.started + RECHECK)
            }
            None if entry.previously_blocked => Some(entry.started),
            _ => None,
        }
    }

    pub(super) async fn firewall_verdict(&self, network: u64) -> UdpReachability {
        let started = Clock::now();
        let verdict = {
            let mut cache = self
                .firewall_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if self.peers.current_network_generation_sync() != network {
                return UdpReachability::Unknown;
            }
            let previously_blocked = cache.entry.as_ref().is_some_and(|old| {
                old.network == network
                    && match old.verdict.get() {
                        Some(UdpReachability::Available) => false,
                        Some(UdpReachability::Blocked) => true,
                        _ => old.previously_blocked,
                    }
            });
            let entry = cache
                .entry
                .take()
                .filter(|entry| entry.network == network && started - entry.started < RECHECK);
            let entry = cache.entry.insert(entry.unwrap_or_else(|| Observation {
                network,
                started,
                previously_blocked,
                verdict: Arc::new(OnceCell::new()),
            }));
            entry.verdict.clone()
        };
        // All peers share the same actual observation. Cancellation releases
        // the initializer and a following waiter can finish the transaction.
        let status = *verdict
            .get_or_init(|| async {
                let specs = self.peers.configured_firewall_targets();
                if specs.is_empty() {
                    return UdpReachability::Unknown;
                }
                match crate::parse_stun_servers(&specs, Duration::from_secs(1)).await {
                    Ok(targets) => {
                        check_udp_reachability(
                            &targets,
                            self.outbound_interface.as_deref(),
                            Duration::from_millis(800),
                        )
                        .await
                    }
                    Err(_) => UdpReachability::Unknown,
                }
            })
            .await;
        let cache = self
            .firewall_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.peers.current_network_generation_sync() == network
            && cache
                .entry
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(&entry.verdict, &verdict))
        {
            status
        } else {
            UdpReachability::Unknown
        }
    }
}
