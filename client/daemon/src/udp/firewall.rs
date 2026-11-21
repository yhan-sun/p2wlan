use super::*;
use p2pnet_nat::engine::{check_udp_reachability, UdpReachability};

#[derive(Default)]
pub(super) struct FirewallCache {
    entry: Option<(u64, Instant, UdpReachability)>,
}

impl UdpTransport {
    pub(super) async fn firewall_verdict(&self, network: u64) -> UdpReachability {
        let started = Instant::now();
        {
            let mut cache = self
                .firewall_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((generation, observed, status)) = cache.entry {
                if generation == network
                    && started.duration_since(observed) < Duration::from_secs(10)
                {
                    return status;
                }
            }
            cache.entry = Some((network, started, UdpReachability::Unknown));
        }
        let specs = self.peers.configured_firewall_targets();
        let status = if specs.is_empty() {
            UdpReachability::Unknown
        } else {
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
        };
        let mut cache = self
            .firewall_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if self.peers.current_network_generation_sync() == network
            && cache
                .entry
                .is_some_and(|(generation, time, _)| generation == network && time == started)
        {
            cache.entry = Some((network, started, status));
            return status;
        }
        UdpReachability::Unknown
    }
}
