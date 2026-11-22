use crate::StunClient;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, time::Duration};
use tokio::task::JoinSet;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpReachability {
    #[default]
    Unknown,
    Available,
    Blocked,
}

/// Check configured STUN endpoints from independent connected sockets. These
/// observations never enter the NAT allocation sample for the tunnel socket.
pub async fn check_udp_reachability(
    targets: &[SocketAddr],
    interface: Option<&str>,
    budget: Duration,
) -> UdpReachability {
    if targets.is_empty() {
        return UdpReachability::Unknown;
    }
    let mut tasks = JoinSet::new();
    for target in targets.iter().copied().take(8) {
        let interface = interface.map(str::to_owned);
        tasks.spawn(async move {
            let bind = SocketAddr::new(
                if target.is_ipv4() {
                    std::net::Ipv4Addr::UNSPECIFIED.into()
                } else {
                    std::net::Ipv6Addr::UNSPECIFIED.into()
                },
                0,
            );
            let socket = p2pnet_netbind::bind_udp(bind, interface.as_deref())
                .await
                .ok()?;
            socket.connect(target).await.ok()?;
            Some(
                StunClient::with_timeout(budget)
                    .binding_request(&socket, target)
                    .await
                    .is_ok_and(|reply| reply.reflexive_address.is_some()),
            )
        });
    }
    let result = tokio::time::timeout(budget + Duration::from_millis(100), async {
        let mut all_attempted = true;
        while let Some(outcome) = tasks.join_next().await {
            match outcome {
                Ok(Some(true)) => return UdpReachability::Available,
                Ok(Some(false)) => continue,
                _ => all_attempted = false,
            }
        }
        if all_attempted {
            UdpReachability::Blocked
        } else {
            UdpReachability::Unknown
        }
    })
    .await
    .unwrap_or(UdpReachability::Unknown);
    tasks.shutdown().await;
    result
}
