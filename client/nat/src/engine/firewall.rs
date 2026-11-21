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
                    .is_ok(),
            )
        });
    }
    let mut attempted = false;
    let result = tokio::time::timeout(budget + Duration::from_millis(100), async {
        while let Some(outcome) = tasks.join_next().await {
            match outcome {
                Ok(Some(true)) => return UdpReachability::Available,
                Ok(Some(false)) => attempted = true,
                _ => {}
            }
        }
        if attempted {
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
