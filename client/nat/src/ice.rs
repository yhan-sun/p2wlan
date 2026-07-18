//! ICE candidate gathering and prioritization (RFC 5245).
//!
//! ## Candidate Types
//!
//! - **Host**: Local network interface address (highest priority)
//! - **Server Reflexive (srflx)**: Public address discovered via STUN
//! - **Peer Reflexive (prflx)**: Discovered during ICE connectivity checks
//! - **Relay**: DERP/TURN relay address (lowest priority)
//!
//! ## Priority Formula (RFC 5245)
//!
//! `priority = 2^24 * type_preference + 2^8 * local_preference + component_id`
//!
//! | Type | Preference |
//! |------|-----------|
//! | Host | 126 |
//! | PeerReflexive | 110 |
//! | ServerReflexive | 100 |
//! | Relay | 0 |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use if_addrs::IfAddr;
use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::client::StunClient;
use crate::error::Result;
use crate::{CandidateType, IceCandidate};

/// Type preference values (RFC 5245 Section 4.1.2.1).
const PREF_HOST: u32 = 126;
const PREF_PEER_REFLEXIVE: u32 = 110;
const PREF_SERVER_REFLEXIVE: u32 = 100;
const PREF_RELAY: u32 = 0;

/// Local preference (use max for all interfaces equally).
const LOCAL_PREF: u32 = 65535;

/// Component ID (1 for the only component in our P2P tunnel).
const COMPONENT_ID: u32 = 1;

/// Configuration for ICE candidate gathering.
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// STUN servers for server-reflexive candidate discovery.
    pub stun_servers: Vec<SocketAddr>,
    /// Timeout for STUN queries.
    pub stun_timeout: Duration,
    /// Whether to gather host candidates.
    pub gather_host: bool,
    /// Whether to gather server-reflexive candidates.
    pub gather_srflx: bool,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_secs(3),
            gather_host: true,
            gather_srflx: true,
        }
    }
}

/// Compute the ICE priority for a candidate.
pub fn compute_priority(candidate_type: CandidateType) -> u32 {
    let type_pref = match candidate_type {
        CandidateType::Host => PREF_HOST,
        CandidateType::PeerReflexive => PREF_PEER_REFLEXIVE,
        CandidateType::ServerReflexive => PREF_SERVER_REFLEXIVE,
        CandidateType::Relay => PREF_RELAY,
    };
    (1u32 << 24) * type_pref + (1u32 << 8) * LOCAL_PREF + COMPONENT_ID
}

/// Gather local network interface addresses.
///
/// Enumerates interface addresses first, then supplements them with UDP route
/// probes. Interface enumeration is important on hosts with VPN/utun routes
/// that hijack every public route probe, while the actual LAN address remains
/// available on a physical interface.
pub fn gather_local_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();

    for (name, ip) in interface_addresses() {
        if is_candidate_interface_name(&name) && is_candidate_host_ip(ip) {
            push_unique(&mut addresses, ip);
        }
    }

    for probe in ["1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53"] {
        if let Some(ip) = route_probe_source_ip("0.0.0.0:0", probe) {
            push_unique(&mut addresses, ip);
        }
    }

    for probe in ["[2606:4700:4700::1111]:53", "[2001:4860:4860::8888]:53"] {
        if let Some(ip) = route_probe_source_ip("[::]:0", probe) {
            push_unique(&mut addresses, ip);
        }
    }

    // Always include loopback
    let loopback_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    push_unique(&mut addresses, loopback_v4);

    addresses
}

fn interface_addresses() -> Vec<(String, IpAddr)> {
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces
            .into_iter()
            .map(|iface| {
                let ip = match iface.addr {
                    IfAddr::V4(v4) => IpAddr::V4(v4.ip),
                    IfAddr::V6(v6) => IpAddr::V6(v6.ip),
                };
                (iface.name, ip)
            })
            .collect(),
        Err(err) => {
            debug!("failed to enumerate local interfaces: {}", err);
            Vec::new()
        }
    }
}

fn route_probe_source_ip(bind: &str, probe: &str) -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if is_candidate_host_ip(ip) {
        Some(ip)
    } else {
        None
    }
}

fn push_unique(addresses: &mut Vec<IpAddr>, ip: IpAddr) {
    if !addresses.contains(&ip) {
        addresses.push(ip);
    }
}

fn is_candidate_host_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_candidate_ipv4(ip),
        IpAddr::V6(ip) => is_candidate_ipv6(ip),
    }
}

fn is_candidate_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_link_local()
}

fn is_candidate_ipv6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !is_ipv6_unicast_link_local(ip)
}

fn is_ipv6_unicast_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_candidate_interface_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ![
        "lo", "utun", "tun", "tap", "wg", "p2pnet", "p2wlan", "wintun", "docker", "br-", "veth",
        "llw", "awdl",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// Gather ICE candidates for the given socket.
///
/// This function:
/// 1. Enumerates local interfaces → host candidates
/// 2. Queries STUN servers → server-reflexive candidates
/// 3. Sorts candidates by priority (highest first)
pub async fn gather_candidates(
    socket: &UdpSocket,
    config: &IceConfig,
) -> Result<Vec<IceCandidate>> {
    let local_addr = socket.local_addr()?;
    let mut candidates = Vec::new();

    // 1. Host candidates
    if config.gather_host {
        let local_ips = gather_local_addresses();
        for ip in local_ips {
            let candidate = IceCandidate {
                candidate_type: CandidateType::Host,
                endpoint: crate::Endpoint::new(&ip.to_string(), local_addr.port()),
                priority: compute_priority(CandidateType::Host),
            };
            debug!("Host candidate: {}", candidate.endpoint.to_string());
            candidates.push(candidate);
        }
    }

    // 2. Server-reflexive candidates
    if config.gather_srflx && !config.stun_servers.is_empty() {
        let stun_client = StunClient::with_timeout(config.stun_timeout);

        for &server in &config.stun_servers {
            match stun_client.get_reflexive_address(socket, server).await {
                Ok(reflexive) => {
                    let candidate = IceCandidate {
                        candidate_type: CandidateType::ServerReflexive,
                        endpoint: crate::Endpoint::new(
                            &reflexive.ip().to_string(),
                            reflexive.port(),
                        ),
                        priority: compute_priority(CandidateType::ServerReflexive),
                    };
                    debug!(
                        "Server-reflexive candidate: {} (via {})",
                        candidate.endpoint.to_string(),
                        server
                    );
                    candidates.push(candidate);
                    break; // One srflx candidate is enough
                }
                Err(e) => {
                    debug!("STUN query to {} failed: {}", server, e);
                }
            }
        }
    }

    // 3. Sort by priority (highest first)
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));

    // Deduplicate by (type, endpoint) — same address with different types is valid
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert((c.candidate_type, c.endpoint.to_string())));

    info!("Gathered {} ICE candidates", candidates.len());
    Ok(candidates)
}

/// Convert ICE candidates to a list of SocketAddr for hole punching.
pub fn candidates_to_addrs(candidates: &[IceCandidate]) -> Vec<SocketAddr> {
    candidates
        .iter()
        .filter_map(|c| c.endpoint.to_socket_addr())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        let host_pri = compute_priority(CandidateType::Host);
        let srflx_pri = compute_priority(CandidateType::ServerReflexive);
        let prflx_pri = compute_priority(CandidateType::PeerReflexive);
        let relay_pri = compute_priority(CandidateType::Relay);

        assert!(host_pri > prflx_pri);
        assert!(prflx_pri > srflx_pri);
        assert!(srflx_pri > relay_pri);

        // Check exact values
        assert_eq!(host_pri, (1 << 24) * PREF_HOST + (1 << 8) * LOCAL_PREF + 1);
        assert_eq!(
            srflx_pri,
            (1 << 24) * PREF_SERVER_REFLEXIVE + (1 << 8) * LOCAL_PREF + 1
        );
    }

    #[test]
    fn test_gather_local_addresses() {
        let addrs = gather_local_addresses();
        assert!(!addrs.is_empty());

        // Should always include loopback
        assert!(addrs.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        let unique: std::collections::HashSet<_> = addrs.iter().copied().collect();
        assert_eq!(unique.len(), addrs.len());
    }

    #[test]
    fn test_candidate_host_ip_filter() {
        assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 2
        ))));
        assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 1
        ))));
        assert!(!is_candidate_host_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_candidate_host_ip(IpAddr::V6(
            "fe80::1".parse().unwrap()
        )));
        assert!(is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 2, 4
        ))));
    }

    #[test]
    fn test_candidate_interface_name_filter() {
        assert!(is_candidate_interface_name("en0"));
        assert!(is_candidate_interface_name("Ethernet"));
        assert!(is_candidate_interface_name("Wi-Fi"));

        for name in [
            "lo0", "utun6", "tun0", "tap0", "wg0", "p2pnet0", "p2wlan", "wintun", "docker0",
            "br-123", "vethabc", "llw0", "awdl0",
        ] {
            assert!(!is_candidate_interface_name(name), "{name}");
        }
    }

    #[test]
    fn test_push_unique_keeps_first_address() {
        let mut addrs = Vec::new();
        push_unique(&mut addrs, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)));
        push_unique(&mut addrs, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)));
        push_unique(&mut addrs, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)));
        assert_eq!(
            addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)),
                IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
            ]
        );
    }

    #[tokio::test]
    async fn test_gather_candidates_host_only() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let config = IceConfig {
            gather_host: true,
            gather_srflx: false,
            stun_servers: vec![],
            stun_timeout: Duration::from_secs(1),
        };

        let candidates = gather_candidates(&socket, &config).await.unwrap();
        assert!(!candidates.is_empty());

        // All should be host candidates
        assert!(candidates
            .iter()
            .all(|c| c.candidate_type == CandidateType::Host));

        // Should be sorted by priority (highest first)
        for i in 0..candidates.len().saturating_sub(1) {
            assert!(candidates[i].priority >= candidates[i + 1].priority);
        }
    }

    #[tokio::test]
    async fn test_gather_candidates_with_mock_stun() {
        let (server_addr, _handle) = crate::client::test_helpers::spawn_mock_stun_server().await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();

        let config = IceConfig {
            gather_host: true,
            gather_srflx: true,
            stun_servers: vec![server_addr],
            stun_timeout: Duration::from_secs(2),
        };

        let candidates = gather_candidates(&socket, &config).await.unwrap();

        // Should have at least one host and one srflx candidate
        let has_host = candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::Host);
        let has_srflx = candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::ServerReflexive);
        assert!(has_host);
        assert!(has_srflx);

        // The srflx candidate should have the same address as our local socket
        let srflx = candidates
            .iter()
            .find(|c| c.candidate_type == CandidateType::ServerReflexive)
            .unwrap();
        let srflx_addr = srflx.endpoint.to_socket_addr().unwrap();
        assert_eq!(srflx_addr, local);
    }

    #[test]
    fn test_candidates_to_addrs() {
        let candidates = vec![
            IceCandidate::host("192.168.1.1", 5000),
            IceCandidate::server_reflexive("1.2.3.4", 5678),
        ];

        let addrs = candidates_to_addrs(&candidates);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&"192.168.1.1:5000".parse().unwrap()));
        assert!(addrs.contains(&"1.2.3.4:5678".parse().unwrap()));
    }

    #[test]
    fn test_dedup_candidates() {
        // This test is about the dedup logic in gather_candidates
        // but since that requires async, we test the dedup logic here
        let mut candidates = vec![
            IceCandidate::host("127.0.0.1", 8080),
            IceCandidate::host("127.0.0.1", 8080), // duplicate
            IceCandidate::server_reflexive("1.2.3.4", 5678),
        ];

        let mut seen = std::collections::HashSet::new();
        candidates.retain(|c| seen.insert((c.candidate_type, c.endpoint.to_string())));

        assert_eq!(candidates.len(), 2);
    }
}
