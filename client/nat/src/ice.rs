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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

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
/// Uses a practical approach: connect a UDP socket to a well-known address
/// to determine the primary outgoing interface. Also includes loopback.
pub fn gather_local_addresses() -> Vec<IpAddr> {
    let mut addresses = Vec::new();

    // Try connecting to a public address to get the primary interface address
    // (UDP connect doesn't send packets, just sets the routing)
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:53").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    addresses.push(ip);
                }
            }
        }
    }

    // Try IPv6
    if let Ok(socket) = std::net::UdpSocket::bind("[::]:0") {
        if socket.connect("[2001:4860:4860::8888]:53").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() && !addresses.contains(&ip) {
                    addresses.push(ip);
                }
            }
        }
    }

    // Always include loopback
    let loopback_v4 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    if !addresses.contains(&loopback_v4) {
        addresses.push(loopback_v4);
    }

    addresses
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
