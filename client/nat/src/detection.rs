//! NAT type detection using STUN.
//!
//! Implements both the classic RFC 3489 algorithm (with CHANGE-REQUEST) and
//! a simplified heuristic (using two different STUN servers) for servers that
//! don't support CHANGE-REQUEST.
//!
//! ## Detection Algorithm (Simplified)
//!
//! 1. Query STUN server 1 → get reflexive address R1
//! 2. Query STUN server 2 → get reflexive address R2
//! 3. If no response → UDP blocked
//! 4. If R1 matches local address → Open (no NAT)
//! 5. If R1.port == R2.port → Cone NAT (Full/Restricted/PortRestricted)
//!    (exact sub-type requires CHANGE-REQUEST support)
//! 6. If R1.port != R2.port → Symmetric NAT
//!
//! ## Detection Algorithm (Full, requires CHANGE-REQUEST support)
//!
//! - Test 1: Send to Server 1, no change → get R1
//! - Test 2: Send to Server 1, change IP+port → if response: Full Cone
//! - Test 3: Send to Server 1, change port → if response: Restricted Cone
//! - Test 1b: Send to Server 2 → get R2
//! - If R1 != R2: Symmetric NAT
//! - Otherwise: Port Restricted Cone

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::client::StunClient;
use crate::error::{NatError, Result};
use crate::{Endpoint, IceCandidate, NatDiscoveryResult, NatType};

/// Configuration for NAT detection.
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// List of STUN server addresses to use.
    /// At least 2 are needed for Symmetric NAT detection.
    pub stun_servers: Vec<SocketAddr>,
    /// Timeout per STUN query.
    pub timeout: Duration,
    /// Local port to bind the test socket (0 = random).
    pub local_port: u16,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            timeout: Duration::from_secs(3),
            local_port: 0,
        }
    }
}

/// NAT type detector.
pub struct NatDetector {
    config: DetectionConfig,
    stun_client: StunClient,
}

impl NatDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: DetectionConfig) -> Self {
        let timeout = config.timeout;
        Self {
            config,
            stun_client: StunClient::with_timeout(timeout),
        }
    }

    /// Create a detector with default settings and the given STUN servers.
    pub fn with_servers(servers: Vec<SocketAddr>) -> Self {
        let config = DetectionConfig {
            stun_servers: servers,
            ..Default::default()
        };
        Self::new(config)
    }

    /// Run NAT detection and return the result.
    ///
    /// This uses the simplified detection algorithm (2 servers, no CHANGE-REQUEST).
    pub async fn detect(&self) -> Result<NatDiscoveryResult> {
        if self.config.stun_servers.is_empty() {
            return Err(NatError::DetectionFailed(
                "no STUN servers configured".into(),
            ));
        }

        let bind_addr = if self.config.local_port > 0 {
            format!("0.0.0.0:{}", self.config.local_port)
        } else {
            "0.0.0.0:0".to_string()
        };

        let socket = UdpSocket::bind(&bind_addr).await.map_err(NatError::Io)?;
        let local_addr = socket.local_addr()?;

        info!("Starting NAT detection from {}", local_addr);

        // Query the first STUN server
        let server1 = self.config.stun_servers[0];
        let resp1 = match self.stun_client.binding_request(&socket, server1).await {
            Ok(r) => r,
            Err(e) => {
                warn!("First STUN server {} failed: {}", server1, e);
                // Try remaining servers
                let mut found = false;
                let mut resp = None;
                for &srv in &self.config.stun_servers[1..] {
                    if let Ok(r) = self.stun_client.binding_request(&socket, srv).await {
                        resp = Some(r);
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(NatError::DetectionFailed(
                        "all STUN servers unreachable — UDP may be blocked".into(),
                    ));
                }
                resp.unwrap()
            }
        };

        let reflexive1 = resp1.reflexive_address.ok_or_else(|| {
            NatError::DetectionFailed("STUN server did not return reflexive address".into())
        })?;

        debug!("First STUN response: reflexive = {}", reflexive1);

        // Check if we're on open internet (no NAT)
        if reflexive1.ip() == local_addr.ip() {
            info!("Open internet (no NAT detected)");
            let mut result = NatDiscoveryResult::new(NatType::Open);
            result.add_candidate(IceCandidate::host(
                &local_addr.ip().to_string(),
                local_addr.port(),
            ));
            result.add_candidate(IceCandidate::server_reflexive(
                &reflexive1.ip().to_string(),
                reflexive1.port(),
            ));
            result.public_endpoint = Some(Endpoint::from(reflexive1));
            return Ok(result);
        }

        // We have NAT — try to detect the type
        let nat_type = if self.config.stun_servers.len() >= 2 {
            // Query the second STUN server
            let server2 = self.config.stun_servers[1];
            match self.stun_client.binding_request(&socket, server2).await {
                Ok(resp2) => {
                    let reflexive2 = resp2.reflexive_address;
                    if let Some(r2) = reflexive2 {
                        debug!("Second STUN response: reflexive = {}", r2);
                        if r2.port() == reflexive1.port() {
                            // Same port → Cone NAT
                            // Without CHANGE-REQUEST support, we can't tell which type of Cone NAT
                            // Assume Port Restricted (most conservative that still allows P2P)
                            info!("Cone NAT detected (port consistent across servers)");
                            NatType::PortRestrictedCone
                        } else {
                            // Different port → Symmetric NAT
                            info!("Symmetric NAT detected (port changed across servers)");
                            NatType::Symmetric
                        }
                    } else {
                        warn!("Second STUN server returned no reflexive address");
                        NatType::Unknown
                    }
                }
                Err(e) => {
                    warn!("Second STUN server {} failed: {}", server2, e);
                    // Can't determine — assume unknown
                    NatType::Unknown
                }
            }
        } else {
            // Only one server — can't detect Symmetric NAT
            info!("Only one STUN server configured — assuming Cone NAT");
            NatType::PortRestrictedCone
        };

        let mut result = NatDiscoveryResult::new(nat_type);
        result.add_candidate(IceCandidate::host(
            &local_addr.ip().to_string(),
            local_addr.port(),
        ));
        result.add_candidate(IceCandidate::server_reflexive(
            &reflexive1.ip().to_string(),
            reflexive1.port(),
        ));
        result.public_endpoint = Some(Endpoint::from(reflexive1));

        info!("NAT detection complete: type = {}", nat_type);
        Ok(result)
    }

    /// Run full NAT detection with CHANGE-REQUEST support.
    ///
    /// This requires STUN servers that support the CHANGE-REQUEST attribute.
    /// Most public STUN servers do NOT support this.
    pub async fn detect_full(&self) -> Result<NatDiscoveryResult> {
        if self.config.stun_servers.is_empty() {
            return Err(NatError::DetectionFailed(
                "no STUN servers configured".into(),
            ));
        }

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;
        let server1 = self.config.stun_servers[0];

        info!("Starting full NAT detection from {}", local_addr);

        // Test 1: Send Binding Request to Server 1 (no change)
        let resp1 = self.stun_client.binding_request(&socket, server1).await?;
        let reflexive1 = resp1.reflexive_address.ok_or_else(|| {
            NatError::DetectionFailed("no reflexive address from server 1".into())
        })?;

        // Check open internet
        if reflexive1.ip() == local_addr.ip() {
            let mut result = NatDiscoveryResult::new(NatType::Open);
            result.add_candidate(IceCandidate::host(
                &local_addr.ip().to_string(),
                local_addr.port(),
            ));
            result.add_candidate(IceCandidate::server_reflexive(
                &reflexive1.ip().to_string(),
                reflexive1.port(),
            ));
            result.public_endpoint = Some(Endpoint::from(reflexive1));
            return Ok(result);
        }

        // Test 2: Send to Server 1 with CHANGE-REQUEST (change IP + port)
        let test2 = self
            .stun_client
            .binding_request_with_change(&socket, server1, true, true)
            .await;

        if test2.is_ok() {
            // Got response from a different IP+port → Full Cone NAT
            info!("Full Cone NAT detected (response from changed IP+port)");
            return Ok(Self::build_result(
                NatType::FullCone,
                reflexive1,
                local_addr,
            ));
        }

        // Test 1b: Send to a second STUN server to check for Symmetric NAT
        if self.config.stun_servers.len() >= 2 {
            let server2 = self.config.stun_servers[1];
            if let Ok(resp2) = self.stun_client.binding_request(&socket, server2).await {
                if let Some(reflexive2) = resp2.reflexive_address {
                    if reflexive2.port() != reflexive1.port() {
                        // Different port → Symmetric NAT
                        info!("Symmetric NAT detected (port changed with different server)");
                        return Ok(Self::build_result(
                            NatType::Symmetric,
                            reflexive1,
                            local_addr,
                        ));
                    }
                }
            }
        }

        // Test 3: Send to Server 1 with CHANGE-REQUEST (change port only)
        let test3 = self
            .stun_client
            .binding_request_with_change(&socket, server1, false, true)
            .await;

        if test3.is_ok() {
            // Got response from changed port → Restricted Cone NAT
            info!("Restricted Cone NAT detected (response from changed port)");
            return Ok(Self::build_result(
                NatType::RestrictedCone,
                reflexive1,
                local_addr,
            ));
        }

        // All tests failed → Port Restricted Cone NAT
        info!("Port Restricted Cone NAT detected");
        Ok(Self::build_result(
            NatType::PortRestrictedCone,
            reflexive1,
            local_addr,
        ))
    }

    fn build_result(
        nat_type: NatType,
        reflexive: SocketAddr,
        local: SocketAddr,
    ) -> NatDiscoveryResult {
        let mut result = NatDiscoveryResult::new(nat_type);
        result.add_candidate(IceCandidate::host(&local.ip().to_string(), local.port()));
        result.add_candidate(IceCandidate::server_reflexive(
            &reflexive.ip().to_string(),
            reflexive.port(),
        ));
        result.public_endpoint = Some(Endpoint::from(reflexive));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Spawn a mock STUN server with a configurable reflexive port.
    /// If `reflexive_port_override` is Some(port), the server pretends the
    /// client's port is different (simulating Symmetric NAT behavior).
    async fn spawn_mock_stun_server(
        port_override: Option<u16>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            while let Ok((len, client_addr)) = socket.recv_from(&mut buf).await {
                if let Ok(req) = StunMessage::decode(&buf[..len]) {
                    if req.msg_type == BINDING_REQUEST {
                        // Check for CHANGE-REQUEST
                        let mut _change_ip = false;
                        let mut _change_port = false;
                        for attr in &req.attributes {
                            if let StunAttribute::ChangeRequest {
                                change_ip: ci,
                                change_port: cp,
                            } = attr
                            {
                                _change_ip = *ci;
                                _change_port = *cp;
                            }
                        }

                        let reflexive_addr = if let Some(port) = port_override {
                            SocketAddr::new(client_addr.ip(), port)
                        } else {
                            client_addr
                        };

                        let mut resp =
                            StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
                        resp.add_attribute(StunAttribute::XorMappedAddress(reflexive_addr));

                        // If CHANGE-REQUEST requested, respond from a "different" address
                        // (In this test we can't easily change the source address,
                        // so we just respond normally — the test will check the reflexive addr)
                        let encoded = resp.encode();
                        let _ = socket.send_to(&encoded, client_addr).await;
                    }
                }
            }
        });

        (addr, handle)
    }

    #[tokio::test]
    async fn test_detect_cone_nat() {
        // Single mock server — no port override → consistent port
        let (server, _handle) = spawn_mock_stun_server(None).await;

        let config = DetectionConfig {
            stun_servers: vec![server],
            timeout: Duration::from_secs(2),
            local_port: 0,
        };

        let detector = NatDetector::new(config);
        let result = detector.detect().await.unwrap();

        // Should detect as some form of Cone NAT (PortRestrictedCone with our heuristic)
        assert_ne!(result.nat_type, NatType::Symmetric);
        assert!(result.public_endpoint.is_some());
        assert_eq!(result.candidates.len(), 2); // host + srflx
    }

    #[tokio::test]
    async fn test_detect_symmetric_nat() {
        // Two mock servers with different port overrides
        let (server1, _h1) = spawn_mock_stun_server(Some(12345)).await;
        let (server2, _h2) = spawn_mock_stun_server(Some(54321)).await;

        let config = DetectionConfig {
            stun_servers: vec![server1, server2],
            timeout: Duration::from_secs(2),
            local_port: 0,
        };

        let detector = NatDetector::new(config);
        let result = detector.detect().await.unwrap();

        // Different ports → Symmetric NAT
        assert_eq!(result.nat_type, NatType::Symmetric);
        assert!(!result.can_p2p());
    }

    #[tokio::test]
    async fn test_detect_with_consistent_ports() {
        // Two mock servers with the same port override
        let (server1, _h1) = spawn_mock_stun_server(Some(9999)).await;
        let (server2, _h2) = spawn_mock_stun_server(Some(9999)).await;

        let config = DetectionConfig {
            stun_servers: vec![server1, server2],
            timeout: Duration::from_secs(2),
            local_port: 0,
        };

        let detector = NatDetector::new(config);
        let result = detector.detect().await.unwrap();

        // Same port → Cone NAT (not Symmetric)
        assert_ne!(result.nat_type, NatType::Symmetric);
        assert!(result.can_p2p());
    }

    #[tokio::test]
    async fn test_no_stun_servers() {
        let config = DetectionConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let detector = NatDetector::new(config);
        let result = detector.detect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_all_servers_unreachable() {
        // Use a port that's unlikely to have a server
        let config = DetectionConfig {
            stun_servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1)],
            timeout: Duration::from_millis(300),
            local_port: 0,
        };
        let detector = NatDetector::new(config);
        let result = detector.detect().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_detected_result_has_candidates() {
        let (server, _handle) = spawn_mock_stun_server(None).await;

        let config = DetectionConfig {
            stun_servers: vec![server],
            timeout: Duration::from_secs(2),
            ..Default::default()
        };

        let detector = NatDetector::new(config);
        let result = detector.detect().await.unwrap();

        assert!(!result.candidates.is_empty());

        // Should have at least one host candidate and one srflx candidate
        let has_host = result
            .candidates
            .iter()
            .any(|c| c.candidate_type == crate::CandidateType::Host);
        let has_srflx = result
            .candidates
            .iter()
            .any(|c| c.candidate_type == crate::CandidateType::ServerReflexive);
        assert!(has_host);
        assert!(has_srflx);
    }
}
