//! # p2pnet-nat
//!
//! NAT traversal for P2PNet using STUN, ICE, and UDP Hole Punching.
//!
//! ## Overview
//!
//! - **STUN**: Discover public endpoint (IP + port) as seen by a STUN server
//! - **ICE**: Gather and prioritize candidate addresses
//! - **UDP Hole Punching**: Establish direct P2P connection through NAT
//!
//! ## Status
//!
//! Phase 3 module.

pub mod client;
pub mod detection;
pub mod error;
pub mod ice;
pub mod punch;
pub mod stun;

// Re-export key types
pub use client::{BindingResponse, StunClient, DEFAULT_TIMEOUT};
pub use detection::{DetectionConfig, NatDetector};
pub use error::{NatError, Result};
pub use ice::{
    candidates_to_addrs, compute_priority, gather_candidates, gather_local_addresses, IceConfig,
};
pub use punch::{
    build_punch_ack, build_punch_packet, decode_punch_packet, hole_punch, send_keepalive,
    send_punch, DecodedPunchPacket, PunchConfig, PunchPacketKind, PunchResult,
};
pub use stun::{
    compute_fingerprint, crc32, StunAttribute, StunMessage, BINDING_ERROR_RESPONSE,
    BINDING_REQUEST, BINDING_RESPONSE, MAGIC_COOKIE,
};

use std::net::SocketAddr;

/// NAT type classification (RFC 3489).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP).
    Open,
    /// Full Cone NAT (easiest to traverse).
    FullCone,
    /// Restricted Cone NAT.
    RestrictedCone,
    /// Port Restricted Cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse, often requires relay).
    Symmetric,
    /// Unknown NAT type.
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Open => write!(f, "Open"),
            NatType::FullCone => write!(f, "Full Cone"),
            NatType::RestrictedCone => write!(f, "Restricted Cone"),
            NatType::PortRestrictedCone => write!(f, "Port Restricted Cone"),
            NatType::Symmetric => write!(f, "Symmetric"),
            NatType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// A network endpoint (public address as seen by an external observer).
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// IP address (public).
    pub ip: String,
    /// Port number.
    pub port: u16,
}

impl Endpoint {
    /// Create a new endpoint.
    pub fn new(ip: &str, port: u16) -> Self {
        Self {
            ip: ip.to_string(),
            port,
        }
    }

    /// Parse from a "ip:port" string.
    pub fn parse(s: &str) -> Option<Self> {
        let addr: SocketAddr = s.parse().ok()?;
        Some(Self {
            ip: addr.ip().to_string(),
            port: addr.port(),
        })
    }

    /// Convert to a `SocketAddr`.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        self.to_string().parse().ok()
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.ip, self.port)
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        Self {
            ip: addr.ip().to_string(),
            port: addr.port(),
        }
    }
}

impl From<&SocketAddr> for Endpoint {
    fn from(addr: &SocketAddr) -> Self {
        Self {
            ip: addr.ip().to_string(),
            port: addr.port(),
        }
    }
}

/// ICE candidate types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Local network address (e.g. 192.168.1.100).
    Host,
    /// Server-reflexive address (from STUN).
    ServerReflexive,
    /// Peer-reflexive address (discovered during ICE).
    PeerReflexive,
    /// Relay address (via DERP/TURN).
    Relay,
}

/// An ICE candidate address.
#[derive(Debug, Clone)]
pub struct IceCandidate {
    /// Candidate type.
    pub candidate_type: CandidateType,
    /// The endpoint address.
    pub endpoint: Endpoint,
    /// Priority (higher = preferred).
    pub priority: u32,
}

impl IceCandidate {
    /// Create a host candidate.
    pub fn host(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::Host,
            endpoint: Endpoint::new(ip, port),
            priority: 100,
        }
    }

    /// Create a server-reflexive candidate.
    pub fn server_reflexive(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::ServerReflexive,
            endpoint: Endpoint::new(ip, port),
            priority: 90,
        }
    }

    /// Create a relay candidate.
    pub fn relay(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::Relay,
            endpoint: Endpoint::new(ip, port),
            priority: 50,
        }
    }
}

/// Result of NAT discovery.
#[derive(Debug, Clone)]
pub struct NatDiscoveryResult {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Public endpoint (if discovered).
    pub public_endpoint: Option<Endpoint>,
    /// All gathered ICE candidates.
    pub candidates: Vec<IceCandidate>,
}

impl NatDiscoveryResult {
    /// Create a new result.
    pub fn new(nat_type: NatType) -> Self {
        Self {
            nat_type,
            public_endpoint: None,
            candidates: Vec::new(),
        }
    }

    /// Add a candidate.
    pub fn add_candidate(&mut self, candidate: IceCandidate) {
        if candidate.candidate_type == CandidateType::ServerReflexive {
            self.public_endpoint = Some(candidate.endpoint.clone());
        }
        self.candidates.push(candidate);
    }

    /// Check if direct P2P is likely possible.
    pub fn can_p2p(&self) -> bool {
        !matches!(self.nat_type, NatType::Symmetric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_display() {
        assert_eq!(NatType::Open.to_string(), "Open");
        assert_eq!(NatType::FullCone.to_string(), "Full Cone");
        assert_eq!(NatType::Symmetric.to_string(), "Symmetric");
    }

    #[test]
    fn test_endpoint_parse() {
        let ep = Endpoint::parse("1.2.3.4:5678").unwrap();
        assert_eq!(ep.ip, "1.2.3.4");
        assert_eq!(ep.port, 5678);
    }

    #[test]
    fn test_candidate_creation() {
        let host = IceCandidate::host("192.168.1.1", 5000);
        assert_eq!(host.candidate_type, CandidateType::Host);
        assert_eq!(host.priority, 100);

        let srflx = IceCandidate::server_reflexive("1.2.3.4", 5678);
        assert_eq!(srflx.candidate_type, CandidateType::ServerReflexive);
    }

    #[test]
    fn test_nat_discovery() {
        let mut result = NatDiscoveryResult::new(NatType::FullCone);
        result.add_candidate(IceCandidate::host("192.168.1.1", 5000));
        result.add_candidate(IceCandidate::server_reflexive("1.2.3.4", 5678));

        assert!(result.public_endpoint.is_some());
        assert_eq!(result.candidates.len(), 2);
        assert!(result.can_p2p());
    }

    #[test]
    fn test_symmetric_cannot_p2p() {
        let result = NatDiscoveryResult::new(NatType::Symmetric);
        assert!(!result.can_p2p());
    }
}
