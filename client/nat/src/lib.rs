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

pub mod adaptive;
pub mod client;
pub mod detection;
pub mod error;
pub mod ice;
pub mod mapping;
pub mod outbound_liveness;
pub mod punch;
pub mod stun;
pub mod traversal;

// Re-export key types
pub use adaptive::{DirectionPattern, ReverseDetector, StepLearner};
pub use client::{BindingResponse, StunClient, DEFAULT_TIMEOUT};
pub use detection::{DetectionConfig, NatDetector};
pub use error::{NatError, Result};
pub use ice::{
    candidate_report_from_observations, candidates_to_addrs, compute_priority,
    gather_candidate_report, gather_candidates, gather_local_addresses, gather_local_networks,
    parse_nat_hint, CandidateGatherReport, FilteringBehavior, HairpinBehavior, IceConfig,
    LocalNetwork, MappingBehavior, MappingLifetime, NatAllocation, NatFingerprintHint, NatProfile,
    StunObservation,
};
pub use mapping::{
    build_model, build_model_for_batch, model_is_fresh, modular_add, modular_difference,
    predict_ports, predict_ports_for_elapsed, predict_ports_with_learning, MappingBatch,
    MappingObservation, ModelRejection, PortModel, PortModelKind, PredictionCandidate,
    PredictionReason, MAX_PREDICTED_PORTS,
};
pub use punch::{
    build_authenticated_punch_ack, build_authenticated_punch_packet,
    build_authenticated_punch_packet_with_nomination, build_punch_ack, build_punch_packet,
    build_punch_packet_with_nonce, decode_authenticated_punch_packet, decode_punch_packet,
    hole_punch, peek_authenticated_punch_identity, send_keepalive, send_punch,
    AuthenticatedPunchIdentity, DecodedPunchPacket, ProbeMacKey, PunchConfig, PunchPacketKind,
    PunchResult,
};
pub use stun::{
    compute_fingerprint, crc32, StunAttribute, StunMessage, BINDING_ERROR_RESPONSE,
    BINDING_REQUEST, BINDING_RESPONSE, MAGIC_COOKIE,
};
pub use traversal::{
    confirmed_on_link_lan, plan_traversal, NatCapabilities, NatProfileEvidence, NetworkHint,
    RemoteNatProfile, TraversalCapability, TraversalContext, TraversalFallback, TraversalPlan,
    TraversalReason, TraversalStrategy, MIN_PREDICTION_CONFIDENCE,
};

use std::net::{IpAddr, SocketAddr};

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
        match self.ip.parse::<IpAddr>() {
            Ok(ip) => write!(f, "{}", SocketAddr::new(ip, self.port)),
            Err(_) => write!(f, "{}:{}", self.ip, self.port),
        }
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
    /// Endpoint opened by an explicit gateway mapping (UPnP/PCP/NAT-PMP).
    PortMapped,
    /// Server-reflexive address (from STUN).
    ServerReflexive,
    /// Peer-reflexive address (discovered during ICE).
    PeerReflexive,
    /// Relay address (via DERP/TURN).
    Relay,
}

/// Internal provenance for an ICE candidate.
///
/// This is intentionally local metadata. Control-plane compatibility is kept by
/// continuing to serialize candidates as plain endpoint strings, while newer
/// components may carry this source alongside the endpoint for diagnostics and
/// probe-budget decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateSource {
    /// Candidate came from local interface enumeration.
    Host,
    /// Candidate came from a successful STUN observation.
    StunObserved,
    /// Candidate was predicted from a stable observed NAT port delta.
    Predicted,
    /// Candidate was discovered from authenticated peer-reflexive traffic.
    PeerReflexive,
    /// Candidate came from an explicit gateway port mapping (UPnP/PCP/NAT-PMP).
    PortMapped,
    /// Candidate was manually configured or explicitly advertised.
    Manual,
    /// Candidate came from a relay transport.
    Relay,
}

/// Address classification kept separate from [`CandidateSource`].
///
/// A global-looking address is still only a `Host` candidate until an
/// independent observation (STUN, an explicit mapping, or authenticated
/// traffic) supplies public-reachability evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressScope {
    Unspecified,
    Loopback,
    Multicast,
    LinkLocal,
    Private,
    Shared,
    Global,
    Other,
}

/// Classify an address without changing its candidate provenance.
pub fn classify_address_scope(address: IpAddr) -> AddressScope {
    match address {
        IpAddr::V4(ip) => {
            if ip.is_unspecified() {
                AddressScope::Unspecified
            } else if ip.is_loopback() {
                AddressScope::Loopback
            } else if ip.is_multicast() || ip.is_broadcast() {
                AddressScope::Multicast
            } else if ip.is_link_local() {
                AddressScope::LinkLocal
            } else if ip.is_private() {
                AddressScope::Private
            } else if is_shared_ipv4(ip) {
                AddressScope::Shared
            } else if is_documentation_ipv4(ip) {
                AddressScope::Other
            } else {
                AddressScope::Global
            }
        }
        IpAddr::V6(ip) => {
            let first_segment = ip.segments()[0];
            if ip.is_unspecified() {
                AddressScope::Unspecified
            } else if ip.is_loopback() {
                AddressScope::Loopback
            } else if ip.is_multicast() {
                AddressScope::Multicast
            } else if (first_segment & 0xffc0) == 0xfe80 {
                AddressScope::LinkLocal
            } else if (first_segment & 0xfe00) == 0xfc00 {
                AddressScope::Private
            } else {
                AddressScope::Global
            }
        }
    }
}

fn is_shared_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_documentation_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
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
    /// Local-only candidate source metadata.
    pub source: CandidateSource,
}

impl IceCandidate {
    /// Create a host candidate.
    pub fn host(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::Host,
            endpoint: Endpoint::new(ip, port),
            priority: 100,
            source: CandidateSource::Host,
        }
    }

    /// Create an explicitly port-mapped candidate.
    pub fn port_mapped(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::PortMapped,
            endpoint: Endpoint::new(ip, port),
            priority: 95,
            source: CandidateSource::PortMapped,
        }
    }

    /// Create a server-reflexive candidate.
    pub fn server_reflexive(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::ServerReflexive,
            endpoint: Endpoint::new(ip, port),
            priority: 90,
            source: CandidateSource::StunObserved,
        }
    }

    /// Create a predicted server-reflexive candidate.
    pub fn predicted_server_reflexive(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::ServerReflexive,
            endpoint: Endpoint::new(ip, port),
            priority: 89,
            source: CandidateSource::Predicted,
        }
    }

    /// Create a relay candidate.
    pub fn relay(ip: &str, port: u16) -> Self {
        Self {
            candidate_type: CandidateType::Relay,
            endpoint: Endpoint::new(ip, port),
            priority: 50,
            source: CandidateSource::Relay,
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
        if matches!(
            candidate.candidate_type,
            CandidateType::ServerReflexive | CandidateType::PortMapped
        ) {
            self.public_endpoint = Some(candidate.endpoint.clone());
        }
        self.candidates.push(candidate);
    }

    /// Check if direct P2P is likely possible.
    ///
    /// # Deprecated
    ///
    /// This collapses NAT behavior into the legacy 5-way [`NatType`] enum and
    /// reports `false` for anything labelled `Symmetric`.  p2wlan actively
    /// traverses address-or-port-dependent (and partial symmetric) NATs via
    /// fresh-mapping prediction, so `false` here is a **false negative** — the
    /// peer is often directly reachable even when this returns `false`.
    ///
    /// Do not gate new path decisions on it.  Use the structured
    /// [`ice::MappingBehavior`] / [`ice::FilteringBehavior`] from
    /// [`ice::NatProfile`] (and the peer's `p2v2:` fingerprint), which
    /// distinguishes endpoint-dependent mapping from true symmetric behavior.
    /// Retained only for wire compatibility with older discovery payloads.
    #[deprecated(
        since = "0.1.118",
        note = "legacy NatType enum under-reports traversability; use ice::MappingBehavior / NatProfile instead"
    )]
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
    fn endpoint_display_formats_ipv6_socket_addr() {
        let ep = Endpoint::new("2001:db8::1", 5678);

        assert_eq!(ep.to_string(), "[2001:db8::1]:5678");
        assert_eq!(
            ep.to_socket_addr().unwrap(),
            "[2001:db8::1]:5678".parse().unwrap()
        );
    }

    #[test]
    fn test_candidate_creation() {
        let host = IceCandidate::host("192.168.1.1", 5000);
        assert_eq!(host.candidate_type, CandidateType::Host);
        assert_eq!(host.source, CandidateSource::Host);
        assert_eq!(host.priority, 100);

        let srflx = IceCandidate::server_reflexive("1.2.3.4", 5678);
        assert_eq!(srflx.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(srflx.source, CandidateSource::StunObserved);

        let predicted = IceCandidate::predicted_server_reflexive("1.2.3.4", 5680);
        assert_eq!(predicted.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(predicted.source, CandidateSource::Predicted);
    }

    #[test]
    #[allow(deprecated)] // wire-compat: the legacy enum value must stay stable
    fn test_nat_discovery() {
        let mut result = NatDiscoveryResult::new(NatType::FullCone);
        result.add_candidate(IceCandidate::host("192.168.1.1", 5000));
        result.add_candidate(IceCandidate::server_reflexive("1.2.3.4", 5678));

        assert!(result.public_endpoint.is_some());
        assert_eq!(result.candidates.len(), 2);
        assert!(result.can_p2p());
    }

    #[test]
    #[allow(deprecated)] // wire-compat: the legacy enum value must stay stable
    fn test_symmetric_cannot_p2p() {
        let result = NatDiscoveryResult::new(NatType::Symmetric);
        assert!(!result.can_p2p());
    }

    // The legacy `can_p2p` value is intentionally frozen for wire
    // compatibility (older discovery payloads still carry it).  The structured
    // profile, not this enum, is what p2wlan gates traversal on today — see the
    // deprecation note on `can_p2p`.  This test pins that the frozen legacy
    // mapping has not drifted while the structured path is the authority.
    #[test]
    #[allow(deprecated)]
    fn can_p2p_legacy_value_is_frozen_for_wire_compat() {
        let symmetric = NatDiscoveryResult::new(NatType::Symmetric);
        assert!(!symmetric.can_p2p(), "Symmetric historically reports false");
        for nat_type in [
            NatType::Open,
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::PortRestrictedCone,
            NatType::Unknown,
        ] {
            let result = NatDiscoveryResult::new(nat_type);
            assert!(
                result.can_p2p(),
                "{nat_type:?} must still report true (unchanged legacy value)"
            );
        }
    }
}
