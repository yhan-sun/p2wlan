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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use if_addrs::IfAddr;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
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

/// Short timeout for best-effort active NAT behavior probes.
///
/// These probes run on the same UDP socket after ordinary STUN gathering. Keep
/// them intentionally small so diagnostics never turn startup into a long NAT
/// lab run when public STUN servers do not support CHANGE-REQUEST.
const ACTIVE_BEHAVIOR_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Short idle delay before re-checking whether the mapped endpoint is stable.
const MAPPING_LIFETIME_PROBE_DELAY: Duration = Duration::from_millis(250);

/// Prefix for self-addressed UDP hairpin probes.
const HAIRPIN_PROBE_PREFIX: &[u8] = b"P2WLAN_HAIRPIN_V1";

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

/// One STUN observation collected from a single external observer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StunObservation {
    /// STUN server queried.
    pub server: String,
    /// Public mapped address seen by the server.
    pub mapped_address: Option<String>,
    /// Query round-trip time in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Error, if the query failed.
    pub error: Option<String>,
}

/// Behavioral NAT mapping classification based on multiple STUN observers.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingBehavior {
    /// No STUN data was collected.
    #[default]
    Unknown,
    /// STUN was configured but no server replied.
    UdpBlocked,
    /// Mapped address matches the local socket address.
    OpenInternet,
    /// Multiple observers saw the same public address and port.
    EndpointIndependent,
    /// Observers returned different public addresses or ports.
    AddressOrPortDependent,
}

/// Best-effort NAT filtering classification.
///
/// `NAT-01b-a` intentionally exposes this as a diagnostic foundation before
/// adding active RFC 5780 / multi-socket filtering probes. Values are therefore
/// conservative unless a future active probe can prove them directly.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilteringBehavior {
    /// No filtering behavior could be inferred.
    #[default]
    Unknown,
    /// CHANGE-REQUEST proved endpoint-independent filtering.
    EndpointIndependent,
    /// Mapping observations suggest endpoint-independent behavior.
    LikelyEndpointIndependent,
    /// CHANGE-REQUEST proved address-dependent filtering.
    AddressDependent,
    /// Mapping observations suggest address or port dependent behavior.
    AddressOrPortDependent,
    /// STUN was configured but no server replied.
    UdpBlocked,
}

/// Local NAT hairpin behavior.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HairpinBehavior {
    /// Hairpin behavior has not been probed yet.
    #[default]
    Unknown,
    /// A self-addressed UDP probe returned through the mapped endpoint.
    Supported,
    /// A self-addressed UDP probe did not return within the bounded probe budget.
    Unsupported,
    /// Hairpin does not matter for a public/open endpoint.
    NotApplicable,
}

/// Observed NAT mapping lifetime.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingLifetime {
    /// Lifetime has not been measured yet.
    #[default]
    Unknown,
    /// The mapped endpoint stayed stable for at least this many milliseconds.
    LowerBoundMs(u64),
}

/// Local NAT profile inferred from candidate gathering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatProfile {
    /// Local UDP socket address used for STUN and direct traffic.
    pub local_addr: String,
    /// STUN observations used to infer this profile.
    pub observations: Vec<StunObservation>,
    /// True when STUN was configured but every request failed.
    pub udp_blocked: bool,
    /// Best public endpoint discovered from STUN, if any.
    pub public_endpoint: Option<String>,
    /// Whether all successful observations shared the same public IP.
    pub public_ip_stable: Option<bool>,
    /// Whether all successful observations shared the same public port.
    pub public_port_stable: Option<bool>,
    /// Whether the NAT preserved the local UDP port in the first observation.
    pub port_preserved: Option<bool>,
    /// Stable consecutive port delta, when observable.
    pub port_delta: Option<i32>,
    /// Conservative symmetric/address-dependent indicator.
    pub likely_symmetric: Option<bool>,
    /// Behavioral mapping summary.
    pub mapping_behavior: MappingBehavior,
    /// Best-effort filtering behavior summary.
    #[serde(default)]
    pub filtering_behavior: FilteringBehavior,
    /// Hairpin behavior summary.
    #[serde(default)]
    pub hairpin_behavior: HairpinBehavior,
    /// NAT mapping lifetime summary.
    #[serde(default)]
    pub mapping_lifetime: MappingLifetime,
    /// Whether this profile is a good candidate for bounded port prediction.
    #[serde(default)]
    pub prediction_candidate: bool,
    /// Whether this profile is a good candidate for bounded birthday probing.
    #[serde(default)]
    pub birthday_candidate: bool,
    /// Confidence score from 0-100.
    pub confidence: u8,
}

impl NatProfile {
    fn unknown(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: local_addr.to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: None,
            public_ip_stable: None,
            public_port_stable: None,
            port_preserved: None,
            port_delta: None,
            likely_symmetric: None,
            mapping_behavior: MappingBehavior::Unknown,
            filtering_behavior: FilteringBehavior::Unknown,
            hairpin_behavior: HairpinBehavior::Unknown,
            mapping_lifetime: MappingLifetime::Unknown,
            prediction_candidate: false,
            birthday_candidate: false,
            confidence: 0,
        }
    }
}

/// Candidate gathering output with STUN observations and inferred NAT behavior.
#[derive(Debug, Clone)]
pub struct CandidateGatherReport {
    /// Gathered ICE candidates.
    pub candidates: Vec<IceCandidate>,
    /// Inferred NAT profile.
    pub nat_profile: NatProfile,
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
    Ok(gather_candidate_report(socket, config).await?.candidates)
}

/// Gather ICE candidates and a behavioral NAT profile for the given socket.
pub async fn gather_candidate_report(
    socket: &UdpSocket,
    config: &IceConfig,
) -> Result<CandidateGatherReport> {
    let local_addr = socket.local_addr()?;
    let mut candidates = Vec::new();
    let mut observations = Vec::new();

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
            let started = Instant::now();
            match stun_client.binding_request(socket, server).await {
                Ok(response) => {
                    let rtt_ms = duration_millis(started.elapsed());
                    let reflexive = response.reflexive_address;
                    observations.push(StunObservation {
                        server: server.to_string(),
                        mapped_address: reflexive.map(|addr| addr.to_string()),
                        rtt_ms: Some(rtt_ms),
                        error: None,
                    });

                    if let Some(reflexive) = reflexive {
                        let candidate = IceCandidate {
                            candidate_type: CandidateType::ServerReflexive,
                            endpoint: crate::Endpoint::new(
                                &reflexive.ip().to_string(),
                                reflexive.port(),
                            ),
                            priority: compute_priority(CandidateType::ServerReflexive),
                        };
                        debug!(
                            "Server-reflexive candidate: {} (via {}, rtt={}ms)",
                            candidate.endpoint.to_string(),
                            server,
                            rtt_ms
                        );
                        candidates.push(candidate);
                    } else {
                        debug!("STUN query to {} returned no reflexive address", server);
                    }
                }
                Err(e) => {
                    observations.push(StunObservation {
                        server: server.to_string(),
                        mapped_address: None,
                        rtt_ms: None,
                        error: Some(e.to_string()),
                    });
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

    let mut nat_profile = build_nat_profile(local_addr, observations);
    apply_active_behavior_probes(socket, config, &mut nat_profile).await;
    info!(
        "Gathered {} ICE candidates (STUN success {}/{}, mapping={:?}, filtering={:?}, hairpin={:?}, lifetime={:?})",
        candidates.len(),
        nat_profile
            .observations
            .iter()
            .filter(|observation| observation.mapped_address.is_some())
            .count(),
        nat_profile.observations.len(),
        nat_profile.mapping_behavior,
        nat_profile.filtering_behavior,
        nat_profile.hairpin_behavior,
        nat_profile.mapping_lifetime
    );
    Ok(CandidateGatherReport {
        candidates,
        nat_profile,
    })
}

fn build_nat_profile(local_addr: SocketAddr, observations: Vec<StunObservation>) -> NatProfile {
    if observations.is_empty() {
        return NatProfile::unknown(local_addr);
    }

    let mapped = observations
        .iter()
        .filter_map(|observation| {
            observation
                .mapped_address
                .as_deref()
                .and_then(|addr| addr.parse::<SocketAddr>().ok())
        })
        .collect::<Vec<_>>();

    if mapped.is_empty() {
        let udp_blocked = observations
            .iter()
            .all(|observation| observation.error.is_some());
        return NatProfile {
            local_addr: local_addr.to_string(),
            observations,
            udp_blocked,
            public_endpoint: None,
            public_ip_stable: None,
            public_port_stable: None,
            port_preserved: None,
            port_delta: None,
            likely_symmetric: None,
            mapping_behavior: if udp_blocked {
                MappingBehavior::UdpBlocked
            } else {
                MappingBehavior::Unknown
            },
            filtering_behavior: if udp_blocked {
                FilteringBehavior::UdpBlocked
            } else {
                FilteringBehavior::Unknown
            },
            hairpin_behavior: HairpinBehavior::Unknown,
            mapping_lifetime: MappingLifetime::Unknown,
            prediction_candidate: false,
            birthday_candidate: false,
            confidence: if udp_blocked { 60 } else { 20 },
        };
    }

    let first = mapped[0];
    let public_ip_stable =
        (mapped.len() >= 2).then(|| mapped.iter().all(|addr| addr.ip() == first.ip()));
    let public_port_stable =
        (mapped.len() >= 2).then(|| mapped.iter().all(|addr| addr.port() == first.port()));
    let likely_symmetric = match (public_ip_stable, public_port_stable) {
        (Some(ip_stable), Some(port_stable)) => Some(!ip_stable || !port_stable),
        _ => None,
    };

    let mapping_behavior = if first.ip() == local_addr.ip() && first.port() == local_addr.port() {
        MappingBehavior::OpenInternet
    } else if public_ip_stable == Some(true) && public_port_stable == Some(true) {
        MappingBehavior::EndpointIndependent
    } else if mapped.len() >= 2 {
        MappingBehavior::AddressOrPortDependent
    } else {
        MappingBehavior::Unknown
    };

    let confidence = match mapped.len() {
        0 => 0,
        1 => 40,
        2 => 70,
        _ => 90,
    };
    let filtering_behavior = infer_filtering_behavior(false, mapping_behavior);
    let hairpin_behavior = infer_hairpin_behavior(mapping_behavior);
    let port_delta = stable_port_delta(&mapped);
    let prediction_candidate = is_prediction_candidate(
        false,
        public_ip_stable,
        public_port_stable,
        mapping_behavior,
        port_delta,
    );
    let birthday_candidate = is_birthday_candidate(
        false,
        mapping_behavior,
        likely_symmetric,
        prediction_candidate,
    );

    NatProfile {
        local_addr: local_addr.to_string(),
        observations,
        udp_blocked: false,
        public_endpoint: Some(first.to_string()),
        public_ip_stable,
        public_port_stable,
        port_preserved: Some(first.port() == local_addr.port()),
        port_delta,
        likely_symmetric,
        mapping_behavior,
        filtering_behavior,
        hairpin_behavior,
        mapping_lifetime: MappingLifetime::Unknown,
        prediction_candidate,
        birthday_candidate,
        confidence,
    }
}

async fn apply_active_behavior_probes(
    socket: &UdpSocket,
    config: &IceConfig,
    profile: &mut NatProfile,
) {
    if !config.gather_srflx || profile.udp_blocked || profile.public_endpoint.is_none() {
        return;
    }

    let Some((server, public_endpoint)) = first_successful_stun_mapping(config, profile) else {
        return;
    };
    let probe_timeout = active_probe_timeout(config.stun_timeout);

    if let Some(filtering_behavior) = probe_filtering_behavior(socket, server, probe_timeout).await
    {
        profile.filtering_behavior = filtering_behavior;
    }

    if let Some(lifetime) =
        probe_mapping_lifetime(socket, server, public_endpoint, probe_timeout).await
    {
        profile.mapping_lifetime = lifetime;
    }

    if profile.mapping_behavior == MappingBehavior::OpenInternet {
        profile.hairpin_behavior = HairpinBehavior::NotApplicable;
    } else if let Some(hairpin_behavior) =
        probe_hairpin_behavior(socket, public_endpoint, probe_timeout).await
    {
        profile.hairpin_behavior = hairpin_behavior;
    }
}

fn first_successful_stun_mapping(
    config: &IceConfig,
    profile: &NatProfile,
) -> Option<(SocketAddr, SocketAddr)> {
    profile.observations.iter().find_map(|observation| {
        let server = observation.server.parse::<SocketAddr>().ok()?;
        if !config.stun_servers.contains(&server) {
            return None;
        }
        let mapped = observation
            .mapped_address
            .as_deref()?
            .parse::<SocketAddr>()
            .ok()?;
        Some((server, mapped))
    })
}

fn active_probe_timeout(stun_timeout: Duration) -> Duration {
    stun_timeout
        .min(ACTIVE_BEHAVIOR_PROBE_TIMEOUT)
        .max(Duration::from_millis(50))
}

async fn probe_filtering_behavior(
    socket: &UdpSocket,
    server: SocketAddr,
    probe_timeout: Duration,
) -> Option<FilteringBehavior> {
    let stun_client = StunClient::with_timeout(probe_timeout);

    match stun_client
        .binding_request_with_change(socket, server, true, true)
        .await
    {
        Ok(response) => {
            if let Some(behavior) = classify_changed_ip_port_response(server, response.from_addr) {
                debug!(
                    "Active NAT filtering probe: {:?} response from {} via {}",
                    behavior, response.from_addr, server
                );
                return Some(behavior);
            }
            debug!(
                "Active NAT filtering probe: server {} ignored change-ip+port (response from {})",
                server, response.from_addr
            );
        }
        Err(error) => {
            debug!(
                "Active NAT filtering probe change-ip+port via {} failed: {}",
                server, error
            );
        }
    }

    match stun_client
        .binding_request_with_change(socket, server, false, true)
        .await
    {
        Ok(response) if response.from_addr.ip() == server.ip() && response.from_addr != server => {
            debug!(
                "Active NAT filtering probe: address-dependent response from {} via {}",
                response.from_addr, server
            );
            Some(FilteringBehavior::AddressDependent)
        }
        Ok(response) => {
            debug!(
                "Active NAT filtering probe: server {} ignored change-port (response from {})",
                server, response.from_addr
            );
            None
        }
        Err(error) => {
            debug!(
                "Active NAT filtering probe change-port via {} failed: {}",
                server, error
            );
            None
        }
    }
}

fn classify_changed_ip_port_response(
    server: SocketAddr,
    from_addr: SocketAddr,
) -> Option<FilteringBehavior> {
    if from_addr.ip() != server.ip() {
        Some(FilteringBehavior::EndpointIndependent)
    } else if from_addr != server {
        Some(FilteringBehavior::AddressDependent)
    } else {
        None
    }
}

async fn probe_mapping_lifetime(
    socket: &UdpSocket,
    server: SocketAddr,
    expected_endpoint: SocketAddr,
    probe_timeout: Duration,
) -> Option<MappingLifetime> {
    sleep(MAPPING_LIFETIME_PROBE_DELAY).await;

    let stun_client = StunClient::with_timeout(probe_timeout);
    match stun_client.binding_request(socket, server).await {
        Ok(response) if response.reflexive_address == Some(expected_endpoint) => Some(
            MappingLifetime::LowerBoundMs(duration_millis(MAPPING_LIFETIME_PROBE_DELAY)),
        ),
        Ok(response) => {
            debug!(
                "Active NAT lifetime probe changed mapping via {}: expected {}, got {:?}",
                server, expected_endpoint, response.reflexive_address
            );
            None
        }
        Err(error) => {
            debug!(
                "Active NAT lifetime probe via {} failed after {:?}: {}",
                server, MAPPING_LIFETIME_PROBE_DELAY, error
            );
            None
        }
    }
}

async fn probe_hairpin_behavior(
    socket: &UdpSocket,
    public_endpoint: SocketAddr,
    probe_timeout: Duration,
) -> Option<HairpinBehavior> {
    let payload = build_hairpin_probe_payload(socket.local_addr().ok()?, public_endpoint);
    socket.send_to(&payload, public_endpoint).await.ok()?;

    match timeout(probe_timeout, recv_matching_hairpin_probe(socket, &payload)).await {
        Ok(true) => Some(HairpinBehavior::Supported),
        Ok(false) | Err(_) => Some(HairpinBehavior::Unsupported),
    }
}

async fn recv_matching_hairpin_probe(socket: &UdpSocket, expected_payload: &[u8]) -> bool {
    let mut buf = [0u8; 2048];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _from)) if &buf[..len] == expected_payload => return true,
            Ok((_len, from)) => {
                debug!(
                    "Ignoring non-hairpin UDP packet from {} during hairpin probe",
                    from
                );
            }
            Err(error) => {
                debug!("Hairpin probe recv failed: {}", error);
                return false;
            }
        }
    }
}

fn build_hairpin_probe_payload(local_addr: SocketAddr, public_endpoint: SocketAddr) -> Vec<u8> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!(
        "{}/{}/{}/{}",
        String::from_utf8_lossy(HAIRPIN_PROBE_PREFIX),
        local_addr,
        public_endpoint,
        nonce
    )
    .into_bytes()
}

fn infer_filtering_behavior(
    udp_blocked: bool,
    mapping_behavior: MappingBehavior,
) -> FilteringBehavior {
    if udp_blocked {
        return FilteringBehavior::UdpBlocked;
    }
    match mapping_behavior {
        MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent => {
            FilteringBehavior::LikelyEndpointIndependent
        }
        MappingBehavior::AddressOrPortDependent => FilteringBehavior::AddressOrPortDependent,
        MappingBehavior::Unknown | MappingBehavior::UdpBlocked => FilteringBehavior::Unknown,
    }
}

fn infer_hairpin_behavior(mapping_behavior: MappingBehavior) -> HairpinBehavior {
    match mapping_behavior {
        MappingBehavior::OpenInternet => HairpinBehavior::NotApplicable,
        MappingBehavior::Unknown
        | MappingBehavior::UdpBlocked
        | MappingBehavior::EndpointIndependent
        | MappingBehavior::AddressOrPortDependent => HairpinBehavior::Unknown,
    }
}

fn is_prediction_candidate(
    udp_blocked: bool,
    public_ip_stable: Option<bool>,
    public_port_stable: Option<bool>,
    mapping_behavior: MappingBehavior,
    port_delta: Option<i32>,
) -> bool {
    !udp_blocked
        && public_ip_stable == Some(true)
        && public_port_stable == Some(false)
        && mapping_behavior == MappingBehavior::AddressOrPortDependent
        && port_delta.is_some_and(|delta| (-8..=8).contains(&delta))
}

fn is_birthday_candidate(
    udp_blocked: bool,
    mapping_behavior: MappingBehavior,
    likely_symmetric: Option<bool>,
    prediction_candidate: bool,
) -> bool {
    !udp_blocked
        && (prediction_candidate
            || likely_symmetric == Some(true)
            || mapping_behavior == MappingBehavior::AddressOrPortDependent)
}

fn stable_port_delta(mapped: &[SocketAddr]) -> Option<i32> {
    if mapped.len() < 2 {
        return None;
    }
    let deltas = mapped
        .windows(2)
        .map(|pair| pair[1].port() as i32 - pair[0].port() as i32)
        .collect::<Vec<_>>();
    let first = deltas[0];
    deltas.iter().all(|delta| *delta == first).then_some(first)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
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
    use crate::stun::{StunAttribute, StunMessage, BINDING_REQUEST, BINDING_RESPONSE};

    #[derive(Debug, Clone, Copy)]
    enum ChangeResponseMode {
        ChangedPortForIpPort,
        ChangedPortForPortOnly,
    }

    async fn spawn_change_request_stun_server(
        mode: ChangeResponseMode,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let alternate = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = primary.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, client_addr)) = primary.recv_from(&mut buf).await {
                let Ok(req) = StunMessage::decode(&buf[..len]) else {
                    continue;
                };
                if req.msg_type != BINDING_REQUEST {
                    continue;
                }

                let (change_ip, change_port) = change_request_flags(&req);
                let should_drop = matches!(
                    (mode, change_ip, change_port),
                    (ChangeResponseMode::ChangedPortForPortOnly, true, true)
                );
                if should_drop {
                    continue;
                }

                let from_alternate = matches!(
                    (mode, change_ip, change_port),
                    (ChangeResponseMode::ChangedPortForIpPort, true, true)
                        | (ChangeResponseMode::ChangedPortForPortOnly, false, true)
                );
                let mut resp =
                    StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
                resp.add_attribute(StunAttribute::XorMappedAddress(client_addr));
                let encoded = resp.encode();
                if from_alternate {
                    let _ = alternate.send_to(&encoded, client_addr).await;
                } else {
                    let _ = primary.send_to(&encoded, client_addr).await;
                }
            }
        });

        (addr, handle)
    }

    fn change_request_flags(message: &StunMessage) -> (bool, bool) {
        message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                StunAttribute::ChangeRequest {
                    change_ip,
                    change_port,
                } => Some((*change_ip, *change_port)),
                _ => None,
            })
            .unwrap_or((false, false))
    }

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

    #[test]
    fn test_build_nat_profile_unknown_without_observations() {
        let profile = build_nat_profile("192.168.1.2:5000".parse().unwrap(), Vec::new());
        assert_eq!(profile.mapping_behavior, MappingBehavior::Unknown);
        assert!(!profile.udp_blocked);
        assert_eq!(profile.public_endpoint, None);
        assert_eq!(profile.filtering_behavior, FilteringBehavior::Unknown);
        assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
        assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
        assert!(!profile.prediction_candidate);
        assert!(!profile.birthday_candidate);
        assert_eq!(profile.confidence, 0);
    }

    #[test]
    fn test_build_nat_profile_udp_blocked_when_all_stun_failed() {
        let profile = build_nat_profile(
            "192.168.1.2:5000".parse().unwrap(),
            vec![StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: None,
                rtt_ms: None,
                error: Some("timeout".to_string()),
            }],
        );
        assert_eq!(profile.mapping_behavior, MappingBehavior::UdpBlocked);
        assert!(profile.udp_blocked);
        assert_eq!(profile.likely_symmetric, None);
        assert_eq!(profile.filtering_behavior, FilteringBehavior::UdpBlocked);
        assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
        assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
        assert!(!profile.prediction_candidate);
        assert!(!profile.birthday_candidate);
        assert_eq!(profile.confidence, 60);
    }

    #[test]
    fn test_build_nat_profile_unknown_when_stun_replies_without_mapping() {
        let profile = build_nat_profile(
            "192.168.1.2:5000".parse().unwrap(),
            vec![StunObservation {
                server: "stun-a.example:3478".to_string(),
                mapped_address: None,
                rtt_ms: Some(10),
                error: None,
            }],
        );
        assert_eq!(profile.mapping_behavior, MappingBehavior::Unknown);
        assert!(!profile.udp_blocked);
        assert_eq!(profile.filtering_behavior, FilteringBehavior::Unknown);
        assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
        assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
        assert!(!profile.prediction_candidate);
        assert!(!profile.birthday_candidate);
        assert_eq!(profile.confidence, 20);
    }

    #[test]
    fn test_build_nat_profile_endpoint_independent_mapping() {
        let profile = build_nat_profile(
            "192.168.1.2:5000".parse().unwrap(),
            vec![
                StunObservation {
                    server: "stun-a.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:62000".to_string()),
                    rtt_ms: Some(10),
                    error: None,
                },
                StunObservation {
                    server: "stun-b.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:62000".to_string()),
                    rtt_ms: Some(12),
                    error: None,
                },
            ],
        );
        assert_eq!(
            profile.mapping_behavior,
            MappingBehavior::EndpointIndependent
        );
        assert_eq!(
            profile.public_endpoint.as_deref(),
            Some("203.0.113.10:62000")
        );
        assert_eq!(profile.public_ip_stable, Some(true));
        assert_eq!(profile.public_port_stable, Some(true));
        assert_eq!(profile.port_preserved, Some(false));
        assert_eq!(profile.likely_symmetric, Some(false));
        assert_eq!(profile.port_delta, Some(0));
        assert_eq!(
            profile.filtering_behavior,
            FilteringBehavior::LikelyEndpointIndependent
        );
        assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
        assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
        assert!(!profile.prediction_candidate);
        assert!(!profile.birthday_candidate);
        assert_eq!(profile.confidence, 70);
    }

    #[test]
    fn test_build_nat_profile_detects_port_dependent_mapping() {
        let profile = build_nat_profile(
            "192.168.1.2:5000".parse().unwrap(),
            vec![
                StunObservation {
                    server: "stun-a.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40001".to_string()),
                    rtt_ms: Some(10),
                    error: None,
                },
                StunObservation {
                    server: "stun-b.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40003".to_string()),
                    rtt_ms: Some(11),
                    error: None,
                },
                StunObservation {
                    server: "stun-c.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40005".to_string()),
                    rtt_ms: Some(12),
                    error: None,
                },
            ],
        );
        assert_eq!(
            profile.mapping_behavior,
            MappingBehavior::AddressOrPortDependent
        );
        assert_eq!(profile.public_ip_stable, Some(true));
        assert_eq!(profile.public_port_stable, Some(false));
        assert_eq!(profile.likely_symmetric, Some(true));
        assert_eq!(profile.port_delta, Some(2));
        assert_eq!(
            profile.filtering_behavior,
            FilteringBehavior::AddressOrPortDependent
        );
        assert_eq!(profile.hairpin_behavior, HairpinBehavior::Unknown);
        assert_eq!(profile.mapping_lifetime, MappingLifetime::Unknown);
        assert!(profile.prediction_candidate);
        assert!(profile.birthday_candidate);
        assert_eq!(profile.confidence, 90);
    }

    #[test]
    fn test_build_nat_profile_rejects_wide_delta_for_prediction() {
        let profile = build_nat_profile(
            "192.168.1.2:5000".parse().unwrap(),
            vec![
                StunObservation {
                    server: "stun-a.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40001".to_string()),
                    rtt_ms: Some(10),
                    error: None,
                },
                StunObservation {
                    server: "stun-b.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40033".to_string()),
                    rtt_ms: Some(11),
                    error: None,
                },
                StunObservation {
                    server: "stun-c.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40065".to_string()),
                    rtt_ms: Some(12),
                    error: None,
                },
            ],
        );
        assert_eq!(
            profile.mapping_behavior,
            MappingBehavior::AddressOrPortDependent
        );
        assert_eq!(profile.port_delta, Some(32));
        assert!(!profile.prediction_candidate);
        assert!(profile.birthday_candidate);
    }

    #[tokio::test]
    async fn test_probe_filtering_behavior_treats_changed_port_as_address_dependent() {
        let (server, _handle) =
            spawn_change_request_stun_server(ChangeResponseMode::ChangedPortForIpPort).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let filtering = probe_filtering_behavior(&socket, server, Duration::from_secs(1)).await;

        assert_eq!(filtering, Some(FilteringBehavior::AddressDependent));
    }

    #[tokio::test]
    async fn test_probe_filtering_behavior_detects_address_dependent() {
        let (server, _handle) =
            spawn_change_request_stun_server(ChangeResponseMode::ChangedPortForPortOnly).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let filtering = probe_filtering_behavior(&socket, server, Duration::from_millis(100)).await;

        assert_eq!(filtering, Some(FilteringBehavior::AddressDependent));
    }

    #[test]
    fn test_changed_ip_port_classifier_requires_ip_change_for_endpoint_independent() {
        let server = "192.0.2.10:3478".parse().unwrap();
        let changed_ip = "198.51.100.10:3479".parse().unwrap();
        let changed_port = "192.0.2.10:3479".parse().unwrap();
        let unchanged = server;

        assert_eq!(
            classify_changed_ip_port_response(server, changed_ip),
            Some(FilteringBehavior::EndpointIndependent)
        );
        assert_eq!(
            classify_changed_ip_port_response(server, changed_port),
            Some(FilteringBehavior::AddressDependent)
        );
        assert_eq!(classify_changed_ip_port_response(server, unchanged), None);
    }

    #[tokio::test]
    async fn test_probe_mapping_lifetime_records_lower_bound() {
        let (server, _handle) = crate::client::test_helpers::spawn_mock_stun_server().await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected_endpoint = socket.local_addr().unwrap();

        let lifetime =
            probe_mapping_lifetime(&socket, server, expected_endpoint, Duration::from_secs(1))
                .await;

        assert_eq!(
            lifetime,
            Some(MappingLifetime::LowerBoundMs(duration_millis(
                MAPPING_LIFETIME_PROBE_DELAY
            )))
        );
    }

    #[tokio::test]
    async fn test_probe_hairpin_behavior_detects_self_hairpin() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let public_endpoint = socket.local_addr().unwrap();

        let hairpin =
            probe_hairpin_behavior(&socket, public_endpoint, Duration::from_secs(1)).await;

        assert_eq!(hairpin, Some(HairpinBehavior::Supported));
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

        let report = gather_candidate_report(&socket, &config).await.unwrap();
        let candidates = report.candidates;
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

        let report = gather_candidate_report(&socket, &config).await.unwrap();
        let candidates = report.candidates;

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
        assert_eq!(report.nat_profile.observations.len(), 1);
        assert_eq!(
            report.nat_profile.mapping_behavior,
            MappingBehavior::OpenInternet
        );
        let local_text = local.to_string();
        assert_eq!(
            report.nat_profile.public_endpoint.as_deref(),
            Some(local_text.as_str())
        );
        assert_eq!(
            report.nat_profile.filtering_behavior,
            FilteringBehavior::LikelyEndpointIndependent
        );
        assert_eq!(
            report.nat_profile.hairpin_behavior,
            HairpinBehavior::NotApplicable
        );
        assert_eq!(
            report.nat_profile.mapping_lifetime,
            MappingLifetime::LowerBoundMs(duration_millis(MAPPING_LIFETIME_PROBE_DELAY))
        );
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
