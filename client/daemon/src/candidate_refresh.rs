use super::*;

pub(super) fn advertised_udp_endpoint(
    local_addr: SocketAddr,
    configured: Option<&str>,
    candidates: &[String],
) -> Option<String> {
    if let Some(endpoint) = configured
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
    {
        return Some(endpoint.to_string());
    }

    if !local_addr.ip().is_unspecified() {
        return Some(local_addr.to_string());
    }

    candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .find(|candidate| is_public_udp_candidate(*candidate))
        .or_else(|| {
            candidates
                .iter()
                .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
                .find(|candidate| !candidate.ip().is_unspecified() && !candidate.ip().is_loopback())
        })
        .map(|candidate| candidate.to_string())
}

pub(super) fn control_udp_endpoint_from_candidates(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> Option<String> {
    candidates
        .iter()
        .enumerate()
        .min_by_key(|(index, endpoint)| {
            let endpoint = endpoint.as_str();
            (
                control_udp_endpoint_rank(
                    endpoint,
                    candidate_sources.get(endpoint).map(String::as_str),
                ),
                *index,
            )
        })
        .and_then(|(_, endpoint)| {
            let endpoint = endpoint.as_str();
            (control_udp_endpoint_rank(
                endpoint,
                candidate_sources.get(endpoint).map(String::as_str),
            ) < u8::MAX)
                .then(|| endpoint.to_string())
        })
}

fn control_udp_endpoint_rank(endpoint: &str, source: Option<&str>) -> u8 {
    match source {
        Some("manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping") => 0,
        Some("stun_observed")
            if endpoint
                .parse::<SocketAddr>()
                .is_ok_and(is_public_udp_candidate) =>
        {
            1
        }
        Some("host")
            if endpoint
                .parse::<SocketAddr>()
                .is_ok_and(is_public_udp_candidate) =>
        {
            2
        }
        Some("peer_reflexive" | "learned" | "predicted" | "birthday") => u8::MAX,
        Some("relay") => u8::MAX,
        Some(_) | None => {
            if endpoint.parse::<SocketAddr>().is_ok_and(|candidate| {
                !candidate.ip().is_unspecified() && !candidate.ip().is_loopback()
            }) {
                3
            } else {
                u8::MAX
            }
        }
    }
}

pub(super) fn should_update_stable_control_endpoint(
    published_endpoint: Option<&str>,
    next_endpoint: &str,
) -> bool {
    let next_endpoint = next_endpoint.trim();
    if next_endpoint.is_empty() {
        return false;
    }
    let Some(published_endpoint) = published_endpoint
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
    else {
        return true;
    };
    if published_endpoint == next_endpoint {
        return false;
    }

    let published_addr = published_endpoint.parse::<SocketAddr>().ok();
    let next_addr = next_endpoint.parse::<SocketAddr>().ok();
    match (published_addr, next_addr) {
        (Some(published_addr), Some(next_addr)) if is_public_udp_candidate(next_addr) => {
            !is_public_udp_candidate(published_addr) || published_addr.ip() != next_addr.ip()
        }
        (Some(published_addr), Some(next_addr)) => {
            !is_public_udp_candidate(published_addr) && published_addr != next_addr
        }
        _ => true,
    }
}

pub(super) fn candidate_endpoints_from_report(
    report: &CandidateGatherReport,
) -> (Vec<String>, HashMap<String, String>) {
    let mut endpoints = Vec::new();
    let mut sources = HashMap::new();
    for candidate in &report.candidates {
        let endpoint = candidate.endpoint.to_string();
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint.clone());
        }
        sources.insert(
            endpoint,
            candidate_source_label(candidate.source).to_string(),
        );
    }
    compact_volatile_public_signal_candidates(&mut endpoints, &mut sources);
    truncate_signal_candidates(&mut endpoints, &mut sources);
    (endpoints, sources)
}

pub(super) fn compact_volatile_public_signal_candidates(
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    let mut volatile_public_by_ip: HashMap<IpAddr, usize> = HashMap::new();
    candidates.retain(|endpoint| {
        let Some(source) = candidate_sources.get(endpoint).map(String::as_str) else {
            return true;
        };
        if !is_volatile_public_signal_source(source) {
            return true;
        }
        let Ok(addr) = endpoint.parse::<SocketAddr>() else {
            return true;
        };
        if !is_public_udp_candidate(addr) {
            return true;
        }
        let count = volatile_public_by_ip.entry(addr.ip()).or_default();
        *count += 1;
        *count <= MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP
    });
    let retained = candidates.iter().cloned().collect::<HashSet<_>>();
    candidate_sources.retain(|endpoint, _| retained.contains(endpoint));
}

fn is_volatile_public_signal_source(source: &str) -> bool {
    matches!(
        source,
        "stun_observed" | "peer_reflexive" | "learned" | "predicted"
    )
}

pub(super) fn truncate_signal_candidates(
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    if candidates.len() > MAX_SIGNAL_CANDIDATES {
        let original_order = candidates
            .iter()
            .enumerate()
            .map(|(index, endpoint)| (endpoint.clone(), index))
            .collect::<HashMap<_, _>>();
        candidates.sort_by(|left, right| {
            signal_candidate_rank(left, candidate_sources.get(left).map(String::as_str))
                .cmp(&signal_candidate_rank(
                    right,
                    candidate_sources.get(right).map(String::as_str),
                ))
                .then_with(|| {
                    original_order
                        .get(left)
                        .unwrap_or(&usize::MAX)
                        .cmp(original_order.get(right).unwrap_or(&usize::MAX))
                })
        });
        warn!(
            "Truncating {} gathered UDP candidates to the signaling limit of {}",
            candidates.len(),
            MAX_SIGNAL_CANDIDATES
        );
        candidates.truncate(MAX_SIGNAL_CANDIDATES);
    }
    let retained = candidates.iter().cloned().collect::<HashSet<_>>();
    candidate_sources.retain(|endpoint, _| retained.contains(endpoint));
}

fn signal_candidate_rank(endpoint: &str, source: Option<&str>) -> u8 {
    match source {
        Some("peer_reflexive" | "learned") => 0,
        Some("upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping") => 1,
        Some("manual") => 2,
        Some("stun_observed") => 3,
        Some("predicted") => 4,
        Some("host") => match endpoint.parse::<SocketAddr>() {
            Ok(endpoint) if is_public_udp_candidate(endpoint) => 5,
            _ => 8,
        },
        Some("relay") => 9,
        Some(_) | None => {
            if endpoint
                .parse::<SocketAddr>()
                .is_ok_and(is_public_udp_candidate)
            {
                6
            } else {
                8
            }
        }
    }
}

fn candidate_source_label(source: CandidateSource) -> &'static str {
    match source {
        CandidateSource::Host => "host",
        CandidateSource::StunObserved => "stun_observed",
        CandidateSource::Predicted => "predicted",
        CandidateSource::PeerReflexive => "peer_reflexive",
        CandidateSource::Manual => "manual",
        CandidateSource::Relay => "relay",
    }
}

pub(super) fn preserve_peer_reflexive_candidates(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    let current_candidate_ips = candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .map(|candidate| candidate.ip())
        .collect::<Vec<_>>();
    for endpoint in previous_candidates.iter().rev() {
        if previous_candidate_sources.get(endpoint).map(String::as_str) != Some("peer_reflexive") {
            continue;
        }
        let Ok(addr) = endpoint.parse::<SocketAddr>() else {
            continue;
        };
        if !is_public_udp_candidate(addr)
            || !current_candidate_ips.contains(&addr.ip())
            || candidates.contains(endpoint)
        {
            continue;
        }
        candidates.insert(0, endpoint.clone());
        candidate_sources.insert(endpoint.clone(), "peer_reflexive".to_string());
    }
}

pub(super) fn add_peer_reflexive_candidate_to_set(
    observed_endpoint: &str,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) -> std::result::Result<bool, std::net::AddrParseError> {
    let endpoint = observed_endpoint.parse::<SocketAddr>()?.to_string();
    let already_present = candidates.contains(&endpoint);
    let source_changed =
        candidate_sources.get(&endpoint).map(String::as_str) != Some("peer_reflexive");

    if !already_present {
        candidates.insert(0, endpoint.clone());
    }
    candidate_sources.insert(endpoint, "peer_reflexive".to_string());
    compact_volatile_public_signal_candidates(candidates, candidate_sources);
    truncate_signal_candidates(candidates, candidate_sources);

    Ok(!already_present || source_changed)
}

pub(super) fn candidate_refresh_requires_network_generation_advance(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    stable_network_candidate_signature(previous_candidates, previous_candidate_sources)
        != stable_network_candidate_signature(candidates, candidate_sources)
}

fn stable_network_candidate_signature(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> Vec<String> {
    let mut signature = Vec::new();
    for endpoint in candidates {
        let source = candidate_sources
            .get(endpoint)
            .map(String::as_str)
            .unwrap_or("signaled");
        match endpoint.parse::<SocketAddr>() {
            Ok(addr) if is_external_overlay_udp_candidate(addr) => {}
            Ok(addr) if is_public_udp_candidate(addr) => match source {
                "stun_observed" | "predicted" | "peer_reflexive" | "learned" => {
                    signature.push(format!("public-ip:{}", addr.ip()));
                }
                "host" | "manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" => {
                    signature.push(format!("{source}:{addr}"));
                }
                _ => {}
            },
            Ok(addr) => match source {
                // A LAN endpoint can be reported as either a gathered host candidate
                // or a peer-reflexive observation from another machine on the same
                // LAN. Treat the endpoint itself as stable so source-label churn
                // does not invalidate healthy direct paths every refresh.
                "host" | "peer_reflexive" | "learned" => {
                    signature.push(format!("private-endpoint:{addr}"));
                }
                "manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" => {
                    signature.push(format!("{source}:{addr}"));
                }
                _ => {}
            },
            Err(_) => match source {
                "host" | "manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" => {
                    signature.push(format!("{source}:{endpoint}"));
                }
                "stun_observed" | "predicted" | "peer_reflexive" | "learned" => {
                    signature.push(format!("{source}:{endpoint}"));
                }
                _ => {}
            },
        }
    }
    signature.sort();
    signature.dedup();
    signature
}

fn is_public_udp_candidate(candidate: SocketAddr) -> bool {
    match candidate.ip() {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !is_shared_ipv4(ip)
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && (ip.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

fn is_external_overlay_udp_candidate(candidate: SocketAddr) -> bool {
    match candidate.ip() {
        IpAddr::V4(ip) => is_shared_ipv4(ip),
        IpAddr::V6(ip) => ip.is_unique_local(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortMappingCandidate {
    endpoint: String,
    source: &'static str,
}

pub(super) async fn maybe_add_port_mapping_udp_candidate(
    udp_local_addr: Option<SocketAddr>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
    runtime: Arc<RwLock<GatewayMappingRuntime>>,
    diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
) {
    let Some(local_addr) = port_mapping_local_addr(udp_local_addr, candidates, candidate_sources)
    else {
        let mut diagnostics = diagnostics.write().await;
        diagnostics.local_endpoint = None;
        diagnostics.upnp.status = "unavailable".to_string();
        diagnostics.upnp.last_error = Some("no LAN IPv4 UDP endpoint available".to_string());
        debug!("Skipping port-mapping UDP candidate because no LAN IPv4 local address was found");
        return;
    };

    let now = Instant::now();
    {
        let runtime = runtime.read().await;
        if runtime.retain_candidate(local_addr, now) {
            if let (Some(endpoint), Some(source)) = (
                runtime.candidate_endpoint.as_ref(),
                runtime.candidate_source,
            ) {
                if !candidates.contains(endpoint) {
                    candidates.insert(0, endpoint.clone());
                    candidate_sources.insert(endpoint.clone(), source.to_string());
                }
                let snapshot = runtime.snapshot(
                    true,
                    PORT_MAPPING_LEASE_SECS,
                    diagnostics.read().await.clone(),
                );
                *diagnostics.write().await = snapshot;
                return;
            }
        }
        if !runtime.needs_discovery(local_addr, now) {
            let snapshot = runtime.snapshot(
                true,
                PORT_MAPPING_LEASE_SECS,
                diagnostics.read().await.clone(),
            );
            *diagnostics.write().await = snapshot;
            return;
        }
    }

    match discover_port_mapping_udp_candidate(local_addr).await {
        GatewayMappingDiscovery {
            candidate: Some(candidate),
            upnp,
            pcp,
            nat_pmp,
        } => {
            let mut diagnostics_guard = diagnostics.write().await;
            record_method_result(&mut diagnostics_guard.upnp, upnp);
            if let Some(result) = pcp {
                record_method_result(&mut diagnostics_guard.pcp, result);
            }
            if let Some(result) = nat_pmp {
                record_method_result(&mut diagnostics_guard.nat_pmp, result);
            }
            if !candidates.contains(&candidate.endpoint) {
                info!(
                    "{} mapped UDP {local_addr} as {}",
                    candidate.source, candidate.endpoint
                );
                // A gateway-created mapping is usually more useful than another
                // host/predicted address and must survive the signaling cap.
                candidates.insert(0, candidate.endpoint.clone());
            }
            candidate_sources.insert(candidate.endpoint.clone(), candidate.source.to_string());
            drop(diagnostics_guard);
            {
                let mut runtime = runtime.write().await;
                runtime.record_success(
                    local_addr,
                    candidate.endpoint.clone(),
                    candidate.source,
                    Duration::from_secs(PORT_MAPPING_LEASE_SECS.into()),
                );
                let snapshot = runtime.snapshot(
                    true,
                    PORT_MAPPING_LEASE_SECS,
                    diagnostics.read().await.clone(),
                );
                *diagnostics.write().await = snapshot;
            }
        }
        GatewayMappingDiscovery {
            candidate: None,
            upnp,
            pcp,
            nat_pmp,
        } => {
            let mut diagnostics_guard = diagnostics.write().await;
            record_method_result(&mut diagnostics_guard.upnp, upnp);
            if let Some(result) = pcp {
                record_method_result(&mut diagnostics_guard.pcp, result);
            }
            if let Some(result) = nat_pmp {
                record_method_result(&mut diagnostics_guard.nat_pmp, result);
            }
            drop(diagnostics_guard);
            let mut runtime = runtime.write().await;
            runtime.record_failure(local_addr, PORT_MAPPING_FAILURE_RETRY);
            let snapshot = runtime.snapshot(
                true,
                PORT_MAPPING_LEASE_SECS,
                diagnostics.read().await.clone(),
            );
            *diagnostics.write().await = snapshot;
            debug!("No UPnP/PCP/NAT-PMP UDP mapping candidate discovered for {local_addr}");
        }
    }
}

struct GatewayMappingDiscovery {
    candidate: Option<PortMappingCandidate>,
    upnp: std::result::Result<(), String>,
    pcp: Option<std::result::Result<(), String>>,
    nat_pmp: Option<std::result::Result<(), String>>,
}

async fn discover_port_mapping_udp_candidate(local_addr: SocketAddr) -> GatewayMappingDiscovery {
    match discover_upnp_udp_candidate(local_addr).await {
        Ok(candidate) => GatewayMappingDiscovery {
            candidate: Some(candidate),
            upnp: Ok(()),
            pcp: None,
            nat_pmp: None,
        },
        Err(upnp) => {
            let (pcp, nat_pmp) = discover_pcp_or_nat_pmp_udp_candidate(local_addr).await;
            let candidate = pcp
                .as_ref()
                .ok()
                .cloned()
                .or_else(|| nat_pmp.as_ref().ok().cloned());
            GatewayMappingDiscovery {
                candidate,
                upnp: Err(upnp),
                pcp: Some(pcp.map(|_| ())),
                nat_pmp: Some(nat_pmp.map(|_| ())),
            }
        }
    }
}

async fn discover_upnp_udp_candidate(
    local_addr: SocketAddr,
) -> std::result::Result<PortMappingCandidate, String> {
    let options = SearchOptions {
        timeout: Some(UPNP_DISCOVERY_TIMEOUT),
        single_search_timeout: Some(UPNP_DISCOVERY_TIMEOUT),
        ..Default::default()
    };
    let gateway = match search_gateway(options).await {
        Ok(gateway) => gateway,
        Err(error) => {
            debug!("UPnP IGD gateway search failed: {error}");
            return Err(format!("gateway discovery failed: {error}"));
        }
    };

    let external_ip = match gateway.get_external_ip().await {
        Ok(ip) if is_public_udp_candidate(SocketAddr::new(ip, 1)) => ip,
        Ok(ip) => {
            debug!("UPnP IGD external IP {ip} is not publicly routable; skipping candidate");
            return Err(format!("gateway reported non-public external IP {ip}"));
        }
        Err(error) => {
            debug!("UPnP IGD external IP lookup failed: {error}");
            return Err(format!("external IP lookup failed: {error}"));
        }
    };

    if gateway
        .add_port(
            PortMappingProtocol::UDP,
            local_addr.port(),
            local_addr,
            PORT_MAPPING_LEASE_SECS,
            "p2wlan direct udp",
        )
        .await
        .is_ok()
    {
        return Ok(PortMappingCandidate {
            endpoint: SocketAddr::new(external_ip, local_addr.port()).to_string(),
            source: "upnp",
        });
    }

    match gateway
        .get_any_address(
            PortMappingProtocol::UDP,
            local_addr,
            PORT_MAPPING_LEASE_SECS,
            "p2wlan direct udp",
        )
        .await
    {
        Ok(endpoint) if is_public_udp_candidate(endpoint) => Ok(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "upnp",
        }),
        Ok(endpoint) => {
            debug!("UPnP IGD mapped to non-public endpoint {endpoint}; skipping candidate");
            Err(format!("gateway assigned non-public endpoint {endpoint}"))
        }
        Err(error) => {
            debug!("UPnP IGD UDP port mapping failed: {error}");
            Err(format!("UDP port mapping failed: {error}"))
        }
    }
}

async fn discover_pcp_or_nat_pmp_udp_candidate(
    local_addr: SocketAddr,
) -> (
    std::result::Result<PortMappingCandidate, String>,
    std::result::Result<PortMappingCandidate, String>,
) {
    let gateway = match default_ipv4_gateway().await {
        Some(gateway) => gateway,
        None => {
            debug!("No default IPv4 gateway found for PCP/NAT-PMP discovery");
            let error = "no default IPv4 gateway found".to_string();
            return (Err(error.clone()), Err(error));
        }
    };
    let Some(local_ip) = local_addr_ipv4(local_addr) else {
        let error = "no usable LAN IPv4 source address".to_string();
        return (Err(error.clone()), Err(error));
    };

    let pcp = discover_pcp_udp_candidate(local_ip, local_addr.port(), gateway);
    let nat_pmp = discover_nat_pmp_udp_candidate(local_ip, local_addr.port(), gateway);
    let (pcp, nat_pmp) = tokio::join!(pcp, nat_pmp);
    (pcp, nat_pmp)
}

async fn discover_nat_pmp_udp_candidate(
    local_ip: Ipv4Addr,
    local_port: u16,
    gateway: Ipv4Addr,
) -> std::result::Result<PortMappingCandidate, String> {
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), NAT_MAPPING_CONTROL_PORT);
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            debug!("NAT-PMP bind failed on {bind_addr}: {error}");
            return Err(format!("bind {bind_addr} failed: {error}"));
        }
    };

    let public_request = [0u8, 0u8];
    if let Err(error) = socket.send_to(&public_request, gateway_addr).await {
        return Err(format!("public address request send failed: {error}"));
    }
    let mut response = [0u8; 64];
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("NAT-PMP public address receive failed: {error}");
            return Err(format!("public address receive failed: {error}"));
        }
        Err(_) => return Err("public address request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!(
            "public address response came from unexpected {from}"
        ));
    }
    let external_ip = parse_nat_pmp_public_address_response(&response[..len])
        .ok_or_else(|| "invalid NAT-PMP public address response".to_string())?;

    let mut map_request = [0u8; 12];
    map_request[1] = 1; // Map UDP.
    map_request[4..6].copy_from_slice(&local_port.to_be_bytes());
    map_request[6..8].copy_from_slice(&local_port.to_be_bytes());
    map_request[8..12].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    if let Err(error) = socket.send_to(&map_request, gateway_addr).await {
        return Err(format!("UDP mapping request send failed: {error}"));
    }
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("NAT-PMP UDP mapping receive failed: {error}");
            return Err(format!("UDP mapping receive failed: {error}"));
        }
        Err(_) => return Err("UDP mapping request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!("UDP mapping response came from unexpected {from}"));
    }
    let external_port = parse_nat_pmp_mapping_response(&response[..len], local_port)
        .ok_or_else(|| "invalid NAT-PMP UDP mapping response".to_string())?;
    let endpoint = SocketAddr::new(IpAddr::V4(external_ip), external_port);
    is_public_udp_candidate(endpoint)
        .then_some(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "nat_pmp",
        })
        .ok_or_else(|| format!("gateway returned non-public endpoint {endpoint}"))
}

async fn discover_pcp_udp_candidate(
    local_ip: Ipv4Addr,
    local_port: u16,
    gateway: Ipv4Addr,
) -> std::result::Result<PortMappingCandidate, String> {
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), NAT_MAPPING_CONTROL_PORT);
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            debug!("PCP bind failed on {bind_addr}: {error}");
            return Err(format!("bind {bind_addr} failed: {error}"));
        }
    };

    let mut request = [0u8; 60];
    request[0] = 2; // PCP version.
    request[1] = 1; // MAP opcode.
    request[4..8].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    request[8..24].copy_from_slice(&ipv4_mapped_octets(local_ip));
    rand::thread_rng().fill_bytes(&mut request[24..36]);
    request[36] = 17; // UDP.
    request[40..42].copy_from_slice(&local_port.to_be_bytes());
    request[42..44].copy_from_slice(&local_port.to_be_bytes());

    if let Err(error) = socket.send_to(&request, gateway_addr).await {
        return Err(format!("MAP request send failed: {error}"));
    }
    let mut response = [0u8; 128];
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("PCP UDP mapping receive failed: {error}");
            return Err(format!("MAP response receive failed: {error}"));
        }
        Err(_) => return Err("MAP request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!("MAP response came from unexpected {from}"));
    }
    let endpoint = parse_pcp_mapping_response(&response[..len], local_port)
        .ok_or_else(|| "invalid PCP MAP response".to_string())?;
    is_public_udp_candidate(endpoint)
        .then_some(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "pcp",
        })
        .ok_or_else(|| format!("gateway returned non-public endpoint {endpoint}"))
}

pub(super) fn parse_nat_pmp_public_address_response(response: &[u8]) -> Option<Ipv4Addr> {
    if response.len() < 12 || response[0] != 0 || response[1] != 128 {
        return None;
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        debug!("NAT-PMP public address request failed with result code {result}");
        return None;
    }
    Some(Ipv4Addr::new(
        response[8],
        response[9],
        response[10],
        response[11],
    ))
}

pub(super) fn parse_nat_pmp_mapping_response(
    response: &[u8],
    expected_internal_port: u16,
) -> Option<u16> {
    if response.len() < 16 || response[0] != 0 || response[1] != 129 {
        return None;
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        debug!("NAT-PMP UDP mapping failed with result code {result}");
        return None;
    }
    let internal_port = u16::from_be_bytes([response[8], response[9]]);
    if internal_port != expected_internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([response[10], response[11]]);
    (external_port > 0).then_some(external_port)
}

pub(super) fn parse_pcp_mapping_response(
    response: &[u8],
    expected_internal_port: u16,
) -> Option<SocketAddr> {
    if response.len() < 60 || response[0] != 2 || response[1] != 0x81 {
        return None;
    }
    let result = response[3];
    if result != 0 {
        debug!("PCP UDP mapping failed with result code {result}");
        return None;
    }
    if response[36] != 17 {
        return None;
    }
    let internal_port = u16::from_be_bytes([response[40], response[41]]);
    if internal_port != expected_internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([response[42], response[43]]);
    if external_port == 0 {
        return None;
    }
    let external_ip = parse_pcp_ip_address(&response[44..60])?;
    Some(SocketAddr::new(external_ip, external_port))
}

fn parse_pcp_ip_address(bytes: &[u8]) -> Option<IpAddr> {
    let bytes: [u8; 16] = bytes.try_into().ok()?;
    if bytes[..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
        return Some(IpAddr::V4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        )));
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

pub(super) fn ipv4_mapped_octets(ip: Ipv4Addr) -> [u8; 16] {
    let mut octets = [0u8; 16];
    octets[10] = 0xff;
    octets[11] = 0xff;
    octets[12..16].copy_from_slice(&ip.octets());
    octets
}

async fn default_ipv4_gateway() -> Option<Ipv4Addr> {
    tokio::task::spawn_blocking(default_ipv4_gateway_blocking)
        .await
        .ok()
        .flatten()
}

fn default_ipv4_gateway_blocking() -> Option<Ipv4Addr> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let output = Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).NextHop",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[allow(unreachable_code)]
    None
}

pub(super) fn parse_first_ipv4(text: &str) -> Option<Ipv4Addr> {
    text.split_whitespace().find_map(parse_ipv4_token)
}

fn parse_ipv4_token(token: &str) -> Option<Ipv4Addr> {
    token
        .trim_matches(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .parse()
        .ok()
}

fn port_mapping_local_addr(
    udp_local_addr: Option<SocketAddr>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> Option<SocketAddr> {
    if udp_local_addr.is_some_and(is_port_mapping_local_addr) {
        return udp_local_addr;
    }

    candidates.iter().find_map(|candidate| {
        if candidate_sources.get(candidate).map(String::as_str) != Some("host") {
            return None;
        }
        let endpoint = candidate.parse::<SocketAddr>().ok()?;
        is_port_mapping_local_addr(endpoint).then_some(endpoint)
    })
}

fn is_port_mapping_local_addr(endpoint: SocketAddr) -> bool {
    endpoint.port() > 0
        && matches!(
            endpoint.ip(),
            IpAddr::V4(ip)
                if !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_link_local()
                    && !ip.is_broadcast()
        )
}

fn local_addr_ipv4(endpoint: SocketAddr) -> Option<Ipv4Addr> {
    match endpoint.ip() {
        IpAddr::V4(ip) if is_port_mapping_local_addr(endpoint) => Some(ip),
        _ => None,
    }
}

fn is_shared_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

pub(super) struct UdpCandidateRefreshContext {
    pub(super) udp: UdpTransport,
    pub(super) stun_servers: Vec<SocketAddr>,
    pub(super) stun_timeout: Duration,
    pub(super) udp_advertise: Option<String>,
    pub(super) upnp_enabled: bool,
    pub(super) published_endpoint: Option<String>,
    pub(super) local_candidates: Arc<RwLock<Vec<String>>>,
    pub(super) local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    pub(super) nat_profile: Arc<RwLock<Option<NatProfile>>>,
    pub(super) gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    pub(super) gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    pub(super) punch_deduplicator: PunchAttemptDeduplicator,
    pub(super) control: ControlClient,
    pub(super) peers: Arc<PeerManager>,
    pub(super) probe_interval: Duration,
    pub(super) punch_attempts: u32,
}

pub(super) async fn run_udp_candidate_refresh(context: UdpCandidateRefreshContext) {
    let UdpCandidateRefreshContext {
        udp,
        stun_servers,
        stun_timeout,
        udp_advertise,
        upnp_enabled,
        mut published_endpoint,
        local_candidates,
        local_candidate_sources,
        nat_profile,
        gateway_mapping_runtime,
        gateway_mapping_diagnostics,
        punch_deduplicator,
        control,
        peers,
        probe_interval,
        punch_attempts,
    } = context;
    let mut ticker = interval(CANDIDATE_REFRESH_INTERVAL);
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let report = match udp
            .gather_candidate_report_live(stun_servers.clone(), stun_timeout)
            .await
        {
            Ok(report) => report,
            Err(err) => {
                warn!("Periodic UDP candidate refresh failed: {err}");
                continue;
            }
        };
        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        peers.update_nat_profile(report.nat_profile.clone()).await;
        let profile_changed = {
            let mut current_profile = nat_profile.write().await;
            if current_profile.as_ref() == Some(&report.nat_profile) {
                false
            } else {
                *current_profile = Some(report.nat_profile.clone());
                true
            }
        };

        let advertised_endpoint = udp.local_addr().ok().and_then(|local_addr| {
            advertised_udp_endpoint(local_addr, udp_advertise.as_deref(), &candidates)
        });
        if let Some(endpoint) = advertised_endpoint.as_ref() {
            if !candidates.contains(endpoint) {
                candidates.insert(0, endpoint.clone());
            }
            candidate_sources
                .entry(endpoint.clone())
                .or_insert_with(|| {
                    if udp_advertise.as_deref().is_some_and(|configured| {
                        !configured.trim().is_empty() && configured.trim() == endpoint
                    }) {
                        "manual".to_string()
                    } else {
                        "host".to_string()
                    }
                });
        }

        if upnp_enabled {
            maybe_add_port_mapping_udp_candidate(
                udp.local_addr().ok(),
                &mut candidates,
                &mut candidate_sources,
                gateway_mapping_runtime.clone(),
                gateway_mapping_diagnostics.clone(),
            )
            .await;
        }
        truncate_signal_candidates(&mut candidates, &mut candidate_sources);

        let previous_candidates = local_candidates.read().await.clone();
        let previous_candidate_sources = local_candidate_sources.read().await.clone();
        preserve_peer_reflexive_candidates(
            &previous_candidates,
            &previous_candidate_sources,
            &mut candidates,
            &mut candidate_sources,
        );
        compact_volatile_public_signal_candidates(&mut candidates, &mut candidate_sources);
        truncate_signal_candidates(&mut candidates, &mut candidate_sources);
        let should_advance_generation = candidate_refresh_requires_network_generation_advance(
            &previous_candidates,
            &previous_candidate_sources,
            &candidates,
            &candidate_sources,
        );

        let changed = {
            let mut current = local_candidates.write().await;
            if previous_candidates == candidates && previous_candidate_sources == candidate_sources
            {
                false
            } else {
                *current = candidates.clone();
                *local_candidate_sources.write().await = candidate_sources.clone();
                true
            }
        };
        if !changed {
            if profile_changed {
                debug!(
                    "UDP NAT profile changed without advertised candidate endpoint changes: mapping={:?} public={:?}",
                    report.nat_profile.mapping_behavior,
                    report.nat_profile.public_endpoint
                );
            }
            continue;
        }

        info!(
            "UDP candidates changed after network update; refreshed {} candidates (mapping={:?}, public={:?})",
            candidates.len(),
            report.nat_profile.mapping_behavior,
            report.nat_profile.public_endpoint
        );
        let endpoint = control_udp_endpoint_from_candidates(&candidates, &candidate_sources)
            .or(advertised_endpoint)
            .unwrap_or_default();
        if should_advance_generation {
            peers
                .advance_candidate_refresh_generation("refreshed UDP candidates")
                .await;
        } else {
            debug!(
                "UDP candidate refresh changed only volatile reflexive ports; keeping network generation and signaling stable"
            );
            if should_update_stable_control_endpoint(published_endpoint.as_deref(), &endpoint) {
                if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
                    warn!("Failed to publish refreshed UDP endpoint '{endpoint}': {err}");
                } else {
                    published_endpoint = Some(endpoint);
                }
            }
            publish_local_candidates_to_known_peers(
                &control,
                peers.clone(),
                udp.clone(),
                punch_deduplicator.clone(),
                &candidates,
                &candidate_sources,
                probe_interval,
                punch_attempts,
                "UDP volatile candidate refresh",
            )
            .await;
            continue;
        }
        if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
            warn!("Failed to publish refreshed UDP endpoint '{endpoint}': {err}");
        } else if !endpoint.is_empty() {
            published_endpoint = Some(endpoint.clone());
        }

        publish_local_candidates_to_known_peers(
            &control,
            peers.clone(),
            udp.clone(),
            punch_deduplicator.clone(),
            &candidates,
            &candidate_sources,
            probe_interval,
            punch_attempts,
            "UDP candidate refresh",
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_local_candidates_to_known_peers(
    control: &ControlClient,
    peers: Arc<PeerManager>,
    udp: UdpTransport,
    punch_deduplicator: PunchAttemptDeduplicator,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    probe_interval: Duration,
    attempts: u32,
    reason: &str,
) {
    if candidates.is_empty() {
        debug!("Skipping {reason} candidate publication because local candidate set is empty");
        return;
    }

    let attempts = peers.recommended_punch_attempts(attempts).await;

    for (peer_id, peer_info) in control.peers().await {
        if !peer_info.online {
            continue;
        }
        let punch_at_ms = Some(relay_assisted_punch_at_ms());
        if let Err(error) = control
            .send_peer_offer_with_sources_and_punch_at(
                &peer_id,
                candidates,
                candidate_sources,
                &[],
                punch_at_ms,
            )
            .await
        {
            warn!("Failed to publish {reason} UDP candidates to peer {peer_id}: {error}");
            continue;
        }

        debug!(
            "Published {reason} UDP candidates to peer {peer_id} with punch_at_ms={punch_at_ms:?}"
        );
        spawn_hole_punch_task(
            udp.clone(),
            peers.clone(),
            punch_deduplicator.clone(),
            peer_id,
            probe_interval,
            attempts,
            punch_at_ms,
        )
        .await;
    }
}
