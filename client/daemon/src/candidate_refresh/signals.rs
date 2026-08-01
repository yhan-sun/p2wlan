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
