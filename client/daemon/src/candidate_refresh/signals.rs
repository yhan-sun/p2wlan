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
    (endpoints, sources)
}

pub(super) fn compact_volatile_public_signal_candidates(
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    let original_order = candidates
        .iter()
        .enumerate()
        .map(|(index, endpoint)| (endpoint.clone(), index))
        .collect::<HashMap<_, _>>();
    let predicted_order = balanced_predicted_signal_order(candidates, candidate_sources);
    let mut volatile_public_by_ip: HashMap<IpAddr, Vec<String>> = HashMap::new();
    for endpoint in candidates.iter() {
        let Some(source) = candidate_sources.get(endpoint).map(String::as_str) else {
            continue;
        };
        if !is_volatile_public_signal_source(source) {
            continue;
        }
        let Ok(addr) = endpoint.parse::<SocketAddr>() else {
            continue;
        };
        if !is_public_udp_candidate(addr) {
            continue;
        }
        volatile_public_by_ip
            .entry(addr.ip())
            .or_default()
            .push(endpoint.clone());
    }

    let mut retained_volatile = HashSet::new();
    for endpoints in volatile_public_by_ip.values_mut() {
        endpoints.sort_by(|left, right| {
            compare_signal_candidates(
                left,
                right,
                candidate_sources,
                &original_order,
                &predicted_order,
            )
        });
        endpoints.truncate(MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP);
        retained_volatile.extend(endpoints.iter().cloned());
    }

    candidates.retain(|endpoint| {
        let is_volatile_public = candidate_sources
            .get(endpoint)
            .map(String::as_str)
            .is_some_and(is_volatile_public_signal_source)
            && endpoint
                .parse::<SocketAddr>()
                .is_ok_and(is_public_udp_candidate);
        !is_volatile_public || retained_volatile.contains(endpoint)
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
        let predicted_order = balanced_predicted_signal_order(candidates, candidate_sources);
        candidates.sort_by(|left, right| {
            compare_signal_candidates(
                left,
                right,
                candidate_sources,
                &original_order,
                &predicted_order,
            )
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

fn compare_signal_candidates(
    left: &str,
    right: &str,
    candidate_sources: &HashMap<String, String>,
    original_order: &HashMap<String, usize>,
    predicted_order: &HashMap<String, usize>,
) -> std::cmp::Ordering {
    let left_rank =
        signal_candidate_rank(left, candidate_sources.get(left).map(String::as_str));
    let right_rank =
        signal_candidate_rank(right, candidate_sources.get(right).map(String::as_str));
    left_rank
        .cmp(&right_rank)
        .then_with(|| {
            if left_rank == 4 && right_rank == 4 {
                predicted_order
                    .get(left)
                    .unwrap_or(&usize::MAX)
                    .cmp(predicted_order.get(right).unwrap_or(&usize::MAX))
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .then_with(|| {
            original_order
                .get(left)
                .unwrap_or(&usize::MAX)
                .cmp(original_order.get(right).unwrap_or(&usize::MAX))
        })
}

fn balanced_predicted_signal_order(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> HashMap<String, usize> {
    let mut runs: Vec<Vec<String>> = Vec::new();
    let mut previous: Option<(SocketAddr, i32)> = None;

    for endpoint in candidates.iter().filter(|endpoint| {
        candidate_sources.get(*endpoint).map(String::as_str) == Some("predicted")
    }) {
        let Ok(address) = endpoint.parse::<SocketAddr>() else {
            runs.push(vec![endpoint.clone()]);
            previous = None;
            continue;
        };

        let mut append_to_current = false;
        let mut next_direction = 0;
        if let Some((previous_address, direction)) = previous {
            let delta = address.port() as i32 - previous_address.port() as i32;
            if address.ip() == previous_address.ip()
                && delta.abs() == 1
                && (direction == 0 || direction == delta)
            {
                append_to_current = true;
                next_direction = delta;
            }
        }

        if append_to_current {
            if let Some(run) = runs.last_mut() {
                run.push(endpoint.clone());
            }
        } else {
            runs.push(vec![endpoint.clone()]);
        }
        previous = Some((address, next_direction));
    }

    let mut balanced = Vec::new();
    let mut offset = 0usize;
    loop {
        let mut added = false;
        for run in &runs {
            if let Some(endpoint) = run.get(offset) {
                balanced.push(endpoint.clone());
                added = true;
            }
        }
        if !added {
            break;
        }
        offset += 1;
    }

    balanced
        .into_iter()
        .enumerate()
        .map(|(index, endpoint)| (endpoint, index))
        .collect()
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

#[cfg(test)]
pub(super) fn candidate_refresh_requires_network_generation_advance(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    stable_network_candidate_signature(previous_candidates, previous_candidate_sources)
        != stable_network_candidate_signature(candidates, candidate_sources)
}

pub(super) fn stable_network_candidate_signature(
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
            Ok(addr) if is_public_udp_candidate(addr) => {
                // Port churn and candidate-source promotion do not mean the
                // host changed networks. A public IP change does.
                signature.push(format!("public-ip:{}", addr.ip()));
            }
            Ok(addr) => match source {
                "host" | "peer_reflexive" | "learned" => {
                    signature.push(format!("physical-host-ip:{}", addr.ip()));
                }
                "manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" => {
                    signature.push(format!("mapped-ip:{}", addr.ip()));
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
