pub(super) fn advertised_udp_endpoint(
    local_addr: SocketAddr,
    configured: Option<&str>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    include_host_candidate: bool,
) -> Option<String> {
    if let Some(endpoint) = configured
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
    {
        return Some(endpoint.to_string());
    }

    // A STUN/port-mapping candidate is a credible public primary target. A
    // global-looking Host candidate is not: it may be a VPN/VNIC address
    // whose literal scope says nothing about public reachability. Keep Host
    // candidates available as fallbacks, but rank an ordinary private Host
    // ahead of a global-looking unrelated Host. This preserves the LAN path
    // in the multi-NIC case without turning a static address heuristic into a
    // hard rejection.
    candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .enumerate()
        .min_by_key(|(index, candidate)| {
            (
                advertised_candidate_rank(
                    *candidate,
                    candidate_sources
                        .get(&candidate.to_string())
                        .map(String::as_str),
                ),
                *index,
            )
        })
        .filter(|(_, candidate)| {
            !candidate.ip().is_unspecified() && !candidate.ip().is_loopback()
        })
        .map(|(_, candidate)| candidate.to_string())
        .or_else(|| {
            candidates
                .iter()
                .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
                .find(|candidate| {
                    !candidate.ip().is_unspecified() && !candidate.ip().is_loopback()
                })
                .map(|candidate| candidate.to_string())
        })
        .or_else(|| {
            (include_host_candidate && !local_addr.ip().is_unspecified())
                .then(|| local_addr.to_string())
        })
}

fn advertised_candidate_rank(endpoint: SocketAddr, source: Option<&str>) -> u8 {
    let public = is_public_udp_candidate(endpoint);
    match source {
        Some("manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping")
            if public => 0,
        Some("stun_observed") if public => 1,
        Some("host") if !public => 2,
        Some("host") => 3,
        Some("signaled") if public => 4,
        None if public => 4,
        Some("signaled") | None => 5,
        Some("peer_reflexive" | "learned" | "predicted" | "birthday" | "relay") => 6,
        Some(_) if public => 5,
        Some(_) => 6,
    }
}

fn is_verified_public_source(source: Option<&str>) -> bool {
    matches!(
        source,
        Some("manual" | "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" | "stun_observed")
    )
}

fn is_verified_public_candidate(endpoint: SocketAddr, source: Option<&str>) -> bool {
    is_public_udp_candidate(endpoint) && is_verified_public_source(source)
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
        // Host provenance never becomes public proof merely because the
        // address is outside RFC1918. It remains a usable last-resort Host
        // candidate, but it must follow independently observed mappings.
        Some("host") => endpoint
            .parse::<SocketAddr>()
            .ok()
            .map(|endpoint| if is_public_udp_candidate(endpoint) { 4 } else { 3 })
            .unwrap_or(u8::MAX),
        Some("peer_reflexive" | "learned" | "predicted" | "birthday") => u8::MAX,
        Some("relay") => u8::MAX,
        Some(source) if crate::parse_fresh_prediction_source_label(source).is_some() => u8::MAX,
        Some(_) | None => {
            if endpoint.parse::<SocketAddr>().is_ok_and(|candidate| {
                !candidate.ip().is_unspecified() && !candidate.ip().is_loopback()
            }) {
                5
            } else {
                u8::MAX
            }
        }
    }
}

pub(super) fn should_update_stable_control_endpoint(
    published_endpoint: Option<&str>,
    next_endpoint: &str,
    mapping_behavior: MappingBehavior,
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
            !is_public_udp_candidate(published_addr)
                || published_addr.ip() != next_addr.ip()
                // An address/port-dependent NAT allocates a different public
                // port for different destinations.  The port is therefore
                // part of the peer-facing mapping even when the public IP is
                // unchanged; suppressing this update leaves late joiners
                // with an observer-specific or already-expired endpoint.
                || (mapping_behavior == MappingBehavior::AddressOrPortDependent
                    && published_addr.port() != next_addr.port())
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
        // Fresh-mapping prediction windows are reserved by
        // `truncate_signal_candidates` after this stage: the per-public-IP
        // volatile truncation must never delete a predicted port before the
        // reservation can preserve it, so the whole prepared candidate set
        // keeps every publishable window port (top-1 first).
        if is_valid_fresh_signal_source(source) {
            continue;
        }
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
        let is_fresh_reserved = candidate_sources
            .get(endpoint)
            .map(String::as_str)
            .is_some_and(is_valid_fresh_signal_source);
        let is_volatile_public = !is_fresh_reserved
            && candidate_sources
                .get(endpoint)
                .map(String::as_str)
                .is_some_and(is_volatile_public_signal_source)
            && endpoint
                .parse::<SocketAddr>()
                .is_ok_and(is_public_udp_candidate);
        is_fresh_reserved || !is_volatile_public || retained_volatile.contains(endpoint)
    });
    let retained = candidates.iter().cloned().collect::<HashSet<_>>();
    candidate_sources.retain(|endpoint, _| retained.contains(endpoint));
}

/// Whether a source label identifies a volatile public candidate that may be
/// compacted and truncated per public IP.  A genuine fresh-mapping prediction
/// window is volatile too: it is a time-sensitive guess, not a stable path.
fn is_volatile_public_signal_source(source: &str) -> bool {
    matches!(
        source,
        "stun_observed" | "peer_reflexive" | "learned" | "predicted"
    ) || crate::parse_fresh_prediction_source_label(source).is_some()
}

/// Whether a source label belongs to the predicted class: ordinary `predicted`
/// or a valid fresh-mapping prediction label.  Both order after STUN evidence
/// and before host/public unknowns, but only within the same rank.
fn is_predicted_class_signal_source(source: &str) -> bool {
    source == "predicted" || crate::parse_fresh_prediction_source_label(source).is_some()
}

pub(super) fn truncate_signal_candidates(
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    if candidates.len() > MAX_SIGNAL_CANDIDATES {
        let original_candidate_count = candidates.len();
        let original_order = candidates
            .iter()
            .enumerate()
            .map(|(index, endpoint)| (endpoint.clone(), index))
            .collect::<HashMap<_, _>>();
        let predicted_order = balanced_predicted_signal_order(candidates, candidate_sources);
        let mut retained_lan_hosts = candidates
            .iter()
            .filter(|endpoint| {
                is_physical_lan_host_signal_candidate(
                    endpoint,
                    candidate_sources.get(*endpoint).map(String::as_str),
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        retained_lan_hosts.sort();
        retained_lan_hosts.truncate(MAX_SIGNAL_LAN_HOST_CANDIDATES);

        // Fresh-mapping prediction windows are time-sensitive: reserve their
        // whole window (bounded by the model's widest window) so a full
        // ordinary candidate set cannot crowd them out.  The window keeps its
        // sender order (top-1 first, then the successor window).
        let fresh_candidates = candidates
            .iter()
            .filter(|endpoint| {
                candidate_sources
                    .get(*endpoint)
                    .map(String::as_str)
                    .is_some_and(is_valid_fresh_signal_source)
            })
            .take(MAX_SIGNAL_FRESH_WINDOW_CANDIDATES)
            .cloned()
            .collect::<Vec<_>>();
        let fresh_host_reservation = retained_lan_hosts.len();
        let fresh_window = fresh_candidates
            .into_iter()
            .take(
                MAX_SIGNAL_CANDIDATES
                    .saturating_sub(fresh_host_reservation),
            )
            .collect::<Vec<_>>();
        let fresh_window_set = fresh_window.iter().cloned().collect::<HashSet<_>>();
        let fresh_budget = fresh_window.len();
        // The reservations share one signaling budget, but a bounded Host
        // prefix is deliberately reserved even when the fresh prediction
        // window reaches its maximum. The remote can only prove on-link status
        // after receiving these candidates and comparing them with its own
        // interfaces; dropping every Host here makes same-LAN recovery depend
        // on the public/NAT path.
        retained_lan_hosts.truncate(
            MAX_SIGNAL_CANDIDATES
                .saturating_sub(fresh_budget)
                .min(fresh_host_reservation),
        );
        let retained_lan_host_set = retained_lan_hosts.iter().cloned().collect::<HashSet<_>>();

        let mut others = candidates
            .iter()
            .filter(|endpoint| {
                !fresh_window_set.contains(*endpoint) && !retained_lan_host_set.contains(*endpoint)
            })
            .cloned()
            .collect::<Vec<_>>();
        let public_budget = MAX_SIGNAL_CANDIDATES
            .saturating_sub(fresh_budget)
            .saturating_sub(retained_lan_hosts.len());
        others.sort_by(|left, right| {
            compare_signal_candidates(
                left,
                right,
                candidate_sources,
                &original_order,
                &predicted_order,
            )
        });
        others.truncate(public_budget);
        let mut retained = fresh_window;
        retained.extend(others);
        retained.extend(retained_lan_hosts);
        *candidates = retained;

        // Deduplicate by the exact retained payload, not the over-limit input.
        // Different gathered tails that compact to the same 96 candidates must
        // not keep invalidating the same published snapshot.
        let truncation_dedup = truncation_reporter();
        let canonical_hash = canonical_candidate_set_hash(candidates, candidate_sources);
        if truncation_dedup
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .report(canonical_hash)
        {
            warn!(
                "Truncating {} gathered UDP candidates to the signaling limit of {} (retained canonical set hash={canonical_hash})",
                original_candidate_count,
                MAX_SIGNAL_CANDIDATES
            );
        }
    }
    let retained = candidates.iter().cloned().collect::<HashSet<_>>();
    candidate_sources.retain(|endpoint, _| retained.contains(endpoint));
}

/// Whether a source label is a well-formed fresh-mapping prediction label
/// that may claim the reserved signaling window.
fn is_valid_fresh_signal_source(source: &str) -> bool {
    crate::parse_fresh_prediction_source_label(source).is_some()
}

fn is_physical_lan_host_signal_candidate(endpoint: &str, source: Option<&str>) -> bool {
    if source != Some("host") {
        return false;
    }
    endpoint.parse::<SocketAddr>().is_ok_and(|candidate| {
        !candidate.ip().is_unspecified()
            && !candidate.ip().is_loopback()
            && !is_public_udp_candidate(candidate)
    })
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
        candidate_sources
            .get(*endpoint)
            .map(String::as_str)
            .is_some_and(is_predicted_class_signal_source)
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
        // Ordinary `predicted` and fresh predictions share the predicted
        // rank: both are volatile guesses that order after observed
        // evidence.  The fresh window additionally holds a reserved budget
        // in `truncate_signal_candidates` so it is never crowded out.
        Some("predicted") => 4,
        Some(source) if crate::parse_fresh_prediction_source_label(source).is_some() => 4,
        // Host provenance remains Host regardless of address scope. A
        // global-looking Host must not outrank independently observed public
        // evidence merely because it is not RFC1918.
        Some("host") => 8,
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
        CandidateSource::PortMapped => "port_mapping",
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

/// Build the canonical local network identity from the complete candidate
/// snapshot, then apply the smaller control-plane signaling budget.
///
/// Network identity must not depend on which entries happen to fit inside the
/// 96-candidate wire limit. In particular, hard-NAT prediction windows can
/// fill that limit and otherwise hide the physical LAN host address.
pub(super) fn prepare_signal_candidates_and_network_identity(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) -> Vec<String> {
    // A peer-reflexive endpoint is evidence about a remote path, not about
    // this machine's active interface/NAT identity.  Keep the previous
    // stable identity available while a STUN report is temporarily missing so
    // a single incomplete report cannot revoke a healthy relay generation.
    let previous_network_identity =
        stable_network_candidate_signature(previous_candidates, previous_candidate_sources);
    preserve_peer_reflexive_candidates(
        previous_candidates,
        previous_candidate_sources,
        candidates,
        candidate_sources,
    );
    let current_network_identity = stable_network_candidate_signature(candidates, candidate_sources);
    let network_identity = carry_forward_missing_network_identity(
        &previous_network_identity,
        current_network_identity,
    );
    compact_volatile_public_signal_candidates(candidates, candidate_sources);
    truncate_signal_candidates(candidates, candidate_sources);
    network_identity
}

pub(super) fn candidate_refresh_requires_commit(
    real_candidate_change: bool,
    should_advance_generation: bool,
) -> bool {
    real_candidate_change || should_advance_generation
}

/// Return whether the candidate snapshot contains a public endpoint backed by
/// local discovery evidence.  Predicted ports and peer-reflexive/learned
/// endpoints are useful punch targets, but they are not proof that this
/// daemon's current NAT mapping is ready to advertise as the primary path.
///
/// This distinction matters when startup publishes a host-only snapshot and a
/// later STUN refresh discovers the public mapping.  That transition must be
/// signaled immediately even though it does not replace the local network
/// identity (and therefore must not advance the connection generation).
pub(super) fn has_real_public_candidate(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    candidates.iter().any(|endpoint| {
        let endpoint_text = endpoint.as_str();
        let Ok(endpoint) = endpoint_text.parse::<SocketAddr>() else {
            return false;
        };
        if !is_public_udp_candidate(endpoint) {
            return false;
        }
        let source = candidate_sources.get(endpoint_text).map(String::as_str);
        is_verified_public_candidate(endpoint, source)
    })
}

/// Whether the candidate set is backed by the current daemon's reliable
/// primary NAT observation, rather than only by a socket-pool observation.
///
/// A pool socket can discover a public endpoint while the primary socket's
/// profile still says `UdpBlocked`.  That endpoint is useful as a bounded
/// punch target, but it must not stop the startup retry loop: in the Air
/// acceptance run this distinction was the difference between a fresh
/// mapping refresh and waiting for the normal 15-second cadence.  The NAT
/// profile is deliberately the authority for startup readiness; candidate
/// source labels alone cannot prove that the current primary mapping is
/// usable.
pub(super) fn has_reliable_public_candidate(
    nat_profile: Option<&NatProfile>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    nat_profile.is_some_and(|profile| {
        !profile.udp_blocked
            && profile.public_endpoint.is_some()
            && profile.public_endpoint.as_ref().is_some_and(|endpoint| {
                has_real_public_candidate(
                    std::slice::from_ref(endpoint),
                    candidate_sources,
                ) && candidates.iter().any(|candidate| candidate == endpoint)
            })
    })
}

/// A mapping-dependent socket pool needs one complete post-bind gather even
/// when the bounded primary-socket gather already returned a public STUN
/// endpoint.  That first endpoint is observer-specific evidence; for an
/// address/port-dependent NAT it is not necessarily the mapping a peer can
/// reach.  Waiting for the normal 15-second refresh cadence leaves the peer
/// probing a stale observer mapping for the whole interval.
pub(super) fn should_warm_mapping_dependent_socket_pool(
    socket_count: usize,
    socket_pool_active: bool,
    nat_profile: Option<&NatProfile>,
) -> bool {
    socket_count > 1
        && socket_pool_active
        && nat_profile.is_some_and(|profile| {
            !profile.udp_blocked
                && profile.mapping_behavior == MappingBehavior::AddressOrPortDependent
        })
}

/// Whether a refresh crossed the boundary between “only private/predicted
/// candidates” and “a locally observed public candidate is available”.
///
/// A public port changing on the same mapping remains volatile churn and may
/// use the normal short debounce.  A readiness transition is different:
/// retaining even that brief debounce here would leave peers probing an
/// obsolete private endpoint after STUN has already produced a usable mapping.
pub(super) fn public_candidate_readiness_changed(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    has_real_public_candidate(previous_candidates, previous_candidate_sources)
        != has_real_public_candidate(candidates, candidate_sources)
}

pub(super) fn add_peer_reflexive_candidate_to_set(
    observed_endpoint: &str,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) -> std::result::Result<bool, std::net::AddrParseError> {
    let endpoint = observed_endpoint.parse::<SocketAddr>()?.to_string();
    if candidates.contains(&endpoint) {
        // The endpoint is already advertised. Keep its existing global source
        // evidence (especially STUN or gateway mapping) instead of repeatedly
        // relabeling it as peer-specific evidence on every observation.
        return Ok(false);
    }
    candidates.insert(0, endpoint.clone());
    candidate_sources.insert(endpoint, "peer_reflexive".to_string());
    compact_volatile_public_signal_candidates(candidates, candidate_sources);
    truncate_signal_candidates(candidates, candidate_sources);

    Ok(true)
}

#[cfg(test)]
pub(super) fn candidate_refresh_requires_network_generation_advance(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    network_identity_changed(
        &stable_network_candidate_signature(previous_candidates, previous_candidate_sources),
        &stable_network_candidate_signature(candidates, candidate_sources),
    )
}

/// Decide whether a candidate refresh represents a real local network
/// identity replacement.
///
/// Candidate sets are deliberately additive: a new interface, a new mapped
/// port, or a peer-reflexive observation may be added while the established
/// local path remains valid.  Advancing the generation for that kind of
/// change revokes relay sessions and forces a needless Direct restart.  A
/// generation advances only when a previously observed identity category has
/// no surviving member in the new set.  Empty categories are treated as
/// inconclusive because STUN can fail transiently.
pub(super) fn network_identity_changed(previous: &[String], next: &[String]) -> bool {
    const CATEGORIES: [&str; 3] = ["public-ip:", "physical-host-ip:", "mapped-ip:"];

    for category in CATEGORIES {
        let previous_values = previous
            .iter()
            .filter_map(|entry| entry.strip_prefix(category))
            .collect::<HashSet<_>>();
        let next_values = next
            .iter()
            .filter_map(|entry| entry.strip_prefix(category))
            .collect::<HashSet<_>>();
        if !previous_values.is_empty()
            && !next_values.is_empty()
            && previous_values.is_disjoint(&next_values)
        {
            return true;
        }
    }

    let previous_other = previous
        .iter()
        .filter(|entry| !CATEGORIES.iter().any(|category| entry.starts_with(category)))
        .collect::<HashSet<_>>();
    let next_other = next
        .iter()
        .filter(|entry| !CATEGORIES.iter().any(|category| entry.starts_with(category)))
        .collect::<HashSet<_>>();
    !previous_other.is_empty()
        && !next_other.is_empty()
        && previous_other.is_disjoint(&next_other)
}

fn carry_forward_missing_network_identity(previous: &[String], mut current: Vec<String>) -> Vec<String> {
    const CATEGORIES: [&str; 3] = ["public-ip:", "physical-host-ip:", "mapped-ip:"];
    for category in CATEGORIES {
        if current.iter().any(|entry| entry.starts_with(category)) {
            continue;
        }
        current.extend(
            previous
                .iter()
                .filter(|entry| entry.starts_with(category))
                .cloned(),
        );
    }
    current.sort();
    current.dedup();
    current
}

/// Order-insensitive change classification for a candidate set refresh.
///
/// Candidate reports frequently reorder endpoints (and re-promote sources)
/// without any real NAT change. Refresh logic must compare sets, not vector
/// order, and only publish/advance when the set actually changed.
pub(super) fn candidate_set_change_reason(
    previous_candidates: &[String],
    next_candidates: &[String],
    previous_sources: &HashMap<String, String>,
    next_sources: &HashMap<String, String>,
) -> &'static str {
    let previous_set = previous_candidates
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let next_set = next_candidates.iter().map(String::as_str).collect::<HashSet<_>>();
    let added = next_set.difference(&previous_set).copied().collect::<Vec<_>>();
    let removed = previous_set
        .difference(&next_set)
        .copied()
        .collect::<Vec<_>>();
    if added.is_empty() && removed.is_empty() {
        if previous_candidates == next_candidates && previous_sources == next_sources {
            return "no_change";
        }
        if previous_sources != next_sources {
            return "source_changed";
        }
        return "order_only";
    }
    if !added.is_empty() && !removed.is_empty() {
        let ips = |entries: &[&str]| {
            entries
                .iter()
                .filter_map(|endpoint| endpoint.parse::<SocketAddr>().ok())
                .map(|endpoint| endpoint.ip())
                .collect::<HashSet<_>>()
        };
        if !ips(&added).is_empty() && ips(&added) == ips(&removed) {
            return "port_changed";
        }
        return "added_removed";
    }
    if !added.is_empty() {
        "added"
    } else {
        "removed"
    }
}

/// Order-insensitive hash of a candidate set for diagnostics diffs.
pub(super) fn candidate_set_hash(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut entries = candidates
        .iter()
        .map(|endpoint| {
            format!(
                "{}={}",
                endpoint,
                candidate_sources
                    .get(endpoint)
                    .map(String::as_str)
                    .unwrap_or("signaled")
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for entry in &entries {
        entry.hash(&mut hasher);
    }
    hasher.finish()
}

/// Canonical (order-insensitive) hash of the truncated top-N candidate set.
///
/// This is the identity used to deduplicate the truncation warning and the
/// volatile publication gate: if the canonical top-N content is unchanged,
/// the refresh produced no semantic change and must not warn, offer, publish
/// or punch again.
pub(super) fn canonical_candidate_set_hash(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> u64 {
    let mut entries = candidates
        .iter()
        .map(|endpoint| {
            format!(
                "{}={}",
                endpoint,
                candidate_sources
                    .get(endpoint)
                    .map(String::as_str)
                    .unwrap_or("signaled")
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    for entry in &entries {
        entry.hash(&mut hasher);
    }
    hasher.finish()
}

/// Process-wide truncation warning deduplicator.
///
/// A gathered set that stays over the signaling limit across refreshes
/// (e.g. the same 98 gathered candidates truncating to the same top-96)
/// must warn exactly once per canonical content, then only update a
/// counter.  The event remains observable as a structured counter instead
/// of a log flood.
#[derive(Debug, Default)]
pub(super) struct TruncationReporter {
    last_canonical_hash: Option<u64>,
    identical_truncations: u64,
    total_truncations: u64,
}

impl TruncationReporter {
    /// Report one truncation event; returns `true` when this canonical
    /// content was NOT seen before (the caller should surface the warning).
    pub(super) fn report(&mut self, canonical_hash: u64) -> bool {
        self.total_truncations = self.total_truncations.saturating_add(1);
        if self.last_canonical_hash == Some(canonical_hash) {
            self.identical_truncations = self.identical_truncations.saturating_add(1);
            false
        } else {
            self.last_canonical_hash = Some(canonical_hash);
            true
        }
    }

    /// Counters exposed for diagnostics and tests.
    #[cfg(test)]
    pub(super) fn counters(&self) -> (u64, u64) {
        (self.total_truncations, self.identical_truncations)
    }
}

/// Process-wide singleton truncation reporter (the reporter itself holds no
/// candidate content, only hashes and counters).
fn truncation_reporter() -> &'static std::sync::Mutex<TruncationReporter> {
    use std::sync::OnceLock;
    static REPORTER: OnceLock<std::sync::Mutex<TruncationReporter>> = OnceLock::new();
    REPORTER.get_or_init(|| std::sync::Mutex::new(TruncationReporter::default()))
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
            Ok(addr) if is_public_udp_candidate(addr) => match source {
                // Only independently observed/mapped evidence is a public
                // identity. A global-looking Host is still a physical Host
                // identity, not proof of a public NAT mapping.
                "stun_observed" | "manual" | "upnp" | "pcp" | "nat_pmp"
                | "nat-pmp" | "port_mapping" => {
                    signature.push(format!("public-ip:{}", addr.ip()));
                }
                "host" => signature.push(format!("physical-host-ip:{}", addr.ip())),
                // Prediction is not current reachability proof, but its IP is
                // derived from an earlier local public observation and still
                // belongs to the stable network-identity fingerprint.
                "predicted" => signature.push(format!("public-ip:{}", addr.ip())),
                // Peer-reflexive/learned endpoints describe a remote path,
                // not this daemon's local network identity.
                "peer_reflexive" | "learned" => {}
                _ => signature.push(format!("physical-host-ip:{}", addr.ip())),
            },
            Ok(addr) => match source {
                "host" => {
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
                "stun_observed" | "predicted" => {
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
