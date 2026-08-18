use super::*;

#[derive(Debug, Clone)]
pub(super) struct BirthdayEndpointPlan {
    pub endpoints: Vec<SocketAddr>,
    pub next_rank: usize,
    pub wrapped: bool,
}

#[cfg(test)]
pub(super) fn birthday_probe_endpoints(base: SocketAddr) -> Vec<SocketAddr> {
    (0..birthday_probe_near_rank_count())
        .filter_map(birthday_probe_near_delta)
        .filter_map(|delta| birthday_probe_endpoint(base, delta))
        .collect()
}

fn birthday_probe_endpoint_for_rank(base: SocketAddr, rank: usize) -> Option<SocketAddr> {
    if let Some(delta) = birthday_probe_near_delta(rank) {
        return birthday_probe_endpoint(base, delta);
    }

    let wide_rank = rank.saturating_sub(birthday_probe_near_rank_count());
    Some(SocketAddr::new(
        base.ip(),
        permuted_port_from_origin(base.port(), wide_rank),
    ))
}

pub(super) fn birthday_probe_wide_rank_count() -> usize {
    BIRTHDAY_PROBE_PORT_SPACE
}

pub(super) fn birthday_probe_near_rank_count() -> usize {
    (BIRTHDAY_PROBE_NEAR_MAX_DELTA as usize).saturating_mul(2)
}

fn birthday_probe_near_delta(rank: usize) -> Option<i32> {
    if rank >= birthday_probe_near_rank_count() {
        return None;
    }
    let magnitude = (rank / 2 + 1) as i32;
    Some(if rank.is_multiple_of(2) {
        magnitude
    } else {
        -magnitude
    })
}

#[cfg(test)]
pub(super) fn birthday_probe_endpoints_for_bases(
    bases: &[SocketAddr],
    budget: usize,
) -> Vec<SocketAddr> {
    birthday_probe_endpoints_for_bases_from_rank(bases, budget, 0)
}

#[cfg(test)]
pub(super) fn birthday_probe_endpoints_for_bases_from_rank(
    bases: &[SocketAddr],
    budget: usize,
    start_rank: usize,
) -> Vec<SocketAddr> {
    birthday_probe_endpoint_plan_for_bases_from_rank(bases, budget, start_rank, true).endpoints
}

pub(super) fn birthday_probe_endpoint_plan_for_bases_from_rank(
    bases: &[SocketAddr],
    budget: usize,
    start_rank: usize,
    include_near: bool,
) -> BirthdayEndpointPlan {
    let mut endpoints = Vec::new();
    if bases.is_empty() || budget == 0 {
        return BirthdayEndpointPlan {
            endpoints,
            next_rank: start_rank % birthday_probe_wide_rank_count(),
            wrapped: false,
        };
    }

    let mut seen = HashSet::new();
    if include_near {
        for rank in 0..birthday_probe_near_rank_count() {
            for base in bases {
                if endpoints.len() >= budget {
                    return BirthdayEndpointPlan {
                        endpoints,
                        next_rank: start_rank % birthday_probe_wide_rank_count(),
                        wrapped: false,
                    };
                }
                let Some(endpoint) = birthday_probe_endpoint_for_rank(*base, rank) else {
                    continue;
                };
                if seen.insert(endpoint) {
                    endpoints.push(endpoint);
                }
            }
        }
    }

    let rank_count = birthday_probe_wide_rank_count();
    let normalized_start_rank = start_rank % rank_count;
    let mut ranks_consumed = 0usize;
    for offset in 0..birthday_probe_wide_rank_count() {
        let wide_rank = normalized_start_rank.saturating_add(offset) % rank_count;
        let rank = birthday_probe_near_rank_count().saturating_add(wide_rank);
        let mut rank_endpoints = Vec::with_capacity(bases.len());
        for base in bases {
            let Some(endpoint) = birthday_probe_endpoint_for_rank(*base, rank) else {
                continue;
            };
            if seen.insert(endpoint) {
                rank_endpoints.push(endpoint);
            }
        }
        if endpoints.len().saturating_add(rank_endpoints.len()) > budget {
            break;
        }
        endpoints.extend(rank_endpoints);
        ranks_consumed = offset.saturating_add(1);
        if endpoints.len() >= budget {
            break;
        }
    }
    let next_rank = normalized_start_rank.saturating_add(ranks_consumed) % rank_count;
    BirthdayEndpointPlan {
        endpoints,
        next_rank,
        wrapped: normalized_start_rank.saturating_add(ranks_consumed) >= rank_count,
    }
}

fn birthday_probe_endpoint(base: SocketAddr, delta: i32) -> Option<SocketAddr> {
    let zero_based = i32::from(base.port().saturating_sub(1));
    let wrapped = (zero_based + delta).rem_euclid(BIRTHDAY_PROBE_PORT_SPACE as i32);
    let port = u16::try_from(wrapped + 1).ok()?;
    Some(SocketAddr::new(base.ip(), port))
}

/// Wrapped port neighbor of an advertised base for the fast-prefix
/// neighborhood merge.  Deduplicated by the caller.
pub(super) fn advertised_neighborhood_endpoint(base: SocketAddr, delta: i32) -> Option<SocketAddr> {
    birthday_probe_endpoint(base, delta)
}

fn permuted_port_from_origin(origin: u16, rank: usize) -> u16 {
    let zero_based_origin = usize::from(origin.saturating_sub(1));
    let offset = rank
        .saturating_add(1)
        .saturating_mul(BIRTHDAY_PROBE_WIDE_STRIDE)
        % BIRTHDAY_PROBE_PORT_SPACE;
    u16::try_from((zero_based_origin + offset) % BIRTHDAY_PROBE_PORT_SPACE + 1)
        .expect("permuted UDP port must fit u16")
}

fn public_ip_port_seed(ip: IpAddr) -> u16 {
    let bytes = match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let seed = bytes.into_iter().fold(0usize, |seed, byte| {
        (seed.saturating_mul(257) + usize::from(byte)) % BIRTHDAY_PROBE_PORT_SPACE
    });
    u16::try_from(seed + 1).expect("public IP port seed must fit u16")
}

pub(super) fn stable_public_ip_probe_plan_from_rank(
    public_ips: &[IpAddr],
    budget: usize,
    start_rank: usize,
    excluded: &HashSet<SocketAddr>,
) -> BirthdayEndpointPlan {
    let rank_count = birthday_probe_wide_rank_count();
    let normalized_start_rank = start_rank % rank_count;
    let mut endpoints = Vec::with_capacity(budget);
    let mut seen = excluded.clone();
    let mut ranks_consumed = 0usize;

    for offset in 0..rank_count {
        let rank = normalized_start_rank.saturating_add(offset) % rank_count;
        let mut rank_endpoints = Vec::with_capacity(public_ips.len());
        for ip in public_ips {
            let endpoint = SocketAddr::new(
                *ip,
                permuted_port_from_origin(public_ip_port_seed(*ip), rank),
            );
            if seen.insert(endpoint) {
                rank_endpoints.push(endpoint);
            }
        }
        if endpoints.len().saturating_add(rank_endpoints.len()) > budget {
            break;
        }
        endpoints.extend(rank_endpoints);
        ranks_consumed = offset.saturating_add(1);
        if endpoints.len() >= budget {
            break;
        }
    }

    BirthdayEndpointPlan {
        endpoints,
        next_rank: normalized_start_rank.saturating_add(ranks_consumed) % rank_count,
        wrapped: normalized_start_rank.saturating_add(ranks_consumed) >= rank_count,
    }
}

pub(super) fn peer_candidates_need_port_scatter(bases: &[SocketAddr]) -> bool {
    let mut ports_by_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for endpoint in bases {
        ports_by_ip
            .entry(endpoint.ip())
            .or_default()
            .insert(endpoint.port());
    }
    ports_by_ip.values().any(|ports| ports.len() >= 2)
}
