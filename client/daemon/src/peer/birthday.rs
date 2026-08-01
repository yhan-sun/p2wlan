use super::*;

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
    let bounded_rank = wide_rank % birthday_probe_wide_rank_count();
    let magnitude = (((bounded_rank / 2) as i32 + 1) * BIRTHDAY_PROBE_WIDE_STRIDE)
        % BIRTHDAY_PROBE_WIDE_MAX_DELTA;
    let magnitude = if magnitude == 0 {
        BIRTHDAY_PROBE_WIDE_MAX_DELTA
    } else {
        magnitude
    };
    let delta = if bounded_rank % 2 == 0 {
        magnitude
    } else {
        -magnitude
    };
    birthday_probe_endpoint(base, delta)
}

pub(super) fn birthday_probe_wide_rank_count() -> usize {
    (BIRTHDAY_PROBE_WIDE_MAX_DELTA as usize).saturating_mul(2)
}

pub(super) fn birthday_probe_near_rank_count() -> usize {
    (BIRTHDAY_PROBE_NEAR_MAX_DELTA as usize).saturating_mul(2)
}

fn birthday_probe_near_delta(rank: usize) -> Option<i32> {
    if rank >= birthday_probe_near_rank_count() {
        return None;
    }
    let magnitude = (rank / 2 + 1) as i32;
    Some(if rank % 2 == 0 { magnitude } else { -magnitude })
}

#[cfg(test)]
pub(super) fn birthday_probe_endpoints_for_bases(
    bases: &[SocketAddr],
    budget: usize,
) -> Vec<SocketAddr> {
    birthday_probe_endpoints_for_bases_from_rank(bases, budget, 0)
}

pub(super) fn birthday_probe_endpoints_for_bases_from_rank(
    bases: &[SocketAddr],
    budget: usize,
    start_rank: usize,
) -> Vec<SocketAddr> {
    let mut endpoints = Vec::new();
    if bases.is_empty() || budget == 0 {
        return endpoints;
    }

    let mut seen = HashSet::new();
    let max_rank =
        birthday_probe_near_rank_count().saturating_add(birthday_probe_wide_rank_count());
    for offset in 0..max_rank {
        let rank = start_rank.saturating_add(offset);
        for base in bases {
            if endpoints.len() >= budget {
                return endpoints;
            }
            let Some(endpoint) = birthday_probe_endpoint_for_rank(*base, rank) else {
                continue;
            };
            if seen.insert(endpoint) {
                endpoints.push(endpoint);
            }
        }
    }
    endpoints
}

fn birthday_probe_endpoint(base: SocketAddr, delta: i32) -> Option<SocketAddr> {
    let port = base.port() as i32 + delta;
    let port = u16::try_from(port).ok()?;
    (port > 0).then_some(SocketAddr::new(base.ip(), port))
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
