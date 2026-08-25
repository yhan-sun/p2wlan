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
            predicted_endpoints: Vec::new(),
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
    let linear_successor_predictions = linear_successor_reflexive_endpoints(&mapped);
    let prediction_candidate = linear_successor_predictions.is_some()
        || (mapped.len() >= 2
            && is_prediction_candidate(
        false,
        public_ip_stable,
        public_port_stable,
        mapping_behavior,
        port_delta,
            ));
    let predicted_endpoints = predicted_reflexive_endpoints_for_mappings(
        &mapped,
        port_delta,
        prediction_candidate,
        linear_successor_predictions,
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
        predicted_endpoints,
        birthday_candidate,
        confidence,
    }
}

fn predicted_reflexive_endpoints(
    base_endpoint: SocketAddr,
    port_delta: Option<i32>,
    prediction_candidate: bool,
) -> Vec<String> {
    if !prediction_candidate {
        return Vec::new();
    }
    let Some(delta) = port_delta else {
        return Vec::new();
    };
    // A noisy model is deliberately restricted to the small-step range by
    // `is_prediction_candidate`, but its ports still need modular arithmetic
    // when the allocator crosses 65535.  Exact wide-step models are handled
    // by `linear_successor_reflexive_endpoints` below.
    if delta == 0 || !(-8..=8).contains(&delta) {
        return Vec::new();
    }

    (1..=MAX_PREDICTED_REFLEXIVE_CANDIDATES)
        .filter_map(|step| {
            let port = modular_port_add(base_endpoint.port(), delta * step as i32);
            if port == 0 || port == base_endpoint.port() {
                return None;
            }
            Some(SocketAddr::new(base_endpoint.ip(), port).to_string())
        })
        .collect()
}

fn predicted_reflexive_endpoints_for_mappings(
    mapped: &[SocketAddr],
    port_delta: Option<i32>,
    prediction_candidate: bool,
    linear_successor_predictions: Option<Vec<String>>,
) -> Vec<String> {
    if !prediction_candidate {
        return Vec::new();
    }

    if let Some(endpoints) = linear_successor_predictions {
        return endpoints;
    }

    mapped
        .last()
        .copied()
        .map(|base| predicted_reflexive_endpoints(base, port_delta, true))
        .unwrap_or_default()
}

fn linear_successor_reflexive_endpoints(mapped: &[SocketAddr]) -> Option<Vec<String>> {
    if mapped.len() < 3 {
        return None;
    }

    for start in 0..=mapped.len().saturating_sub(3) {
        if let Some(endpoints) = linear_successor_reflexive_endpoints_for_run(&mapped[start..]) {
            return Some(endpoints);
        }
    }

    None
}

fn linear_successor_reflexive_endpoints_for_run(mapped: &[SocketAddr]) -> Option<Vec<String>> {
    if mapped.len() < 3 {
        return None;
    }
    let first_ip = mapped[0].ip();
    if !mapped.iter().all(|endpoint| endpoint.ip() == first_ip) {
        return None;
    }

    let deltas = mapped
        .windows(2)
        .map(|pair| modular_port_delta(pair[0].port(), pair[1].port()))
        .collect::<Vec<_>>();
    if !deltas
        .iter()
        .all(|delta| *delta != 0 && delta.abs() != 32_768)
    {
        return None;
    }

    let exact_step = deltas
        .first()
        .copied()
        .filter(|first| deltas.iter().all(|delta| delta == first));
    let positive = deltas.iter().all(|delta| *delta > 0);
    let negative = deltas.iter().all(|delta| *delta < 0);
    let direction = match (positive, negative) {
        (true, false) => 1,
        (false, true) => -1,
        _ => return None,
    };
    // A constant step is the strong model: preserve its full modular value
    // instead of rejecting UU/WebRTC-style wide allocation strides.  For a
    // noisy run, retain the old conservative one-port successor behavior and
    // require every observed delta to be small.
    let step = if let Some(exact_step) = exact_step {
        exact_step
    } else {
        if !deltas.iter().all(|delta| delta.abs() <= 8) {
            return None;
        }
        direction
    };

    let observed_ports = mapped.iter().map(SocketAddr::port).collect::<HashSet<_>>();
    let edge_port = if exact_step.is_some() {
        // The last observation is the edge even when the modular sequence
        // crossed 65535; max/min would choose the wrong side of the circle.
        mapped.last()?.port()
    } else if direction > 0 {
        *observed_ports.iter().max()?
    } else {
        *observed_ports.iter().min()?
    };

    let mut endpoints = Vec::with_capacity(MAX_PREDICTED_REFLEXIVE_CANDIDATES);
    for index in 1..=MAX_PREDICTED_REFLEXIVE_CANDIDATES {
        let port = modular_port_add(edge_port, step * index as i32);
        if port == 0 || observed_ports.contains(&port) {
            continue;
        }
        endpoints.push(SocketAddr::new(first_ip, port).to_string());
    }

    (!endpoints.is_empty()).then_some(endpoints)
}

/// Return the signed shortest distance from one UDP port to the next on the
/// 16-bit port ring.  Keeping this explicit avoids treating 65535 -> 0 as a
/// huge random jump and makes wrap-around predictions testable.
fn modular_port_delta(previous: u16, next: u16) -> i32 {
    let raw = i32::from(next) - i32::from(previous);
    if raw > 32_767 {
        raw - 65_536
    } else if raw < -32_768 {
        raw + 65_536
    } else {
        raw
    }
}

fn modular_port_add(base: u16, delta: i32) -> u16 {
    (i64::from(base) + i64::from(delta)).rem_euclid(65_536) as u16
}

fn add_predicted_reflexive_candidates(candidates: &mut Vec<IceCandidate>, profile: &NatProfile) {
    for endpoint in &profile.predicted_endpoints {
        let Ok(addr) = endpoint.parse::<SocketAddr>() else {
            continue;
        };
        candidates.push(IceCandidate {
            candidate_type: CandidateType::ServerReflexive,
            endpoint: crate::Endpoint::new(&addr.ip().to_string(), addr.port()),
            priority: compute_priority(CandidateType::ServerReflexive).saturating_sub(1),
            source: crate::CandidateSource::Predicted,
        });
    }
}
