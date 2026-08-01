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
        MappingBehavior::OpenInternet => FilteringBehavior::EndpointIndependent,
        // A stable public mapping does not prove that the gateway accepts
        // unsolicited UDP from a peer.  Many home routers are EIM + APDF:
        // stable port, strict filtering.  Only the active CHANGE-REQUEST
        // probe may upgrade this to endpoint/address-dependent filtering.
        MappingBehavior::EndpointIndependent => FilteringBehavior::Unknown,
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
    if deltas.iter().all(|delta| *delta == first) {
        return Some(first);
    }

    // WebRTC/UU classifies this case as linear symmetric even when one STUN
    // query slips between two adjacent allocations. Treat a same-direction,
    // tiny-delta run as predictable and use the median step.
    if deltas
        .iter()
        .all(|delta| *delta != 0 && (-8..=8).contains(delta))
    {
        let positive = deltas.iter().all(|delta| *delta > 0);
        let negative = deltas.iter().all(|delta| *delta < 0);
        if positive || negative {
            let mut sorted = deltas;
            sorted.sort_unstable();
            return sorted.get(sorted.len() / 2).copied();
        }
    }

    None
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}
