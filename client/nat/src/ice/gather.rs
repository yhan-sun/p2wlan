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
                source: crate::CandidateSource::Host,
            };
            debug!("Host candidate: {}", candidate.endpoint.to_string());
            candidates.push(candidate);
        }
    }

    // 2. Server-reflexive candidates
    if config.gather_srflx && !config.stun_servers.is_empty() {
        let stun_client = StunClient::with_timeout(config.stun_timeout);

        for &server in &config.stun_servers {
            if server.is_ipv4() != local_addr.is_ipv4() {
                debug!(
                    "Skipping STUN server {} because it does not match local socket family {}",
                    server, local_addr
                );
                continue;
            }
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
                            source: crate::CandidateSource::StunObserved,
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

    let mut nat_profile = build_nat_profile(local_addr, observations);
    add_predicted_reflexive_candidates(&mut candidates, &nat_profile);
    apply_active_behavior_probes(socket, config, &mut nat_profile).await;

    // 3. Sort by priority (highest first)
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));

    // Deduplicate by (type, endpoint) — same address with different types is valid
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert((c.candidate_type, c.endpoint.to_string())));

    info!(
        "Gathered {} ICE candidates (STUN success {}/{}, mapping={:?}, filtering={:?}, hairpin={:?}, lifetime={:?}, predicted={})",
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
        nat_profile.mapping_lifetime,
        nat_profile.predicted_endpoints.len()
    );
    Ok(CandidateGatherReport {
        candidates,
        nat_profile,
    })
}

/// Build a candidate report from STUN observations already collected by an
/// external socket dispatcher. This is used when a live UDP data socket has a
/// single receive owner and STUN responses cannot safely call `recv_from`
/// independently.
pub fn candidate_report_from_observations(
    local_addr: SocketAddr,
    gather_host: bool,
    observations: Vec<StunObservation>,
) -> CandidateGatherReport {
    let mut candidates = Vec::new();
    if gather_host {
        for ip in gather_local_addresses() {
            candidates.push(IceCandidate {
                candidate_type: CandidateType::Host,
                endpoint: crate::Endpoint::new(&ip.to_string(), local_addr.port()),
                priority: compute_priority(CandidateType::Host),
                source: crate::CandidateSource::Host,
            });
        }
    }
    for observation in &observations {
        let Some(reflexive) = observation
            .mapped_address
            .as_deref()
            .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok())
        else {
            continue;
        };
        candidates.push(IceCandidate {
            candidate_type: CandidateType::ServerReflexive,
            endpoint: crate::Endpoint::new(&reflexive.ip().to_string(), reflexive.port()),
            priority: compute_priority(CandidateType::ServerReflexive),
            source: crate::CandidateSource::StunObserved,
        });
    }

    let nat_profile = build_nat_profile(local_addr, observations);
    add_predicted_reflexive_candidates(&mut candidates, &nat_profile);
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.priority));
    let mut seen = HashSet::new();
    candidates.retain(|candidate| {
        seen.insert((candidate.candidate_type, candidate.endpoint.to_string()))
    });
    CandidateGatherReport {
        candidates,
        nat_profile,
    }
}
