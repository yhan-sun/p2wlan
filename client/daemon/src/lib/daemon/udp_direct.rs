struct UdpDirectTaskContext {
    udp_bind: SocketAddr,
    peers: Arc<PeerManager>,
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    local_network_identity: Arc<RwLock<Vec<String>>>,
    candidate_refresh_lock: Arc<Mutex<()>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    direct_validation_transport: WireGuardTransport,
    direct_validation_local_ip: String,
    udp_inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    local_node_id: String,
    stun_servers: Vec<SocketAddr>,
    stun_timeout: Duration,
    udp_advertise: Option<String>,
    upnp_enabled: bool,
    socket_pool_enabled: bool,
    socket_pool_size: usize,
    keepalive_interval: Duration,
    punch_deduplicator: PunchAttemptDeduplicator,
    udp_punch_interval: Duration,
    udp_punch_attempts: u32,
    /// Daemon incarnation epoch embedded in fresh-prediction labels.
    boot_epoch_ms: u64,
}

async fn run_udp_direct_task(ctx: UdpDirectTaskContext) -> Result<()> {
    let UdpDirectTaskContext {
        udp_bind,
        peers,
        control,
        local_candidates,
        local_candidate_sources: udp_local_candidate_sources,
        local_network_identity,
        candidate_refresh_lock,
        nat_profile,
        gateway_mapping_runtime,
        gateway_mapping_diagnostics,
        udp_transport,
        direct_validation_transport,
        direct_validation_local_ip,
        udp_inbound_tx,
        local_node_id,
        stun_servers,
        stun_timeout,
        udp_advertise,
        upnp_enabled,
        socket_pool_enabled,
        socket_pool_size,
        keepalive_interval,
        punch_deduplicator,
        udp_punch_interval,
        udp_punch_attempts,
        boot_epoch_ms,
    } = ctx;

    match UdpTransport::bind(udp_bind, peers.clone()).await {
        Ok(udp) => {
            let initial_refresh_guard = candidate_refresh_lock.lock().await;
            let udp = if socket_pool_enabled {
                match udp.clone().with_socket_pool(socket_pool_size).await {
                    Ok(udp) => udp,
                    Err(error) => {
                        warn!(
                            "Failed to create experimental UDP socket pool; using the primary socket only: {error}"
                        );
                        udp
                    }
                }
            } else {
                udp
            };
            let (peer_reflexive_tx, peer_reflexive_rx) = mpsc::channel(128);
            let udp = udp
                .with_local_node_id(local_node_id.clone())
                .with_wireguard_transport(direct_validation_transport.clone())
                .with_inbound_channel(udp_inbound_tx.clone())
                .with_peer_reflexive_observer(peer_reflexive_tx);
            tokio::spawn(run_peer_reflexive_signal_loop(
                peer_reflexive_rx,
                control.clone(),
                udp.clone(),
                peers.clone(),
                direct_validation_transport,
                direct_validation_local_ip,
            ));
            *udp_transport.write().await = Some(udp.clone());

            let (mut candidate_endpoints, mut candidate_sources) =
                match udp.gather_candidate_report(stun_servers.clone(), stun_timeout).await
                {
                    Ok(report) => {
                        let (endpoints, sources) = candidate_endpoints_from_report(&report);
                        info!(
                            "Local NAT profile: mapping={:?} public={:?} stun_success={}/{} confidence={}",
                            report.nat_profile.mapping_behavior,
                            report.nat_profile.public_endpoint,
                            report
                                .nat_profile
                                .observations
                                .iter()
                                .filter(|observation| observation.mapped_address.is_some())
                                .count(),
                            report.nat_profile.observations.len(),
                            report.nat_profile.confidence
                        );
                        peers.update_nat_profile(report.nat_profile.clone()).await;
                        let pool_eligible = socket_pool_enabled
                            && report.nat_profile.mapping_behavior
                                == MappingBehavior::AddressOrPortDependent
                            && !report.nat_profile.udp_blocked;
                        udp.set_socket_pool_active(pool_eligible);
                        if udp.socket_count() > 1 {
                            info!(
                                "Experimental UDP socket pool: sockets={} active={} reason={}",
                                udp.socket_count(),
                                udp.socket_pool_active(),
                                if pool_eligible {
                                    "address/port-dependent mapping"
                                } else {
                                    "NAT profile did not qualify"
                                }
                            );
                        }
                        *nat_profile.write().await = Some(report.nat_profile);
                        (endpoints, sources)
                    }
                    Err(err) => {
                        warn!("Failed to gather UDP candidates: {err}");
                        (Vec::new(), HashMap::new())
                    }
                };

            match udp.local_addr() {
                Ok(addr) => {
                    if let Some(endpoint) = advertised_udp_endpoint(
                        addr,
                        udp_advertise.as_deref(),
                        &candidate_endpoints,
                    ) {
                        if !candidate_endpoints.contains(&endpoint) {
                            candidate_endpoints.insert(0, endpoint.clone());
                        }
                        candidate_sources.entry(endpoint.clone()).or_insert_with(|| {
                            if udp_advertise.as_deref().is_some_and(|configured| {
                                !configured.trim().is_empty() && configured.trim() == endpoint
                            }) {
                                "manual".to_string()
                            } else {
                                "host".to_string()
                            }
                        });
                        info!(
                            "UDP transport listening on {addr}; advertising {endpoint}"
                        );
                    } else {
                        warn!(
                            "UDP transport listening on {addr}; no reachable endpoint was discovered or configured."
                        );
                    }
                }
                Err(err) => {
                    warn!("UDP transport bound but local addr unavailable: {err}")
                }
            }

            if upnp_enabled {
                maybe_add_port_mapping_udp_candidate(
                    udp.local_addr().ok(),
                    &mut candidate_endpoints,
                    &mut candidate_sources,
                    gateway_mapping_runtime.clone(),
                    gateway_mapping_diagnostics.clone(),
                )
                .await;
            }
            let initial_network_identity = prepare_signal_candidates_and_network_identity(
                &[],
                &HashMap::new(),
                &mut candidate_endpoints,
                &mut candidate_sources,
            );
            *local_network_identity.write().await = initial_network_identity;
            let mut published_endpoint = None;
            if let Some(endpoint) = control_udp_endpoint_from_candidates(
                &candidate_endpoints,
                &candidate_sources,
            ) {
                if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
                    warn!("Failed to queue UDP endpoint update '{endpoint}': {err}");
                } else {
                    published_endpoint = Some(endpoint);
                }
            }

            info!(
                "Prepared {} UDP candidate endpoints for signaling",
                candidate_endpoints.len()
            );
            *local_candidates.write().await = candidate_endpoints.clone();
            *udp_local_candidate_sources.write().await = candidate_sources.clone();
            drop(initial_refresh_guard);

            publish_local_candidates_to_known_peers(
                &control,
                peers.clone(),
                udp.clone(),
                punch_deduplicator.clone(),
                &candidate_endpoints,
                &candidate_sources,
                udp_punch_interval,
                udp_punch_attempts,
                "initial UDP candidates ready",
                Some(HolePunchSignalContext {
                    control: control.clone(),
                    local_candidates: local_candidates.clone(),
                    local_candidate_sources: udp_local_candidate_sources.clone(),
                    stun_servers: stun_servers.clone(),
                    stun_timeout,
                    boot_epoch_ms,
                }),
            )
            .await;

            if keepalive_interval.is_zero() {
                let refresh_udp = udp.clone();
                tokio::select! {
                    result = udp.run_inbound(udp_inbound_tx) => result,
                    _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                        udp: refresh_udp,
                        stun_servers,
                        stun_timeout,
                        udp_advertise,
                        upnp_enabled,
                        published_endpoint,
                        local_candidates,
                        local_candidate_sources: udp_local_candidate_sources.clone(),
                        local_network_identity: local_network_identity.clone(),
                        candidate_refresh_lock: candidate_refresh_lock.clone(),
                        nat_profile,
                        gateway_mapping_runtime,
                        gateway_mapping_diagnostics,
                        punch_deduplicator,
                        control,
                        peers: peers.clone(),
                        probe_interval: udp_punch_interval,
                        punch_attempts: udp_punch_attempts,
                        boot_epoch_ms,
                    }) => Ok(()),
                }
            } else {
                let keepalive_udp = udp.clone();
                let refresh_udp = udp.clone();
                tokio::select! {
                    result = udp.run_inbound(udp_inbound_tx) => result,
                    _ = keepalive_udp.run_keepalives(keepalive_interval) => Ok(()),
                    _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                        udp: refresh_udp,
                        stun_servers,
                        stun_timeout,
                        udp_advertise,
                        upnp_enabled,
                        published_endpoint,
                        local_candidates,
                        local_candidate_sources: udp_local_candidate_sources.clone(),
                        local_network_identity: local_network_identity.clone(),
                        candidate_refresh_lock: candidate_refresh_lock.clone(),
                        nat_profile,
                        gateway_mapping_runtime,
                        gateway_mapping_diagnostics,
                        punch_deduplicator,
                        control,
                        peers: peers.clone(),
                        probe_interval: udp_punch_interval,
                        punch_attempts: udp_punch_attempts,
                        boot_epoch_ms,
                    }) => Ok(()),
                }
            }
        }
        Err(err) => {
            warn!("UDP transport unavailable ({err}); direct UDP disabled");
            Ok(())
        }
    }

}
