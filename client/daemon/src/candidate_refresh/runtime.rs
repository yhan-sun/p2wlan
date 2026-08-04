pub(super) struct UdpCandidateRefreshContext {
    pub(super) udp: UdpTransport,
    pub(super) stun_servers: Vec<SocketAddr>,
    pub(super) stun_timeout: Duration,
    pub(super) udp_advertise: Option<String>,
    pub(super) upnp_enabled: bool,
    pub(super) published_endpoint: Option<String>,
    pub(super) local_candidates: Arc<RwLock<Vec<String>>>,
    pub(super) local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    pub(super) local_network_identity: Arc<RwLock<Vec<String>>>,
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
        local_network_identity,
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
        let next_network_identity = stable_network_candidate_signature(
            &candidates,
            &candidate_sources,
        );
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
        let previous_network_identity = local_network_identity.read().await.clone();
        let should_advance_generation = !previous_network_identity.is_empty()
            && previous_network_identity != next_network_identity;

        let change_reason = candidate_set_change_reason(
            &previous_candidates,
            &candidates,
            &previous_candidate_sources,
            &candidate_sources,
        );
        let old_hash = candidate_set_hash(&previous_candidates, &previous_candidate_sources);
        let new_hash = candidate_set_hash(&candidates, &candidate_sources);
        let old_candidate_count = previous_candidates.len();
        let new_candidate_count = candidates.len();
        let real_change = change_reason != "no_change" && change_reason != "order_only";
        if !real_change {
            if profile_changed {
                debug!(
                    "UDP NAT profile changed without advertised candidate endpoint changes: mapping={:?} public={:?}",
                    report.nat_profile.mapping_behavior,
                    report.nat_profile.public_endpoint
                );
            }
            debug!(
                "UDP candidate refresh kept the existing {} candidates: changed_reason={change_reason} old_hash={old_hash} new_hash={new_hash} old_candidate_count={old_candidate_count} new_candidate_count={new_candidate_count}",
                candidates.len()
            );
            continue;
        }

        {
            let mut current = local_candidates.write().await;
            *current = candidates.clone();
            *local_candidate_sources.write().await = candidate_sources.clone();
            *local_network_identity.write().await = next_network_identity.clone();
        }

        info!(
            "UDP candidates changed after network update; refreshed {} candidates (mapping={:?}, public={:?}, old_hash={old_hash}, new_hash={new_hash}, changed_reason={change_reason}, old_candidate_count={old_candidate_count}, new_candidate_count={new_candidate_count})",
            candidates.len(),
            report.nat_profile.mapping_behavior,
            report.nat_profile.public_endpoint
        );
        debug!(
            "UDP candidate set diff: changed_reason={change_reason} old_candidates={previous_candidates:?} new_candidates={candidates:?}"
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
