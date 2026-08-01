pub(super) async fn maybe_add_port_mapping_udp_candidate(
    udp_local_addr: Option<SocketAddr>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
    runtime: Arc<RwLock<GatewayMappingRuntime>>,
    diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
) {
    let Some(local_addr) = port_mapping_local_addr(udp_local_addr, candidates, candidate_sources)
    else {
        let mut diagnostics = diagnostics.write().await;
        diagnostics.local_endpoint = None;
        diagnostics.upnp.status = "unavailable".to_string();
        diagnostics.upnp.last_error = Some("no LAN IPv4 UDP endpoint available".to_string());
        debug!("Skipping port-mapping UDP candidate because no LAN IPv4 local address was found");
        return;
    };

    let now = Instant::now();
    {
        let runtime = runtime.read().await;
        if runtime.retain_candidate(local_addr, now) {
            if let (Some(endpoint), Some(source)) = (
                runtime.candidate_endpoint.as_ref(),
                runtime.candidate_source,
            ) {
                if !candidates.contains(endpoint) {
                    candidates.insert(0, endpoint.clone());
                    candidate_sources.insert(endpoint.clone(), source.to_string());
                }
                let snapshot = runtime.snapshot(
                    true,
                    PORT_MAPPING_LEASE_SECS,
                    diagnostics.read().await.clone(),
                );
                *diagnostics.write().await = snapshot;
                return;
            }
        }
        if !runtime.needs_discovery(local_addr, now) {
            let snapshot = runtime.snapshot(
                true,
                PORT_MAPPING_LEASE_SECS,
                diagnostics.read().await.clone(),
            );
            *diagnostics.write().await = snapshot;
            return;
        }
    }

    match discover_port_mapping_udp_candidate(local_addr).await {
        GatewayMappingDiscovery {
            candidate: Some(candidate),
            upnp,
            pcp,
            nat_pmp,
        } => {
            let mut diagnostics_guard = diagnostics.write().await;
            record_method_result(&mut diagnostics_guard.upnp, upnp);
            if let Some(result) = pcp {
                record_method_result(&mut diagnostics_guard.pcp, result);
            }
            if let Some(result) = nat_pmp {
                record_method_result(&mut diagnostics_guard.nat_pmp, result);
            }
            if !candidates.contains(&candidate.endpoint) {
                info!(
                    "{} mapped UDP {local_addr} as {}",
                    candidate.source, candidate.endpoint
                );
                // A gateway-created mapping is usually more useful than another
                // host/predicted address and must survive the signaling cap.
                candidates.insert(0, candidate.endpoint.clone());
            }
            candidate_sources.insert(candidate.endpoint.clone(), candidate.source.to_string());
            drop(diagnostics_guard);
            {
                let mut runtime = runtime.write().await;
                runtime.record_success(
                    local_addr,
                    candidate.endpoint.clone(),
                    candidate.source,
                    Duration::from_secs(PORT_MAPPING_LEASE_SECS.into()),
                );
                let snapshot = runtime.snapshot(
                    true,
                    PORT_MAPPING_LEASE_SECS,
                    diagnostics.read().await.clone(),
                );
                *diagnostics.write().await = snapshot;
            }
        }
        GatewayMappingDiscovery {
            candidate: None,
            upnp,
            pcp,
            nat_pmp,
        } => {
            let mut diagnostics_guard = diagnostics.write().await;
            record_method_result(&mut diagnostics_guard.upnp, upnp);
            if let Some(result) = pcp {
                record_method_result(&mut diagnostics_guard.pcp, result);
            }
            if let Some(result) = nat_pmp {
                record_method_result(&mut diagnostics_guard.nat_pmp, result);
            }
            drop(diagnostics_guard);
            let mut runtime = runtime.write().await;
            runtime.record_failure(local_addr, PORT_MAPPING_FAILURE_RETRY);
            let snapshot = runtime.snapshot(
                true,
                PORT_MAPPING_LEASE_SECS,
                diagnostics.read().await.clone(),
            );
            *diagnostics.write().await = snapshot;
            debug!("No UPnP/PCP/NAT-PMP UDP mapping candidate discovered for {local_addr}");
        }
    }
}
