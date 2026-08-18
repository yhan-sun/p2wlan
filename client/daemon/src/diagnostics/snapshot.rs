async fn build_snapshot(context: DiagnosticsContext) -> DiagnosticsSnapshot {
    let udp = context.udp_transport.read().await.clone();
    let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
    let udp_local_addr = udp_local_endpoint.map(|addr| addr.to_string());
    let udp_socket_count = udp.as_ref().map(UdpTransport::socket_count).unwrap_or(0);
    let udp_socket_pool_active = udp.as_ref().is_some_and(UdpTransport::socket_pool_active);
    let udp_socket_pool = match udp.as_ref() {
        Some(udp) => udp.socket_pool_diagnostics().await,
        None => Vec::new(),
    };
    let relay_connected = context.relay_transport.read().await.is_some();
    let direct_retry_after = DIRECT_RETRY_BASE_INTERVAL;

    let tasks = context.task_manager.task_statuses().await;
    let health_snap = context.health.snapshot(&tasks).await;
    let mut relay_selection = context.relay_selection.read().await.clone();
    relay_selection.refresh_runtime_ages();

    let peers = context
        .peers
        .diagnostics_with_path_selection(
            context.config.relay.prefer_direct,
            relay_connected,
            direct_retry_after,
            udp_local_endpoint,
        )
        .await;
    let mut stats = PeerManagerStats::from_diagnostics(&peers);
    let outbound_loss = context.peers.outbound_loss_stats().await;
    stats.outbound_drops = outbound_loss.drops;
    stats.outbound_send_failures = outbound_loss.send_failures;
    stats.outbound_loss_events = outbound_loss.events;
    let candidate_snapshot = context.candidate_snapshot.read().await.clone();
    let (local_candidates, candidate_snapshot_version, candidate_snapshot_hash) = candidate_snapshot
        .map(|snapshot| (snapshot.candidates, Some(snapshot.version), Some(snapshot.hash)))
        .unwrap_or_else(|| (Vec::new(), None, None));

    DiagnosticsSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        process_id: std::process::id(),
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation: context.peers.current_network_generation_sync(),
        uptime_ms: context.timeline.uptime_ms(),
        revision: context.status_events.current_seq(),
        ready_phase: derive_ready_phase(
            &health_snap,
            relay_connected,
            &peers,
            &context.config.network.virtual_ip,
        )
        .to_string(),
        protocol: ProtocolDiagnostics::current(),
        mtu: MtuDiagnostics::from_runtime(
            context.config.network.mtu,
            relay_connected || stats.relay_connections > 0,
        ),
        udp_local_addr,
        udp_socket_count,
        udp_socket_pool_active,
        udp_socket_pool,
        local_candidates,
        candidate_snapshot_version,
        candidate_snapshot_hash,
        nat_profile: context.nat_profile.read().await.clone(),
        gateway_mapping: context.gateway_mapping.read().await.clone(),
        relay_servers: context.config.relay.servers.clone(),
        relay_connected,
        relay_selection,
        control_proxy_mode: context.config.control.proxy_mode.as_label().to_string(),
        control_proxy_consults_env: crate::control::proxy_consults_environment(
            context.config.control.proxy_mode,
        ),
        connection_timeline: context.timeline.snapshot(),
        traversal_history: context.peers.traversal_history_diagnostics().await,
        peers,
        stats,
        health: health_snap,
    }
}

async fn build_peer_scoped_snapshot(
    context: DiagnosticsContext,
    peer_id: &str,
) -> PeerScopedDiagnosticsSnapshot {
    let relay_connected = context.relay_transport.read().await.is_some();
    let udp_local_endpoint = context
        .udp_transport
        .read()
        .await
        .as_ref()
        .and_then(|udp| udp.local_addr().ok());
    let peer_snapshot = context
        .peers
        .diagnostic_with_path_selection(
            peer_id,
            context.config.relay.prefer_direct,
            relay_connected,
            DIRECT_RETRY_BASE_INTERVAL,
            udp_local_endpoint,
        )
        .await;
    let (network_generation, peer) = peer_snapshot
        .map(|(generation, peer)| (generation, Some(peer)))
        .unwrap_or_else(|| (context.peers.current_network_generation_sync(), None));
    let network_peer_count = context.peers.active_connection_count().await;
    let captured_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default();
    PeerScopedDiagnosticsSnapshot {
        node_id: context.config.node.node_id.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation,
        network_peer_count,
        captured_at_ms,
        peer,
    }
}

async fn build_runtime_snapshot(context: DiagnosticsContext) -> RuntimeDiagnosticsSnapshot {
    RuntimeDiagnosticsSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        process_id: std::process::id(),
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation: context.peers.current_network_generation_sync(),
        uptime_ms: context.timeline.uptime_ms(),
        relay_connected: context.relay_transport.read().await.is_some(),
    }
}
