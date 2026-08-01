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
    let stats = PeerManagerStats::from_diagnostics(&peers);

    DiagnosticsSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        process_id: std::process::id(),
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation: context.peers.current_network_generation().await,
        protocol: ProtocolDiagnostics::current(),
        mtu: MtuDiagnostics::from_runtime(
            context.config.network.mtu,
            relay_connected || stats.relay_connections > 0,
        ),
        udp_local_addr,
        udp_socket_count,
        udp_socket_pool_active,
        udp_socket_pool,
        local_candidates: context.local_candidates.read().await.clone(),
        nat_profile: context.nat_profile.read().await.clone(),
        gateway_mapping: context.gateway_mapping.read().await.clone(),
        relay_servers: context.config.relay.servers.clone(),
        relay_connected,
        relay_selection,
        traversal_history: context.peers.traversal_history_diagnostics().await,
        peers,
        stats,
        health: health_snap,
    }
}
