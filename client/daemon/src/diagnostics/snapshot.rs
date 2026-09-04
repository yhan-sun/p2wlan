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

    let stable_peers = capture_stable_peer_snapshot(
        &context,
        relay_connected,
        direct_retry_after,
        udp_local_endpoint,
    )
    .await;
    let cached_peer_count = stable_peers.cached_peer_count;
    let peers = stable_peers.peers;
    let mut stats = PeerManagerStats::from_diagnostics(&peers);
    debug_assert_eq!(stats.total_peers, cached_peer_count);
    let outbound_loss = context.peers.outbound_loss_stats().await;
    stats.outbound_drops = outbound_loss.drops;
    stats.outbound_send_failures = outbound_loss.send_failures;
    stats.outbound_loss_events = outbound_loss.events;
    stats.path_observability.active_tasks = health_snap
        .critical_tasks
        .iter()
        .filter(|task| task.running && !task.finished)
        .count() as u64;
    stats.path_observability.active_sockets = udp_socket_count as u64;
    stats.path_observability.control_reconnects = context.timeline.control_reconnects();
    let connection_timeline = context.timeline.snapshot();
    let candidate_snapshot = context.candidate_snapshot.read().await.clone();
    let (local_candidates, candidate_snapshot_version, candidate_snapshot_hash) =
        candidate_snapshot
            .map(|snapshot| {
                (
                    snapshot.candidates,
                    Some(snapshot.version),
                    Some(snapshot.hash),
                )
            })
            .unwrap_or_else(|| (Vec::new(), None, None));
    // This generation was fenced by the same double-read as `peers`. Reading
    // it again here could pair old peer data with a newly advanced generation.
    let network_generation = stable_peers.network_generation;
    let nat_profile = context.nat_profile.read().await.clone();
    let nat_capabilities = nat_profile.as_ref().map(|profile| {
        NatCapabilities::from_profile(profile)
            .with_profile_generation(context.peers.current_local_profile_generation_sync())
    });
    let gateway_mapping = context.gateway_mapping.read().await.clone();
    let traversal_history = context.peers.traversal_history_diagnostics().await;
    let uptime_ms = context.timeline.uptime_ms();
    let peer_snapshot_age_ms = stable_peers
        .captured_at
        .elapsed()
        .as_millis()
        .min(u64::MAX as u128) as u64;

    DiagnosticsSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        process_id: std::process::id(),
        runtime_incarnation: context.runtime_incarnation,
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation,
        network_hint: NetworkHint::Unknown,
        uptime_ms,
        revision: stable_peers.capture_revision,
        captured_revision: stable_peers.capture_revision,
        captured_at_ms: stable_peers.captured_at_ms,
        peer_snapshot_stale: stable_peers.stale,
        peer_snapshot_age_ms,
        peer_snapshot_shape: stable_peers.shape,
        ready_phase: derive_ready_phase(
            &health_snap,
            relay_connected,
            &peers,
            &context.config.network.virtual_ip,
            context.config.network.manual,
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
        nat_profile,
        nat_capabilities,
        gateway_mapping,
        relay_servers: context.config.relay.servers.clone(),
        relay_connected,
        relay_selection,
        control_proxy_mode: context.config.control.proxy_mode.as_label().to_string(),
        control_proxy_consults_env: crate::control::proxy_consults_environment(
            context.config.control.proxy_mode,
        ),
        connection_timeline,
        traversal_history,
        peers,
        stats,
        health: health_snap,
    }
}

struct StablePeerSnapshot {
    peers: Vec<PeerDiagnostics>,
    cached_peer_count: usize,
    network_generation: u64,
    capture_revision: u64,
    captured_at_ms: u64,
    captured_at: std::time::Instant,
    shape: String,
    stale: bool,
}

/// Build a peer array using only non-queuing connection-map reads.  A fully
/// validated capture is preferred; when Tokio's writer-preferred `RwLock`
/// rejects a reader (an active or queued writer can do so), return the last
/// internally consistent capture as explicitly stale instead of putting
/// `/status` behind the same writer and eventually returning HTTP 503.
async fn capture_stable_peer_snapshot(
    context: &DiagnosticsContext,
    relay_connected: bool,
    direct_retry_after: Duration,
    udp_local_endpoint: Option<std::net::SocketAddr>,
) -> StablePeerSnapshot {
    const MAX_CAPTURE_ATTEMPTS: usize = 8;

    for attempt in 0..MAX_CAPTURE_ATTEMPTS {
        let revision_before = context.status_events.current_seq();
        let generation_before = context.peers.current_network_generation_sync();
        let Some(connections_before) = context.peers.try_all_connections() else {
            emit_status_connection_map_contention(
                context,
                generation_before,
                "initial_read",
                attempt,
            );
            return cached_or_best_effort_peer_snapshot(
                context,
                relay_connected,
                direct_retry_after,
                udp_local_endpoint,
            )
            .await;
        };
        let mut node_ids: Vec<_> = connections_before
            .into_iter()
            .map(|connection| connection.node_id)
            .collect();
        node_ids.sort();

        let mut peers = Vec::with_capacity(node_ids.len());
        let mut retry = false;
        for node_id in &node_ids {
            match context
                .peers
                .diagnostic_with_path_selection(
                    node_id,
                    context.config.relay.prefer_direct,
                    relay_connected,
                    direct_retry_after,
                    udp_local_endpoint,
                )
                .await
            {
                Some((generation, peer)) if generation == generation_before => peers.push(peer),
                _ => {
                    retry = true;
                    break;
                }
            }
        }
        if retry {
            emit_status_connection_map_contention(
                context,
                generation_before,
                "peer_diagnostic_read",
                attempt,
            );
            tokio::task::yield_now().await;
            continue;
        }
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));

        let Some(live_after) = context.peers.try_all_connections() else {
            emit_status_connection_map_contention(
                context,
                generation_before,
                "validation_read",
                attempt,
            );
            return cached_or_best_effort_peer_snapshot(
                context,
                relay_connected,
                direct_retry_after,
                udp_local_endpoint,
            )
            .await;
        };
        let revision_after = context.status_events.current_seq();
        let generation_after = context.peers.current_network_generation_sync();
        if revision_before != revision_after
            || generation_before != generation_after
            || !peer_snapshot_core_matches(&peers, &live_after)
        {
            tokio::task::yield_now().await;
            continue;
        }

        let captured_at_ms = context.timeline.uptime_ms();
        let shape = peer_snapshot_shape(&peers);
        let cached = CachedPeerSnapshot {
            peers: peers.clone(),
            network_generation: generation_after,
            capture_revision: revision_after,
            captured_at: std::time::Instant::now(),
            captured_at_ms,
            shape: shape.clone(),
        };
        let capture_revision = cached.capture_revision;
        let captured_at_ms = cached.captured_at_ms;
        let captured_at = cached.captured_at;
        let shape = cached.shape.clone();
        let cached_peer_count = cached.peers.len();
        *context
            .peer_snapshot_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(cached);
        return StablePeerSnapshot {
            peers,
            cached_peer_count,
            network_generation: generation_after,
            capture_revision,
            captured_at_ms,
            captured_at,
            shape,
            stale: false,
        };
    }

    let generation = context.peers.current_network_generation_sync();
    emit_status_connection_map_contention(
        context,
        generation,
        "coherency_retry_exhausted",
        MAX_CAPTURE_ATTEMPTS,
    );
    cached_or_best_effort_peer_snapshot(
        context,
        relay_connected,
        direct_retry_after,
        udp_local_endpoint,
    )
    .await
}

fn emit_status_connection_map_contention(
    context: &DiagnosticsContext,
    generation: u64,
    phase: &'static str,
    attempt: usize,
) {
    context.timeline.emit_first_scoped(
        &format!("status:{generation}"),
        "status_connection_map_read_contended",
        None,
        Some("writer_active_or_fairly_queued"),
        Some(format!(
            "generation={generation} phase={phase} attempt={attempt} wait_us=0 nonblocking_read=true fair_rwlock_queued_writer_possible=true fallback=validated_cache"
        )),
    );
}

async fn cached_or_best_effort_peer_snapshot(
    context: &DiagnosticsContext,
    relay_connected: bool,
    direct_retry_after: Duration,
    udp_local_endpoint: Option<std::net::SocketAddr>,
) -> StablePeerSnapshot {
    let cached = context
        .peer_snapshot_cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    if let Some(cached) = cached {
        return StablePeerSnapshot {
            cached_peer_count: cached.peers.len(),
            peers: cached.peers,
            network_generation: cached.network_generation,
            capture_revision: cached.capture_revision,
            captured_at_ms: cached.captured_at_ms,
            captured_at: cached.captured_at,
            shape: cached.shape,
            stale: true,
        };
    }

    // The first status request can race startup before a validated capture
    // exists.  PeerManager's diagnostics path is itself non-queuing and uses
    // its bounded last-good cache; an empty array is preferable to blocking
    // the health endpoint, and is explicitly marked stale.
    let peers = context
        .peers
        .diagnostics_with_path_selection(
            context.config.relay.prefer_direct,
            relay_connected,
            direct_retry_after,
            udp_local_endpoint,
        )
        .await;
    let captured_at = std::time::Instant::now();
    let captured_at_ms = context.timeline.uptime_ms();
    let shape = peer_snapshot_shape(&peers);
    StablePeerSnapshot {
        cached_peer_count: peers.len(),
        peers,
        network_generation: context.peers.current_network_generation_sync(),
        capture_revision: context.status_events.current_seq(),
        captured_at_ms,
        captured_at,
        shape,
        stale: true,
    }
}

fn peer_snapshot_shape(peers: &[PeerDiagnostics]) -> String {
    use sha2::{Digest, Sha256};

    let encoded = serde_json::to_vec(peers).unwrap_or_default();
    format!("v1:{}", hex::encode(Sha256::digest(encoded)))
}

/// Compare every peer field that can change the rendered liveness/path/latency
/// result. Age counters are deliberately excluded: they advance between two
/// otherwise atomic reads and do not represent a state transition.
fn peer_snapshot_core_matches(
    peers: &[PeerDiagnostics],
    connections: &[crate::peer::PeerConnection],
) -> bool {
    use std::hash::{Hash, Hasher};

    fn hash_diagnostics(peers: &[PeerDiagnostics]) -> u64 {
        let mut sorted: Vec<_> = peers.iter().collect();
        sorted.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for peer in sorted {
            peer.node_id.hash(&mut hasher);
            peer.device_name.hash(&mut hasher);
            peer.app_version.hash(&mut hasher);
            peer.virtual_ip.hash(&mut hasher);
            peer.endpoint.hash(&mut hasher);
            peer.nat_type.hash(&mut hasher);
            peer.online.hash(&mut hasher);
            peer.last_seen.hash(&mut hasher);
            peer.remote_relay_latency_ms.hash(&mut hasher);
            format!("{:?}", peer.state).hash(&mut hasher);
            peer.probe_session_id.hash(&mut hasher);
            peer.relay_server.hash(&mut hasher);
            peer.candidates.hash(&mut hasher);
            peer.direct.latency_ms.hash(&mut hasher);
            peer.direct.rtt_ewma_ms.hash(&mut hasher);
            peer.direct.jitter_ms.hash(&mut hasher);
            peer.direct.consecutive_failures.hash(&mut hasher);
            peer.direct.last_error.hash(&mut hasher);
            peer.direct.last_error_code.hash(&mut hasher);
            peer.direct.success_count.hash(&mut hasher);
            peer.direct.failure_count.hash(&mut hasher);
            peer.relay.latency_ms.hash(&mut hasher);
            peer.relay.rtt_ewma_ms.hash(&mut hasher);
            peer.relay.jitter_ms.hash(&mut hasher);
            peer.relay.consecutive_failures.hash(&mut hasher);
            peer.relay.last_error.hash(&mut hasher);
            peer.relay.last_error_code.hash(&mut hasher);
            peer.relay.success_count.hash(&mut hasher);
            peer.relay.failure_count.hash(&mut hasher);
            peer.direct_generation.hash(&mut hasher);
            peer.relay_ready_generation.hash(&mut hasher);
            peer.relay_ready_endpoint.hash(&mut hasher);
            peer.relay_ready_connection_id.hash(&mut hasher);
            peer.relay_confirmed_generation.hash(&mut hasher);
            peer.relay_confirmed_endpoint.hash(&mut hasher);
            peer.relay_confirmed_connection_id.hash(&mut hasher);
        }
        hasher.finish()
    }

    fn hash_connections(connections: &[crate::peer::PeerConnection]) -> u64 {
        let mut sorted: Vec<_> = connections.iter().collect();
        sorted.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for peer in sorted {
            peer.node_id.hash(&mut hasher);
            peer.device_name.hash(&mut hasher);
            peer.app_version.hash(&mut hasher);
            peer.virtual_ip.hash(&mut hasher);
            peer.endpoint
                .map(|endpoint| endpoint.to_string())
                .hash(&mut hasher);
            peer.nat_type.hash(&mut hasher);
            peer.online.hash(&mut hasher);
            peer.last_seen.hash(&mut hasher);
            peer.remote_relay_rtt_ms.hash(&mut hasher);
            format!("{:?}", peer.state).hash(&mut hasher);
            peer.probe_session_id.hash(&mut hasher);
            peer.relay_server.hash(&mut hasher);
            peer.candidates.hash(&mut hasher);
            peer.direct_health.latency_ms.hash(&mut hasher);
            peer.direct_health.rtt_ewma_ms.hash(&mut hasher);
            peer.direct_health.jitter_ms.hash(&mut hasher);
            peer.direct_health.consecutive_failures.hash(&mut hasher);
            peer.direct_health.last_error.hash(&mut hasher);
            peer.direct_health.last_error_code.hash(&mut hasher);
            peer.direct_health.success_count.hash(&mut hasher);
            peer.direct_health.failure_count.hash(&mut hasher);
            peer.relay_health.latency_ms.hash(&mut hasher);
            peer.relay_health.rtt_ewma_ms.hash(&mut hasher);
            peer.relay_health.jitter_ms.hash(&mut hasher);
            peer.relay_health.consecutive_failures.hash(&mut hasher);
            peer.relay_health.last_error.hash(&mut hasher);
            peer.relay_health.last_error_code.hash(&mut hasher);
            peer.relay_health.success_count.hash(&mut hasher);
            peer.relay_health.failure_count.hash(&mut hasher);
            peer.direct_generation.hash(&mut hasher);
            peer.relay_ready_generation.hash(&mut hasher);
            peer.relay_ready_endpoint.hash(&mut hasher);
            peer.relay_ready_connection_id.hash(&mut hasher);
            peer.relay_confirmed_generation.hash(&mut hasher);
            peer.relay_confirmed_endpoint.hash(&mut hasher);
            peer.relay_confirmed_connection_id.hash(&mut hasher);
        }
        hasher.finish()
    }

    peers.len() == connections.len() && hash_diagnostics(peers) == hash_connections(connections)
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
        runtime_incarnation: context.runtime_incarnation,
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation: context.peers.current_network_generation_sync(),
        uptime_ms: context.timeline.uptime_ms(),
        relay_connected: context.relay_transport.read().await.is_some(),
    }
}
