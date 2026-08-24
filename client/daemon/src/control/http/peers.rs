pub(super) async fn poll_peers(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
    self_node_id: &str,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
) -> Result<()> {
    let res = http
        .get(format!(
            "{base_url}/api/v1/nodes?network_id={}",
            config.network.network_id
        ))
        .timeout(CONTROL_REQUEST_TIMEOUT)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list nodes request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "list nodes request returned HTTP {}",
            res.status()
        )));
    }

    let body: ListNodesResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list nodes decode failed: {e}")))?;

    info!(
        "poll_peers: received {} nodes from control plane (self_node_id={})",
        body.nodes.len(),
        self_node_id
    );

    let mut seen = HashMap::new();
    let mut joined = Vec::new();
    let mut updated = Vec::new();

    {
        let mut state = state.write().await;

        for node in body.nodes {
            if node.id == self_node_id || node.public_key == config.node.public_key {
                continue;
            }

            let peer = PeerInfo {
                node_id: node.id.clone(),
                device_name: node.device_name,
                app_version: node.app_version,
                public_key: node.public_key,
                endpoint: node.endpoint,
                nat_type: node.nat_type,
                virtual_ip: node.virtual_ip,
                online: node.online,
                last_seen: node.last_seen,
                relay_rtt_ms: node.relay_rtt_ms,
            };

            seen.insert(peer.node_id.clone(), peer.clone());
            match state.peers.get(&peer.node_id) {
                Some(known) if peer_metadata_changed(known, &peer) => updated.push(peer.clone()),
                None => joined.push(peer.clone()),
                _ => {}
            }
            state.peers.insert(peer.node_id.clone(), peer);
        }

        let departed: Vec<String> = state
            .peers
            .keys()
            .filter(|node_id| !seen.contains_key(*node_id))
            .cloned()
            .collect();

        for node_id in departed {
            state.peers.remove(&node_id);
            let _ = event_tx.send(ControlEvent::PeerLeft(node_id));
        }
    }

    info!(
        "poll_peers: {} joined, {} updated, {} total known peers",
        joined.len(),
        updated.len(),
        seen.len()
    );

    // The control plane also returns historical/offline device rows.  A
    // cold-start roster can therefore contain dozens of records before the
    // one live peer that can carry the first business packet.  Control-event
    // handling performs bounded per-peer work, so preserve the dataplane
    // invariant that a live peer is admitted before an offline historical
    // record.  Within the same liveness class, prefer the most recently seen
    // device and use node_id only as a deterministic tie-breaker.
    let prioritize_live = |left: &PeerInfo, right: &PeerInfo| {
        right
            .online
            .cmp(&left.online)
            .then_with(|| right.last_seen.cmp(&left.last_seen))
            .then_with(|| left.node_id.cmp(&right.node_id))
    };
    joined.sort_by(prioritize_live);
    updated.sort_by(prioritize_live);

    for peer in joined {
        let _ = event_tx.send(ControlEvent::PeerJoined(peer));
    }
    for peer in updated {
        let _ = event_tx.send(ControlEvent::PeerUpdated(peer));
    }

    Ok(())
}

pub(super) fn peer_metadata_changed(known: &PeerInfo, peer: &PeerInfo) -> bool {
    known.device_name != peer.device_name
        || known.app_version != peer.app_version
        || known.public_key != peer.public_key
        || known.endpoint != peer.endpoint
        || known.nat_type != peer.nat_type
        || known.virtual_ip != peer.virtual_ip
        || known.online != peer.online
        // `last_seen` is user-visible diagnostics and part of peer liveness.
        // Suppressing heartbeat-only updates left PeerManager permanently on
        // the join-time value even while ClientState kept advancing it.
        || known.last_seen != peer.last_seen
        || known.relay_rtt_ms != peer.relay_rtt_ms
}

pub(super) async fn create_tunnel(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    protocol: &str,
    local_port: u16,
    remote_port: u16,
) -> Result<(String, String)> {
    let res = http
        .post(format!("{base_url}/api/v1/tunnels"))
        .timeout(CONTROL_REQUEST_TIMEOUT)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "device_id": device_id,
            "protocol": protocol,
            "local_port": local_port,
            "remote_port": remote_port,
            "local_address": "127.0.0.1",
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("create tunnel request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "create tunnel request returned HTTP {}",
            res.status()
        )));
    }

    let body: CreateTunnelResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("create tunnel decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "create tunnel failed".to_string()),
        ));
    }

    Ok((
        body.tunnel_id
            .ok_or_else(|| DaemonError::ControlPlane("create tunnel response missing id".into()))?,
        body.public_endpoint.ok_or_else(|| {
            DaemonError::ControlPlane("create tunnel response missing public endpoint".into())
        })?,
    ))
}
