impl PeerManager {
    /// Add or update a peer from control plane info.
    pub async fn add_peer(&self, info: &PeerInfo) -> PeerUpdate {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let mut ip_map = self.ip_to_node.write().await;

        let is_new = !conns.contains_key(&info.node_id);

        let conn = conns
            .entry(info.node_id.clone())
            .or_insert_with(|| PeerConnection::new(&info.node_id, &info.virtual_ip));

        let old_virtual_ip = conn.virtual_ip.clone();
        let old_public_key = conn.public_key.clone();
        let old_signaled_endpoint = conn.signaled_endpoint;
        let virtual_ip_changed = !is_new && old_virtual_ip != info.virtual_ip;
        let public_key_changed = !is_new && old_public_key != info.public_key;

        if virtual_ip_changed
            && ip_map.get(&old_virtual_ip).map(String::as_str) == Some(info.node_id.as_str())
        {
            ip_map.remove(&old_virtual_ip);
        }
        conn.virtual_ip = info.virtual_ip.clone();
        conn.device_name = info.device_name.clone();
        conn.app_version = info.app_version.clone();
        if conn.public_key != info.public_key {
            conn.public_key = info.public_key.clone();
            conn.probe_mac_key = derive_probe_mac_key(&self.config, &info.public_key);
            if conn.probe_mac_key.is_none() {
                debug!(
                    "Peer {} has no usable Probe v2 MAC key; falling back to legacy UDP probes",
                    info.node_id
                );
            }
        }
        if public_key_changed {
            conn.reset_for_identity_change();
        }
        conn.nat_type = info.nat_type.clone();
        conn.online = info.online;
        conn.last_seen = info.last_seen;
        conn.remote_relay_rtt_ms = info.relay_rtt_ms;

        let signaled_endpoint = if info.endpoint.trim().is_empty() {
            None
        } else {
            match info.endpoint.parse::<SocketAddr>() {
                Ok(endpoint) => Some(endpoint),
                Err(error) => {
                    warn!(
                        "Ignoring invalid endpoint '{}' for peer {}: {error}",
                        info.endpoint, info.node_id
                    );
                    None
                }
            }
        };
        let endpoint_changed = !is_new && old_signaled_endpoint != signaled_endpoint;
        if (endpoint_changed && conn.endpoint == old_signaled_endpoint) || conn.endpoint.is_none() {
            conn.endpoint = signaled_endpoint;
        }
        conn.signaled_endpoint = signaled_endpoint;
        if let Some(addr) = signaled_endpoint {
            conn.ensure_candidate_pair(addr, generation);
        }
        if !info.online {
            conn.transition(ConnectionState::Closed);
            conn.relay_server = None;
            conn.probe_session_id = None;
            conn.probe_ephemeral_shared = None;
        } else if conn.state == ConnectionState::Closed {
            conn.transition(ConnectionState::Idle);
        }

        ip_map.insert(info.virtual_ip.clone(), info.node_id.clone());
        PeerUpdate {
            is_new,
            virtual_ip_changed,
            endpoint_changed,
            public_key_changed,
        }
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, node_id: &str) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(node_id) {
            let mut ip_map = self.ip_to_node.write().await;
            ip_map.remove(&conn.virtual_ip);
        }
    }

    /// Get a peer connection by node ID.
    pub async fn get_connection(&self, node_id: &str) -> Option<PeerConnection> {
        self.connections.read().await.get(node_id).cloned()
    }

    /// Look up the node ID for a virtual IP.
    pub async fn resolve_virtual_ip(&self, virtual_ip: &str) -> Option<String> {
        self.ip_to_node.read().await.get(virtual_ip).cloned()
    }

    /// Update a peer's connection state.
    pub async fn update_state(&self, node_id: &str, state: ConnectionState) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.transition(state);
        }
    }

    /// Record a direct traversal timeline event for diagnostics.
    pub async fn record_direct_event(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let generation = self.current_network_generation().await;
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_direct_event(
                generation,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
            );
        }
    }

    /// Record a direct traversal event with structured probe coverage counters.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_direct_event_with_probe_coverage(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
        socket0_count: u32,
        alt_socket_count: u32,
        unique_target_ports: u32,
        repeated_target_ports: u32,
    ) {
        let generation = self.current_network_generation().await;
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_direct_event_with_probe_coverage(
                generation,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
                socket0_count,
                alt_socket_count,
                unique_target_ports,
                repeated_target_ports,
            );
        }
    }

    /// Set the explicit control-plane session ID used to bind Probe v2 MAC keys.
    pub async fn set_probe_session_id(&self, node_id: &str, session_id: Option<String>) -> bool {
        let normalized = session_id.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        });
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        if conn.probe_session_id == normalized {
            return true;
        }
        conn.probe_session_id = normalized;
        conn.probe_ephemeral_shared = None;
        true
    }

    /// Set the explicit traversal session and optional ephemeral X25519 shared secret.
    pub async fn set_probe_session_binding(
        &self,
        node_id: &str,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let normalized = session_id.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        });
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.probe_session_id = normalized;
        conn.probe_ephemeral_shared = ephemeral_shared;
        true
    }

    /// Return the Probe v2 MAC key for a known peer, if both public keys are valid.
    ///
    /// New peers with an explicit signaling session ID receive a session-bound
    /// key; legacy peers without a session ID retain the static v2 skeleton key.
    pub async fn probe_key_for_peer(&self, node_id: &str) -> Option<ProbeMacKey> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(effective_probe_mac_key)
    }

    /// Return Probe v2 MAC keys to try for inbound compatibility.
    ///
    /// The strongest key is first.  When a session ID is active, weaker
    /// session/static fallbacks are retained so upgraded peers can still receive
    /// probes from older clients or from signals relayed by older control servers.
    pub async fn probe_keys_for_peer(&self, node_id: &str) -> Vec<ProbeMacKey> {
        let Some(conn) = self.connections.read().await.get(node_id).cloned() else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        if let Some(key) = effective_probe_mac_key(&conn) {
            keys.push(key);
        }
        if conn.probe_session_id.is_some() {
            if let Some(base_key) = conn.probe_mac_key {
                if let Some(session_id) = conn.probe_session_id.as_deref() {
                    let session_key = derive_session_probe_mac_key(&base_key, session_id);
                    if !keys.contains(&session_key) {
                        keys.push(session_key);
                    }
                }
                if !keys.contains(&base_key) {
                    keys.push(base_key);
                }
            }
        }
        keys
    }
}
