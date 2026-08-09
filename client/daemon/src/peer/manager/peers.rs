fn normalize_probe_session_id(session_id: Option<String>) -> Option<String> {
    session_id.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn prune_probe_session_bindings(conn: &mut PeerConnection, now: Instant) {
    conn.pending_probe_bindings
        .retain(|_, pending| pending.expires_at > now);
    if conn
        .previous_probe_binding
        .as_ref()
        .is_some_and(|previous| previous.expires_at <= now)
    {
        conn.previous_probe_binding = None;
    }
}

fn install_active_probe_binding(
    conn: &mut PeerConnection,
    binding: ProbeSessionBinding,
    retain_previous: bool,
) -> bool {
    let previous = active_probe_binding(conn);
    let replaced = previous != binding;
    if retain_previous && replaced {
        conn.previous_probe_binding = Some(RetainedProbeSessionBinding {
            binding: previous,
            expires_at: Instant::now() + PROBE_SESSION_BINDING_OVERLAP,
        });
    } else if !retain_previous {
        conn.previous_probe_binding = None;
    }
    conn.probe_binding_token = binding.token.clone();
    conn.probe_session_id = binding.session_id.clone();
    conn.probe_ephemeral_shared = binding.ephemeral_shared;
    conn.pending_probe_bindings.clear();
    replaced
}

fn push_unique_probe_key(
    candidates: &mut Vec<ProbeKeyCandidate>,
    key: ProbeMacKey,
    role: ProbeKeyRole,
) {
    if !candidates.iter().any(|candidate| candidate.key == key) {
        candidates.push(ProbeKeyCandidate { key, role });
    }
}

fn push_probe_binding_compatibility_keys(
    candidates: &mut Vec<ProbeKeyCandidate>,
    base_key: ProbeMacKey,
    binding: &ProbeSessionBinding,
) {
    if let Some(session_id) = binding.session_id.as_deref() {
        push_unique_probe_key(
            candidates,
            derive_session_probe_mac_key(&base_key, session_id),
            ProbeKeyRole::Compatibility,
        );
    }
}

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
        // Keep the synchronous Direct-set mirror attached to every connection
        // so its `transition` keeps the UDP eviction's nonevictable set fresh.
        conn.attach_direct_cache(self.direct_peers.clone());

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
        // The remote fresh-prediction space is bound to the peer's identity
        // (public key): a rejoin with a NEW key — including a PeerLeft
        // followed by `add_peer` with `is_new == true` — must not inherit the
        // old incarnation's high-water, or the new incarnation's predictions
        // would be judged stale against it forever.  The key map survives
        // `remove_peer`, so the comparison works even when the connection was
        // recreated.
        let identity_changed = {
            let mut keys = self
                .remote_fresh_identity_keys
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let changed = keys
                .get(&info.node_id)
                .is_none_or(|key| key != &info.public_key);
            keys.insert(info.node_id.clone(), info.public_key.clone());
            changed
        };
        if identity_changed {
            self.reset_remote_fresh_generation(
                &info.node_id,
                if public_key_changed {
                    "public_key_changed"
                } else {
                    "identity_key_changed_on_rejoin"
                },
            )
            .await;
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
            conn.probe_binding_token = None;
            conn.pending_probe_bindings.clear();
            conn.previous_probe_binding = None;
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
    ///
    /// A plain PeerLeft must NOT clear the remote fresh high-water: a late
    /// signal from the old incarnation must stay rejected after the peer
    /// rejoins, and the new incarnation's strictly-monotonic counter
    /// supersedes the old one anyway.  Only a public-key / identity change
    /// resets the fresh space.
    pub async fn remove_peer(&self, node_id: &str) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(node_id) {
            let mut ip_map = self.ip_to_node.write().await;
            ip_map.remove(&conn.virtual_ip);
        }
        drop(conns);
        self.direct_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(node_id);
        self.recovery_epoch_end(node_id, "peer_removed").await;
        self.clear_fresh_mapping(node_id, "peer_removed").await;
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
        let normalized = normalize_probe_session_id(session_id);
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.pending_probe_bindings.clear();
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: None,
                session_id: normalized,
                ephemeral_shared: None,
            },
            false,
        );
        true
    }

    /// Set the explicit traversal session and optional ephemeral X25519 shared secret.
    pub async fn set_probe_session_binding(
        &self,
        node_id: &str,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let normalized = normalize_probe_session_id(session_id);
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.pending_probe_bindings.clear();
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: None,
                session_id: normalized,
                ephemeral_shared,
            },
            false,
        );
        true
    }

    /// Stage a Probe-v2 replacement without changing the outbound key. A
    /// responder marks its staged key promotable by authenticated inbound
    /// traffic; an initiator waits for the matching answer and installs it
    /// explicitly.
    pub(crate) async fn stage_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
        promote_on_match: bool,
    ) -> ProbeBindingStage {
        let token = token.trim().to_string();
        if token.is_empty() {
            return ProbeBindingStage::StaleDuplicate;
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return ProbeBindingStage::PeerMissing;
        };
        let now = Instant::now();
        prune_probe_session_bindings(conn, now);
        if conn.probe_binding_token.as_deref() == Some(token.as_str()) {
            return ProbeBindingStage::ReplayableDuplicate;
        }
        if let Some(pending) = conn.pending_probe_bindings.get_mut(&token) {
            // An exact cached answer replay gets a fresh delivery window.
            pending.expires_at = now + PENDING_PROBE_SESSION_BINDING_GRACE;
            return ProbeBindingStage::ReplayableDuplicate;
        }
        if conn
            .previous_probe_binding
            .as_ref()
            .and_then(|previous| previous.binding.token.as_deref())
            == Some(token.as_str())
        {
            return ProbeBindingStage::StaleDuplicate;
        }
        if conn.pending_probe_bindings.len() >= MAX_PENDING_PROBE_SESSION_BINDINGS_PER_PEER {
            return ProbeBindingStage::Busy;
        }
        conn.pending_probe_bindings.insert(token.clone(), PendingProbeSessionBinding {
            binding: ProbeSessionBinding {
                token: Some(token),
                session_id: normalize_probe_session_id(session_id),
                ephemeral_shared,
            },
            expires_at: now + PENDING_PROBE_SESSION_BINDING_GRACE,
            promote_on_match,
        });
        ProbeBindingStage::Staged
    }

    /// Extend a staged responder binding after the control-plane answer
    /// delivery attempt completes. This keeps signaling latency separate from
    /// the authenticated adoption window.
    pub(crate) async fn refresh_pending_probe_session_binding_grace(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let Some(pending) = conn.pending_probe_bindings.get_mut(token) else {
            return false;
        };
        pending.expires_at = Instant::now() + PENDING_PROBE_SESSION_BINDING_GRACE;
        true
    }

    /// Install an answer-confirmed Probe-v2 binding for outbound traffic while
    /// retaining the former inbound key during the overlap window.
    pub(crate) async fn install_probe_session_binding(
        &self,
        node_id: &str,
        token: String,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        prune_probe_session_bindings(conn, Instant::now());
        install_active_probe_binding(
            conn,
            ProbeSessionBinding {
                token: Some(token),
                session_id: normalize_probe_session_id(session_id),
                ephemeral_shared,
            },
            true,
        );
        true
    }

    /// Roll back an unpublished Probe-v2 replacement. Returns false when the
    /// token was already promoted by authenticated traffic.
    pub(crate) async fn discard_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return true;
        };
        prune_probe_session_bindings(conn, Instant::now());
        if conn.probe_binding_token.as_deref() == Some(token) {
            return false;
        }
        conn.pending_probe_bindings.remove(token);
        true
    }

    /// Promote a responder's staged Probe-v2 binding after a packet validates
    /// under that exact key and token.
    pub(crate) async fn confirm_pending_probe_session_binding(
        &self,
        node_id: &str,
        token: &str,
    ) -> bool {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let should_promote = conn
            .pending_probe_bindings
            .get(token)
            .is_some_and(|pending| pending.promote_on_match);
        if !should_promote {
            return conn.probe_binding_token.as_deref() == Some(token);
        }
        let pending = conn
            .pending_probe_bindings
            .remove(token)
            .expect("pending Probe binding checked above");
        install_active_probe_binding(conn, pending.binding, true);
        true
    }

    /// Atomically bridge a Probe-v2 adoption check with its matching
    /// WireGuard responder confirmation. The peer binding write lock remains
    /// held across `confirm_transport`, so peer removal, identity rotation,
    /// and competing handshake commits cannot clear the Probe transaction
    /// after WireGuard has already been promoted.
    pub(crate) async fn confirm_probe_and_transport_transaction<F, Fut>(
        &self,
        node_id: &str,
        token: &str,
        confirm_transport: F,
    ) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let should_promote = conn
            .pending_probe_bindings
            .get(token)
            .is_some_and(|pending| pending.promote_on_match);
        let already_active = conn.probe_binding_token.as_deref() == Some(token);
        if !should_promote && !already_active {
            return false;
        }
        if !confirm_transport().await {
            return false;
        }
        if should_promote {
            let pending = conn
                .pending_probe_bindings
                .remove(token)
                .expect("promotable Probe binding checked above");
            install_active_probe_binding(conn, pending.binding, true);
        }
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

    /// Return role-tagged Probe-v2 keys for inbound authentication. Only an
    /// exact match on a promotable pending key can commit a responder rekey.
    pub(crate) async fn probe_key_candidates_for_peer(
        &self,
        node_id: &str,
    ) -> Vec<ProbeKeyCandidate> {
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return Vec::new();
        };
        prune_probe_session_bindings(conn, Instant::now());
        let Some(base_key) = conn.probe_mac_key else {
            return Vec::new();
        };

        let active = active_probe_binding(conn);
        let pending = conn.pending_probe_bindings.clone();
        let previous = conn.previous_probe_binding.clone();
        let mut candidates = Vec::new();
        push_unique_probe_key(
            &mut candidates,
            probe_mac_key_for_binding(base_key, &active),
            ProbeKeyRole::Active,
        );
        for pending in pending.values() {
            let role = if pending.promote_on_match {
                ProbeKeyRole::Pending {
                    token: pending
                        .binding
                        .token
                        .clone()
                        .expect("staged Probe binding must have a token"),
                }
            } else {
                ProbeKeyRole::Compatibility
            };
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &pending.binding),
                role,
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &previous.binding),
                ProbeKeyRole::Previous,
            );
        }
        push_probe_binding_compatibility_keys(&mut candidates, base_key, &active);
        for pending in pending.values() {
            push_probe_binding_compatibility_keys(
                &mut candidates,
                base_key,
                &pending.binding,
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_probe_binding_compatibility_keys(
                &mut candidates,
                base_key,
                &previous.binding,
            );
        }
        push_unique_probe_key(
            &mut candidates,
            base_key,
            ProbeKeyRole::Compatibility,
        );
        candidates
    }

    /// Return Probe v2 MAC keys to try for inbound compatibility.
    ///
    /// The strongest key is first.  When a session ID is active, weaker
    /// session/static fallbacks are retained so upgraded peers can still receive
    /// probes from older clients or from signals relayed by older control servers.
    pub async fn probe_keys_for_peer(&self, node_id: &str) -> Vec<ProbeMacKey> {
        self.probe_key_candidates_for_peer(node_id)
            .await
            .into_iter()
            .map(|candidate| candidate.key)
            .collect()
    }
}
