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
    session_id: Option<String>,
) {
    if !candidates.iter().any(|candidate| candidate.key == key) {
        candidates.push(ProbeKeyCandidate {
            key,
            role,
            session_id,
        });
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
            binding.session_id.clone(),
        );
    }
}

impl PeerManager {
    /// Add or update a peer from control plane info.
    pub async fn add_peer(&self, info: &PeerInfo) -> PeerUpdate {
        let generation = self.current_network_generation().await;
        // Un-quarantine evidence is computed under the connection lock but the
        // quarantine map is re-opened only AFTER the lock is dropped:
        // `unquarantine_peer` records a diagnostics event that re-locks the
        // connection map, so awaiting it while holding the write guard would
        // deadlock.
        let mut unquarantine_after_lock: Option<&'static str> = None;
        let mut cancel_heartbeat_after_lock = false;
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
            cancel_heartbeat_after_lock = true;
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
        // PeerUpdated may carry a new host/private endpoint while an
        // encrypted-confirmed public pair is live. Keep the confirmed pair as
        // the active endpoint; the new value remains in signaled_endpoint and
        // can enter the candidate/probing set after Direct health fails.
        if (endpoint_changed
            && conn.endpoint == old_signaled_endpoint
            && !conn.direct_is_healthy_confirmed())
            || conn.endpoint.is_none()
        {
            conn.endpoint = signaled_endpoint;
        }
        conn.signaled_endpoint = signaled_endpoint;
        if let Some(addr) = signaled_endpoint {
            conn.ensure_candidate_pair(addr, generation);
        }
        if !info.online {
            conn.transition(ConnectionState::Closed);
            conn.relay_server = None;
            cancel_heartbeat_after_lock = true;
            conn.probe_session_id = None;
            conn.probe_ephemeral_shared = None;
            conn.probe_binding_token = None;
            conn.pending_probe_bindings.clear();
            conn.previous_probe_binding = None;
        } else if conn.state == ConnectionState::Closed {
            conn.transition(ConnectionState::Idle);
        }

        // A relay 404 is authoritative evidence that the peer's registration
        // is absent on the relay.  Only evidence that the peer is a NEW
        // instance re-opens the registration-grace window: a brand-new node
        // ID (fresh registration) or a changed public key (identity rotation
        // / reinstall).  Endpoint heartbeats, `last_seen` growth, ordinary
        // NAT endpoint churn and online transitions are all consistent with
        // the SAME stale incarnation still missing its relay registration, so
        // they must NOT clear the grace window (field evidence: old v0.1.108 /
        // v0.1.110 nodes kept restarting 404 grace and quarantine churn on
        // every control-plane heartbeat while their relay registration was
        // permanently absent).
        let clear_relay_not_found_grace_after_lock = info.online
            && (is_new || public_key_changed);

        // Authoritative recovery re-open for a quarantined peer is limited to
        // identity/incarnation change (public-key rotation) and new
        // registrations.  Endpoint churn on a stale incarnation is NOT
        // authoritative: the NAT endpoint moves every heartbeat while the
        // relay registration stays absent, and unquarantining on it would
        // restart the whole punch / relay-404 / re-quarantine storm on every
        // poll.  Authenticated inbound evidence (a live encrypted punch from
        // the peer) is handled by `learn_authenticated_endpoint`, and a
        // PeerLeft removes the quarantine in `remove_peer`.  The re-open is
        // deferred until the connection map guard is released to avoid
        // re-locking it inside `unquarantine_peer`.
        if identity_changed && info.online && self.peer_quarantined_sync(&info.node_id) {
            unquarantine_after_lock = Some("identity/incarnation change");
        }

        ip_map.insert(info.virtual_ip.clone(), info.node_id.clone());
        drop(conns);
        drop(ip_map);
        if cancel_heartbeat_after_lock {
            self.cancel_relay_backoff_heartbeat(&info.node_id);
        }
        if clear_relay_not_found_grace_after_lock {
            self.clear_relay_not_found_grace(&info.node_id).await;
        }
        if let Some(reason) = unquarantine_after_lock {
            self.unquarantine_peer(&info.node_id, reason).await;
        }
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
        self.cancel_relay_backoff_heartbeat(node_id);
        self.clear_relay_not_found_grace(node_id).await;
        // A PeerLeft is authoritative evidence that the peer's incarnation is
        // gone: drop any relay-404 quarantine so a later rejoin (a NEW node
        // ID / registration) starts clean instead of inheriting the dead
        // incarnation's isolation.
        self.quarantined_peers.lock().await.remove(node_id);
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
        let updated = {
            let mut conns = self.connections.write().await;
            if let Some(conn) = conns.get_mut(node_id) {
                conn.transition(state);
                true
            } else {
                false
            }
        };
        if updated && !matches!(state, ConnectionState::Relay | ConnectionState::FallbackToRelay) {
            self.cancel_relay_backoff_heartbeat(node_id);
        }
    }

    /// Atomically re-check the state observed before an asynchronous punch
    /// setup and, if it is still current, enter HolePunching.  The caller
    /// must not make this decision from a cloned `PeerConnection`: Direct
    /// promotion may have committed while candidate refresh or HTTP work was
    /// in flight.
    pub(crate) async fn begin_hole_punch_if_current(
        &self,
        node_id: &str,
        observed_generation: u64,
        observed_commit_seq: Option<u64>,
    ) -> bool {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        if self.current_network_generation_sync() != observed_generation
            || self.direct_commit_seq_sync(node_id) != observed_commit_seq
        {
            return false;
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        if conn.state == ConnectionState::Direct && conn.direct_is_healthy_confirmed() {
            return false;
        }
        if !matches!(conn.state, ConnectionState::Direct | ConnectionState::Relay) {
            conn.transition(ConnectionState::HolePunching);
        }
        true
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

    /// Generation-stable direct-event recorder with the actual UDP socket
    /// index when receive-side code can identify it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_event_for_generation_with_socket(
        &self,
        node_id: &str,
        generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_direct_event_with_socket(
                generation,
                stage,
                endpoint,
                socket_index,
                candidate_count,
                sent_probes,
                detail,
            );
        }
    }

    /// Record a lifecycle event for one owned encrypted direct-validation
    /// worker.  The worker's lease supplies `generation` and
    /// `validation_session_id`; do not substitute the manager's current
    /// generation here because this method is also used to explain a worker
    /// that was cancelled by a generation advance.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event(
        &self,
        node_id: &str,
        generation: u64,
        validation_session_id: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record_direct_validation_event_with_socket(
            node_id,
            generation,
            validation_session_id,
            stage,
            endpoint,
            None,
            candidate_count,
            sent_probes,
            detail,
        )
        .await;
    }

    /// Generation- and owner-stable validation lifecycle recorder with the
    /// actual UDP socket index where it is available.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event_with_socket(
        &self,
        node_id: &str,
        generation: u64,
        validation_session_id: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record_direct_validation_event_with_metadata(
            node_id,
            generation,
            DirectValidationEventMetadata {
                local_validation_session_id: Some(validation_session_id),
                ..DirectValidationEventMetadata::default()
            },
            stage,
            endpoint,
            socket_index,
            candidate_count,
            sent_probes,
            detail,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_direct_validation_event_with_metadata(
        &self,
        node_id: &str,
        generation: u64,
        metadata: DirectValidationEventMetadata,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_direct_validation_event_with_metadata(
                generation,
                metadata,
                stage,
                endpoint,
                socket_index,
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
        self.probe_key_and_session_for_peer(node_id)
            .await
            .map(|(key, _)| key)
    }

    /// Return the active Probe v2 MAC key together with the session that
    /// derived it under one connection snapshot.  The session is carried by a
    /// pending outbound probe solely for diagnostics attribution; it is never
    /// trusted in place of MAC verification.
    pub(crate) async fn probe_key_and_session_for_peer(
        &self,
        node_id: &str,
    ) -> Option<(ProbeMacKey, Option<String>)> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|connection| {
                effective_probe_mac_key(connection)
                    .map(|key| (key, connection.probe_session_id.clone()))
            })
    }

    /// Snapshot the active Probe session for peer-scoped receive diagnostics.
    /// The value is not sent on the wire and cannot influence authentication.
    pub(crate) async fn probe_session_id_for_peer(&self, node_id: &str) -> Option<String> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|connection| connection.probe_session_id.clone())
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
            active.session_id.clone(),
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
                pending.binding.session_id.clone(),
            );
        }
        if let Some(previous) = previous.as_ref() {
            push_unique_probe_key(
                &mut candidates,
                probe_mac_key_for_binding(base_key, &previous.binding),
                ProbeKeyRole::Previous,
                previous.binding.session_id.clone(),
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
            None,
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
