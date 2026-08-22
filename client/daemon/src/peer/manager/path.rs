impl PeerManager {
    /// Select the data path for one outbound encrypted packet.
    pub async fn select_path_for_data(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
    ) -> PathSelection {
        self.select_path_for_data_with_local_endpoint(node_id, prefer_direct, relay_available, None)
            .await
    }

    /// Select the data path and include the local UDP endpoint in transition diagnostics.
    pub async fn select_path_for_data_with_local_endpoint(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
        local_endpoint: Option<SocketAddr>,
    ) -> PathSelection {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let generation = self.current_network_generation_sync();
        self.select_path_for_data_with_local_endpoint_in_epoch(
            node_id,
            prefer_direct,
            relay_available,
            local_endpoint,
            generation,
        )
        .await
    }

    /// Select a path while the caller already owns the network epoch gate.
    /// This is used by the outbound counter/send transaction; taking the
    /// public wrapper there would attempt to lock the same async mutex twice.
    pub(crate) async fn select_path_for_data_with_local_endpoint_in_epoch(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
        local_endpoint: Option<SocketAddr>,
        generation: u64,
    ) -> PathSelection {
        let mut conns = self.connections.write().await;
        match conns.get_mut(node_id) {
            Some(conn) => {
                conn.expire_stale_trial_nominations(generation, local_endpoint);
                let mut selection =
                    conn.select_path_for_data(generation, prefer_direct, relay_available);
                if selection.path == Some(NetworkPath::Relay) {
                    selection.relay_server = conn.relay_server.clone();
                }
                if selection.path == Some(NetworkPath::Direct)
                    && !selection.direct_confirmed
                    && selection.reason_code == REASON_PATH_DIRECT_TRIAL
                {
                    if let Some(endpoint) = selection.direct_endpoint {
                        conn.mark_candidate_pair_nominated(
                            endpoint,
                            generation,
                            local_endpoint,
                            &selection.reason,
                        );
                    }
                }
                conn.record_path_selection_event(generation, &selection, local_endpoint);
                conn.last_path_selection = Some(selection.clone());
                selection
            }
            None => {
                if relay_available {
                    PathSelection::relay(
                        REASON_PATH_DIRECT_NO_ENDPOINT,
                        "peer has no direct state; using relay",
                    )
                } else {
                    PathSelection::unavailable(
                        REASON_PATH_UNAVAILABLE,
                        "peer has no direct state and relay is unavailable",
                    )
                }
            }
        }
    }

    /// Whether encrypted data should use direct UDP for this peer right now.
    pub async fn should_use_direct_for_data(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
    ) -> bool {
        self.select_path_for_data(node_id, prefer_direct, relay_available)
            .await
            .path
            == Some(NetworkPath::Direct)
    }

    /// Whether a queued business packet may consume a WireGuard counter in
    /// the current generation.  A Direct ACK is a valid background probe
    /// result, but relay-first keeps it out of the data plane until the
    /// per-peer relay transport has also received its matching encrypted ACK.
    /// The predicate is intentionally evaluated from one connection snapshot
    /// so queue admission cannot observe Direct and relay confirmation from
    /// different generations.
    pub async fn is_data_path_admitted_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        relay_available: bool,
    ) -> bool {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        self.is_data_path_admitted_for_generation_in_epoch(node_id, generation, relay_available)
            .await
    }

    /// Admission check for callers that already hold the network epoch gate.
    pub(crate) async fn is_data_path_admitted_for_generation_in_epoch(
        &self,
        node_id: &str,
        generation: u64,
        relay_available: bool,
    ) -> bool {
        if generation != self.current_network_generation_sync() {
            return false;
        }
        self.connections
            .write()
            .await
            .get_mut(node_id)
            .map(|conn| {
                if (relay_available || self.relay_first_required())
                    && conn.relay_first.gate_generation != Some(generation)
                {
                    conn.relay_first.gate_generation = Some(generation);
                    conn.relay_first.gate_started_at = Some(Instant::now());
                }
                if !conn.online || conn.state == ConnectionState::Closed {
                    return false;
                }
                let relay_confirmed = relay_available
                    && conn.relay_confirmed_at.is_some()
                    && conn.relay_confirmed_generation == Some(generation)
                    && conn
                        .relay_confirmed_endpoint
                        .as_deref()
                        .is_some_and(|endpoint| !endpoint.is_empty());
                if relay_confirmed {
                    return true;
                }
                if conn.relay_first_confirmation_pending(generation, relay_available) {
                    return false;
                }
                conn.state == ConnectionState::Direct && conn.direct_generation == generation
            })
            .unwrap_or(false)
    }

    /// Whether direct retry suppression has expired for diagnostics/probing.
    pub async fn direct_retry_due(&self, node_id: &str, retry_after: Duration) -> bool {
        let Some(conn) = self.connections.read().await.get(node_id).cloned() else {
            return false;
        };

        conn.direct_retry_due(retry_after)
    }

    /// Whether the peer is inside the aggressive Direct reclaim window.
    pub async fn direct_reclaim_active(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(PeerConnection::direct_reclaim_active)
    }

    /// Whether the peer currently has a verified direct path.
    pub async fn is_direct(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .map(|conn| conn.state == ConnectionState::Direct)
            .unwrap_or(false)
    }

    /// Node IDs of every peer with a verified direct path.
    ///
    /// Used by the dynamic socket cap to pre-compute the nonevictable set
    /// before taking the socket-state lock, so eviction selection never awaits
    /// peer state while holding the lock.
    pub(crate) async fn direct_peer_ids(&self) -> HashSet<String> {
        self.connections
            .read()
            .await
            .values()
            .filter(|conn| conn.state == ConnectionState::Direct)
            .map(|conn| conn.node_id.clone())
            .collect()
    }

    /// Whether the peer is Direct, synchronously, via the mirror.  Updated
    /// by every `ConnectionState` transition, so it is always at least as
    /// fresh as the last committed transition.
    pub(crate) fn is_direct_sync(&self, node_id: &str) -> bool {
        self.direct_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(node_id)
    }

    /// Whether a peer is still eligible to receive a newly allocated
    /// direct-validation worker. This deliberately distinguishes an offline
    /// peer retained for diagnostics from a live peer: lifecycle cleanup can
    /// cancel an old owner, and queued observations must not immediately
    /// recreate one for a Closed/offline connection.
    #[allow(dead_code)]
    pub(crate) async fn is_direct_validation_eligible(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(|connection| {
                connection.online && connection.state != ConnectionState::Closed
            })
    }

    /// Whether an encrypted validation may establish `endpoint` as a new
    /// Direct path.  A confirmed public/UU path remains eligible for a
    /// directly-connected LAN endpoint, but ordinary alternate public
    /// candidates are still suppressed while Direct is healthy.
    pub(crate) async fn is_direct_validation_eligible_for_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
    ) -> bool {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(|connection| {
                connection.online
                    && connection.state != ConnectionState::Closed
                    && (connection.state != ConnectionState::Direct
                        || connection.should_upgrade_direct_to_on_link(generation, endpoint))
            })
    }

    /// Lock-free/try-lock counterpart used by the synchronous UDP ingress
    /// gate.  A Direct peer's ordinary matched ACKs must be dropped before
    /// they wake the scheduler; only an on-link alternate may pass through to
    /// the async registry check.
    pub(crate) fn is_direct_validation_eligible_for_endpoint_sync(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
    ) -> bool {
        if !self.is_direct_sync(node_id) {
            return true;
        }
        let Ok(connections) = self.connections.try_read() else {
            return false;
        };
        let generation = self.current_network_generation_sync();
        connections.get(node_id).is_some_and(|connection| {
            connection.online
                && connection.state != ConnectionState::Closed
                && (connection.state != ConnectionState::Direct
                    || connection.should_upgrade_direct_to_on_link(generation, endpoint))
        })
    }

    /// Whether relay-assisted punching should be deferred for a peer that is
    /// already on a healthy confirmed Direct path.
    ///
    /// While the selected Direct pair has recent success and zero consecutive
    /// failures, repeated peer-reflexive observations and peer offers must not
    /// schedule new relay-assisted punch sessions, full offer re-advertisements,
    /// or speculative candidate sweeps. Consent keepalive continues separately.
    pub async fn should_defer_relay_assisted_punch(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(PeerConnection::direct_is_healthy_confirmed)
    }

    /// The currently selected direct endpoint for consent keepalive, if any.
    pub async fn selected_direct_endpoint_for_consent(
        &self,
        node_id: &str,
    ) -> Option<SocketAddr> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.selected_direct_endpoint_for_consent(generation))
    }

    /// Whether the peer is currently in Relay state.
    pub async fn is_relay(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .map(|conn| conn.state == ConnectionState::Relay)
            .unwrap_or(false)
    }

    /// Whether a relay path already covers this peer during a direct probe
    /// failure window.
    ///
    /// Unlike [`Self::is_relay`], this also recognizes the FallbackToRelay
    /// handover and an active relay traffic path, so a synchronized punch
    /// no-ACK during fallback still enters batch failure learning. It is
    /// deliberately a separate predicate because handshake offer/answer logic
    /// keeps using `is_relay` and must not be broadened.
    pub async fn has_relay_safety_net(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .map(|conn| {
                matches!(
                    conn.state,
                    ConnectionState::Relay | ConnectionState::FallbackToRelay
                ) || conn.active_path() == Some(NetworkPath::Relay)
            })
            .unwrap_or(false)
    }

    /// Whether a candidate endpoint has recently returned an authenticated
    /// but too-slow ACK in the current generation.  This is intentionally a
    /// point query used by the UDP sender immediately before emission: target
    /// planning can race a late ACK, so filtering only at plan construction
    /// still allows the already-built sweep to keep sending into the delayed
    /// mapping.
    pub(crate) async fn direct_probe_endpoint_quarantined(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> bool {
        if generation != self.current_network_generation_sync() {
            return true;
        }
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(|conn| {
                conn.direct_probe_endpoint_quarantined(endpoint, generation, Instant::now())
            })
    }

    /// Whether this IP is known as a peer public candidate before any packet
    /// content is parsed.
    ///
    /// The match covers the current endpoint, the signaled endpoint, signaled
    /// candidates, and candidate-pair remote endpoints. Used by the UDP
    /// inbound path to prove that datagrams from a known peer public IP
    /// reached this daemon at all, independently of Probe v1/v2 decoding.
    pub async fn has_known_public_candidate_ip(&self, ip: IpAddr) -> bool {
        self.connections
            .read()
            .await
            .values()
            .any(|conn| {
                conn.endpoint.is_some_and(|endpoint| endpoint.ip() == ip)
                    || conn.signaled_endpoint.is_some_and(|endpoint| endpoint.ip() == ip)
                    || conn
                        .candidates
                        .iter()
                        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
                        .any(|endpoint| endpoint.ip() == ip)
                    || conn
                        .candidate_pairs
                        .iter()
                        .any(|pair| pair.remote_endpoint.ip() == ip)
            })
    }
}
