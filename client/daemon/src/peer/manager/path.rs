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
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        match conns.get_mut(node_id) {
            Some(conn) => {
                conn.expire_stale_trial_nominations(generation, local_endpoint);
                let selection =
                    conn.select_path_for_data(generation, prefer_direct, relay_available);
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
