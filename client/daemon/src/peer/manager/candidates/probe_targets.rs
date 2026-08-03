impl PeerManager {
    /// Return the best current direct endpoint for encrypted UDP data.
    pub async fn direct_endpoint_for_send(&self, node_id: &str) -> Option<SocketAddr> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.direct_endpoint_for_send(generation))
    }

    /// Return direct UDP endpoints for NAT keepalive probes.
    pub async fn direct_endpoints(&self) -> Vec<(String, SocketAddr)> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .values()
            .filter(|conn| conn.state == ConnectionState::Direct)
            .filter_map(|conn| {
                conn.selected_direct_endpoint_for_consent(generation)
                    .map(|endpoint| (conn.node_id.clone(), endpoint))
            })
            .collect()
    }

    /// Return candidate endpoints for a specific peer using the adaptive probe scheduler.
    pub async fn direct_probe_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return Vec::new();
        };
        if !conn.online {
            return Vec::new();
        }
        if conn.state == ConnectionState::Direct
            && !conn.should_probe_private_alternates_while_direct(generation)
        {
            return Vec::new();
        }
        let endpoints = conn.candidate_probe_endpoints(
            generation,
            &history,
            local_nat_profile.as_ref(),
            ProbeTargetMode::Synchronized,
        );
        if !endpoints.is_empty() {
            conn.record_direct_event(
                generation,
                "probe_targets_selected",
                endpoints.first().copied(),
                Some(endpoints.len()),
                None,
                format!(
                    "selected {} UDP candidates for synchronized punching",
                    endpoints.len()
                ),
            );
        }
        endpoints
    }

    /// Return stable public endpoints that a hard local NAT should continuously
    /// probe with one socket while the easier peer scans this side's moving
    /// public-port window.
    pub async fn direct_nat_maintainer_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        let generation = self.current_network_generation().await;
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        if !local_nat_profile.as_ref().is_some_and(is_hard_nat_profile) {
            return Vec::new();
        }

        let conns = self.connections.read().await;
        let Some(conn) = conns.get(node_id) else {
            return Vec::new();
        };
        if !conn.online || conn.state == ConnectionState::Direct {
            return Vec::new();
        }
        if !conn.should_use_asymmetric_stable_remote_role(local_nat_profile.as_ref()) {
            return Vec::new();
        }

        let mut endpoints = conn
            .asymmetric_stable_remote_endpoints(generation)
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .collect::<Vec<_>>();
        endpoints.dedup();
        endpoints.truncate(1);
        endpoints
    }

    /// Whether the current direct probe pass must keep a stable local UDP
    /// source by using only socket 0.
    pub async fn direct_probe_uses_primary_socket_only(
        &self,
        node_id: &str,
        endpoints: &[SocketAddr],
    ) -> bool {
        if endpoints.is_empty() {
            return false;
        }

        let generation = self.current_network_generation().await;
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        let conns = self.connections.read().await;
        let Some(conn) = conns.get(node_id) else {
            return false;
        };
        if !conn.online {
            return false;
        }

        if local_nat_profile.as_ref().is_some_and(is_hard_nat_profile)
            && conn.should_use_asymmetric_stable_remote_role(local_nat_profile.as_ref())
        {
            return true;
        }

        endpoints.iter().any(|endpoint| {
            is_public_probe_endpoint(*endpoint)
                && (matches!(
                    conn.candidate_source_for_endpoint(*endpoint),
                    CandidatePairSource::Predicted | CandidatePairSource::Birthday
                ) || conn.candidate_pairs.iter().any(|pair| {
                    pair.local_generation == generation
                        && pair.remote_endpoint == *endpoint
                        && is_speculative_probe_source(pair.source)
                }))
        })
    }

    /// Return candidate endpoints that should continue receiving direct-path probes.
    pub async fn direct_probe_targets(&self) -> Vec<(String, Vec<SocketAddr>)> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter_map(|conn| {
                if !conn.online {
                    return None;
                }
                if conn.state == ConnectionState::Direct
                    && !conn.should_probe_private_alternates_while_direct(generation)
                {
                    return None;
                }
                if conn.state != ConnectionState::Direct
                    && !conn.has_direct_retry_opportunity(local_nat_profile.as_ref())
                {
                    if conn
                        .direct_events
                        .last()
                        .is_none_or(|event| {
                            event.network_generation != generation
                                || event.stage != "retry_skipped_no_viable_nat_window"
                        })
                    {
                        conn.record_direct_event(
                            generation,
                            "retry_skipped_no_viable_nat_window",
                            conn.endpoint,
                            None,
                            None,
                            "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                        );
                    }
                    return None;
                }
                let endpoints = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                    ProbeTargetMode::Background,
                );

                if endpoints.is_empty() {
                    None
                } else {
                    conn.record_direct_event(
                        generation,
                        "probe_targets_due",
                        endpoints.first().copied(),
                        Some(endpoints.len()),
                        None,
                        format!(
                            "selected {} UDP candidates for background retry",
                            endpoints.len()
                        ),
                    );
                    Some((conn.node_id.clone(), endpoints))
                }
            })
            .collect()
    }

    /// Return candidate endpoints that are due for direct-path reprobe.
    ///
    /// Unlike `direct_probe_targets`, this only transitions pairs to Probing
    /// after the peer-level retry cooldown has elapsed, except during the
    /// short generation-change reclaim window for peers with previous Direct
    /// success.
    pub async fn direct_probe_targets_due(
        &self,
        base_retry_after: Duration,
    ) -> Vec<(String, Vec<SocketAddr>)> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter_map(|conn| {
                if !conn.online {
                    return None;
                }
                if conn.state == ConnectionState::Direct {
                    return None;
                }
                let reclaim_active = conn.direct_reclaim_active();
                if !reclaim_active && !conn.direct_retry_due(base_retry_after) {
                    return None;
                }
                if !conn.has_direct_retry_opportunity(local_nat_profile.as_ref()) {
                    if conn
                        .direct_events
                        .last()
                        .is_none_or(|event| {
                            event.network_generation != generation
                                || event.stage != "retry_skipped_no_viable_nat_window"
                        })
                    {
                        conn.record_direct_event(
                            generation,
                            "retry_skipped_no_viable_nat_window",
                            conn.endpoint,
                            None,
                            None,
                            "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                        );
                    }
                    return None;
                }
                let endpoints = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                    if reclaim_active {
                        ProbeTargetMode::Reclaim
                    } else {
                        ProbeTargetMode::Background
                    },
                );

                if endpoints.is_empty() {
                    None
                } else {
                    if reclaim_active {
                        conn.record_direct_event(
                            generation,
                            "direct_reclaim_targets_due",
                            endpoints.first().copied(),
                            Some(endpoints.len()),
                            None,
                            format!(
                                "selected {} UDP candidates for generation-change Direct reclaim",
                                endpoints.len()
                            ),
                        );
                    }
                    Some((conn.node_id.clone(), endpoints))
                }
            })
            .collect()
    }

    /// Record that a UDP probe datagram was actually sent to a candidate.
    ///
    /// Candidate selection can be broader than the outbound rate-limit budget;
    /// mark pairs as probing only once the UDP layer confirms a packet left.
    pub async fn record_direct_probe_sent(&self, node_id: &str, endpoint: SocketAddr) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.mark_candidate_pair_probing(endpoint, generation);
        true
    }
}
