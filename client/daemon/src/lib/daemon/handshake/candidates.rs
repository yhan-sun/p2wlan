impl Daemon {
    /// Build the optional signaling context for fresh-mapping punch
    /// generations.  Present whenever the UDP transport, control plane and
    /// STUN observers are available.
    async fn hole_punch_signal_context(&self) -> Option<HolePunchSignalContext> {
        Some(HolePunchSignalContext {
            control: self.control.clone(),
            local_candidates: self.local_candidates.clone(),
            local_candidate_sources: self.local_candidate_sources.clone(),
            stun_servers: self.runtime_stun_servers.read().await.clone(),
            stun_timeout: *self.runtime_stun_timeout.read().await,
            boot_epoch_ms: self.boot_epoch_ms,
        })
    }

    async fn current_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        let _refresh_guard = self.candidate_refresh_lock.lock().await;
        (
            self.local_candidates.read().await.clone(),
            self.local_candidate_sources.read().await.clone(),
        )
    }

    /// Snapshot the cached candidate set WITHOUT taking the refresh lock.
    ///
    /// Used only by the responder answer path: a live STUN refresh must never
    /// delay the answer, so the snapshot may be momentarily inconsistent with
    /// the source map.  That is harmless for a best-effort signal payload (a
    /// missing source label is ignored by the server).
    async fn cached_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        (
            self.local_candidates.read().await.clone(),
            self.local_candidate_sources.read().await.clone(),
        )
    }

    async fn wait_for_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(50);
        let timeout = Duration::from_millis(CANDIDATE_READY_TIMEOUT_MS);

        loop {
            let (candidates, candidate_sources) = self.current_local_candidate_set().await;
            if !candidates.is_empty() {
                return (candidates, candidate_sources);
            }
            if waited >= timeout {
                warn!(
                    "Proceeding with WireGuard signaling before UDP candidates are ready after {} ms",
                    timeout.as_millis()
                );
                return (candidates, candidate_sources);
            }
            sleep(step).await;
            waited += step;
        }
    }

    async fn local_candidate_set_for_signal(
        &self,
        reason: &str,
    ) -> (Vec<String>, HashMap<String, String>) {
        if let Some(udp) = self.udp_transport.read().await.clone() {
            if let Some(refreshed) = self
                .refresh_local_candidates_for_imminent_signal(&udp, reason)
                .await
            {
                return refreshed;
            }
        }
        self.wait_for_local_candidate_set().await
    }

    async fn add_local_peer_reflexive_candidate(&self, observed_endpoint: &str) -> bool {
        let _refresh_guard = self.candidate_refresh_lock.lock().await;
        let mut candidates = self.local_candidates.write().await;
        let mut candidate_sources = self.local_candidate_sources.write().await;
        match add_peer_reflexive_candidate_to_set(
            observed_endpoint,
            &mut candidates,
            &mut candidate_sources,
        ) {
            Ok(true) => {
                info!(
                    "Updated relay-assisted peer-reflexive local UDP candidate {}",
                    observed_endpoint
                );
                true
            }
            Ok(false) => false,
            Err(err) => {
                warn!(
                    "Ignoring invalid relay-assisted peer-reflexive endpoint '{}': {err}",
                    observed_endpoint
                );
                false
            }
        }
    }

    async fn publish_current_candidates_to_peer(&self, node_id: &str, reason: &str) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!(
                "UDP transport is not ready; skipping {reason} candidate publication to {node_id}"
            );
            return;
        };
        let (candidates, candidate_sources) = if let Some(refreshed) = self
            .refresh_local_candidates_for_imminent_signal(&udp, reason)
            .await
        {
            refreshed
        } else {
            self.current_local_candidate_set().await
        };
        if candidates.is_empty() {
            debug!("Local UDP candidates are not ready; skipping {reason} candidate publication to {node_id}");
            return;
        }
        let punch_at_ms = Some(relay_assisted_punch_at_ms());

        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_and_punch_at(
                node_id,
                &candidates,
                &candidate_sources,
                &[],
                punch_at_ms,
                None,
            )
            .await
        {
            warn!("Failed to publish {reason} UDP candidates to peer {node_id}: {error}");
            return;
        }

        info!(
            "Published {reason} UDP candidates to peer {node_id} ({} candidates) punch_at_ms={punch_at_ms:?}",
            candidates.len()
        );
        if self.peers.should_defer_relay_assisted_punch(node_id).await {
            debug!(
                "Skipping relay-assisted punch for {node_id}: healthy confirmed Direct path is active"
            );
            return;
        }
        let attempts = self
            .peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        let signal = self.hole_punch_signal_context().await;
        spawn_hole_punch_task(
            udp,
            self.peers.clone(),
            self.punch_attempts.clone(),
            node_id.to_string(),
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
            signal,
            None,
            None,
        )
        .await;
    }

    async fn refresh_local_candidates_for_imminent_signal(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<(Vec<String>, HashMap<String, String>)> {
        let refreshed = self.refresh_local_candidates_core(udp, reason).await?;
        if let Some(endpoint) =
            control_udp_endpoint_from_candidates(&refreshed.0, &refreshed.1)
        {
            // The endpoint publish travels the handshake control lane with a
            // short caller budget: the ordinary lane may be congested by
            // candidate-only traffic and must never delay the signal that
            // follows this refresh.
            match tokio::time::timeout(
                Duration::from_millis(PRE_SIGNAL_ENDPOINT_PUBLISH_BUDGET_MS),
                self.control.update_endpoint_for_handshake(&endpoint, "unknown"),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!("Failed to publish pre-signal UDP endpoint '{endpoint}': {err}")
                }
                Err(_) => {
                    debug!(
                        "Pre-signal UDP endpoint publish '{endpoint}' exceeded its budget"
                    )
                }
            }
        }
        Some(refreshed)
    }

    /// Bounded, best-effort candidate refresh that runs only AFTER a responder
    /// answer has been issued.  The answer itself uses the cached candidate
    /// snapshot; this background step keeps future candidate-only publishes
    /// and the server-side endpoint fresh.  It never blocks the answer, never
    /// waits on the ordinary control FIFO (the endpoint publish travels the
    /// handshake control lane), and is aborted by the caller when PeerLeft or
    /// an owner replacement fires.
    async fn post_answer_candidate_refresh_and_endpoint_publish(&self) {
        let _deadline_guard = tokio::time::timeout(
            Duration::from_secs(POST_ANSWER_REFRESH_DEADLINE_SECS),
            async {
                let Some(udp) = self.udp_transport.read().await.clone() else {
                    return;
                };
                let Some((candidates, candidate_sources)) = self
                    .refresh_local_candidates_core(&udp, "post-answer")
                    .await
                else {
                    return;
                };
                if let Some(endpoint) =
                    control_udp_endpoint_from_candidates(&candidates, &candidate_sources)
                {
                    if let Err(err) = self
                        .control
                        .update_endpoint_for_handshake(&endpoint, "unknown")
                        .await
                    {
                        warn!(
                            "Failed to publish post-answer UDP endpoint '{endpoint}': {err}"
                        );
                    }
                }
            },
        )
        .await;
    }

    async fn refresh_local_candidates_core(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<(Vec<String>, HashMap<String, String>)> {
        let _refresh_guard = self.candidate_refresh_lock.lock().await;
        let stun_servers = self.runtime_stun_servers.read().await.clone();
        if stun_servers.is_empty() {
            return None;
        }
        let stun_timeout = *self.runtime_stun_timeout.read().await;
        let report = match udp
            .gather_candidate_report_live(stun_servers, stun_timeout)
            .await
        {
            Ok(report) => report,
            Err(err) => {
                warn!("Pre-signal UDP candidate refresh failed for {reason}: {err}");
                return None;
            }
        };

        self.peers.update_nat_profile(report.nat_profile.clone()).await;
        *self.nat_profile.write().await = Some(report.nat_profile.clone());

        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        let include_host_candidate = self.peers.gather_host_candidates().await;
        if let Some(endpoint) = udp.local_addr().ok().and_then(|local_addr| {
            advertised_udp_endpoint(
                local_addr,
                self.config.network.udp_advertise.as_deref(),
                &candidates,
                include_host_candidate,
            )
        }) {
            if !candidates.contains(&endpoint) {
                candidates.insert(0, endpoint.clone());
            }
            candidate_sources.entry(endpoint.clone()).or_insert_with(|| {
                if self
                    .config
                    .network
                    .udp_advertise
                    .as_deref()
                    .is_some_and(|configured| {
                        !configured.trim().is_empty() && configured.trim() == endpoint
                    })
                {
                    "manual".to_string()
                } else {
                    "host".to_string()
                }
            });
        }

        let previous_candidates = self.local_candidates.read().await.clone();
        let previous_candidate_sources = self.local_candidate_sources.read().await.clone();
        let next_network_identity = prepare_signal_candidates_and_network_identity(
            &previous_candidates,
            &previous_candidate_sources,
            &mut candidates,
            &mut candidate_sources,
        );
        let previous_network_identity = self.local_network_identity.read().await.clone();
        let should_advance_generation =
            !previous_network_identity.is_empty() && previous_network_identity != next_network_identity;
        let change_reason = candidate_set_change_reason(
            &previous_candidates,
            &candidates,
            &previous_candidate_sources,
            &candidate_sources,
        );
        let old_hash = candidate_set_hash(&previous_candidates, &previous_candidate_sources);
        let new_hash = candidate_set_hash(&candidates, &candidate_sources);
        let old_candidate_count = previous_candidates.len();
        let new_candidate_count = candidates.len();
        let real_change = change_reason != "no_change" && change_reason != "order_only";

        if candidate_refresh_requires_commit(real_change, should_advance_generation) {
            *self.local_candidates.write().await = candidates.clone();
            *self.local_candidate_sources.write().await = candidate_sources.clone();
            *self.local_network_identity.write().await = next_network_identity;
            if should_advance_generation {
                self.peers
                    .advance_candidate_refresh_generation("pre-signal UDP candidate refresh")
                    .await;
            }
            info!(
                "Pre-signal UDP candidates refreshed for {reason}; {} candidates (mapping={:?}, public={:?}, old_hash={old_hash}, new_hash={new_hash}, changed_reason={change_reason}, old_candidate_count={old_candidate_count}, new_candidate_count={new_candidate_count})",
                candidates.len(),
                report.nat_profile.mapping_behavior,
                report.nat_profile.public_endpoint
            );
            debug!(
                "Pre-signal UDP candidate set diff for {reason}: changed_reason={change_reason} old_candidates={previous_candidates:?} new_candidates={candidates:?}"
            );
        } else {
            debug!(
                "Pre-signal UDP candidate refresh for {reason} kept the existing {} candidates (old_hash={old_hash} new_hash={new_hash} changed_reason={change_reason})",
                candidates.len()
            );
        }

        Some((candidates, candidate_sources))
    }

    async fn start_hole_punch(&self, node_id: &str) {
        self.start_hole_punch_at(node_id, None, None, None).await;
    }

    /// Start a synchronized hole punch for `node_id`.
    ///
    /// `frozen_targets` is only Some for a fresh-mapping prediction session:
    /// the immutable candidate snapshot frozen when the fresh signal arrived.
    /// A later ordinary refresh may update the shared candidate set, but it
    /// must never change the target of a running fresh session.
    async fn start_hole_punch_at(
        &self,
        node_id: &str,
        punch_at_ms: Option<u64>,
        fresh_prediction: Option<FreshPredictionId>,
        frozen_targets: Option<Vec<SocketAddr>>,
    ) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!("UDP transport is not ready; skipping hole punch for {node_id}");
            return;
        };

        let Some(conn) = self.peers.get_connection(node_id).await else {
            debug!("No peer connection for {node_id}; skipping hole punch");
            return;
        };

        if self.peers.should_defer_relay_assisted_punch(node_id).await {
            debug!(
                "Skipping relay-assisted punch for {node_id}: healthy confirmed Direct path is active"
            );
            return;
        }

        if self.local_candidates.read().await.is_empty() {
            self.peers
                .record_direct_event(
                    node_id,
                    "punch_delayed_local_candidates_not_ready",
                    None,
                    Some(0),
                    None,
                    "delayed UDP punch until local candidates are ready",
                )
                .await;
            debug!("Local UDP candidates are not ready; delaying hole punch for {node_id}");
            return;
        }

        if !matches!(conn.state, ConnectionState::Direct | ConnectionState::Relay) {
            self.peers
                .update_state(node_id, ConnectionState::HolePunching)
                .await;
        }

        let peer_id = node_id.to_string();
        let peers = self.peers.clone();
        let attempts = peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        let signal = self.hole_punch_signal_context().await;
        spawn_hole_punch_task(
            udp,
            peers,
            self.punch_attempts.clone(),
            peer_id,
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
            signal,
            fresh_prediction,
            frozen_targets,
        )
        .await;
    }


}
