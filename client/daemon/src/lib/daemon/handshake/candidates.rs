impl Daemon {
    async fn wait_for_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(50);
        let timeout = Duration::from_millis(CANDIDATE_READY_TIMEOUT_MS);

        loop {
            let candidates = self.local_candidates.read().await.clone();
            let candidate_sources = self.local_candidate_sources.read().await.clone();
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

    async fn add_local_peer_reflexive_candidate(&self, observed_endpoint: &str) -> bool {
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
        let candidates = self.local_candidates.read().await.clone();
        if candidates.is_empty() {
            debug!("Local UDP candidates are not ready; skipping {reason} candidate publication to {node_id}");
            return;
        }
        let candidate_sources = self.local_candidate_sources.read().await.clone();
        let punch_at_ms = Some(relay_assisted_punch_at_ms());

        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_and_punch_at(
                node_id,
                &candidates,
                &candidate_sources,
                &[],
                punch_at_ms,
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
        let attempts = self
            .peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        spawn_hole_punch_task(
            udp,
            self.peers.clone(),
            self.punch_attempts.clone(),
            node_id.to_string(),
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
        )
        .await;
    }

    async fn start_hole_punch(&self, node_id: &str) {
        self.start_hole_punch_at(node_id, None).await;
    }

    async fn start_hole_punch_at(&self, node_id: &str, punch_at_ms: Option<u64>) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!("UDP transport is not ready; skipping hole punch for {node_id}");
            return;
        };

        let Some(conn) = self.peers.get_connection(node_id).await else {
            debug!("No peer connection for {node_id}; skipping hole punch");
            return;
        };

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
        spawn_hole_punch_task(
            udp,
            peers,
            self.punch_attempts.clone(),
            peer_id,
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
        )
        .await;
    }


}
