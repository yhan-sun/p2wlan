impl PeerManager {
    /// Learn an endpoint from an authenticated Probe v2 packet.
    ///
    /// Unlike legacy endpoint learning, this may accept a peer-reflexive source
    /// address that was not present in the control-plane candidate set because
    /// the probe MAC proves the sender controls the peer identity.
    pub async fn learn_authenticated_endpoint(&self, node_id: &str, endpoint: SocketAddr) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };

        if let Some(previous_endpoint) = conn.endpoint {
            let previous_endpoint_text = previous_endpoint.to_string();
            if !conn.candidates.contains(&previous_endpoint_text) {
                conn.candidates.push(previous_endpoint_text);
            }
        }
        conn.endpoint = Some(endpoint);
        let endpoint_text = endpoint.to_string();
        if !conn.candidates.contains(&endpoint_text) {
            conn.candidates.push(endpoint_text.clone());
        }
        conn.candidate_sources
            .insert(endpoint_text, CandidatePairSource::PeerReflexive);
        conn.mark_candidate_pair_probing_with_source(
            endpoint,
            generation,
            CandidatePairSource::PeerReflexive,
        );
        let pruned = conn.prune_stale_peer_reflexive_candidates_for_ip(endpoint, generation);
        if pruned > 0 {
            conn.record_direct_event(
                generation,
                "peer_reflexive_window_pruned",
                Some(endpoint),
                Some(conn.candidates.len()),
                None,
                format!(
                    "pruned {pruned} stale peer-reflexive UDP ports for {}",
                    endpoint.ip()
                ),
            );
        }
        true
    }

    /// Learn an endpoint from a legacy ACK correlated to an outstanding nonce.
    ///
    /// The caller must verify the nonce, generation, local socket, and source
    /// IP before using this method. Unlike Probe v2 learning, this endpoint is
    /// deliberately classified as merely learned rather than peer-reflexive.
    pub async fn learn_correlated_probe_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
    ) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };

        if let Some(previous_endpoint) = conn.endpoint {
            let previous_endpoint_text = previous_endpoint.to_string();
            if !conn.candidates.contains(&previous_endpoint_text) {
                conn.candidates.push(previous_endpoint_text);
            }
        }
        conn.endpoint = Some(endpoint);
        let endpoint_text = endpoint.to_string();
        if !conn.candidates.contains(&endpoint_text) {
            conn.candidates.push(endpoint_text.clone());
        }
        conn.candidate_sources
            .insert(endpoint_text, CandidatePairSource::Learned);
        conn.mark_candidate_pair_probing_with_source(
            endpoint,
            generation,
            CandidatePairSource::Learned,
        );
        true
    }

    /// Learn a candidate endpoint after receiving a probe or packet from that address.
    ///
    /// This intentionally does not mark the peer as Direct. UDP punch probes only
    /// prove that a candidate address is visible; the direct path is confirmed
    /// only after an encrypted WireGuard packet decrypts successfully.
    pub async fn learn_endpoint_from_addr(&self, endpoint: SocketAddr) -> Option<String> {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;

        for (node_id, conn) in conns.iter_mut() {
            let matches_candidate = conn
                .candidates
                .iter()
                .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
                .any(|candidate| candidate == endpoint);
            let matches_current = conn.endpoint == Some(endpoint);

            if matches_candidate || matches_current {
                conn.endpoint = Some(endpoint);
                conn.candidate_sources
                    .insert(endpoint.to_string(), CandidatePairSource::Learned);
                conn.mark_candidate_pair_probing_with_source(
                    endpoint,
                    generation,
                    CandidatePairSource::Learned,
                );
                return Some(node_id.clone());
            }
        }

        None
    }

    /// Record an authenticated remote ICE-style nomination check.
    ///
    /// This marks the candidate pair as nominated/trial-ready, but it still does not select
    /// Direct; encrypted data must decrypt successfully before the path becomes confirmed.
    pub async fn record_direct_nomination_check_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.mark_candidate_pair_probing_with_local_endpoint(endpoint, generation, local_endpoint);
        conn.mark_candidate_pair_nominated(
            endpoint,
            generation,
            local_endpoint,
            "received authenticated use_candidate connectivity check",
        )
        .is_some()
    }

    /// Backwards-compatible alias for endpoint learning.
    pub async fn select_endpoint_from_addr(&self, endpoint: SocketAddr) -> Option<String> {
        self.learn_endpoint_from_addr(endpoint).await
    }

}
