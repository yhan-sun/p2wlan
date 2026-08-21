impl PeerManager {
    /// Whether a bidirectional UDP probe succeeded in the current generation.
    pub async fn has_direct_probe_success_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> bool {
        generation == self.current_network_generation().await
            && self
                .connections
                .read()
                .await
                .get(node_id)
                .is_some_and(|conn| {
                    conn.candidate_pairs.iter().any(|pair| {
                        pair.local_generation == generation
                            && conn.pair_belongs_to_current_remote_epoch(pair)
                            && matches!(
                                pair.state,
                                CandidatePairState::Succeeded | CandidatePairState::Selected
                            )
                    })
                })
    }

    /// Monotonic count of matched bidirectional probe ACKs for one peer and
    /// generation. Callers can snapshot this before a probe round and require
    /// it to increase, avoiding false success from an older Succeeded pair.
    pub async fn direct_probe_success_count_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> u64 {
        if generation != self.current_network_generation().await {
            return 0;
        }
        let connections = self.connections.read().await;
        let Some(conn) = connections.get(node_id) else {
            return 0;
        };
        conn.candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == generation
                    && conn.pair_belongs_to_current_remote_epoch(pair)
            })
            .map(|pair| pair.success_count)
            .sum()
    }
}
