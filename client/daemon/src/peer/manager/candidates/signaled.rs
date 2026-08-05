impl PeerManager {
    /// Add ICE candidates for a peer.
    pub async fn add_candidates(&self, node_id: &str, candidates: &[String]) {
        // This compatibility API has always meant explicitly signaled
        // candidates.  Preserve that behavior; wire signals which genuinely
        // omit metadata enter through `add_candidates_with_metadata` and are
        // classified from their address there.
        let sources = candidates
            .iter()
            .cloned()
            .map(|candidate| (candidate, "signaled".to_string()))
            .collect::<HashMap<_, _>>();
        self.add_candidates_with_metadata(node_id, candidates, &sources, 0, None)
            .await;
    }

    /// Add ICE candidates plus optional source metadata for a peer.
    pub async fn add_candidates_with_sources(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
    ) {
        self.add_candidates_with_metadata(node_id, candidates, candidate_sources, 0, None)
            .await;
    }

    /// Install a versioned candidate set, ignoring a stale signal or an
    /// already-expired set before it can reintroduce old NAT ports.
    pub async fn add_candidates_with_metadata(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
    ) -> CandidateSetApplyResult {
        let generation = self.current_network_generation().await;
        let mut connections = self.connections.write().await;
        let Some(conn) = connections.get_mut(node_id) else {
            return CandidateSetApplyResult::PeerMissing;
        };
        let valid_candidates = candidates
            .iter()
            .filter(|candidate| candidate.parse::<SocketAddr>().is_ok())
            .cloned()
            .collect::<Vec<_>>();
        if valid_candidates.is_empty() {
            conn.record_direct_event(
                generation,
                "candidates_empty",
                None,
                Some(candidates.len()),
                None,
                "ignored empty or entirely invalid signaled UDP candidate set",
            );
            return CandidateSetApplyResult::IgnoredEmpty;
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if candidates_expires_at_ms.is_some_and(|expires_at| {
            expires_at.saturating_add(CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS) <= now_ms
        }) {
            conn.record_direct_event(
                generation,
                "candidates_expired",
                None,
                Some(valid_candidates.len()),
                None,
                "ignored expired signaled UDP candidate set",
            );
            return CandidateSetApplyResult::IgnoredExpired;
        }
        if candidate_generation != 0 && candidate_generation <= conn.last_candidate_generation {
            conn.record_direct_event(
                generation,
                "candidates_stale",
                None,
                Some(valid_candidates.len()),
                None,
                format!("ignored stale candidate generation {candidate_generation}"),
            );
            return CandidateSetApplyResult::IgnoredStale;
        }
        if candidate_generation != 0 {
            conn.last_candidate_generation = candidate_generation;
        }
        conn.last_candidates_expires_at_ms = candidates_expires_at_ms;
            let old_signaled_endpoint = conn.signaled_endpoint;
            let previous_signaled = std::mem::take(&mut conn.signaled_candidates);
            let endpoint_was_previous_signaled = conn.endpoint.is_some_and(|endpoint| {
                previous_signaled.contains(&endpoint.to_string())
            });
            for candidate in previous_signaled {
                let learned = matches!(
                    conn.candidate_sources.get(&candidate),
                    Some(CandidatePairSource::Learned | CandidatePairSource::PeerReflexive)
                );
                if !learned {
                    conn.candidates.retain(|existing| existing != &candidate);
                    conn.candidate_sources.remove(&candidate);
                }
            }

            if endpoint_was_previous_signaled
                && conn.endpoint.is_some_and(|endpoint| {
                    !valid_candidates
                        .iter()
                        .any(|candidate| candidate == &endpoint.to_string())
                })
            {
                conn.endpoint = None;
            }

            // A current trickled signal is authoritative.  Keeping the node
            // registry's old endpoint forever causes port churn to accumulate
            // stale public targets and wastes each synchronized punch window.
            if !valid_candidates.is_empty() {
                if let Some(endpoint) = old_signaled_endpoint {
                    if !valid_candidates
                        .iter()
                        .any(|candidate| candidate == &endpoint.to_string())
                    {
                        conn.signaled_endpoint = None;
                        if conn.endpoint == Some(endpoint) {
                            conn.endpoint = None;
                        }
                        let endpoint = endpoint.to_string();
                        if conn.candidate_sources.get(&endpoint)
                            == Some(&CandidatePairSource::Signaled)
                        {
                            conn.candidates.retain(|candidate| candidate != &endpoint);
                            conn.candidate_sources.remove(&endpoint);
                        }
                    }
                }
            }

            for c in &valid_candidates {
                if !conn.candidates.contains(c) {
                    conn.candidates.push(c.clone());
                }
                conn.signaled_candidates.insert(c.clone());
                // Old peers did not send candidate_sources.  Classifying
                // their literal socket address keeps a private LAN candidate
                // from taking precedence over a public server-reflexive one.
                let source = candidate_sources
                    .get(c)
                    .and_then(|value| candidate_pair_source_from_label(value))
                    .unwrap_or_else(|| infer_unlabeled_candidate_source(c));
                conn.candidate_sources.insert(c.clone(), source);
                if let Ok(endpoint) = c.parse::<SocketAddr>() {
                    conn.ensure_candidate_pair_with_observed_source(endpoint, generation, source);
                }
            }

            if !valid_candidates.is_empty() {
                conn.record_direct_event(
                    generation,
                    "candidates_received",
                    None,
                    Some(valid_candidates.len()),
                    None,
                    format!(
                        "received {} signaled UDP candidates with {} source labels",
                        valid_candidates.len(),
                        candidate_sources.len()
                    ),
                );
            }

            if conn.endpoint.is_none() {
                conn.endpoint = conn
                    .candidates
                    .iter()
                    .find_map(|candidate| candidate.parse::<SocketAddr>().ok());
            }
        CandidateSetApplyResult::Applied
    }

}
