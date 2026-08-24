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
        self.add_candidates_with_metadata_for_identity_with_hard_hard_retire(
            node_id,
            candidates,
            candidate_sources,
            candidate_generation,
            candidates_expires_at_ms,
            None,
            true,
        )
        .await
    }

    /// Identity-bound candidate apply used by control-plane signals.
    ///
    /// The sender fingerprint is checked inside the same epoch/connection
    /// transaction that mutates candidate state. A public-key update therefore
    /// linearizes wholly before or wholly after this apply; a queued signal from
    /// the retired identity can never populate the replacement connection.
    pub(crate) async fn add_candidates_with_metadata_for_identity(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
    ) -> CandidateSetApplyResult {
        self.add_candidates_with_metadata_for_identity_with_hard_hard_retire(
            node_id,
            candidates,
            candidate_sources,
            candidate_generation,
            candidates_expires_at_ms,
            sender_public_key,
            false,
        )
        .await
    }

    async fn add_candidates_with_metadata_for_identity_with_hard_hard_retire(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
        retire_hard_hard: bool,
    ) -> CandidateSetApplyResult {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let generation = self.current_network_generation_sync();
        let mut connections = self.connections.write().await;
        let Some(conn) = connections.get_mut(node_id) else {
            return CandidateSetApplyResult::PeerMissing;
        };
        if sender_public_key.map(str::trim).is_some_and(|public_key| {
            public_key.is_empty() || conn.public_key.trim() != public_key
        }) {
            conn.record_direct_event(
                generation,
                "candidates_stale_identity",
                None,
                Some(candidates.len()),
                None,
                "ignored candidate signal bound to a retired sender public key",
            );
            return CandidateSetApplyResult::IgnoredStale;
        }
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
        let candidate_incarnation =
            crate::control::candidate_generation_incarnation(candidate_generation);
        if crate::control::candidate_generation_is_malformed_encoded(candidate_generation) {
            conn.record_direct_event(
                generation,
                "candidates_invalid_generation",
                None,
                Some(valid_candidates.len()),
                None,
                format!(
                    "ignored malformed incarnation-encoded candidate generation {candidate_generation}"
                ),
            );
            return CandidateSetApplyResult::IgnoredStale;
        }
        if candidate_incarnation.is_some_and(|incoming| {
            conn.remote_candidate_incarnation_high_water
                .is_some_and(|accepted| incoming < accepted)
        }) {
            conn.record_direct_event(
                generation,
                "candidates_stale_incarnation",
                None,
                Some(valid_candidates.len()),
                None,
                format!(
                    "ignored candidate generation {candidate_generation} from a retired remote incarnation"
                ),
            );
            return CandidateSetApplyResult::IgnoredStale;
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
            self.record_remote_candidate_generation_replay_floor(
                node_id,
                &conn.public_key,
                candidate_generation,
            );
        }
        if let Some(incarnation) = candidate_incarnation {
            conn.remote_candidate_incarnation_high_water = Some(
                conn.remote_candidate_incarnation_high_water
                    .map_or(incarnation, |accepted| accepted.max(incarnation)),
            );
            self.record_remote_candidate_incarnation_high_water(
                node_id,
                &conn.public_key,
                incarnation,
            );
        }
        conn.last_candidates_expires_at_ms = candidates_expires_at_ms;

        // `candidate_generation` is a freshness revision, not proof that the
        // peer rebound its UDP transport.  Production assigns a new revision
        // to every offer/answer (including routine WireGuard rekeys), so only
        // an actual endpoint-set change may advance the remote transport epoch.
        let incoming_signaled = valid_candidates.iter().cloned().collect::<HashSet<_>>();
        let remote_candidate_set_changed = conn.signaled_candidates != incoming_signaled;
        // Make-before-break for an encrypted-confirmed Direct path: a revised
        // set that still advertises the selected endpoint is continuity of the
        // same live remote transport.  Alternate candidates may be added or
        // withdrawn without tearing down that proven path.  If the selected
        // endpoint disappears (or there is no Direct proof), the change is a
        // real handover and retains the strict epoch/cancellation fence.
        let retained_direct_endpoint = remote_candidate_set_changed
            .then(|| {
                (conn.state == ConnectionState::Direct)
                    .then(|| conn.selected_direct_endpoint_for_consent(generation))
                    .flatten()
                    .filter(|endpoint| incoming_signaled.contains(&endpoint.to_string()))
            })
            .flatten();
        let remote_transport_handover =
            remote_candidate_set_changed && retained_direct_endpoint.is_none();
        if remote_transport_handover {
            conn.mark_remote_transport_handover(
                generation,
                "accepted remote candidate set that replaced the active transport context",
            );
            conn.direct_commit_seq = conn.direct_commit_seq.wrapping_add(1);
            self.bump_direct_commit_seq(node_id);
        }

        let old_signaled_endpoint = conn.signaled_endpoint;
        let previous_signaled = std::mem::take(&mut conn.signaled_candidates);
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

        // A current trickled signal is authoritative. Keeping the node
        // registry's old endpoint forever causes port churn to accumulate
        // stale public targets and wastes each synchronized punch window.
        if let Some(endpoint) = old_signaled_endpoint {
            if !valid_candidates
                .iter()
                .any(|candidate| candidate == &endpoint.to_string())
            {
                conn.signaled_endpoint = None;
                let endpoint = endpoint.to_string();
                if conn.candidate_sources.get(&endpoint) == Some(&CandidatePairSource::Signaled) {
                    conn.candidates.retain(|candidate| candidate != &endpoint);
                    conn.candidate_sources.remove(&endpoint);
                }
            }
        }

        for (rank, c) in valid_candidates.iter().enumerate() {
            if !conn.candidates.contains(c) {
                conn.candidates.push(c.clone());
            }
            conn.signaled_candidates.insert(c.clone());
            // Old peers did not send candidate_sources. Classifying their
            // literal socket address keeps a private LAN candidate from
            // taking precedence over a public server-reflexive one.
            let source = candidate_sources
                .get(c)
                .and_then(|value| candidate_pair_source_from_label(value))
                .unwrap_or_else(|| infer_unlabeled_candidate_source(c));
            conn.candidate_sources.insert(c.clone(), source);
            if let Ok(endpoint) = c.parse::<SocketAddr>() {
                let pair =
                    conn.ensure_candidate_pair_with_observed_source(endpoint, generation, source);
                // The sender ordered its predicted window by priority;
                // preserve that order for stable-side probing.
                if source == CandidatePairSource::Predicted {
                    pair.signal_rank = Some(rank as u32);
                }
            }
        }

        if let Some(endpoint) = retained_direct_endpoint {
            let retired_pairs = conn.retire_withdrawn_signaled_candidate_pairs(
                &incoming_signaled,
                "candidate revision withdrew an alternate endpoint while retaining the encrypted-confirmed Direct transport",
            );
            conn.mark_remote_candidate_revision_with_direct_continuity(
                generation,
                endpoint,
                candidate_generation,
                retired_pairs,
            );
        } else if !remote_candidate_set_changed && candidate_generation != 0 {
            conn.record_direct_event(
                generation,
                "candidate_revision_refreshed",
                conn.endpoint,
                Some(valid_candidates.len()),
                None,
                format!(
                    "accepted freshness revision {candidate_generation} for an unchanged remote candidate set; transport epoch retained"
                ),
            );
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
            conn.endpoint = valid_candidates
                .iter()
                .find_map(|candidate| candidate.parse::<SocketAddr>().ok());
        }
        drop(connections);
        if remote_transport_handover {
            self.cancel_direct_validation_for_remote_candidate_change(node_id)
                .await;
            if retire_hard_hard {
                // Candidate handover retires the complete direct transport
                // context. Control-event ingress applies the candidate set
                // before its hh1 response/offer handler, so identity-bound
                // control updates deliberately retain the current ledger
                // until that handler can validate the session role.
                self.clear_hard_hard_sessions(Some(node_id)).await;
            }
        }
        CandidateSetApplyResult::Applied
    }

}
