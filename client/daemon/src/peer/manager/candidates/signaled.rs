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
        match self
            .add_candidates_with_metadata_for_identity_with_hard_hard_retire(
                node_id,
                candidates,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
                None,
                true,
                false,
            )
            .await
        {
            CandidateSetTryApplyOutcome::Completed(result) => result,
            CandidateSetTryApplyOutcome::ContendedEpoch
            | CandidateSetTryApplyOutcome::ContendedConnections => {
                unreachable!("blocking candidate transaction returned contention")
            }
        }
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
        match self
            .add_candidates_with_metadata_for_identity_with_hard_hard_retire(
                node_id,
                candidates,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
                sender_public_key,
                false,
                false,
            )
            .await
        {
            CandidateSetTryApplyOutcome::Completed(result) => result,
            CandidateSetTryApplyOutcome::ContendedEpoch
            | CandidateSetTryApplyOutcome::ContendedConnections => {
                unreachable!("blocking candidate transaction returned contention")
            }
        }
    }

    /// Apply one identity-bound control-plane candidate revision without
    /// queueing on either canonical lifecycle lock. The caller owns the
    /// bounded newest-wins retry ledger. Once both guards are acquired, the
    /// existing epoch fence remains held through the post-commit cancellation
    /// transaction, but connection-lock contention is never awaited while
    /// that epoch fence is owned.
    pub(crate) async fn try_add_candidates_with_metadata_for_identity(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
    ) -> CandidateSetTryApplyOutcome {
        self.add_candidates_with_metadata_for_identity_with_hard_hard_retire(
            node_id,
            candidates,
            candidate_sources,
            candidate_generation,
            candidates_expires_at_ms,
            sender_public_key,
            false,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn add_candidates_with_metadata_for_identity_with_hard_hard_retire(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
        sender_public_key: Option<&str>,
        retire_hard_hard: bool,
        non_queuing: bool,
    ) -> CandidateSetTryApplyOutcome {
        let epoch_gate = self.network_epoch_gate();
        let (_epoch_guard, mut connections) = loop {
            let epoch_guard = if non_queuing {
                let Ok(guard) = epoch_gate.try_lock() else {
                    return CandidateSetTryApplyOutcome::ContendedEpoch;
                };
                guard
            } else {
                epoch_gate.lock().await
            };
            match self.connections.try_write() {
                Ok(connections) => break (epoch_guard, connections),
                Err(_) if non_queuing => {
                    return CandidateSetTryApplyOutcome::ContendedConnections;
                }
                Err(_) => {
                    // Preserve the canonical epoch -> connections order for
                    // mutation, but never join Tokio's writer queue while the
                    // epoch is held. Taking and immediately releasing a writer
                    // turn without the epoch lets an older reader finish its
                    // epoch-fenced work before this transaction retries.
                    drop(epoch_guard);
                    drop(self.connections.write().await);
                }
            }
        };
        let generation = self.current_network_generation_sync();
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::PeerMissing);
        };
        let Some(conn) = connections.get_mut(node_id) else {
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::PeerMissing);
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
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::IgnoredStale);
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
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::IgnoredEmpty);
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
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::IgnoredExpired);
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
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::IgnoredStale);
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
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::IgnoredStale);
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
            return CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::IgnoredStale);
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
        // set is continuity of the same live remote transport even when the
        // selected endpoint is peer-reflexive, predicted, or simply omitted
        // from a volatile refresh.  The authenticated Direct path is stronger
        // evidence than the latest signaled candidate list; consent/keepalive
        // failure remains the hard liveness fence that can demote it.  Without
        // Direct proof, a changed set is still a real handover and retains the
        // strict epoch/cancellation fence.
        // The generation comparison is defense-in-depth: public lifecycle
        // transitions update both values under the shared epoch gate, while
        // this guard also rejects a synthetic invariant violation.
        let retained_direct_endpoint = remote_candidate_set_changed
            .then(|| {
                (conn.state == ConnectionState::Direct
                    && conn.direct_generation == generation)
                    .then(|| conn.selected_direct_endpoint_for_consent(generation))
                    .flatten()
            })
            .flatten();
        let remote_transport_handover =
            remote_candidate_set_changed && retained_direct_endpoint.is_none();
        if remote_transport_handover {
            conn.mark_remote_transport_handover(
                generation,
                peer_session_generation,
                "accepted remote candidate set that replaced the active transport context",
            );
            conn.direct_commit_seq = conn.direct_commit_seq.wrapping_add(1);
            self.bump_direct_commit_seq(node_id);
        }

        let old_signaled_endpoint = conn.signaled_endpoint;
        let previous_signaled = std::mem::take(&mut conn.signaled_candidates);
        for candidate in previous_signaled {
            let retained_direct_candidate = retained_direct_endpoint.is_some_and(|endpoint| {
                candidate
                    .parse::<SocketAddr>()
                    .is_ok_and(|candidate_endpoint| candidate_endpoint == endpoint)
            });
            let learned = matches!(
                conn.candidate_sources.get(&candidate),
                Some(CandidatePairSource::Learned | CandidatePairSource::PeerReflexive)
            );
            if !learned && !retained_direct_candidate {
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
                && Some(endpoint) != retained_direct_endpoint
            {
                conn.signaled_endpoint = None;
                let endpoint = endpoint.to_string();
                if conn.candidate_sources.get(&endpoint) == Some(&CandidatePairSource::Signaled) {
                    conn.candidates.retain(|candidate| candidate != &endpoint);
                    conn.candidate_sources.remove(&endpoint);
                }
            }
        }

        // Keep the active, encrypted-confirmed endpoint in the candidate
        // registry even if the latest volatile signal omitted it. The normal
        // endpoint/epoch fences still apply, while the Direct consent monitor
        // decides whether the old mapping is actually dead.
        if let Some(endpoint) = retained_direct_endpoint {
            let endpoint_text = endpoint.to_string();
            if !conn.candidates.contains(&endpoint_text) {
                conn.candidates.push(endpoint_text.clone());
            }
            conn.candidate_sources
                .entry(endpoint_text)
                .or_insert(CandidatePairSource::PeerReflexive);
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
                retained_direct_endpoint,
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
            // A changed authenticated candidate set is real transport
            // evidence, not ordinary freshness churn.  If the previous
            // recovery window was frozen after exhausting its scatter
            // credit, give this new mapping a bounded retry window before
            // cancelling the old validation owner.  The recovery ledger
            // caps these re-opens per epoch, so repeated NAT churn cannot
            // turn candidate refreshes into an unbounded punch storm.
            self.recovery_reopen_on_evidence(node_id, "remote_candidate_handover")
                .await;
            self.cancel_direct_validation_for_remote_candidate_change(node_id)
                .await;
            self.cancel_dplpmtud_for_remote_candidate_change(node_id)
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
        CandidateSetTryApplyOutcome::Completed(CandidateSetApplyResult::Applied)
    }

}
