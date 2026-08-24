#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectFailureCommitOutcome {
    Rejected,
    IgnoredConfirmedDirect,
    Applied,
}

impl PeerManager {
    /// Record a failed direct-path event and enter relay fallback state.
    pub async fn record_direct_failure(&self, node_id: &str, reason: impl Into<String>) {
        self.record_direct_failure_with_code(node_id, REASON_DIRECT_PROBE_FAILED, reason)
            .await;
    }

    /// Record a failed direct-path event with a stable reason code.
    pub async fn record_direct_failure_with_code(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.record_direct_failure_with_code_and_local_endpoint(node_id, code, reason, None)
            .await;
    }

    /// Record a failed direct-path event with a stable reason code and local UDP endpoint.
    pub async fn record_direct_failure_with_code_and_local_endpoint(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_failure_for_generation_with_local_endpoint(
            node_id,
            generation,
            code,
            reason,
            local_endpoint,
        )
        .await;
    }

    /// Record a failed direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_failure_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> bool {
        self.record_direct_failure_for_generation_with_local_endpoint(
            node_id, generation, code, reason, None,
        )
        .await
    }

    /// Record a failed direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_failure_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        // Snapshot before the first await. If this work was admitted for one
        // lifecycle and PeerLeft/offline/rejoin wins the epoch gate first, the
        // exact-generation check below rejects the stale commit instead of
        // treating the replacement's `online=true` as equivalent (ABA).
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        self.record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
            node_id,
            generation,
            peer_session_generation,
            code,
            reason,
            local_endpoint,
        )
        .await
    }

    /// Commit a delayed failure only for the lifecycle that admitted the work.
    /// Callers such as handshake timeout owners already carry this stamp and
    /// must not re-snapshot after a leave/rejoin boundary.
    pub(crate) async fn record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        self.record_direct_failure_commit_for_peer_session(
            node_id,
            generation,
            peer_session_generation,
            code,
            reason,
            local_endpoint,
            false,
        )
        .await
            != DirectFailureCommitOutcome::Rejected
    }

    /// Shared exact-lifecycle commit. `ignore_confirmed_direct` is used by
    /// opportunistic probe-batch timeouts: the Direct-state check and the
    /// failure mutation must occur in the same epoch critical section, or a
    /// promotion between two separate checks can be torn down by a late batch.
    #[allow(clippy::too_many_arguments)]
    async fn record_direct_failure_commit_for_peer_session(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
        ignore_confirmed_direct: bool,
    ) -> DirectFailureCommitOutcome {
        let reason = reason.into();
        let code = code.into();
        let epoch_gate = self.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return DirectFailureCommitOutcome::Rejected;
        }
        // NOTE: a no-ACK probe batch must NOT move the recovery stage into
        // RelayBackoff — the stage machine advances Initial -> Predicted ->
        // ScatterSmall -> ScatterExtended on no-ACK feedback (see
        // `record_direct_probe_batch_failure_for_generation`), and marking
        // RelayBackoff here would short-circuit that progression and cap the
        // scan at 96 ports forever.  Only true hard failures (send errors,
        // handshake timeouts) call `mark_recovery_relay_backoff` explicitly.
        let probed_sources = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return DirectFailureCommitOutcome::Rejected;
            };
            if !conn.online || conn.state == ConnectionState::Closed {
                return DirectFailureCommitOutcome::Rejected;
            }
            if ignore_confirmed_direct
                && conn.state == ConnectionState::Direct
                && conn.direct_generation == generation
            {
                conn.record_direct_event(
                    generation,
                    "direct_probe_batch_timeout_ignored",
                    conn.endpoint,
                    Some(conn.candidate_pairs.len()),
                    None,
                    format!("{reason}; ignored because encrypted Direct is already confirmed"),
                );
                debug!(
                    event = "direct_probe_batch_timeout_ignored",
                    peer_id = %node_id,
                    remote_endpoint = ?conn.endpoint,
                    reason = %reason,
                    "ignored background/reclaim Direct probe failure for confirmed Direct peer"
                );
                return DirectFailureCommitOutcome::IgnoredConfirmedDirect;
            }
            conn.direct_health
                .record_failure(code.clone(), reason.clone());
            conn.record_direct_event(
                generation,
                code.clone(),
                conn.endpoint,
                Some(conn.candidate_pairs.len()),
                None,
                reason.clone(),
            );
            let probed_sources =
                conn.mark_current_candidate_pairs_failed(generation, code, reason, local_endpoint);
            if conn.state != ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                info!(
                    event = "direct_path_degraded",
                    peer_id = %node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = ?conn.endpoint,
                    candidate_source = ?conn.endpoint.and_then(|endpoint| {
                        conn.candidate_pairs
                            .iter()
                            .find(|pair| {
                                pair.local_generation == generation
                                    && pair.remote_endpoint == endpoint
                                    && conn.pair_belongs_to_current_remote_epoch(pair)
                            })
                            .map(|pair| pair.source)
                    }),
                    rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                    reason = %conn.direct_health.last_error.as_deref().unwrap_or("direct path failed"),
                    "direct_path_degraded peer_id={} reason={}",
                    node_id,
                    conn.direct_health.last_error.as_deref().unwrap_or("direct path failed")
                );
            }
            probed_sources
        };
        drop(epoch_guard);
        self.record_traversal_failures(probed_sources).await;
        DirectFailureCommitOutcome::Applied
    }

    /// Record a failed background/reclaim probe batch.
    ///
    /// A confirmed Direct path should not be torn down by an opportunistic
    /// retry batch timing out; consent/keepalive failures are the authoritative
    /// signal for degrading an already selected Direct data path.
    pub async fn record_direct_probe_batch_failure_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        reason: impl Into<String>,
    ) -> bool {
        let reason = reason.into();
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        let outcome = self
            .record_direct_failure_commit_for_peer_session(
                node_id,
                generation,
                peer_session_generation,
                REASON_DIRECT_PROBE_FAILED,
                reason.clone(),
                None,
                true,
            )
            .await;
        match outcome {
            DirectFailureCommitOutcome::Rejected => false,
            DirectFailureCommitOutcome::IgnoredConfirmedDirect => true,
            DirectFailureCommitOutcome::Applied => {
                // A batch with zero matched ACKs is the explicit feedback that
                // widens the recovery stage. Bind this secondary ledger write
                // to the same peer lifecycle so a leave/rejoin after the state
                // commit cannot advance the replacement's epoch.
                self.advance_recovery_stage_after_no_ack_for_peer_session(
                    node_id,
                    generation,
                    peer_session_generation,
                    &reason,
                )
                .await;
                true
            }
        }
    }

    /// Record an expected miss from one stable-side birthday window.
    ///
    /// Missing a single probabilistic window is normal and must not increase
    /// peer-level exponential retry backoff.  The candidate pairs are still
    /// marked for source learning.  Only when `completed_epoch` is true (the
    /// absolute-port cursor wrapped after a fully sent window) is the miss
    /// promoted to a peer-level Direct failure.
    pub async fn record_expected_birthday_window_miss_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        endpoints: &[SocketAddr],
        completed_epoch: bool,
        reason: impl Into<String>,
    ) -> bool {
        if endpoints.is_empty() {
            return false;
        }
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        let reason = reason.into();
        let epoch_gate = self.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        let probed_sources = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if !conn.online || conn.state == ConnectionState::Closed {
                return false;
            }

            if conn.state == ConnectionState::Direct && conn.direct_generation == generation {
                conn.record_direct_event(
                    generation,
                    "direct_probe_window_miss_ignored",
                    conn.endpoint,
                    Some(endpoints.len()),
                    None,
                    format!("{reason}; ignored because encrypted Direct is already confirmed"),
                );
                return true;
            }

            let probed_sources = conn.mark_candidate_pairs_failed_for_endpoints(
                generation,
                endpoints,
                REASON_DIRECT_PROBE_FAILED,
                reason.clone(),
                None,
            );
            let stage = if completed_epoch {
                "birthday_probe_epoch_missed"
            } else {
                "birthday_probe_window_missed"
            };
            conn.record_direct_event(
                generation,
                stage,
                conn.endpoint,
                Some(endpoints.len()),
                None,
                format!(
                    "{reason}; completed_epoch={completed_epoch}; peer_backoff_applied={completed_epoch}"
                ),
            );

            if completed_epoch {
                conn.direct_health
                    .record_failure(REASON_DIRECT_PROBE_FAILED, reason.clone());
                if conn.state != ConnectionState::Relay {
                    conn.transition(ConnectionState::FallbackToRelay);
                }
            }
            probed_sources
        };

        drop(epoch_guard);
        self.record_traversal_failures(probed_sources).await;
        true
    }

    /// Record an unanswered direct keepalive without tearing down a path on one lost probe.
    pub async fn record_direct_keepalive_timeout_for_generation(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> bool {
        self.record_direct_keepalive_timeout_for_generation_with_local_endpoint(
            node_id, endpoint, generation, None,
        )
        .await
    }

    /// Record an unanswered direct keepalive and the local UDP endpoint that sent it.
    pub async fn record_direct_keepalive_timeout_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        let epoch_gate = self.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }

        let source = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if !conn.online
                || conn.direct_generation != generation
                || conn.state != ConnectionState::Direct
            {
                return false;
            }

            let reason = format!("direct keepalive ACK timeout for {endpoint}");
            conn.direct_health
                .record_failure(REASON_DIRECT_KEEPALIVE_TIMEOUT, reason.clone());
            let peer_id = conn.node_id.clone();
            let pair = conn.ensure_candidate_pair(endpoint, generation);
            let source = pair.source;
            let old_state = pair.state;
            pair.record_failure(
                REASON_DIRECT_KEEPALIVE_TIMEOUT,
                reason.clone(),
                local_endpoint,
            );
            log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);

            if conn.direct_health.consecutive_failures >= DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
                conn.transition(ConnectionState::FallbackToRelay);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                info!(
                    event = "direct_path_degraded",
                    peer_id = %node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %endpoint,
                    candidate_source = ?source,
                    rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                    reason = "direct keepalive failure threshold reached",
                    "direct_path_degraded peer_id={} remote_endpoint={} reason=direct keepalive failure threshold reached",
                    node_id,
                    endpoint
                );
            }
            source
        };
        drop(epoch_guard);
        self.record_traversal_failures(vec![source]).await;
        true
    }
}
