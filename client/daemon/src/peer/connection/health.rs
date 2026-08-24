impl PeerConnection {
    fn mark_candidate_pair_probing(&mut self, endpoint: SocketAddr, local_generation: u64) {
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        pair.record_probing(None);
        log_candidate_pair_state_changed(&peer_id, pair, old_state, "probe scheduled");
    }

    fn mark_candidate_pair_probing_with_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) {
        let peer_id = self.node_id.clone();
        let pair =
            self.ensure_candidate_pair_with_observed_source(endpoint, local_generation, source);
        let old_state = pair.state;
        pair.record_probing(None);
        log_candidate_pair_state_changed(&peer_id, pair, old_state, "probe scheduled");
    }

    fn mark_candidate_pair_probing_with_local_endpoint(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) {
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        pair.record_probing(local_endpoint);
        log_candidate_pair_state_changed(&peer_id, pair, old_state, "inbound probe observed");
    }

    fn mark_candidate_pair_success(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        latency: Option<Duration>,
        selected: bool,
        local_endpoint: Option<SocketAddr>,
    ) -> (CandidatePairSource, bool) {
        let peer_id = self.node_id.clone();
        let remote_epoch = self.remote_candidate_epoch;
        if selected {
            for pair in self.candidate_pairs.iter_mut().filter(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_candidate_epoch == remote_epoch
                    && pair.remote_endpoint != endpoint
            }) {
                let was_selected = pair.state == CandidatePairState::Selected
                    || pair.selected_at.is_some()
                    || pair.nominated;
                if was_selected {
                    let old_state = pair.state;
                    pair.clear_selection();
                    log_candidate_pair_state_changed(
                        &peer_id,
                        pair,
                        old_state,
                        "superseded by newer encrypted-confirmed Direct UDP endpoint",
                    );
                }
            }
        }
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        let became_reachable = !matches!(
            old_state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        );
        pair.record_success(latency, selected, local_endpoint);
        log_candidate_pair_state_changed(
            &peer_id,
            pair,
            old_state,
            if selected {
                "encrypted data path confirmed Direct UDP"
            } else {
                "received UDP punch ACK"
            },
        );
        (pair.source, became_reachable)
    }

    fn mark_candidate_pair_authoritative_success(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        latency: Duration,
        selected: bool,
        local_endpoint: Option<SocketAddr>,
    ) -> (CandidatePairSource, bool) {
        let peer_id = self.node_id.clone();
        let remote_epoch = self.remote_candidate_epoch;
        if selected {
            for pair in self.candidate_pairs.iter_mut().filter(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_candidate_epoch == remote_epoch
                    && pair.remote_endpoint != endpoint
            }) {
                let was_selected = pair.state == CandidatePairState::Selected
                    || pair.selected_at.is_some()
                    || pair.nominated;
                if was_selected {
                    let old_state = pair.state;
                    pair.clear_selection();
                    log_candidate_pair_state_changed(
                        &peer_id,
                        pair,
                        old_state,
                        "superseded by newer encrypted-confirmed Direct UDP endpoint",
                    );
                }
            }
        }
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        let became_reachable = !matches!(
            old_state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        );
        pair.record_authoritative_success(latency, selected, local_endpoint);
        log_candidate_pair_state_changed(
            &peer_id,
            pair,
            old_state,
            "encrypted data path confirmed Direct UDP with authoritative RTT",
        );
        (pair.source, became_reachable)
    }

    fn mark_candidate_pair_slow_validation(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        latency: Duration,
        local_endpoint: Option<SocketAddr>,
    ) -> (CandidatePairSource, bool) {
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        pair.record_slow_validation(
            latency,
            local_endpoint,
            REASON_DIRECT_SLOW_RELAY_RETAINED,
            format!(
                "bidirectional Direct validation reached the peer but RTT={}ms exceeded the relay-retention floor {}ms",
                duration_millis(latency),
                SLOW_DIRECT_RELAY_VALIDATION_RTT_MS
            ),
        );
        log_candidate_pair_state_changed(
            &peer_id,
            pair,
            old_state,
            "received slow UDP probe ACK; confirmed relay retained",
        );
        (pair.source, false)
    }

    /// A slow but authenticated ACK quarantines the remote endpoint for every
    /// local socket in this generation.  Checking the pair table here keeps
    /// the outbound sender from re-emitting the same destination after a
    /// delayed ACK has already proved that it is currently queue-prone.
    pub(crate) fn direct_probe_endpoint_quarantined(
        &self,
        endpoint: SocketAddr,
        local_generation: u64,
        now: Instant,
    ) -> bool {
        self.candidate_pairs.iter().any(|pair| {
            pair.remote_endpoint == endpoint
                && pair.local_generation == local_generation
                && pair.remote_candidate_epoch == self.remote_candidate_epoch
                && pair.slow_validation_is_recent_at(now, SLOW_DIRECT_RELAY_RETRY_COOLDOWN)
        })
    }

    fn mark_candidate_pair_nominated(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
        reason: &str,
    ) -> Option<CandidatePairSource> {
        let peer_id = self.node_id.clone();
        let remote_epoch = self.remote_candidate_epoch;
        let pair = self.candidate_pairs.iter_mut().find(|pair| {
            pair.remote_endpoint == endpoint
                && pair.local_generation == local_generation
                && pair.remote_candidate_epoch == remote_epoch
        })?;
        let nominated = pair.nominate(local_endpoint);
        if nominated {
            log_candidate_pair_nominated(&peer_id, pair, reason);
        }
        Some(pair.source)
    }

    fn expire_stale_trial_nominations(
        &mut self,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> usize {
        let peer_id = self.node_id.clone();
        let reason = format!(
            "direct trial was not encrypted-confirmed within {}ms",
            duration_millis(DIRECT_TRIAL_WINDOW)
        );
        let mut expired = 0usize;
        for pair in self
            .candidate_pairs
            .iter_mut()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_candidate_epoch == self.remote_candidate_epoch
            })
        {
            let old_state = pair.state;
            if pair.expire_stale_nomination(DIRECT_TRIAL_WINDOW, reason.clone(), local_endpoint) {
                expired += 1;
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
                debug!(
                    event = "candidate_pair_nomination_expired",
                    peer_id = %peer_id,
                    local_endpoint = %format_log_endpoint(pair.local_endpoint),
                    remote_endpoint = %pair.remote_endpoint,
                    candidate_source = ?pair.source,
                    rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
                    reason = %reason,
                    "candidate_pair_nomination_expired peer_id={} remote_endpoint={} reason={}",
                    peer_id,
                    pair.remote_endpoint,
                    reason
                );
            }
        }
        expired
    }

    fn mark_current_candidate_pairs_failed(
        &mut self,
        local_generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> Vec<CandidatePairSource> {
        let code = code.into();
        let reason = reason.into();
        let local_endpoint_text = format_log_endpoint(local_endpoint);
        let peer_id = self.node_id.clone();
        let mut probed_sources = Vec::new();
        let mut failure_endpoints = self.candidate_endpoints();
        let has_probed_pair = self
            .candidate_pairs
            .iter()
            .any(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_candidate_epoch == self.remote_candidate_epoch
                    && pair.last_probe_at.is_some()
            });
        if has_probed_pair {
            let probed_transient_endpoints = self
                .candidate_pairs
                .iter()
                .filter(|pair| {
                    pair.local_generation == local_generation
                        && pair.remote_candidate_epoch == self.remote_candidate_epoch
                        && pair.last_probe_at.is_some()
                })
                .map(|pair| pair.remote_endpoint)
                .collect::<Vec<_>>();
            for endpoint in probed_transient_endpoints {
                if !failure_endpoints.contains(&endpoint) {
                    failure_endpoints.push(endpoint);
                }
            }
        }
        for endpoint in failure_endpoints {
            let pair = self.ensure_candidate_pair(endpoint, local_generation);
            if has_probed_pair && pair.last_probe_at.is_none() {
                continue;
            }
            if pair.last_probe_at.is_some() && !probed_sources.contains(&pair.source) {
                probed_sources.push(pair.source);
            }
            let candidate_source = pair.source;
            let rtt_ms = pair.rtt_ewma_ms.or(pair.rtt_ms);
            let old_state = pair.state;
            pair.record_failure(code.clone(), reason.clone(), local_endpoint);
            log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            debug!(
                event = "candidate_pair_probe_failed",
                peer_id = %peer_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %endpoint,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %reason,
                "candidate_pair_probe_failed peer_id={} remote_endpoint={} reason={}",
                peer_id,
                endpoint,
                reason
            );
        }
        probed_sources
    }

    /// Mark only the candidate pairs that were part of a completed probe
    /// window as failed.  A stable-side birthday sweep deliberately probes a
    /// different absolute-port window on each pass, so applying failure to
    /// every current candidate would incorrectly penalize endpoints that were
    /// not sent in this pass.
    fn mark_candidate_pairs_failed_for_endpoints(
        &mut self,
        local_generation: u64,
        endpoints: &[SocketAddr],
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> Vec<CandidatePairSource> {
        let code = code.into();
        let reason = reason.into();
        let local_endpoint_text = format_log_endpoint(local_endpoint);
        let peer_id = self.node_id.clone();
        let mut probed_sources = Vec::new();
        let mut seen_endpoints = Vec::new();

        for endpoint in endpoints.iter().copied() {
            if seen_endpoints.contains(&endpoint) {
                continue;
            }
            seen_endpoints.push(endpoint);

            let Some(pair) = self.candidate_pairs.iter_mut().find(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_candidate_epoch == self.remote_candidate_epoch
                    && pair.remote_endpoint == endpoint
                    && pair.last_probe_at.is_some()
            }) else {
                continue;
            };

            if !probed_sources.contains(&pair.source) {
                probed_sources.push(pair.source);
            }
            let candidate_source = pair.source;
            let rtt_ms = pair.rtt_ewma_ms.or(pair.rtt_ms);
            let old_state = pair.state;
            pair.record_failure(code.clone(), reason.clone(), local_endpoint);
            log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            debug!(
                event = "candidate_pair_probe_window_missed",
                peer_id = %peer_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %endpoint,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %reason,
                "candidate_pair_probe_window_missed peer_id={} remote_endpoint={} reason={}",
                peer_id,
                endpoint,
                reason
            );
        }

        probed_sources
    }

    fn mark_network_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        let peer_id = self.node_id.clone();
        let previous_state = self.state;
        let previous_direct_generation = self.direct_generation;
        let previous_relay_ready_generation = self.relay_ready_generation;
        let previous_relay_confirmed_generation = self.relay_confirmed_generation;
        let previous_relay_confirmed_connection_id = self.relay_confirmed_connection_id;
        let previous_first_usable_generation = self.first_usable_generation;
        let previous_candidate_pair_count = self.candidate_pairs.len();
        // `first_usable` is intentionally scoped to peer + generation. A
        // restart or interface handover must not reuse proof from an old NAT
        // mapping, even when the old connection object is retained.
        if self.first_usable_generation != Some(local_generation) {
            self.first_usable_generation = None;
            self.first_usable_at = None;
            self.first_usable_path = None;
        }
        if self.relay_first.business_gate_completed_generation != Some(local_generation) {
            // The relay-first proof is scoped to the network generation. A
            // relay ticket renewal keeps this marker, but a real network
            // handover starts a new first-business contract.
            self.relay_first.business_gate_completed_generation = None;
        }
        // A true network handover invalidates the local relay transport
        // milestone as well as the encrypted peer confirmation. Keeping the
        // old ready timestamp would make a new generation look relay-ready
        // before its session/writer has actually been rebuilt.
        if self.relay_ready_generation != Some(local_generation) {
            self.relay_ready_generation = None;
            self.relay_ready_at = None;
            self.relay_ready_endpoint = None;
            self.relay_ready_connection_id = None;
            self.relay_first.business_sent_generation = None;
            self.relay_first.business_received_generation = None;
            self.relay_first.business_exchange_generation = None;
            self.relay_first.business_pathcommit_generation = None;
            self.relay_first.preconfirmation = None;
        }
        if self.relay_first.gate_generation != Some(local_generation) {
            self.relay_first.gate_generation = None;
            self.relay_first.gate_started_at = None;
        }
        if self.relay_confirmed_generation != Some(local_generation) {
            self.relay_confirmed_generation = None;
            self.relay_confirmed_at = None;
            self.relay_confirmed_endpoint = None;
            self.relay_confirmed_connection_id = None;
            self.relay_first.business_sent_generation = None;
            self.relay_first.business_received_generation = None;
            self.relay_first.business_exchange_generation = None;
            self.relay_first.business_pathcommit_generation = None;
            self.relay_first.preconfirmation = None;
            self.relay_confirm_seq = self.relay_confirm_seq.wrapping_add(1);
            if self.state == ConnectionState::Relay {
                self.transition(ConnectionState::FallbackToRelay);
            }
        }
        self.candidate_pairs
            .retain(|pair| pair.local_generation.saturating_add(1) >= local_generation);
        for pair in &mut self.candidate_pairs {
            if pair.local_generation < local_generation {
                let old_state = pair.state;
                pair.record_generation_change(reason.clone());
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            }
        }
        self.ensure_current_candidate_pairs(local_generation);
        debug!(target: "p2pnet_daemon::peer::connection",
            event = "peer_network_generation_invalidated",
            peer_id = %peer_id,
            generation = local_generation,
            reason = %reason,
            previous_state = ?previous_state,
            current_state = ?self.state,
            previous_direct_generation,
            previous_relay_ready_generation = ?previous_relay_ready_generation,
            previous_relay_confirmed_generation = ?previous_relay_confirmed_generation,
            previous_relay_confirmed_connection_id = ?previous_relay_confirmed_connection_id,
            previous_first_usable_generation = ?previous_first_usable_generation,
            current_relay_ready_generation = ?self.relay_ready_generation,
            current_relay_confirmed_generation = ?self.relay_confirmed_generation,
            current_first_usable_generation = ?self.first_usable_generation,
            previous_candidate_pair_count,
            current_candidate_pair_count = self.candidate_pairs.len(),
            "peer network generation invalidated peer_id={} generation={} reason={}",
            peer_id,
            local_generation,
            reason,
        );
    }

    /// Invalidate all Direct evidence for a real remote transport handover.
    ///
    /// The wire candidate generation is only a freshness revision and is not
    /// sufficient to call this method: an unchanged set, or a revised set that
    /// retains the encrypted-confirmed Direct endpoint, continues on the same
    /// transport epoch. The old pairs remain in bounded history here, but their
    /// epoch no longer matches the replacement transport context.
    pub(super) fn mark_remote_transport_handover(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) -> u64 {
        let reason = reason.into();
        let peer_id = self.node_id.clone();
        let previous_epoch = self.remote_candidate_epoch;
        let next_epoch = self.remote_candidate_epoch.wrapping_add(1).max(1);
        self.remote_candidate_epoch = next_epoch;
        // The profile was captured for the previous remote candidate context.
        // It must be published again before it can authorize a new
        // synchronized fresh-mapping session.
        self.remote_nat_profile_candidate_epoch = None;

        for pair in &mut self.candidate_pairs {
            if pair.remote_candidate_epoch != next_epoch {
                let old_state = pair.state;
                pair.record_remote_candidate_generation_change(reason.clone());
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            }
        }

        if self.first_usable_path == Some(NetworkPath::Direct) {
            self.first_usable_generation = None;
            self.first_usable_at = None;
            self.first_usable_path = None;
        }
        self.endpoint = None;
        self.direct_reclaim_until = None;
        self.last_path_selection = None;
        if self.state == ConnectionState::Direct {
            self.transition(ConnectionState::FallbackToRelay);
        }
        self.record_direct_event(
            local_generation,
            "remote_candidates_invalidated",
            None,
            Some(self.candidate_pairs.len()),
            None,
            format!(
                "remote candidate epoch advanced from {previous_epoch} to {next_epoch}; old Direct evidence fenced: {reason}"
            ),
        );
        next_epoch
    }

    /// Keep an encrypted-confirmed Direct transport across a newer candidate
    /// freshness revision, even when a volatile signal omits the selected
    /// endpoint. The authenticated path remains stronger evidence than the
    /// latest candidate list; consent/keepalive is the liveness fence.
    ///
    /// This is the remote-side make-before-break counterpart to local candidate
    /// refresh retention.  It intentionally leaves the remote epoch, selected
    /// pair, Direct commit sequence and validation owner unchanged; changing
    /// any of those would turn a routine rekey/candidate refresh into a path
    /// teardown even though the live UDP transport is still present.
    pub(super) fn mark_remote_candidate_revision_with_direct_continuity(
        &mut self,
        local_generation: u64,
        retained_endpoint: SocketAddr,
        candidate_revision: u64,
        retired_pair_count: usize,
    ) {
        debug_assert_eq!(self.state, ConnectionState::Direct);
        debug_assert!(self
            .selected_direct_endpoint_for_consent(local_generation)
            .is_some_and(|endpoint| endpoint == retained_endpoint));
        self.record_direct_event(
            local_generation,
            "remote_candidate_revision_direct_retained",
            Some(retained_endpoint),
            Some(self.candidate_pairs.len()),
            None,
            format!(
                "accepted candidate freshness revision {candidate_revision} with encrypted-confirmed endpoint continuity; remote transport epoch={} retired_alternate_pairs={retired_pair_count}",
                self.remote_candidate_epoch,
            ),
        );
    }

    fn mark_candidate_refresh_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) -> bool {
        let reason = reason.into();
        let peer_id = self.node_id.clone();
        let previous_state = self.state;
        let previous_direct_generation = self.direct_generation;
        let previous_relay_ready_generation = self.relay_ready_generation;
        let previous_relay_confirmed_generation = self.relay_confirmed_generation;
        let previous_relay_confirmed_connection_id = self.relay_confirmed_connection_id;
        let previous_first_usable_generation = self.first_usable_generation;
        let previous_candidate_pair_count = self.candidate_pairs.len();
        // Candidate refresh creates a new generation even when a private Direct
        // pair is retained. Its first-usable evidence must be earned again.
        if self.first_usable_generation != Some(local_generation) {
            self.first_usable_generation = None;
            self.first_usable_at = None;
            self.first_usable_path = None;
        }
        // A candidate-refresh generation is a Direct-candidate epoch, not a
        // relay-session replacement. Keep the already encrypted-confirmed
        // relay ingress usable while new UDP candidates are probed in the
        // background. True network handover, peer restart and relay transport
        // replacement use the separate invalidation paths and still revoke
        // this proof.
        if self.relay_confirmed_at.is_some() && self.relay_confirmed_endpoint.is_some() {
            self.relay_confirmed_generation = Some(local_generation);
            self.relay_ready_generation = Some(local_generation);
            self.relay_ready_connection_id = self.relay_confirmed_connection_id;
            self.relay_first.business_sent_generation = None;
            self.relay_first.business_received_generation = None;
            self.relay_first.business_exchange_generation = None;
            self.relay_first.business_pathcommit_generation = None;
            self.relay_first.preconfirmation = None;
            self.relay_first.gate_generation = None;
            self.relay_first.gate_started_at = None;
        } else {
            self.relay_ready_generation = None;
            self.relay_ready_at = None;
            self.relay_ready_endpoint = None;
            self.relay_ready_connection_id = None;
            self.relay_first.business_sent_generation = None;
            self.relay_first.business_received_generation = None;
            self.relay_first.business_exchange_generation = None;
            self.relay_first.business_pathcommit_generation = None;
            self.relay_first.preconfirmation = None;
            self.relay_first.gate_generation = None;
            self.relay_first.gate_started_at = None;
        }
        let retained_confirmed_direct = (self.state == ConnectionState::Direct)
            .then(|| {
                self.candidate_pairs
                    .iter()
                    .find(|pair| should_retain_confirmed_direct_pair_on_candidate_refresh(pair))
                    .map(|pair| pair.retained_for_generation(local_generation))
            })
            .flatten();
        let retained_endpoint = retained_confirmed_direct
            .as_ref()
            .map(|pair| pair.remote_endpoint);

        self.candidate_pairs
            .retain(|pair| pair.local_generation.saturating_add(1) >= local_generation);
        for pair in &mut self.candidate_pairs {
            if pair.local_generation < local_generation {
                let old_state = pair.state;
                pair.record_generation_change(reason.clone());
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            }
        }
        self.ensure_current_candidate_pairs(local_generation);

        debug!(target: "p2pnet_daemon::peer::connection",
            event = "peer_candidate_refresh_generation_advanced",
            peer_id = %peer_id,
            generation = local_generation,
            reason = %reason,
            previous_state = ?previous_state,
            current_state = ?self.state,
            previous_direct_generation,
            previous_relay_ready_generation = ?previous_relay_ready_generation,
            previous_relay_confirmed_generation = ?previous_relay_confirmed_generation,
            previous_relay_confirmed_connection_id = ?previous_relay_confirmed_connection_id,
            previous_first_usable_generation = ?previous_first_usable_generation,
            current_relay_ready_generation = ?self.relay_ready_generation,
            current_relay_confirmed_generation = ?self.relay_confirmed_generation,
            current_first_usable_generation = ?self.first_usable_generation,
            previous_candidate_pair_count,
            current_candidate_pair_count = self.candidate_pairs.len(),
            "peer candidate-refresh generation advanced peer_id={} generation={} reason={}",
            peer_id,
            local_generation,
            reason,
        );

        if let Some(retained) = retained_confirmed_direct {
            if let Some(index) = self.candidate_pairs.iter().position(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_endpoint == retained.remote_endpoint
            }) {
                self.candidate_pairs[index] = retained;
            } else {
                self.candidate_pairs.push(retained);
            }
            if let Some(endpoint) = retained_endpoint {
                self.endpoint = Some(endpoint);
                self.direct_generation = local_generation;
            }
            self.clear_direct_reclaim_window();
            true
        } else {
            false
        }
    }

    fn direct_retry_after(&self, base: Duration) -> Duration {
        self.direct_health.retry_after(base)
    }

    /// Whether the peer is on a confirmed Direct path with recent success and
    /// no consecutive failures, making relay-assisted punching unnecessary.
    pub(crate) fn direct_is_healthy_confirmed(&self) -> bool {
        if self.state != ConnectionState::Direct
            || self.direct_health.consecutive_failures != 0
            || self
                .direct_health
                .success_age()
                .is_none_or(|age| age > RELAY_PEER_CONFIRMATION_MAX_AGE)
        {
            return false;
        }
        self.candidate_pairs.iter().any(|pair| {
            pair.selected_at.is_some() && pair.state != CandidatePairState::Frozen
                && pair.remote_candidate_epoch == self.remote_candidate_epoch
        })
    }

    fn direct_retry_remaining(&self, base: Duration) -> Duration {
        self.direct_health.retry_remaining(base)
    }

    fn direct_retry_due(&self, base: Duration) -> bool {
        self.direct_health.retry_due(base)
    }

    /// Relay-flat retry cadence: when the relay already carries the data
    /// plane, a background scatter retry must not grow an exponential
    /// backoff across consecutive misses — the special interval keeps the
    /// window warm so a post-black-hole probe hits immediately.
    fn direct_retry_due_relay_flat(&self, base: Duration) -> bool {
        self.direct_health.retry_due_relay_flat(base)
    }

    fn direct_reclaim_active(&self) -> bool {
        self.direct_reclaim_until
            .is_some_and(|until| Instant::now() < until)
    }

    fn start_direct_reclaim_window(&mut self, local_generation: u64, reason: &str) -> bool {
        if !self.has_direct_success_history() || self.candidate_endpoints().is_empty() {
            return false;
        }

        self.direct_reclaim_until = Some(Instant::now() + DIRECT_RECLAIM_WINDOW);
        let candidate_count = self.candidate_endpoints().len();
        self.record_direct_event(
            local_generation,
            "direct_reclaim_window_started",
            self.endpoint,
            Some(candidate_count),
            None,
            format!(
                "network changed after previous Direct success; aggressively reprobing for {}ms: {reason}",
                duration_millis(DIRECT_RECLAIM_WINDOW)
            ),
        );
        true
    }

    fn clear_direct_reclaim_window(&mut self) {
        self.direct_reclaim_until = None;
    }

    fn has_direct_success_history(&self) -> bool {
        self.direct_health.success_count > 0
            || self
                .candidate_pairs
                .iter()
                .any(|pair| pair.success_count > 0 || pair.selected_at.is_some())
    }

    fn has_private_direct_candidate(&self) -> bool {
        self.candidate_endpoints()
            .into_iter()
            .any(is_low_latency_direct_endpoint)
    }

    fn has_mapping_assisted_candidate(&self) -> bool {
        self.candidate_endpoints().into_iter().any(|endpoint| {
            matches!(
                self.candidate_source_for_endpoint(endpoint),
                CandidatePairSource::Upnp
                    | CandidatePairSource::Pcp
                    | CandidatePairSource::NatPmp
                    | CandidatePairSource::Predicted
            )
        })
    }

    fn peer_public_candidates_need_scatter(&self) -> bool {
        let bases = self.asymmetric_stable_public_endpoints(self.candidate_endpoints());
        peer_candidates_need_port_scatter(&bases)
    }

    fn has_direct_retry_opportunity(&self, local_nat_profile: Option<&NatProfile>) -> bool {
        let endpoints = self.candidate_endpoints();
        if endpoints.is_empty() {
            return false;
        }

        // A path that has worked before is exactly the kind of transient NAT
        // window we want to recover quickly after sleep, network refresh, or
        // daemon socket rebinding.
        if self.has_direct_success_history()
            || self.has_private_direct_candidate()
            || self.has_mapping_assisted_candidate()
        {
            return true;
        }

        if local_nat_profile.is_some_and(|profile| profile.udp_blocked) {
            return false;
        }

        let local_is_hard = local_nat_profile.is_some_and(is_hard_nat_profile);
        let peer_looks_hard = self.peer_public_candidates_need_scatter();
        !(local_is_hard && peer_looks_hard)
    }
}
