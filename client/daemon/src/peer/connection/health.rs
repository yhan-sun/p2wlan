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
    ) -> CandidatePairSource {
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
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
        pair.source
    }

    fn mark_candidate_pair_nominated(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
        reason: &str,
    ) -> Option<CandidatePairSource> {
        let peer_id = self.node_id.clone();
        let pair = self.candidate_pairs.iter_mut().find(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
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
            .filter(|pair| pair.local_generation == local_generation)
        {
            let old_state = pair.state;
            if pair.expire_stale_nomination(DIRECT_TRIAL_WINDOW, reason.clone(), local_endpoint) {
                expired += 1;
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
                info!(
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
        let current_endpoints = self.candidate_endpoints();
        let has_probed_pair = current_endpoints.iter().copied().any(|endpoint| {
            let pair = self.ensure_candidate_pair(endpoint, local_generation);
            pair.last_probe_at.is_some()
        });
        for endpoint in current_endpoints {
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
            info!(
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

    fn mark_network_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        let peer_id = self.node_id.clone();
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
    }

    fn mark_candidate_refresh_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) -> bool {
        let reason = reason.into();
        let retained_private_direct = (self.state == ConnectionState::Direct)
            .then(|| {
                self.candidate_pairs
                    .iter()
                    .find(|pair| should_retain_private_direct_pair(pair))
                    .map(|pair| pair.retained_for_generation(local_generation))
            })
            .flatten();
        let retained_endpoint = retained_private_direct
            .as_ref()
            .map(|pair| pair.remote_endpoint);

        let peer_id = self.node_id.clone();
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

        if let Some(retained) = retained_private_direct {
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
            true
        } else {
            false
        }
    }

    fn direct_retry_after(&self, base: Duration) -> Duration {
        self.direct_health.retry_after(base)
    }

    fn direct_retry_remaining(&self, base: Duration) -> Duration {
        self.direct_health.retry_remaining(base)
    }

    fn direct_retry_due(&self, base: Duration) -> bool {
        self.direct_health.retry_due(base)
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
        let bases = self
            .candidate_endpoints()
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .collect::<Vec<_>>();
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
