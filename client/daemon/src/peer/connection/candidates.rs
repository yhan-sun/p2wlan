impl PeerConnection {
    fn candidate_endpoints(&self) -> Vec<SocketAddr> {
        let mut endpoints = Vec::new();
        for candidate in &self.candidates {
            if let Ok(endpoint) = candidate.parse::<SocketAddr>() {
                if !endpoints.contains(&endpoint) {
                    endpoints.push(endpoint);
                }
            }
        }
        if let Some(endpoint) = self.endpoint {
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        endpoints
    }

    fn probe_candidate_endpoints(&self) -> Vec<SocketAddr> {
        let mut endpoints = Vec::new();
        for candidate in &self.candidates {
            if let Ok(endpoint) = candidate.parse::<SocketAddr>() {
                if !endpoints.contains(&endpoint) {
                    endpoints.push(endpoint);
                }
            }
        }
        if endpoints.is_empty() {
            if let Some(endpoint) = self.endpoint {
                endpoints.push(endpoint);
            }
        } else if let Some(endpoint) = self.endpoint {
            let has_current_or_recent_success = self.candidate_pairs.iter().any(|pair| {
                pair.remote_endpoint == endpoint
                    && (pair.last_success_at.is_some()
                        || matches!(
                            pair.state,
                            CandidatePairState::Selected | CandidatePairState::Succeeded
                        ))
            });
            if has_current_or_recent_success && !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        endpoints
    }

    fn candidate_source_for_endpoint(&self, endpoint: SocketAddr) -> CandidatePairSource {
        self.candidate_sources
            .get(&endpoint.to_string())
            .copied()
            .or_else(|| {
                self.candidate_pairs
                    .iter()
                    .filter(|pair| pair.remote_endpoint == endpoint)
                    .min_by_key(|pair| candidate_pair_source_rank(pair.source))
                    .map(|pair| pair.source)
            })
            .unwrap_or(CandidatePairSource::Signaled)
    }

    fn ensure_candidate_pair(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
    ) -> &mut CandidatePair {
        if let Some(index) = self.candidate_pairs.iter().position(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        }) {
            return &mut self.candidate_pairs[index];
        }
        self.ensure_candidate_pair_with_source(
            endpoint,
            local_generation,
            CandidatePairSource::Signaled,
        )
    }

    fn ensure_candidate_pair_with_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) -> &mut CandidatePair {
        if let Some(index) = self.candidate_pairs.iter().position(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        }) {
            self.candidate_pairs[index].promote_source(source);
            return &mut self.candidate_pairs[index];
        }
        self.candidate_pairs.push(CandidatePair::new_with_source(
            endpoint,
            local_generation,
            source,
        ));
        self.candidate_pairs
            .last_mut()
            .expect("candidate pair inserted")
    }

    fn ensure_candidate_pair_with_observed_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) -> &mut CandidatePair {
        if let Some(index) = self.candidate_pairs.iter().position(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        }) {
            self.candidate_pairs[index].observe_source(source);
            return &mut self.candidate_pairs[index];
        }
        self.candidate_pairs.push(CandidatePair::new_with_source(
            endpoint,
            local_generation,
            source,
        ));
        self.candidate_pairs
            .last_mut()
            .expect("candidate pair inserted")
    }

    fn ensure_current_candidate_pairs(&mut self, local_generation: u64) {
        for endpoint in self.candidate_endpoints() {
            let source = self.candidate_source_for_endpoint(endpoint);
            self.ensure_candidate_pair_with_source(endpoint, local_generation, source);
        }
    }

    fn prune_candidate_pairs_outside_targets(
        &mut self,
        local_generation: u64,
        endpoints: &[SocketAddr],
    ) -> usize {
        let target_endpoints = endpoints.iter().copied().collect::<HashSet<_>>();
        let before = self.candidate_pairs.len();
        self.candidate_pairs.retain(|pair| {
            if pair.local_generation != local_generation {
                return true;
            }
            if target_endpoints.contains(&pair.remote_endpoint) {
                return true;
            }
            matches!(
                pair.state,
                CandidatePairState::Selected | CandidatePairState::Succeeded
            ) && pair
                .last_success_at
                .is_some_and(|at| at.elapsed() < DIRECT_TRIAL_WINDOW)
        });
        before.saturating_sub(self.candidate_pairs.len())
    }

    fn candidate_probe_endpoints(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        mode: ProbeTargetMode,
    ) -> Vec<SocketAddr> {
        self.ensure_current_candidate_pairs(local_generation);
        let use_asymmetric_stable_role =
            self.should_use_asymmetric_stable_remote_role(local_nat_profile);
        let mut endpoints = if use_asymmetric_stable_role {
            self.asymmetric_stable_remote_endpoints(local_generation)
        } else {
            self.probe_candidate_endpoints()
        };
        self.ensure_birthday_candidate_pairs(
            local_generation,
            history,
            local_nat_profile,
            mode.allows_local_nat_birthday() && !use_asymmetric_stable_role,
            mode.allows_failed_prediction_fallback() && !use_asymmetric_stable_role,
            &mut endpoints,
        );
        self.prune_candidate_pairs_outside_targets(local_generation, &endpoints);
        let source_stats =
            candidate_pair_source_stats(&self.candidate_pairs, local_generation, None);
        let active_endpoint = self.endpoint;
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && endpoints.contains(&pair.remote_endpoint)
                    && (mode.bypasses_pair_cooldown() || candidate_pair_probe_due(pair))
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            outbound_probe_priority_rank(a)
                .cmp(&outbound_probe_priority_rank(b))
                .then_with(|| {
                    speculative_probe_source_rank_for_mode(a.source, mode)
                        .cmp(&speculative_probe_source_rank_for_mode(b.source, mode))
                })
                .then_with(|| {
                    candidate_pair_probe_rank_for_mode(a.state, a.source, mode)
                        .cmp(&candidate_pair_probe_rank_for_mode(b.state, b.source, mode))
                })
                .then_with(|| {
                    candidate_pair_source_quality_rank(&source_stats, history, a.source).cmp(
                        &candidate_pair_source_quality_rank(&source_stats, history, b.source),
                    )
                })
                .then_with(|| {
                    candidate_pair_dynamic_probe_rank(a, active_endpoint)
                        .cmp(&candidate_pair_dynamic_probe_rank(b, active_endpoint))
                })
                .then_with(|| {
                    discovered_endpoint_probe_rank(a.source)
                        .cmp(&discovered_endpoint_probe_rank(b.source))
                })
                .then_with(|| {
                    speculative_probe_rotation_rank(a).cmp(&speculative_probe_rotation_rank(b))
                })
                .then_with(|| {
                    endpoint_probe_rank(a.remote_endpoint)
                        .cmp(&endpoint_probe_rank(b.remote_endpoint))
                })
                .then_with(|| {
                    candidate_pair_source_rank(a.source).cmp(&candidate_pair_source_rank(b.source))
                })
                .then_with(|| a.probe_count.cmp(&b.probe_count))
                .then_with(|| a.consecutive_failures.cmp(&b.consecutive_failures))
                .then_with(|| a.failure_count.cmp(&b.failure_count))
                .then_with(|| {
                    a.rtt_ewma_ms
                        .or(a.rtt_ms)
                        .unwrap_or(u64::MAX)
                        .cmp(&b.rtt_ewma_ms.or(b.rtt_ms).unwrap_or(u64::MAX))
                })
                .then_with(|| {
                    a.jitter_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.jitter_ms.unwrap_or(u64::MAX))
                })
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });
        apply_adaptive_probe_budgets(pairs, &source_stats, history, mode)
            .into_iter()
            .map(|pair| pair.remote_endpoint)
            .collect()
    }

    /// A mapping-dependent local NAT should create only a few mappings toward
    /// an easy peer's stable public endpoint. The easy peer can then scan this
    /// side's explicit predicted ports without both sides destroying their
    /// useful NAT windows through simultaneous birthday sweeps.
    fn should_use_asymmetric_stable_remote_role(
        &self,
        local_nat_profile: Option<&NatProfile>,
    ) -> bool {
        if !local_nat_profile.is_some_and(is_hard_nat_profile) {
            return false;
        }

        let public_endpoints =
            self.asymmetric_stable_public_endpoints(self.probe_candidate_endpoints());
        !public_endpoints.is_empty()
            && !self.has_explicit_predicted_window()
            && !peer_candidates_need_port_scatter(&public_endpoints)
    }

    fn asymmetric_stable_public_endpoints(&self, endpoints: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let mut authoritative = endpoints
            .iter()
            .copied()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .filter(|endpoint| {
                is_authoritative_stable_public_source(self.candidate_source_for_endpoint(*endpoint))
            })
            .collect::<Vec<_>>();
        authoritative.dedup();
        if !authoritative.is_empty() {
            return authoritative;
        }

        let mut reclaim = endpoints
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .filter(|endpoint| {
                matches!(
                    self.candidate_source_for_endpoint(*endpoint),
                    CandidatePairSource::PeerReflexive | CandidatePairSource::Learned
                )
            })
            .collect::<Vec<_>>();
        reclaim.dedup();
        reclaim
    }

    fn has_explicit_predicted_window(&self) -> bool {
        self.candidate_sources
            .values()
            .any(|source| *source == CandidatePairSource::Predicted)
    }

    fn explicit_predicted_window_failed(&self, local_generation: u64) -> bool {
        let mut found_predicted = false;
        for endpoint in self.candidate_sources.iter().filter_map(|(candidate, source)| {
            (*source == CandidatePairSource::Predicted)
                .then(|| candidate.parse::<SocketAddr>().ok())
                .flatten()
        }) {
            found_predicted = true;
            if !self.candidate_pairs.iter().any(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_endpoint == endpoint
                    && pair.failure_count > 0
            }) {
                return false;
            }
        }
        found_predicted
    }

    fn asymmetric_stable_remote_endpoints(
        &self,
        local_generation: u64,
    ) -> Vec<SocketAddr> {
        let mut endpoints = self
            .probe_candidate_endpoints()
            .into_iter()
            .filter(|endpoint| {
                is_low_latency_direct_endpoint(*endpoint)
                    && self.candidate_pairs.iter().any(|pair| {
                        pair.local_generation == local_generation
                            && pair.remote_endpoint == *endpoint
                            && (pair.last_success_at.is_some()
                                || matches!(
                                    pair.state,
                                    CandidatePairState::Selected | CandidatePairState::Succeeded
                                ))
                    })
            })
            .collect::<Vec<_>>();
        let mut public = self.asymmetric_stable_public_endpoints(self.probe_candidate_endpoints());
        public.sort_by(|left, right| {
            birthday_base_rank(self, *left, local_generation)
                .cmp(&birthday_base_rank(self, *right, local_generation))
                .then_with(|| left.cmp(right))
        });
        if let Some(endpoint) = public.first().copied() {
            endpoints.push(endpoint);
        }
        endpoints
    }

    fn ensure_birthday_candidate_pairs(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        allow_local_nat_trigger: bool,
        allow_failed_prediction_fallback: bool,
        endpoints: &mut Vec<SocketAddr>,
    ) {
        let bases = self.birthday_probe_bases(endpoints, local_generation);

        let has_explicit_predicted_window = self.has_explicit_predicted_window();
        // Keep the first synchronized attempt compact. If every advertised
        // prediction has missed, an easy local NAT can safely rotate a wider
        // remote-port window while the mapping-dependent peer keeps probing
        // this side's stable endpoint. This is the asymmetric full-punch
        // fallback used when the peer's destination-specific mapping moved
        // beyond its signaled prediction window.
        let failed_prediction_fallback = allow_failed_prediction_fallback
            && has_explicit_predicted_window
            && local_nat_profile.is_none_or(|profile| !is_hard_nat_profile(profile))
            && self.explicit_predicted_window_failed(local_generation);
        let local_needs_birthday = allow_local_nat_trigger
            && ((!has_explicit_predicted_window
                && local_nat_profile.is_some_and(|profile| profile.birthday_candidate))
                || failed_prediction_fallback);
        let peer_looks_port_dependent = peer_candidates_need_port_scatter(&bases)
            && (!has_explicit_predicted_window || failed_prediction_fallback);
        if !local_needs_birthday && !peer_looks_port_dependent {
            return;
        }

        let per_base_budget = birthday_probe_budget(history);
        let budget =
            per_base_budget.saturating_mul(bases.len().min(BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE));
        if budget == 0 {
            return;
        }

        let mut generated = 0usize;
        let rotation_start_rank = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && pair.source == CandidatePairSource::Birthday
            })
            .map(|pair| pair.probe_count as usize)
            .min()
            .unwrap_or(0)
            .saturating_mul(per_base_budget)
            % birthday_probe_wide_rank_count();
        for endpoint in
            birthday_probe_endpoints_for_bases_from_rank(&bases, budget, rotation_start_rank)
        {
            if endpoints.contains(&endpoint) {
                continue;
            }
            endpoints.push(endpoint);
            self.ensure_candidate_pair_with_source(
                endpoint,
                local_generation,
                CandidatePairSource::Birthday,
            );
            generated += 1;
            if generated >= budget {
                return;
            }
        }
    }

    fn birthday_probe_bases(
        &self,
        endpoints: &[SocketAddr],
        local_generation: u64,
    ) -> Vec<SocketAddr> {
        let mut bases = endpoints
            .iter()
            .copied()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .filter(|endpoint| {
                !matches!(
                    self.candidate_source_for_endpoint(*endpoint),
                    CandidatePairSource::Host
                        | CandidatePairSource::Predicted
                        | CandidatePairSource::Birthday
                        | CandidatePairSource::Learned
                        | CandidatePairSource::PeerReflexive
                        | CandidatePairSource::Upnp
                        | CandidatePairSource::Pcp
                        | CandidatePairSource::NatPmp
                )
            })
            .collect::<Vec<_>>();

        bases.sort_by(|a, b| {
            birthday_base_rank(self, *a, local_generation)
                .cmp(&birthday_base_rank(self, *b, local_generation))
                .then_with(|| a.cmp(b))
        });
        bases.dedup();
        bases.truncate(BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE);
        bases
    }

    fn prune_stale_peer_reflexive_candidates_for_ip(
        &mut self,
        fresh_endpoint: SocketAddr,
        local_generation: u64,
    ) -> usize {
        if !is_public_probe_endpoint(fresh_endpoint) {
            return 0;
        }

        let mut peer_reflexive = self
            .candidate_sources
            .iter()
            .filter_map(|(candidate, source)| {
                (*source == CandidatePairSource::PeerReflexive)
                    .then(|| candidate.parse::<SocketAddr>().ok())
                    .flatten()
            })
            .filter(|endpoint| {
                endpoint.ip() == fresh_endpoint.ip() && is_public_probe_endpoint(*endpoint)
            })
            .collect::<Vec<_>>();

        if peer_reflexive.len() <= PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS {
            return 0;
        }

        peer_reflexive.sort_by(|a, b| {
            peer_reflexive_retention_rank(self, *a, fresh_endpoint, local_generation)
                .cmp(&peer_reflexive_retention_rank(
                    self,
                    *b,
                    fresh_endpoint,
                    local_generation,
                ))
                .then_with(|| a.cmp(b))
        });

        let mut retained = peer_reflexive
            .iter()
            .take(PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS)
            .copied()
            .collect::<HashSet<_>>();

        for pair in &self.candidate_pairs {
            if pair.local_generation == local_generation
                && pair.source == CandidatePairSource::PeerReflexive
                && pair.remote_endpoint.ip() == fresh_endpoint.ip()
                && should_retain_peer_reflexive_pair(pair)
            {
                retained.insert(pair.remote_endpoint);
            }
        }

        let removed = peer_reflexive
            .into_iter()
            .filter(|endpoint| !retained.contains(endpoint))
            .collect::<HashSet<_>>();
        if removed.is_empty() {
            return 0;
        }

        self.candidates.retain(|candidate| {
            candidate
                .parse::<SocketAddr>()
                .map_or(true, |endpoint| !removed.contains(&endpoint))
        });
        for endpoint in &removed {
            self.candidate_sources.remove(&endpoint.to_string());
        }
        self.candidate_pairs.retain(|pair| {
            !(pair.local_generation == local_generation
                && pair.source == CandidatePairSource::PeerReflexive
                && removed.contains(&pair.remote_endpoint)
                && !should_retain_peer_reflexive_pair(pair))
        });

        removed.len()
    }
}

fn is_authoritative_stable_public_source(source: CandidatePairSource) -> bool {
    matches!(
        source,
        CandidatePairSource::StunObserved
            | CandidatePairSource::Signaled
            | CandidatePairSource::Upnp
            | CandidatePairSource::Pcp
            | CandidatePairSource::NatPmp
    )
}
