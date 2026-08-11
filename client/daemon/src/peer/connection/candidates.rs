impl PeerConnection {
    fn commit_birthday_probe_cursor(&mut self, start_rank: usize, end_rank: usize) -> bool {
        if self.birthday_probe_cursor != start_rank {
            return false;
        }
        self.birthday_probe_cursor = end_rank % birthday_probe_wide_rank_count();
        true
    }

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

    fn candidate_targets_need_remote_scatter_pool(&self, endpoints: &[SocketAddr]) -> bool {
        if endpoints.iter().any(|endpoint| {
            matches!(
                self.candidate_source_for_endpoint(*endpoint),
                CandidatePairSource::Predicted | CandidatePairSource::Birthday
            )
        }) {
            return true;
        }

        let mut ports_by_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        for endpoint in endpoints
            .iter()
            .copied()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
        {
            ports_by_ip
                .entry(endpoint.ip())
                .or_default()
                .insert(endpoint.port());
        }
        ports_by_ip
            .values()
            .any(|ports| ports.len() >= REMOTE_SCATTER_POOL_MIN_PUBLIC_PORTS)
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
            if target_endpoints.contains(&pair.remote_endpoint) {
                return true;
            }
            if pair.local_generation == local_generation {
                return matches!(
                    pair.state,
                    CandidatePairState::Selected | CandidatePairState::Succeeded
                ) && pair
                    .last_success_at
                    .is_some_and(|at| at.elapsed() < DIRECT_TRIAL_WINDOW);
            }
            // Pairs from older generations are diagnostics only: retain just
            // the ones carrying success evidence, because the Direct-reclaim
            // window and `has_direct_success_history` read the pair table
            // across generations.  Everything else (the retired birthday and
            // predicted windows of previous generations) is dropped so
            // candidate state cannot balloon across generations.
            pair.success_count > 0
                || pair.selected_at.is_some()
                || matches!(
                    pair.state,
                    CandidatePairState::Selected | CandidatePairState::Succeeded
                )
        });
        before
            .saturating_sub(self.candidate_pairs.len())
            .saturating_add(self.retire_candidate_pairs_over_cap(local_generation))
    }

    /// Enforce the hard per-peer candidate-pair bound.  Retires the oldest
    /// non-target pairs without any success evidence (old generations first,
    /// then least-probed, then least recently observed) until the table fits.
    /// Returns the number of pairs retired.
    fn retire_candidate_pairs_over_cap(&mut self, local_generation: u64) -> usize {
        if self.candidate_pairs.len() <= MAX_CANDIDATE_PAIRS_PER_PEER {
            return 0;
        }
        let mut removable = self
            .candidate_pairs
            .iter()
            .enumerate()
            .filter(|(_, pair)| {
                pair.success_count == 0
                    && pair.selected_at.is_none()
                    && pair.last_success_at.is_none()
                    && !matches!(
                        pair.state,
                        CandidatePairState::Selected | CandidatePairState::Succeeded
                    )
            })
            .map(|(index, pair)| {
                (
                    index,
                    pair.local_generation != local_generation,
                    pair.probe_count,
                    pair.source_observed_at.map(|at| at.elapsed()),
                )
            })
            .collect::<Vec<_>>();
        removable.sort_by(|left, right| {
            // `true` means an old generation: retire it before current
            // generation pairs. Within a generation, lower probe value and
            // older observation are the weaker evidence.
            right
                .1
                .cmp(&left.1)
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| {
                    right
                        .3
                        .unwrap_or(Duration::MAX)
                        .cmp(&left.3.unwrap_or(Duration::MAX))
                })
        });
        let mut indices = removable
            .into_iter()
            .map(|(index, _, _, _)| index)
            .collect::<Vec<_>>();
        indices.sort_unstable_by(|left, right| right.cmp(left));
        let mut removed = 0usize;
        for index in indices {
            if self.candidate_pairs.len() <= MAX_CANDIDATE_PAIRS_PER_PEER {
                break;
            }
            self.candidate_pairs.remove(index);
            removed += 1;
        }
        if removed > 0 {
            self.record_direct_event(
                local_generation,
                "candidate_pair_state_bounded",
                None,
                Some(self.candidate_pairs.len()),
                None,
                format!(
                    "retired {removed} candidate pairs to stay within the {MAX_CANDIDATE_PAIRS_PER_PEER}-pair per-peer cap"
                ),
            );
        }
        removed
    }

    /// Retire unsuccessful speculative probe pairs while a confirmed Direct
    /// path is healthy, so diagnostics no longer present hundreds of stale
    /// predicted/birthday/STUN sweep pairs as current probing state.
    ///
    /// Only the pair state is frozen; traversal history, cooldown counters and
    /// the advertised candidate list are untouched. When the Direct path
    /// fails, the network generation changes, or the selected pair ages out,
    /// probing resumes and these pairs are re-expanded from the same
    /// candidates. Returns the number of pairs retired.
    pub(super) fn retire_speculative_pairs_when_direct_confirmed(
        &mut self,
        local_generation: u64,
    ) -> usize {
        if self.state != ConnectionState::Direct
            || self.direct_health.consecutive_failures != 0
            || !self
                .direct_health
                .success_age()
                .is_some_and(|age| age <= RELAY_PEER_CONFIRMATION_MAX_AGE)
            || !self.candidate_pairs.iter().any(|pair| {
                pair.local_generation == local_generation
                    && pair.state == CandidatePairState::Selected
                    && pair.consecutive_failures == 0
                    && pair
                        .success_age()
                        .is_some_and(|age| age <= RELAY_PEER_CONFIRMATION_MAX_AGE)
            })
        {
            return 0;
        }

        let mut pruned_predicted = 0usize;
        let mut pruned_birthday = 0usize;
        let mut pruned_stun = 0usize;
        for pair in self.candidate_pairs.iter_mut() {
            if pair.local_generation != local_generation
                || pair.state == CandidatePairState::Frozen
                || pair.state == CandidatePairState::Selected
                || pair.last_success_at.is_some()
                || is_low_latency_direct_endpoint(pair.remote_endpoint)
            {
                continue;
            }
            match pair.source {
                CandidatePairSource::Predicted => pruned_predicted += 1,
                CandidatePairSource::Birthday => pruned_birthday += 1,
                CandidatePairSource::StunObserved => pruned_stun += 1,
                _ => continue,
            }
            pair.state = CandidatePairState::Frozen;
        }
        let total = pruned_predicted + pruned_birthday + pruned_stun;
        if total > 0 {
            self.record_direct_event(
                local_generation,
                "speculative_pairs_retired",
                self.endpoint,
                Some(total),
                None,
                format!(
                    "retired speculative probing pairs while Direct confirmed: pruned_predicted_count={pruned_predicted} pruned_birthday_count={pruned_birthday} pruned_stun_count={pruned_stun} retained_reason=selected_direct_healthy"
                ),
            );
        }
        total
    }

    fn candidate_probe_endpoints(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        mode: ProbeTargetMode,
        max_targets: Option<usize>,
    ) -> (Vec<SocketAddr>, Option<BirthdayProbePlan>) {
        self.ensure_current_candidate_pairs(local_generation);
        let use_asymmetric_stable_role =
            self.should_use_asymmetric_stable_remote_role(local_nat_profile);
        let stable_side_unique_scatter =
            self.should_use_stable_side_unique_scatter(local_nat_profile);
        let mut endpoints = if use_asymmetric_stable_role {
            self.asymmetric_stable_remote_endpoints(local_generation)
        } else {
            self.probe_candidate_endpoints()
        };
        // The asymmetric role NEVER birthday-sweeps: the easy peer's
        // multi-port set was already accepted as a stable socket pool (the
        // role gate bounds it), and scanning it as "port churn" would turn
        // the hard side's compact stable-endpoint burst into a wide sweep
        // against a peer that only has 3-4 live mappings.  The easy side is
        // the one that scans this side's moving port window.
        let mut birthday_plan = if use_asymmetric_stable_role {
            None
        } else {
            self.ensure_birthday_candidate_pairs(
                local_generation,
                history,
                local_nat_profile,
                mode.allows_local_nat_birthday() && !use_asymmetric_stable_role,
                mode.allows_failed_prediction_fallback() && !use_asymmetric_stable_role,
                stable_side_unique_scatter,
                &mut endpoints,
                max_targets,
            )
        };
        self.prune_candidate_pairs_outside_targets(local_generation, &endpoints);
        let source_stats =
            candidate_pair_source_stats(&self.candidate_pairs, local_generation, None);
        let active_endpoint = self.endpoint;
        let now = Instant::now();
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
                    // The sender ordered its predicted window by priority
                    // (top-1 first); probe it in that order so a
                    // linear-symmetric peer's peer-facing mapping is hit
                    // before wider fallbacks.  This must outrank any
                    // recency/probe-count heuristics for `Predicted` pairs.
                    a.signal_rank
                        .unwrap_or(u32::MAX)
                        .cmp(&b.signal_rank.unwrap_or(u32::MAX))
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
                    candidate_pair_freshness_rank_at(a, now)
                        .cmp(&candidate_pair_freshness_rank_at(b, now))
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
        let endpoints = apply_adaptive_probe_budgets(
            pairs,
            &source_stats,
            history,
            mode,
            birthday_plan
                .as_ref()
                .filter(|plan| plan.stable_side_unique_scatter)
                .map(|plan| plan.generated_candidates),
        )
        .into_iter()
        .map(|pair| pair.remote_endpoint)
        .collect::<Vec<_>>();
        // The recovery stage cap is applied to the FINAL list as well: when
        // `max_targets` is set, the plan must not carry candidates beyond the
        // stage's real scan window, or `planned != selected` would stall the
        // birthday cursor forever on a truncated plan.
        let endpoints = if let Some(max_targets) = max_targets {
            endpoints.into_iter().take(max_targets).collect::<Vec<_>>()
        } else {
            endpoints
        };
        let selected_birthday_candidates = endpoints
            .iter()
            .filter(|endpoint| {
                self.candidate_source_for_endpoint(**endpoint) == CandidatePairSource::Birthday
            })
            .count();
        if let Some(plan) = birthday_plan.as_mut() {
            plan.selected_candidates = endpoints.len();
            plan.selected_birthday_candidates = selected_birthday_candidates;
            plan.unique_target_ports = endpoints
                .iter()
                .map(|endpoint| endpoint.port())
                .collect::<HashSet<_>>()
                .len();
        }
        (endpoints, birthday_plan)
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
            && public_endpoints_fit_stable_socket_pool(&public_endpoints)
    }

    fn should_use_stable_side_unique_scatter(
        &self,
        local_nat_profile: Option<&NatProfile>,
    ) -> bool {
        let local_is_stable = local_nat_profile.is_some_and(|profile| {
            !profile.udp_blocked
                && profile.public_ip_stable == Some(true)
                && profile.public_port_stable == Some(true)
                && matches!(
                    profile.mapping_behavior,
                    MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
                )
        });
        if !local_is_stable {
            return false;
        }

        self.has_explicit_predicted_window()
            || self.candidate_targets_need_remote_scatter_pool(&self.probe_candidate_endpoints())
    }

    /// Widened trigger for the NAT-state binding maintainer.
    ///
    /// Probe-target selection keeps the strict asymmetric-role predicate above
    /// so easy NATs still expand predicted/birthday windows, but the maintainer
    /// only needs stable peer endpoints plus any hard-NAT risk signal. A
    /// symmetric side whose explicit predicted window was advertised, or whose
    /// local profile detection was imprecise, still keeps one destination-
    /// specific binding warm toward the stable peer while that peer scans this
    /// side's moving public-port window.
    fn should_maintain_nat_binding_toward_stable_remote(
        &self,
        local_nat_profile: Option<&NatProfile>,
    ) -> bool {
        let local_hard_nat = local_nat_profile.is_some_and(is_hard_nat_profile);
        let remote_scatter_risk = self
            .candidate_targets_need_remote_scatter_pool(&self.probe_candidate_endpoints());
        if !local_hard_nat && !remote_scatter_risk {
            return false;
        }

        let public_endpoints =
            self.asymmetric_stable_public_endpoints(self.probe_candidate_endpoints());
        !public_endpoints.is_empty() && public_endpoints_fit_stable_socket_pool(&public_endpoints)
    }

    fn asymmetric_stable_public_endpoints(&self, endpoints: Vec<SocketAddr>) -> Vec<SocketAddr> {
        self.asymmetric_stable_endpoints(endpoints, false)
    }

    /// Stable remote targets for a fresh-mapping generation.
    ///
    /// Production only accepts public endpoints. The deterministic NAT
    /// harness opts into loopback explicitly so it can exercise the same
    /// source-selection policy without weakening the production boundary.
    pub(crate) fn asymmetric_stable_endpoints_for_fresh_mapping(
        &self,
        endpoints: Vec<SocketAddr>,
        allow_loopback: bool,
    ) -> Vec<SocketAddr> {
        self.asymmetric_stable_endpoints(endpoints, allow_loopback)
    }

    fn asymmetric_stable_endpoints(
        &self,
        endpoints: Vec<SocketAddr>,
        allow_loopback: bool,
    ) -> Vec<SocketAddr> {
        let eligible = |endpoint: SocketAddr| {
            is_public_probe_endpoint(endpoint) || (allow_loopback && endpoint.ip().is_loopback())
        };
        let mut authoritative = endpoints
            .iter()
            .copied()
            .filter(|endpoint| eligible(*endpoint))
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
            .filter(|endpoint| eligible(*endpoint))
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
        // Cover EVERY advertised stable public mapping in the bounded initial
        // burst.  The easy peer's socket-pool bindings expire independently
        // (only one may be alive right now), so ranking alone is never enough:
        // `public.first()` would freeze the punch on whatever endpoint was
        // learned most recently even when its mapping is dead.  The pool-size
        // gate (`public_endpoints_fit_stable_socket_pool`) keeps this set
        // small; the truncation below is the final hard bound.
        public.truncate(ASYMMETRIC_STABLE_MAX_PUBLIC_ENDPOINTS);
        for endpoint in public {
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        endpoints
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_birthday_candidate_pairs(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        allow_local_nat_trigger: bool,
        allow_failed_prediction_fallback: bool,
        stable_side_unique_scatter: bool,
        endpoints: &mut Vec<SocketAddr>,
        max_targets: Option<usize>,
    ) -> Option<BirthdayProbePlan> {
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
            return None;
        }

        let per_base_budget = birthday_probe_budget(history);
        let budget = if stable_side_unique_scatter {
            STABLE_WIDE_SCATTER_UNIQUE_TARGET_BUDGET.saturating_sub(endpoints.len())
        } else {
            per_base_budget.saturating_mul(bases.len().min(BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE))
        };
        // Slice the plan to the window that will actually be sent this
        // session.  The stage cap (`max_targets`) and the per-plan slice keep
        // the generated window inside the real scan window, so the plan
        // never persists hundreds of birthday pairs that the stage caps
        // truncate away, and the cursor can advance rank-by-rank.
        let slice = max_targets
            .unwrap_or(usize::MAX)
            .min(if stable_side_unique_scatter {
                STABLE_SCATTER_PLAN_SLICE
            } else {
                BIRTHDAY_PLAN_SLICE
            });
        let budget = budget.min(slice.saturating_sub(endpoints.len()));
        if budget == 0 {
            return None;
        }

        let mut generated = 0usize;
        let mut public_ips = bases.iter().map(|base| base.ip()).collect::<Vec<_>>();
        public_ips.sort_unstable();
        public_ips.dedup();
        if stable_side_unique_scatter && public_ips.is_empty() {
            return None;
        }
        let rotation_start_rank = if stable_side_unique_scatter {
            self.birthday_probe_cursor % birthday_probe_wide_rank_count()
        } else {
            self.candidate_pairs
                .iter()
                .filter(|pair| {
                    pair.local_generation == local_generation
                        && pair.source == CandidatePairSource::Birthday
                })
                .map(|pair| pair.probe_count as usize)
                .min()
                .unwrap_or(0)
                .saturating_mul(per_base_budget)
                % birthday_probe_wide_rank_count()
        };
        let endpoint_plan = if stable_side_unique_scatter {
            stable_public_ip_probe_plan_from_rank(
                &public_ips,
                budget,
                rotation_start_rank,
                &endpoints.iter().copied().collect(),
            )
        } else {
            birthday_probe_endpoint_plan_for_bases_from_rank(
                &bases,
                budget,
                rotation_start_rank,
                true,
            )
        };
        let plan_end_rank = endpoint_plan.next_rank;
        let plan_wrapped = endpoint_plan.wrapped;
        for endpoint in endpoint_plan.endpoints {
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
                break;
            }
        }
        Some(BirthdayProbePlan {
            local_generation,
            stable_side_unique_scatter,
            bases,
            public_ips,
            start_rank: rotation_start_rank,
            end_rank: plan_end_rank,
            generated_candidates: generated,
            planned_candidates: endpoints.len(),
            selected_candidates: 0,
            selected_birthday_candidates: 0,
            unique_target_ports: 0,
            wrapped: plan_wrapped,
        })
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

fn public_endpoints_fit_stable_socket_pool(endpoints: &[SocketAddr]) -> bool {
    let mut ports_by_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
    for endpoint in endpoints {
        if !is_public_probe_endpoint(*endpoint) {
            continue;
        }
        ports_by_ip
            .entry(endpoint.ip())
            .or_default()
            .insert(endpoint.port());
    }
    !ports_by_ip.is_empty()
        && ports_by_ip
            .values()
            .all(|ports| ports.len() <= STABLE_PUBLIC_POOL_MAX_PORTS_PER_IP)
}
