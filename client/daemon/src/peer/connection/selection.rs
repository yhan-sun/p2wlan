impl PeerConnection {
    pub(super) fn is_overlay_candidate_pair(&self, pair: &CandidatePair) -> bool {
        is_overlay_endpoint(pair.remote_endpoint)
            && !self.is_on_link_host_candidate(pair.remote_endpoint)
    }

    pub(super) fn is_overlay_direct_endpoint(&self, endpoint: SocketAddr) -> bool {
        self.candidate_pairs
            .iter()
            .filter(|pair| pair.remote_endpoint == endpoint)
            .all(|pair| self.is_overlay_candidate_pair(pair))
    }

    fn candidate_pairs_for_send(&self, local_generation: u64) -> Vec<&CandidatePair> {
        let now = Instant::now();
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && self.pair_belongs_to_current_remote_epoch(pair)
                    && !self.is_overlay_candidate_pair(pair)
                    && (matches!(
                        pair.state,
                        CandidatePairState::Selected
                            | CandidatePairState::Succeeded
                            | CandidatePairState::Probing
                            | CandidatePairState::Waiting
                    ) || is_recent_successful_direct_trial_pair_at(pair, now))
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            candidate_pair_send_rank_at(a, now, self.is_on_link_host_candidate(a.remote_endpoint))
                .cmp(&candidate_pair_send_rank_at(
                    b,
                    now,
                    self.is_on_link_host_candidate(b.remote_endpoint),
                ))
                .then_with(|| candidate_pair_last_success_sort_key(a).cmp(&candidate_pair_last_success_sort_key(b)))
                .then_with(|| {
                    candidate_pair_source_rank(a.source).cmp(&candidate_pair_source_rank(b.source))
                })
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
        pairs
    }

    fn best_candidate_pair_for_send(&self, local_generation: u64) -> Option<&CandidatePair> {
        self.candidate_pairs_for_send(local_generation)
            .into_iter()
            .next()
    }

    fn direct_endpoint_for_send(&self, local_generation: u64) -> Option<SocketAddr> {
        self.best_candidate_pair_for_send(local_generation)
            .map(|pair| pair.remote_endpoint)
            .or_else(|| {
                self.endpoint
                    .filter(|endpoint| {
                        !self.is_overlay_direct_endpoint(*endpoint)
                            && self.is_current_remote_endpoint(*endpoint)
                    })
            })
    }

    pub(crate) fn selected_direct_endpoint_for_consent(
        &self,
        local_generation: u64,
    ) -> Option<SocketAddr> {
        self.candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && self.pair_belongs_to_current_remote_epoch(pair)
                    && !self.is_overlay_candidate_pair(pair)
                    && pair.selected_at.is_some()
                    && pair.state != CandidatePairState::Frozen
            })
            .min_by_key(|pair| {
                (
                    std::cmp::Reverse(pair.selected_at.expect("filtered selected_at")),
                    pair.rtt_ewma_ms.or(pair.rtt_ms).unwrap_or(u64::MAX),
                    pair.remote_endpoint,
                )
            })
            .map(|pair| pair.remote_endpoint)
    }

    pub(crate) fn should_upgrade_direct_to_on_link(
        &self,
        local_generation: u64,
        endpoint: SocketAddr,
    ) -> bool {
        if self.state != ConnectionState::Direct
            || !self.is_current_remote_endpoint(endpoint)
            || !self.is_on_link_host_candidate(endpoint)
        {
            return false;
        }

        let selected_endpoint = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && self.pair_belongs_to_current_remote_epoch(pair)
                    && !self.is_overlay_candidate_pair(pair)
                    && pair.state == CandidatePairState::Selected
                    && pair.selected_at.is_some()
            })
            .max_by_key(|pair| pair.selected_at)
            .map(|pair| pair.remote_endpoint)
            .or(self.endpoint);

        selected_endpoint != Some(endpoint)
            && selected_endpoint.is_none_or(|selected| {
                !self.is_on_link_host_candidate(selected)
            })
    }

    fn selected_candidate_pair_for_diagnostics(
        &self,
        local_generation: u64,
    ) -> Option<&CandidatePair> {
        let now = Instant::now();
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && self.pair_belongs_to_current_remote_epoch(pair)
                    && pair.state == CandidatePairState::Selected
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            candidate_pair_send_rank_at(a, now, self.is_on_link_host_candidate(a.remote_endpoint))
                .cmp(&candidate_pair_send_rank_at(
                    b,
                    now,
                    self.is_on_link_host_candidate(b.remote_endpoint),
                ))
                .then_with(|| {
                    candidate_pair_source_rank(a.source).cmp(&candidate_pair_source_rank(b.source))
                })
                .then_with(|| {
                    a.rtt_ewma_ms
                        .or(a.rtt_ms)
                        .unwrap_or(u64::MAX)
                        .cmp(&b.rtt_ewma_ms.or(b.rtt_ms).unwrap_or(u64::MAX))
                })
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });
        pairs.into_iter().next()
    }

    fn current_direct_pair_for_diagnostics(
        &self,
        local_generation: u64,
        current_selection: Option<&PathSelection>,
    ) -> Option<&CandidatePair> {
        if let Some(endpoint) = current_selection.and_then(|selection| selection.direct_endpoint) {
            if let Some(pair) = self.candidate_pairs.iter().find(|pair| {
                pair.local_generation == local_generation
                    && self.pair_belongs_to_current_remote_epoch(pair)
                    && pair.remote_endpoint == endpoint
            }) {
                return Some(pair);
            }
        }

        self.selected_candidate_pair_for_diagnostics(local_generation)
            .or_else(|| self.best_candidate_pair_for_send(local_generation))
    }

    fn direct_path_score(
        &self,
        local_generation: u64,
        direct_endpoint: Option<SocketAddr>,
        confirmed: bool,
        trial: bool,
    ) -> Option<PathScore> {
        let direct_endpoint = direct_endpoint?;
        let pair = self.candidate_pairs.iter().find(|pair| {
            pair.local_generation == local_generation
                && self.pair_belongs_to_current_remote_epoch(pair)
                && pair.remote_endpoint == direct_endpoint
        });

        let reachable = confirmed || trial;
        let reachability_score = if confirmed {
            80
        } else if trial {
            50
        } else {
            0
        };
        let preference_score = 10;
        let latency_ms = pair
            .and_then(|pair| pair.rtt_ewma_ms.or(pair.rtt_ms))
            .or(self
                .direct_health
                .rtt_ewma_ms
                .or(self.direct_health.latency_ms));
        let jitter_ms = pair
            .and_then(|pair| pair.jitter_ms)
            .or(self.direct_health.jitter_ms);
        let latency_score = latency_score(latency_ms);
        let jitter_penalty = jitter_penalty(jitter_ms);
        let stability_score = stability_score(
            self.direct_health.success_count,
            self.direct_health.consecutive_failures,
            self.direct_health.failure_count,
        );
        let migration_penalty = if trial && !confirmed { -5 } else { 0 };
        let penalty_score = jitter_penalty + migration_penalty;
        let score =
            reachability_score + preference_score + latency_score + stability_score + penalty_score;
        Some(PathScore {
            path: NetworkPath::Direct,
            score,
            reachable,
            reachability_score,
            preference_score,
            latency_score,
            stability_score,
            penalty_score,
            reason: format!(
                "reachable={reachable} confirmed={confirmed} trial={trial} rtt={} jitter={} failures={}",
                format_optional_ms(latency_ms),
                format_optional_ms(jitter_ms),
                self.direct_health.consecutive_failures,
            ),
        })
    }

    fn relay_path_score(&self, relay_available: bool) -> Option<PathScore> {
        if !relay_available {
            return None;
        }
        let reachability_score = 55;
        let preference_score = 0;
        let latency_score = latency_score(
            self.relay_health
                .rtt_ewma_ms
                .or(self.relay_health.latency_ms),
        );
        let jitter_penalty = jitter_penalty(self.relay_health.jitter_ms);
        let stability_score = stability_score(
            self.relay_health.success_count,
            self.relay_health.consecutive_failures,
            self.relay_health.failure_count,
        );
        let penalty_score = jitter_penalty;
        let score =
            reachability_score + preference_score + latency_score + stability_score + penalty_score;
        Some(PathScore {
            path: NetworkPath::Relay,
            score,
            reachable: true,
            reachability_score,
            preference_score,
            latency_score,
            stability_score,
            penalty_score,
            reason: format!(
                "relay_available=true rtt={} jitter={} failures={}",
                format_optional_ms(
                    self.relay_health
                        .rtt_ewma_ms
                        .or(self.relay_health.latency_ms)
                ),
                format_optional_ms(self.relay_health.jitter_ms),
                self.relay_health.consecutive_failures,
            ),
        })
    }

    /// A recent relay-health sample is not relay admission.  It can come from
    /// a local writer completion or a validation packet that was not proven to
    /// have reached this peer.  Only the same-generation encrypted relay ACK
    /// may authorize a Direct -> Relay fallback for business traffic.
    fn relay_peer_confirmed_for_generation(&self, local_generation: u64) -> bool {
        self.relay_confirmed_at.is_some()
            && self.relay_confirmed_generation == Some(local_generation)
            && self
                .relay_confirmed_endpoint
                .as_deref()
                .is_some_and(|endpoint| !endpoint.is_empty())
    }

    fn relay_first_confirmation_pending(
        &self,
        local_generation: u64,
        relay_available: bool,
    ) -> bool {
        // Relay ticket renewal is make-before-break.  Once this generation
        // has completed the initial relay-first business exchange, a fresh
        // relay incarnation must not pause an already established Direct
        // path while its fallback proof is renewed in the background.
        if self.relay_first.business_gate_completed_generation == Some(local_generation) {
            return false;
        }
        let gate_started_at = if self.relay_ready_generation == Some(local_generation) {
            self.relay_ready_at
        } else if self.relay_first.gate_generation == Some(local_generation) {
            self.relay_first.gate_started_at
        } else {
            None
        };
        relay_available
            && gate_started_at.is_some()
            && !self.relay_peer_confirmed_for_generation(local_generation)
            && gate_started_at
                .map(|started_at| {
                    Instant::now().saturating_duration_since(started_at)
                        < RELAY_FIRST_CONFIRMATION_GRACE
                })
                .unwrap_or(true)
    }

    fn relay_first_business_pending(
        &self,
        local_generation: u64,
        relay_available: bool,
    ) -> bool {
        if !relay_available
            || self.relay_ready_generation != Some(local_generation)
            || !self.relay_peer_confirmed_for_generation(local_generation)
            || self.relay_first.business_gate_completed_generation == Some(local_generation)
            || self.relay_first.business_exchange_generation == Some(local_generation)
            || self.relay_first.business_pathcommit_generation == Some(local_generation)
        {
            return false;
        }
        // A confirmed relay is the safety path for this generation.  Do not
        // let a wall-clock grace window turn a missing business ingress into
        // a Direct promotion: that would make the first real TUN packet
        // depend on scheduling rather than on the relay-first invariant.
        // The relay transport itself has already been proven by the encrypted
        // probe ACK; the only remaining gate is that both local business
        // directions have crossed this same confirmed relay.
        true
    }

    pub(super) fn select_path_for_data_with_policy(
        &self,
        local_generation: u64,
        policy: crate::config::PathPolicy,
        relay_available: bool,
    ) -> PathSelection {
        let direct_endpoint = self.direct_endpoint_for_send(local_generation);
        let relay_score = self.relay_path_score(relay_available);

        if policy == crate::config::PathPolicy::RelayOnly {
            return if relay_available {
                PathSelection::relay(
                    REASON_PATH_DIRECT_DISABLED,
                    "relay policy disables direct UDP",
                )
                .with_scores(None, relay_score)
            } else {
                PathSelection::unavailable(
                    REASON_PATH_UNAVAILABLE,
                    "relay unavailable and Direct is not encrypted-confirmed",
                )
                .with_scores(None, None)
            };
        }

        let Some(endpoint) = direct_endpoint else {
            return if relay_available {
                PathSelection::relay(
                    REASON_PATH_DIRECT_NO_ENDPOINT,
                    "direct UDP has no candidate endpoint",
                )
                .with_scores(None, relay_score)
            } else {
                PathSelection::unavailable(
                    REASON_PATH_UNAVAILABLE,
                    "no relay and no direct UDP endpoint exists",
                )
                .with_scores(None, None)
            };
        };

        let selected_pair = self.candidate_pairs.iter().find(|pair| {
            pair.local_generation == local_generation
                && self.pair_belongs_to_current_remote_epoch(pair)
                && pair.remote_endpoint == endpoint
        });
        let selected_pair_state = selected_pair.map(|pair| pair.state);
        let confirmed_direct = self.state == ConnectionState::Direct
            && selected_pair_state == Some(CandidatePairState::Selected);
        let recent_success_trial =
            selected_pair.is_some_and(is_recent_successful_direct_trial_pair);
        let trial_direct = selected_pair.is_some_and(|pair| {
            pair.state == CandidatePairState::Succeeded
                || (pair.state == CandidatePairState::Probing && pair.nominated)
        }) && self.direct_health.consecutive_failures == 0
            && self
                .direct_health
                .success_age()
                .map(|age| age <= DIRECT_TRIAL_WINDOW)
                .unwrap_or(false)
            || recent_success_trial;
        let direct_score = self.direct_path_score(
            local_generation,
            Some(endpoint),
            confirmed_direct,
            trial_direct,
        );
        // `auto` keeps the existing LAN/private-direct safety preference.
        // An explicit `score` policy opts into score-based selection even for
        // a private endpoint; `direct-sticky` returns earlier and never
        // reaches this quality fallback.
        let retain_private_direct = policy != crate::config::PathPolicy::Score
            && selected_pair.is_some_and(should_retain_private_direct_pair);
        // An encrypted-confirmed pair whose endpoint is on one of our physical
        // interface prefixes is already the strongest available path.  The
        // relay-first business gate is a safety net for off-link traversal;
        // applying it to a proven LAN pair needlessly sends local traffic via
        // the relay and can overwrite a successful 4 ms direct path.
        let on_link_direct = selected_pair
            .is_some_and(|pair| self.is_on_link_host_candidate(pair.remote_endpoint));

        if confirmed_direct {
            // Direct validation is deliberately allowed to run in parallel,
            // but it is not allowed to win the first business packet while a
            // relay transport is already ready for this peer and its matching
            // encrypted relay ACK is still pending.  Returning unavailable
            // (rather than Direct or an unconfirmed Relay) makes the outbound
            // FIFO retain the plaintext packet and keeps its WireGuard counter
            // from being committed on the wrong path.
            if !on_link_direct
                && self.relay_first_confirmation_pending(local_generation, relay_available)
            {
                return PathSelection::unavailable(
                    REASON_PATH_RELAY_FIRST_PENDING,
                    "Direct is encrypted-confirmed, but same-generation relay peer ACK is pending",
                )
                .with_scores(direct_score, relay_score);
            }
            if !on_link_direct && self.relay_first_business_pending(local_generation, relay_available) {
                return PathSelection::relay(
                    REASON_PATH_RELAY_FIRST_BUSINESS,
                    "same-generation relay peer is confirmed; both relay business directions are required before off-link Direct",
                )
                .with_scores(direct_score, relay_score);
            }
            if self.relay_peer_confirmed_for_generation(local_generation)
                && selected_pair.is_some_and(|pair| {
                    pair.slow_validation_is_recent_at(
                        Instant::now(),
                        SLOW_DIRECT_RELAY_RETRY_COOLDOWN,
                    )
                })
            {
                if policy != crate::config::PathPolicy::DirectSticky {
                    return PathSelection::relay(
                        REASON_PATH_DIRECT_SLOW_RELAY_RETAINED,
                        format!(
                            "probe-only Direct evidence is quarantined for {}ms after a slow ACK",
                            SLOW_DIRECT_RELAY_RETRY_COOLDOWN.as_millis()
                        ),
                    )
                    .with_scores(direct_score, relay_score);
                }
            }

            // `direct-sticky` deliberately ignores score and historical
            // latency/failure penalties after encrypted Direct promotion. A
            // hard consent/keepalive failure still changes the connection
            // state before the selector is called, so this cannot force a
            // dead socket to remain active.
            if policy == crate::config::PathPolicy::DirectSticky {
                return PathSelection::direct(
                    endpoint,
                    REASON_PATH_DIRECT_STICKY,
                    format!(
                        "encrypted Direct is sticky; keeping endpoint {endpoint} until hard liveness failure"
                    ),
                    true,
                )
                .with_scores(direct_score, relay_score);
            }

            // An encrypted Direct validation is the admission proof for this
            // generation.  Probe failures accumulated before that proof are
            // historical telemetry, not evidence that the newly validated
            // path is currently unhealthy.  Let the path become active and
            // let the consent/keepalive monitor provide the failure evidence
            // needed for a relay fallback.  Otherwise a fresh Direct ACK can
            // be immediately undone by the score's historical failure term.
            let direct_has_current_failure = self.direct_health.consecutive_failures > 0;
            if let (Some(direct_score), Some(relay_score)) = (&direct_score, &relay_score) {
                let score_policy = policy == crate::config::PathPolicy::Score;
                if (score_policy || direct_has_current_failure)
                    && !retain_private_direct
                    && direct_score.score < DIRECT_CONFIRMED_MIN_SCORE
                    && direct_score.score <= relay_score.score
                {
                    if !self.relay_peer_confirmed_for_generation(local_generation) {
                        return PathSelection::direct(
                            endpoint,
                            if score_policy {
                                REASON_PATH_SCORE_DIRECT
                            } else {
                                REASON_PATH_DIRECT_DEGRADED
                            },
                            format!(
                                "{} direct score {} is poor, but relay is not peer-confirmed; retaining Direct",
                                if score_policy { "score policy:" } else { "confirmed" },
                                direct_score.score
                            ),
                            true,
                        )
                        .with_scores(Some(direct_score.clone()), Some(relay_score.clone()));
                    }
                    return PathSelection::relay(
                        if score_policy {
                            REASON_PATH_SCORE_RELAY
                        } else {
                            REASON_PATH_DIRECT_DEGRADED
                        },
                        format!(
                            "{} direct score {} is below quality floor {} and relay score {}",
                            if score_policy { "score policy:" } else { "confirmed" },
                            direct_score.score, DIRECT_CONFIRMED_MIN_SCORE, relay_score.score
                        ),
                    )
                    .with_scores(Some(direct_score.clone()), Some(relay_score.clone()));
                }
                if (score_policy || direct_has_current_failure)
                    && !retain_private_direct
                    && direct_score.score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN < relay_score.score
                {
                    if !self.relay_peer_confirmed_for_generation(local_generation) {
                        return PathSelection::direct(
                            endpoint,
                            if score_policy {
                                REASON_PATH_SCORE_DIRECT
                            } else {
                                REASON_PATH_DIRECT_DEGRADED
                            },
                            format!(
                                "{} direct score {} is below relay score {}, but relay is not peer-confirmed; retaining Direct",
                                if score_policy { "score policy:" } else { "confirmed" },
                                direct_score.score,
                                relay_score.score
                            ),
                            true,
                        )
                        .with_scores(Some(direct_score.clone()), Some(relay_score.clone()));
                    }
                    return PathSelection::relay(
                        if score_policy {
                            REASON_PATH_SCORE_RELAY
                        } else {
                            REASON_PATH_DIRECT_DEGRADED
                        },
                        format!(
                            "{} direct score {} is below relay score {} after hysteresis",
                            if score_policy { "score policy:" } else { "confirmed" },
                            direct_score.score, relay_score.score
                        ),
                    )
                    .with_scores(Some(direct_score.clone()), Some(relay_score.clone()));
                }
            }
            return PathSelection::direct(
                endpoint,
                if policy == crate::config::PathPolicy::Score {
                    REASON_PATH_SCORE_DIRECT
                } else {
                    REASON_PATH_DIRECT_CONFIRMED
                },
                direct_score
                    .as_ref()
                    .map(|score| {
                        if policy == crate::config::PathPolicy::Score {
                            format!("score policy selected encrypted Direct; score={}", score.score)
                        } else {
                            format!("direct UDP pair is confirmed; score={}", score.score)
                        }
                    })
                    .unwrap_or_else(|| "direct UDP pair is confirmed".to_string()),
                true,
            )
            .with_scores(direct_score, relay_score);
        }

        if relay_available {
            return PathSelection::relay(
                REASON_PATH_DIRECT_NOT_CONFIRMED,
                match (&direct_score, &relay_score) {
                    (Some(direct_score), Some(relay_score)) => format!(
                        "direct UDP pair is not encrypted-confirmed; direct_score={} relay_score={}",
                        direct_score.score, relay_score.score
                    ),
                    _ => "direct UDP pair is not encrypted-confirmed; using relay".to_string(),
                },
            )
            .with_scores(direct_score, relay_score);
        }

        // Candidate/probe success is deliberately not a data-plane delivery
        // proof.  Without a confirmed relay there is no safe path for this
        // counter: waiting keeps FIFO/counter order intact, and the outbound
        // actor will apply its bounded deadline/drop policy.
        PathSelection::unavailable(
            REASON_PATH_UNAVAILABLE,
            "no confirmed relay and Direct is not encrypted-confirmed",
        )
        .with_scores(direct_score, None)
    }
}
