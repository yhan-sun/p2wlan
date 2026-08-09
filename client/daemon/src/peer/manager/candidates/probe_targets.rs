#[derive(Debug, Clone)]
pub(crate) struct DirectProbeTargetSet {
    pub peer_id: String,
    pub candidates: Vec<SocketAddr>,
    pub remote_scatter_pool: bool,
    pub stable_remote_scatter: bool,
    pub birthday_plan: Option<BirthdayProbePlan>,
    /// Recovery epoch this target set was planned for.
    pub recovery_epoch: u64,
}

impl PeerManager {
    /// Return the best current direct endpoint for encrypted UDP data.
    pub async fn direct_endpoint_for_send(&self, node_id: &str) -> Option<SocketAddr> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.direct_endpoint_for_send(generation))
    }

    /// Return direct UDP endpoints for NAT keepalive probes.
    pub async fn direct_endpoints(&self) -> Vec<(String, SocketAddr)> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .values()
            .filter(|conn| conn.state == ConnectionState::Direct)
            .filter_map(|conn| {
                conn.selected_direct_endpoint_for_consent(generation)
                    .map(|endpoint| (conn.node_id.clone(), endpoint))
            })
            .collect()
    }

    /// Return candidate endpoints for a specific peer using the adaptive probe scheduler.
    pub async fn direct_probe_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        self.direct_probe_target_set_for(node_id)
            .await
            .map(|target| target.candidates)
            .unwrap_or_default()
    }

    pub(crate) async fn direct_probe_target_set_for(
        &self,
        node_id: &str,
    ) -> Option<DirectProbeTargetSet> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        // A quarantined peer's candidate set is authoritative-stale (relay
        // 404): no synchronized target may be derived from it until new
        // control-plane evidence re-opens recovery.
        if self.peer_quarantined_sync(node_id) {
            return None;
        }
        let recovery_stage = if self.recovery_epoch_active(node_id).await {
            Some(self.recovery_stage_for(node_id).await)
        } else {
            None
        };
        // The relay safety net is read BEFORE the connection-map write guard:
        // `has_relay_safety_net` takes the connection map read lock, which
        // would deadlock while the write guard below is held.
        let relay_safety_net = match recovery_stage {
            Some(_) => self.has_relay_safety_net(node_id).await,
            None => false,
        };
        let mut conns = self.connections.write().await;
        let conn = conns.get_mut(node_id)?;
        if !conn.online {
            return None;
        }
        if conn.state == ConnectionState::Direct {
            // A Direct peer has converged: no synchronized punch targets may
            // be derived from its candidate set.  Speculative probing of
            // private/public alternates while Direct would keep re-creating
            // traversal scans on a confirmed path; the Exploring window
            // re-opens only after a Direct health failure or a
            // network-generation change moves the connection out of Direct.
            conn.retire_speculative_pairs_when_direct_confirmed(generation);
            return None;
        }
        let (endpoints, birthday_plan) = conn.candidate_probe_endpoints(
            generation,
            &history,
            local_nat_profile.as_ref(),
            ProbeTargetMode::Synchronized,
        );
        if !endpoints.is_empty() {
            conn.record_direct_event(
                generation,
                "probe_targets_selected",
                endpoints.first().copied(),
                Some(endpoints.len()),
                None,
                format!(
                    "selected {} UDP candidates for synchronized punching",
                    endpoints.len()
                ),
            );
        }
        if endpoints.is_empty() {
            None
        } else {
            let mut remote_scatter_pool =
                conn.candidate_targets_need_remote_scatter_pool(&endpoints);
            let mut birthday_plan = birthday_plan;
            let mut endpoints = endpoints;
            // The recovery stage machine bounds the target set: wide scatter
            // plans are only reachable after explicit no-ACK feedback, and
            // every stage has a hard probe ceiling.  A relay-backed peer is
            // capped to the bounded heartbeat even in the wide stage.
            if let Some(stage) = recovery_stage {
                cap_targets_by_recovery_stage(
                    conn,
                    &mut endpoints,
                    &mut birthday_plan,
                    &mut remote_scatter_pool,
                    stage,
                    relay_safety_net,
                );
            }
            Some(DirectProbeTargetSet {
                peer_id: conn.node_id.clone(),
                stable_remote_scatter: remote_scatter_pool
                    && birthday_plan
                        .as_ref()
                        .is_some_and(|plan| plan.stable_side_unique_scatter),
                remote_scatter_pool,
                candidates: endpoints,
                birthday_plan,
                recovery_epoch: if recovery_stage.is_some() {
                    self.recovery_epoch_for(node_id).await
                } else {
                    0
                },
            })
        }
    }

    /// Return the preferred stable public endpoint that every active local UDP
    /// socket should continuously probe while the easier peer scans this side's
    /// moving public-port window.
    pub async fn direct_nat_maintainer_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        let generation = self.current_network_generation().await;
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;

        let conns = self.connections.read().await;
        let Some(conn) = conns.get(node_id) else {
            return Vec::new();
        };
        if !conn.online || conn.state == ConnectionState::Direct {
            return Vec::new();
        }
        if !conn.should_maintain_nat_binding_toward_stable_remote(local_nat_profile.as_ref()) {
            return Vec::new();
        }

        let mut endpoints = conn
            .asymmetric_stable_remote_endpoints(generation)
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .collect::<Vec<_>>();
        endpoints.dedup();
        endpoints.truncate(1);
        endpoints
    }

    /// Return candidate endpoints that should continue receiving direct-path probes.
    pub async fn direct_probe_targets(&self) -> Vec<(String, Vec<SocketAddr>)> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter_map(|conn| {
                if !conn.online {
                    return None;
                }
                if conn.state == ConnectionState::Direct {
                    conn.retire_speculative_pairs_when_direct_confirmed(generation);
                    return None;
                }
                if conn.state != ConnectionState::Direct
                    && !conn.has_direct_retry_opportunity(local_nat_profile.as_ref())
                {
                    if conn
                        .direct_events
                        .last()
                        .is_none_or(|event| {
                            event.network_generation != generation
                                || event.stage != "retry_skipped_no_viable_nat_window"
                        })
                    {
                        conn.record_direct_event(
                            generation,
                            "retry_skipped_no_viable_nat_window",
                            conn.endpoint,
                            None,
                            None,
                            "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                        );
                    }
                    return None;
                }
                let (endpoints, _) = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                    ProbeTargetMode::Background,
                );

                if endpoints.is_empty() {
                    None
                } else {
                    conn.record_direct_event(
                        generation,
                        "probe_targets_due",
                        endpoints.first().copied(),
                        Some(endpoints.len()),
                        None,
                        format!(
                            "selected {} UDP candidates for background retry",
                            endpoints.len()
                        ),
                    );
                    Some((conn.node_id.clone(), endpoints))
                }
            })
            .collect()
    }

    /// Return candidate endpoints that are due for direct-path reprobe.
    ///
    /// Unlike `direct_probe_targets`, this only transitions pairs to Probing
    /// after the peer-level retry cooldown has elapsed, except during the
    /// short generation-change reclaim window for peers with previous Direct
    /// success.
    ///
    /// This is the per-tick recovery scheduler: every tick at most
    /// `RECOVERY_WORK_SLOTS_PER_TICK` peers may enter a recovery session,
    /// served by priority (recently-Direct reclaim first, then peers with
    /// prior Direct success, then the rest), so a failing stale peer can
    /// never starve the main peer's recovery.  Quarantined peers, budget-
    /// frozen epochs and plan/session-quota-exhausted epochs are skipped
    /// here — they must not rebuild a plan on this tick.
    pub(crate) async fn direct_probe_targets_due(
        &self,
        base_retry_after: Duration,
    ) -> Vec<DirectProbeTargetSet> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        // Pre-admit every online non-Direct peer into the recovery scheduler:
        // the target sets below are then planned inside the epoch's stage
        // caps, so background retries can never build a wide scatter plan
        // without explicit no-ACK feedback.  Quarantined peers are excluded
        // at the source: their relay 404 is authoritative and no candidate
        // plan may be derived from their stale set.
        let eligible = {
            let conns = self.connections.read().await;
            conns
                .values()
                .filter(|conn| {
                    conn.online
                        && conn.state != ConnectionState::Direct
                        && !self.peer_quarantined_sync(&conn.node_id)
                })
                .map(|conn| conn.node_id.clone())
                .collect::<Vec<_>>()
        };
        // Priority order for the per-tick work slots: recently-Direct
        // reclaim first, then peers with prior Direct success (the most
        // probable live path), then the rest.
        let mut ordered = Vec::new();
        for peer_id in eligible {
            let priority = {
                let conns = self.connections.read().await;
                let Some(conn) = conns.get(&peer_id) else {
                    continue;
                };
                if conn.direct_reclaim_active() {
                    0
                } else if conn.has_direct_success_history() {
                    1
                } else {
                    2
                }
            };
            ordered.push((priority, peer_id));
        }
        ordered.sort_by_key(|(priority, peer_id)| (*priority, peer_id.clone()));

        let mut granted = 0usize;
        let mut sets = Vec::new();
        for (_, peer_id) in ordered {
            if granted >= RECOVERY_WORK_SLOTS_PER_TICK {
                // The per-tick work budget is spent: remaining peers are
                // deferred to the next tick.  One exhausted peer must not
                // consume the whole shared scheduler.
                self.record_direct_event(
                    &peer_id,
                    "scheduler_fairness_deferred",
                    None,
                    None,
                    None,
                    format!(
                        "deferred recovery work to the next tick: {granted} peer(s) already hold this tick's {} work slot(s)",
                        RECOVERY_WORK_SLOTS_PER_TICK
                    ),
                )
                .await;
                continue;
            }
            let RecoveryAdmission::Accepted { epoch } = self.recovery_epoch_admit(&peer_id).await
            else {
                continue;
            };
            // A frozen budget epoch cannot build a plan this tick.
            if !self.try_consume_recovery_plan_build(&peer_id).await {
                self.record_direct_event(
                    &peer_id,
                    "recovery_plan_build_quota_exhausted",
                    None,
                    None,
                    None,
                    format!("recovery epoch {epoch} used its plan-build quota; no new plan until the epoch rotates"),
                )
                .await;
                continue;
            }
            if !self.try_consume_recovery_session(&peer_id).await {
                self.record_direct_event(
                    &peer_id,
                    "recovery_session_quota_exhausted",
                    None,
                    None,
                    None,
                    format!("recovery epoch {epoch} used its session quota; no new session until the epoch rotates"),
                )
                .await;
                continue;
            }
            granted += 1;
            let stage = self.recovery_stage_for(&peer_id).await;
            let relay_safety_net = self.has_relay_safety_net(&peer_id).await;
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(&peer_id) else {
                continue;
            };
            if !conn.online || conn.state == ConnectionState::Direct {
                continue;
            }
            let reclaim_active = conn.direct_reclaim_active();
            if !reclaim_active && !conn.direct_retry_due(base_retry_after) {
                continue;
            }
            if !conn.has_direct_retry_opportunity(local_nat_profile.as_ref()) {
                if conn
                    .direct_events
                    .last()
                    .is_none_or(|event| {
                        event.network_generation != generation
                            || event.stage != "retry_skipped_no_viable_nat_window"
                    })
                {
                    conn.record_direct_event(
                        generation,
                        "retry_skipped_no_viable_nat_window",
                        conn.endpoint,
                        None,
                        None,
                        "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                    );
                }
                continue;
            }
            let (endpoints, birthday_plan) = conn.candidate_probe_endpoints(
                generation,
                &history,
                local_nat_profile.as_ref(),
                if reclaim_active {
                    ProbeTargetMode::Reclaim
                } else {
                    ProbeTargetMode::Background
                },
            );
            if endpoints.is_empty() {
                continue;
            }
            if reclaim_active {
                conn.record_direct_event(
                    generation,
                    "direct_reclaim_targets_due",
                    endpoints.first().copied(),
                    Some(endpoints.len()),
                    None,
                    format!(
                        "selected {} UDP candidates for generation-change Direct reclaim",
                        endpoints.len()
                    ),
                );
            }
            let mut remote_scatter_pool =
                conn.candidate_targets_need_remote_scatter_pool(&endpoints);
            let mut birthday_plan = birthday_plan;
            let mut endpoints = endpoints;
            // The recovery stage machine bounds the background target set the
            // same way it bounds synchronized targets.  A relay-backed peer
            // gets the bounded trusted-endpoint heartbeat even in the wide
            // scatter stage (cold-start capability is reserved for peers
            // without a relay safety net).
            cap_targets_by_recovery_stage(
                conn,
                &mut endpoints,
                &mut birthday_plan,
                &mut remote_scatter_pool,
                stage,
                relay_safety_net,
            );
            sets.push(DirectProbeTargetSet {
                peer_id: conn.node_id.clone(),
                stable_remote_scatter: remote_scatter_pool
                    && birthday_plan
                        .as_ref()
                        .is_some_and(|plan| plan.stable_side_unique_scatter),
                remote_scatter_pool,
                candidates: endpoints,
                birthday_plan,
                recovery_epoch: epoch,
            });
        }
        sets
    }

    pub(crate) async fn record_birthday_probe_plan_started(
        &self,
        node_id: &str,
        plan: &BirthdayProbePlan,
    ) {
        let bases = plan
            .bases
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let public_ips = plan
            .public_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let detail = format!(
            "generation={} stable_side={} public_ips={public_ips:?} bases={bases:?} start_rank={} end_rank={} wrapped={} generated_candidates={} planned_candidates={} selected_candidates={} selected_birthday_candidates={} unique_target_ports={}",
            plan.local_generation,
            plan.stable_side_unique_scatter,
            plan.start_rank,
            plan.end_rank,
            plan.wrapped,
            plan.generated_candidates,
            plan.planned_candidates,
            plan.selected_candidates,
            plan.selected_birthday_candidates,
            plan.unique_target_ports,
        );
        self.record_direct_event(
            node_id,
            "birthday_probe_plan_started",
            plan.bases.first().copied(),
            Some(plan.selected_candidates),
            None,
            detail.clone(),
        )
        .await;
        info!(
            event = "birthday_probe_plan_started",
            peer_id = %node_id,
            network_generation = plan.local_generation,
            stable_side = plan.stable_side_unique_scatter,
            public_ips = ?public_ips,
            bases = ?bases,
            start_rank = plan.start_rank,
            end_rank = plan.end_rank,
            wrapped = plan.wrapped,
            generated_candidates = plan.generated_candidates,
            selected_candidates = plan.selected_candidates,
            selected_birthday_candidates = plan.selected_birthday_candidates,
            unique_target_ports = plan.unique_target_ports,
            "birthday_probe_plan_started peer_id={} generation={} stable_side={} public_ips={:?} bases={:?} start_rank={} end_rank={} wrapped={} generated_candidates={} selected_candidates={} selected_birthday_candidates={} unique_target_ports={}",
            node_id,
            plan.local_generation,
            plan.stable_side_unique_scatter,
            public_ips,
            bases,
            plan.start_rank,
            plan.end_rank,
            plan.wrapped,
            plan.generated_candidates,
            plan.selected_candidates,
            plan.selected_birthday_candidates,
            plan.unique_target_ports,
        );
    }

    pub(crate) async fn commit_birthday_probe_cursor(
        &self,
        node_id: &str,
        plan: &BirthdayProbePlan,
        covered_all_selected_candidates: bool,
    ) -> bool {
        // Only the public IPs and the actual probing coverage matter.  The
        // candidate base ports churn every refresh cycle (peer STUN ports
        // move), and `generated_candidates` excludes bases that were already
        // in the endpoint set, so comparing it against the selected birthday
        // count would stall the cursor forever on a healthy scan.
        // The budget check is strict: `planned_candidates` is the full target
        // list before cooldown/budget filtering, so a plan whose endpoints
        // were dropped before sending must not advance the cursor past ports
        // that were never probed.
        if !plan.stable_side_unique_scatter
            || !covered_all_selected_candidates
            || plan.selected_birthday_candidates == 0
            || plan.selected_candidates != plan.planned_candidates
        {
            return false;
        }
        let generation = self.current_network_generation().await;
        if generation != plan.local_generation {
            return false;
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let current_endpoints = conn.probe_candidate_endpoints();
        let current_bases = conn.birthday_probe_bases(&current_endpoints, generation);
        let mut current_public_ips = current_bases
            .iter()
            .map(|base| base.ip())
            .collect::<Vec<_>>();
        current_public_ips.sort_unstable();
        current_public_ips.dedup();
        if current_public_ips != plan.public_ips {
            return false;
        }
        let advanced = conn.commit_birthday_probe_cursor(plan.start_rank, plan.end_rank);
        if advanced {
            // A fully covered scatter-extended window counts toward the
            // epoch's window report.
            self.record_recovery_scatter_window(node_id).await;
        }
        advanced
    }

    /// Record that a UDP probe datagram was actually sent to a candidate.
    ///
    /// Candidate selection can be broader than the outbound rate-limit budget;
    /// mark pairs as probing only once the UDP layer confirms a packet left.
    pub async fn record_direct_probe_sent(&self, node_id: &str, endpoint: SocketAddr) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.mark_candidate_pair_probing(endpoint, generation);
        true
    }
}

/// Bound a target set by the recovery stage machine.
///
/// - Wide scatter (birthday plans / remote scatter pool) is only built at
///   [`RecoveryStage::ScatterExtended`], which is only reachable after the
///   smaller stages produced explicit zero-matched-ACK feedback.
/// - Every stage has a hard probe ceiling (`RecoveryStage::max_probes`).
/// - The Initial stage drops only locally-generated Birthday speculation
///   (never peer-signaled Predicted ports: for an address/port-dependent
///   peer the predicted window IS the only viable target set, so dropping it
///   would leave only LAN hosts that cannot traverse the NATs).
/// - A relay-backed peer (`relay_safety_net == true`) is capped at the
///   bounded trusted-endpoint ceiling even in the wide-scatter stage: relay
///   is the data plane, so traversal is a low-frequency heartbeat and the
///   wide birthday capability is reserved for cold starts without a relay.
fn cap_targets_by_recovery_stage(
    conn: &PeerConnection,
    endpoints: &mut Vec<SocketAddr>,
    birthday_plan: &mut Option<BirthdayProbePlan>,
    remote_scatter_pool: &mut bool,
    stage: RecoveryStage,
    relay_safety_net: bool,
) {
    if stage < RecoveryStage::ScatterExtended {
        *birthday_plan = None;
        *remote_scatter_pool = false;
    }
    if stage == RecoveryStage::Initial {
        let trusted = endpoints
            .iter()
            .copied()
            .filter(|endpoint| {
                conn.candidate_source_for_endpoint(*endpoint)
                    != CandidatePairSource::Birthday
            })
            .collect::<Vec<_>>();
        if !trusted.is_empty() {
            *endpoints = trusted;
        }
    }
    let max_probes = if relay_safety_net && stage >= RecoveryStage::ScatterExtended {
        // Relay is available: wide scatter is downgraded to a bounded
        // trusted-endpoint heartbeat (the full cold-start capability stays
        // reachable for peers without a relay safety net).
        RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES
    } else {
        stage.max_probes()
    } as usize;
    if endpoints.len() > max_probes {
        endpoints.truncate(max_probes);
    }
}
