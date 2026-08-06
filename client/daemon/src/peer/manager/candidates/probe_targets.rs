#[derive(Debug, Clone)]
pub(crate) struct DirectProbeTargetSet {
    pub peer_id: String,
    pub candidates: Vec<SocketAddr>,
    pub remote_scatter_pool: bool,
    pub stable_remote_scatter: bool,
    pub birthday_plan: Option<BirthdayProbePlan>,
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
        let mut conns = self.connections.write().await;
        let conn = conns.get_mut(node_id)?;
        if !conn.online {
            return None;
        }
        if conn.state == ConnectionState::Direct
            && !conn.should_probe_private_alternates_while_direct(generation)
        {
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
            let remote_scatter_pool = conn.candidate_targets_need_remote_scatter_pool(&endpoints);
            Some(DirectProbeTargetSet {
                peer_id: conn.node_id.clone(),
                stable_remote_scatter: remote_scatter_pool
                    && birthday_plan
                        .as_ref()
                        .is_some_and(|plan| plan.stable_side_unique_scatter),
                remote_scatter_pool,
                candidates: endpoints,
                birthday_plan,
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
                if conn.state == ConnectionState::Direct
                    && !conn.should_probe_private_alternates_while_direct(generation)
                {
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
    pub(crate) async fn direct_probe_targets_due(
        &self,
        base_retry_after: Duration,
    ) -> Vec<DirectProbeTargetSet> {
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
                let reclaim_active = conn.direct_reclaim_active();
                if !reclaim_active && !conn.direct_retry_due(base_retry_after) {
                    return None;
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
                    return None;
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
                    None
                } else {
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
                    let remote_scatter_pool =
                        conn.candidate_targets_need_remote_scatter_pool(&endpoints);
                    Some(DirectProbeTargetSet {
                        peer_id: conn.node_id.clone(),
                        stable_remote_scatter: remote_scatter_pool
                            && birthday_plan
                                .as_ref()
                                .is_some_and(|plan| plan.stable_side_unique_scatter),
                        remote_scatter_pool,
                        candidates: endpoints,
                        birthday_plan,
                    })
                }
            })
            .collect()
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
        conn.commit_birthday_probe_cursor(plan.start_rank, plan.end_rank)
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
