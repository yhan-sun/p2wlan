#[derive(Debug, Clone)]
pub(crate) struct DirectProbeTargetSet {
    pub peer_id: String,
    pub candidates: Vec<SocketAddr>,
    /// Authenticated/learned candidate sources that should get the larger
    /// bounded fast prefix.  The complete `candidates` vector remains the
    /// authoritative FIFO for the broad punch plan.
    pub preferred_fast_candidates: Vec<SocketAddr>,
    pub remote_scatter_pool: bool,
    pub stable_remote_scatter: bool,
    pub birthday_plan: Option<BirthdayProbePlan>,
    /// Recovery epoch this target set was planned for.
    pub recovery_epoch: u64,
}

/// Trusted relay-backoff heartbeat targets, separated before the UDP sender
/// chooses a local socket.  The groups retain the candidate ranking within
/// each source class while allowing a bounded heartbeat to revisit an
/// authenticated/selected endpoint without repeatedly pinning the whole beat
/// to the first predicted port.
#[derive(Debug, Clone)]
pub(crate) struct RelayBackoffHeartbeatTargetSet {
    pub generation: u64,
    pub priority: Vec<SocketAddr>,
    pub predicted: Vec<SocketAddr>,
    pub fallback: Vec<SocketAddr>,
}

impl RelayBackoffHeartbeatTargetSet {
    pub(crate) fn is_empty(&self) -> bool {
        self.priority.is_empty() && self.predicted.is_empty() && self.fallback.is_empty()
    }

    pub(crate) fn candidate_count(&self) -> usize {
        self.priority.len() + self.predicted.len() + self.fallback.len()
    }
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

    /// Keep an already-created asynchronous probe snapshot bounded to the
    /// remote candidate set that is current at the moment it is consumed.
    ///
    /// Recovery workers intentionally hold snapshots across await points, so
    /// filtering only when the snapshot is first built is insufficient: a
    /// remote handover may arrive while the worker is waiting for its shared
    /// punch deadline.  A missing connection is also a hard invalidation —
    /// there is no authoritative remote endpoint to probe.
    pub(crate) async fn current_remote_endpoints_for(
        &self,
        node_id: &str,
        endpoints: Vec<SocketAddr>,
    ) -> Vec<SocketAddr> {
        let connections = self.connections.read().await;
        let Some(conn) = connections.get(node_id) else {
            return Vec::new();
        };
        endpoints
            .into_iter()
            .filter(|endpoint| conn.is_current_remote_endpoint(*endpoint))
            .collect()
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
        // Snapshot this independent ledger before taking the process-wide
        // connection write guard.  Awaiting it while that guard is held lets
        // a background Direct planner starve control PeerJoined/PeerAnswer
        // processing when another recovery operation owns the epoch lock.
        let recovery_epoch = if recovery_stage.is_some() {
            self.recovery_epoch_for(node_id).await
        } else {
            0
        };
        let local_interface_networks = self.local_interface_networks.read().await.clone();
        let mut conns = self.connections.write().await;
        let conn = conns.get_mut(node_id)?;
        conn.set_local_interface_networks(local_interface_networks);
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
            recovery_target_cap(
                recovery_stage,
                relay_safety_net,
                self.config.network.socket_pool_size,
                conn.remote_nat_requires_port_scatter(),
            ),
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
                    self.config.network.socket_pool_size,
                );
            }
            let preferred_fast_candidates = conn.preferred_fast_candidates(&endpoints);
            Some(DirectProbeTargetSet {
                peer_id: conn.node_id.clone(),
                stable_remote_scatter: remote_scatter_pool
                    && birthday_plan
                        .as_ref()
                        .is_some_and(|plan| plan.stable_side_unique_scatter),
                remote_scatter_pool,
                candidates: endpoints,
                preferred_fast_candidates,
                birthday_plan,
                recovery_epoch,
            })
        }
    }

    /// Return the preferred stable public endpoints that every active local
    /// UDP socket should continuously probe while the easier peer scans this
    /// side's moving public-port window.
    ///
    /// ALL advertised stable public mappings are maintained, never just the
    /// top-ranked one: the easy peer's socket-pool bindings expire
    /// independently, and a maintainer locked onto a single stale port leaves
    /// the live mapping's binding dead.  The set is already bounded by the
    /// stable-pool role gate (≤ `ASYMMETRIC_STABLE_MAX_PUBLIC_ENDPOINTS`).
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
                    None,
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

    /// Whether probing this peer should activate the local UDP socket pool
    /// even when the NAT profile alone would keep it dormant.
    ///
    /// An easy NAT with a bound (but dormant) socket pool advertises every
    /// pool socket's STUN-observed mapping to the peer.  A multi-socket peer
    /// (≥2 public ports on one IP, i.e. its own pool / hard-NAT profile) may
    /// probe ANY of those advertised mappings, but the easy side's secondary
    /// socket bindings expire while the pool is dormant because only STUN
    /// traffic refreshes them.  Activating the pool makes the next punch send
    /// peer-directed traffic from every pool socket, keeping every advertised
    /// mapping alive for the first punch.
    pub(crate) async fn peer_needs_local_socket_pool(&self, node_id: &str) -> bool {
        let Some(profile) = self.local_nat_profile_for_probe_budget().await else {
            return false;
        };
        if profile.udp_blocked || is_hard_nat_profile(&profile) {
            // A hard local NAT already runs the pool; a UDP-blocked network
            // cannot benefit from it.
            return false;
        }
        let conns = self.connections.read().await;
        let Some(conn) = conns.get(node_id) else {
            return false;
        };
        if !conn.online || conn.state == ConnectionState::Direct {
            return false;
        }
        let mut ports_by_ip: HashMap<IpAddr, HashSet<u16>> = HashMap::new();
        for endpoint in conn
            .candidate_endpoints()
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
        {
            ports_by_ip
                .entry(endpoint.ip())
                .or_default()
                .insert(endpoint.port());
        }
        ports_by_ip.values().any(|ports| ports.len() >= 2)
    }

    /// Trusted-endpoint target set for the relay-backed recovery heartbeat.
    ///
    /// Returns `None` when the peer has no relay safety net (the heartbeat
    /// must not probe during a cold start without relay — that is the
    /// recovery epoch's job), is Direct, or is quarantined.  The returned
    /// set is capped to the bounded relay-backoff ceiling so one beat stays
    /// small; it deliberately bypasses the epoch's plan/session quotas.
    pub(crate) async fn relay_backoff_heartbeat_targets_for(
        &self,
        node_id: &str,
    ) -> Option<RelayBackoffHeartbeatTargetSet> {
        let generation = self.current_network_generation().await;
        let relay_available = self
            .connections
            .read()
            .await
            .get(node_id)
            .is_some_and(|conn| {
                conn.state == ConnectionState::Relay
                    || (conn.state == ConnectionState::FallbackToRelay
                        && conn.relay_server.is_some())
            });
        if !relay_available {
            return None;
        }
        let mut set = self.direct_probe_target_set_for(node_id).await?;
        set.candidates.truncate(RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES as usize);
        // A network generation transition invalidates every candidate pair
        // and its cursor.  Return no mixed-generation snapshot; the next beat
        // rebuilds against the authoritative generation.
        if self.current_network_generation().await != generation {
            return None;
        }
        let connections = self.connections.read().await;
        let conn = connections.get(node_id)?;
        let mut priority = Vec::new();
        let mut predicted = Vec::new();
        let mut fallback = Vec::new();
        for endpoint in set.candidates {
            let source = conn.candidate_source_for_endpoint(endpoint);
            let authenticated_or_successful = conn.candidate_pairs.iter().any(|pair| {
                pair.local_generation == generation
                    && pair.remote_endpoint == endpoint
                    && conn.pair_belongs_to_current_remote_epoch(pair)
                    && (matches!(
                        pair.source,
                        CandidatePairSource::PeerReflexive | CandidatePairSource::Learned
                    ) || pair.last_success_at.is_some()
                        || matches!(
                            pair.state,
                            CandidatePairState::Selected | CandidatePairState::Succeeded
                        ))
            });
            if authenticated_or_successful
                || matches!(
                    source,
                    CandidatePairSource::PeerReflexive | CandidatePairSource::Learned
                )
            {
                priority.push(endpoint);
            } else if source == CandidatePairSource::Predicted {
                predicted.push(endpoint);
            } else {
                fallback.push(endpoint);
            }
        }
        let targets = RelayBackoffHeartbeatTargetSet {
            generation,
            priority,
            predicted,
            fallback,
        };
        (!targets.is_empty()).then_some(targets)
    }

    /// Lock-free relay safety-net check for the heartbeat's per-send owner
    /// gate.  A transient `try_read` failure while the connection map is
    /// being written aborts the beat conservatively; the worker re-verifies
    /// on the next beat with the authoritative async check.
    pub(crate) fn relay_backoff_heartbeat_available_sync(&self, node_id: &str) -> bool {
        self.connections
            .try_read()
            .map(|connections| {
                connections.get(node_id).is_some_and(|conn| {
                    conn.state == ConnectionState::Relay
                        || (conn.state == ConnectionState::FallbackToRelay
                            && conn.relay_server.is_some())
                })
            })
            .unwrap_or(false)
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
            // Eligibility (retry due, reclaim window, viable NAT window) is
            // checked BEFORE any recovery quota is consumed: a peer that is
            // still in its retry backoff must not burn a plan-build/session
            // slot on a tick where nothing will be sent.  The old ordering
            // drained the 16-plan quota in ~16 idle seconds and then locked
            // the peer out of re-planning for the rest of the epoch.
            let reclaim_active = {
                let conns = self.connections.read().await;
                let Some(conn) = conns.get(&peer_id) else {
                    continue;
                };
                if !conn.online || conn.state == ConnectionState::Direct {
                    continue;
                }
                let reclaim_active = conn.direct_reclaim_active();
                if !reclaim_active {
                    // A relay-backed peer in the wide scatter stage keeps the
                    // retry cadence flat (no exponential growth) so the scan
                    // window stays warm during a transient black hole; only
                    // peers without a relay safety net retain the classic
                    // failure backoff.  See `PathHealth::retry_due_relay_flat`.
                    // Derive the safety-net verdict from this same immutable
                    // connection snapshot. Re-entering `connections.read()`
                    // here can deadlock Tokio's writer-preferring `RwLock`:
                    // a queued writer waits for `conns`, while a nested reader
                    // queues behind that writer and can never let `conns` go.
                    let relay_safety_net = matches!(
                        conn.state,
                        ConnectionState::Relay | ConnectionState::FallbackToRelay
                    ) || conn.active_path() == Some(NetworkPath::Relay);
                    let retry_due = if relay_safety_net {
                        conn.direct_retry_due_relay_flat(base_retry_after)
                    } else {
                        conn.direct_retry_due(base_retry_after)
                    };
                    if !retry_due {
                        continue;
                    }
                }
                if !conn.has_direct_retry_opportunity(local_nat_profile.as_ref()) {
                    let needs_record = conn
                        .direct_events
                        .last()
                        .is_none_or(|event| {
                            event.network_generation != generation
                                || event.stage != "retry_skipped_no_viable_nat_window"
                        });
                    let endpoint = conn.endpoint;
                    drop(conns);
                    if needs_record {
                        self.record_direct_event(
                            &peer_id,
                            "retry_skipped_no_viable_nat_window",
                            endpoint,
                            None,
                            None,
                            "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                        )
                        .await;
                    }
                    continue;
                }
                reclaim_active
            };
            granted += 1;
            if !self.try_consume_recovery_plan_build(&peer_id).await {
                if self
                    .recovery_quota_event_report_due(&peer_id, "plan_build")
                    .await
                {
                    self.record_direct_event(
                        &peer_id,
                        "recovery_plan_build_quota_exhausted",
                        None,
                        None,
                        None,
                        format!("recovery epoch {epoch} used its plan-build quota; no new plan until the epoch rotates"),
                    )
                    .await;
                }
                continue;
            }
            if !self.try_consume_recovery_session(&peer_id).await {
                if self
                    .recovery_quota_event_report_due(&peer_id, "session")
                    .await
                {
                    self.record_direct_event(
                        &peer_id,
                        "recovery_session_quota_exhausted",
                        None,
                        None,
                        None,
                        format!("recovery epoch {epoch} used its session quota; no new session until the epoch rotates"),
                    )
                    .await;
                }
                continue;
            }
            let stage = self.recovery_stage_for(&peer_id).await;
            let relay_safety_net = self.has_relay_safety_net(&peer_id).await;
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(&peer_id) else {
                continue;
            };
            if !conn.online || conn.state == ConnectionState::Direct {
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
                recovery_target_cap(
                    Some(stage),
                    relay_safety_net,
                    self.config.network.socket_pool_size,
                    conn.remote_nat_requires_port_scatter(),
                ),
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
                self.config.network.socket_pool_size,
            );
            let preferred_fast_candidates = conn.preferred_fast_candidates(&endpoints);
            sets.push(DirectProbeTargetSet {
                peer_id: conn.node_id.clone(),
                stable_remote_scatter: remote_scatter_pool
                    && birthday_plan
                        .as_ref()
                    .is_some_and(|plan| plan.stable_side_unique_scatter),
                remote_scatter_pool,
                candidates: endpoints,
                preferred_fast_candidates,
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
        // The cursor advances only when every selected candidate was really
        // sent (`covered_all_selected_candidates`) AND birthday candidates
        // were generated and selected.  The plan generation is sliced by the
        // recovery stage cap and the per-plan window slice, so the generated
        // window is exactly what this session sends: `planned == selected`
        // is guaranteed by construction instead of being re-checked here.
        // Cooldown filtering can legally drop a candidate between planning
        // and sending without making the cursor skip unprobed ports: the
        // whole remote-port window is re-swept rank-by-rank across plans, so
        // a skipped port is simply covered by a later slice (or the wrap).
        if !plan.stable_side_unique_scatter
            || !covered_all_selected_candidates
            || plan.selected_birthday_candidates == 0
            || plan.generated_candidates == 0
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
        drop(conns);
        if advanced {
            // A fully covered scatter-extended window counts toward the
            // epoch's window report.  The ledger update must happen after the
            // connection map guard is released.
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
        let first_probe = self.emit_timeline_first(
            node_id,
            generation,
            "first_direct_probe_sent",
            Some("direct"),
            None,
            Some(format!("peer={node_id} endpoint={endpoint} generation={generation}")),
        );
        if first_probe {
            // Route inspection is intentionally first-probe-only: it is
            // valuable for diagnosing Windows multi-NIC selection, but doing
            // an interface enumeration for every punch would turn a
            // diagnostic into a source of probe latency.
            let route = tokio::task::spawn_blocking(move || {
                p2pnet_netbind::resolve_route(endpoint.ip())
            })
            .await
            .ok()
            .flatten();
            let source = self
                .connections
                .read()
                .await
                .get(node_id)
                .map(|connection| connection.candidate_source_for_endpoint(endpoint));
            self.emit_timeline_debug(
                "direct_probe_route",
                Some("direct"),
                None,
                Some(format!(
                    "peer={node_id} destination={endpoint} candidate_source={source:?} route_interface={:?} interface_index={:?} preferred_source={:?} next_hop={:?} metric={:?}",
                    route.as_ref().and_then(|route| route.interface_name.as_deref()),
                    route.as_ref().and_then(|route| route.interface_index),
                    route.as_ref().and_then(|route| route.preferred_source),
                    route.as_ref().and_then(|route| route.next_hop),
                    route.as_ref().and_then(|route| route.metric),
                )),
            );
        }
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.mark_candidate_pair_probing(endpoint, generation);
        true
    }
}

/// The recovery stage's probe ceiling as a candidate-count cap for plan
/// construction.
///
/// This is applied BEFORE `candidate_probe_endpoints` generates the birthday
/// window so the plan never persists candidates beyond the stage's real scan:
/// `cap_targets_by_recovery_stage` below remains as the post-selection safety
/// net with identical numbers.
///
/// The stage ceiling counts PHYSICAL kernel datagrams, while a punch session
/// sends every planned candidate from every active local socket (the wide
/// window's whole purpose is multi-socket coverage of a moving remote-port
/// window).  The plan is therefore sized to the number of candidates that one
/// session can cover COMPLETELY: `ceiling / socket_count`.  Field evidence
/// (v0.1.115 Mini log): a 384-candidate ScatterSmall plan was truncated at
/// 171 unique endpoints by the 512-datagram session cap (512/3 sockets), so
/// the remaining window was never scanned, the birthday cursor could not
/// advance, and the next session re-scanned the same 171 ports.
fn recovery_target_cap(
    stage: Option<RecoveryStage>,
    relay_safety_net: bool,
    socket_count: usize,
    remote_port_dependent: bool,
) -> Option<usize> {
    let stage = stage?;
    // A port-dependent remote's predicted window is destination-specific, so
    // the stage machine must not trickle through Predicted/ScatterSmall at
    // the small ceilings: the wide scatter is the only coverage of its real
    // mapping (field evidence v0.1.116, R9).  The Initial stage still opens
    // with the predicted window untouched; the wide ceiling opens as soon as
    // that window had no matched ACK.  A relay safety net does NOT suppress
    // this: the relay is only the fallback data plane, and for a
    // destination-dependent remote the wide scatter is the ONLY route to
    // Direct (field evidence v0.1.116: availability runs always have the
    // relay confirmed within ~100 ms, so a `!relay_safety_net` gate left the
    // stable side permanently capped at 64 unique ports).
    let effective_stage = if remote_port_dependent
        && stage >= RecoveryStage::Predicted
        && stage < RecoveryStage::ScatterExtended
    {
        RecoveryStage::ScatterExtended
    } else {
        stage
    };
    let max_probes = if relay_safety_net && effective_stage >= RecoveryStage::ScatterExtended {
        RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES
    } else {
        effective_stage.max_probes()
    };
    // The physical-datagram ceiling counts kernel datagrams, while an
    // ActivePool sweep fan-outs every candidate to every socket — so the
    // plan is sized `ceiling / sockets` so one session covers a COMPLETE
    // window (field evidence: a 512-cap/3-socket truncation left a window
    // half-scanned).  A port-dependent remote makes the local side the
    // asymmetric STABLE role, which sweeps through `StableUniqueScatter`
    // (ONE socket, one datagram per distinct remote port): the fan-out
    // division must NOT apply there, otherwise a 192-datagram ceiling is
    // spent as a 64-port window (field evidence v0.1.116, R4/R7/R8: the
    // stable side covered only 64 unique CGNAT ports per session; at ~0.1%
    // per-port hit odds that is why 3/10 rounds stayed on relay).
    let max_candidates = if remote_port_dependent
        && effective_stage >= RecoveryStage::ScatterExtended
    {
        max_probes as usize
    } else {
        (max_probes / socket_count.max(1) as u32).max(1) as usize
    };
    Some(max_candidates)
}

/// Bound a target set by the recovery stage machine.
///
/// - Wide scatter (birthday plans / remote scatter pool) is only built at
///   [`RecoveryStage::ScatterExtended`] — UNLESS the remote peer's NAT is
///   address/port-dependent, in which case the Predicted stage already
///   carries it: the remote's own fresh window is destination-specific
///   evidence that two different local ports see two different remote
///   renderings, so the wide scatter must start as soon as the first
///   (predicted-window) burst had no matched ACK.  Waiting for the small
///   scatter stages to fail sequentially costs the epoch several extra
///   no-ACK rounds (field evidence v0.1.116, R9).
/// - Every stage has a hard probe ceiling (`RecoveryStage::max_probes`).
/// - The Initial stage drops only locally-generated Birthday speculation
///   (never peer-signaled Predicted ports: for an address/port-dependent
///   peer the predicted window IS the only viable target set, so dropping it
///   would leave only LAN hosts that cannot traverse the NATs).
/// - A relay-backed peer (`relay_safety_net == true`) is capped at the
///   bounded trusted-endpoint ceiling even in the wide-scatter stage: relay
///   is the data plane, so traversal keeps probing at a bounded rate while
///   the wide birthday pool stays reachable — a destination-dependent remote
///   cannot rely on its step prediction, so its wide scatter must NOT be
///   suppressed just because a relay fallback exists (field evidence
///   v0.1.116: availability runs confirm the relay within ~100 ms, which
///   otherwise left the stable side permanently capped at 64 unique ports).
fn cap_targets_by_recovery_stage(
    conn: &PeerConnection,
    endpoints: &mut Vec<SocketAddr>,
    birthday_plan: &mut Option<BirthdayProbePlan>,
    remote_scatter_pool: &mut bool,
    stage: RecoveryStage,
    relay_safety_net: bool,
    socket_count: usize,
) {
    let remote_port_dependent = conn.remote_nat_requires_port_scatter();
    let wide_scatter_allowed = stage >= RecoveryStage::ScatterExtended
        || (remote_port_dependent && stage >= RecoveryStage::Predicted);
    if !wide_scatter_allowed {
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
    // Mirror `recovery_target_cap`: a port-dependent remote opens the
    // wide-scatter ceiling right after its predicted window had no matched
    // ACK instead of trickling through the small-stage ceilings.
    let effective_stage = if remote_port_dependent
        && stage >= RecoveryStage::Predicted
        && stage < RecoveryStage::ScatterExtended
    {
        RecoveryStage::ScatterExtended
    } else {
        stage
    };
    let max_probes = if relay_safety_net && effective_stage >= RecoveryStage::ScatterExtended {
        // Relay is available: wide scatter is downgraded to a bounded
        // trusted-endpoint heartbeat (the full cold-start capability stays
        // reachable for peers without a relay safety net).
        RECOVERY_STAGE_RELAY_BACKOFF_MAX_PROBES
    } else {
        effective_stage.max_probes()
    };
    // Same physical-datagram semantics as `recovery_target_cap`: the ceiling
    // is per-datagram; an ActivePool sweep sends every candidate from every
    // socket, so the truncation boundary is `ceiling / socket_count` — but a
    // port-dependent remote's stable side sweeps through
    // `StableUniqueScatter` (one socket, one datagram per distinct port), so
    // the fan-out division is skipped there.  Field evidence v0.1.116:
    // applying the division capped the stable side at 64 unique CGNAT ports
    // while the session budget allowed 192.
    let max_candidates = if remote_port_dependent
        && effective_stage >= RecoveryStage::ScatterExtended
    {
        max_probes as usize
    } else {
        (max_probes / socket_count.max(1) as u32).max(1) as usize
    };
    if endpoints.len() > max_candidates {
        endpoints.truncate(max_candidates);
    }
}
