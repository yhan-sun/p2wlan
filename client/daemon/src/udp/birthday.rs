use super::*;

pub(super) const HARD_HARD_BIRTHDAY_WAVE_INTERVAL: Duration = Duration::from_millis(20);

pub(super) const HARD_HARD_BIRTHDAY_WAVES: usize = 2;

/// Generate a bounded, token-scoped birthday window. It deliberately uses a
/// permutation stride over the UDP port ring and stops at the negotiated
/// level; it never enumerates the full 65,535-port space.
pub(super) fn hard_hard_birthday_candidates(
    public_ip: IpAddr,
    observed_ports: &[u16],
    level: usize,
    session_token: &str,
) -> Vec<SocketAddr> {
    let mut seed = 0xcbf29ce484222325u64;
    for byte in public_ip.to_string().bytes().chain(session_token.bytes()) {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    // Walk the non-zero UDP port ring with an odd stride.  Keep the stride
    // below 65535: a stride equal to the modulus would repeat one port and
    // could make a bounded level appear shorter than requested.
    let modulus = u64::from(u16::MAX);
    let stride = (seed % (modulus - 1)) | 1;
    let mut candidates = Vec::with_capacity(level);
    let mut seen = HashSet::new();
    for port in observed_ports {
        if *port != 0 && seen.insert(*port) {
            candidates.push(SocketAddr::new(public_ip, *port));
            if candidates.len() == level {
                return candidates;
            }
        }
    }
    let origin = seed % modulus;
    for index in 0..level.saturating_mul(4) {
        let port = ((origin + (index as u64).saturating_mul(stride)) % modulus + 1) as u16;
        if seen.insert(port) {
            candidates.push(SocketAddr::new(public_ip, port));
            if candidates.len() == level {
                break;
            }
        }
    }
    candidates
}

pub(crate) fn hard_hard_birthday_socket_count(level: usize) -> usize {
    match level {
        0..=64 => 2,
        65..=128 => 4,
        _ => 8,
    }
}

pub(super) fn hard_hard_birthday_capacity_plan(
    requested_level: usize,
    attached_socket_count: usize,
) -> Option<(usize, usize)> {
    let requested_level = match requested_level {
        0..=64 => 64,
        65..=128 => 128,
        _ => 256,
    };
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let available_socket_count = if attached_socket_count >= 8 {
        8
    } else if attached_socket_count >= 4 {
        4
    } else if attached_socket_count >= 2 {
        2
    } else {
        return None;
    };
    let actual_socket_count = available_socket_count.min(requested_socket_count);
    let actual_level = match actual_socket_count {
        2 => 64,
        4 => 128,
        8 => 256,
        _ => return None,
    };
    Some((actual_level, actual_socket_count))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BirthdaySocketPlan {
    pub(super) requested_socket_count: usize,
    pub(super) attached_socket_count: usize,
    pub(super) usable_socket_count: usize,
    pub(super) unavailable_socket_count: usize,
    pub(super) usable_socket_indices: Vec<usize>,
}

/// Convert the exact session socket snapshot into the only socket list the
/// birthday scheduler is allowed to use.  This deliberately has no pool
/// lookup or "best effort" substitution: a missing requested member remains
/// unavailable and lowers the wave plan.
pub(super) fn hard_hard_birthday_socket_plan(
    requested_level: usize,
    snapshot: Vec<HardHardSocketSnapshot>,
) -> BirthdaySocketPlan {
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let attached_socket_count = snapshot.iter().filter(|entry| entry.attached).count();
    let usable_socket_indices = snapshot
        .into_iter()
        .filter(|entry| entry.usable)
        .map(|entry| entry.socket_index)
        .collect::<Vec<_>>();
    let usable_socket_count = usable_socket_indices.len();
    BirthdaySocketPlan {
        requested_socket_count,
        attached_socket_count,
        usable_socket_count,
        unavailable_socket_count: requested_socket_count.saturating_sub(usable_socket_count),
        usable_socket_indices,
    }
}

pub(crate) fn hard_hard_birthday_wave_count(socket_count: usize) -> usize {
    match socket_count {
        0 => 0,
        1 => 1,
        _ => HARD_HARD_BIRTHDAY_WAVES,
    }
}

pub(super) fn hard_hard_birthday_packets_planned(
    socket_count: usize,
    target_count: usize,
) -> usize {
    target_count.saturating_mul(hard_hard_birthday_wave_count(socket_count))
}

pub(super) fn hard_hard_birthday_wave_assignments(
    socket_count: usize,
    targets: Vec<SocketAddr>,
    wave: usize,
) -> Vec<Vec<SocketAddr>> {
    if socket_count == 0 {
        return Vec::new();
    }
    let mut assignments = vec![Vec::new(); socket_count];
    let socket_offset = wave % socket_count;
    for (index, target) in targets.into_iter().enumerate() {
        assignments[(index + socket_offset) % socket_count].push(target);
    }
    assignments
}

impl UdpTransport {
    /// Run the bounded high-entropy Hard↔Hard lane. Each level owns a small
    /// set of fresh sockets, measures several observers on the first socket,
    /// and derives a token-scoped destination guess set. The sockets remain
    /// attached and authenticated until the first peer-reflexive packet
    /// promotes one of them; all losers are then detached immediately.
    pub(crate) async fn run_hard_hard_birthday_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        level: usize,
        session_token: &str,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> std::result::Result<HardHardBirthdayResult, FreshMappingRejection> {
        if !self.peers.local_nat_requires_fresh_mapping_punch().await {
            return Err(FreshMappingRejection::StableLocalNat);
        }
        if cancellation.is_some_and(|cancellation| cancellation.is_cancelled())
            || self.peers.is_direct(peer_id).await
        {
            return Err(FreshMappingRejection::Superseded);
        }
        if self.local_node_id.is_none() || self.peers.probe_key_for_peer(peer_id).await.is_none() {
            return Err(FreshMappingRejection::MissingProbeKey);
        }
        let observers = observers
            .iter()
            .copied()
            .filter(|observer| observer.is_ipv4())
            .collect::<Vec<_>>();
        if observers.len() < 3 {
            return Err(FreshMappingRejection::InsufficientSamples);
        }
        let requested_level = match level {
            0..=64 => 64,
            65..=128 => 128,
            _ => 256,
        };
        let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
        let mut level = requested_level;
        let network_generation = self.peers.current_network_generation_sync();
        let mut attached: Vec<(
            usize,
            std::sync::Arc<UdpSocket>,
            ProvisionalSocketGuard,
            u64,
            SocketAddr,
        )> = Vec::with_capacity(requested_socket_count);
        let mut capacity_rejected = false;
        for _ in 0..requested_socket_count {
            let punch_generation = self.peers.next_punch_generation(peer_id).await;
            let (socket_index, socket) = match self.bind_fresh_punch_socket().await {
                Ok(bound) => bound,
                Err(_) => {
                    for attached_socket in &attached {
                        self.detach_dynamic_socket_by_index(
                            attached_socket.0,
                            "hard_hard_birthday_bind_failed",
                        )
                        .await;
                    }
                    return Err(FreshMappingRejection::BindFailed);
                }
            };
            let local_endpoint = socket.local_addr().ok();
            let Some(local_endpoint) = local_endpoint else {
                self.detach_dynamic_socket_by_index(
                    socket_index,
                    "hard_hard_birthday_no_local_endpoint",
                )
                .await;
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_no_local_endpoint",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::BindFailed);
            };
            let guard = match self
                .attach_dynamic_punch_socket(
                    peer_id,
                    socket_index,
                    socket.clone(),
                    network_generation,
                    punch_generation,
                    cancellation,
                )
                .await
            {
                Ok(guard) => guard,
                Err(DynamicSocketAttachError::CapacityRejected) => {
                    capacity_rejected = true;
                    break;
                }
                Err(error) => {
                    for attached_socket in &attached {
                        self.detach_dynamic_socket_by_index(
                            attached_socket.0,
                            "hard_hard_birthday_attach_failed",
                        )
                        .await;
                    }
                    return Err(match error {
                        DynamicSocketAttachError::Superseded => FreshMappingRejection::Superseded,
                        DynamicSocketAttachError::CapacityRejected => {
                            FreshMappingRejection::CapacityRejected
                        }
                        DynamicSocketAttachError::NoInboundChannel
                        | DynamicSocketAttachError::ReaderStartupFailed => {
                            FreshMappingRejection::BindFailed
                        }
                    });
                }
            };
            attached.push((
                socket_index,
                socket,
                guard,
                punch_generation,
                local_endpoint,
            ));
        }

        if capacity_rejected {
            let Some((actual_level, actual_socket_count)) =
                hard_hard_birthday_capacity_plan(requested_level, attached.len())
            else {
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_capacity_rejected",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::CapacityRejected);
            };
            level = actual_level;
            while attached.len() > actual_socket_count {
                if let Some((socket_index, _, _, _, _)) = attached.pop() {
                    self.detach_dynamic_socket_by_index(
                        socket_index,
                        "hard_hard_birthday_capacity_downgrade",
                    )
                    .await;
                }
            }
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_birthday_degraded",
                    None,
                    Some(level),
                    None,
                    format!(
                        "requested_level={} actual_level={} requested_socket_count={} actual_socket_count={} reason=socket_cap",
                        requested_level,
                        level,
                        requested_socket_count,
                        attached.len(),
                    ),
                )
                .await;
        }

        let mut measurements = JoinSet::new();
        for (position, (_, socket, _, _, _)) in attached.iter().enumerate() {
            let transport = self.clone();
            let socket = socket.clone();
            let peer_id = peer_id.to_string();
            let cancellation = cancellation.cloned();
            let selected_observers = if position == 0 {
                observers.iter().copied().take(4).collect::<Vec<_>>()
            } else {
                vec![observers[position % observers.len()]]
            };
            measurements.spawn(async move {
                let observations = transport
                    .measure_fresh_mapping_batch(&socket, &selected_observers, stun_timeout, || {
                        !cancellation
                            .as_ref()
                            .is_some_and(|cancellation| cancellation.is_cancelled())
                            && !transport.peers.is_direct_sync(&peer_id)
                            && transport.peers.current_network_generation_sync()
                                == network_generation
                    })
                    .await;
                (position, observations)
            });
        }
        let mut observations_by_socket = vec![Vec::new(); attached.len()];
        while let Some(joined) = measurements.join_next().await {
            if let Ok((position, observations)) = joined {
                observations_by_socket[position] = observations;
            }
        }
        if cancellation.is_some_and(|cancellation| cancellation.is_cancelled())
            || self.peers.current_network_generation_sync() != network_generation
            || self.peers.is_direct(peer_id).await
        {
            for attached_socket in &attached {
                self.detach_dynamic_socket_by_index(
                    attached_socket.0,
                    "hard_hard_birthday_superseded",
                )
                .await;
            }
            return Err(FreshMappingRejection::Superseded);
        }
        let all_observations = observations_by_socket
            .iter()
            .flat_map(|observations| observations.iter().cloned())
            .collect::<Vec<_>>();
        let mut public_ip = None;
        let mut observed_ports = Vec::new();
        for observation in &all_observations {
            if public_ip.is_some_and(|ip| ip != observation.observed.ip()) {
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_public_ip_changed",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::PublicIpChanged);
            }
            public_ip = Some(observation.observed.ip());
            observed_ports.push(observation.observed.port());
        }
        let Some(public_ip) = public_ip else {
            for attached_socket in &attached {
                self.detach_dynamic_socket_by_index(
                    attached_socket.0,
                    "hard_hard_birthday_no_observation",
                )
                .await;
            }
            return Err(FreshMappingRejection::InsufficientSamples);
        };
        observed_ports.sort_unstable();
        observed_ports.dedup();
        let local_model = infer_allocation_model(&observations_by_socket[0]);
        let model_label = local_model.kind.label().to_string();
        let candidate_endpoints =
            hard_hard_birthday_candidates(public_ip, &observed_ports, level, session_token);
        if candidate_endpoints.len() != level {
            for attached_socket in &attached {
                self.detach_dynamic_socket_by_index(
                    attached_socket.0,
                    "hard_hard_birthday_candidate_generation_failed",
                )
                .await;
            }
            return Err(FreshMappingRejection::UnpredictableSequence);
        }
        // A birthday window has one affinity owner but several authenticated
        // speculative receivers.  Pin only the first socket; committing each
        // guard with commit_and_pin would overwrite the previous pin and make
        // every earlier guard fail its finalize revalidation.  The remaining
        // guards use the no-affinity speculative commit below and are still
        // protected by the same generation/cancellation fences.
        for (position, (socket_index, _, guard, punch_generation, _)) in attached.iter().enumerate()
        {
            let committed = if position == 0 {
                guard
                    .commit_and_pin(
                        self,
                        peer_id,
                        *socket_index,
                        network_generation,
                        *punch_generation,
                    )
                    .await
                    .committed()
            } else {
                guard
                    .commit_speculative(
                        self,
                        peer_id,
                        *socket_index,
                        network_generation,
                        *punch_generation,
                    )
                    .await
                    .committed()
            };
            if !committed
                || !self
                    .tag_hard_hard_socket(peer_id, *socket_index, session_token)
                    .await
            {
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_commit_failed",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::Superseded);
            }
        }
        self.peers
            .record_direct_event(
                peer_id,
                "hard_hard_fresh_mapping_observed",
                candidate_endpoints.first().copied(),
                Some(candidate_endpoints.len()),
                None,
                format!(
                    "model={} strategy=bounded_birthday confidence={} socket_count={} observation_count={} public_ip={} level={} requested_level={} requested_socket_count={} public_port_samples={}",
                    model_label,
                    local_model.confidence,
                    attached.len(),
                    all_observations.len(),
                    public_ip,
                    level,
                    requested_level,
                    requested_socket_count,
                    observed_ports.len(),
                ),
            )
            .await;
        let sockets = attached
            .into_iter()
            .map(
                |(socket_index, _, guard, punch_generation, socket_local_endpoint)| {
                    HardHardBirthdaySocket {
                        punch_generation,
                        socket_index,
                        socket_local_endpoint,
                        guard,
                    }
                },
            )
            .collect();
        Ok(HardHardBirthdayResult {
            requested_level,
            requested_socket_count,
            level,
            public_ip,
            public_port_samples: observed_ports,
            observation_count: all_observations.len(),
            candidate_endpoints,
            sockets,
            model_label,
            model_confidence: local_model.confidence,
        })
    }

    /// Fan a bounded Hard↔Hard birthday window across the committed candidate
    /// sockets in up to two deterministic waves. Each wave sends every target
    /// from exactly one socket; the second wave rotates the socket assignment
    /// so a target is retried from a different source port without creating a
    /// socket-count Cartesian product.
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(crate) async fn punch_hard_hard_birthday_candidates(
        &self,
        peer_id: &str,
        socket_indices: Vec<usize>,
        targets: Vec<SocketAddr>,
        requested_level: usize,
        peer_session_generation: crate::peer::PeerSessionGeneration,
        profile_fence: (u64, u64),
        session_token: &str,
    ) -> Result<PunchSendReport> {
        self.punch_hard_hard_birthday_candidates_with_metadata(
            peer_id,
            socket_indices,
            targets.clone(),
            requested_level,
            targets.len(),
            targets.len(),
            peer_session_generation,
            profile_fence,
            session_token,
            None,
        )
        .await
    }

    /// Scheduler entry used by the Hard↔Hard runtime.  The metadata counts
    /// come from the local session ledger's pre-cap measurement contract; the
    /// scheduler never derives them from the remote/effective target list.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn punch_hard_hard_birthday_candidates_with_metadata(
        &self,
        peer_id: &str,
        requested_socket_indices: Vec<usize>,
        targets: Vec<SocketAddr>,
        requested_level: usize,
        generated_candidate_count: usize,
        signaled_candidate_count: usize,
        peer_session_generation: crate::peer::PeerSessionGeneration,
        profile_fence: (u64, u64),
        session_token: &str,
        progress: Option<Arc<Mutex<BirthdaySweepProgress>>>,
    ) -> Result<PunchSendReport> {
        let live = if let Some(progress) = progress.as_ref() {
            Some(progress.lock().await.live.clone())
        } else {
            None
        };
        let mut effective_targets =
            Vec::with_capacity(targets.len().min(crate::MAX_SIGNAL_CANDIDATES));
        for target in targets {
            if target.port() == 0 || effective_targets.contains(&target) {
                continue;
            }
            effective_targets.push(target);
            if effective_targets.len() == crate::MAX_SIGNAL_CANDIDATES {
                break;
            }
        }
        let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
        // This is the only socket snapshot used for scheduling.  It is exact
        // and session-token scoped; a detached member becomes unavailable and
        // can never be replaced by a pool socket.
        let socket_snapshot = self
            .hard_hard_socket_snapshot_for_token(peer_id, session_token, &requested_socket_indices)
            .await;
        let socket_plan = hard_hard_birthday_socket_plan(requested_level, socket_snapshot);
        let attached_socket_count = socket_plan.attached_socket_count;
        let effective_socket_indices = socket_plan.usable_socket_indices;
        let usable_socket_count = socket_plan.usable_socket_count;
        let unavailable_socket_count = socket_plan.unavailable_socket_count;
        let waves_planned = hard_hard_birthday_wave_count(usable_socket_count);
        let mut birthday = BirthdaySweepReport {
            requested_level,
            generated_candidate_count,
            signaled_candidate_count,
            effective_target_count: effective_targets.len(),
            requested_socket_count,
            attached_socket_count,
            usable_socket_count,
            unavailable_socket_count,
            socket_count: usable_socket_count,
            waves_planned,
            packets_planned: hard_hard_birthday_packets_planned(
                usable_socket_count,
                effective_targets.len(),
            ),
            ..BirthdaySweepReport::default()
        };
        if usable_socket_count == 1 {
            birthday.degraded_reason = Some(
                if requested_socket_count > 1 {
                    "partial_socket_unavailable"
                } else {
                    "single_socket"
                }
                .to_string(),
            );
        } else if usable_socket_count > 0 && usable_socket_count < requested_socket_count {
            birthday.degraded_reason = Some("partial_socket_unavailable".to_string());
        }
        let mut aggregate = PunchSendReport::default();
        publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
        if effective_targets.is_empty() {
            birthday.stop_reason = Some("empty_targets".to_string());
            update_birthday_sweep_counters(&mut birthday, &aggregate);
            aggregate.birthday = Some(birthday);
            publish_birthday_sweep_progress(
                &progress,
                aggregate
                    .birthday
                    .as_ref()
                    .expect("birthday report just set"),
                &aggregate,
            )
            .await;
            return Ok(aggregate);
        }
        if effective_socket_indices.is_empty() {
            birthday.stop_reason = Some("socket_unavailable".to_string());
            aggregate.failure_kind = Some(BirthdaySweepFailureKind::SocketUnavailable);
            update_birthday_sweep_counters(&mut birthday, &aggregate);
            aggregate.birthday = Some(birthday);
            publish_birthday_sweep_progress(
                &progress,
                aggregate
                    .birthday
                    .as_ref()
                    .expect("birthday report just set"),
                &aggregate,
            )
            .await;
            return Ok(aggregate);
        }

        let network_generation_at_start = self.peers.current_network_generation_sync();
        let remote_candidate_epoch_at_start = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or_default();
        let direct_commit_seq_at_start = self.peers.direct_commit_seq_sync(peer_id);
        for wave in 0..birthday.waves_planned {
            if wave > 0 {
                sleep(HARD_HARD_BIRTHDAY_WAVE_INTERVAL).await;
            }
            if wave > 0 {
                if let Some(reason) = self
                    .hard_hard_birthday_stop_reason(
                        peer_id,
                        session_token,
                        profile_fence,
                        peer_session_generation,
                        network_generation_at_start,
                        remote_candidate_epoch_at_start,
                        direct_commit_seq_at_start,
                    )
                    .await
                {
                    birthday.stop_reason = Some(reason.to_string());
                    if let Some(failure_kind) = BirthdaySweepFailureKind::from_stop_reason(reason) {
                        aggregate.failure_kind = combine_birthday_failure_kind(
                            aggregate.failure_kind,
                            Some(failure_kind),
                        );
                        update_birthday_sweep_counters(&mut birthday, &aggregate);
                        publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                        return Err(DaemonError::Network(format!(
                            "hard-hard birthday stopped: {reason}"
                        )));
                    }
                    break;
                }
            }

            birthday.waves_started = birthday.waves_started.saturating_add(1);
            let mut assignments = hard_hard_birthday_wave_assignments(
                effective_socket_indices.len(),
                effective_targets.clone(),
                wave,
            );
            let wave_assigned_count = assignments.iter().map(Vec::len).sum::<usize>();
            birthday.targets_assigned = birthday
                .targets_assigned
                .saturating_add(effective_targets.len());
            update_live_birthday_counters(&live, |counters| {
                counters.targets_assigned = counters
                    .targets_assigned
                    .saturating_add(u32::try_from(wave_assigned_count).unwrap_or(u32::MAX));
            });
            let mut workers = JoinSet::new();
            for (socket_position, socket_index) in
                effective_socket_indices.iter().copied().enumerate()
            {
                let assigned = std::mem::take(&mut assignments[socket_position]);
                if assigned.is_empty() {
                    continue;
                }
                let transport = self.clone();
                let peer_id = peer_id.to_string();
                let session_token = session_token.to_string();
                let live_counters = live.clone();
                let assigned_count = assigned.len();
                workers.spawn(async move {
                    let result = transport
                        .punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session_and_live(
                            &peer_id,
                            socket_index,
                            assigned,
                            HARD_HARD_BIRTHDAY_WAVE_INTERVAL,
                            1,
                            Some(profile_fence),
                            Some(&session_token),
                            live_counters,
                        )
                        .await;
                    (assigned_count, result)
                });
            }
            update_birthday_sweep_counters(&mut birthday, &aggregate);
            publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;

            let mut wave_report = PunchSendReport::default();
            let mut wave_fully_completed = true;
            let mut failure_kind = None;
            while let Some(joined) = workers.join_next().await {
                update_live_birthday_counters(&live, |counters| {
                    counters.workers_completed = counters.workers_completed.saturating_add(1);
                });
                record_birthday_worker_result(
                    &mut wave_report,
                    &mut wave_fully_completed,
                    &mut failure_kind,
                    joined,
                );
            }
            // A JoinError has no return payload, so normalize the wave's
            // assigned count from the scheduler plan and retain every target
            // not reached by a returned worker as cancelled progress.
            wave_report.targets_assigned = u32::try_from(wave_assigned_count).unwrap_or(u32::MAX);
            wave_report.targets_cancelled = wave_report.targets_cancelled.max(
                u32::try_from(wave_assigned_count)
                    .unwrap_or(u32::MAX)
                    .saturating_sub(wave_report.targets_attempted),
            );
            update_live_birthday_counters(&live, |counters| {
                counters.targets_cancelled = counters
                    .targets_cancelled
                    .saturating_add(wave_report.targets_cancelled);
            });
            merge_punch_send_reports(&mut aggregate, wave_report.clone());
            if let Some(failure_kind) = failure_kind.or(wave_report.failure_kind) {
                aggregate.failure_kind = Some(failure_kind);
                aggregate.worker_failed |= failure_kind == BirthdaySweepFailureKind::WorkerJoin;
                let stop_reason = failure_kind.stop_reason();
                birthday.stop_reason = Some(stop_reason.to_string());
                update_birthday_sweep_counters(&mut birthday, &aggregate);
                publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                return Err(DaemonError::Network(format!(
                    "hard-hard birthday worker stopped: {stop_reason}"
                )));
            }
            if !wave_fully_completed {
                birthday.stop_reason = Some(
                    self.hard_hard_birthday_stop_reason(
                        peer_id,
                        session_token,
                        profile_fence,
                        peer_session_generation,
                        network_generation_at_start,
                        remote_candidate_epoch_at_start,
                        direct_commit_seq_at_start,
                    )
                    .await
                    .unwrap_or("socket_unavailable")
                    .to_string(),
                );
                update_birthday_sweep_counters(&mut birthday, &aggregate);
                publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                break;
            }
            birthday.waves_fully_completed = birthday.waves_fully_completed.saturating_add(1);
            birthday.waves_completed = birthday.waves_fully_completed;
            update_birthday_sweep_counters(&mut birthday, &aggregate);
            publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
            if let Some(reason) = self
                .hard_hard_birthday_stop_reason(
                    peer_id,
                    session_token,
                    profile_fence,
                    peer_session_generation,
                    network_generation_at_start,
                    remote_candidate_epoch_at_start,
                    direct_commit_seq_at_start,
                )
                .await
            {
                birthday.stop_reason = Some(reason.to_string());
                publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                break;
            }
            if wave_report.epoch_budget_exhausted {
                birthday.stop_reason = Some("epoch_budget_exhausted".to_string());
                publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                break;
            }
            if wave_report.candidate_iteration_capped {
                birthday.stop_reason = Some("candidate_iteration_capped".to_string());
                publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                break;
            }
            if wave_report.packets_sent == 0 && wave_report.budget_skipped > 0 {
                birthday.stop_reason = Some("budget_exhausted".to_string());
                publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                break;
            }
            if wave_report.packets_sent == 0 && wave_report.budget_skipped == 0 {
                // A physical send failure is local to the logical target.
                // Keep the bounded scheduler alive so a later target (or the
                // rotated second wave) can still establish the path.  Only a
                // wave that made no logical attempt and had no physical error
                // is an unavailable-socket verdict.
                if wave_report.logical_probes_attempted == 0
                    && wave_report.physical_send_errors == 0
                {
                    birthday.stop_reason = Some("socket_unavailable".to_string());
                    aggregate.failure_kind = Some(BirthdaySweepFailureKind::SocketUnavailable);
                    publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
                    break;
                }
            }
        }

        // Do not turn one or more transient target send failures into an
        // early scheduler abort.  The terminal send verdict is only emitted
        // after every bounded wave has had its chance and every logical Probe
        // attempted by this session failed at the physical send boundary.
        if birthday.stop_reason.is_none()
            && aggregate.logical_probes_attempted > 0
            && aggregate.logical_probes_sent == 0
            && aggregate.logical_probe_send_failures > 0
            && aggregate.physical_send_errors > 0
        {
            aggregate.failure_kind = Some(BirthdaySweepFailureKind::Send);
            birthday.stop_reason = Some("send_error".to_string());
            update_birthday_sweep_counters(&mut birthday, &aggregate);
            publish_birthday_sweep_progress(&progress, &birthday, &aggregate).await;
            return Err(DaemonError::Network(
                "hard-hard birthday probes all failed at the physical send boundary".to_string(),
            ));
        }

        if birthday.stop_reason.is_none() {
            birthday.stop_reason = Some("completed".to_string());
        }
        aggregate.unique_target_endpoints =
            u32::try_from(aggregate.sent_target_endpoints.len()).unwrap_or(u32::MAX);
        update_birthday_sweep_counters(&mut birthday, &aggregate);
        aggregate.birthday = Some(birthday);
        publish_birthday_sweep_progress(
            &progress,
            aggregate
                .birthday
                .as_ref()
                .expect("birthday report just set"),
            &aggregate,
        )
        .await;
        Ok(aggregate)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn hard_hard_birthday_stop_reason(
        &self,
        peer_id: &str,
        session_token: &str,
        profile_fence: (u64, u64),
        peer_session_generation: crate::peer::PeerSessionGeneration,
        network_generation: u64,
        remote_candidate_epoch: u64,
        direct_commit_seq: Option<u64>,
    ) -> Option<&'static str> {
        if self
            .peers
            .hard_hard_winner_for_token(peer_id, session_token)
            .await
            .is_some()
        {
            return Some("winner_selected");
        }
        if self.peers.is_direct_sync(peer_id) {
            return Some("direct_confirmed");
        }
        if self.peers.current_network_generation_sync() != network_generation {
            return Some("network_generation_changed");
        }
        if !self
            .peers
            .peer_session_is_current_sync(peer_id, peer_session_generation)
        {
            return Some("peer_session_changed");
        }
        if self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or_default()
            != remote_candidate_epoch
        {
            return Some("candidate_epoch_changed");
        }
        let profile_current = self
            .peers
            .hard_hard_plan_for_peer(peer_id)
            .await
            .is_some_and(|plan| {
                plan.local_profile_generation == profile_fence.0
                    && plan.remote_profile_generation == profile_fence.1
            });
        if !profile_current {
            return Some("profile_generation_changed");
        }
        if !self
            .peers
            .hard_hard_session_token_is_current(peer_id, session_token)
            .await
        {
            return Some("session_retired");
        }
        if self.peers.direct_commit_seq_sync(peer_id) != direct_commit_seq {
            return Some("direct_commit_seq_changed");
        }
        None
    }
}
