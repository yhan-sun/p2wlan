#[cfg(test)]
use super::wait_for_birthday_worker_completion_gate_for_test;
use super::{
    build_probe_schedule, combine_birthday_failure_kind, debug, finalize_physical_send_failure,
    hard_hard_birthday_packets_planned, hard_hard_birthday_socket_count,
    hard_hard_birthday_socket_plan, hard_hard_birthday_wave_assignments,
    hard_hard_birthday_wave_count, merge_punch_send_reports, outbound_probe_admission_reason,
    publish_birthday_sweep_progress, record_birthday_worker_result, sleep, trace,
    update_birthday_sweep_counters, update_live_birthday_counters, Arc, BirthdayLiveRecorder,
    BirthdaySweepFailureKind, BirthdaySweepProgress, BirthdaySweepReport, DaemonError, Duration,
    HashSet, JoinSet, LiveBirthdayProgress, Mutex, OutboundProbeAdmission, PendingProbePurpose,
    ProbeSendFailureKind, PunchSendReport, Result, SocketAddr, StdMutex, UdpSocket, UdpTransport,
    HARD_HARD_BIRTHDAY_WAVE_INTERVAL, OUTBOUND_CONNECTIVITY_PROBE_SPACING,
};

impl UdpTransport {
    /// Probe the peer's candidates from the dedicated punch socket only.
    ///
    /// Used by the synchronized punch flow after a fresh-mapping generation,
    /// so the predictable mapping socket carries the whole candidate sweep
    /// while the other pool sockets stay untouched.
    #[allow(dead_code)]
    pub(crate) async fn punch_candidates_from_dynamic_socket(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        // The leased resolve re-validates peer ownership, Committed phase and
        // the network generation under the socket-state lock and keeps the
        // entry's reader alive until this whole sweep ends: a detach racing
        // the resolve can neither hand out a socket the peer must not use nor
        // kill the reader before the sweep's ACKs can arrive.
        let Some((index, socket, _lease)) = self.resolve_dynamic_socket_for_send(peer_id).await
        else {
            return Ok(PunchSendReport::default());
        };
        self.punch_candidates_from_dynamic_socket_resolved(
            peer_id,
            index,
            socket,
            candidates,
            probe_interval,
            attempts,
            None,
            None,
            None,
        )
        .await
    }

    /// Sweep an explicitly named committed dynamic socket.  This is the
    /// fail-closed variant used by Hard↔Hard sessions: if the measured socket
    /// is no longer available, the caller receives an empty report instead of
    /// silently sending the prediction from a different socket.
    pub(crate) async fn punch_candidates_from_dynamic_socket_index(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        self.punch_candidates_from_dynamic_socket_index_with_profile_fence(
            peer_id,
            socket_index,
            candidates,
            probe_interval,
            attempts,
            None,
        )
        .await
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

    /// Exact-index sweep with an optional Hard↔Hard profile-generation fence.
    /// The ordinary dynamic helper leaves the fence unset; the synchronized
    /// path supplies both profile generations so a remote profile refresh
    /// cancels the old session before another datagram is emitted.
    pub(crate) async fn punch_candidates_from_dynamic_socket_index_with_profile_fence(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
    ) -> Result<PunchSendReport> {
        self.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
            peer_id,
            socket_index,
            candidates,
            probe_interval,
            attempts,
            profile_fence,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
        hard_hard_session_token: Option<&str>,
    ) -> Result<PunchSendReport> {
        let mut report = self
            .punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session_and_live(
                peer_id,
                socket_index,
                candidates,
                probe_interval,
                attempts,
                profile_fence,
                hard_hard_session_token,
                None,
            )
            .await?;
        finalize_physical_send_failure(&mut report);
        Ok(report)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session_and_live(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
        hard_hard_session_token: Option<&str>,
        live: Option<Arc<StdMutex<LiveBirthdayProgress>>>,
    ) -> Result<PunchSendReport> {
        let Some((index, socket, _lease)) = self
            .resolve_dynamic_socket_index_for_send(peer_id, socket_index)
            .await
        else {
            let failure_kind = self
                .classify_dynamic_socket_failure_kind(peer_id, socket_index)
                .await;
            return Ok(PunchSendReport {
                targets_assigned: u32::try_from(candidates.len()).unwrap_or(u32::MAX),
                targets_cancelled: u32::try_from(candidates.len()).unwrap_or(u32::MAX),
                probe_path_errors: 1,
                failure_kind: Some(BirthdaySweepFailureKind::from_probe_failure(failure_kind)),
                ..PunchSendReport::default()
            });
        };
        self.punch_candidates_from_dynamic_socket_resolved(
            peer_id,
            index,
            socket,
            candidates,
            probe_interval,
            attempts,
            profile_fence,
            hard_hard_session_token,
            live,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn punch_candidates_from_dynamic_socket_resolved(
        &self,
        peer_id: &str,
        index: usize,
        socket: Arc<UdpSocket>,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
        hard_hard_session_token: Option<&str>,
        live: Option<Arc<StdMutex<LiveBirthdayProgress>>>,
    ) -> Result<PunchSendReport> {
        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        let mut packets_sent = 0u32;
        let mut logical_probes_attempted = 0u32;
        let mut logical_probes_sent = 0u32;
        let mut logical_probe_send_failures = 0u32;
        let mut physical_datagrams_sent = 0u32;
        let mut physical_send_errors = 0u32;
        let mut partial_physical_send_errors = 0u32;
        let mut probe_path_errors = 0u32;
        let mut budget_skipped = 0u32;
        let mut last_budget_reason = None;
        let mut sent_endpoints = HashSet::new();
        let mut first_send_at_ms = None;
        let mut last_send_at_ms: Option<u64> = None;
        let mut per_socket_sent = 0u32;
        let mut per_socket_sent_index = index;
        let targets_assigned = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
        let mut targets_examined = 0u32;
        let mut targets_attempted = 0u32;
        let mut target_processing_completed = true;
        let mut failure_kind = None;
        let live_recorder = live.clone().map(BirthdayLiveRecorder::new);
        let commit_seq_at_start = self.peers.direct_commit_seq_sync(peer_id);
        let network_generation_at_start = self.peers.current_network_generation_sync();
        let remote_candidate_epoch_at_start = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or_default();
        'schedule: for round in schedule {
            if self.peers.current_network_generation_sync() != network_generation_at_start {
                trace!(
                    "Aborting dynamic-socket punch for peer {peer_id}: network generation changed mid-session"
                );
                target_processing_completed = false;
                failure_kind = combine_birthday_failure_kind(
                    failure_kind,
                    Some(BirthdaySweepFailureKind::NetworkGenerationChanged),
                );
                break;
            }
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }
            for candidate in round.endpoints {
                targets_examined = targets_examined.saturating_add(1);
                update_live_birthday_counters(&live, |counters| {
                    counters.targets_examined = counters.targets_examined.saturating_add(1);
                });
                if let Some(token) = hard_hard_session_token {
                    if self
                        .peers
                        .hard_hard_winner_for_token(peer_id, token)
                        .await
                        .is_some()
                    {
                        trace!(
                            "Aborting dynamic-socket Hard↔Hard scatter for peer {peer_id}: winner already selected"
                        );
                        target_processing_completed = false;
                        break 'schedule;
                    }
                }
                if self.peers.current_network_generation_sync() != network_generation_at_start {
                    trace!(
                        "Aborting dynamic-socket punch for peer {peer_id}: network generation changed before candidate send"
                    );
                    target_processing_completed = false;
                    failure_kind = combine_birthday_failure_kind(
                        failure_kind,
                        Some(BirthdaySweepFailureKind::NetworkGenerationChanged),
                    );
                    break;
                }
                if self
                    .peers
                    .current_remote_candidate_epoch(peer_id)
                    .await
                    .unwrap_or_default()
                    != remote_candidate_epoch_at_start
                {
                    trace!(
                        "Aborting dynamic-socket punch for peer {peer_id}: remote candidate epoch changed before candidate send"
                    );
                    target_processing_completed = false;
                    failure_kind = combine_birthday_failure_kind(
                        failure_kind,
                        Some(BirthdaySweepFailureKind::CandidateEpochChanged),
                    );
                    break;
                }
                if let Some((local_profile_generation, remote_profile_generation)) = profile_fence {
                    let current_plan = self.peers.hard_hard_plan_for_peer(peer_id).await;
                    let profile_failure = match current_plan {
                        Some(plan)
                            if plan.local_profile_generation == local_profile_generation
                                && plan.remote_profile_generation == remote_profile_generation =>
                        {
                            None
                        }
                        Some(plan) if plan.local_profile_generation != local_profile_generation => {
                            Some(ProbeSendFailureKind::LocalProfileGenerationChanged)
                        }
                        Some(_) => Some(ProbeSendFailureKind::RemoteProfileGenerationChanged),
                        None => Some(ProbeSendFailureKind::PeerSessionChanged),
                    };
                    if let Some(profile_failure) = profile_failure {
                        trace!(
                            "Aborting dynamic-socket punch for peer {peer_id}: Hard↔Hard profile generation changed before candidate send"
                        );
                        target_processing_completed = false;
                        failure_kind = combine_birthday_failure_kind(
                            failure_kind,
                            Some(BirthdaySweepFailureKind::from_probe_failure(
                                profile_failure,
                            )),
                        );
                        break;
                    }
                }
                if let Some(token) = hard_hard_session_token {
                    if !self
                        .peers
                        .hard_hard_session_token_is_current(peer_id, token)
                        .await
                    {
                        trace!(
                            "Aborting dynamic-socket Hard↔Hard punch for peer {peer_id}: session token was retired"
                        );
                        target_processing_completed = false;
                        failure_kind = combine_birthday_failure_kind(
                            failure_kind,
                            Some(BirthdaySweepFailureKind::from_probe_failure(
                                ProbeSendFailureKind::SessionRetired,
                            )),
                        );
                        break;
                    }
                }
                if self.peers.is_direct_sync(peer_id) {
                    // Direct was confirmed while this dedicated-socket sweep
                    // was in flight: stop emitting peer-directed probes.
                    trace!(
                        "Aborting dynamic-socket UDP punch for peer {peer_id}: Direct was confirmed mid-session"
                    );
                    target_processing_completed = false;
                    break;
                }
                if self.peers.direct_commit_seq_sync(peer_id) != commit_seq_at_start {
                    trace!(
                        "Aborting dynamic-socket UDP punch for peer {peer_id}: direct_commit_seq advanced past {commit_seq_at_start:?} mid-session"
                    );
                    target_processing_completed = false;
                    break;
                }
                // All session, network, profile, winner, Direct and commit
                // fences passed. A budget rejection below is still an
                // attempted target: it entered this worker's admission path,
                // but it is not a logical Probe construction/send attempt.
                targets_attempted = targets_attempted.saturating_add(1);
                update_live_birthday_counters(&live, |counters| {
                    counters.targets_attempted = counters.targets_attempted.saturating_add(1);
                });
                if self
                    .peers
                    .direct_probe_endpoint_quarantined(
                        peer_id,
                        candidate,
                        self.peers.current_network_generation_sync(),
                    )
                    .await
                {
                    budget_skipped = budget_skipped.saturating_add(1);
                    last_budget_reason = Some("direct_slow_relay_retained");
                    update_live_birthday_counters(&live, |counters| {
                        counters.budget_skipped = counters.budget_skipped.saturating_add(1);
                    });
                    trace!(
                        "Skipped dynamic-socket punch for peer {peer_id} candidate {candidate}: recent slow ACK quarantine"
                    );
                    continue;
                }
                match self
                    .admit_outbound_connectivity_probe(peer_id, candidate, index)
                    .await
                {
                    OutboundProbeAdmission::Accepted => {}
                    limited => {
                        // The dedicated-socket sweep now shares the same
                        // admission as the pool sweeps: per-second windows,
                        // the persistent budgets AND the recovery-epoch probe
                        // credit all apply to fresh-mapping punches.
                        budget_skipped = budget_skipped.saturating_add(1);
                        last_budget_reason = Some(outbound_probe_admission_reason(limited));
                        update_live_birthday_counters(&live, |counters| {
                            counters.budget_skipped = counters.budget_skipped.saturating_add(1);
                        });
                        continue;
                    }
                }
                logical_probes_attempted = logical_probes_attempted.saturating_add(1);
                update_live_birthday_counters(&live, |counters| {
                    counters.logical_probes_attempted =
                        counters.logical_probes_attempted.saturating_add(1);
                });
                match self
                    .send_probe_on_socket_result_with_hard_hard_token_classified(
                        index,
                        socket.clone(),
                        Some(peer_id),
                        candidate,
                        false,
                        PendingProbePurpose::ConnectivityCheck,
                        hard_hard_session_token,
                        true,
                        live_recorder.clone(),
                    )
                    .await
                {
                    Ok(sent) => {
                        packets_sent = packets_sent.saturating_add(1);
                        logical_probes_sent = logical_probes_sent.saturating_add(1);
                        let successful_datagrams = u32::from(sent.datagrams_sent);
                        let failed_datagrams = u32::from(sent.physical_send_errors);
                        per_socket_sent_index = sent.socket_index;
                        physical_datagrams_sent =
                            physical_datagrams_sent.saturating_add(successful_datagrams);
                        physical_send_errors =
                            physical_send_errors.saturating_add(failed_datagrams);
                        if failed_datagrams > 0 {
                            partial_physical_send_errors =
                                partial_physical_send_errors.saturating_add(failed_datagrams);
                        }
                        if let Some(sent_at_ms) = sent.first_send_at_ms {
                            first_send_at_ms.get_or_insert(sent_at_ms);
                            last_send_at_ms = Some(
                                last_send_at_ms.map_or(sent_at_ms, |last| last.max(sent_at_ms)),
                            );
                        }
                        per_socket_sent =
                            per_socket_sent.saturating_add(u32::from(sent.datagrams_sent));
                        if successful_datagrams > 0 {
                            sent_endpoints.insert(candidate);
                        }
                        self.peers
                            .record_direct_probe_sent(peer_id, candidate)
                            .await;
                        trace!(
                            "Sent dynamic-socket punch probe to peer {peer_id} candidate {} commit_seq={commit_seq_at_start:?}",
                            candidate
                        );
                        if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                            sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                        }
                    }
                    Err(failure) => {
                        let failed_datagrams = u32::from(failure.physical_send_errors);
                        if failure.kind == ProbeSendFailureKind::PhysicalSend
                            && failed_datagrams > 0
                        {
                            physical_send_errors =
                                physical_send_errors.saturating_add(failed_datagrams);
                            logical_probe_send_failures =
                                logical_probe_send_failures.saturating_add(1);
                        } else {
                            probe_path_errors = probe_path_errors.saturating_add(1);
                            update_live_birthday_counters(&live, |counters| {
                                counters.probe_path_errors =
                                    counters.probe_path_errors.saturating_add(1);
                            });
                            failure_kind = combine_birthday_failure_kind(
                                failure_kind,
                                Some(BirthdaySweepFailureKind::from_probe_failure(failure.kind)),
                            );
                            target_processing_completed = false;
                        }
                        debug!(
                            "Dynamic-socket punch to peer {peer_id} candidate {candidate} failed kind={:?}: {}",
                            failure.kind, failure.error
                        );
                        if failure.kind != ProbeSendFailureKind::PhysicalSend {
                            break 'schedule;
                        }
                    }
                }
            }
        }
        if budget_skipped > 0 {
            let reason = last_budget_reason.unwrap_or("probe_budget_limited");
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_probe_budget_limited",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "skipped {budget_skipped} dedicated-socket punch probes due to outbound {reason}; sent {packets_sent}"
                    ),
                )
                .await;
        }
        #[cfg(test)]
        wait_for_birthday_worker_completion_gate_for_test().await;
        Ok(PunchSendReport {
            packets_sent,
            logical_probes_attempted,
            logical_probes_sent,
            logical_probe_send_failures,
            physical_datagrams_sent,
            physical_send_errors,
            partial_physical_send_errors,
            probe_path_errors,
            unique_target_endpoints: u32::try_from(sent_endpoints.len()).unwrap_or(u32::MAX),
            first_send_at_ms,
            per_socket_sent: (per_socket_sent > 0)
                .then_some(vec![(per_socket_sent_index, per_socket_sent)])
                .unwrap_or_default(),
            budget_skipped,
            epoch_budget_exhausted: false,
            candidate_iteration_capped: false,
            sent_target_endpoints: sent_endpoints.into_iter().collect(),
            last_send_at_ms,
            targets_assigned,
            targets_examined,
            targets_attempted,
            targets_cancelled: targets_assigned.saturating_sub(targets_attempted),
            target_processing_completed,
            failure_kind,
            ..PunchSendReport::default()
        })
    }
}
