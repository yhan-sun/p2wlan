use super::*;

/// The standalone exact-socket API returns a complete report to its caller,
/// so it performs the terminal all-physical-failure classification itself.
/// Birthday workers intentionally do not call this helper: their scheduler
/// must first give every target and bounded wave an opportunity to send.
pub(super) fn finalize_physical_send_failure(report: &mut PunchSendReport) {
    if report.failure_kind.is_none()
        && report.logical_probes_attempted > 0
        && report.logical_probes_sent == 0
        && report.logical_probe_send_failures > 0
        && report.physical_send_errors > 0
    {
        report.failure_kind = Some(BirthdaySweepFailureKind::Send);
    }
}

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
        let mut physical_bytes_sent = 0u64;
        let mut physical_send_errors = 0u32;
        let mut physical_send_error_bytes = 0u64;
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
                        physical_bytes_sent =
                            physical_bytes_sent.saturating_add(sent.physical_bytes_sent);
                        physical_send_errors =
                            physical_send_errors.saturating_add(failed_datagrams);
                        physical_send_error_bytes = physical_send_error_bytes
                            .saturating_add(sent.physical_send_error_bytes);
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
                        physical_send_error_bytes = physical_send_error_bytes
                            .saturating_add(failure.physical_send_error_bytes);
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
            physical_bytes_sent,
            physical_send_errors,
            physical_send_error_bytes,
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
