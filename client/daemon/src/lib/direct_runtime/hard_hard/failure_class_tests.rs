// Exercise the production attempt-report builder with the sender's existing
// ledger, rather than constructing a parallel set of diagnostic counters.
struct FailureClassBuilderFixture {
    peers: Arc<PeerManager>,
    udp: UdpTransport,
    identity: crate::peer::HardHardFreshSocketIdentity,
    remote: SocketAddr,
}

impl FailureClassBuilderFixture {
    async fn new() -> Self {
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        Self {
            peers,
            udp,
            identity,
            remote,
        }
    }

    fn build(
        &self,
        send: &PunchSendReport,
        planned: usize,
        received: UdpProbeRxSnapshot,
        direct: bool,
        reason: &str,
        birthday: bool,
    ) -> crate::peer::HardHardAttemptReport {
        let generation = self
            .peers
            .peer_session_generation_sync(&self.identity.peer_id)
            .expect("the report fixture has a current peer session");
        let measurement = crate::peer::HardHardMeasurementObservation {
            candidate_cap: 32,
            ..Default::default()
        };
        build_hard_hard_attempt_report(
            &self.peers,
            false,
            generation,
            &self.identity,
            &self.identity.session_token,
            "initiator",
            birthday,
            0,
            &measurement,
            &[self.remote],
            1,
            1,
            planned,
            None,
            send,
            received,
            direct,
            None,
            direct.then_some(1),
            None,
            reason,
        )
    }

    async fn close(self) {
        self.udp
            .detach_all_dynamic_punch_sockets("failure_class_report_fixture")
            .await;
    }
}

fn failure_class_complete_ledger() -> PunchSendReport {
    let sent_at = crate::udp::monotonic_millis();
    PunchSendReport {
        packets_sent: 2,
        logical_probes_attempted: 2,
        logical_probes_sent: 2,
        physical_datagrams_sent: 2,
        physical_bytes_sent: 160,
        unique_target_endpoints: 1,
        first_send_at_ms: Some(sent_at),
        last_send_at_ms: Some(sent_at),
        per_socket_sent: vec![(4_096, 2)],
        targets_assigned: 2,
        targets_examined: 2,
        targets_attempted: 2,
        target_processing_completed: true,
        ..Default::default()
    }
}

fn failure_class_partial_ledger() -> PunchSendReport {
    let mut report = failure_class_complete_ledger();
    report.packets_sent = 1;
    report.logical_probes_attempted = 1;
    report.logical_probes_sent = 1;
    report.physical_datagrams_sent = 1;
    report.physical_bytes_sent = 80;
    report.per_socket_sent = vec![(4_096, 1)];
    report.targets_examined = 1;
    report.targets_attempted = 1;
    report.target_processing_completed = false;
    report
}

fn assert_failure_class_report_evidence(
    source: &PunchSendReport,
    report: &crate::peer::HardHardAttemptReport,
    planned: usize,
    reason: &str,
    birthday: bool,
) {
    assert_eq!(
        report.schema_version,
        crate::peer::HARD_HARD_ATTEMPT_REPORT_SCHEMA_VERSION
    );
    assert_eq!(report.counts.planned_logical_probes, planned as u32);
    assert_eq!(
        report.counts.logical_probes_attempted,
        source.logical_probes_attempted
    );
    assert_eq!(
        report.counts.logical_probes_sent,
        source.logical_probes_sent
    );
    assert_eq!(
        report.counts.send_success_datagrams,
        source.physical_datagrams_sent
    );
    assert_eq!(report.counts.send_success_bytes, source.physical_bytes_sent);
    assert_eq!(report.counts.send_errors, source.physical_send_errors);
    assert_eq!(
        report.counts.send_error_bytes,
        source.physical_send_error_bytes
    );
    assert_eq!(report.counts.budget_skipped, source.budget_skipped);
    assert_eq!(
        report.counts.planned_logical_probes_not_attempted,
        (planned as u32).saturating_sub(source.logical_probes_attempted)
    );
    assert_eq!(report.terminal_reason, reason);
    assert_eq!(
        report.mode,
        if birthday { "birthday" } else { "predictable" }
    );
    assert_eq!(
        report.timeline.actual_first_send_at_ms.is_some(),
        source.first_send_at_ms.is_some()
    );
    if birthday {
        let detail = report
            .birthday_sweep
            .as_ref()
            .expect("birthday detail remains present");
        assert_eq!(
            detail.physical_datagrams_sent,
            source.physical_datagrams_sent as usize
        );
        assert_eq!(
            detail.physical_send_errors,
            source.physical_send_errors as usize
        );
        assert_eq!(
            detail.partial_physical_send_errors,
            source.partial_physical_send_errors as usize
        );
        assert_eq!(detail.physical_bytes_sent, source.physical_bytes_sent);
        assert_eq!(detail.probe_path_errors, source.probe_path_errors);
        assert_eq!(detail.first_send_at_ms, source.first_send_at_ms);
        assert_eq!(detail.last_send_at_ms, source.last_send_at_ms);
        assert_eq!(detail.per_socket_sent, source.per_socket_sent);
        assert_eq!(
            detail.target_processing_completed,
            source.target_processing_completed
        );
        assert_eq!(
            detail.failure_kind,
            source
                .failure_kind
                .map(|kind| kind.stop_reason().to_string())
        );
    } else {
        assert!(report.birthday_sweep.is_none());
    }
}

fn failure_class_with_birthday_detail(
    mut report: PunchSendReport,
    planned: usize,
) -> PunchSendReport {
    let completed_waves = report.logical_probes_sent as usize;
    report.birthday = Some(BirthdaySweepReport {
        effective_target_count: 1,
        requested_socket_count: 1,
        attached_socket_count: 1,
        usable_socket_count: 1,
        socket_count: 1,
        waves_planned: planned,
        waves_started: report.logical_probes_attempted as usize,
        waves_fully_completed: completed_waves,
        waves_completed: completed_waves,
        packets_planned: planned,
        targets_assigned: report.targets_assigned as usize,
        targets_examined: report.targets_examined as usize,
        targets_attempted: report.targets_attempted as usize,
        logical_probes_attempted: report.logical_probes_attempted as usize,
        logical_probes_sent: report.logical_probes_sent as usize,
        logical_probe_send_failures: report.logical_probe_send_failures as usize,
        physical_datagrams_sent: report.physical_datagrams_sent as usize,
        physical_send_errors: report.physical_send_errors as usize,
        partial_physical_send_errors: report.partial_physical_send_errors as usize,
        targets_budget_skipped: report.budget_skipped as usize,
        targets_cancelled: report.targets_cancelled as usize,
        ..Default::default()
    });
    report
}

fn assert_failure_case(
    fixture: &FailureClassBuilderFixture,
    send: PunchSendReport,
    received: UdpProbeRxSnapshot,
    planned: usize,
    reason: &str,
    expected: &str,
    case: &str,
) {
    // Every incomplete/error/RX example must stay rejected by the existing
    // learning predicate independently of its new diagnostic label. This is
    // not a claim that a synthetic report exercises the outer receipt gates.
    assert!(
        !hard_hard_complete_unanswered_exploration(&send, planned, received),
        "{case}"
    );
    for birthday in [false, true] {
        let send = if birthday {
            failure_class_with_birthday_detail(send.clone(), planned)
        } else {
            send.clone()
        };
        let report = fixture.build(&send, planned, received, false, reason, birthday);
        assert_failure_class_report_evidence(&send, &report, planned, reason, birthday);
        assert!(!report.direct_confirmed, "{case}");
        assert_eq!(
            report.failure_class, expected,
            "case={case} birthday={birthday}"
        );
    }
}

#[tokio::test]
async fn hard_hard_failure_class_complete_exploration_control() {
    let fixture = FailureClassBuilderFixture::new().await;
    let complete = failure_class_complete_ledger();
    assert!(hard_hard_complete_unanswered_exploration(
        &complete,
        2,
        Default::default()
    ));
    for birthday in [false, true] {
        let send = if birthday {
            failure_class_with_birthday_detail(complete.clone(), 2)
        } else {
            complete.clone()
        };
        let report = fixture.build(
            &send,
            2,
            Default::default(),
            false,
            "no_authenticated_direct_confirmation",
            birthday,
        );
        assert_failure_class_report_evidence(
            &send,
            &report,
            2,
            "no_authenticated_direct_confirmation",
            birthday,
        );
        assert_eq!(report.failure_class, "no_response");

        // The builder's confirmation input stays the highest-priority
        // observation; this fixture does not establish a real Direct commit.
        let mut failed = send.clone();
        failed.failure_kind = Some(BirthdaySweepFailureKind::SocketRevoked);
        failed.probe_path_errors = 1;
        failed.physical_send_errors = 1;
        failed.physical_send_error_bytes = 80;
        failed.budget_skipped = 1;
        failed.pacing_deadline_reached = true;
        if birthday {
            failed = failure_class_with_birthday_detail(failed, 2);
        }
        let confirmed = fixture.build(
            &failed,
            2,
            Default::default(),
            true,
            "direct_confirmed",
            birthday,
        );
        assert_eq!(confirmed.failure_class, "encrypted_validation_completed");
        assert!(confirmed.direct_confirmed);
        assert_eq!(confirmed.counts.send_success_datagrams, 2);
        assert_eq!(confirmed.counts.send_errors, 1);
        assert_eq!(confirmed.counts.budget_skipped, 1);
        assert_failure_class_report_evidence(&failed, &confirmed, 2, "direct_confirmed", birthday);
    }
    fixture.close().await;
}

#[tokio::test]
async fn hard_hard_partial_budget_failure_class_keeps_handoff_costs() {
    let fixture = FailureClassBuilderFixture::new().await;
    let mut partial = failure_class_partial_ledger();
    partial.budget_skipped = 1;
    let epoch = crate::udp::hard_hard_report_with_epoch_credit_stop_for_test(partial.clone());
    let reserve =
        crate::udp::hard_hard_report_with_confirmation_reserve_stop_for_test(partial.clone());
    let mut iteration = failure_class_partial_ledger();
    iteration.candidate_iteration_capped = true;
    for (case, send) in [
        ("partial epoch credit", epoch),
        ("partial confirmation reserve", reserve),
        ("partial rolling admission", partial),
        ("partial candidate iteration cap", iteration),
    ] {
        assert_failure_case(
            &fixture,
            send,
            Default::default(),
            2,
            "no_authenticated_direct_confirmation",
            "budget_rejected",
            case,
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn hard_hard_partial_physical_error_failure_class_keeps_success() {
    let fixture = FailureClassBuilderFixture::new().await;
    let mut compatibility = failure_class_complete_ledger();
    compatibility.physical_send_errors = 1;
    compatibility.physical_send_error_bytes = 80;
    compatibility.partial_physical_send_errors = 1;
    assert_failure_case(
        &fixture,
        compatibility,
        Default::default(),
        2,
        "no_authenticated_direct_confirmation",
        "send_error",
        "primary success with compatibility syscall failure",
    );
    let mut later_success = failure_class_complete_ledger();
    later_success.logical_probes_sent = 1;
    later_success.packets_sent = 1;
    later_success.physical_datagrams_sent = 1;
    later_success.physical_bytes_sent = 80;
    later_success.per_socket_sent = vec![(4_096, 1)];
    later_success.physical_send_errors = 1;
    later_success.physical_send_error_bytes = 80;
    later_success.logical_probe_send_failures = 1;
    assert_failure_case(
        &fixture,
        later_success,
        Default::default(),
        2,
        "no_authenticated_direct_confirmation",
        "send_error",
        "failed target followed by successful target",
    );
    fixture.close().await;
}

#[tokio::test]
async fn hard_hard_path_failure_and_pacing_deadline_are_not_no_response() {
    let fixture = FailureClassBuilderFixture::new().await;
    for kind in [
        BirthdaySweepFailureKind::ProbeRegistrationFailed,
        BirthdaySweepFailureKind::ProbeEncodingFailed,
        BirthdaySweepFailureKind::PreHandoffTimeout,
        BirthdaySweepFailureKind::SocketUnavailable,
        BirthdaySweepFailureKind::WorkerJoin,
    ] {
        for sent_before_failure in [true, false] {
            let mut send = if sent_before_failure {
                failure_class_partial_ledger()
            } else {
                PunchSendReport {
                    logical_probes_attempted: 1,
                    targets_assigned: 1,
                    targets_examined: 1,
                    target_processing_completed: false,
                    ..Default::default()
                }
            };
            send.failure_kind = Some(kind);
            send.probe_path_errors = 1;
            send.worker_failed = kind == BirthdaySweepFailureKind::WorkerJoin;
            assert_eq!(send.physical_send_errors, 0);
            assert_failure_case(
                &fixture,
                send,
                Default::default(),
                2,
                kind.stop_reason(),
                "execution_incomplete",
                "typed path failure without a physical syscall failure",
            );
        }
    }
    for retry_skip in [0, 1] {
        let mut send = failure_class_partial_ledger();
        send.pacing_deadline_reached = true;
        send.budget_skipped = retry_skip;
        assert_failure_case(
            &fixture,
            send,
            Default::default(),
            2,
            "deadline",
            "execution_incomplete",
            "post-send pacing deadline with optional retry skip",
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn hard_hard_stale_recovery_identity_is_lifecycle_failure_before_or_after_send() {
    let fixture = FailureClassBuilderFixture::new().await;
    for sent_before_stale in [true, false] {
        let mut send = if sent_before_stale {
            failure_class_partial_ledger()
        } else {
            PunchSendReport::default()
        };
        send.budget_skipped = 1;
        send.target_processing_completed = false;
        let stale = crate::udp::hard_hard_report_with_stale_recovery_stop_for_test(send);
        assert_failure_case(
            &fixture,
            stale,
            Default::default(),
            2,
            "no_authenticated_direct_confirmation",
            "cancelled_generation_changed",
            "typed recovery allocation identity expired",
        );
    }
    for kind in [
        BirthdaySweepFailureKind::NetworkGenerationChanged,
        BirthdaySweepFailureKind::CandidateEpochChanged,
        BirthdaySweepFailureKind::ProfileGenerationChanged,
        BirthdaySweepFailureKind::PeerSessionChanged,
        BirthdaySweepFailureKind::SessionRetired,
        BirthdaySweepFailureKind::SocketRevoked,
    ] {
        let mut send = failure_class_partial_ledger();
        send.failure_kind = Some(kind);
        send.probe_path_errors = 1;
        assert_failure_case(
            &fixture,
            send,
            Default::default(),
            2,
            "deadline",
            "cancelled_generation_changed",
            "typed lifecycle invalidation has precedence over an outer deadline",
        );
    }
    fixture.close().await;
}

#[tokio::test]
async fn hard_hard_no_response_requires_full_planned_execution() {
    let fixture = FailureClassBuilderFixture::new().await;
    // Even an otherwise clean completed worker does not prove that the full
    // plan was executed. The builder already owns this planned denominator.
    let mut deficient = failure_class_partial_ledger();
    deficient.target_processing_completed = true;
    assert_failure_case(
        &fixture,
        deficient,
        Default::default(),
        2,
        "no_authenticated_direct_confirmation",
        "execution_incomplete",
        "logical send deficit against the actual plan",
    );
    let mut cancelled = failure_class_complete_ledger();
    cancelled.targets_cancelled = 1;
    cancelled.target_processing_completed = false;
    assert_failure_case(
        &fixture,
        cancelled,
        Default::default(),
        2,
        "no_authenticated_direct_confirmation",
        "execution_incomplete",
        "task returned with cancelled targets",
    );
    assert_failure_case(
        &fixture,
        failure_class_complete_ledger(),
        UdpProbeRxSnapshot {
            authenticated_probe_acks_observed: 1,
            authenticated_probe_acks_unmatched: 1,
            ..Default::default()
        },
        2,
        "no_authenticated_direct_confirmation",
        "unknown",
        "only unmatched authenticated ACK observed",
    );
    for received in [
        UdpProbeRxSnapshot {
            authenticated_probe_packets_received: 1,
            ..Default::default()
        },
        UdpProbeRxSnapshot {
            probe_acks_received: 1,
            ..Default::default()
        },
    ] {
        let mut skipped = PunchSendReport {
            budget_skipped: 1,
            ..Default::default()
        };
        skipped.target_processing_completed = false;
        assert_failure_case(
            &fixture,
            skipped,
            received,
            2,
            "no_authenticated_direct_confirmation",
            "probe_hit_validation_failed",
            "exact probe evidence with zero local handoff and admission skips",
        );
        let mut physical = failure_class_complete_ledger();
        physical.physical_send_errors = 1;
        physical.physical_send_error_bytes = 80;
        physical.partial_physical_send_errors = 1;
        assert_failure_case(
            &fixture,
            physical,
            received,
            2,
            "no_authenticated_direct_confirmation",
            "probe_hit_validation_failed",
            "authenticated hit has priority over a degraded local send",
        );
    }
    fixture.close().await;
}
