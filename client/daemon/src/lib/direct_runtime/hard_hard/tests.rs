#[cfg(test)]
mod hard_hard_tests {
    use super::*;
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;

    #[test]
    fn hard_hard_payload_expiry_is_reported_as_stale_not_unpredictable() {
        let public_ip = "198.51.100.10".parse().unwrap();
        let mut result = FreshMappingResult {
            punch_generation: 7,
            network_generation: 3,
            socket_local_endpoint: "0.0.0.0:45000".parse().unwrap(),
            socket_index: 4096,
            model: p2pnet_nat::build_model(&[40000, 40001, 40002], Some(public_ip), 100),
            predicted_ports: vec![40003, 40004, 40005],
            public_ip: Some(public_ip),
            first_punch_sent_at_ms: 0,
            last_punch_sent_at_ms: 0,
            measurement: crate::udp::HardHardMeasurementStats::default(),
        };
        let expires_at = 100 + crate::udp::FRESH_MAPPING_MODEL_MAX_AGE.as_millis() as u64;
        assert!(hard_hard_prediction_payload_at(&result, 10, expires_at).is_ok());
        let rejection = hard_hard_prediction_payload_at(&result, 10, expires_at + 1).unwrap_err();
        assert_eq!(rejection, HardHardPayloadRejection::BatchStale);
        assert_eq!(rejection.failure_class(), "measurement_insufficient");
        assert_eq!(
            rejection.reason(),
            FreshMappingRejection::BatchStale.label()
        );
        result.predicted_ports.clear();
        assert_eq!(
            hard_hard_prediction_payload_at(&result, 10, 101).unwrap_err(),
            HardHardPayloadRejection::EmptyPredictionWindow,
        );
        result.predicted_ports.push(40003);
        result.public_ip = None;
        assert_eq!(
            hard_hard_prediction_payload_at(&result, 10, 101).unwrap_err(),
            HardHardPayloadRejection::InvalidPublicIp,
        );
    }

    #[test]
    fn hard_hard_signal_delay_requires_the_explicit_experiment_lane() {
        assert_eq!(hard_hard_experiment_signal_delay_ms(false, Some("1200")), 0);
        assert_eq!(
            hard_hard_experiment_signal_delay_ms(true, Some("1200")),
            1200
        );
        assert_eq!(hard_hard_experiment_signal_delay_ms(true, Some("2001")), 0);
        assert_eq!(hard_hard_experiment_signal_delay_ms(true, Some("bad")), 0);
    }

    #[test]
    fn hard_hard_a0_stage_tags_are_shared_only_after_session_identity_exists() {
        let (session, plan, scope) = hard_hard_a0_stage_tags(None);
        assert_eq!(session, "none");
        assert_eq!(plan, "none");
        assert_eq!(scope, "local_pre_session");

        let raw_token = "hh1-raw-control-correlation-token";
        let (session, plan, scope) = hard_hard_a0_stage_tags(Some(raw_token));
        assert_eq!(scope, "shared_session");
        assert!(session.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(plan.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(session.len(), 16);
        assert_eq!(plan.len(), 16);
        assert_ne!(session, plan);
        assert!(!session.contains(raw_token));
        assert!(!plan.contains(raw_token));
        assert_eq!(
            HardHardA0Stage::ReciprocalResponseAdmission.label(),
            "reciprocal_response_admission"
        );
        assert_eq!(
            HardHardA0Reason::DeadlineExpired.label(),
            "deadline_expired"
        );
    }

    #[test]
    fn birthday_level_caps_android_without_downgrading_desktop() {
        use crate::peer::RecoveryStage;

        assert_eq!(
            hard_hard_birthday_level_for_stage(false, RecoveryStage::Initial),
            64
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(false, RecoveryStage::ScatterExtended),
            256
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::Initial),
            64
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::Predicted),
            128
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::ScatterExtended),
            128
        );
        assert_eq!(
            hard_hard_birthday_level_for_stage(true, RecoveryStage::RelayBackoff),
            128
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn birthday_runtime_level_cap_tracks_platform_and_recovery_stage() {
        use crate::peer::RecoveryStage;

        for (platform, expected_level) in [("android", 128), ("linux", 256)] {
            let identity = NodeIdentity::generate();
            let mut config = Config::generate_default(
                "https://hard-hard-runtime-cap.test",
                &format!("hard-hard-runtime-cap-{platform}"),
            )
            .unwrap();
            config.node.node_id = format!("hard-hard-runtime-cap-{platform}");
            config.node.platform = platform.to_string();
            let peers = PeerManager::new(config);
            let peer_id = format!("peer-runtime-cap-{platform}");
            peers
                .add_peer(&crate::control::PeerInfo {
                    capabilities: crate::control::PeerCapabilities::default(),
                    registration_seq: 0,
                    node_id: peer_id.clone(),
                    device_name: "runtime-cap".to_string(),
                    app_version: "test".to_string(),
                    public_key: hex::encode(identity.public_key()),
                    endpoint: "198.51.100.20:41000".to_string(),
                    nat_type:
                        "p2v2:m=address_or_port_dependent;a=random;d=?;c=90;f=address_or_port_dependent;h=unknown;g=1"
                            .to_string(),
                    virtual_ip: "10.20.0.20".to_string(),
                    online: true,
                    last_seen: 1,
                    relay_rtt_ms: None,
                })
                .await;
            assert!(matches!(
                peers.recovery_epoch_admit(&peer_id).await,
                crate::peer::RecoveryAdmission::Accepted { .. }
            ));
            for _ in 0..3 {
                peers
                    .advance_recovery_stage_after_no_ack(&peer_id, "runtime cap test")
                    .await;
            }
            assert_eq!(
                peers.recovery_stage_for(&peer_id).await,
                RecoveryStage::ScatterExtended
            );
            assert_eq!(
                hard_hard_birthday_level(&peers, &peer_id).await,
                expected_level
            );
        }
    }

    #[test]
    fn initiator_response_match_keeps_raw_birthday_level_after_candidate_cap() {
        let endpoint = "198.51.100.20:41000".parse().unwrap();
        let identity = crate::peer::HardHardFreshSocketIdentity {
            peer_id: "peer-raw-level".to_string(),
            session_token: "raw-level-token".to_string(),
            network_generation: 3,
            remote_candidate_epoch: 5,
            local_profile_generation: 7,
            remote_profile_generation: 11,
            punch_generation: 13,
            socket_index: 4_096,
            socket_local_endpoint: endpoint,
        };
        let expected = HardHardSessionRecord {
            pair_nomination: None,
            coordinated_plan: None,
            session_id: "hh1:i:raw-level-token:3:5:7:11:90:0:0".to_string(),
            probe_session_id: None,
            session_token: identity.session_token.clone(),
            peer_id: identity.peer_id.clone(),
            initiator: true,
            remote_network_generation: 0,
            local_network_generation: identity.network_generation,
            remote_candidate_epoch: identity.remote_candidate_epoch,
            local_profile_generation: identity.local_profile_generation,
            remote_profile_generation: identity.remote_profile_generation,
            local_prediction_confidence: 90,
            remote_prediction_confidence: 0,
            requested_birthday_level: 128,
            generated_candidate_count: 128,
            signaled_candidate_count: 96,
            birthday: true,
            requested_socket_indices: vec![4_096, 4_097, 4_098, 4_099],
            requested_socket_count: 4,
            prediction_window: vec![endpoint; 96],
            remote_prediction: Vec::new(),
            fresh_socket: identity.clone(),
            punch_at_ms: hard_hard_now_ms().saturating_add(5_000),
            expires_at_ms: hard_hard_now_ms().saturating_add(30_000),
            state: HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            measurement: crate::peer::HardHardMeasurementObservation::default(),
            created_at: Instant::now(),
            cancellation: Arc::new(crate::PunchSessionCancellation::default()),
        };
        assert!(hard_hard_initiator_response_record_matches(
            &expected, &expected
        ));

        let mut capped_level = expected.clone();
        capped_level.requested_birthday_level = capped_level.signaled_candidate_count;
        assert!(!hard_hard_initiator_response_record_matches(
            &capped_level,
            &expected
        ));

        let mut replaced_socket = expected.clone();
        replaced_socket.requested_socket_indices = vec![4_096, 4_097, 4_098, 5_000];
        assert!(!hard_hard_initiator_response_record_matches(
            &replaced_socket,
            &expected
        ));
    }

    #[test]
    fn predictable_strategy_cap_preserves_forecast_inside_existing_maximum() {
        use p2pnet_nat::mapping::PortModelKind;

        let fixed = PortModelKind::FixedStep { step: 1 };
        assert_eq!(hard_hard_prediction_limit(&fixed, 90), 32);
        assert_eq!(hard_hard_prediction_limit(&fixed, 75), 32);
        assert_eq!(hard_hard_prediction_limit(&fixed, 74), 32);
        assert_eq!(
            hard_hard_prediction_limit(&PortModelKind::MonotonicWindow { direction: 1 }, 99),
            32
        );
    }

    #[test]
    fn reciprocal_deadline_allows_only_bounded_server_clock_normalization_jitter() {
        let expected = 1_700_000_003_500;
        assert!(hard_hard_response_deadline_matches(expected, expected));
        assert!(hard_hard_response_deadline_matches(expected, expected + 2));
        assert!(hard_hard_response_deadline_matches(
            expected,
            expected - HARD_HARD_RESPONSE_DEADLINE_TOLERANCE.as_millis() as u64
        ));
        assert!(!hard_hard_response_deadline_matches(
            expected,
            expected + HARD_HARD_RESPONSE_DEADLINE_TOLERANCE.as_millis() as u64 + 1
        ));
    }

    #[tokio::test]
    async fn birthday_terminal_report_preserves_partial_logical_and_physical_progress() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                requested_level: 256,
                generated_candidate_count: 256,
                signaled_candidate_count: 96,
                effective_target_count: 96,
                requested_socket_count: 8,
                attached_socket_count: 8,
                usable_socket_count: 8,
                socket_count: 8,
                waves_planned: 2,
                waves_started: 1,
                waves_fully_completed: 0,
                waves_completed: 0,
                targets_assigned: 96,
                ..BirthdaySweepReport::default()
            },
            aggregate: PunchSendReport {
                packets_sent: 2,
                per_socket_sent: vec![(4_096, 3)],
                sent_target_endpoints: vec![endpoint_for_test(41000), endpoint_for_test(41001)],
                targets_assigned: 96,
                targets_attempted: 2,
                targets_cancelled: 94,
                ..PunchSendReport::default()
            },
            ..BirthdaySweepProgress::default()
        }));

        let report = hard_hard_terminal_report(&Some(progress), "worker_failed", true)
            .await
            .expect("birthday progress must yield a terminal partial report");
        let birthday = report
            .birthday
            .as_ref()
            .expect("terminal report must retain Birthday details");
        assert_eq!(birthday.requested_level, 256);
        assert_eq!(birthday.signaled_candidate_count, 96);
        assert_eq!(birthday.waves_fully_completed, 0);
        assert_eq!(birthday.waves_completed, 0);
        assert_eq!(birthday.logical_probes_sent, 2);
        assert_eq!(birthday.physical_datagrams_sent, 3);
        assert_eq!(birthday.targets_cancelled, 94);
        assert_eq!(birthday.stop_reason.as_deref(), Some("worker_failed"));
    }

    #[tokio::test]
    async fn birthday_terminal_report_reads_in_flight_live_counters() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                targets_assigned: 4,
                waves_planned: 2,
                waves_started: 1,
                ..BirthdaySweepReport::default()
            },
            ..BirthdaySweepProgress::default()
        }));
        {
            let live = {
                let current = progress.lock().await;
                current.live.clone()
            };
            let mut progress = live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            progress.counters.targets_assigned = 4;
            progress.counters.targets_examined = 3;
            progress.counters.targets_attempted = 1;
            progress.counters.targets_cancelled = 3;
            progress.counters.budget_skipped = 1;
            progress.counters.logical_probes_attempted = 1;
            progress.counters.logical_probes_sent = 1;
            progress.counters.physical_datagrams_sent = 2;
            progress.counters.physical_send_errors = 1;
            progress
                .sent_target_endpoints
                .insert(endpoint_for_test(41000));
            progress.per_socket_sent.insert(4_096, 2);
            progress.first_send_at_ms = Some(100);
            progress.last_send_at_ms = Some(110);
        }

        let report = hard_hard_terminal_report(&Some(progress), "deadline", true)
            .await
            .expect("live birthday progress must produce a terminal report");
        let birthday = report.birthday.as_ref().unwrap();
        assert_eq!(report.targets_assigned, 4);
        assert_eq!(report.targets_examined, 3);
        assert_eq!(report.targets_attempted, 1);
        assert_eq!(report.logical_probes_attempted, 1);
        assert_eq!(report.logical_probes_sent, 1);
        assert_eq!(report.physical_datagrams_sent, 2);
        assert_eq!(report.physical_send_errors, 1);
        assert_eq!(report.unique_target_endpoints, 1);
        assert_eq!(report.per_socket_sent, vec![(4_096, 2)]);
        assert_eq!(report.first_send_at_ms, Some(100));
        assert_eq!(report.last_send_at_ms, Some(110));
        assert_eq!(birthday.targets_examined, 3);
        assert_eq!(birthday.logical_probes_attempted, 1);
        assert_eq!(birthday.physical_send_errors, 1);
        assert_eq!(birthday.targets_cancelled, 3);
        assert_eq!(birthday.stop_reason.as_deref(), Some("deadline"));
        assert!(report.logical_probes_sent <= report.logical_probes_attempted);
        assert!(report.physical_datagrams_sent >= report.logical_probes_sent);
        assert!(report.targets_attempted <= report.targets_examined);
        assert!(report.targets_examined <= report.targets_assigned);
    }

    #[tokio::test]
    async fn predictable_terminal_report_without_handoff_preserves_errors_and_budget() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress::default()));
        let live = progress.lock().await.live.clone();
        {
            let mut live = live.lock().unwrap();
            live.counters.targets_assigned = 2;
            live.counters.targets_attempted = 1;
            live.counters.logical_probes_attempted = 1;
            live.counters.logical_probe_send_failures = 1;
            live.counters.physical_send_errors = 1;
            live.counters.physical_send_error_bytes = 96;
            live.counters.budget_skipped = 1;
        }
        let report = hard_hard_terminal_report(&Some(progress), "deadline", false)
            .await
            .unwrap();
        assert!(report.birthday.is_none());
        assert_eq!(report.physical_datagrams_sent, 0);
        assert_eq!(report.physical_bytes_sent, 0);
        assert_eq!(report.logical_probes_sent, 0);
        assert_eq!(report.logical_probes_attempted, 1);
        assert_eq!(report.physical_send_errors, 1);
        assert_eq!(report.physical_send_error_bytes, 96);
        assert_eq!(report.logical_probe_send_failures, 1);
        assert_eq!(report.budget_skipped, 1);
        assert_eq!(report.targets_cancelled, 1);
        assert!(!report.target_processing_completed);
        assert!(report.first_send_at_ms.is_none());
        assert!(report.last_send_at_ms.is_none());
        assert!(report.per_socket_sent.is_empty());
        assert!(report.sent_target_endpoints.is_empty());
    }

    #[tokio::test]
    async fn birthday_terminal_report_preserves_scheduler_failure_reason() {
        let progress = Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                stop_reason: Some("worker_failed".to_string()),
                ..BirthdaySweepReport::default()
            },
            aggregate: PunchSendReport {
                failure_kind: Some(BirthdaySweepFailureKind::WorkerJoin),
                worker_failed: true,
                ..PunchSendReport::default()
            },
            ..BirthdaySweepProgress::default()
        }));

        let report = hard_hard_terminal_report(&Some(progress), "send_error", true)
            .await
            .expect("scheduler failure must remain observable");
        assert_eq!(
            report.birthday.unwrap().stop_reason.as_deref(),
            Some("worker_failed")
        );
    }

    #[test]
    fn direct_confirmation_grace_is_bounded_after_busy_executor_regression() {
        // The earlier one-second grace was insufficient in the full reciprocal
        // birthday suite when validation and durable event work shared a busy
        // executor. Keep the evidence-backed two-second lease, but retain the
        // explicit outer 250ms bound so this is not an unbounded wait.
        assert_eq!(HARD_HARD_DIRECT_CONFIRMATION_GRACE, Duration::from_secs(2));
        assert!(
            HARD_HARD_DIRECT_CONFIRMATION_GRACE + Duration::from_millis(250)
                <= HARD_HARD_SWEEP_DEADLINE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn direct_confirmation_grace_accepts_an_exact_commit_after_one_second() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let deduplicator = PunchAttemptDeduplicator::default();
        let session = deduplicator
            .claim("peer-exact-proof")
            .await
            .expect("test must own the confirmation session");
        let wait = tokio::spawn({
            let peers = peers.clone();
            let udp = udp.clone();
            let identity = identity.clone();
            async move {
                hard_hard_wait_for_exact_direct_confirmation(
                    &udp, &peers, &session, &identity, None,
                )
                .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!wait.is_finished(), "confirmation must still be pending");

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !wait.is_finished(),
            "one second must not exhaust the two-second confirmation grace"
        );

        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );
        assert!(wait.await.unwrap());
        udp.detach_all_dynamic_punch_sockets("test_confirmation_grace")
            .await;
    }

    #[tokio::test]
    async fn direct_confirmation_start_does_not_wait_for_connection_writer() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let session = PunchAttemptDeduplicator::default()
            .claim("peer-exact-proof")
            .await
            .expect("test must own the confirmation session");
        let before_commit = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );

        let connection_writer = peers.hold_connections_writer_for_test().await;
        let confirmed = tokio::time::timeout(
            Duration::from_millis(100),
            hard_hard_wait_for_exact_direct_confirmation(
                &udp,
                &peers,
                &session,
                &identity,
                before_commit,
            ),
        )
        .await
        .expect("confirmation must not await the connection writer");
        assert!(confirmed);
        drop(connection_writer);

        peers
            .record_direct_event(
                &identity.peer_id,
                "hard_hard_failed",
                Some(remote),
                Some(1),
                Some(1),
                "lock contention terminal event",
            )
            .await;
        assert!(peers
            .diagnostics()
            .await
            .into_iter()
            .flat_map(|peer| peer.direct_events)
            .any(|event| event.stage == "hard_hard_failed"));
        udp.detach_all_dynamic_punch_sockets("test_confirmation_writer")
            .await;
    }

    #[tokio::test]
    async fn exact_direct_commit_wins_the_expected_owner_cancellation_race() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let session = PunchAttemptDeduplicator::default()
            .claim("peer-exact-proof")
            .await
            .expect("test must own the confirmation session");
        let before_commit = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );
        session.cancellation_handle().cancel_for_hard_hard_cleanup();

        assert!(
            hard_hard_wait_for_exact_direct_confirmation(
                &udp,
                &peers,
                &session,
                &identity,
                before_commit,
            )
            .await,
            "the exact encrypted Direct commit must be observed before its expected recovery-owner cancellation"
        );
        udp.detach_all_dynamic_punch_sockets("test_confirmation_cancel_race")
            .await;
    }

    #[tokio::test]
    async fn exact_probe_session_diagnostics_survive_connection_writer_contention() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        udp.update_peer_probe_rx_diagnostics(
            &identity.peer_id,
            identity.network_generation,
            Some("probe-session-exact"),
            |snapshot| {
                snapshot.authenticated_probe_acks_observed = 3;
                snapshot.probe_acks_received = 2;
            },
        )
        .await;

        let connection_writer = peers.hold_connections_writer_for_test().await;
        let snapshot = tokio::time::timeout(
            Duration::from_millis(100),
            udp.probe_rx_snapshot_for_peer_session(
                &identity.peer_id,
                identity.network_generation,
                Some("probe-session-exact"),
            ),
        )
        .await
        .expect("exact session diagnostics must not consult connections");
        drop(connection_writer);
        assert_eq!(snapshot.authenticated_probe_acks_observed, 3);
        assert_eq!(snapshot.probe_acks_received, 2);
        udp.detach_all_dynamic_punch_sockets("test_probe_session_lock")
            .await;
    }

    fn birthday_runtime_nat_profile() -> p2pnet_nat::NatProfile {
        p2pnet_nat::NatProfile {
            local_addr: "127.0.0.1:0".to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: Some("198.51.100.10:40000".to_string()),
            public_ip_stable: Some(true),
            public_port_stable: Some(false),
            port_preserved: Some(false),
            port_delta: None,
            likely_symmetric: Some(true),
            mapping_behavior: p2pnet_nat::MappingBehavior::AddressOrPortDependent,
            filtering_behavior: p2pnet_nat::FilteringBehavior::AddressOrPortDependent,
            hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
            mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
            prediction_candidate: false,
            predicted_endpoints: Vec::new(),
            birthday_candidate: true,
            confidence: 70,
        }
    }

    async fn exact_birthday_runtime_fixture() -> (
        Arc<PeerManager>,
        UdpTransport,
        crate::peer::HardHardFreshSocketIdentity,
        SocketAddr,
        crate::peer::PeerSessionGeneration,
    ) {
        // The socket and session must receive their final token at first
        // installation; an existing proof socket cannot be retagged.
        let (peers, udp, identity, remote) = exact_socket_fixture(None, true).await;
        let peer_session_generation = peers
            .peer_session_generation_sync(&identity.peer_id)
            .expect("exact fixture peer must have an active lifecycle generation");
        (peers, udp, identity, remote, peer_session_generation)
    }

    #[tokio::test]
    async fn hard_hard_winner_promotion_releases_epoch_despite_contended_diagnostics() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        udp.clear_authenticated_evidence_for_test(identity.socket_index)
            .await;
        assert!(
            !udp.hard_hard_socket_identity_has_authenticated_evidence(&identity)
                .await
        );

        let sweeping = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture session must enter its single sweep");
        assert_eq!(sweeping.fresh_socket, identity);

        // Promotion runs under the same epoch held by the receive path before
        // its ACK. A contended diagnostic ring must not keep that transaction
        // alive after winner/socket evidence is committed.
        let connections_writer = peers.hold_connections_writer_for_test().await;
        let socket_index = identity.socket_index;
        let network_generation = identity.network_generation;
        let promotion = tokio::spawn({
            let udp = udp.clone();
            let peer_id = identity.peer_id.clone();
            let token = identity.session_token.clone();
            async move {
                udp.promote_hard_hard_winner_for_test(
                    &peer_id,
                    &token,
                    socket_index,
                    network_generation,
                )
                .await
            }
        });
        assert!(tokio::time::timeout(Duration::from_millis(100), promotion)
            .await
            .expect("promotion must return while the diagnostic writer remains held")
            .expect("promotion task must not panic"));
        let epoch_gate = peers.network_epoch_gate();
        assert!(
            epoch_gate.try_lock().is_ok(),
            "winner diagnostics must release the epoch needed by ACK and cleanup"
        );
        assert!(
            udp.hard_hard_socket_identity_has_authenticated_evidence(&identity)
                .await
        );
        assert_eq!(
            peers
                .hard_hard_winner_for_token(&identity.peer_id, &identity.session_token)
                .await,
            Some(identity.socket_index)
        );
        drop(connections_writer);
        assert_eq!(
            hard_hard_authenticated_winner_for_cleanup(
                &udp,
                &peers,
                &identity.peer_id,
                &identity.session_token,
            )
            .await,
            Some(identity.clone()),
            "cleanup retention requires the same transaction's authenticated socket evidence"
        );

        assert!(
            peers
                .hard_hard_retire_session(
                    &identity.peer_id,
                    &sweeping.session_id,
                    &identity.session_token,
                )
                .await
        );
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_winner_promotion_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
        )
        .await;
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &identity.peer_id,
                    &sweeping.session_id,
                    &identity.session_token,
                )
                .await
        );
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    #[tokio::test]
    async fn hard_hard_duplicate_registration_keeps_new_measurement_under_rollback_owner() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, _remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let original = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "birthday-runtime-session",
                &identity.session_token,
            )
            .await
            .expect("fixture must expose its authoritative session");
        let duplicate_cancellation = Arc::new(crate::PunchSessionCancellation::default());
        let mut duplicate = original.clone();
        duplicate.fresh_socket.socket_index = identity.socket_index.saturating_add(100);
        duplicate.fresh_socket.punch_generation = identity.punch_generation.saturating_add(1);
        duplicate.fresh_socket.socket_local_endpoint = "127.0.0.1:45000".parse().unwrap();
        duplicate.cancellation = duplicate_cancellation.clone();
        duplicate.created_at = Instant::now();

        {
            let _rollback_owner =
                PendingHardHardSessionCancellation::new(duplicate_cancellation.clone());
            assert!(
                !peers.hard_hard_register_session(duplicate).await,
                "an existing session must not transfer its cleanup ownership to a duplicate measurement"
            );
        }
        assert!(
            duplicate_cancellation.is_cancelled(),
            "the rejected duplicate measurement must keep its rollback cancellation armed"
        );
        let current = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                &original.session_id,
                &identity.session_token,
            )
            .await
            .expect("the original session must remain authoritative");
        assert_eq!(current.fresh_socket, original.fresh_socket);
        assert!(Arc::ptr_eq(&current.cancellation, &original.cancellation));
        assert!(!current.cancellation.is_cancelled());
        assert_eq!(udp.dynamic_socket_count().await, 1);

        assert!(
            peers
                .hard_hard_retire_session(
                    &identity.peer_id,
                    &original.session_id,
                    &identity.session_token,
                )
                .await
        );
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_duplicate_registration_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
        )
        .await;
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &identity.peer_id,
                    &original.session_id,
                    &identity.session_token,
                )
                .await
        );
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    #[tokio::test]
    async fn hard_hard_winner_promotion_cancellation_before_commit_leaves_no_half_winner() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        udp.clear_authenticated_evidence_for_test(identity.socket_index)
            .await;
        let sweeping = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture session must enter its single sweep");

        let winner_writer = peers.hold_hard_hard_winner_writer_for_test().await;
        let socket_index = identity.socket_index;
        let network_generation = identity.network_generation;
        let promotion = tokio::spawn({
            let udp = udp.clone();
            let peer_id = identity.peer_id.clone();
            let token = identity.session_token.clone();
            async move {
                udp.promote_hard_hard_winner_for_test(
                    &peer_id,
                    &token,
                    socket_index,
                    network_generation,
                )
                .await
            }
        });
        for _ in 0..256 {
            if udp.hard_hard_socket_state_is_locked_for_test() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            udp.hard_hard_socket_state_is_locked_for_test(),
            "promotion must own the exact socket transaction before cancellation"
        );
        promotion.abort();
        let cancelled = tokio::time::timeout(Duration::from_secs(1), promotion)
            .await
            .expect("aborted promotion must stop without waiting for the winner writer")
            .expect_err("promotion must be cancelled at the pre-commit lock wait");
        assert!(cancelled.is_cancelled());
        drop(winner_writer);

        assert_eq!(
            peers
                .hard_hard_winner_for_token(&identity.peer_id, &identity.session_token)
                .await,
            None,
            "pre-commit cancellation must not strand a manager-only winner"
        );
        assert!(
            !udp.hard_hard_socket_identity_has_authenticated_evidence(&identity)
                .await
        );
        assert_eq!(
            hard_hard_authenticated_winner_for_cleanup(
                &udp,
                &peers,
                &identity.peer_id,
                &identity.session_token,
            )
            .await,
            None,
            "an unauthenticated pre-commit socket must never be preserved"
        );

        assert!(
            peers
                .hard_hard_retire_session(
                    &identity.peer_id,
                    &sweeping.session_id,
                    &identity.session_token,
                )
                .await
        );
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_cancelled_winner_promotion_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
        )
        .await;
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &identity.peer_id,
                    &sweeping.session_id,
                    &identity.session_token,
                )
                .await
        );
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    struct HardHardTestClockReset;

    impl Drop for HardHardTestClockReset {
        fn drop(&mut self) {
            set_hard_hard_test_now_ms(None);
        }
    }

    async fn seed_hard_hard_pending_probes(
        udp: &UdpTransport,
        identity: &crate::peer::HardHardFreshSocketIdentity,
        count: usize,
    ) -> PunchSendReport {
        let localhost = "127.0.0.1".parse().unwrap();
        let candidates = (0..count)
            .map(|offset| SocketAddr::new(localhost, 41_000 + u16::try_from(offset).unwrap()))
            .collect::<Vec<_>>();
        udp.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
            &identity.peer_id,
            identity.socket_index,
            candidates,
            Duration::ZERO,
            1,
            None,
            Some(&identity.session_token),
        )
        .await
        .expect("test probe seeding must produce a report")
    }

    async fn wait_for_hard_hard_cleanup_owner(
        peers: &PeerManager,
        descriptor: &HardHardCleanupDescriptor,
    ) {
        for _ in 0..256 {
            if peers
                .hard_hard_cleanup_owner_claimed_for_test(
                    &descriptor.peer_id,
                    &descriptor.session_id,
                    &descriptor.session_token,
                )
                .await
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("Hard↔Hard cleanup watcher did not claim its exact owner");
    }

    async fn wait_for_hard_hard_cleanup_gate(gate: &Arc<crate::peer::HardHardCleanupGate>) {
        let reached = gate.wait_for_reached();
        tokio::pin!(reached);
        let watchdog = async {
            for _ in 0..512 {
                tokio::task::yield_now().await;
            }
        };
        tokio::pin!(watchdog);
        tokio::select! {
            _ = &mut reached => {}
            _ = &mut watchdog => panic!("Hard↔Hard cleanup did not reach the test gate"),
        }
    }

    async fn wait_for_hard_hard_cleanup_completion(completion: &HardHardCleanupCompletion) {
        let wait = completion.wait();
        tokio::pin!(wait);
        let watchdog = async {
            for _ in 0..64 {
                tokio::time::advance(Duration::from_millis(100)).await;
                tokio::task::yield_now().await;
            }
        };
        tokio::pin!(watchdog);
        tokio::select! {
            _ = &mut wait => {}
            _ = &mut watchdog => panic!("Hard↔Hard cleanup did not complete"),
        }
    }

    async fn exercise_hard_hard_cleanup_cancellation(cancel_before_watcher: bool) {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(Some(4_000_000_000));
        let _clock = HardHardTestClockReset;
        let (peers, udp, identity, _remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let record = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "birthday-runtime-session",
                &identity.session_token,
            )
            .await
            .expect("Birthday fixture must expose its exact session record");
        let descriptor = HardHardCleanupDescriptor::from_record(&record);
        assert!(matches!(
            peers.recovery_epoch_admit(&identity.peer_id).await,
            crate::peer::RecoveryAdmission::Accepted { .. }
        ));
        let report = seed_hard_hard_pending_probes(&udp, &identity, 5).await;
        assert_eq!(report.logical_probes_sent, 5, "{report:?}");
        assert_eq!(report.physical_datagrams_sent, 5, "{report:?}");
        assert_eq!(
            udp.hard_hard_pending_probe_count_for_token_for_test(
                &identity.peer_id,
                &identity.session_token,
            )
            .await,
            5
        );

        let (gate, _gate_guard) = peers.install_hard_hard_cleanup_gate_for_test(
            &descriptor.peer_id,
            &descriptor.session_id,
            &descriptor.session_token,
        );
        if cancel_before_watcher {
            assert!(
                !peers
                    .hard_hard_cleanup_owner_claimed_for_test(
                        &descriptor.peer_id,
                        &descriptor.session_id,
                        &descriptor.session_token,
                    )
                    .await
            );
            descriptor.cancellation.cancel_for_hard_hard_cleanup();
        }
        let completion =
            spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
        if !cancel_before_watcher {
            wait_for_hard_hard_cleanup_owner(&peers, &descriptor).await;
            assert_eq!(
                peers
                    .hard_hard_session_snapshot_for_cleanup(
                        &descriptor.peer_id,
                        &descriptor.session_id,
                        &descriptor.session_token,
                    )
                    .await
                    .expect("registered cleanup session must remain observable")
                    .state,
                HardHardSessionState::AwaitingPeer
            );
            descriptor.cancellation.cancel_for_hard_hard_cleanup();
        }

        wait_for_hard_hard_cleanup_gate(&gate).await;
        let retiring = peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
            .expect("retiring record must remain until UDP cleanup completes");
        assert_eq!(retiring.state, HardHardSessionState::Retiring);
        assert!(!peers.hard_hard_session_is_active(&descriptor.peer_id).await);
        assert_eq!(udp.dynamic_socket_count().await, 1);
        assert_eq!(
            udp.hard_hard_pending_probe_count_for_token_for_test(
                &descriptor.peer_id,
                &descriptor.session_token,
            )
            .await,
            5
        );
        assert!(!udp
            .hard_hard_socket_indices_for_token(&descriptor.peer_id, &descriptor.session_token)
            .await
            .is_empty());

        gate.release();
        wait_for_hard_hard_cleanup_completion(&completion).await;
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
            .is_none());
        assert!(
            !peers
                .hard_hard_cleanup_owner_claimed_for_test(
                    &descriptor.peer_id,
                    &descriptor.session_id,
                    &descriptor.session_token,
                )
                .await
        );
        assert_eq!(udp.dynamic_socket_count().await, 0);
        assert_eq!(
            udp.hard_hard_pending_probe_count_for_token_for_test(
                &descriptor.peer_id,
                &descriptor.session_token,
            )
            .await,
            0
        );
        assert!(udp
            .hard_hard_socket_indices_for_token(&descriptor.peer_id, &descriptor.session_token)
            .await
            .is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_cleanup_cancellation_before_watcher_registration_is_exact_and_complete() {
        exercise_hard_hard_cleanup_cancellation(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_cleanup_cancellation_after_watcher_registration_is_exact_and_complete() {
        exercise_hard_hard_cleanup_cancellation(false).await;
    }

    #[tokio::test]
    async fn hard_hard_session_observers_do_not_prune_expired_records_and_cleanup_is_idempotent() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(Some(4_000_000_000));
        let _clock = HardHardTestClockReset;
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        let record = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .expect("exact proof fixture must expose its session");
        let cancellation = record.cancellation.clone();
        assert!(peers.hard_hard_session_is_active(&identity.peer_id).await);
        assert!(peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .is_some());
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .is_some());
        assert!(!cancellation.is_cancelled());

        set_hard_hard_test_now_ms(Some(record.expires_at_ms.saturating_add(1)));
        assert!(!peers.hard_hard_session_is_active(&identity.peer_id).await);
        assert!(peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .is_none());
        let expired_snapshot = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .expect("pure snapshots must not remove expired records");
        assert_eq!(expired_snapshot.state, HardHardSessionState::AwaitingPeer);
        assert!(!cancellation.is_cancelled());

        assert!(
            peers
                .hard_hard_retire_session(
                    &identity.peer_id,
                    "proof-session",
                    &identity.session_token,
                )
                .await
        );
        assert!(
            peers
                .hard_hard_retire_session(
                    &identity.peer_id,
                    "proof-session",
                    &identity.session_token,
                )
                .await
        );
        assert!(!peers.hard_hard_session_is_active(&identity.peer_id).await);
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &identity.peer_id,
                    "proof-session",
                    &identity.session_token,
                )
                .await
        );
        assert!(
            !peers
                .hard_hard_complete_session_cleanup(
                    &identity.peer_id,
                    "proof-session",
                    &identity.session_token,
                )
                .await
        );
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "proof-session",
                &identity.session_token,
            )
            .await
            .is_none());
        udp.detach_all_dynamic_punch_sockets("test_cleanup_idempotence")
            .await;
    }

    #[tokio::test]
    async fn hard_hard_late_cleanup_cannot_remove_replacement_session() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, old_identity, _remote) = exact_socket_proof_fixture().await;
        let old = peers
            .hard_hard_session_snapshot_for_cleanup(
                &old_identity.peer_id,
                "proof-session",
                &old_identity.session_token,
            )
            .await
            .expect("replacement fixture must expose its old session");
        let mut replacement = old.clone();
        replacement.session_id = "replacement-session".to_string();
        replacement.session_token = "replacement-token".to_string();
        replacement.fresh_socket.session_token = replacement.session_token.clone();
        replacement.cancellation = Arc::new(crate::PunchSessionCancellation::default());
        assert!(
            !udp.tag_hard_hard_socket(
                &old.peer_id,
                old.fresh_socket.socket_index,
                &replacement.session_token,
            )
            .await,
            "a replacement session must not take over a socket bound to the old token"
        );
        assert_eq!(
            udp.hard_hard_socket_token(old.fresh_socket.socket_index)
                .await,
            Some(old.session_token.clone())
        );
        let (socket_index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
        assert_ne!(socket_index, old.fresh_socket.socket_index);
        replacement.fresh_socket.socket_index = socket_index;
        replacement.fresh_socket.socket_local_endpoint = socket.local_addr().unwrap();
        replacement.fresh_socket.punch_generation += 1;
        replacement.requested_socket_indices = vec![socket_index];
        let handoff = udp
            .attach_dynamic_punch_socket(
                &replacement.peer_id,
                socket_index,
                socket,
                replacement.local_network_generation,
                replacement.fresh_socket.punch_generation,
                Some(&replacement.cancellation),
            )
            .await
            .unwrap();
        assert!(
            udp.reserve_hard_hard_socket(&replacement.peer_id, socket_index)
                .await
        );
        assert!(
            handoff
                .commit_and_pin_for_test(
                    &udp,
                    &replacement.peer_id,
                    socket_index,
                    replacement.local_network_generation,
                    replacement.fresh_socket.punch_generation,
                )
                .await
        );
        assert!(handoff.finalize().await);
        // Finalizing the new affinity detaches its superseded predecessor
        // before session registration cancels the old session. Late cleanup
        // must therefore tolerate the old socket already being gone.
        assert!(!old.cancellation.is_cancelled());
        assert_eq!(
            udp.hard_hard_socket_token(old.fresh_socket.socket_index)
                .await,
            None,
            "the finalized handoff must retire the old socket before late session cleanup"
        );
        assert!(peers.hard_hard_register_session(replacement.clone()).await);
        assert!(old.cancellation.is_cancelled());
        assert_eq!(
            peers
                .hard_hard_session_snapshot_for_cleanup(
                    &old.peer_id,
                    &old.session_id,
                    &old.session_token,
                )
                .await
                .expect("old session must remain in Retiring state")
                .state,
            HardHardSessionState::Retiring
        );
        assert!(
            udp.tag_hard_hard_socket(
                &replacement.peer_id,
                replacement.fresh_socket.socket_index,
                &replacement.session_token,
            )
            .await
        );
        assert!(
            udp.hard_hard_socket_identity_is_current(&replacement.fresh_socket)
                .await,
            "the replacement must own its exact socket and affinity before old cleanup"
        );
        assert!(!replacement.cancellation.is_cancelled());

        let _ = peers
            .hard_hard_retire_session(&old.peer_id, &old.session_id, &old.session_token)
            .await;
        udp.detach_hard_hard_sockets_for_token(
            &old.peer_id,
            &old.session_token,
            None,
            "test_old_token_cleanup",
        )
        .await;
        udp.detach_hard_hard_socket_if_identity(&old.fresh_socket, "test_old_identity_cleanup")
            .await;
        udp.clear_hard_hard_pending_probes_for_token(&old.peer_id, &old.session_token, None)
            .await;
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &old.peer_id,
                    &old.session_id,
                    &old.session_token
                )
                .await
        );
        assert_eq!(udp.dynamic_socket_count().await, 1);
        assert!(
            udp.hard_hard_socket_identity_is_current(&replacement.fresh_socket)
                .await,
            "old token and socket cleanup must preserve the replacement's exact identity and affinity"
        );
        assert!(!replacement.cancellation.is_cancelled());
        assert!(peers
            .hard_hard_session_by_token(&replacement.peer_id, &replacement.session_token)
            .await
            .is_some());
        assert!(
            peers
                .hard_hard_session_is_active(&replacement.peer_id)
                .await
        );
        assert_eq!(
            udp.hard_hard_socket_indices_for_token(
                &replacement.peer_id,
                &replacement.session_token,
            )
            .await,
            vec![replacement.fresh_socket.socket_index]
        );

        assert!(
            peers
                .hard_hard_retire_session(
                    &replacement.peer_id,
                    &replacement.session_id,
                    &replacement.session_token,
                )
                .await
        );
        udp.detach_hard_hard_sockets_for_token(
            &replacement.peer_id,
            &replacement.session_token,
            None,
            "test_replacement_cleanup",
        )
        .await;
        udp.clear_hard_hard_pending_probes_for_token(
            &replacement.peer_id,
            &replacement.session_token,
            None,
        )
        .await;
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &replacement.peer_id,
                    &replacement.session_id,
                    &replacement.session_token,
                )
                .await
        );
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    #[tokio::test]
    async fn hard_hard_token_cleanup_uses_exact_fallback_and_preserves_mismatched_token() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            "retired-token",
            None,
            "test_token_mismatch_no_match",
        )
        .await;
        assert_eq!(udp.dynamic_socket_count().await, 1);
        udp.detach_hard_hard_socket_if_identity(&identity, "test_exact_identity_fallback")
            .await;
        assert_eq!(udp.dynamic_socket_count().await, 0);

        let (socket_index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
        let socket_local_endpoint = socket.local_addr().unwrap();
        let handoff = udp
            .attach_dynamic_punch_socket(&identity.peer_id, socket_index, socket, 0, 2, None)
            .await
            .unwrap();
        assert!(
            handoff
                .commit_and_pin_for_test(&udp, &identity.peer_id, socket_index, 0, 2)
                .await
        );
        assert!(handoff.finalize().await);
        assert!(
            udp.tag_hard_hard_socket(&identity.peer_id, socket_index, "replacement-token")
                .await
        );
        let mut mismatched_identity = identity.clone();
        mismatched_identity.socket_index = socket_index;
        mismatched_identity.punch_generation = 2;
        mismatched_identity.socket_local_endpoint = socket_local_endpoint;
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            &identity.session_token,
            None,
            "test_old_token_does_not_match_replacement",
        )
        .await;
        udp.detach_hard_hard_socket_if_identity(
            &mismatched_identity,
            "test_old_identity_does_not_match_replacement",
        )
        .await;
        assert_eq!(udp.dynamic_socket_count().await, 1);
        udp.detach_hard_hard_sockets_for_token(
            &identity.peer_id,
            "replacement-token",
            None,
            "test_replacement_token_cleanup",
        )
        .await;
        assert_eq!(udp.dynamic_socket_count().await, 0);
        peers
            .clear_hard_hard_sessions(Some(&identity.peer_id))
            .await;
        udp.detach_all_dynamic_punch_sockets("test_token_mismatch_cleanup")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_expiry_retains_only_authenticated_current_direct_socket() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(Some(4_000_000_000));
        let _clock = HardHardTestClockReset;
        let (peers, udp, identity, remote, _peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );
        assert!(
            hard_hard_exact_direct_socket_is_current_for_cleanup(&udp, &peers, &identity).await
        );
        let record = peers
            .hard_hard_session_snapshot_for_cleanup(
                &identity.peer_id,
                "birthday-runtime-session",
                &identity.session_token,
            )
            .await
            .unwrap();
        let descriptor = HardHardCleanupDescriptor::from_record(&record);
        set_hard_hard_test_now_ms(Some(record.expires_at_ms.saturating_add(1)));
        let (gate, _gate_guard) = peers.install_hard_hard_cleanup_gate_for_test(
            &descriptor.peer_id,
            &descriptor.session_id,
            &descriptor.session_token,
        );
        let completion =
            spawn_hard_hard_session_cleanup(udp.clone(), peers.clone(), descriptor.clone());
        wait_for_hard_hard_cleanup_gate(&gate).await;
        assert_eq!(
            udp.hard_hard_socket_indices_for_token(&identity.peer_id, &identity.session_token)
                .await,
            vec![identity.socket_index]
        );
        gate.release();
        wait_for_hard_hard_cleanup_completion(&completion).await;
        assert!(peers
            .hard_hard_session_snapshot_for_cleanup(
                &descriptor.peer_id,
                &descriptor.session_id,
                &descriptor.session_token,
            )
            .await
            .is_none());
        assert_eq!(udp.dynamic_socket_count().await, 1);
        udp.detach_dynamic_socket_by_index(identity.socket_index, "test_retained_direct_cleanup")
            .await;
        assert_eq!(udp.dynamic_socket_count().await, 0);
    }

    async fn wait_for_birthday_worker_gate(gate: &Arc<crate::udp::BirthdayWorkerCompletionGate>) {
        tokio::time::timeout(Duration::from_secs(1), gate.reached.notified())
            .await
            .expect("production Birthday worker did not publish live progress");
    }

    async fn wait_for_birthday_post_send_gate(gate: &Arc<crate::udp::ProbePostSendGate>) {
        tokio::time::timeout(Duration::from_secs(1), gate.reached.notified())
            .await
            .expect("production Birthday send did not reach the post-send gate");
    }

    // Capture only the production terminal archive for this one worker future.
    // Retired identities cannot write into a replacement peer's current ring.
    #[derive(Clone, Default)]
    struct HardHardTerminalArchiveCapture(
        Arc<std::sync::Mutex<Option<crate::peer::HardHardAttemptReport>>>,
    );

    #[derive(Default)]
    struct HardHardTerminalArchiveFields {
        event: Option<String>,
        report_json: Option<String>,
    }

    impl tracing::field::Visit for HardHardTerminalArchiveFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "event" => self.event = Some(value.to_string()),
                "report_json" => self.report_json = Some(value.to_string()),
                _ => {}
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "report_json" {
                self.report_json = Some(format!("{value:?}"));
            }
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for HardHardTerminalArchiveCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = HardHardTerminalArchiveFields::default();
            event.record(&mut fields);
            if fields.event.as_deref() == Some("hard_hard_attempt_report_archived") {
                let report = serde_json::from_str(
                    fields
                        .report_json
                        .as_deref()
                        .expect("terminal archive must contain its formal report"),
                )
                .expect("terminal archive must contain a valid typed report");
                assert!(
                    self.0.lock().unwrap().replace(report).is_none(),
                    "one worker must archive its terminal report only once"
                );
            }
        }
    }

    async fn birthday_terminal_attempt(
        peers: &PeerManager,
        record: &crate::peer::HardHardSessionRecord,
        archive: &HardHardTerminalArchiveCapture,
    ) -> crate::peer::HardHardAttemptReport {
        let (session_tag, _, _) = hard_hard_a0_stage_tags(Some(&record.session_token));
        let reports = peers
            .diagnostics()
            .await
            .into_iter()
            .flat_map(|peer| peer.direct_events)
            .filter_map(|event| event.hard_hard_attempt)
            .filter(|report| {
                report.session_tag == session_tag && report.attempt == record.attempt_count
            })
            .collect::<Vec<_>>();
        let archived = archive.0.lock().unwrap().take();
        assert_eq!(
            reports.len() + usize::from(archived.is_some()),
            1,
            "the exact attempt must commit or archive one formal terminal report"
        );
        let report = reports.into_iter().next().or(archived).unwrap();
        assert_eq!(report.session_tag, session_tag);
        assert_eq!(report.attempt, record.attempt_count);
        assert_eq!(report.network_generation, record.local_network_generation);
        assert_eq!(report.remote_candidate_epoch, record.remote_candidate_epoch);
        assert_eq!(
            report.local_profile_generation,
            record.local_profile_generation
        );
        assert_eq!(
            report.remote_profile_generation,
            record.remote_profile_generation
        );
        assert_eq!(
            report.punch_generation,
            record.fresh_socket.punch_generation
        );
        assert_eq!(
            report.peer_session_generation,
            record
                .measurement
                .evidence
                .peer_session_generation()
                .unwrap()
                .value()
        );
        assert_eq!(report.socket_index, Some(record.fresh_socket.socket_index));
        assert!(!report.direct_confirmed);
        report
    }

    fn assert_live_birthday_terminal_summary(
        report: &crate::peer::HardHardAttemptReport,
        stop_reason: &str,
    ) {
        let summary = report
            .birthday_sweep
            .as_ref()
            .expect("terminal Birthday details must be sealed");
        assert!(summary.physical_datagrams_sent >= 1);
        assert!(!summary.per_socket_sent.is_empty());
        assert_eq!(
            summary.physical_datagrams_sent,
            summary
                .per_socket_sent
                .iter()
                .map(|(_, sent)| *sent as usize)
                .sum::<usize>()
        );
        assert!(summary.first_send_at_ms.is_some());
        assert!(summary.last_send_at_ms.is_some());
        assert_eq!(summary.unique_target_endpoints, 1);
        assert_eq!(summary.waves_fully_completed, 0);
        assert_eq!(summary.stop_reason.as_deref(), Some(stop_reason));
        assert_eq!(report.terminal_reason, stop_reason);
    }

    fn assert_post_send_race_summary(
        report: &crate::peer::HardHardAttemptReport,
        stop_reason: &str,
        require_physical_error: bool,
    ) {
        let summary = report
            .birthday_sweep
            .as_ref()
            .expect("post-send race must seal Birthday details");
        if require_physical_error {
            assert!(summary.physical_send_errors >= 1);
        } else {
            assert!(summary.physical_datagrams_sent >= 1);
            assert!(summary.logical_probes_sent >= 1);
            assert!(summary.unique_target_endpoints >= 1);
            assert!(!summary.per_socket_sent.is_empty());
            assert_eq!(
                summary.physical_datagrams_sent,
                summary
                    .per_socket_sent
                    .iter()
                    .map(|(_, sent)| *sent as usize)
                    .sum::<usize>()
            );
            assert!(summary.first_send_at_ms.is_some());
            assert!(summary.last_send_at_ms.is_some());
        }
        assert_eq!(summary.waves_fully_completed, 0);
        assert_eq!(summary.stop_reason.as_deref(), Some(stop_reason));
        assert_eq!(report.terminal_reason, stop_reason);
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_deadline_snapshots_live_progress_at_production_entry() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let (gate, _gate_guard) = crate::udp::install_birthday_worker_completion_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let record = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture must claim the actual attempt and its bound observation owner");
        let archive = HardHardTerminalArchiveCapture::default();
        let subscriber = tracing_subscriber::registry().with(archive.clone());
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            let measurement = record.measurement.clone();
            let attempt = record.attempt_count;
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-deadline",
                    attempt,
                    measurement,
                )
                .await
            }
            .with_subscriber(subscriber)
        });
        wait_for_birthday_worker_gate(&gate).await;
        tokio::time::advance(HARD_HARD_SWEEP_DEADLINE).await;
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let report = birthday_terminal_attempt(&peers, &record, &archive).await;
        assert_live_birthday_terminal_summary(&report, "deadline");
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_deadline_live_progress")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_cancellation_snapshots_live_progress_at_production_entry() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let cancellation = session.cancellation_handle();
        let (gate, _gate_guard) = crate::udp::install_birthday_worker_completion_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let record = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture must claim the actual attempt and its bound observation owner");
        let archive = HardHardTerminalArchiveCapture::default();
        let subscriber = tracing_subscriber::registry().with(archive.clone());
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            let measurement = record.measurement.clone();
            let attempt = record.attempt_count;
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-cancel",
                    attempt,
                    measurement,
                )
                .await
            }
            .with_subscriber(subscriber)
        });
        wait_for_birthday_worker_gate(&gate).await;
        cancellation.cancel_for_hard_hard_cleanup();
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let report = birthday_terminal_attempt(&peers, &record, &archive).await;
        assert_live_birthday_terminal_summary(&report, "session_cancelled");
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_cancel_live_progress")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_post_send_deadline_preserves_live_progress() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let record = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture must claim the actual attempt and its bound observation owner");
        let archive = HardHardTerminalArchiveCapture::default();
        let subscriber = tracing_subscriber::registry().with(archive.clone());
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            let measurement = record.measurement.clone();
            let attempt = record.attempt_count;
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-post-send-deadline",
                    attempt,
                    measurement,
                )
                .await
            }
            .with_subscriber(subscriber)
        });
        wait_for_birthday_post_send_gate(&gate).await;
        tokio::time::advance(HARD_HARD_SWEEP_DEADLINE).await;
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let report = birthday_terminal_attempt(&peers, &record, &archive).await;
        assert_post_send_race_summary(&report, "deadline", false);
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_post_send_deadline")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_post_send_cancellation_preserves_live_progress() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let cancellation = session.cancellation_handle();
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let record = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture must claim the actual attempt and its bound observation owner");
        let archive = HardHardTerminalArchiveCapture::default();
        let subscriber = tracing_subscriber::registry().with(archive.clone());
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            let measurement = record.measurement.clone();
            let attempt = record.attempt_count;
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-post-send-cancel",
                    attempt,
                    measurement,
                )
                .await
            }
            .with_subscriber(subscriber)
        });
        wait_for_birthday_post_send_gate(&gate).await;
        cancellation.cancel_for_hard_hard_cleanup();
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let report = birthday_terminal_attempt(&peers, &record, &archive).await;
        assert_post_send_race_summary(&report, "session_cancelled", false);
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_post_send_cancellation")
            .await;
    }

    async fn assert_predictable_post_send_terminal(cancel: bool) {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // The sender is held after its syscall, so receiving needs no runtime
        // progress. Wait for native loopback delivery with a wall-clock bound;
        // a successful handoff does not imply immediate nonblocking readability.
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let remote = receiver.local_addr().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production predictable punch session");
        let cancellation = session.cancellation_handle();
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let record = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture must claim the exact attempt and observation owner");
        let archive = HardHardTerminalArchiveCapture::default();
        let subscriber = tracing_subscriber::registry().with(archive.clone());
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            let measurement = record.measurement.clone();
            let attempt = record.attempt_count;
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    None,
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    0,
                    1,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-predictable-post-send",
                    attempt,
                    measurement,
                )
                .await
            }
            .with_subscriber(subscriber)
        });
        tokio::time::timeout(Duration::from_secs(1), gate.reached.notified())
            .await
            .expect("production predictable send did not reach the post-send gate");
        // The production gate is after the primary kernel send and before the
        // compatibility copy or any later await can complete the sender report.
        let mut bytes = [0; 2_048];
        let (received_bytes, source) = receiver.recv_from(&mut bytes).unwrap();
        assert!(received_bytes > 0);
        assert_eq!(source, identity.socket_local_endpoint);
        if cancel {
            cancellation.cancel_for_hard_hard_cleanup();
        } else {
            tokio::time::advance(HARD_HARD_SWEEP_DEADLINE).await;
        }
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let report = birthday_terminal_attempt(&peers, &record, &archive).await;
        let stop_reason = if cancel {
            "session_cancelled"
        } else {
            "deadline"
        };
        assert_eq!(report.terminal_reason, stop_reason);
        assert_eq!(report.mode, "predictable");
        assert!(report.birthday_sweep.is_none());
        assert_eq!(report.socket_index, Some(identity.socket_index));
        assert_eq!(report.counts.send_success_datagrams, 1);
        assert_eq!(report.counts.send_success_bytes, received_bytes as u64);
        assert_eq!(report.counts.logical_probes_attempted, 1);
        assert_eq!(report.counts.logical_probes_sent, 1);
        assert_eq!(report.counts.attempted_targets, 1);
        assert_eq!(report.counts.send_errors, 0);
        assert!(report.timeline.actual_first_send_at_ms.is_some());
        assert_ne!(report.failure_class, "missed_schedule");
        assert!(!peers.is_direct_sync(&identity.peer_id));
        assert!(report
            .timeline
            .encrypted_validation_completed_at_ms
            .is_none());
        assert!(report.business_attribution_identity.is_none());
        assert!(report.counts.logical_probes_sent < report.counts.planned_logical_probes);
        // Even with every other completion condition granted, this partial
        // physical ledger cannot qualify as negative strategy evidence.
        assert!(!hard_hard_complete_unanswered_exploration(
            &PunchSendReport {
                packets_sent: report.counts.logical_probes_sent,
                logical_probes_sent: report.counts.logical_probes_sent,
                physical_datagrams_sent: report.counts.send_success_datagrams,
                target_processing_completed: true,
                ..Default::default()
            },
            report.counts.planned_logical_probes as usize,
            Default::default(),
        ));
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_predictable_post_send_terminal")
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_predictable_post_send_deadline_preserves_live_progress() {
        assert_predictable_post_send_terminal(false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_predictable_post_send_cancellation_preserves_live_progress() {
        assert_predictable_post_send_terminal(true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn hard_hard_birthday_primary_send_error_is_recorded_before_cleanup_cancel() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        set_hard_hard_test_now_ms(None);
        let (peers, udp, identity, _remote, peer_session_generation) =
            exact_birthday_runtime_fixture().await;
        let remote: SocketAddr = "127.0.0.1:41004".parse().unwrap();
        let session = PunchAttemptDeduplicator::default()
            .claim(&identity.peer_id)
            .await
            .expect("test must own the production Hard↔Hard punch session");
        let cancellation = session.cancellation_handle();
        let _send_failures = udp.set_probe_send_failures_for_test([1]);
        let (gate, _gate_guard) = crate::udp::install_probe_post_send_gate_for_test();
        let socket_indices = vec![identity.socket_index, identity.socket_index + 1];
        let record = peers
            .hard_hard_begin_sweep(
                &identity.peer_id,
                &identity.session_token,
                vec![remote],
                90,
                0,
            )
            .await
            .expect("fixture must claim the actual attempt and its bound observation owner");
        let archive = HardHardTerminalArchiveCapture::default();
        let subscriber = tracing_subscriber::registry().with(archive.clone());
        let task = tokio::spawn({
            let udp = udp.clone();
            let peers = peers.clone();
            let identity = identity.clone();
            let measurement = record.measurement.clone();
            let attempt = record.attempt_count;
            async move {
                hard_hard_wait_and_sweep(
                    udp,
                    peers,
                    session,
                    identity.peer_id.clone(),
                    peer_session_generation,
                    identity,
                    Some(socket_indices),
                    "birthday-runtime-token".to_string(),
                    vec![remote],
                    64,
                    64,
                    1,
                    hard_hard_now_ms(),
                    0,
                    (1, 7),
                    Some("probe-session-exact".to_string()),
                    "test-primary-error-cancel",
                    attempt,
                    measurement,
                )
                .await
            }
            .with_subscriber(subscriber)
        });
        wait_for_birthday_post_send_gate(&gate).await;
        cancellation.cancel_for_hard_hard_cleanup();
        tokio::task::yield_now().await;
        assert!(!task.await.unwrap());

        let report = birthday_terminal_attempt(&peers, &record, &archive).await;
        assert_post_send_race_summary(&report, "session_cancelled", true);
        gate.release.notify_waiters();
        udp.detach_all_dynamic_punch_sockets("test_primary_error_cancel")
            .await;
    }

    fn endpoint_for_test(port: u16) -> SocketAddr {
        SocketAddr::new("198.51.100.20".parse().unwrap(), port)
    }

    #[test]
    fn hard_hard_elapsed_ms_rejects_missing_or_reversed_timestamps() {
        assert_eq!(hard_hard_elapsed_ms(Some(10), Some(15)), Some(5));
        assert_eq!(hard_hard_elapsed_ms(Some(15), Some(10)), None);
        assert_eq!(hard_hard_elapsed_ms(Some(10), None), None);
        assert_eq!(hard_hard_elapsed_ms(None, Some(15)), None);
    }

    #[tokio::test]
    async fn hard_hard_attempt_report_keeps_candidate_order_and_cost_dimensions_separate() {
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let peer_session_generation = peers
            .peer_session_generation_sync(&identity.peer_id)
            .expect("fixture peer must have a lifecycle identity");
        let other = endpoint_for_test(remote.port() + 1);
        let targets = vec![remote, other, remote];
        let measurement = crate::peer::HardHardMeasurementObservation {
            measurement_started_at_ms: Some(10),
            last_measurement_send_at_ms: Some(20),
            measurement_completed_at_ms: Some(30),
            candidate_signal_accepted_at_ms: Some(40),
            planned_send_at_ms: Some(50),
            requested_candidate_count: 0,
            generated_candidate_count: 0,
            deduplicated_candidate_count: 0,
            advertised_candidate_count: 0,
            candidate_cap: 32,
            truncation_reason: "empty_model".to_string(),
            stun_datagrams_sent: 4,
            stun_bytes_sent: 80,
            stun_send_errors: 1,
            stun_send_error_bytes: 20,
            stun_responses: 3,
            candidate_signal_payload_logic_bytes: 48,
            evidence: Default::default(),
        };
        let send = PunchSendReport {
            logical_probes_attempted: 4,
            logical_probes_sent: 3,
            physical_datagrams_sent: 5,
            physical_bytes_sent: 300,
            physical_send_errors: 1,
            physical_send_error_bytes: 60,
            targets_attempted: 2,
            unique_target_endpoints: 2,
            budget_skipped: 1,
            ..PunchSendReport::default()
        };
        let report = build_hard_hard_attempt_report(
            &peers,
            false,
            peer_session_generation,
            &identity,
            &identity.session_token,
            "initiator",
            false,
            0,
            &measurement,
            &targets,
            1,
            3,
            6,
            Some(45),
            &send,
            UdpProbeRxSnapshot::default(),
            false,
            None,
            None,
            None,
            "send_error",
        );

        assert_eq!(report.counts.requested, 0);
        assert_eq!(report.counts.generated, 0);
        assert_eq!(report.counts.parsed_targets_for_plan, 3);
        assert_eq!(report.counts.planned_socket_target_combinations, 3);
        assert_eq!(report.counts.attempted_targets, 2);
        assert_eq!(report.counts.logical_probes_attempted, 4);
        assert_eq!(report.counts.send_success_datagrams, 5);
        assert_eq!(report.counts.send_success_bytes, 300);
        assert_eq!(report.counts.send_error_bytes, 60);
        assert_eq!(report.counts.stun_send_success_datagrams, 4);
        assert_eq!(report.counts.stun_send_success_bytes, 80);
        assert_eq!(report.counts.candidate_signal_payload_logic_bytes, 48);
        assert_eq!(
            report.schema_version,
            crate::peer::HARD_HARD_ATTEMPT_REPORT_SCHEMA_VERSION
        );
        assert_eq!(
            report.plan_tag,
            hard_hard_rendezvous_plan_tag(&identity.session_token)
        );
        assert_eq!(report.target_order_tags.len(), targets.len());
        assert_eq!(report.target_order_tags[0], report.target_order_tags[2]);
        assert_ne!(report.target_order_tags[0], report.target_order_tags[1]);

        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains(&remote.to_string()));
        assert!(!encoded.contains(&identity.session_token));
        assert!(encoded.contains("send_success_datagrams"));
        udp.detach_all_dynamic_punch_sockets("attempt_report_dimensions")
            .await;
    }

    #[test]
    fn hard_hard_attempt_failure_classes_preserve_terminal_evidence() {
        let classify =
            |report: PunchSendReport, probe_rx: UdpProbeRxSnapshot, direct: bool, reason: &str| {
                hard_hard_attempt_failure_class(&report, 2, probe_rx, direct, reason)
            };
        assert_eq!(
            classify(
                PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                true,
                "direct_confirmed"
            ),
            "encrypted_validation_completed"
        );
        assert_eq!(
            classify(
                PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                false,
                "network_generation_changed"
            ),
            "cancelled_generation_changed"
        );
        assert_eq!(
            classify(
                PunchSendReport {
                    budget_skipped: 2,
                    ..PunchSendReport::default()
                },
                UdpProbeRxSnapshot::default(),
                false,
                "budget"
            ),
            "budget_rejected"
        );
        assert_eq!(
            classify(
                PunchSendReport {
                    physical_send_errors: 1,
                    ..PunchSendReport::default()
                },
                UdpProbeRxSnapshot::default(),
                false,
                "send_error"
            ),
            "send_error"
        );
        assert_eq!(
            classify(
                PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                false,
                "deadline"
            ),
            "missed_schedule"
        );
        assert_eq!(
            classify(
                PunchSendReport {
                    logical_probes_attempted: 1,
                    physical_datagrams_sent: 1,
                    ..PunchSendReport::default()
                },
                UdpProbeRxSnapshot {
                    authenticated_probe_packets_received: 1,
                    ..UdpProbeRxSnapshot::default()
                },
                false,
                "no_authenticated_direct_confirmation"
            ),
            "probe_hit_validation_failed"
        );
        assert_eq!(
            classify(
                failure_class_complete_ledger(),
                UdpProbeRxSnapshot::default(),
                false,
                "no_authenticated_direct_confirmation"
            ),
            "no_response"
        );
    }

    fn report_for_observation_fixture(
        record: &HardHardSessionRecord,
    ) -> crate::peer::HardHardAttemptReport {
        crate::peer::HardHardAttemptReport {
            network_generation: record.local_network_generation,
            peer_session_generation: record
                .measurement
                .evidence
                .peer_session_generation()
                .unwrap()
                .value(),
            remote_candidate_epoch: record.remote_candidate_epoch,
            local_profile_generation: record.local_profile_generation,
            remote_profile_generation: record.remote_profile_generation,
            punch_generation: record.fresh_socket.punch_generation,
            socket_index: Some(record.fresh_socket.socket_index),
            attempt: record.attempt_count,
            ..crate::peer::HardHardAttemptReport::default()
        }
    }

    #[tokio::test]
    async fn hh_attempt_receive_evidence_excludes_peer_traffic_and_other_tokens() {
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let record = peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .unwrap();
        udp.update_peer_probe_rx_diagnostics(
            &identity.peer_id,
            identity.network_generation,
            Some("probe-session-exact"),
            |snapshot| {
                snapshot.authenticated_probe_packets_received = 50;
                snapshot.probe_acks_received = 25;
            },
        )
        .await;
        assert_eq!(
            record.measurement.evidence.receive_snapshot(),
            UdpProbeRxSnapshot::default()
        );
        let pair = crate::peer::HardHardPairKey {
            socket_index: identity.socket_index,
            local_endpoint: identity.socket_local_endpoint,
            remote_endpoint: remote,
        };
        let peer_session = record
            .measurement
            .evidence
            .peer_session_generation()
            .unwrap();
        peers
            .record_hard_hard_receive(
                &identity.peer_id,
                "other-token",
                peer_session,
                pair.clone(),
                crate::peer::HardHardReceiveObservation::AuthenticatedAck,
                1,
            )
            .await;
        assert_eq!(
            record.measurement.evidence.receive_snapshot(),
            UdpProbeRxSnapshot::default()
        );
        peers
            .record_hard_hard_receive(
                &identity.peer_id,
                &identity.session_token,
                peer_session,
                pair,
                crate::peer::HardHardReceiveObservation::AuthenticatedAck,
                2,
            )
            .await;
        let observed = record.measurement.evidence.receive_snapshot();
        assert_eq!(observed.authenticated_probe_packets_received, 1);
        assert_eq!(observed.authenticated_probe_acks_unmatched, 1);
        assert_eq!(observed.probe_acks_received, 0);
        udp.detach_all_dynamic_punch_sockets("attempt_receive_isolation")
            .await;
    }

    #[tokio::test]
    async fn terminal_report_rechecks_retirement_after_connection_writer_wait() {
        let (peers, udp, identity, _) = exact_socket_proof_fixture().await;
        let record = peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .unwrap();
        let report = report_for_observation_fixture(&record);
        let writer = peers.hold_connections_writer_for_test().await;
        let archive = HardHardTerminalArchiveCapture::default();
        let mut commit = Box::pin(
            peers
                .record_hard_hard_attempt_report_with_evidence(
                    &identity.peer_id,
                    &identity.session_token,
                    report.clone(),
                    &record.measurement.evidence,
                )
                .with_subscriber(tracing_subscriber::registry().with(archive.clone())),
        );
        assert!(futures_util::poll!(commit.as_mut()).is_pending());
        assert!(
            peers
                .hard_hard_retire_session(
                    &identity.peer_id,
                    &record.session_id,
                    &identity.session_token
                )
                .await
        );
        assert!(
            peers
                .hard_hard_complete_session_cleanup(
                    &identity.peer_id,
                    &record.session_id,
                    &identity.session_token
                )
                .await
        );
        drop(writer);
        assert!(
            !commit.await,
            "the old observation may archive but cannot commit into the current ring"
        );
        assert_eq!(archive.0.lock().unwrap().as_ref(), Some(&report));
        assert!(
            !peers
                .record_hard_hard_attempt_report_with_evidence(
                    &identity.peer_id,
                    &identity.session_token,
                    report,
                    &record.measurement.evidence
                )
                .await,
            "archived observations must remain sealed"
        );
        assert!(!peers.diagnostics().await[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_attempt_report"));
        udp.detach_all_dynamic_punch_sockets("attempt_retired_during_commit")
            .await;
    }

    #[tokio::test]
    async fn cancelled_terminal_commit_keeps_one_shot_observation_sealed() {
        let (peers, udp, identity, _) = exact_socket_proof_fixture().await;
        let record = peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .unwrap();
        let report = report_for_observation_fixture(&record);
        let writer = peers.hold_connections_writer_for_test().await;
        // Exercise the production ordering: auxiliary summaries precede the
        // formal report. The first Pending must occur in that report's sealed
        // commit transaction, never in a summary writer wait. Dropping here
        // must therefore still archive and preserve one-shot ownership.
        let mut commit = Box::pin(async {
            peers
                .record_direct_event_for_generation_with_socket(
                    &identity.peer_id,
                    identity.network_generation,
                    "hard_hard_probe_summary",
                    None,
                    Some(identity.socket_index),
                    Some(1),
                    Some(1),
                    "terminal summary before sealed report",
                )
                .await;
            peers
                .record_direct_event(
                    &identity.peer_id,
                    "hard_hard_sweep_failed",
                    None,
                    Some(1),
                    Some(1),
                    "terminal marker before sealed report",
                )
                .await;
            peers
                .record_hard_hard_attempt_report_with_evidence(
                    &identity.peer_id,
                    &identity.session_token,
                    report.clone(),
                    &record.measurement.evidence,
                )
                .await
        });
        assert!(futures_util::poll!(commit.as_mut()).is_pending());
        drop(commit); // The RAII terminal owner archives while the writer is unavailable.
        drop(writer);
        assert!(
            !peers
                .record_hard_hard_attempt_report_with_evidence(
                    &identity.peer_id,
                    &identity.session_token,
                    report,
                    &record.measurement.evidence
                )
                .await
        );
        assert!(!peers.diagnostics().await[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_attempt_report"));
        udp.detach_all_dynamic_punch_sockets("attempt_commit_future_cancelled")
            .await;
    }

    #[tokio::test]
    async fn stale_hard_hard_attempt_report_is_fenced_before_durable_status() {
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let peer_session_generation = peers
            .peer_session_generation_sync(&identity.peer_id)
            .expect("fixture peer must have a lifecycle identity");
        let current = build_hard_hard_attempt_report(
            &peers,
            false,
            peer_session_generation,
            &identity,
            &identity.session_token,
            "initiator",
            false,
            0,
            &crate::peer::HardHardMeasurementObservation::default(),
            &[remote],
            1,
            1,
            2,
            None,
            &PunchSendReport::default(),
            UdpProbeRxSnapshot::default(),
            false,
            None,
            None,
            None,
            "session_cancelled",
        );
        let mut stale = current.clone();
        stale.remote_candidate_epoch = stale.remote_candidate_epoch.saturating_add(1);
        assert!(
            !peers
                .record_hard_hard_attempt_report(&identity.peer_id, &identity.session_token, stale,)
                .await
        );
        assert!(!peers.diagnostics().await[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_attempt_report"));
        assert!(
            peers
                .record_hard_hard_attempt_report(
                    &identity.peer_id,
                    &identity.session_token,
                    current,
                )
                .await
        );
        // Twice the production 32-entry direct-event bound proves that an
        // all-protected validation burst cannot evict the terminal report.
        for request_id in 1..=64 {
            peers
                .record_direct_validation_event(
                    &identity.peer_id,
                    identity.network_generation,
                    request_id as u64,
                    "direct_validation_request_sent",
                    Some(remote),
                    Some(1),
                    Some(1),
                    "protected validation churn after terminal attempt",
                )
                .await;
        }
        let events = peers.diagnostics().await[0].direct_events.clone();
        let event = events
            .iter()
            .find(|event| event.stage == "hard_hard_attempt_report")
            .expect("current typed attempt must be durable");
        assert_eq!(
            event
                .hard_hard_attempt
                .as_ref()
                .map(|report| report.failure_class.as_str()),
            Some("cancelled_generation_changed")
        );
        udp.detach_all_dynamic_punch_sockets("attempt_report_fence")
            .await;
    }

    #[tokio::test]
    async fn attempt_report_uses_only_its_current_tokens_agreed_strategy() {
        use crate::peer::HardHardProbeStrategy::{Birthday, FixedAnchor, Predictable};
        for (strategy, expected_mode) in [
            (None, "legacy_custom"),
            (Some(FixedAnchor), "fixed_anchor"),
            (Some(Predictable), "predictable"),
            (Some(Birthday), "birthday"),
        ] {
            let (peers, udp, identity, remote) =
                exact_socket_proof_fixture_with_strategy(strategy).await;
            let peer_session = peers
                .peer_session_generation_sync(&identity.peer_id)
                .unwrap();
            let mut report = build_hard_hard_attempt_report(
                &peers,
                false,
                peer_session,
                &identity,
                &identity.session_token,
                "initiator",
                true,
                0,
                &crate::peer::HardHardMeasurementObservation::default(),
                &[remote],
                1,
                1,
                2,
                None,
                &PunchSendReport::default(),
                UdpProbeRxSnapshot::default(),
                false,
                None,
                None,
                None,
                "session_cancelled",
            );
            report.mode = "legacy_custom".to_string();
            assert!(
                !peers
                    .record_hard_hard_attempt_report(
                        &identity.peer_id,
                        "replaced-token",
                        report.clone()
                    )
                    .await
            );
            assert!(
                peers
                    .record_hard_hard_attempt_report(
                        &identity.peer_id,
                        &identity.session_token,
                        report
                    )
                    .await
            );
            let diagnostics = peers.diagnostics().await;
            let event = diagnostics[0]
                .direct_events
                .iter()
                .find(|event| event.stage == "hard_hard_attempt_report")
                .unwrap();
            assert_eq!(
                event.hard_hard_attempt.as_ref().unwrap().mode,
                expected_mode
            );
            assert!(event.detail.contains(&format!("mode={expected_mode}")));
            udp.detach_all_dynamic_punch_sockets("attempt_report_strategy")
                .await;
        }
    }

    #[tokio::test]
    async fn unexecuted_live_session_response_retains_typed_terminal_evidence() {
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let peer_session_generation = peers
            .peer_session_generation_sync(&identity.peer_id)
            .expect("fixture peer must have a lifecycle identity");
        let record = peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .expect("fixture must own a live session");

        assert!(
            record_hard_hard_unexecuted_session_attempt(
                &peers,
                &identity.peer_id,
                peer_session_generation,
                &record,
                "initiator",
                &[remote],
                "response_plan_unavailable",
            )
            .await
        );
        let events = peers.diagnostics().await[0].direct_events.clone();
        let report = events
            .iter()
            .find_map(|event| event.hard_hard_attempt.as_ref())
            .expect("the consumed response must leave a typed report");
        assert_eq!(report.failure_class, "candidate_not_executed");
        assert_eq!(report.terminal_reason, "response_plan_unavailable");
        assert_eq!(report.counts.planned_targets, 1);
        assert_eq!(
            report.counts.planned_logical_probes,
            HARD_HARD_SWEEP_ATTEMPTS
        );
        assert_eq!(
            report.counts.planned_logical_probes_not_attempted,
            HARD_HARD_SWEEP_ATTEMPTS
        );
        udp.detach_all_dynamic_punch_sockets("unexecuted_response_report")
            .await;
    }

    #[tokio::test]
    async fn pre_session_report_uses_exact_identity_when_strategy_plan_is_unavailable() {
        let (peers, udp, identity, _remote) = exact_socket_proof_fixture().await;
        assert!(
            peers
                .hard_hard_plan_for_peer(&identity.peer_id)
                .await
                .is_none(),
            "fixture intentionally has no local NAT profile for planner admission"
        );
        let peer_session_generation = peers
            .peer_session_generation_sync(&identity.peer_id)
            .expect("fixture peer must have a lifecycle identity");
        let plan = crate::peer::HardHardPlanSnapshot {
            local_network_generation: identity.network_generation,
            remote_candidate_epoch: identity.remote_candidate_epoch,
            local_profile_generation: identity.local_profile_generation,
            remote_profile_generation: identity.remote_profile_generation,
        };
        let report = build_hard_hard_pre_session_attempt_report(
            false,
            peer_session_generation,
            plan,
            &identity.session_token,
            "responder",
            0,
            None,
            "candidate_not_executed",
            "planner_prerequisites_unavailable",
        );

        assert!(
            peers
                .record_hard_hard_pre_session_attempt_report(&identity.peer_id, report)
                .await
        );
        let events = peers.diagnostics().await[0].direct_events.clone();
        let retained = events
            .iter()
            .find_map(|event| event.hard_hard_attempt.as_ref())
            .expect("exact pre-session failure must survive planner unavailability");
        assert_eq!(retained.socket_index, None);
        assert_eq!(retained.failure_class, "candidate_not_executed");
        assert_eq!(
            retained.terminal_reason,
            "planner_prerequisites_unavailable"
        );
        udp.detach_all_dynamic_punch_sockets("pre_session_report")
            .await;
    }

    async fn exact_socket_proof_fixture() -> (
        Arc<PeerManager>,
        UdpTransport,
        crate::peer::HardHardFreshSocketIdentity,
        SocketAddr,
    ) {
        exact_socket_proof_fixture_with_strategy(None).await
    }

    async fn exact_socket_proof_fixture_with_strategy(
        strategy: Option<crate::peer::HardHardProbeStrategy>,
    ) -> (
        Arc<PeerManager>,
        UdpTransport,
        crate::peer::HardHardFreshSocketIdentity,
        SocketAddr,
    ) {
        exact_socket_fixture(strategy, false).await
    }

    async fn exact_socket_fixture(
        strategy: Option<crate::peer::HardHardProbeStrategy>,
        birthday: bool,
    ) -> (
        Arc<PeerManager>,
        UdpTransport,
        crate::peer::HardHardFreshSocketIdentity,
        SocketAddr,
    ) {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "hard-hard-exact-proof").unwrap(),
        ));
        peers.set_timeline(crate::connection_timeline::ConnectionTimeline::new(
            "hard-hard-exact-proof",
            0,
        ));
        let (session_id, session_token) = if birthday {
            peers
                .update_nat_profile(birthday_runtime_nat_profile())
                .await;
            ("birthday-runtime-session", "birthday-runtime-token")
        } else {
            ("proof-session", "proof-token")
        };
        let remote: SocketAddr = "198.51.100.20:41000".parse().unwrap();
        peers
            .add_peer(&crate::control::PeerInfo {
                capabilities: crate::control::PeerCapabilities::default(),
                registration_seq: 0,
                node_id: "peer-exact-proof".to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: "pk".to_string(),
                endpoint: remote.to_string(),
                nat_type:
                    "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7"
                        .to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
        let sources = HashMap::from([(remote.to_string(), "stun_observed".to_string())]);
        peers
            .add_candidates_with_sources("peer-exact-proof", &[remote.to_string()], &sources)
            .await;
        let remote_candidate_epoch = peers
            .current_remote_candidate_epoch("peer-exact-proof")
            .await
            .unwrap();
        assert!(
            peers
                .bind_remote_nat_profile_to_candidate_epoch("peer-exact-proof", 7)
                .await
        );
        assert!(
            peers
                .set_probe_session_id("peer-exact-proof", Some("probe-session-exact".to_string()),)
                .await
        );

        let (inbound_tx, _inbound_rx) = tokio::sync::mpsc::channel(8);
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_inbound_channel(inbound_tx);
        let (socket_index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
        let socket_local_endpoint = socket.local_addr().unwrap();
        let handoff = udp
            .attach_dynamic_punch_socket("peer-exact-proof", socket_index, socket, 0, 1, None)
            .await
            .unwrap();
        assert!(
            handoff
                .commit_and_pin_for_test(&udp, "peer-exact-proof", socket_index, 0, 1)
                .await
        );
        assert!(handoff.finalize().await);
        udp.remember_peer_socket(
            "peer-exact-proof",
            socket_index,
            crate::udp::SocketEvidence::Fresh,
        )
        .await;

        let identity = crate::peer::HardHardFreshSocketIdentity {
            peer_id: "peer-exact-proof".to_string(),
            session_token: session_token.to_string(),
            network_generation: 0,
            remote_candidate_epoch,
            local_profile_generation: peers.current_local_profile_generation_sync(),
            remote_profile_generation: 7,
            punch_generation: 1,
            socket_index,
            socket_local_endpoint,
        };
        assert!(
            udp.tag_hard_hard_socket(
                &identity.peer_id,
                identity.socket_index,
                &identity.session_token,
            )
            .await
        );
        let now = hard_hard_now_ms();
        assert!(
            peers
                .hard_hard_register_session(crate::peer::HardHardSessionRecord {
                    pair_nomination: None,
                    coordinated_plan: strategy.map(|strategy| {
                        crate::peer::HardHardCoordinatedPlan {
                            measurement_lease: None,
                            recovery_identity: None,
                            strategy_order: 0,
                            local_offer: crate::peer::HardHardOfferParameters::default(),
                            remote_offer: None,
                            local_registration_seq: 1,
                            remote_registration_seq: 1,
                            phase: false,
                            canonical_server_deadline: now.saturating_add(5_000),
                            scheduled_start: Instant::now() + Duration::from_secs(5),
                            forecast_first_send_deadline: Instant::now() + Duration::from_secs(5),
                            agreement: Some(crate::peer::HardHardAgreedPlan {
                                strategy,
                                digest: [1; 16],
                            }),
                            ready_received: false,
                            ready_ack_received: false,
                            ready_sent_at: None,
                            ready_retransmitted: false,
                            ready_rtt: None,
                            sync_uncertainty: Duration::ZERO,
                            start: None,
                            start_ack_received: false,
                            start_ack_queued: false,
                            start_ack_delivery: None,
                        }
                    }),
                    session_id: session_id.to_string(),
                    probe_session_id: Some("probe-session-exact".to_string()),
                    session_token: identity.session_token.clone(),
                    peer_id: identity.peer_id.clone(),
                    initiator: true,
                    remote_network_generation: 0,
                    local_network_generation: identity.network_generation,
                    remote_candidate_epoch: identity.remote_candidate_epoch,
                    local_profile_generation: identity.local_profile_generation,
                    remote_profile_generation: identity.remote_profile_generation,
                    local_prediction_confidence: 90,
                    remote_prediction_confidence: 90,
                    requested_birthday_level: if birthday { 64 } else { 0 },
                    generated_candidate_count: if birthday { 64 } else { 1 },
                    signaled_candidate_count: 1,
                    birthday,
                    requested_socket_indices: if birthday {
                        vec![socket_index, socket_index + 1]
                    } else {
                        vec![socket_index]
                    },
                    requested_socket_count: if birthday { 2 } else { 1 },
                    prediction_window: vec![remote],
                    remote_prediction: vec![remote],
                    fresh_socket: identity.clone(),
                    punch_at_ms: if birthday {
                        now
                    } else {
                        now.saturating_add(5_000)
                    },
                    expires_at_ms: now.saturating_add(30_000),
                    state: crate::peer::HardHardSessionState::AwaitingPeer,
                    attempt_count: 0,
                    measurement: crate::peer::HardHardMeasurementObservation::default(),
                    created_at: Instant::now(),
                    cancellation: Arc::new(crate::PunchSessionCancellation::default()),
                })
                .await
        );
        (peers, udp, identity, remote)
    }

    #[tokio::test]
    async fn hard_hard_exact_proof_rejects_peer_global_direct_on_other_socket() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let other_local: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let commit_before = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(other_local),
                )
                .await
        );
        assert!(peers.is_direct(&identity.peer_id).await);
        assert_ne!(
            peers.direct_commit_seq_sync(&identity.peer_id),
            commit_before,
            "the competing ordinary Direct path must have a distinct commit"
        );
        assert!(udp.hard_hard_socket_identity_is_current(&identity).await);
        assert!(
            udp.hard_hard_socket_identity_has_authenticated_evidence(&identity)
                .await
        );
        assert!(
            !hard_hard_exact_direct_confirmation_is_current(&udp, &peers, &identity).await,
            "peer-global Direct on another local socket must not be Hard↔Hard success"
        );
        let events = peers.diagnostics().await[0].direct_events.clone();
        assert!(
            !events
                .iter()
                .any(|event| event.stage == "hard_hard_sweep_completed"),
            "a competing Direct path must not create a Hard↔Hard success event"
        );
        udp.detach_all_dynamic_punch_sockets("test_exact_proof")
            .await;
    }

    #[tokio::test]
    async fn hard_hard_exact_proof_requires_selected_pair_and_authenticated_evidence() {
        let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
        let (peers, udp, identity, remote) = exact_socket_proof_fixture().await;
        let commit_before = peers.direct_commit_seq_sync(&identity.peer_id);
        assert!(
            peers
                .record_direct_success_for_generation_with_local_endpoint(
                    &identity.peer_id,
                    Some(remote),
                    identity.network_generation,
                    Some(identity.socket_local_endpoint),
                )
                .await
        );
        assert_ne!(
            peers.direct_commit_seq_sync(&identity.peer_id),
            commit_before,
            "the exact Direct confirmation must advance the existing commit sequence"
        );
        assert!(
            peers
                .direct_commit_pair_snapshot_sync(&identity.peer_id)
                .and_then(|snapshot| snapshot.confirmed_at_ms)
                .is_some(),
            "the Direct commit transaction must snapshot its actual process-local validation time"
        );
        assert!(
            hard_hard_exact_direct_confirmation_is_current(&udp, &peers, &identity).await,
            "selected pair, current generations, affinity, and authenticated evidence must agree"
        );
        assert!(udp.hard_hard_socket_identity_is_current(&identity).await);
        let (data_socket_index, data_socket) = udp
            .socket_for_peer(Some(&identity.peer_id))
            .await
            .expect("the proven Hard↔Hard socket must remain the data socket");
        assert_eq!(data_socket_index, identity.socket_index);
        assert_eq!(
            data_socket.local_addr().unwrap(),
            identity.socket_local_endpoint
        );
        let selection = peers
            .select_path_for_data(&identity.peer_id, true, true)
            .await;
        assert_eq!(selection.path, Some(crate::peer::NetworkPath::Direct));
        assert!(selection.direct_confirmed);

        let mut mismatched_peer = identity.clone();
        mismatched_peer.peer_id = "peer-other".to_string();
        let mut mismatched_token = identity.clone();
        mismatched_token.session_token = "retired-token".to_string();
        let mut mismatched_network = identity.clone();
        mismatched_network.network_generation += 1;
        let mut mismatched_candidate_epoch = identity.clone();
        mismatched_candidate_epoch.remote_candidate_epoch += 1;
        let mut mismatched_local_profile = identity.clone();
        mismatched_local_profile.local_profile_generation += 1;
        let mut mismatched_remote_profile = identity.clone();
        mismatched_remote_profile.remote_profile_generation += 1;
        let mut mismatched_punch = identity.clone();
        mismatched_punch.punch_generation += 1;
        let mut mismatched_index = identity.clone();
        mismatched_index.socket_index += 1;
        let mut mismatched_endpoint = identity.clone();
        mismatched_endpoint.socket_local_endpoint = SocketAddr::new(
            identity.socket_local_endpoint.ip(),
            identity.socket_local_endpoint.port().wrapping_add(1),
        );
        for mismatched in [
            mismatched_peer,
            mismatched_token,
            mismatched_network,
            mismatched_candidate_epoch,
            mismatched_local_profile,
            mismatched_remote_profile,
            mismatched_punch,
            mismatched_index,
            mismatched_endpoint,
        ] {
            assert!(
                !hard_hard_exact_direct_confirmation_is_current(&udp, &peers, &mismatched).await,
                "every HardHardFreshSocketIdentity field must be authoritative"
            );
        }
        udp.detach_all_dynamic_punch_sockets("test_exact_proof")
            .await;
    }

    #[test]
    fn coordination_envelope_round_trips_directional_fences() {
        let offer = HardHardCoordination {
            v2: None,
            role: HardHardRole::Initiator,
            token: "deadbeef01".to_string(),
            local_network_generation: 7,
            remote_candidate_epoch: 11,
            local_profile_generation: 13,
            remote_profile_generation: 19,
            local_prediction_confidence: 83,
            remote_prediction_confidence: 0,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "unknown".to_string(),
            remote_network_generation: 0,
        };
        let encoded = offer.encode();
        assert!(encoded.len() < 128);
        assert_eq!(HardHardCoordination::parse(&encoded), Some(offer));

        let response = HardHardCoordination::parse(&encoded)
            .expect("encoded offer must parse")
            .as_response(
                crate::peer::HardHardPlanSnapshot {
                    local_network_generation: 23,
                    remote_candidate_epoch: 23,
                    local_profile_generation: 29,
                    remote_profile_generation: 13,
                },
                71,
                "small_window".to_string(),
            );
        assert_eq!(response.role, HardHardRole::Responder);
        assert_eq!(response.token, "deadbeef01");
        assert_eq!(response.local_network_generation, 23);
        assert_eq!(response.remote_candidate_epoch, 23);
        assert_eq!(response.local_profile_generation, 29);
        assert_eq!(response.remote_profile_generation, 13);
        assert_eq!(response.local_prediction_confidence, 71);
        assert_eq!(response.remote_prediction_confidence, 83);
        assert_eq!(
            HardHardCoordination::parse(&response.encode()),
            Some(response)
        );
    }

    #[test]
    fn malformed_or_oversized_session_envelopes_fail_closed() {
        assert!(!HardHardCoordination::looks_like("peer-session"));
        assert!(HardHardCoordination::parse("hh1:x:token:1:2:1:2").is_none());
        assert!(HardHardCoordination::parse("hh1:i:not*hex:1:2:1:2").is_none());
        assert!(
            HardHardCoordination::parse(&format!("hh1:i:{}:1:2:1:2", "a".repeat(33))).is_none()
        );
        assert!(HardHardCoordination::parse("hh1:i:token:1:2:1:2:bad").is_none());
        assert!(HardHardCoordination::parse("hh1:i:token:1:2:1:2:1:2:extra").is_none());
    }

    #[test]
    fn session_fence_requires_all_generation_domains_to_match() {
        let expected = crate::peer::HardHardPlanSnapshot {
            local_network_generation: 4,
            remote_candidate_epoch: 9,
            local_profile_generation: 12,
            remote_profile_generation: 12,
        };
        assert!(hard_hard_plan_matches(expected, expected));
        for changed in [
            crate::peer::HardHardPlanSnapshot {
                local_network_generation: 5,
                ..expected
            },
            crate::peer::HardHardPlanSnapshot {
                remote_candidate_epoch: 10,
                ..expected
            },
            crate::peer::HardHardPlanSnapshot {
                local_profile_generation: 5,
                ..expected
            },
            crate::peer::HardHardPlanSnapshot {
                remote_profile_generation: 13,
                ..expected
            },
        ] {
            assert!(!hard_hard_plan_matches(expected, changed));
        }
    }

    #[test]
    fn coordination_round_trip_exchanges_both_network_generations() {
        let offer = HardHardCoordination {
            v2: None,
            role: HardHardRole::Initiator,
            token: "a1b2c3".to_string(),
            local_network_generation: 17,
            remote_candidate_epoch: 23,
            local_profile_generation: 29,
            remote_profile_generation: 31,
            local_prediction_confidence: 91,
            remote_prediction_confidence: 0,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "unknown".to_string(),
            remote_network_generation: 0,
        };
        let response = offer.as_response(
            crate::peer::HardHardPlanSnapshot {
                local_network_generation: 41,
                remote_candidate_epoch: 43,
                local_profile_generation: 47,
                remote_profile_generation: 29,
            },
            88,
            "high_entropy".to_string(),
        );
        assert_eq!(response.local_network_generation, 41);
        assert_eq!(response.remote_network_generation, 17);
        assert_eq!(response.remote_prediction_confidence, 91);
        assert_eq!(
            HardHardCoordination::parse(&response.encode()),
            Some(response)
        );
    }

    #[test]
    fn fixed_step_models_drive_unequal_stride_cross_sweeps() {
        fn model_window(start: u16, step: u16) -> Vec<u16> {
            let local = "0.0.0.0:41000".parse().unwrap();
            let observations = (0..4)
                .map(|sequence| p2pnet_nat::mapping::MappingObservation {
                    sequence,
                    observer: SocketAddr::new("192.0.2.1".parse().unwrap(), 3478 + sequence),
                    observed: SocketAddr::new(
                        "198.51.100.10".parse().unwrap(),
                        start.wrapping_add(step.wrapping_mul(sequence)),
                    ),
                    sent_at_ms: 1_000 + u64::from(sequence) * 10,
                    responded_at_ms: 1_005 + u64::from(sequence) * 10,
                    local_endpoint: local,
                })
                .collect();
            let batch = p2pnet_nat::mapping::MappingBatch {
                generation: 7,
                network_generation: 3,
                socket_identity: local,
                observations,
                started_at_ms: 1_000,
                finished_at_ms: 1_100,
            };
            let model =
                p2pnet_nat::mapping::build_model_for_batch(&batch, Duration::from_secs(5), 1_100)
                    .expect("the deterministic APDM sequence must model");
            p2pnet_nat::mapping::predict_ports(&model, start.wrapping_add(step * 3))
                .into_iter()
                .map(|candidate| candidate.port)
                .collect()
        }

        let a_window = model_window(30_000, 4);
        let b_window = model_window(40_000, 3);
        assert!(a_window.contains(&30_016));
        assert!(b_window.contains(&40_012));
        // Each side sweeps the other side's actual fresh window; no common
        // stride or equal window length is assumed by the coordinator.
        assert!(!a_window.is_empty() && !b_window.is_empty());

        let a_plus_one = model_window(50_000, 1);
        let b_plus_seven = model_window(55_000, 7);
        assert!(a_plus_one.contains(&50_004));
        assert!(b_plus_seven.contains(&55_028));
    }

    #[test]
    fn prediction_windows_and_punch_time_are_bounded_at_udp_edges() {
        let local = "0.0.0.0:41001".parse().unwrap();
        let observations = (0..4)
            .map(|sequence| p2pnet_nat::mapping::MappingObservation {
                sequence,
                observer: SocketAddr::new("192.0.2.2".parse().unwrap(), 4000 + sequence),
                observed: SocketAddr::new(
                    "198.51.100.11".parse().unwrap(),
                    65_520u16.wrapping_add(4 * sequence),
                ),
                sent_at_ms: 2_000 + u64::from(sequence),
                responded_at_ms: 2_001 + u64::from(sequence),
                local_endpoint: local,
            })
            .collect();
        let batch = p2pnet_nat::mapping::MappingBatch {
            generation: 8,
            network_generation: 4,
            socket_identity: local,
            observations,
            started_at_ms: 2_000,
            finished_at_ms: 2_010,
        };
        let model =
            p2pnet_nat::mapping::build_model_for_batch(&batch, Duration::from_secs(5), 2_010)
                .unwrap();
        let window = p2pnet_nat::mapping::predict_ports(&model, 65_532);
        assert!(!window.iter().any(|candidate| candidate.port == 0));
        assert_eq!(window.first().map(|candidate| candidate.port), Some(4));

        let now = 10_000;
        assert!(hard_hard_punch_window_is_usable(now, now + 1_300));
        // A modest ±50ms scheduling jitter stays inside the bounded window;
        // an expired punch deadline does not.
        assert!(hard_hard_punch_window_is_usable(now + 50, now + 1_301));
        assert_eq!(
            hard_hard_punch_window(now, now + 1_250),
            HardHardPunchWindow::TooSoon
        );
        assert_eq!(
            hard_hard_punch_window(now, now + 1_251),
            HardHardPunchWindow::Usable
        );
        assert_eq!(
            hard_hard_punch_window(now, now + HARD_HARD_SESSION_TTL.as_millis() as u64 + 1),
            HardHardPunchWindow::BeyondFreshLifetime
        );
        assert!(!hard_hard_punch_window_is_usable(
            now,
            now + HARD_HARD_SESSION_TTL.as_millis() as u64 + 1
        ));
    }

    #[tokio::test]
    async fn session_ledger_supersedes_old_token_and_cleans_up_100_cycles() {
        fn record(
            peer_id: &str,
            token: &str,
            cancellation: Arc<crate::PunchSessionCancellation>,
        ) -> crate::peer::HardHardSessionRecord {
            let endpoint = "0.0.0.0:41002".parse().unwrap();
            let identity = crate::peer::HardHardFreshSocketIdentity {
                peer_id: peer_id.to_string(),
                session_token: token.to_string(),
                network_generation: 1,
                remote_candidate_epoch: 2,
                local_profile_generation: 3,
                remote_profile_generation: 4,
                punch_generation: 5,
                socket_index: 4_096,
                socket_local_endpoint: endpoint,
            };
            crate::peer::HardHardSessionRecord {
                pair_nomination: None,
                coordinated_plan: None,
                session_id: format!("hh1:i:{token}:1:2:3:4:90:0:0"),
                probe_session_id: None,
                session_token: token.to_string(),
                peer_id: peer_id.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: 1,
                remote_candidate_epoch: 2,
                local_profile_generation: 3,
                remote_profile_generation: 4,
                local_prediction_confidence: 90,
                remote_prediction_confidence: 0,
                requested_birthday_level: 0,
                generated_candidate_count: 1,
                signaled_candidate_count: 1,
                birthday: false,
                requested_socket_indices: vec![4_096],
                requested_socket_count: 1,
                prediction_window: vec!["198.51.100.1:40000".parse().unwrap()],
                remote_prediction: Vec::new(),
                fresh_socket: identity,
                punch_at_ms: hard_hard_now_ms() + 3_000,
                expires_at_ms: hard_hard_now_ms() + 45_000,
                state: crate::peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                measurement: crate::peer::HardHardMeasurementObservation::default(),
                created_at: Instant::now(),
                cancellation,
            }
        }

        let manager = crate::peer::PeerManager::new(
            crate::Config::generate_default("https://ctrl.test", "hard-hard-tests").unwrap(),
        );
        let first_cancel = Arc::new(crate::PunchSessionCancellation::default());
        assert!(
            manager
                .hard_hard_register_session(record(
                    "peer-session-ledger",
                    "a1",
                    first_cancel.clone()
                ))
                .await
        );
        assert!(
            manager
                .hard_hard_session_token_is_current("peer-session-ledger", "a1")
                .await
        );
        assert_eq!(
            manager
                .hard_hard_prepare_response("peer-session-ledger", "a1", 3)
                .await,
            crate::peer::HardHardResponseAdmission::Ready
        );
        let rebound = manager
            .hard_hard_session_by_token("peer-session-ledger", "a1")
            .await
            .expect("the live initiator session must survive its one expected remote epoch");
        assert_eq!(rebound.remote_candidate_epoch, 3);
        assert_eq!(rebound.fresh_socket.remote_candidate_epoch, 3);
        assert!(manager
            .hard_hard_begin_sweep(
                "peer-session-ledger",
                "a1",
                vec!["198.51.100.2:40000".parse().unwrap()],
                90,
                1,
            )
            .await
            .is_some());
        assert_eq!(
            manager
                .hard_hard_prepare_response("peer-session-ledger", "a1", 3)
                .await,
            crate::peer::HardHardResponseAdmission::AlreadySweeping
        );

        let second_cancel = Arc::new(crate::PunchSessionCancellation::default());
        assert!(
            manager
                .hard_hard_register_session(record(
                    "peer-session-ledger",
                    "b2",
                    second_cancel.clone()
                ))
                .await
        );
        assert!(first_cancel.is_cancelled());
        assert!(
            !manager
                .hard_hard_session_token_is_current("peer-session-ledger", "a1")
                .await
        );
        assert!(
            manager
                .hard_hard_session_token_is_current("peer-session-ledger", "b2")
                .await
        );

        for index in 0..100u64 {
            let token = format!("{index:x}");
            let cancellation = Arc::new(crate::PunchSessionCancellation::default());
            assert!(
                manager
                    .hard_hard_register_session(
                        record("peer-session-ledger", &token, cancellation,)
                    )
                    .await
            );
        }
        manager
            .clear_hard_hard_sessions(Some("peer-session-ledger"))
            .await;
        assert!(
            !manager
                .hard_hard_session_is_active("peer-session-ledger")
                .await
        );
        assert!(second_cancel.is_cancelled());
    }

    include!("failure_class_tests.rs");
}
