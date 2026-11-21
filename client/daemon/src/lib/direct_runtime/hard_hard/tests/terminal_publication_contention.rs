// These controls hold the real manager locks around one original, sealed
// report. They prove publication ownership, not physical sweep execution;
// the existing two-peer 30-second gate still owns the latter evidence.

#[derive(Clone, Copy)]
enum TerminalPublicationCase {
    ProfileReleased,
    SessionReleased,
    ProfileExpired,
    SessionExpired,
    SharedDeadline,
    RetiredWhileContended,
}

struct TerminalPublicationEvidence {
    first_pending: bool,
    all_transaction_guards_released: bool,
    second_pending: Option<bool>,
    original_deadline_pending: Option<bool>,
    committed: bool,
    elapsed: Duration,
    expected: crate::peer::HardHardAttemptReport,
    current: Vec<crate::peer::HardHardAttemptReport>,
    archived: Option<crate::peer::HardHardAttemptReport>,
    summaries: Vec<crate::connection_timeline::HardHardTerminalSummary>,
    second_commit: bool,
    retired: Option<bool>,
}

async fn exercise_terminal_publication_contention(case: TerminalPublicationCase) {
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;

    let _serial = crate::tests::HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    // Setup, original 100 ms transaction and failure cleanup share this one
    // fixture bound. No spawned test task or fresh cleanup deadline is added.
    let fixture_end = tokio::time::Instant::now() + Duration::from_secs(1);
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "terminal-publication-proof").unwrap(),
    ));
    peers.set_timeline(crate::connection_timeline::ConnectionTimeline::new(
        "terminal-publication-proof",
        0,
    ));
    // This report-only fixture deliberately starts no transport reader,
    // watcher, cleanup worker or test task. The socket is owned outside every
    // fallible setup/body await, and is closed before any result assertion.
    let mut socket = None;
    let body = AssertUnwindSafe(tokio::time::timeout_at(fixture_end, async {
        socket = Some(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_endpoint = socket.as_ref().unwrap().local_addr().unwrap();
        let identity = admit_terminal_publication_record(&peers, local_endpoint).await;
        let record = peers
            .hard_hard_session_by_token(&identity.peer_id, &identity.session_token)
            .await
            .expect("the original exact ledger must own this observation");
        let expected = report_for_observation_fixture(&record);
        let archive = HardHardTerminalArchiveCapture::default();
        let mut profile = if matches!(
            case,
            TerminalPublicationCase::ProfileReleased
                | TerminalPublicationCase::ProfileExpired
                | TerminalPublicationCase::SharedDeadline
                | TerminalPublicationCase::RetiredWhileContended
        ) {
            Some(peers.hold_local_nat_profile_writer_for_test().await)
        } else {
            None
        };
        let mut sessions = if matches!(
            case,
            TerminalPublicationCase::SessionReleased
                | TerminalPublicationCase::SessionExpired
                | TerminalPublicationCase::SharedDeadline
        ) {
            Some(peers.hold_hard_hard_session_writer_for_test().await)
        } else {
            None
        };
        let original_start = tokio::time::Instant::now();
        let mut commit = Box::pin(
            peers
                .record_hard_hard_attempt_report_with_evidence(
                    &identity.peer_id,
                    &identity.session_token,
                    expected.clone(),
                    &record.measurement.evidence,
                )
                .with_subscriber(tracing_subscriber::registry().with(archive.clone())),
        );
        let first = futures_util::poll!(commit.as_mut());
        let first_pending = first.is_pending();
        let epoch_gate = peers.network_epoch_gate();
        // These successful real acquisitions prove that no transaction
        // epoch/connections guard survives the contention yield. For session
        // contention, the transaction's profile reader must be released too.
        let epoch_released = epoch_gate.try_lock().is_ok();
        let connections_released = peers
            .hold_connections_writer_for_test()
            .now_or_never()
            .is_some();
        let profile_released = profile.is_some()
            || peers
                .hold_local_nat_profile_writer_for_test()
                .now_or_never()
                .is_some();
        let mut second_pending = None;
        let mut original_deadline_pending = None;
        let mut retired = None;
        let committed = match first {
            std::task::Poll::Ready(committed) => committed,
            std::task::Poll::Pending => {
                match case {
                    TerminalPublicationCase::ProfileReleased
                    | TerminalPublicationCase::SessionReleased => {
                        tokio::time::advance(Duration::from_millis(99)).await;
                        drop(profile.take());
                        drop(sessions.take());
                    }
                    TerminalPublicationCase::ProfileExpired
                    | TerminalPublicationCase::SessionExpired => {
                        // Keep the original offending guard held through the
                        // transaction's original deadline, not a test sleep.
                        tokio::time::advance(Duration::from_millis(100)).await;
                    }
                    TerminalPublicationCase::SharedDeadline => {
                        tokio::time::advance(Duration::from_millis(60)).await;
                        drop(profile.take());
                        let second = futures_util::poll!(commit.as_mut());
                        second_pending = Some(second.is_pending());
                        if let std::task::Poll::Ready(committed) = second {
                            drop(sessions.take());
                            return terminal_publication_evidence(
                                &peers,
                                &identity,
                                &record,
                                expected,
                                &archive,
                                first_pending,
                                epoch_released && connections_released && profile_released,
                                second_pending,
                                original_deadline_pending,
                                committed,
                                original_start.elapsed(),
                                retired,
                            )
                            .await;
                        }
                        tokio::time::advance(Duration::from_millis(40)).await;
                        let at_deadline = futures_util::poll!(commit.as_mut());
                        original_deadline_pending = Some(at_deadline.is_pending());
                        if let std::task::Poll::Ready(committed) = at_deadline {
                            // A completed original future is never polled
                            // again, even under a faulty implementation.
                            drop(sessions.take());
                            return terminal_publication_evidence(
                                &peers,
                                &identity,
                                &record,
                                expected,
                                &archive,
                                first_pending,
                                epoch_released && connections_released && profile_released,
                                second_pending,
                                original_deadline_pending,
                                committed,
                                original_start.elapsed(),
                                retired,
                            )
                            .await;
                        }
                        // A wrongly restarted deadline must become an
                        // observable wrong commit, not a paused-time spin
                        // holding this guard until the outer test times out.
                        // No new time or fixture budget is granted.
                        drop(sessions.take());
                    }
                    TerminalPublicationCase::RetiredWhileContended => {
                        retired = Some(
                            peers
                                .hard_hard_retire_session(
                                    &identity.peer_id,
                                    &record.session_id,
                                    &identity.session_token,
                                )
                                .await,
                        );
                        drop(profile.take());
                    }
                }
                commit.await
            }
        };
        let elapsed = original_start.elapsed();
        drop(profile);
        drop(sessions);
        terminal_publication_evidence(
            &peers,
            &identity,
            &record,
            expected,
            &archive,
            first_pending,
            epoch_released && connections_released && profile_released,
            second_pending,
            original_deadline_pending,
            committed,
            elapsed,
            retired,
        )
        .await
    }))
    .catch_unwind()
    .await;

    // Both timeout and panic drop the borrowed body/transaction first. Revoke
    // the original ledger and then close the external socket. There are no
    // hidden reader/watcher handles whose abort could be mistaken for a join.
    let cleanup = tokio::time::timeout_at(fixture_end, async {
        peers.clear_hard_hard_sessions(None).await;
    })
    .await;
    drop(socket.take());
    let socket_closed = socket.is_none();
    eprintln!(
        "terminal_publication_owned_cleanup: original_ledger_revoked={} external_socket_closed={} spawned_reader_watcher_test_tasks=0 original_fixture_end_unchanged=true",
        cleanup.is_ok(), socket_closed,
    );
    let evidence = match body {
        Ok(Ok(evidence)) => evidence,
        Ok(Err(error)) => panic!(
            "original publication fixture timed out after cleanup: {error}; cleanup={cleanup:?}"
        ),
        Err(payload) => {
            if cleanup.is_err() {
                eprintln!("terminal publication panic cleanup failed: {cleanup:?}");
            }
            std::panic::resume_unwind(payload);
        }
    };
    assert!(cleanup.is_ok(), "cleanup={cleanup:?}");
    assert!(socket_closed);
    assert!(
        evidence.first_pending,
        "a genuine held original lock must be pending"
    );
    assert!(
        evidence.all_transaction_guards_released,
        "no original transaction guard may cross the contention yield"
    );
    assert!(
        !evidence.second_commit,
        "the original evidence must seal only once"
    );
    match case {
        TerminalPublicationCase::ProfileReleased | TerminalPublicationCase::SessionReleased => {
            assert!(
                evidence.committed,
                "released current owner must commit its complete typed report"
            );
            assert_eq!(evidence.elapsed, Duration::from_millis(99));
            assert_eq!(evidence.current, vec![evidence.expected]);
            assert!(evidence.archived.is_none());
            assert_eq!(evidence.summaries.len(), 1);
            assert!(evidence.summaries[0].current_connection_committed);
            assert!(evidence.summaries[0].archive_reason.is_none());
        }
        TerminalPublicationCase::ProfileExpired
        | TerminalPublicationCase::SessionExpired
        | TerminalPublicationCase::SharedDeadline => {
            assert!(!evidence.committed);
            assert_eq!(evidence.elapsed, Duration::from_millis(100));
            assert!(evidence.current.is_empty());
            assert_eq!(evidence.archived, Some(evidence.expected));
            assert_eq!(evidence.summaries.len(), 1);
            assert!(!evidence.summaries[0].current_connection_committed);
            let reason = if matches!(case, TerminalPublicationCase::ProfileExpired) {
                "profile_publication_contended"
            } else {
                "session_publication_contended"
            };
            assert_eq!(
                evidence.summaries[0].archive_reason.as_deref(),
                Some(reason)
            );
            if matches!(case, TerminalPublicationCase::SharedDeadline) {
                assert_eq!(
                    evidence.original_deadline_pending,
                    Some(false),
                    "the original future must finish at the shared 100 ms boundary"
                );
                assert_eq!(
                    evidence.second_pending,
                    Some(true),
                    "the second actual lock must consume the same transaction budget"
                );
            }
        }
        TerminalPublicationCase::RetiredWhileContended => {
            assert_eq!(evidence.retired, Some(true));
            assert!(
                !evidence.committed,
                "identity must be checked again after contention"
            );
            assert!(evidence.current.is_empty());
            assert_eq!(evidence.archived, Some(evidence.expected));
            assert_eq!(evidence.summaries.len(), 1);
            assert!(!evidence.summaries[0].current_connection_committed);
            assert_eq!(
                evidence.summaries[0].archive_reason.as_deref(),
                Some("terminal_identity_superseded")
            );
        }
    }
}

async fn admit_terminal_publication_record(
    peers: &PeerManager,
    local_endpoint: SocketAddr,
) -> crate::peer::HardHardFreshSocketIdentity {
    let remote: SocketAddr = "198.51.100.20:41000".parse().unwrap();
    let peer_id = "terminal-publication-peer";
    peers.add_peer(&crate::control::PeerInfo {
        capabilities: crate::control::PeerCapabilities::default(),
        registration_seq: 0,
        node_id: peer_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: remote.to_string(),
        nat_type: "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown;g=7".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }).await;
    let sources = HashMap::from([(remote.to_string(), "stun_observed".to_string())]);
    peers
        .add_candidates_with_sources(peer_id, &[remote.to_string()], &sources)
        .await;
    assert!(
        peers
            .bind_remote_nat_profile_to_candidate_epoch(peer_id, 7)
            .await
    );
    let identity = crate::peer::HardHardFreshSocketIdentity {
        peer_id: peer_id.to_string(),
        session_token: "terminal-publication-token".to_string(),
        network_generation: peers.current_network_generation_sync(),
        remote_candidate_epoch: peers.current_remote_candidate_epoch(peer_id).await.unwrap(),
        local_profile_generation: peers.current_local_profile_generation_sync(),
        remote_profile_generation: 7,
        punch_generation: 1,
        // A report-only slot label; it is not a registered dynamic UDP reader
        // and is never used to send, validate or commit a Direct path.
        socket_index: 4096,
        socket_local_endpoint: local_endpoint,
    };
    let now = hard_hard_now_ms();
    assert!(
        peers
            .hard_hard_register_session(HardHardSessionRecord {
                pair_nomination: None,
                coordinated_plan: None,
                session_id: "terminal-publication-session".to_string(),
                probe_session_id: None,
                session_token: identity.session_token.clone(),
                peer_id: peer_id.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: identity.network_generation,
                remote_candidate_epoch: identity.remote_candidate_epoch,
                local_profile_generation: identity.local_profile_generation,
                remote_profile_generation: identity.remote_profile_generation,
                local_prediction_confidence: 90,
                remote_prediction_confidence: 90,
                requested_birthday_level: 0,
                generated_candidate_count: 1,
                signaled_candidate_count: 1,
                birthday: false,
                requested_socket_indices: vec![identity.socket_index],
                requested_socket_count: 1,
                prediction_window: vec![remote],
                remote_prediction: vec![remote],
                fresh_socket: identity.clone(),
                punch_at_ms: now.saturating_add(5_000),
                expires_at_ms: now.saturating_add(30_000),
                state: crate::peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                measurement: crate::peer::HardHardMeasurementObservation::default(),
                created_at: Instant::now(),
                cancellation: Arc::new(crate::PunchSessionCancellation::default()),
            })
            .await
    );
    identity
}

#[allow(clippy::too_many_arguments)]
async fn terminal_publication_evidence(
    peers: &PeerManager,
    identity: &crate::peer::HardHardFreshSocketIdentity,
    record: &HardHardSessionRecord,
    expected: crate::peer::HardHardAttemptReport,
    archive: &HardHardTerminalArchiveCapture,
    first_pending: bool,
    all_transaction_guards_released: bool,
    second_pending: Option<bool>,
    original_deadline_pending: Option<bool>,
    committed: bool,
    elapsed: Duration,
    retired: Option<bool>,
) -> TerminalPublicationEvidence {
    let second_commit = peers
        .record_hard_hard_attempt_report_with_evidence(
            &identity.peer_id,
            &identity.session_token,
            expected.clone(),
            &record.measurement.evidence,
        )
        .await;
    let current = peers
        .diagnostics()
        .await
        .into_iter()
        .filter(|peer| peer.node_id == identity.peer_id)
        .flat_map(|peer| peer.direct_events)
        .filter_map(|event| event.hard_hard_attempt)
        .collect();
    TerminalPublicationEvidence {
        first_pending,
        all_transaction_guards_released,
        second_pending,
        original_deadline_pending,
        committed,
        elapsed,
        expected,
        current,
        archived: archive.0.lock().unwrap().clone(),
        summaries: peers.hard_hard_terminal_summaries_for_test(),
        second_commit,
        retired,
    }
}

#[tokio::test(start_paused = true)]
async fn hard_hard_terminal_profile_contention_releases_and_commits_once() {
    exercise_terminal_publication_contention(TerminalPublicationCase::ProfileReleased).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_terminal_session_contention_releases_and_commits_once() {
    exercise_terminal_publication_contention(TerminalPublicationCase::SessionReleased).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_terminal_profile_contention_archives_at_original_deadline() {
    exercise_terminal_publication_contention(TerminalPublicationCase::ProfileExpired).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_terminal_session_contention_archives_at_original_deadline() {
    exercise_terminal_publication_contention(TerminalPublicationCase::SessionExpired).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_terminal_profile_then_session_share_original_deadline() {
    exercise_terminal_publication_contention(TerminalPublicationCase::SharedDeadline).await;
}

#[tokio::test(start_paused = true)]
async fn hard_hard_terminal_retirement_during_contention_rejects_current_report() {
    exercise_terminal_publication_contention(TerminalPublicationCase::RetiredWhileContended).await;
}
