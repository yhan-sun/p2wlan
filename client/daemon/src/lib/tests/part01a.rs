use super::*;
use p2pnet_relay::{Frame, RelayMessage, RelayServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn test_daemon_creation() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let _daemon = Daemon::new(config);
}

#[test]
fn test_daemon_creation_manual_mode() {
    let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    config.network.manual = true;
    config.control.auth_token = "present-but-ignored".to_string();
    // Must not attempt control-plane registration even with a token.
    let _daemon = Daemon::new(config);
}

#[test]
fn only_applied_candidate_only_signals_start_synchronized_punch() {
    assert!(candidate_signal_starts_synchronized_punch(
        &[],
        CandidateSetApplyResult::Applied
    ));
    assert!(!candidate_signal_starts_synchronized_punch(
        &[],
        CandidateSetApplyResult::IgnoredEmpty
    ));
    assert!(!candidate_signal_starts_synchronized_punch(
        &[],
        CandidateSetApplyResult::IgnoredStale
    ));
    assert!(!candidate_signal_starts_synchronized_punch(
        &[],
        CandidateSetApplyResult::IgnoredExpired
    ));
    assert!(!candidate_signal_starts_synchronized_punch(
        &[],
        CandidateSetApplyResult::PeerMissing
    ));
    assert!(candidate_signal_starts_synchronized_punch(
        &[1],
        CandidateSetApplyResult::IgnoredStale
    ));
}

#[tokio::test]
async fn candidate_snapshot_reader_observes_only_committed_tuple() {
    let daemon = Daemon::new(
        Config::generate_default("http://127.0.0.1:1", "net1").unwrap(),
    );
    let candidates = vec!["192.168.1.20:40000".to_string()];
    let sources = HashMap::from([("192.168.1.20:40000".to_string(), "host".to_string())]);
    daemon
        .publish_candidate_snapshot(
            candidates.clone(),
            sources.clone(),
            vec!["host:192.168.1.20".to_string()],
        )
        .await;

    let (read_candidates, read_sources) = daemon.current_local_candidate_set().await;
    assert_eq!(read_candidates, candidates);
    assert_eq!(read_sources, sources);
    let snapshot = daemon.cached_candidate_snapshot().await.unwrap();
    assert_eq!(snapshot.network_identity, vec!["host:192.168.1.20".to_string()]);
    assert_eq!(snapshot.hash, candidate_set_hash(&read_candidates, &read_sources));
}

#[tokio::test]
async fn peer_reflexive_candidate_refreshes_the_committed_snapshot() {
    let daemon = Daemon::new(
        Config::generate_default("http://127.0.0.1:1", "net1").unwrap(),
    );
    let initial = vec!["198.51.100.10:40000".to_string()];
    let initial_sources = HashMap::from([(
        initial[0].clone(),
        "stun_observed".to_string(),
    )]);
    daemon
        .publish_candidate_snapshot(
            initial.clone(),
            initial_sources.clone(),
            vec!["public:198.51.100.10".to_string()],
        )
        .await;

    assert!(daemon.add_local_peer_reflexive_candidate("198.51.100.11:40001").await);

    let snapshot = daemon
        .cached_candidate_snapshot()
        .await
        .expect("peer-reflexive update must publish a new snapshot");
    assert!(snapshot
        .candidates
        .contains(&"198.51.100.11:40001".to_string()));
    assert_eq!(
        snapshot
            .candidate_sources
            .get("198.51.100.11:40001")
            .map(String::as_str),
        Some("peer_reflexive")
    );
    assert_eq!(snapshot.network_identity, vec!["public:198.51.100.10".to_string()]);
    assert!(snapshot.version > 1, "the update must advance snapshot version");
    assert_ne!(snapshot.hash, candidate_set_hash(&initial, &initial_sources));
}

#[tokio::test]
async fn punch_attempt_deduplicator_allows_only_one_short_window_per_peer() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let peer_a = deduplicator.claim("peer-a").await.unwrap();
    assert!(deduplicator.claim("peer-a").await.is_none());
    let _peer_b = deduplicator.claim("peer-b").await.unwrap();
    assert_eq!(deduplicator.active_session_count(), 2);

    drop(peer_a);
    let _peer_a_replacement = deduplicator.claim("peer-a").await.unwrap();
}

#[tokio::test]
async fn punch_attempt_deduplicator_lets_synchronized_punch_override_background() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let background = deduplicator
        .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
        .await
        .unwrap();
    let synchronized = deduplicator
        .claim("peer-a")
        .await
        .expect("synchronized punch should preempt a background retry");
    assert!(background.is_cancelled());
    assert!(
        deduplicator
            .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
            .await
            .is_none(),
        "background retry should not preempt an active synchronized punch"
    );
    assert!(deduplicator.claim("peer-a").await.is_none());
    assert_eq!(deduplicator.active_session_count(), 1);

    drop(background);
    assert_eq!(deduplicator.active_session_count(), 1);
    drop(synchronized);
    assert_eq!(deduplicator.active_session_count(), 0);
}

#[tokio::test]
async fn same_epoch_candidate_refresh_preserves_scheduled_rendezvous_permit() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let scheduled_at = unix_time_millis() + 600;
    let first = match deduplicator
        .claim_for_epoch_with_rendezvous(
            "peer-a",
            17,
            3,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(scheduled_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(permit) => permit,
        RendezvousPunchClaim::Deferred(_) => panic!("first rendezvous must claim"),
    };

    // A same-generation ordinary offer/candidate refresh is useful input, but
    // must never cancel and re-clock the already synchronized first window.
    let refresh = deduplicator
        .claim_for_epoch_with_rendezvous(
            "peer-a",
            17,
            3,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(scheduled_at + 400),
        )
        .await;
    let RendezvousPunchClaim::Deferred(deferred) = refresh else {
        panic!("same epoch refresh must merge into the active rendezvous");
    };
    assert_eq!(deferred.reason, PunchClaimDeferredReason::SameEpochActive);
    assert_eq!(deferred.active_session_id, first.session_id());
    assert_eq!(deferred.active_network_generation, 17);
    assert_eq!(deferred.active_epoch, 3);
    assert_eq!(deferred.active_punch_at_ms, Some(scheduled_at));
    assert!(
        !first.is_cancelled(),
        "same epoch candidate refresh must preserve the scheduled first window"
    );
}

#[tokio::test]
async fn fresh_prediction_inside_rendezvous_lead_preserves_first_window() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let scheduled_at = unix_time_millis() + RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64;
    let first = match deduplicator
        .claim_for_epoch_with_rendezvous(
            "peer-a",
            17,
            3,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(scheduled_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(permit) => permit,
        RendezvousPunchClaim::Deferred(_) => panic!("first rendezvous must claim"),
    };
    let fresh_id = FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation: 42,
    };

    let fresh = deduplicator
        .claim_for_epoch_with_rendezvous(
            "peer-a",
            17,
            3,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            Some(fresh_id),
            Some(scheduled_at + 400),
        )
        .await;
    let RendezvousPunchClaim::Deferred(deferred) = fresh else {
        panic!("fresh prediction inside the lead must defer behind first send");
    };
    assert_eq!(
        deferred.reason,
        PunchClaimDeferredReason::RendezvousLeadProtected
    );
    assert_eq!(deferred.active_session_id, first.session_id());
    assert!(
        !first.is_cancelled(),
        "fresh prediction must not cancel a first rendezvous in its lead window"
    );
}

#[tokio::test]
async fn generation_change_can_replace_protected_rendezvous_with_reason() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let scheduled_at = unix_time_millis() + RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64;
    let first = match deduplicator
        .claim_for_epoch_with_rendezvous(
            "peer-a",
            17,
            3,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(scheduled_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(permit) => permit,
        RendezvousPunchClaim::Deferred(_) => panic!("first rendezvous must claim"),
    };

    let replacement = deduplicator
        .claim_for_epoch_with_rendezvous(
            "peer-a",
            18,
            4,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(scheduled_at + 400),
        )
        .await;
    assert!(matches!(replacement, RendezvousPunchClaim::Claimed(_)));
    assert!(first.is_cancelled(), "new network generation must replace old plan");
    assert_eq!(
        first.cancellation_reason(),
        Some(PunchCancellationReason::NetworkGenerationChanged)
    );
}

#[tokio::test]
async fn punch_attempt_deduplicator_fresh_prediction_preempts_older_sessions() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let boot: u64 = 1_742_987_654_321;
    let id = |generation| FreshPredictionId {
        boot_epoch: boot,
        generation,
    };
    let background = deduplicator
        .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
        .await
        .unwrap();
    let synchronized = deduplicator
        .claim("peer-a")
        .await
        .expect("synchronized punch should preempt a background retry");
    assert!(background.is_cancelled());

    let fresh = deduplicator
        .claim_fresh_prediction("peer-a", id(41))
        .await
        .expect("fresh prediction should preempt an ordinary synchronized punch");
    assert!(synchronized.is_cancelled());
    assert!(
        deduplicator.claim("peer-a").await.is_none(),
        "ordinary punch must not preempt an active fresh-prediction session"
    );
    assert!(
        deduplicator
            .claim_fresh_prediction("peer-a", id(41))
            .await
            .is_none(),
        "an equal-generation fresh prediction must not duplicate the session"
    );

    let newer = deduplicator
        .claim_fresh_prediction("peer-a", id(42))
        .await
        .expect("a newer fresh prediction should supersede an older one");
    assert!(fresh.is_cancelled());
    drop(newer);
    assert_eq!(deduplicator.active_session_count(), 0);

    // A newer daemon incarnation supersedes the old incarnation's session.
    let old_incarnation = FreshPredictionId {
        boot_epoch: boot,
        generation: 99,
    };
    let new_incarnation = FreshPredictionId {
        boot_epoch: boot + 1,
        generation: 1,
    };
    let old_boot_session = deduplicator
        .claim_fresh_prediction("peer-a", old_incarnation)
        .await
        .expect("old incarnation session claims");
    let new_boot_session = deduplicator
        .claim_fresh_prediction("peer-a", new_incarnation)
        .await
        .expect("a restarted daemon incarnation must supersede the old one");
    assert!(old_boot_session.is_cancelled());
    assert!(
        deduplicator
            .claim_fresh_prediction("peer-a", old_incarnation)
            .await
            .is_none(),
        "the old incarnation's late session must not preempt the new incarnation"
    );
    drop(new_boot_session);
    assert_eq!(deduplicator.active_session_count(), 0);
}

#[tokio::test]
async fn punch_attempt_deduplicator_cancel_releases_session_for_rejoin() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let permit = deduplicator.claim("peer-a").await.unwrap();
    assert!(deduplicator.claim("peer-a").await.is_none());

    // Peer leaves and rejoins quickly: the stale session must be cancelled
    // and released so the rejoin is not suppressed.
    deduplicator.cancel("peer-a");
    assert!(permit.is_cancelled());
    assert_eq!(deduplicator.active_session_count(), 0);
    let _rejoin = deduplicator
        .claim("peer-a")
        .await
        .expect("rejoin punch must not be suppressed by the stale session");
}

#[test]
fn fresh_prediction_from_sources_parses_incarnation_and_rejects_conflicts() {
    let boot: u64 = 1_742_987_654_321;
    let label = |generation: u64| {
        fresh_prediction_source_label(FreshPredictionId {
            boot_epoch: boot,
            generation,
        })
    };
    let mut sources = HashMap::new();
    assert_eq!(fresh_prediction_from_sources(&sources), Ok(None));

    // Ordinary ICE gathering emits plain "predicted" labels: not a signal.
    sources.insert("203.0.113.10:40001".to_string(), "predicted".to_string());
    assert_eq!(fresh_prediction_from_sources(&sources), Ok(None));

    // A genuinely fresh prediction carries incarnation + generation.
    sources.insert("203.0.113.10:40002".to_string(), label(39));
    assert_eq!(
        fresh_prediction_from_sources(&sources),
        Ok(Some(FreshPredictionId {
            boot_epoch: boot,
            generation: 39,
        }))
    );

    // A second identical label does not conflict.
    sources.insert("203.0.113.10:40003".to_string(), label(39));
    assert_eq!(
        fresh_prediction_from_sources(&sources),
        Ok(Some(FreshPredictionId {
            boot_epoch: boot,
            generation: 39,
        }))
    );

    // Two different valid labels are inconsistent: deterministic rejection.
    sources.insert("203.0.113.10:40004".to_string(), label(40));
    assert_eq!(fresh_prediction_from_sources(&sources), Err(()));

    // Generation 0 is a legacy/unknown signal: degrade to ordinary and never
    // claim fresh priority.
    let mut zero_sources = HashMap::new();
    zero_sources.insert(
        "203.0.113.10:40005".to_string(),
        format!("{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}{boot}:0"),
    );
    assert_eq!(fresh_prediction_from_sources(&zero_sources), Ok(None));

    // Malformed labels are ignored (old single-number labels included).
    let mut malformed = HashMap::new();
    malformed.insert(
        "203.0.113.10:40006".to_string(),
        format!("{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}garbage"),
    );
    assert_eq!(fresh_prediction_from_sources(&malformed), Ok(None));
    malformed.insert(
        "203.0.113.10:40007".to_string(),
        format!("{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}39"),
    );
    assert_eq!(fresh_prediction_from_sources(&malformed), Ok(None));

    // The canonical label round-trips and stays under the 64-byte wire bound.
    let canonical = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: u64::MAX,
        generation: u64::MAX,
    });
    assert_eq!(
        crate::parse_fresh_prediction_source_label(&canonical),
        Some(FreshPredictionId {
            boot_epoch: u64::MAX,
            generation: u64::MAX,
        })
    );
    assert!(canonical.len() <= 64);
}

#[tokio::test]
async fn start_hole_punch_waits_for_local_candidates_before_state_change() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let remote_endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: remote_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    *daemon.udp_transport.write().await = Some(udp);

    daemon.start_hole_punch_at("node-b", None, None, None).await;

    let conn = daemon.peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.direct_health.failure_count, 0);
    assert!(conn.direct_events.iter().any(|event| {
        event.stage == "punch_delayed_local_candidates_not_ready"
            && event.candidate_count == Some(0)
    }));
}

#[test]
fn relay_assisted_punch_starts_slightly_before_advertised_time() {
    let punch_at_ms = unix_time_millis() + RELAY_ASSISTED_PUNCH_DELAY.as_millis() as u64;

    let delay = relay_assisted_punch_delay(Some(punch_at_ms));

    assert!(delay <= RELAY_ASSISTED_PUNCH_DELAY - RELAY_ASSISTED_PUNCH_LEAD);
    assert!(
        delay >= RELAY_ASSISTED_PUNCH_DELAY - RELAY_ASSISTED_PUNCH_LEAD - Duration::from_millis(50)
    );
}

#[test]
fn direct_fast_probe_window_preserves_candidate_order_and_is_bounded() {
    let candidates = (0..32)
        .map(|port| format!("198.51.100.10:{port}").parse::<SocketAddr>().unwrap())
        .chain(std::iter::once("198.51.100.10:7".parse().unwrap()))
        .collect::<Vec<_>>();

    let selected = direct_fast_probe_candidates(&candidates);

    assert_eq!(selected.len(), DIRECT_FAST_PROBE_MAX_CANDIDATES);
    assert_eq!(selected, candidates[..DIRECT_FAST_PROBE_MAX_CANDIDATES]);
    assert_eq!(
        selected.iter().collect::<HashSet<_>>().len(),
        DIRECT_FAST_PROBE_MAX_CANDIDATES
    );
}

#[test]
fn direct_fast_probe_skips_rendezvous_dependent_target_sets() {
    assert!(direct_fast_probe_is_safe(false, false));
    assert!(!direct_fast_probe_is_safe(true, false));
    assert!(!direct_fast_probe_is_safe(false, true));
    assert!(!direct_fast_probe_is_safe(true, true));
}

#[tokio::test]
async fn encrypted_direct_validation_uses_observed_endpoint_and_wireguard_session() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(local_identity, remote_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(remote_identity, None);
    let (response, remote_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let local_keys = initiator.consume_response(&response).unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(responder.initiator_public_key().unwrap()),
            endpoint: observed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    transport
        .add_session("node-b", TransportSession::new(local_keys))
        .await;

    run_direct_encrypted_validation(
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint,
        },
        udp,
        peers.clone(),
        transport,
        "10.20.0.1",
    )
    .await;

    let mut datagram = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(1),
        remote_socket.recv_from(&mut datagram),
    )
    .await
    .unwrap()
    .unwrap();
    let mut remote_session = TransportSession::new(remote_keys);
    let decrypted = remote_session.decrypt_from_bytes(&datagram[..len]).unwrap();
    let packet = Ipv4Packet::new(&decrypted).unwrap();
    assert_eq!(packet.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(packet.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
    // The first datagram is the daemon-internal validation REQUEST: it
    // carries the request payload prefix plus the token (generation, request
    // id, sequence), never the plain echo payload of the old design.
    let token = parse_direct_validation_token(&decrypted).unwrap();
    assert_eq!(token.kind, DirectValidationKind::Request);
    assert_eq!(token.generation, 0);
    assert_eq!(token.sequence, 0);
    assert_ne!(
        token.owner_token, 0,
        "every validation request must carry its nonzero session owner token"
    );
    // `payload()` here is the whole ICMP datagram (header + data): the
    // request prefix sits after the 8-byte ICMP header.
    assert!(packet
        .payload()
        .get(8..)
        .is_some_and(|data| data.starts_with(DIRECT_VALIDATION_REQUEST_PAYLOAD)));

    let diagnostics = peers.diagnostics().await;
    let validation_session_id = diagnostics[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "direct_validation_started")
        .and_then(|event| event.validation_session_id);
    assert!(validation_session_id.is_some(), "validation start must expose its owner session");
    assert!(diagnostics[0].direct_events.iter().any(|event| {
        event.stage == "direct_validation_request_sent"
            && event.network_generation == 0
            && event.validation_session_id == validation_session_id
    }));
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_sent" && event.sent_probes == Some(3)));
    assert!(diagnostics[0].direct_events.iter().any(|event| {
        event.stage == "direct_validation_timed_out"
            && event.network_generation == 0
            && event.validation_session_id == validation_session_id
            && event.sent_probes == Some(3)
    }));
}

#[tokio::test]
async fn encrypted_direct_validation_waits_for_delayed_wireguard_session() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(local_identity, remote_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(remote_identity, None);
    let (response, remote_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let local_keys = initiator.consume_response(&response).unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(responder.initiator_public_key().unwrap()),
            endpoint: observed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    let session_transport = transport.clone();
    let validation_peers = peers.clone();

    let validation = tokio::spawn(async move {
        run_direct_encrypted_validation(
            PeerReflexiveObservation {
                peer_id: "node-b".to_string(),
                observed_endpoint,
            },
            udp,
            validation_peers,
            transport,
            "10.20.0.1",
        )
        .await;
    });
    sleep(Duration::from_millis(125)).await;
    session_transport
        .add_session("node-b", TransportSession::new(local_keys))
        .await;
    validation.await.unwrap();

    let mut datagram = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(1),
        remote_socket.recv_from(&mut datagram),
    )
    .await
    .unwrap()
    .unwrap();
    let mut remote_session = TransportSession::new(remote_keys);
    let decrypted = remote_session.decrypt_from_bytes(&datagram[..len]).unwrap();
    let packet = Ipv4Packet::new(&decrypted).unwrap();
    assert_eq!(packet.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(packet.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));

    let diagnostics = peers.diagnostics().await;
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_waiting_for_session"));
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_session_ready"));
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_sent" && event.sent_probes == Some(3)));
}

#[tokio::test]
async fn encrypted_validation_cancellation_keeps_lease_generation_and_owner_in_diagnostics() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let observed_endpoint: SocketAddr = "127.0.0.1:45801".parse().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-validation-cancel".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: observed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    let worker_peers = peers.clone();
    let worker = tokio::spawn(async move {
        run_direct_encrypted_validation(
            PeerReflexiveObservation {
                peer_id: "node-validation-cancel".to_string(),
                observed_endpoint,
            },
            udp,
            worker_peers,
            transport,
            "10.20.0.1",
        )
        .await;
    });

    let owner = timeout(Duration::from_secs(1), async {
        loop {
            if let Some(owner) = peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == "node-validation-cancel")
                .and_then(|peer| {
                    peer.direct_events
                        .iter()
                        .find(|event| event.stage == "direct_validation_started")
                        .and_then(|event| event.validation_session_id)
                })
            {
                break owner;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("validation worker must publish its owner before waiting for WireGuard");

    assert_eq!(peers.advance_network_generation("test validation cancellation").await, 1);
    timeout(Duration::from_secs(1), worker)
        .await
        .expect("generation advance must wake the validation worker")
        .unwrap();

    let diagnostics = peers.diagnostics().await;
    let events = &diagnostics
        .iter()
        .find(|peer| peer.node_id == "node-validation-cancel")
        .expect("peer must remain visible after generation advance")
        .direct_events;
    assert!(events.iter().any(|event| {
        event.stage == "direct_validation_cancelled"
            && event.network_generation == 0
            && event.validation_session_id == Some(owner)
            && event.detail.contains("owner was revoked")
    }));
    assert!(!events.iter().any(|event| {
        event.stage == "direct_validation_timed_out"
            && event.network_generation == 0
            && event.validation_session_id == Some(owner)
    }));
}

#[tokio::test]
async fn direct_probe_loop_waits_for_local_candidates_before_background_retry() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: remote_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let udp_transport = Arc::new(RwLock::new(Some(udp)));
    let local_candidates = Arc::new(RwLock::new(Vec::new()));

    let probe_task = tokio::spawn(run_direct_probe_loop(
        peers.clone(),
        udp_transport,
        local_candidates.clone(),
        Arc::new(RwLock::new(None)),
        PunchAttemptDeduplicator::default(),
        ControlClient::disabled_for_test(),
        Arc::new(RwLock::new(Vec::new())),
        Arc::new(RwLock::new(Duration::from_millis(50))),
        1_742_987_654_321,
        Duration::from_millis(20),
        Duration::from_millis(5),
        1,
    ));

    sleep(Duration::from_millis(80)).await;
    let diagnostics = peers.diagnostics().await;
    assert_eq!(diagnostics[0].direct.failure_count, 0);
    assert!(!diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "retry_punch_started"));

    local_candidates
        .write()
        .await
        .push("127.0.0.1:50000".to_string());

    let mut observed_probe_targets_due = false;
    for _ in 0..20 {
        if peers.diagnostics().await[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "retry_punch_started")
        {
            observed_probe_targets_due = true;
            break;
        }
        sleep(Duration::from_millis(25)).await;
    }

    probe_task.abort();
    let _ = probe_task.await;
    assert!(observed_probe_targets_due);
}

#[tokio::test]
async fn relay_validation_sends_encrypted_probe_through_relay() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(local_identity, remote_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(remote_identity, None);
    let (response, remote_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let local_keys = initiator.consume_response(&response).unwrap();

    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(responder.initiator_public_key().unwrap()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers)
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    transport
        .add_session("node-b", TransportSession::new(local_keys))
        .await;

    send_relay_validation_packet(
        RelayValidationPacket {
            peer_id: "node-b",
            peer_virtual_ip: "10.20.0.2",
            local_ip: Ipv4Addr::new(10, 20, 0, 1),
            peer_ip: Ipv4Addr::new(10, 20, 0, 2),
            validation_id: 7,
            sequence: 1,
        },
        &transport,
        &relay_a,
    )
    .await
    .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    let RelayMessage::Data { from_node, data } = received else {
        panic!("Expected relay Data message");
    };
    assert_eq!(from_node, "node-a");

    let mut remote_session = TransportSession::new(remote_keys);
    let decrypted = remote_session.decrypt_from_bytes(&data).unwrap();
    let packet = Ipv4Packet::new(&decrypted).unwrap();
    assert_eq!(packet.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(packet.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
    let icmp_payload = packet.payload();
    assert!(icmp_payload[8..].starts_with(b"p2wlan-relay-validation"));
    assert_eq!(
        icmp_payload[8 + b"p2wlan-relay-validation".len()..].len(),
        8
    );

    server.shutdown().await;
}

#[tokio::test]
async fn encrypted_direct_validation_skips_when_direct_is_already_confirmed() {
    let remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(remote_identity.public_key()),
            endpoint: observed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers
        .record_direct_success("node-b", Some(observed_endpoint))
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();

    run_direct_encrypted_validation(
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint,
        },
        udp,
        peers.clone(),
        transport,
        "10.20.0.1",
    )
    .await;

    let mut datagram = vec![0u8; 2048];
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        remote_socket.recv_from(&mut datagram)
    )
    .await
    .is_err());

    let diagnostics = peers.diagnostics().await;
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| { event.stage == "encrypted_trial_skipped" && event.sent_probes == Some(0) }));
    assert!(!diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_sent" && event.sent_probes == Some(0)));
}

#[tokio::test]
async fn scheduled_hole_punch_skips_direct_peer_even_with_live_candidates() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = remote_socket.local_addr().unwrap();
    let candidates = vec![endpoint.to_string()];
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers.add_candidates("node-b", &candidates).await;
    peers.record_direct_success("node-b", Some(endpoint)).await;
    assert!(peers.is_direct("node-b").await);
    // Frozen targets bypass candidate resolution entirely (fresh-prediction
    // sessions): even then the Direct gate must stop the task before any
    // probe is sent, otherwise every late fresh signal would scan a
    // confirmed path.
    let frozen = Some(vec![endpoint]);

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        "node-b".to_string(),
        Duration::from_millis(10),
        2,
        None,
        None,
        None,
        frozen,
    )
    .await;

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn
                .direct_events
                .iter()
                .any(|event| event.stage == "punch_skipped_already_direct")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scheduled hole punch must skip a Direct peer even with live candidates");

    let conn = peers.get_connection("node-b").await.unwrap();
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "punch_started"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "punch_probes_sent"));
    assert_eq!(conn.state, ConnectionState::Direct);

    // Nothing may have been emitted toward the peer endpoint.
    let mut buf = [0u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), remote_socket.recv_from(&mut buf))
            .await
            .is_err(),
        "a Direct peer must not receive synchronized punch probes"
    );
}

#[tokio::test]
async fn scheduled_hole_punch_skips_without_degrading_already_direct_peer() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers.record_direct_success("node-b", Some(endpoint)).await;
    assert!(peers.is_direct("node-b").await);

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        "node-b".to_string(),
        Duration::from_millis(10),
        1,
        None,
        None,
        None,
        None,
    )

    .await;

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn
                .direct_events
                .iter()
                .any(|event| event.stage == "punch_skipped_already_direct")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scheduled hole punch did not skip the already-direct peer");

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert!(conn.direct_health.last_error.is_none());
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == REASON_DIRECT_PROBE_FAILED));
}

#[tokio::test]
async fn scheduled_hole_punch_ack_timeout_keeps_retrying_without_degrading() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let unused_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = unused_socket.local_addr().unwrap();
    drop(unused_socket);
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers
        .update_state("node-b", ConnectionState::HolePunching)
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_socket_pool(3)
        .await
        .unwrap();
    udp.set_socket_pool_active(true);
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        "node-b".to_string(),
        Duration::from_millis(10),
        1,
        None,
        None,
        None,
        None,
    )

    .await;

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn
                .direct_events
                .iter()
                .any(|event| event.stage == "punch_ack_timeout")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scheduled hole punch did not record ACK timeout");

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::HolePunching);
    assert_eq!(conn.direct_health.failure_count, 0);
    assert!(conn.direct_health.last_error.is_none());
    let active_pool_scan = conn
        .direct_events
        .iter()
        .find(|event| event.stage == "active_pool_scan_completed")
        .expect("scheduled hole punch should use the active socket pool");
    assert_eq!(active_pool_scan.probe_tx_socket0_count, Some(1));
    assert_eq!(active_pool_scan.probe_tx_alt_socket_count, Some(2));
    assert!(active_pool_scan
        .detail
        .contains("scan_socket_policy=active_pool"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "primary_socket_scan_completed"));
    let timeout = conn
        .direct_events
        .iter()
        .find(|event| event.stage == "punch_ack_timeout")
        .expect("scheduled hole punch should record ACK timeout");
    assert!(timeout
        .detail
        .contains("known_peer_ip_rx_delta="));
    assert!(timeout
        .detail
        .contains("authenticated_probe_ack_observed_delta="));
    assert!(timeout.detail.contains("matched_probe_ack_rx_delta="));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == REASON_DIRECT_PROBE_FAILED));
}

#[tokio::test]
async fn suppressed_same_epoch_offer_stashes_latest_targets_without_reclocking_first_window() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let initial_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let refreshed_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let initial_endpoint = initial_socket.local_addr().unwrap();
    let refreshed_endpoint = refreshed_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: initial_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers
        .add_candidates("node-b", &[initial_endpoint.to_string()])
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let deduplicator = PunchAttemptDeduplicator::default();
    let first_punch_at = unix_time_millis() + 2_000;
    spawn_hole_punch_task(
        udp.clone(),
        peers.clone(),
        deduplicator.clone(),
        "node-b".to_string(),
        Duration::from_millis(10),
        1,
        Some(first_punch_at),
        None,
        None,
        None,
    )
    .await;

    // This models a newer trusted offer arriving before the first rendezvous.
    // It changes the target set but must not replace/re-clock the active
    // session; it is stashed for that same owner's dispatch instead.
    peers
        .add_candidates("node-b", &[refreshed_endpoint.to_string()])
        .await;
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        deduplicator,
        "node-b".to_string(),
        Duration::from_millis(10),
        1,
        Some(first_punch_at + 500),
        None,
        None,
        None,
    )
    .await;

    let pending = peers
        .take_recovery_target("node-b")
        .await
        .expect("suppressed same-epoch offer must stash its trusted target");
    assert_eq!(pending.candidates, vec![refreshed_endpoint]);
    assert!(
        pending.punch_at_ms.is_none(),
        "the active rendezvous owns its original punch_at and must not be re-clocked"
    );

    let conn = peers.get_connection("node-b").await.unwrap();
    let preserved = conn
        .direct_events
        .iter()
        .find(|event| event.stage == "punch_window_preserved")
        .expect("the preserved rendezvous must be visible in diagnostics");
    assert!(preserved.detail.contains("reason=same_epoch_active_session"));
    assert!(preserved
        .detail
        .contains(&format!("active_punch_at_ms=Some({first_punch_at})")));
    assert!(preserved.detail.contains("candidate_snapshot_hash="));
    assert!(preserved.detail.contains("candidate_source_counts="));
}

#[tokio::test]
async fn start_hole_punch_skipped_for_healthy_confirmed_direct() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let remote_endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: remote_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    daemon
        .peers
        .add_candidates_with_sources(
            "node-b",
            &[remote_endpoint.to_string()],
            &HashMap::from([(remote_endpoint.to_string(), "stun_observed".to_string())]),
        )
        .await;
    daemon
        .peers
        .record_direct_success("node-b", Some(remote_endpoint))
        .await;

    daemon
        .local_candidates
        .write()
        .await
        .push(remote_endpoint.to_string());
    daemon
        .local_candidate_sources
        .write()
        .await
        .insert(remote_endpoint.to_string(), "stun_observed".to_string());

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    *daemon.udp_transport.write().await = Some(udp);

    assert!(daemon
        .peers
        .should_defer_relay_assisted_punch("node-b")
        .await);
    daemon.start_hole_punch_at("node-b", None, None, None).await;
    daemon.start_hole_punch_at("node-b", None, None, None).await;

    let conn = daemon.peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "punch_scheduled"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "punch_suppressed"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "punch_delayed_local_candidates_not_ready"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "punch_skipped_already_direct"));
}

#[tokio::test]
async fn stale_fresh_signal_never_pollutes_candidate_set_end_to_end() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let remote_endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: remote_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let boot = 1_742_987_654_321u64;
    let label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot,
        generation: 1,
    });
    let candidates = vec!["203.0.113.10:45393".to_string()];
    let sources = HashMap::from([("203.0.113.10:45393".to_string(), label.clone())]);

    // First (accepted) fresh signal installs its candidates.
    daemon
        .control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: "node-b".to_string(),
            candidates: candidates.clone(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: sources.clone(),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: None,
        })
        .unwrap();

    let peers = daemon.peers.clone();
    let control = daemon.control.clone();
    let (net_tx, _net_rx) = mpsc::channel(64);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let handle = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, net_tx)
            .await;
    });
    // Let the event loop process the first offer.
    let peer_conn = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn.candidates.contains(&"203.0.113.10:45393".to_string()) {
                break conn;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first fresh signal candidates must be applied");
    assert!(peer_conn.candidate_sources.contains_key("203.0.113.10:45393"));

    // A stale (older generation) fresh signal arrives late: its candidates
    // must NOT replace the current set.
    let stale_label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot - 1,
        generation: 40,
    });
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: "node-b".to_string(),
            candidates: vec!["198.51.100.9:44444".to_string()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([(
                "198.51.100.9:44444".to_string(),
                stale_label.clone(),
            )]),
            candidate_generation: 2,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: None,
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .unwrap()
                .direct_events
                .iter()
                .any(|event| event.stage == "fresh_prediction_stale")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the stale signal must be observed and rejected");
    let conn = peers.get_connection("node-b").await.unwrap();
    assert!(
        conn.candidates.contains(&"203.0.113.10:45393".to_string()),
        "the current candidate set must survive the stale signal"
    );
    assert!(
        !conn.candidates.contains(&"198.51.100.9:44444".to_string()),
        "stale signal candidates must never pollute the candidate set"
    );

    // An inconsistent signal (two different fresh labels) is also rejected.
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: "node-b".to_string(),
            candidates: vec![
                "198.51.100.9:44445".to_string(),
                "198.51.100.9:44446".to_string(),
            ],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([
                (
                    "198.51.100.9:44445".to_string(),
                    fresh_prediction_source_label(FreshPredictionId {
                        boot_epoch: boot,
                        generation: 2,
                    }),
                ),
                (
                    "198.51.100.9:44446".to_string(),
                    fresh_prediction_source_label(FreshPredictionId {
                        boot_epoch: boot,
                        generation: 3,
                    }),
                ),
            ]),
            candidate_generation: 3,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: None,
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .unwrap()
                .direct_events
                .iter()
                .any(|event| event.stage == "fresh_prediction_inconsistent")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the inconsistent signal must be observed and rejected");
    let conn = peers.get_connection("node-b").await.unwrap();
    assert!(
        !conn.candidates.contains(&"198.51.100.9:44445".to_string())
            && !conn.candidates.contains(&"198.51.100.9:44446".to_string()),
        "inconsistent signal candidates must never be applied"
    );

    handle.abort();
}

/// A fresh prediction whose candidates fail to apply must NOT consume the
/// fresh identity: an expired candidate set is rejected without committing,
/// the same signal retried with a valid set applies and commits, and a retry
/// of the committed identity is idempotent.
#[tokio::test]
async fn fresh_prediction_not_applied_keeps_identity_and_retry_commits() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let boot = 1_742_987_654_321u64;
    let label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot,
        generation: 1,
    });
    let id = FreshPredictionId {
        boot_epoch: boot,
        generation: 1,
    };
    let fresh_candidates = vec!["203.0.113.10:45393".to_string()];
    let fresh_sources = HashMap::from([("203.0.113.10:45393".to_string(), label.clone())]);

    let peers = daemon.peers.clone();
    let control = daemon.control.clone();
    let (net_tx, _net_rx) = mpsc::channel(64);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let handle = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, net_tx)
            .await;
    });
    let send_offer = |control: &ControlClient, expires_at_ms: Option<u64>| {
        control
            .event_sender()
            .send(ControlEvent::PeerOffer {
                from_node_id: "node-b".to_string(),
                candidates: fresh_candidates.clone(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: fresh_sources.clone(),
                candidate_generation: 1,
                candidates_expires_at_ms: expires_at_ms,
                handshake_init: Vec::new(),
                punch_at_ms: None,
                punch_at_server_ms: None,
                sender_public_key: None,
            })
            .unwrap();
    };

    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: "203.0.113.10:51820".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    // 1. An already-expired candidate set is rejected: the identity must stay
    // unconsumed (prepare still sees it as new).
    send_offer(&control, Some(1));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .is_some_and(|conn| {
                    conn.direct_events
                        .iter()
                        .any(|event| event.stage == "fresh_prediction_not_applied")
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the expired apply must be recorded as fresh_prediction_not_applied");
    assert_eq!(
        peers
            .prepare_remote_fresh_prediction(
                "node-b",
                id,
                &fresh_candidates,
                &fresh_sources,
                Some(1),
            )
            .await,
        crate::peer::RemoteFreshAdmission::Accepted,
        "a failed apply must never consume the fresh identity"
    );

    // 2. The same identity retried with a valid candidate set applies and
    // commits.
    send_offer(&control, None);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .is_some_and(|conn| conn.candidates.contains(&"203.0.113.10:45393".to_string()))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the retried fresh candidates must be applied");
    assert_eq!(
        peers
            .prepare_remote_fresh_prediction(
                "node-b",
                id,
                &fresh_candidates,
                &fresh_sources,
                None,
            )
            .await,
        crate::peer::RemoteFreshAdmission::AlreadyRecorded,
        "the retry must commit the identity"
    );

    // 3. An idempotent retry of the committed identity starts no re-apply.
    // The offer-ingress dedup window (2s) suppresses the byte-identical
    // payload first; after the window the retry reaches the fresh
    // transaction's AlreadyRecorded path.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    send_offer(&control, None);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .is_some_and(|conn| {
                    conn.direct_events
                        .iter()
                        .any(|event| event.stage == "fresh_prediction_retry")
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the idempotent retry must be observed");
    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(
        conn.candidates
            .iter()
            .filter(|candidate| *candidate == &"203.0.113.10:45393".to_string())
            .count(),
        1,
        "an idempotent retry must never duplicate candidates"
    );

    handle.abort();
}

/// A fresh prediction for a peer that is not (yet) registered fails to apply
/// with PeerMissing and must NOT consume the identity: a later signal with the
/// same identity is still admitted.
#[tokio::test]
async fn fresh_prediction_for_missing_peer_keeps_identity() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let id = FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation: 1,
    };
    let label = fresh_prediction_source_label(id);
    let peers = daemon.peers.clone();
    let control = daemon.control.clone();
    let (net_tx, _net_rx) = mpsc::channel(64);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let handle = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, net_tx)
            .await;
    });
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: "node-b".to_string(),
            candidates: vec!["203.0.113.10:45393".to_string()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([("203.0.113.10:45393".to_string(), label)]),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: None,
        })
        .unwrap();
    // Give the event loop a deterministic window to process the offer.
    sleep(Duration::from_millis(150)).await;
    assert_eq!(
        peers
            .prepare_remote_fresh_prediction(
                "node-b",
                id,
                &["203.0.113.10:45393".to_string()],
                &HashMap::from([(
                    "203.0.113.10:45393".to_string(),
                    fresh_prediction_source_label(id),
                )]),
                None,
            )
            .await,
        crate::peer::RemoteFreshAdmission::Accepted,
        "PeerMissing must never consume the fresh identity"
    );
    handle.abort();
}

/// The frozen fresh target snapshot is an immutable value: once captured it
/// never changes, even when a later ordinary refresh updates the shared
/// candidate set.
#[tokio::test]
async fn frozen_fresh_target_snapshot_survives_later_ordinary_refresh() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: "203.0.113.10:51820".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    // Commit the fresh identity with its immutable snapshot, then freeze the
    // fresh signal's own candidates from THAT snapshot.
    let id = FreshPredictionId {
        boot_epoch: 1_742_987_654_321,
        generation: 1,
    };
    let candidates = vec![
        "203.0.113.10:45393".to_string(),
        "203.0.113.10:45394".to_string(),
    ];
    let sources = HashMap::from([
        (
            "203.0.113.10:45393".to_string(),
            fresh_prediction_source_label(id),
        ),
        ("203.0.113.10:45394".to_string(), "predicted".to_string()),
    ]);
    assert!(matches!(
        daemon
            .peers
            .prepare_remote_fresh_prediction("node-b", id, &candidates, &sources, None)
            .await,
        crate::peer::RemoteFreshAdmission::Accepted
    ));
    assert_eq!(
        daemon
            .peers
            .apply_remote_fresh_candidates("node-b", id, &candidates, &sources, 1, None)
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(daemon.peers.commit_remote_fresh_prediction("node-b", id).await);
    let frozen = daemon
        .freeze_fresh_punch_targets("node-b", id)
        .await
        .expect("the committed fresh snapshot must freeze");
    assert_eq!(
        frozen,
        vec!["203.0.113.10:45393".parse::<SocketAddr>().unwrap()],
        "ordinary predicted candidates in a fresh signal must not expand the frozen fresh window"
    );

    // An ordinary refresh replaces the shared candidate set entirely.
    daemon
        .peers
        .add_candidates_with_metadata(
            "node-b",
            &["198.51.100.9:44444".to_string()],
            &HashMap::from([("198.51.100.9:44444".to_string(), "predicted".to_string())]),
            10,
            None,
        )
        .await;

    // The shared set moved on...
    let after = daemon.peers.direct_probe_targets_for("node-b").await;
    assert_eq!(after, vec!["198.51.100.9:44444".parse::<SocketAddr>().unwrap()]);
    // ...but the frozen snapshot still targets exactly the fresh window.
    assert_eq!(frozen, vec!["203.0.113.10:45393".parse::<SocketAddr>().unwrap()]);
}
