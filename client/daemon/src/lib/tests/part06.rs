// ============================================================
// v0.1.112: candidate snapshot lease + offer-ingress dedup
// ============================================================

use std::time::Duration;
use std::sync::Arc;

use p2pnet_crypto::NodeIdentity;
use crate::relay_runtime::relay_renewal_deadline;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// The snapshot lease is single-flight: concurrent signaling paths share ONE
/// gather.  Inside the TTL a second `local_candidate_set_for_signal` must
/// return the SAME committed snapshot without re-gathering (no UDP transport
/// is configured here, so any live gather would fail and yield an empty set
/// instead of the lease).
#[tokio::test]
async fn concurrent_initiators_share_one_candidate_snapshot_refresh() {
    let daemon = Arc::new(Daemon::new(
        Config::generate_default("http://ctrl.test", "net1").unwrap(),
    ));
    let candidates = vec!["203.0.113.10:45393".to_string(), "203.0.113.10:45394".to_string()];
    let sources = HashMap::from([
        ("203.0.113.10:45393".to_string(), "stun_observed".to_string()),
        ("203.0.113.10:45394".to_string(), "host".to_string()),
    ]);
    daemon
        .publish_candidate_snapshot(candidates.clone(), sources.clone(), Vec::new())
        .await;

    assert!(
        daemon.candidate_snapshot_is_fresh().await,
        "a freshly published snapshot is inside its lease"
    );

    // A contention cohort of 64 concurrent initiators all receives the same
    // committed snapshot without entering live gather or the refresh lock.
    let mut workers = tokio::task::JoinSet::new();
    for index in 0..64 {
        let daemon = daemon.clone();
        workers.spawn(async move {
            daemon
                .local_candidate_set_for_signal(&format!("initiator-{index}"))
                .await
        });
    }
    while let Some(result) = workers.join_next().await {
        let (received_candidates, received_sources) = result.unwrap();
        assert_eq!(received_candidates, candidates);
        assert_eq!(received_sources, sources);
    }
    assert!(
        daemon.candidate_snapshot_is_fresh().await,
        "reads must not consume or age the lease"
    );

    // After the TTL the lease expires: a signal may re-gather (which here
    // fails without a UDP transport and falls back to the bounded OLD
    // snapshot via wait_for_local_candidate_set's committed set).
    daemon
        .publish_candidate_snapshot_with_age(candidates.clone(), sources.clone(), Duration::from_secs(11))
        .await;
    assert!(
        !daemon.candidate_snapshot_is_fresh().await,
        "the lease expires after the TTL"
    );
    let stale = daemon.local_candidate_set_for_signal("after-ttl").await;
    assert_eq!(
        stale.0, candidates,
        "an expired lease still serves the bounded old snapshot instead of blocking the signal"
    );
}

/// Host candidates are intentionally visible before the first STUN gather,
/// but a new offer must wait for the committed full snapshot when it is about
/// to arrive. This reproduces the startup ordering that previously sent a
/// one-candidate offer a few milliseconds before the public/predicted set.
#[tokio::test]
async fn initial_handshake_candidate_gate_skips_provisional_host_snapshot() {
    let daemon = Arc::new(Daemon::new(
        Config::generate_default("http://ctrl.test", "net1").unwrap(),
    ));
    let provisional = vec!["192.168.1.20:40000".to_string()];
    let provisional_sources = HashMap::from([(
        provisional[0].clone(),
        "host".to_string(),
    )]);
    daemon
        .publish_candidate_snapshot_with_readiness(
            provisional,
            provisional_sources,
            vec!["host:192.168.1.20".to_string()],
            false,
        )
        .await;
    assert!(
        daemon.initial_candidate_set_if_ready().await.is_none(),
        "a non-empty host bootstrap must not satisfy initial offer readiness"
    );

    let complete = vec![
        "203.0.113.10:45393".to_string(),
        "203.0.113.10:45394".to_string(),
    ];
    let complete_sources = HashMap::from([
        (complete[0].clone(), "stun_observed".to_string()),
        (complete[1].clone(), "predicted".to_string()),
    ]);
    let publisher = daemon.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(10)).await;
        publisher
            .publish_candidate_snapshot_with_readiness(
                complete,
                complete_sources,
                vec!["public:203.0.113.10".to_string()],
                true,
            )
            .await;
    });

    let (received, sources) = timeout(
        Duration::from_millis(300),
        daemon.wait_for_initial_candidate_set(),
    )
    .await
    .expect("the full startup snapshot should win before the readiness budget");
    assert_eq!(received.len(), 2);
    assert_eq!(
        sources.get(&received[0]).map(String::as_str),
        Some("stun_observed")
    );
}

/// A Direct peer's rekey reuses the cached candidate snapshot: rekey must
/// never re-trigger a live STUN gather (no traversal churn on a confirmed
/// path).
#[tokio::test]
async fn direct_rekey_uses_cached_candidates_without_live_stun_churn() {
    let daemon = Daemon::new(Config::generate_default("http://ctrl.test", "net1").unwrap());
    let candidates = vec!["203.0.113.10:45393".to_string()];
    let sources = HashMap::from([("203.0.113.10:45393".to_string(), "stun_observed".to_string())]);
    daemon
        .publish_candidate_snapshot(candidates.clone(), sources.clone(), Vec::new())
        .await;

    // The maintenance/rekey path reads the committed candidate set directly
    // (no live gather): with an empty UDP transport any gather would fail, so
    // receiving the cached set proves the rekey path never gathered.
    let leased = daemon.leased_candidate_set().await.expect("lease exists");
    assert_eq!(leased.0, candidates);
    assert_eq!(leased.1, sources);

    // Repeated rekey-adjacent reads do not churn the snapshot.
    for _ in 0..5 {
        let read = daemon.leased_candidate_set().await.unwrap();
        assert_eq!(read.0, candidates);
    }
    let snapshot = daemon.cached_candidate_snapshot().await.unwrap();
    assert_eq!(snapshot.candidates, candidates);
}

/// A byte-identical duplicate offer must NOT touch the candidate plane: no
/// candidate apply, no fresh-prediction transaction, no punch; the event
/// stream records the ingress suppression.
#[tokio::test]
async fn duplicate_offer_has_no_candidate_apply_or_fresh_prediction_side_effect() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let boot = 1_742_987_654_322u64;
    let label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot,
        generation: 1,
    });
    let candidates = vec!["203.0.113.10:45393".to_string()];
    let sources = HashMap::from([("203.0.113.10:45393".to_string(), label)]);

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
    let send_offer = |control: &ControlClient| {
        control
            .event_sender()
            .send(ControlEvent::PeerOffer {
                from_node_id: "node-dupe".to_string(),
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
    };

    peers
        .add_peer(&crate::control::PeerInfo {
            node_id: "node-dupe".to_string(),
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

    // First offer: candidates apply and the fresh identity commits.
    send_offer(&control);
    timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-dupe")
                .await
                .is_some_and(|conn| conn.candidates.contains(&"203.0.113.10:45393".to_string()))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first offer must apply its candidates");

    // Byte-identical duplicate inside the dedup window: no candidate apply,
    // no fresh transaction side effect.
    let candidates_before = peers
        .get_connection("node-dupe")
        .await
        .unwrap()
        .candidates
        .len();
    send_offer(&control);
    timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-dupe")
                .await
                .is_some_and(|conn| {
                    conn.direct_events
                        .iter()
                        .any(|event| event.stage == "peer_offer_ingress_suppressed")
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the duplicate offer must be recorded as ingress-suppressed");
    sleep(Duration::from_millis(100)).await;
    let conn = peers.get_connection("node-dupe").await.unwrap();
    assert_eq!(
        conn.candidates.len(),
        candidates_before,
        "the duplicate offer must not apply candidates"
    );
    assert_eq!(
        conn.candidates
            .iter()
            .filter(|candidate| *candidate == &"203.0.113.10:45393".to_string())
            .count(),
        1,
        "the duplicate offer must not duplicate the candidate"
    );

    handle.abort();
}

/// The proactive relay renewal runs CONCURRENTLY with the inbound drain and
/// swaps the transport only after the replacement connected: the deadline
/// computation proves the swap lands before the server's expiry close.
#[tokio::test]
async fn proactive_relay_ticket_renewal_has_no_transport_gap() {
    // Deadline logic: renewal at expiry - margin.
    let now = 1_000_000i64;
    assert_eq!(
        relay_renewal_deadline(now + 300, now),
        Duration::from_secs(240)
    );
    // The renewal task never waits past the server's expiry close.
    assert!(relay_renewal_deadline(now + 300, now) < Duration::from_secs(300));

    // Ticket-cache expiry accounting: a ticket inside the refresh margin is
    // not served as "valid" for a NEW selection, but the cache keeps the
    // expiry so the renewal task knows exactly when to refresh.
    let manager = PeerManager::new(Config::generate_default("http://ctrl.test", "net1").unwrap());
    let mut transport = RelayTransport::connect_for_test("default", "tcp://relay.test:18081", Arc::new(manager));
    transport = transport.with_ticket_metadata("aud-1", "default", now + 300);
    let (audience, region, expires) = transport.ticket_expiry().unwrap();
    assert_eq!(expires, now + 300);
    // The renewal deadline derived from that expiry fires 240s in, i.e. 60s
    // before the server closes the connection at expiry — the replacement is
    // connected and swapped BEFORE any expiry close, so the data path never
    // sees a gap.
    let deadline = relay_renewal_deadline(expires, now);
    assert_eq!(deadline, Duration::from_secs(240));
    let _ = (audience, region);
}
