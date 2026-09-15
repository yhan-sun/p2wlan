use super::super::test_support::*;
use super::*;

#[tokio::test]
async fn relay_route_monitor_requires_two_nonempty_matching_changes() {
    let original = vec!["default:en0:192.168.1.1".to_string()];
    let replacement = vec!["default:en1:192.168.2.1".to_string()];
    let mut monitor = RelayRouteMonitor::new(original.clone());

    assert!(monitor.enabled());
    assert!(monitor.observe(replacement.clone()).is_none());
    assert!(monitor.observe(Vec::new()).is_none());
    assert!(monitor.observe(original).is_none());
    assert!(monitor.observe(replacement.clone()).is_none());
    assert_eq!(monitor.observe(replacement.clone()), Some(replacement));
}

#[test]
fn relay_ticket_renewal_deadline_precedes_expiry_with_margin() {
    // With a 5-minute ticket the renewal fires 60s before expiry: the
    // old connection is still fully valid while the replacement connects
    // (make-before-break), so there is no transport gap.
    let now = 1_000_000i64;
    let expires = now + 300; // 5-minute ticket
    let deadline = relay_renewal_deadline(expires, now);
    assert_eq!(deadline, Duration::from_secs(240));
    // The deadline is always at least 1s (never a spin).
    assert_eq!(
        relay_renewal_deadline(now + 60, now),
        Duration::from_secs(1)
    );
    assert_eq!(
        relay_renewal_deadline(now + 10, now),
        Duration::from_secs(1)
    );
    assert_eq!(relay_renewal_deadline(now, now), Duration::from_secs(1));
    // An already-expired ticket has no future deadline.
    assert_eq!(relay_renewal_deadline(now - 5, now), Duration::from_secs(1));
    // A short ticket still leaves a real margin: renew at T-60 is
    // impossible, so the renewal waits only for the bounded retry step.
    let deadline_short = relay_renewal_deadline(now + 120, now);
    assert_eq!(deadline_short, Duration::from_secs(60));
}

#[test]
fn relay_ticket_expiry_metadata_roundtrip_is_auditable() {
    use crate::Config;
    // The transport's ticket metadata is what the supervisor reads to
    // schedule the renewal; it must survive the clone the supervisor
    // hands to the renewal task.
    let mut transport = RelayTransport::connect_for_test(
        "default",
        "tcp://relay.test:18081",
        Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "net1").unwrap(),
        )),
    );
    transport = transport.with_ticket_metadata("aud-1", "default", 1_000_300);
    let (audience, region, expires) = transport
        .ticket_expiry()
        .expect("ticket metadata must be attached");
    assert_eq!(audience, "aud-1");
    assert_eq!(region, "default");
    assert_eq!(expires, 1_000_300);
    let transport2 = transport.clone();
    assert_eq!(
        transport2.ticket_expiry(),
        Some(("aud-1".to_string(), "default".to_string(), 1_000_300)),
        "the cloned transport (handed to the renewal task) must carry the same ticket deadline"
    );
}

#[test]
fn relay_reconnect_backoff_is_bounded_and_jittered() {
    // Full-jitter backoff: every retry sleeps in [base, 2*base) so nodes
    // that fail together do not reconnect in lockstep.
    for _ in 0..200 {
        let delay = relay_retry_delay_with_jitter(Duration::from_secs(1));
        assert!(
            delay >= Duration::from_secs(1) && delay < Duration::from_secs(2),
            "jittered delay must stay in [base, 2*base), got {delay:?}"
        );
    }
    let mut observed = std::collections::HashSet::new();
    for _ in 0..50 {
        observed.insert(relay_retry_delay_with_jitter(Duration::from_secs(1)).as_millis());
    }
    assert!(
        observed.len() > 1,
        "the jitter must actually spread the retry delays, got {observed:?}"
    );
    assert_eq!(
        relay_retry_delay_with_jitter(Duration::ZERO),
        Duration::ZERO
    );

    // The supervisor's exponential doubling is capped: simulate the
    // sequence of bases after repeated failures (1s, 2s, 4s, ... capped at
    // the 30s max) and verify each jittered delay respects its own bound.
    let mut retry_delay = Duration::from_secs(1);
    let max_retry_delay = Duration::from_secs(30);
    for _ in 0..10 {
        let jittered = relay_retry_delay_with_jitter(retry_delay);
        assert!(jittered >= retry_delay);
        assert!(jittered < retry_delay.saturating_mul(2));
        retry_delay = retry_delay.saturating_mul(2).min(max_retry_delay);
    }
    assert_eq!(retry_delay, max_retry_delay, "the backoff must be capped");
}

#[tokio::test]
async fn relay_supervisor_legacy_connection_ends_promptly_without_renewal_spin() {
    // A legacy (no-ticket) relay arms no renewal: the renewal branch of
    // the supervisor's select must stay DISARMED so a server EOF is served
    // immediately.  Previously the always-pending renewal branch starved
    // the EOF and the supervisor spun forever.
    let supervisor = test_supervisor(None);
    let transport = RelayTransport::connect_for_test(
        "default",
        "tcp://relay.test:18081",
        supervisor.peers.clone(),
    );
    let endpoint = transport.endpoint().to_string();
    let (relay_tx, relay_rx) = mpsc::channel(4);
    let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ended = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                &endpoint,
                transport,
                relay_rx,
                connection_generation,
                |_expected, _transport| Box::pin(async move { None::<ArmedRelayRenewal> }),
            )
            .await
    });
    sleep(Duration::from_millis(20)).await;
    drop(relay_tx);
    let result = tokio::time::timeout(Duration::from_secs(2), ended)
        .await
        .expect("the supervisor must return after a legacy connection ends, not spin")
        .expect("the supervisor task must not panic");
    assert!(
        result.is_ok(),
        "a clean end must surface Ok, got {result:?}"
    );
}

#[tokio::test]
async fn relay_supervisor_renewal_handoff_survives_superseded_connection_eof() {
    // Make-before-break handoff with the full race: the OLD connection's
    // EOF arrives while its renewal is already connecting (the hub's
    // newest-wins close of the superseded connection).  The supervisor
    // must hold that EOF, swap in the replacement, and only then surface
    // the replacement's own end — the handoff can never be aborted by its
    // predecessor's EOF.
    let supervisor = test_supervisor(None);
    let relay_transport = supervisor.relay_transport.clone();
    let relay_selection = supervisor.relay_selection.clone();
    let transport_a = RelayTransport::connect_for_test(
        "default",
        "tcp://relay-a.test:18081",
        supervisor.peers.clone(),
    )
    .with_ticket_metadata("aud-1", "default", 1_000_300);
    let endpoint = transport_a.endpoint().to_string();
    let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
    let (renewal_tx, renewal_rx) = oneshot::channel();
    let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![ArmedRelayRenewal {
        result: Some(renewal_rx),
        connecting: connecting.clone(),
        abort_handle: None,
    }]);
    let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fake_task = fake.clone();

    let ended = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                &endpoint,
                transport_a,
                relay_rx_a,
                connection_generation,
                fake_task.closure(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
        .await
        .expect("supervisor must arm the renewal closure")
        .expect("armed channel closed");
    // The renewal begins connecting...
    connecting.store(true, std::sync::atomic::Ordering::SeqCst);
    // ...and the superseded connection ends WHILE it is connecting: this
    // EOF is the handoff's own close racing in and must be held, never
    // treated as a real failure.
    relay_tx_a
        .send(RelayMessage::Closed {
            reason: p2pnet_relay::RelayCloseReason::ServerEof,
        })
        .await
        .unwrap();
    fake.release();
    // The renewal resolves with the replacement connection.
    let peers_b =
        PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let transport_b =
        RelayTransport::connect_for_test("default", "tcp://relay-b.test:18081", Arc::new(peers_b))
            .with_ticket_metadata("aud-1", "default", 1_000_600);
    let (relay_tx_b, relay_rx_b) = mpsc::channel(4);
    assert!(
        renewal_tx
            .send(Some((transport_b.clone(), relay_rx_b)))
            .is_ok(),
        "the supervisor must still be awaiting the renewal result"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let current = relay_transport.read().await.clone();
            if current
                .as_ref()
                .is_some_and(|t| t.endpoint() == transport_b.endpoint())
            {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the supervisor must publish the renewal replacement");
    // The replacement's own stream ends cleanly: that end surfaces, not
    // the held superseded EOF.
    drop(relay_tx_b);
    let result = tokio::time::timeout(Duration::from_secs(2), ended)
        .await
        .expect("the supervisor must return after the replacement ends")
        .expect("the supervisor task must not panic");
    assert!(
        result.is_ok(),
        "the handoff must end cleanly, got {result:?}"
    );
    // The superseded connection's EOF was an EXPECTED handoff close: it
    // must never surface as a relay failure in the diagnostics.
    let diags = relay_selection.read().await;
    assert_eq!(
        diags.selected_error_count, 0,
        "a superseded connection's expected EOF must not count as an error"
    );
    assert_eq!(
        diags.last_error, None,
        "a superseded connection's expected EOF must not set last_error"
    );
    assert_eq!(
        diags.last_error_code, None,
        "a superseded connection's expected EOF must not set last_error_code"
    );
}

#[tokio::test]
async fn relay_supervisor_renewal_failure_surfaces_held_connection_end() {
    // When the renewal fails WHILE its connection is ending, the held EOF
    // is a real failure: it must be surfaced with its close reason intact
    // (never swallowed, never converted into a spurious reconnect).
    let supervisor = test_supervisor(None);
    let relay_selection = supervisor.relay_selection.clone();
    let transport_a = RelayTransport::connect_for_test(
        "default",
        "tcp://relay-a.test:18081",
        supervisor.peers.clone(),
    )
    .with_ticket_metadata("aud-1", "default", 1_000_300);
    let endpoint = transport_a.endpoint().to_string();
    let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
    let (renewal_tx, renewal_rx) = oneshot::channel();
    let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![ArmedRelayRenewal {
        result: Some(renewal_rx),
        connecting: connecting.clone(),
        abort_handle: None,
    }]);
    let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fake_task = fake.clone();

    let ended = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                &endpoint,
                transport_a,
                relay_rx_a,
                connection_generation,
                fake_task.closure(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
        .await
        .expect("supervisor must arm the renewal closure")
        .expect("armed channel closed");
    connecting.store(true, std::sync::atomic::Ordering::SeqCst);
    relay_tx_a
        .send(RelayMessage::Closed {
            reason: p2pnet_relay::RelayCloseReason::ServerEof,
        })
        .await
        .unwrap();
    fake.release();
    assert!(
        renewal_tx.send(None).is_ok(),
        "the supervisor must still be awaiting the renewal result"
    );
    let result = tokio::time::timeout(Duration::from_secs(2), ended)
        .await
        .expect("the supervisor must return after a failed renewal with a held end")
        .expect("the supervisor task must not panic");
    let error =
        result.expect_err("a failed renewal with an ending connection must surface an error");
    assert!(
        error.to_string().contains("server_eof"),
        "the held close reason must be preserved, got {error}"
    );
    // The held end was a GENUINE failure of the current connection (the
    // renewal did not resolve it), so the deferred attribution must record
    // it exactly once with the real close reason.
    let diags = relay_selection.read().await;
    assert_eq!(
        diags.selected_error_count, 1,
        "a genuine close with a failed renewal must be counted exactly once"
    );
    assert_eq!(
        diags.last_error.as_deref(),
        Some("relay connection closed: reason=server_eof"),
        "the deferred diagnostics must attribute the real close"
    );
    assert_eq!(
        diags.last_error_code.as_deref(),
        Some("server_eof"),
        "the deferred diagnostics must keep the real close code"
    );
}

#[tokio::test]
async fn relay_supervisor_superseded_connection_eof_after_handoff_keeps_diagnostics_clean() {
    // The field-reported scenario: the hub's newest-wins close of the
    // SUPERSEDED connection arrives AFTER the renewal handoff already
    // published the replacement.  The old-generation EOF is expected and
    // must be ignored — no diagnostics entry, no reconnect, no panic —
    // while the replacement keeps serving.
    let supervisor = test_supervisor(None);
    let relay_transport = supervisor.relay_transport.clone();
    let relay_selection = supervisor.relay_selection.clone();
    let transport_a = RelayTransport::connect_for_test(
        "default",
        "tcp://relay-a.test:18081",
        supervisor.peers.clone(),
    )
    .with_ticket_metadata("aud-1", "default", 1_000_300);
    let endpoint = transport_a.endpoint().to_string();
    let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
    let (renewal_tx, renewal_rx) = oneshot::channel();
    let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![ArmedRelayRenewal {
        result: Some(renewal_rx),
        connecting: connecting.clone(),
        abort_handle: None,
    }]);
    let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fake_task = fake.clone();

    let ended = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                &endpoint,
                transport_a,
                relay_rx_a,
                connection_generation,
                fake_task.closure(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
        .await
        .expect("supervisor must arm the renewal closure")
        .expect("armed channel closed");
    fake.release();
    let peers_b =
        PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let transport_b =
        RelayTransport::connect_for_test("default", "tcp://relay-b.test:18081", Arc::new(peers_b))
            .with_ticket_metadata("aud-1", "default", 1_000_600);
    let (relay_tx_b, relay_rx_b) = mpsc::channel(4);
    assert!(
        renewal_tx
            .send(Some((transport_b.clone(), relay_rx_b)))
            .is_ok(),
        "the supervisor must still be awaiting the renewal result"
    );
    wait_for_relay_transport(&relay_transport, transport_b.endpoint()).await;

    // The hub now closes the superseded connection (old-generation EOF).
    relay_tx_a
        .send(RelayMessage::Closed {
            reason: p2pnet_relay::RelayCloseReason::ServerEof,
        })
        .await
        .unwrap();
    sleep(Duration::from_millis(100)).await;
    assert!(
        !ended.is_finished(),
        "a superseded EOF must not end the supervisor (no reconnect)"
    );
    let current = relay_transport.read().await.clone();
    assert!(
        current.is_some_and(|t| t.endpoint() == transport_b.endpoint()),
        "the replacement must keep serving after a superseded EOF"
    );
    let diags = relay_selection.read().await;
    assert_eq!(
        diags.selected_error_count, 0,
        "an old-generation EOF after handoff must not count as an error"
    );
    assert_eq!(diags.last_error, None);
    assert_eq!(diags.last_error_code, None);

    // The replacement's own stream ends cleanly.
    drop(relay_tx_b);
    let result = tokio::time::timeout(Duration::from_secs(2), ended)
        .await
        .expect("the supervisor must return after the replacement ends")
        .expect("the supervisor task must not panic");
    assert!(result.is_ok(), "clean end, got {result:?}");
}

#[tokio::test]
async fn relay_supervisor_genuine_server_eof_records_diagnostics_once() {
    // A REAL close of the CURRENT connection (no renewal in flight) is a
    // genuine failure: it must return the failure AND record exactly one
    // diagnostics entry with the server_eof attribution — never swallowed,
    // never duplicated.
    let supervisor = test_supervisor(None);
    let relay_selection = supervisor.relay_selection.clone();
    let transport = RelayTransport::connect_for_test(
        "default",
        "tcp://relay.test:18081",
        supervisor.peers.clone(),
    );
    let endpoint = transport.endpoint().to_string();
    let (relay_tx, relay_rx) = mpsc::channel(4);
    let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ended = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                &endpoint,
                transport,
                relay_rx,
                connection_generation,
                |_expected, _transport| Box::pin(async move { None::<ArmedRelayRenewal> }),
            )
            .await
    });
    sleep(Duration::from_millis(20)).await;
    relay_tx
        .send(RelayMessage::Closed {
            reason: p2pnet_relay::RelayCloseReason::ServerEof,
        })
        .await
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), ended)
        .await
        .expect("the supervisor must return after a genuine server EOF")
        .expect("the supervisor task must not panic");
    let error = result.expect_err("a genuine server EOF must surface as a failure");
    assert!(
        error.to_string().contains("server_eof"),
        "the close reason must be preserved, got {error}"
    );
    let diags = relay_selection.read().await;
    assert_eq!(
        diags.selected_error_count, 1,
        "a genuine server EOF must be counted exactly once"
    );
    assert_eq!(
        diags.last_error.as_deref(),
        Some("relay connection closed: reason=server_eof"),
        "the last_error must attribute the real close"
    );
    assert_eq!(
        diags.last_error_code.as_deref(),
        Some("server_eof"),
        "the error code must attribute server_eof"
    );
}

#[tokio::test]
async fn relay_supervisor_two_renewal_cycles_preserve_ticket_metadata_and_diagnostics() {
    // Two consecutive make-before-break cycles: each handoff publishes the
    // replacement WITH its own ticket expiry (so the next renewal is
    // scheduled from the new deadline), superseded connections' EOFs are
    // ignored, and the diagnostics accumulate NO false errors across the
    // whole lifecycle.
    let supervisor = test_supervisor(None);
    let relay_transport = supervisor.relay_transport.clone();
    let relay_selection = supervisor.relay_selection.clone();
    let transport_a = RelayTransport::connect_for_test(
        "default",
        "tcp://relay-a.test:18081",
        supervisor.peers.clone(),
    )
    .with_ticket_metadata("aud-1", "default", 1_000_300);
    let endpoint = transport_a.endpoint().to_string();
    let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
    let (renewal_tx_1, renewal_rx_1) = oneshot::channel();
    let (renewal_tx_2, renewal_rx_2) = oneshot::channel();
    let connecting_1 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connecting_2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The queue is popped LIFO, so the FIRST pop is renewal 1.
    let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![
        ArmedRelayRenewal {
            result: Some(renewal_rx_2),
            connecting: connecting_2.clone(),
            abort_handle: None,
        },
        ArmedRelayRenewal {
            result: Some(renewal_rx_1),
            connecting: connecting_1.clone(),
            abort_handle: None,
        },
    ]);
    let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fake_task = fake.clone();

    let ended = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                &endpoint,
                transport_a,
                relay_rx_a,
                connection_generation,
                fake_task.closure(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
        .await
        .expect("supervisor must arm the first renewal")
        .expect("armed channel closed");
    fake.release();

    // Cycle 1: renewal resolves with a replacement carrying its OWN expiry.
    let peers_b =
        PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let transport_b =
        RelayTransport::connect_for_test("default", "tcp://relay-b.test:18081", Arc::new(peers_b))
            .with_ticket_metadata("aud-1", "default", 1_000_600);
    let (relay_tx_b, relay_rx_b) = mpsc::channel(4);
    assert!(
        renewal_tx_1
            .send(Some((transport_b.clone(), relay_rx_b)))
            .is_ok(),
        "the supervisor must still be awaiting the first renewal result"
    );
    wait_for_relay_transport(&relay_transport, transport_b.endpoint()).await;
    // The hub closes the superseded connection A after handoff 1.
    relay_tx_a
        .send(RelayMessage::Closed {
            reason: p2pnet_relay::RelayCloseReason::ServerEof,
        })
        .await
        .unwrap();

    // Cycle 2: the supervisor re-armed (queue pop 2); resolve it.
    tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
        .await
        .expect("supervisor must re-arm the second renewal")
        .expect("armed channel closed");
    let peers_c =
        PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
    let transport_c =
        RelayTransport::connect_for_test("default", "tcp://relay-c.test:18081", Arc::new(peers_c))
            .with_ticket_metadata("aud-1", "default", 1_001_200);
    let (relay_tx_c, relay_rx_c) = mpsc::channel(4);
    assert!(
        renewal_tx_2
            .send(Some((transport_c.clone(), relay_rx_c)))
            .is_ok(),
        "the supervisor must still be awaiting the second renewal result"
    );
    wait_for_relay_transport(&relay_transport, transport_c.endpoint()).await;
    // The hub closes the superseded connection B after handoff 2.
    relay_tx_b
        .send(RelayMessage::Closed {
            reason: p2pnet_relay::RelayCloseReason::ServerEof,
        })
        .await
        .unwrap();
    sleep(Duration::from_millis(100)).await;

    // The current replacement still carries its own ticket expiry so the
    // NEXT renewal is scheduled from the new deadline.
    let current = relay_transport
        .read()
        .await
        .clone()
        .expect("the second replacement must be published");
    assert_eq!(
        current.ticket_expiry(),
        Some(("aud-1".to_string(), "default".to_string(), 1_001_200)),
        "the second replacement must keep its own ticket expiry for the next renewal"
    );
    // Two handoffs and two superseded EOFs: NO false errors accumulated.
    let diags = relay_selection.read().await;
    assert_eq!(
        diags.selected_error_count, 0,
        "successful renewal cycles must not accumulate false errors"
    );
    assert_eq!(diags.last_error, None);
    assert_eq!(diags.last_error_code, None);

    // The current connection ends cleanly.
    drop(relay_tx_c);
    let result = tokio::time::timeout(Duration::from_secs(2), ended)
        .await
        .expect("the supervisor must return after the current connection ends")
        .expect("the supervisor task must not panic");
    assert!(result.is_ok(), "clean end, got {result:?}");
}

#[tokio::test]
async fn audit_failed_renewal_must_back_off() {
    let cache = Arc::new(RelayTicketCache::new(
        crate::control::ControlClient::disabled_for_test(),
    ));
    let supervisor = test_supervisor(Some(cache.clone()));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let transport = RelayTransport::connect_for_test(
        "default",
        "tcp://relay.test:18081",
        supervisor.peers.clone(),
    )
    .with_ticket_metadata("aud-1", "default", now + 50);
    let (_tx, rx) = mpsc::channel(4);
    let token = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts_task = attempts.clone();
    let peers = supervisor.peers.clone();
    let task = tokio::spawn(async move {
        supervisor
            .supervise_relay_connection(
                "tcp://relay.test:18081",
                transport,
                rx,
                token.clone(),
                move |expected, transport| {
                    attempts_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Box::pin(spawn_relay_renewal_task_impl(
                        Some(cache.clone()),
                        "node-a".into(),
                        peers.clone(),
                        true,
                        None,
                        token.clone(),
                        expected,
                        transport,
                    ))
                },
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    let count = attempts.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        count <= 1,
        "renewal rearmed {count} times in 100ms; expected a 5-second retry delay"
    );
}

/// Deterministic arm/release for the fake renewal closure: the closure
/// signals when the supervisor has invoked it (via `armed`), then blocks
/// until the test sends the `go` watch value, then pops the next armed
/// renewal (or returns `None` when the queue is exhausted).
struct FakeRenewalQueue {
    armed: mpsc::Sender<()>,
    go: tokio::sync::watch::Sender<bool>,
    go_rx: tokio::sync::watch::Receiver<bool>,
    queue: std::sync::Mutex<Vec<ArmedRelayRenewal>>,
}

impl FakeRenewalQueue {
    fn new(queue: Vec<ArmedRelayRenewal>) -> (Arc<Self>, mpsc::Receiver<()>) {
        let (armed, armed_rx) = mpsc::channel(1);
        let (go, go_rx) = tokio::sync::watch::channel(false);
        (
            Arc::new(Self {
                armed,
                go,
                go_rx,
                queue: std::sync::Mutex::new(queue),
            }),
            armed_rx,
        )
    }

    fn release(&self) {
        self.go.send(true).unwrap();
    }

    fn closure(
        self: &Arc<Self>,
    ) -> impl FnMut(
        u64,
        RelayTransport,
    )
        -> Pin<Box<dyn std::future::Future<Output = Option<ArmedRelayRenewal>> + Send>>
           + '_ {
        let queue = self.clone();
        move |_expected: u64, _transport: RelayTransport| {
            let queue = queue.clone();
            let mut go_rx = queue.go_rx.clone();
            Box::pin(async move {
                queue.armed.send(()).await.unwrap();
                while !*go_rx.borrow() {
                    if go_rx.changed().await.is_err() {
                        break;
                    }
                }
                queue.queue.lock().unwrap().pop()
            })
        }
    }
}
