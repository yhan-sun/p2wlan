use super::*;
use p2pnet_nat::{AllocationAttempt, AllocationAttemptOutcome as Outcome};

fn observers() -> Vec<SocketAddr> {
    (1..=4)
        .map(|host| format!("203.0.113.{host}:3478").parse().unwrap())
        .collect()
}

fn attempt(
    sequence: u16,
    socket: u16,
    observer: SocketAddr,
    outcome: Outcome,
) -> AllocationAttempt {
    AllocationAttempt {
        sequence,
        local_endpoint: SocketAddr::new("192.0.2.1".parse().unwrap(), socket),
        destination: observer,
        sent_at_ms: 100 + u64::from(sequence) * 200,
        datagram_bytes: 40,
        outcome,
    }
}

#[test]
fn grid_timeout_changes_the_remaining_share_without_renewing_the_budget() {
    let configured = Duration::from_millis(350);
    let start = 100;
    assert_eq!(
        ordered_mapping_request_timeout(configured, start, start, 6),
        Some(Duration::from_millis(200))
    );
    // After the first 200 ms timeout, only three unused primary pairs remain.
    // Three 250 ms responses now fit in the original 1200 ms budget.
    assert_eq!(
        ordered_mapping_request_timeout(configured, start, start + 200, 3),
        Some(Duration::from_millis(333))
    );
    for (elapsed, remaining) in [(450, 2), (700, 1)] {
        assert_eq!(
            ordered_mapping_request_timeout(configured, start, start + elapsed, remaining),
            Some(configured)
        );
    }
    assert_eq!(
        ordered_mapping_request_timeout(configured, start, start + 1199, 1),
        Some(Duration::from_millis(1))
    );
    assert!(ordered_mapping_request_timeout(configured, start, start + 1200, 1).is_none());
    assert!(ordered_mapping_request_timeout(configured, start, start + 1300, 3).is_none());
    assert!(ordered_mapping_request_timeout(configured, start, start, 0).is_none());
}

#[test]
fn hard_hard_sample_timeout_can_use_spare_time_but_not_extend_the_deadline() {
    let configured = Duration::from_secs(1);
    assert_eq!(
        ordered_mapping_request_timeout(configured, 100, 100, 3),
        Some(Duration::from_millis(400))
    );
    assert_eq!(
        ordered_mapping_request_timeout(configured, 100, 420, 1),
        Some(Duration::from_millis(880))
    );
    assert_eq!(
        ordered_mapping_request_timeout(Duration::from_millis(100), 100, 420, 1),
        Some(Duration::from_millis(100)),
        "the user's configured timeout remains an upper bound"
    );
    assert!(ordered_mapping_request_timeout(configured, 100, 1300, 1).is_none());
}

#[test]
fn primary_fallback_never_reuses_unknown_or_failed_pairs() {
    let observers = observers();
    let primary = "192.0.2.1:5000".parse().unwrap();
    for outcome in [Outcome::SentUnobserved, Outcome::SendFailed] {
        let attempts = vec![attempt(0, 5000, observers[0], outcome)];
        assert_eq!(
            primary_mapping_tail_after_gap(&attempts, primary, &observers, 6).unwrap(),
            observers[1..]
        );
        assert_eq!(
            attempts[0].outcome, outcome,
            "fallback retains the full ledger"
        );
        assert!(primary_mapping_tail_after_gap(&attempts, primary, &observers, 3).is_none());
    }
}

#[test]
fn a_failed_secondary_observation_can_use_unused_primary_destinations() {
    let observers = observers();
    let primary = "192.0.2.1:5000".parse().unwrap();
    for failed_sequence in [1, 2] {
        let mut attempts = vec![
            attempt(0, 5000, observers[0], Outcome::Observed),
            attempt(1, 5001, observers[0], Outcome::Observed),
            attempt(2, 5001, observers[1], Outcome::Observed),
        ];
        attempts.truncate(failed_sequence + 1);
        attempts.last_mut().unwrap().outcome = Outcome::SentUnobserved;
        assert_eq!(
            primary_mapping_tail_after_gap(&attempts, primary, &observers, 6).unwrap(),
            observers[1..]
        );
    }
}

#[test]
fn healthy_grid_and_insufficient_unused_tail_keep_the_existing_plan() {
    let observers = observers();
    let primary = "192.0.2.1:5000".parse().unwrap();
    let mut attempts = vec![attempt(0, 5000, observers[0], Outcome::Observed)];
    assert!(primary_mapping_tail_after_gap(&attempts, primary, &observers, 6).is_none());
    attempts.push(attempt(1, 5000, observers[1], Outcome::SentUnobserved));
    assert!(primary_mapping_tail_after_gap(&attempts, primary, &observers, 6).is_none());
    let duplicate_observers = vec![observers[0], observers[2], observers[2], observers[3]];
    assert!(primary_mapping_tail_after_gap(&attempts, primary, &duplicate_observers, 6).is_none());
}

#[tokio::test(start_paused = true)]
async fn measurement_io_waits_share_the_original_deadline_and_recheck_cancellation() {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    let active = std::sync::atomic::AtomicBool::new(true);
    let keep = || active.load(std::sync::atomic::Ordering::Relaxed);
    let (sender, receiver) = oneshot::channel();
    let mut wait = Box::pin(wait_for_mapping_io(receiver, deadline, &keep));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(wait.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_millis(175)).await;
    sender.send(()).unwrap();
    assert!(wait.await.unwrap().is_ok());
    let remaining = tokio::time::Instant::now();
    assert!(matches!(
        wait_for_mapping_io(std::future::pending::<()>(), deadline, &keep).await,
        Err(MappingIoError::Deadline)
    ));
    assert_eq!(
        tokio::time::Instant::now() - remaining,
        Duration::from_millis(25)
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let (sender, receiver) = oneshot::channel();
    let mut wait = Box::pin(wait_for_mapping_io(receiver, deadline, &keep));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(wait.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    active.store(false, std::sync::atomic::Ordering::Relaxed);
    sender.send(()).unwrap();
    assert!(matches!(wait.await, Err(MappingIoError::Inactive)));
}

#[tokio::test]
async fn cancelling_measurement_during_epoch_admission_never_hands_off_a_datagram() {
    let config =
        crate::config::Config::generate_default("https://ctrl.test", "mapping-cancel").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let epoch = udp.network_epoch_gate.lock().await;
    // Make readiness deterministic; the measurement will now wait at epoch.
    udp.socket.writable().await.unwrap();
    let active = std::sync::atomic::AtomicBool::new(true);
    let keep = || active.load(std::sync::atomic::Ordering::Relaxed);
    let mut send = Box::pin(udp.send_mapping_request_until(
        &udp.socket,
        b"measurement",
        observer.local_addr().unwrap(),
        tokio::time::Instant::now() + Duration::from_secs(1),
        &keep,
    ));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(send.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    active.store(false, std::sync::atomic::Ordering::Relaxed);
    drop(epoch);
    assert!(matches!(send.await, Err(MappingIoError::Inactive)));
    assert_eq!(
        observer.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn live_stun_expiry_and_dropped_admission_release_the_exact_waiter_without_sending() {
    let config =
        crate::config::Config::generate_default("https://ctrl.test", "stun-lease").unwrap();
    let udp = UdpTransport::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(PeerManager::new(config)),
    )
    .await
    .unwrap();
    let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = observer.local_addr().unwrap();
    assert!(udp
        .query_stun_live_response(&udp.socket, server, Duration::ZERO, false, false)
        .await
        .is_err());
    assert_eq!(udp.stun_waiters.len(), 0);

    let epoch = udp.network_epoch_gate.lock().await;
    udp.socket.writable().await.unwrap();
    let mut query = Box::pin(udp.query_stun_live_response(
        &udp.socket,
        server,
        Duration::from_secs(1),
        false,
        false,
    ));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(query.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(udp.stun_waiters.len(), 1);
    drop(query);
    assert_eq!(udp.stun_waiters.len(), 0);
    drop(epoch);
    assert_eq!(
        observer.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
