use super::*;
use p2pnet_nat::{AllocationAttemptOutcome, StunObservation};

async fn publish_observer_health(
    peers: &PeerManager,
    responsive: &[(SocketAddr, u64)],
    unavailable: &[SocketAddr],
) {
    let mut profile = hard_nat_candidate_report(p2pnet_nat::FilteringBehavior::Unknown).nat_profile;
    profile.observations = responsive
        .iter()
        .map(|(observer, rtt)| StunObservation {
            server: observer.to_string(),
            // Deliberately unrelated to the simulator's fresh mapping. Cached
            // addresses may select observers but must never become evidence.
            mapped_address: Some("203.0.113.77:30000".into()),
            rtt_ms: Some(*rtt),
            error: None,
        })
        .chain(unavailable.iter().map(|observer| StunObservation {
            server: observer.to_string(),
            mapped_address: None,
            rtt_ms: None,
            error: Some("STUN timeout".into()),
        }))
        .collect();
    peers.update_nat_profile(profile).await;
}

async fn prepare(
    transport: &UdpTransport,
    observers: &[SocketAddr],
) -> HardHardPreparedMeasurement {
    transport
        .run_hard_hard_prepared_generation(
            "peer-b",
            observers,
            Duration::from_secs(1),
            64,
            "observer-health-test",
            None,
            Duration::from_millis(3_500),
            Duration::from_millis(3_500),
        )
        .await
        .unwrap_or_else(|error| panic!("measurement should retain a fresh primary tail: {error:?}"))
}

async fn assert_fresh_primary_tail(
    transport: &UdpTransport,
    prepared: HardHardPreparedMeasurement,
    nat: &SimulatedNat,
) {
    assert_eq!(prepared.measurement_cost().stun_responses, 3);
    assert_eq!(prepared.measurement_trace.len(), 3);
    let prediction = prepared
        .predictable
        .as_ref()
        .expect("three fresh ordered responses must retain port prediction");
    for attempt in &prepared.measurement_trace {
        assert_eq!(attempt.outcome, AllocationAttemptOutcome::Observed);
        assert!(nat.observers.contains(&attempt.destination));
        assert_eq!(attempt.local_endpoint, prediction.socket_local_endpoint);
    }
    assert_eq!(prediction.public_ip, Some(nat.nat_ip));
    assert_eq!(prediction.model.sequence.len(), 3);
    assert_eq!(
        prepared.measurement_cost().stun_datagrams_sent,
        3,
        "observer selection must not add STUN retries"
    );
    for socket in &prepared.birthday.sockets {
        transport
            .detach_dynamic_socket_by_index(socket.socket_index, "observer_test_complete")
            .await;
    }
}

#[tokio::test]
async fn hard_hard_uses_three_responsive_observers_instead_of_a_failed_grid() {
    let (peers, transport, nat) = generation_env().await;
    // Keep both ports bound without a reader so failure is a real UDP timeout.
    let silent_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unavailable = [
        silent_a.local_addr().unwrap(),
        silent_b.local_addr().unwrap(),
    ];
    let responsive = nat
        .observers
        .iter()
        .map(|addr| (*addr, 5))
        .collect::<Vec<_>>();
    publish_observer_health(&peers, &responsive, &unavailable).await;
    let configured = [
        unavailable[0],
        nat.observers[0],
        unavailable[1],
        nat.observers[1],
        nat.observers[2],
    ];
    let prepared = prepare(&transport, &configured).await;
    assert_fresh_primary_tail(&transport, prepared, &nat).await;
}

#[tokio::test]
async fn hard_hard_allows_a_slow_observer_within_the_original_measurement_budget() {
    let nat = SimulatedNat::start_with_observer_delays(
        1,
        false,
        [Duration::ZERO, Duration::ZERO, Duration::from_millis(450)],
    )
    .await;
    let (peers, transport, nat) = generation_env_with_nat(nat).await;
    let responsive = [
        (nat.observers[0], 5),
        (nat.observers[1], 5),
        (nat.observers[2], 450),
    ];
    publish_observer_health(&peers, &responsive, &[]).await;
    let prepared = prepare(&transport, &nat.observers).await;
    let cost = prepared.measurement_cost();
    assert!(
        cost.measurement_completed_at_ms.unwrap() - cost.measurement_started_at_ms.unwrap()
            <= FRESH_MAPPING_MEASURE_BUDGET.as_millis() as u64 + 50,
        "allowing the slow response must not renew the overall budget"
    );
    assert_fresh_primary_tail(&transport, prepared, &nat).await;
}

#[tokio::test]
async fn hard_hard_remeasures_observers_after_stale_failure_hints() {
    let (peers, transport, nat) = generation_env().await;
    publish_observer_health(&peers, &[], &nat.observers).await;
    let prepared = prepare(&transport, &nat.observers).await;
    assert_fresh_primary_tail(&transport, prepared, &nat).await;
}

#[tokio::test]
async fn hard_hard_cached_success_cannot_replace_a_missing_fresh_response() {
    let (peers, transport, nat) = generation_env().await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let configured = [
        nat.observers[0],
        nat.observers[1],
        silent.local_addr().unwrap(),
    ];
    let responsive = configured.iter().map(|addr| (*addr, 5)).collect::<Vec<_>>();
    publish_observer_health(&peers, &responsive, &[]).await;
    let prepared = prepare(&transport, &configured).await;
    assert_eq!(prepared.measurement_cost().stun_responses, 2);
    assert!(prepared.predictable.is_none());
    assert!(prepared.allocation.is_none());
    assert_eq!(
        prepared.measurement_trace.last().unwrap().outcome,
        AllocationAttemptOutcome::SentUnobserved
    );
    assert!(!peers.is_direct("peer-b").await);
    for socket in &prepared.birthday.sockets {
        transport
            .detach_dynamic_socket_by_index(socket.socket_index, "observer_test_complete")
            .await;
    }
}

#[tokio::test]
async fn hard_hard_cancellation_interrupts_the_slow_observer_wait() {
    check_slow_observer_interruption(false).await;
}

#[tokio::test]
async fn hard_hard_network_change_interrupts_the_slow_observer_wait() {
    check_slow_observer_interruption(true).await;
}

async fn check_slow_observer_interruption(change_network: bool) {
    let nat = SimulatedNat::start_with_observer_delays(
        1,
        false,
        [Duration::ZERO, Duration::ZERO, Duration::from_millis(450)],
    )
    .await;
    let (peers, transport, nat) = generation_env_with_nat(nat).await;
    let responsive = nat
        .observers
        .iter()
        .map(|addr| (*addr, 5))
        .collect::<Vec<_>>();
    publish_observer_health(&peers, &responsive, &[]).await;
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    let mut measurement = Box::pin(transport.run_hard_hard_prepared_generation(
        "peer-b",
        &nat.observers,
        Duration::from_secs(1),
        64,
        "cancel-observer-test",
        Some(&cancellation),
        Duration::from_millis(3_500),
        Duration::from_millis(3_500),
    ));
    // The NAT records the third syscall before delaying its response. Wait on
    // that actual event instead of guessing when the collector is suspended.
    tokio::select! {
        _ = &mut measurement => panic!("slow observation should still be pending"),
        ready = timeout(Duration::from_secs(1), async {
            while nat.mappings.lock().await.len() < 3 {
                tokio::task::yield_now().await;
            }
        }) => ready.expect("third STUN request must reach the real observer"),
    }
    if change_network {
        peers
            .advance_network_generation("observer_test_network_change")
            .await;
    } else {
        cancellation.cancel();
    }
    let result = timeout(Duration::from_millis(200), &mut measurement)
        .await
        .expect("cancellation must interrupt the extended response wait");
    assert!(matches!(result, Err(FreshMappingRejection::Superseded)));
    assert!(transport.socket_state.lock().await.dynamic.is_empty());
}

#[tokio::test]
async fn hard_hard_slow_observers_cannot_extend_the_total_measurement_deadline() {
    let nat = SimulatedNat::start_with_observer_delays(
        1,
        false,
        [Duration::ZERO, Duration::ZERO, Duration::from_secs(3)],
    )
    .await;
    let (peers, transport, nat) = generation_env_with_nat(nat).await;
    let responsive = nat
        .observers
        .iter()
        .map(|addr| (*addr, 5))
        .collect::<Vec<_>>();
    publish_observer_health(&peers, &responsive, &[]).await;
    let prepared = timeout(
        FRESH_MAPPING_MEASURE_BUDGET + Duration::from_millis(200),
        prepare(&transport, &nat.observers),
    )
    .await
    .expect("the original total deadline must stop the slow response wait");
    assert_eq!(prepared.measurement_cost().stun_datagrams_sent, 3);
    assert_eq!(prepared.measurement_cost().stun_responses, 2);
    assert!(prepared.predictable.is_none());
    for socket in &prepared.birthday.sockets {
        transport
            .detach_dynamic_socket_by_index(socket.socket_index, "observer_test_complete")
            .await;
    }
}

#[tokio::test]
async fn ordinary_fresh_mapping_retains_its_short_sample_timeout() {
    let nat = SimulatedNat::start_with_observer_delays(
        1,
        false,
        [Duration::ZERO, Duration::ZERO, Duration::from_millis(450)],
    )
    .await;
    let (_peers, transport, nat) = generation_env_with_nat(nat).await;
    let (index, socket) = transport.bind_fresh_punch_socket().await.unwrap();
    let guard = transport
        .attach_dynamic_punch_socket("peer-b", index, socket.clone(), 0, 1, None)
        .await
        .unwrap();
    let measurement = transport
        .measure_fresh_mapping_batch(&socket, &nat.observers, Duration::from_secs(1), || true)
        .await;
    assert_eq!(measurement.stats.stun_datagrams_sent, 3);
    assert_eq!(measurement.stats.stun_responses, 2);
    assert_eq!(
        measurement.attempts.last().unwrap().outcome,
        AllocationAttemptOutcome::SentUnobserved
    );
    transport
        .detach_dynamic_socket_by_index(index, "observer_test_complete")
        .await;
    drop(guard);
}
