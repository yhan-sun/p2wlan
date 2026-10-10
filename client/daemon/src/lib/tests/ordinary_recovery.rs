use super::*;

#[tokio::test(start_paused = true)]
async fn ordinary_frozen_budget_is_reported_without_claiming_supersession_or_sending() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://control.invalid", "ordinary-budget-test").unwrap(),
    ));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let peer_id = "ordinary-budget-peer";
    peers
        .add_peer(&deferred_initiator_test_peer(
            peer_id,
            &endpoint.to_string(),
        ))
        .await;
    let epoch = match peers.recovery_epoch_admit(peer_id).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        other => panic!("initial recovery must be admitted: {other:?}"),
    };
    peers
        .record_zero_send_recovery_session(peer_id, 1, 1, 1, "test_budget_exhausted")
        .await;
    assert_eq!(
        peers.recovery_epoch_admit(peer_id).await,
        RecoveryAdmission::BudgetExhausted { epoch }
    );
    let original_budget = peers.recovery_epoch_work_budget_report(peer_id).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let deduplicator = PunchAttemptDeduplicator::default();
    for _ in 0..3 {
        // Frozen targets enter the ordinary production admission directly,
        // independently of planner eligibility and asynchronous candidate IO.
        spawn_hole_punch_task(
            udp.clone(),
            peers.clone(),
            deduplicator.clone(),
            peer_id.to_owned(),
            Duration::from_millis(10),
            2,
            None,
            None,
            None,
            Some(vec![endpoint]),
        )
        .await;
        assert_eq!(deduplicator.active_session_count(), 0);
        assert_eq!(
            peers.recovery_epoch_work_budget_report(peer_id).await,
            original_budget,
            "a rejected trigger must not rebuild, reopen or spend the frozen epoch"
        );
    }
    let connection = peers.get_connection(peer_id).await.unwrap();
    assert!(!peers.is_direct(peer_id).await);
    assert!(connection.direct_health.last_error.is_none());
    assert!(!connection.direct_events.iter().any(|event| matches!(
        event.stage.as_str(),
        "punch_suppressed_superseded" | "punch_started" | "punch_probes_sent"
    )));
    let rejections: Vec<_> = connection
        .direct_events
        .iter()
        .filter(|event| event.stage == "punch_suppressed_budget_exhausted")
        .collect();
    assert_eq!(rejections.len(), 3);
    assert!(rejections.iter().all(|event| event.sent_probes == Some(0)));
    let mut bytes = [0u8; 512];
    assert_eq!(
        receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "budget refusal happens before a physical send or worker claim"
    );
}
