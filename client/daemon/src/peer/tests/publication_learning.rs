#[tokio::test]
async fn retired_publication_cannot_train_fresh_mapping_or_admit_recovery_after_wait() {
    let daemon = crate::Daemon::new(test_config());
    let manager = daemon.peers.clone();
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51841".parse().unwrap()))
        .await;
    let udp = crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), manager.clone())
        .await
        .unwrap();
    daemon.udp_transport_publication.publish(udp.clone()).await;
    let fence = crate::control::CandidatePublicationFence::new(
        manager.clone(),
        None,
        "peer1".into(),
        manager.current_network_generation_sync(),
        manager.peer_session_generation_sync("peer1").unwrap(),
        0,
    )
    .with_endpoint(crate::EndpointPublicationFence::new(&udp, &manager), 1);
    let model = p2pnet_nat::mapping::build_model(
        &[45390, 45391, 45392],
        Some("203.0.113.10".parse().unwrap()),
        1_000,
    );
    manager
        .record_fresh_mapping(
            "peer1",
            model,
            vec![45393, 45394],
            "127.0.0.1:58980".parse().unwrap(),
            Some("203.0.113.10".parse().unwrap()),
            39,
            manager.current_network_generation_sync(),
        )
        .await;
    let held_mapping = manager.local_fresh_mappings.write().await;
    let mut learning = Box::pin(manager.record_fresh_mapping_prediction_result_fenced(
        "peer1",
        "203.0.113.10:45394".parse().unwrap(),
        Some(&fence),
    ));
    assert!(futures_util::poll!(learning.as_mut()).is_pending());
    let held_epochs = manager.recovery_epochs.read().await;
    let mut admission =
        Box::pin(manager.recovery_epoch_admit_for_publication("peer1", Some(&fence)));
    assert!(futures_util::poll!(admission.as_mut()).is_pending());
    // Retire only the owner, without changing network generation: this is
    // the teardown window that a generation-only check cannot detect.
    daemon.udp_transport_publication.clear_current().await;
    let replacement = crate::UdpTransport::bind("127.0.0.1:0".parse().unwrap(), manager.clone())
        .await
        .unwrap();
    daemon
        .udp_transport_publication
        .publish(replacement.clone())
        .await;
    drop(held_mapping);
    drop(held_epochs);
    learning.await;
    assert!(matches!(admission.await, RecoveryAdmission::Superseded));
    assert!(manager
        .fresh_mapping_history
        .lock()
        .unwrap()
        .get("peer1")
        .is_none());
    assert_eq!(manager.recovery_epoch_for("peer1").await, 0);
    let current = crate::control::CandidatePublicationFence::new(
        manager.clone(),
        None,
        "peer1".into(),
        manager.current_network_generation_sync(),
        manager.peer_session_generation_sync("peer1").unwrap(),
        0,
    )
    .with_endpoint(
        crate::EndpointPublicationFence::new(&replacement, &manager),
        1,
    );
    let epoch_gate = manager.network_epoch_gate();
    let epoch_transition = epoch_gate.lock().await;
    // Even a current publication must not partly commit while the existing
    // epoch owner is transitioning. These calls must return without waiting
    // for the gate, and leave both authoritative stores untouched.
    tokio::time::timeout(Duration::from_secs(1), async {
        manager
            .record_fresh_mapping_prediction_result_fenced(
                "peer1",
                "203.0.113.10:45393".parse().unwrap(),
                Some(&current),
            )
            .await;
        assert!(matches!(
            manager
                .recovery_epoch_admit_for_publication("peer1", Some(&current))
                .await,
            RecoveryAdmission::Superseded
        ));
    })
    .await
    .expect("epoch contention must not wait while holding local writers");
    assert!(manager
        .fresh_mapping_history
        .lock()
        .unwrap()
        .get("peer1")
        .is_none());
    assert_eq!(manager.recovery_epoch_for("peer1").await, 0);
    drop(epoch_transition);
    manager
        .record_fresh_mapping_prediction_result_fenced(
            "peer1",
            "203.0.113.10:45394".parse().unwrap(),
            Some(&current),
        )
        .await;
    assert_eq!(
        manager
            .fresh_mapping_history
            .lock()
            .unwrap()
            .get("peer1")
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        manager
            .recovery_epoch_admit_for_publication("peer1", Some(&current))
            .await,
        RecoveryAdmission::Accepted { .. }
    ));
}
