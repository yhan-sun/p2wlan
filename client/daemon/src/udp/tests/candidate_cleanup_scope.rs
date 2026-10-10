use super::*;

fn expectation(epoch: crate::peer::PathEpoch, owner: u64) -> DirectValidationExpectation {
    DirectValidationExpectation {
        preflight_attempted: false,
        hard_hard_pair: None,
        request_id: 41,
        generation: epoch.network_generation,
        peer_session_generation: epoch.peer_session_generation,
        remote_candidate_epoch: epoch.remote_candidate_epoch,
        owner_token: owner,
        endpoint: Some("127.0.0.1:47001".parse().unwrap()),
        socket_index: Some(0),
        lease: None,
        sent_at: None,
        expires_at: Instant::now() + Duration::from_secs(1),
    }
}

fn epoch(network: u64, session: u64, candidate: u64) -> crate::peer::PathEpoch {
    crate::peer::PathEpoch::new(network, PeerSessionGeneration::for_test(session), candidate)
}

#[tokio::test]
async fn candidate_cleanup_preserves_current_newer_and_other_lifecycle_owners() {
    let boundary = epoch(7, 11, 3);
    for (target_epoch, cancelled) in [
        (epoch(7, 11, 2), true),
        (epoch(7, 11, 3), false),
        (epoch(7, 11, 4), false),
        (epoch(8, 11, 2), false),
        (epoch(7, 12, 2), false),
    ] {
        let registry = DirectValidationRegistry::new();
        let target = DirectValidationTarget {
            endpoint: "127.0.0.1:47001".parse().unwrap(),
            generation: target_epoch.network_generation,
            peer_session_generation: target_epoch.peer_session_generation,
            remote_candidate_epoch: target_epoch.remote_candidate_epoch,
            owner_token: 13,
            cancelled: false,
        };
        let (target_tx, target_rx) = watch::channel(target);
        registry.sessions.lock().await.insert(
            "peer-b".to_string(),
            DirectValidationSession {
                target_tx,
                hard_hard: None,
            },
        );
        registry
            .expectations
            .lock()
            .await
            .insert("peer-b".to_string(), expectation(target_epoch, 13));
        registry.suppress_slow_relay_validation("peer-b", 7).await;
        registry
            .cancel_peer_before_remote_candidate_epoch("peer-b", boundary)
            .await;
        assert_eq!(target_rx.borrow().cancelled, cancelled);
        assert_eq!(
            registry.sessions.lock().await.contains_key("peer-b"),
            !cancelled
        );
        assert_eq!(
            registry.expectations.lock().await.contains_key("peer-b"),
            !cancelled
        );
        assert!(
            registry
                .is_slow_relay_validation_suppressed("peer-b", 7)
                .await
        );

        // Lifecycle shutdown still revokes current ownership and its cooldown.
        registry
            .cancel_peer_with_reason("peer-b", "peer_left")
            .await;
        assert!(target_rx.borrow().cancelled);
        assert!(!registry.sessions.lock().await.contains_key("peer-b"));
        assert!(!registry.expectations.lock().await.contains_key("peer-b"));
        assert!(
            !registry
                .is_slow_relay_validation_suppressed("peer-b", 7)
                .await
        );
    }
}

#[tokio::test]
async fn candidate_cleanup_fences_orphan_expectations_by_all_epoch_domains() {
    let boundary = epoch(7, 11, 3);
    for (request_epoch, removed) in [
        (epoch(7, 11, 2), true),
        (epoch(7, 11, 3), false),
        (epoch(7, 11, 4), false),
        (epoch(8, 11, 2), false),
        (epoch(7, 12, 2), false),
    ] {
        let registry = DirectValidationRegistry::new();
        registry
            .expectations
            .lock()
            .await
            .insert("peer-b".to_string(), expectation(request_epoch, 13));
        registry
            .cancel_peer_before_remote_candidate_epoch("peer-b", boundary)
            .await;
        assert_eq!(
            registry.expectations.lock().await.contains_key("peer-b"),
            !removed
        );
        registry
            .cancel_peer_with_reason("peer-b", "peer_left")
            .await;
        assert!(!registry.expectations.lock().await.contains_key("peer-b"));
    }
}
