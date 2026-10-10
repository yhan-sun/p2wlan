use super::*;
use crate::udp::{DirectValidationSessionStart, UdpTransport};

#[tokio::test]
async fn delayed_candidate_cleanup_preserves_new_epoch_validation_owner() {
    let peer_id = "peer-handover-validation";
    let old_endpoint: SocketAddr = "198.51.100.20:51820".parse().unwrap();
    let new_endpoint: SocketAddr = "198.51.100.20:51821".parse().unwrap();
    let peers = Arc::new(PeerManager::new(test_config()));
    peers.add_peer(&test_peer(peer_id, old_endpoint)).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert_eq!(
        peers
            .add_candidates_with_metadata(
                peer_id,
                &[old_endpoint.to_string()],
                &HashMap::new(),
                10,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    let generation = peers.current_network_generation_sync();
    let session = peers.peer_session_generation_sync(peer_id).unwrap();
    let old_epoch = peers.current_remote_candidate_epoch(peer_id).await.unwrap();
    let old = match udp
        .begin_or_merge_direct_validation(peer_id, old_endpoint, generation)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease,
        _ => panic!("the first candidate epoch must own validation"),
    };
    assert!(
        peers
            .mark_direct_validation_started(
                peer_id,
                DirectValidationIdentity::owned(
                    PathEpoch::new(generation, session, old_epoch),
                    old.owner_token,
                    Some(0x5101),
                    Some(old_endpoint),
                ),
            )
            .await
    );
    assert!(
        udp.expect_direct_validation_ack_owned_on_socket(
            peer_id,
            0x5101,
            generation,
            old.owner_token,
            old_endpoint,
            Some(0),
        )
        .await
    );

    // Hold the real post-commit recovery resource: candidate publication can
    // finish, but its deferred registry cleanup cannot run yet. No sleep or
    // test-only production hook manufactures the ordering.
    let recovery_guard = peers.recovery_epochs.write().await;
    let handover = tokio::spawn({
        let peers = peers.clone();
        async move {
            peers
                .add_candidates_with_metadata(
                    peer_id,
                    &[new_endpoint.to_string()],
                    &HashMap::new(),
                    11,
                    Some(u64::MAX),
                )
                .await
        }
    });
    let new_epoch = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let epoch = peers.current_remote_candidate_epoch(peer_id).await.unwrap();
            if epoch > old_epoch {
                break epoch;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("candidate publication must precede deferred cleanup");
    assert!(!handover.is_finished());
    let new = match udp
        .begin_or_merge_direct_validation(peer_id, new_endpoint, generation)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease,
        _ => panic!("the committed candidate epoch must grant a new owner"),
    };
    assert!(old.target_rx.borrow().cancelled);
    assert!(
        peers
            .mark_direct_validation_started(
                peer_id,
                DirectValidationIdentity::owned(
                    PathEpoch::new(generation, session, new_epoch),
                    new.owner_token,
                    Some(0x5102),
                    Some(new_endpoint),
                ),
            )
            .await
    );
    assert!(
        udp.expect_direct_validation_ack_owned_on_socket(
            peer_id,
            0x5102,
            generation,
            new.owner_token,
            new_endpoint,
            Some(0),
        )
        .await
    );
    drop(recovery_guard);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), handover)
            .await
            .expect("deferred cleanup must finish")
            .unwrap(),
        CandidateSetApplyResult::Applied
    );
    assert!(
        !new.target_rx.borrow().cancelled,
        "an old candidate commit must not revoke a new-epoch validation owner"
    );
    assert!(
        !udp.finish_direct_validation_session(peer_id, old.owner_token)
            .await
    );
    assert_eq!(
        udp.direct_validation_target(peer_id)
            .await
            .unwrap()
            .owner_token,
        new.owner_token
    );
    assert!(udp
        .consume_direct_validation_ack(
            peer_id,
            0x5101,
            generation,
            old.owner_token,
            generation,
            old_endpoint,
            Some(0),
            true,
        )
        .await
        .is_err());
    let expectation = udp
        .consume_direct_validation_ack(
            peer_id,
            0x5102,
            generation,
            new.owner_token,
            generation,
            new_endpoint,
            Some(0),
            true,
        )
        .await
        .expect("the new owner's exact ACK must survive delayed cleanup");
    let epoch_gate = peers.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    assert!(peers
        .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
            &epoch_guard,
            peer_id,
            Some(new_endpoint),
            generation,
            udp.local_addr().ok(),
            None,
            Some(new_epoch),
            Some(DirectValidationIdentity::authenticated_ack(
                PathEpoch::new(generation, session, new_epoch),
                expectation.owner_token,
                expectation.request_id,
                expectation.endpoint,
                new_endpoint,
            )),
        )
        .await);
    drop(epoch_guard);
    assert_eq!(
        peers.get_connection(peer_id).await.unwrap().state,
        ConnectionState::Direct
    );
}
