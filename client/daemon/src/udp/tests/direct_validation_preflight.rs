use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use p2pnet_crypto::NodeIdentity;

fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_millis(150)
}

async fn fixture() -> (
    UdpTransport,
    UdpSocket,
    DirectValidationIdentity,
    PreparedDirectValidationSend,
) {
    let local = NodeIdentity::generate();
    let remote = NodeIdentity::generate();
    let mut config = Config::generate_default("https://control.test", "net").unwrap();
    config.node.node_id = "peer-a".into();
    config.node.public_key = hex::encode(local.public_key());
    config.node.private_key = hex::encode(local.private_key());
    config.relay.path_policy = crate::config::PathPolicy::Auto;
    let peers = Arc::new(PeerManager::new(config));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers
        .add_peer(&PeerInfo {
            capabilities: crate::control::PeerCapabilities::default(),
            registration_seq: 0,
            node_id: "peer-b".into(),
            device_name: String::new(),
            app_version: "0.1.165".into(),
            public_key: hex::encode(remote.public_key()),
            endpoint: endpoint.to_string(),
            nat_type: "FullCone".into(),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let generation = peers.current_network_generation_sync();
    let lease = match udp
        .begin_or_merge_direct_validation("peer-b", endpoint, generation)
        .await
    {
        DirectValidationSessionStart::Spawn(lease) => lease,
        _ => panic!("fixture must own its ordinary validation session"),
    };
    let target = *lease.target_rx.borrow();
    let identity = DirectValidationIdentity::owned(
        crate::peer::PathEpoch::new(
            generation,
            target.peer_session_generation,
            target.remote_candidate_epoch,
        ),
        lease.owner_token,
        Some(17),
        Some(endpoint),
    );
    let prepared = udp
        .prepare_direct_validation_send("peer-b", identity)
        .await
        .unwrap();
    (udp, receiver, identity, prepared)
}

#[tokio::test]
async fn ordinary_preflight_uses_exact_socket_and_one_v2_non_nominating_datagram() {
    let (udp, receiver, identity, prepared) = fixture().await;
    let mut completion = udp
        .send_validation_preflight("peer-b", identity, &prepared, deadline(), deadline())
        .await
        .unwrap();
    let mut bytes = [0u8; 512];
    let (length, source) = timeout(Duration::from_secs(1), receiver.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source, prepared.socket.local_addr().unwrap());
    let key = udp.peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&bytes[..length], &key).unwrap();
    assert_eq!(packet.kind, PunchPacketKind::Punch);
    assert!(!packet.use_candidate);
    let pending = udp
        .pending_probes
        .lock()
        .await
        .get(&packet.nonce)
        .unwrap()
        .clone();
    assert!(pending.accepts_authenticated_ack);
    assert!(!pending.accepts_legacy_ack);
    assert_eq!(pending.endpoint, identity.request_endpoint().unwrap());
    assert_eq!(pending.socket_index, prepared.socket_index);
    assert!(matches!(
        completion.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(
        udp.send_validation_preflight("peer-b", identity, &prepared, deadline(), deadline())
            .await
            .unwrap_err(),
        "preflight_already_attempted",
    );
    assert!(
        timeout(Duration::from_millis(20), receiver.recv_from(&mut bytes))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn ordinary_preflight_rejects_wrong_request_or_socket_without_reserving_it() {
    let (udp, _receiver, identity, prepared) = fixture().await;
    let wrong_request = DirectValidationIdentity::owned(
        identity.epoch,
        identity.owner_token.unwrap(),
        Some(18),
        identity.request_endpoint(),
    );
    assert_eq!(
        udp.send_validation_preflight("peer-b", wrong_request, &prepared, deadline(), deadline())
            .await
            .unwrap_err(),
        "preflight_owner_revoked"
    );
    let wrong_socket = PreparedDirectValidationSend {
        socket_index: prepared.socket_index,
        socket: Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
    };
    assert_eq!(
        udp.send_validation_preflight("peer-b", identity, &wrong_socket, deadline(), deadline())
            .await
            .unwrap_err(),
        "preflight_socket_revoked"
    );
    assert!(
        !udp.direct_validation
            .expectations
            .lock()
            .await
            .get("peer-b")
            .unwrap()
            .preflight_attempted
    );
    assert!(udp.pending_probes.lock().await.is_empty());
}

#[tokio::test]
async fn preflight_receipt_preserves_original_request_when_same_class_target_moves() {
    let (udp, receiver, identity, prepared) = fixture().await;
    let original_deadline = deadline();
    // The fixture uses the same fixed receipt deadline as production. A lost
    // datagram or declined receipt must fail here, not park the whole suite.
    tokio::time::timeout_at(original_deadline, async {
        let completion = udp
            .send_validation_preflight(
                "peer-b",
                identity,
                &prepared,
                original_deadline,
                original_deadline,
            )
            .await
            .unwrap();
        let mut bytes = [0u8; 512];
        eprintln!("preflight_same_class_wait stage=probe_datagram original_budget_ms=150");
        let (length, _) = receiver.recv_from(&mut bytes).await.unwrap();
        let key = udp.peers.probe_key_for_peer("peer-b").await.unwrap();
        let packet = decode_authenticated_punch_packet(&bytes[..length], &key).unwrap();
        let pending = udp
            .pending_probes
            .lock()
            .await
            .remove(&packet.nonce)
            .unwrap();
        // A genuine Probe ACK may merge another public port into the worker while
        // the in-flight request keeps its original destination and exact lease.
        let drift = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let drift_endpoint = drift.local_addr().unwrap();
        {
            let sessions = udp.direct_validation.sessions.lock().await;
            let session = sessions.get("peer-b").unwrap();
            let current = *session.target_tx.borrow();
            session.target_tx.send_replace(DirectValidationTarget {
                endpoint: drift_endpoint,
                ..current
            });
        }
        let epoch = udp.network_epoch_gate.lock().await;
        assert!(
            udp.peers
                .learn_authenticated_endpoint_in_epoch(&epoch, "peer-b", drift_endpoint)
                .await
        );
        udp.complete_validation_preflight_in_epoch("peer-b", &pending)
            .await;
        let sender_retained = pending
            .validation_preflight
            .as_ref()
            .is_some_and(|receipt| receipt.completion.lock().unwrap().is_some());
        eprintln!(
            "preflight_same_class_wait stage=receipt expired={} sender_retained={sender_retained}",
            pending.is_expired(Instant::now()),
        );
        assert_eq!(completion.await, Ok(()));
        assert_eq!(
            udp.direct_validation
                .expectations
                .lock()
                .await
                .get("peer-b")
                .unwrap()
                .endpoint,
            identity.request_endpoint()
        );
    })
    .await
    .expect("same-class preflight exceeded its original 150ms receipt deadline");
}

#[tokio::test]
async fn expired_receipt_retained_by_pending_cannot_hide_the_original_deadline() {
    let (udp, receiver, identity, prepared) = fixture().await;
    let original_deadline = deadline();
    let mut completion = udp
        .send_validation_preflight(
            "peer-b",
            identity,
            &prepared,
            original_deadline,
            original_deadline,
        )
        .await
        .unwrap();
    let mut bytes = [0u8; 512];
    let (length, _) = tokio::time::timeout_at(original_deadline, receiver.recv_from(&mut bytes))
        .await
        .expect("the original preflight datagram must arrive before its deadline")
        .unwrap();
    let key = udp.peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&bytes[..length], &key).unwrap();
    let mut pending = udp
        .pending_probes
        .lock()
        .await
        .remove(&packet.nonce)
        .unwrap();
    // Force the actual production receipt's expired branch without sleeping,
    // changing its request identity or extending the original deadline.
    pending.expires_at = Instant::now();
    {
        let _epoch = udp.network_epoch_gate.lock().await;
        udp.complete_validation_preflight_in_epoch("peer-b", &pending)
            .await;
    }
    assert!(matches!(
        completion.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(
        tokio::time::timeout_at(original_deadline, &mut completion)
            .await
            .is_err(),
        "a retained expired sender must not turn the original deadline into an unbounded wait"
    );
    assert!(matches!(
        completion.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(pending);
    assert!(
        matches!(
            completion.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ),
        "dropping the sole pending owner must close the real receipt synchronously"
    );
}

#[tokio::test]
async fn deleted_pending_nonce_is_not_preflight_evidence_and_retired_owner_cannot_complete() {
    let (udp, receiver, identity, prepared) = fixture().await;
    let mut completion = udp
        .send_validation_preflight("peer-b", identity, &prepared, deadline(), deadline())
        .await
        .unwrap();
    let mut bytes = [0u8; 512];
    let (length, _) = receiver.recv_from(&mut bytes).await.unwrap();
    let key = udp.peers.probe_key_for_peer("peer-b").await.unwrap();
    let packet = decode_authenticated_punch_packet(&bytes[..length], &key).unwrap();
    let pending = udp
        .pending_probes
        .lock()
        .await
        .remove(&packet.nonce)
        .unwrap();
    assert!(matches!(
        completion.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    udp.finish_direct_validation_session("peer-b", identity.owner_token.unwrap())
        .await;
    let _epoch = udp.network_epoch_gate.lock().await;
    udp.complete_validation_preflight_in_epoch("peer-b", &pending)
        .await;
    assert!(matches!(
        completion.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    drop(pending);
    assert!(completion.await.is_err());
}

#[tokio::test]
async fn expired_preflight_deadline_does_not_send_or_extend_the_attempt() {
    let (udp, _receiver, identity, prepared) = fixture().await;
    // Holding the first admission dependency makes expiration independent of
    // scheduler speed; the public API must cancel before any physical send.
    let _epoch = udp.network_epoch_gate.lock().await;
    assert_eq!(
        udp.send_direct_validation_preflight(
            "peer-b",
            identity,
            &prepared,
            tokio::time::Instant::now()
        )
        .await,
        DirectValidationPreflightOutcome::TimedOut
    );
    assert!(udp.pending_probes.lock().await.is_empty());
}
