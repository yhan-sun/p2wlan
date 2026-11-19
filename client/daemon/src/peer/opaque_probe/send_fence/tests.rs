use super::*;

async fn fixture() -> (PeerManager, crate::control::ControlClient, PeerInfo) {
    let manager =
        PeerManager::new(Config::generate_default("https://control.example.com", "test").unwrap());
    let control = crate::control::ControlClient::disabled_for_test();
    control.set_local_registration_for_test(Some(1), crate::control::PeerCapabilities::current());
    manager.bind_opaque_probe_registration(control.clone());
    let peer = PeerInfo {
        node_id: "peer".into(),
        public_key: hex::encode(NodeIdentity::generate().public_key()),
        virtual_ip: "10.20.0.2".into(),
        online: true,
        registration_seq: 1,
        capabilities: crate::control::PeerCapabilities::default(),
        ..Default::default()
    };
    manager.add_peer(&peer).await;
    (manager, control, peer)
}

#[tokio::test]
async fn probe_send_fence_keeps_legacy_then_rejects_original_wire_after_upgrade() {
    let (manager, _, mut peer) = fixture().await;
    let fence = manager
        .snapshot_probe_send_fence("peer", true)
        .await
        .unwrap();
    let key = manager.probe_key_for_peer("peer").await.unwrap();
    let bytes = p2pnet_nat::build_authenticated_punch_packet("local", "peer", 0, &key).0;
    let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.writable().await.unwrap();
    assert!(manager
        .with_probe_send_fence(&fence, &bytes, || sender
            .try_send_to(&bytes, receiver.local_addr().unwrap()))
        .unwrap()
        .is_ok());
    let mut received = [0; 1024];
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..len], bytes);
    peer.registration_seq = 2;
    peer.capabilities = crate::control::PeerCapabilities::current();
    manager.add_peer(&peer).await;
    let called = std::cell::Cell::new(false);
    assert!(matches!(
        manager.with_probe_send_fence(&fence, &bytes, || {
            called.set(true);
            sender.try_send_to(&bytes, receiver.local_addr().unwrap())
        }),
        Err(ProbeSendFenceError::Revoked)
    ));
    assert!(!called.get());
    assert_eq!(
        receiver.try_recv_from(&mut received).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn probe_send_fence_rejects_binding_and_local_auth_changes_and_recovers_from_contention() {
    let (manager, control, mut peer) = fixture().await;
    peer.registration_seq = 2;
    peer.capabilities = crate::control::PeerCapabilities::current();
    manager.add_peer(&peer).await;
    manager
        .set_probe_session_binding("peer", Some("one".into()), Some([1; 32]))
        .await;
    let fence = manager
        .snapshot_probe_send_fence("peer", true)
        .await
        .unwrap();
    let key = manager.probe_key_for_peer("peer").await.unwrap();
    let bytes = p2pnet_nat::build_opaque_punch_packet_with_nomination(
        "local", "peer", 0, false, &key, &key,
    )
    .0;
    let held = manager.connections.write().await;
    assert_eq!(
        manager.with_probe_send_fence(&fence, &bytes, || ()),
        Err(ProbeSendFenceError::Busy)
    );
    drop(held);
    assert_eq!(manager.with_probe_send_fence(&fence, &bytes, || ()), Ok(()));
    manager
        .set_probe_session_binding("peer", Some("two".into()), Some([2; 32]))
        .await;
    assert_eq!(
        manager.with_probe_send_fence(&fence, &bytes, || ()),
        Err(ProbeSendFenceError::Revoked)
    );
    let current = manager
        .snapshot_probe_send_fence("peer", true)
        .await
        .unwrap();
    control.set_local_registration_for_test(None, crate::control::PeerCapabilities::default());
    assert_eq!(
        manager.with_probe_send_fence(&current, &bytes, || ()),
        Err(ProbeSendFenceError::Revoked)
    );
}

#[tokio::test]
async fn probe_send_fence_only_allows_unidentified_v1_for_initial_unknown_peer() {
    let manager =
        PeerManager::new(Config::generate_default("https://control.example.com", "test").unwrap());
    let initial = manager
        .snapshot_probe_send_fence("unknown", true)
        .await
        .unwrap();
    let v1 = p2pnet_nat::build_punch_packet();
    assert_eq!(manager.with_probe_send_fence(&initial, &v1, || ()), Ok(()));
    let v2 = p2pnet_nat::build_authenticated_punch_packet("local", "unknown", 0, &[3; 32]).0;
    assert_eq!(
        manager.with_probe_send_fence(&initial, &v2, || ()),
        Err(ProbeSendFenceError::Revoked)
    );
    manager
        .add_peer(&PeerInfo {
            node_id: "unknown".into(),
            public_key: hex::encode(NodeIdentity::generate().public_key()),
            virtual_ip: "10.20.0.2".into(),
            online: true,
            ..Default::default()
        })
        .await;
    assert_eq!(
        manager.with_probe_send_fence(&initial, &v1, || ()),
        Err(ProbeSendFenceError::Revoked)
    );
    manager.remove_peer("unknown").await;
    assert_eq!(
        manager.with_probe_send_fence(&initial, &v1, || ()),
        Err(ProbeSendFenceError::Revoked)
    );
    assert!(manager
        .snapshot_probe_send_fence("unknown", true)
        .await
        .is_none());
}
