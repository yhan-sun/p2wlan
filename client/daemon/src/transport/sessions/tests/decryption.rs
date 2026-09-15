use super::*;

#[tokio::test]
async fn pending_session_expiring_while_waiting_for_emit_lock_is_not_promoted() {
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let local = TransportSession::new(p2pnet_wireguard::TransportKeyPair {
        send_key: [1; 32],
        recv_key: [2; 32],
        our_index: 77,
        peer_index: 88,
    });
    let mut remote = TransportSession::new(p2pnet_wireguard::TransportKeyPair {
        send_key: [2; 32],
        recv_key: [1; 32],
        our_index: 88,
        peer_index: 77,
    });
    assert!(matches!(
        transport
            .stage_responder_session("peer", "expiring".to_string(), local)
            .await,
        ResponderSessionStage::Staged { .. },
    ));
    let emit_lock = transport.outbound_emit_lock("peer").await;
    let emit_guard = emit_lock.lock().await;
    let wire = remote
        .encrypt(b"authenticated-before-expiry")
        .unwrap()
        .to_bytes();
    let mut decrypt = std::pin::pin!(transport.decrypt_inbound(&wire));
    {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            decrypt.as_mut().poll(&mut context),
            std::task::Poll::Pending
        ));
    }
    transport
        .expire_pending_responder_for_test("peer", "expiring")
        .await;
    drop(emit_guard);
    assert!(
        decrypt.await.unwrap().is_none(),
        "expired responder must not become active after the emit-lock wait"
    );
    let status = transport.session_status("peer").await;
    assert!(!status.has_active);
    assert_eq!(status.pending_responder_count, 0);
}
