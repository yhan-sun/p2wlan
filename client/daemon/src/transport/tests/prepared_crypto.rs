use crate::dataplane_resources::{BufferStage, ResidencyStage, ResourceCapture};
use crate::request_carriage::test_support::{mint_routed_request, peer_info, PEER};
use crate::request_carriage::RawOutboundReceiver;

async fn install(
    transport: &WireGuardTransport,
    session: TransportSession,
    life: PeerSessionGeneration,
) {
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    transport
        .install_active_session_for_lifecycle_locked(PEER, None, session, life)
        .await;
    drop(emit);
}

#[tokio::test]
async fn business_padding_16_never_changes_control_or_keepalive_encryption() {
    let (transport, _rx) = WireGuardTransport::new();
    let transport = transport.with_business_padding_16(true);
    let (local, mut remote) = establish_sessions();
    transport.add_session("peer-a", local).await;
    let control = Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        7,
        8,
        &build_direct_validation_payload(DirectValidationKind::Request, 1, 2, 3, 4),
    );
    for packet in [vec![], control] {
        let encrypted = transport
            .encrypt_outbound(OutboundPacket {
                room_authorization: None,
                peer_id: "peer-a".into(),
                dst_ip: "10.20.0.2".into(),
                packet: packet.clone(),
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(encrypted.wire_bytes.len(), packet.len() + 32);
        assert_eq!(
            remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
            packet
        );

        // An internal ICMP echo can also return through TUN's business FIFO.
        // The shared control classification excludes it from padding there.
        let prepared = PreparedEncryptionBuffer::new_for_business(&packet, true, None).unwrap();
        let emit = transport.acquire_outbound_emit_guard("peer-a").await;
        let encrypted = transport
            .encrypt_request_with_prepared_buffer_diagnostics(
                OutboundPacket {
                    room_authorization: None,
                    peer_id: "peer-a".into(),
                    dst_ip: "10.20.0.2".into(),
                    packet: packet.clone(),
                    trace: None,
                }
                .into(),
                prepared,
                None,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        drop(emit);
        assert_eq!(encrypted.wire_bytes.len(), packet.len() + 32);
        assert_eq!(
            remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
            packet
        );
    }
}

fn drained(capture: &ResourceCapture) {
    let snapshot = capture.residency_snapshot();
    assert!(snapshot.valid && snapshot.coherent);
    assert_eq!(snapshot.gap_bits, 0);
    assert_eq!(snapshot.total.unwrap().live_buffers, 0);
    assert_eq!(
        capture
            .snapshot()
            .buffer(BufferStage::PreparationPlaintext)
            .live_buffers,
        0
    );
}

#[tokio::test]
async fn prepared_crypto_source_comes_from_actual_replacement_not_storage_or_input() {
    let f = mint_routed_request().await;
    let original_life = f.record.expected_target_lifecycle().unwrap();
    let original_sent = f.record.sent_at;
    let prepared = PreparedEncryptionBuffer::new(f.delivery.packet.len(), None).unwrap();
    f.peers.remove_peer(PEER).await;
    f.peers.add_peer(&peer_info()).await;
    let actual_life = f.peers.peer_session_generation_sync(PEER).unwrap();
    assert_ne!(actual_life, original_life);
    let (session, mut remote) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    install(&transport, session, actual_life).await;
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let gate = f.peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let before = Instant::now();
    let encrypted = transport
        .encrypt_request_with_prepared_buffer_diagnostics(f.delivery.clone(), prepared, None, None)
        .await
        .unwrap()
        .unwrap();
    let after = Instant::now();
    drop(epoch);
    drop(emit);
    let source = encrypted.source().unwrap();
    assert!(source.belongs_to(&transport));
    assert_eq!(source.authorized_peer_lifecycle(), Some(actual_life));
    assert_eq!(source.session_instance(), instance);
    assert!(before <= source.encrypted_at() && source.encrypted_at() <= after);
    assert_eq!(wire_counter(&encrypted.wire_bytes), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
        f.record.original_packet()
    );
    assert!(Arc::ptr_eq(
        &encrypted.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert_eq!(f.record.expected_target_lifecycle(), Some(original_life));
    assert_eq!(f.record.sent_at, original_sent);
}

#[tokio::test]
async fn prepared_crypto_missing_and_expired_session_drop_storage_without_source() {
    let f = mint_routed_request().await;
    let capture = ResourceCapture::new([0x91; 16]);
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    for expired in [false, true] {
        if expired {
            let (session, _) = establish_sessions();
            let session = session.with_thresholds(0, Duration::MAX, 0, Duration::MAX);
            install(
                &transport,
                session,
                f.record.expected_target_lifecycle().unwrap(),
            )
            .await;
        }
        let prepared =
            PreparedEncryptionBuffer::new(f.delivery.packet.len(), Some(&capture)).unwrap();
        let emit = transport.acquire_outbound_emit_guard(PEER).await;
        let gate = f.peers.network_epoch_gate();
        let epoch = gate.lock().await;
        let result = transport
            .encrypt_request_with_prepared_buffer_diagnostics(
                f.delivery.clone(),
                prepared,
                None,
                None,
            )
            .await
            .unwrap();
        drop(epoch);
        drop(emit);
        assert!(result.is_none());
        drained(&capture);
    }
}

#[tokio::test]
async fn prepared_crypto_cancelled_actual_session_wait_drains_and_keeps_counter() {
    let f = mint_routed_request().await;
    let capture = ResourceCapture::new([0x92; 16]);
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    let (session, mut remote) = establish_sessions();
    install(
        &transport,
        session,
        f.record.expected_target_lifecycle().unwrap(),
    )
    .await;
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let gate = f.peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let registry = transport.hold_session_registry_for_test().await;
    let prepared = PreparedEncryptionBuffer::new(f.delivery.packet.len(), Some(&capture)).unwrap();
    let mut attempt = Box::pin(transport.encrypt_request_with_prepared_buffer_diagnostics(
        f.delivery.clone(),
        prepared,
        None,
        None,
    ));
    assert!(matches!(
        futures_util::poll!(attempt.as_mut()),
        std::task::Poll::Pending
    ));
    assert_eq!(capture.residency_snapshot().total.unwrap().live_buffers, 2);
    assert_eq!(
        capture
            .snapshot()
            .buffer(BufferStage::PreparationPlaintext)
            .live_buffers,
        1
    );
    drop(attempt);
    drained(&capture);
    drop(registry);
    let prepared = PreparedEncryptionBuffer::new(f.delivery.packet.len(), Some(&capture)).unwrap();
    let encrypted = transport
        .encrypt_request_with_prepared_buffer_diagnostics(f.delivery.clone(), prepared, None, None)
        .await
        .unwrap()
        .unwrap();
    drop(epoch);
    drop(emit);
    assert_eq!(wire_counter(&encrypted.wire_bytes), Some(0));
    assert_eq!(
        remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
        f.record.original_packet()
    );
    drop(encrypted);
    drained(&capture);
}

#[tokio::test]
async fn prepared_crypto_success_moves_one_real_buffer_observation_without_double_count() {
    let capture = ResourceCapture::new([0x93; 16]);
    let (transport, receiver) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    let mut receiver = RawOutboundReceiver::from(receiver);
    let raw = s3a_outbound(1);
    let plaintext = raw.packet.clone();
    transport.outbound_tx.send(raw).await.unwrap();
    let raw = receiver.recv().await.unwrap();
    let (session, mut remote) = establish_sessions();
    assert!(!transport.add_session("peer-a", session).await);
    let prepared = PreparedEncryptionBuffer::new(raw.packet.len(), Some(&capture)).unwrap();
    let before = capture.residency_snapshot();
    assert_eq!(before.total.unwrap().live_buffers, 2);
    assert_eq!(
        before
            .stage(ResidencyStage::PreparationPlaintext)
            .unwrap()
            .len_bytes,
        plaintext.len() as u64 + 32
    );
    assert_eq!(
        before
            .stage(ResidencyStage::SerializedWire)
            .unwrap()
            .live_buffers,
        0
    );
    let emit = transport.acquire_outbound_emit_guard("peer-a").await;
    let encrypted = transport
        .encrypt_request_with_prepared_buffer_diagnostics(raw, prepared, None, None)
        .await
        .unwrap()
        .unwrap();
    drop(emit);
    assert!(encrypted.binding().is_none() && encrypted.source().is_none());
    let after = capture.residency_snapshot();
    assert!(after.valid && after.coherent);
    assert_eq!(after.gap_bits, 0);
    assert_eq!(after.unknown_bits, 0);
    assert_eq!(after.total.unwrap().live_buffers, 1);
    assert_eq!(after.total, after.stage(ResidencyStage::SerializedWire));
    assert_eq!(
        after.total.unwrap().len_bytes,
        encrypted.wire_bytes.len() as u64
    );
    assert_eq!(
        after.total.unwrap().capacity_bytes,
        encrypted.wire_bytes.capacity() as u64
    );
    assert_eq!(
        remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
        plaintext
    );
    drop(encrypted);
    drained(&capture);
}

#[tokio::test]
async fn prepared_crypto_wrong_length_has_no_source_and_does_not_advance_actual_counter() {
    let f = mint_routed_request().await;
    let capture = ResourceCapture::new([0x94; 16]);
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_resource_capture(capture.clone()).unwrap();
    let (session, _) = establish_sessions();
    install(
        &transport,
        session,
        f.record.expected_target_lifecycle().unwrap(),
    )
    .await;
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let gate = f.peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let wrong = PreparedEncryptionBuffer::new(f.delivery.packet.len() + 1, Some(&capture)).unwrap();
    assert!(transport
        .encrypt_request_with_prepared_buffer_diagnostics(f.delivery.clone(), wrong, None, None)
        .await
        .is_err());
    drained(&capture);
    let correct = PreparedEncryptionBuffer::new(f.delivery.packet.len(), Some(&capture)).unwrap();
    let encrypted = transport
        .encrypt_request_with_prepared_buffer_diagnostics(f.delivery.clone(), correct, None, None)
        .await
        .unwrap()
        .unwrap();
    drop(epoch);
    drop(emit);
    assert_eq!(wire_counter(&encrypted.wire_bytes), Some(0));
    assert!(encrypted.source().is_some());
    drop(encrypted);
    drained(&capture);
}
