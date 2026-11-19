use super::super::test_support::*;
use super::*;
use crate::config::Config;

#[tokio::test]
async fn business_padding_16_cannot_cross_into_unknown_direct_budget_and_plaintext_recovers() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers.add_peer(&test_peer("peer-a", endpoint)).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    peers
        .record_direct_probe_success_with_latency("peer-a", endpoint, None)
        .await;
    peers.record_direct_success("peer-a", Some(endpoint)).await;
    let generation = peers.current_network_generation_sync();
    let original = Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        1,
        2,
        b"x",
    );
    let (transport, _outbound) = WireGuardTransport::new();
    let transport = transport.with_business_padding_16(true);
    let (local, mut remote) = establish_sessions();
    transport.add_session("peer-a", local).await;
    let packet = OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        packet: original.clone(),
        trace: None,
    };
    let prepared =
        crate::transport::PreparedEncryptionBuffer::new_for_business(&original, true, None)
            .unwrap();
    let emit = transport.acquire_outbound_emit_guard("peer-a").await;
    let padded = transport
        .encrypt_request_with_prepared_buffer_diagnostics(
            packet.clone().into(),
            prepared,
            None,
            None,
        )
        .await
        .unwrap()
        .unwrap();
    let udps = RwLock::new(Some(udp));
    let relays = RwLock::new(None);
    let outcome = send_encrypted_packet_bounded(
        &padded,
        &peers,
        true,
        &udps,
        &relays,
        false,
        None,
        None,
        original.len(),
        false,
        SendAdmissionWindow {
            deadline: Some(Instant::now() + Duration::from_secs(2)),
            stopping: None,
            expected_generation: generation,
        },
    )
    .await;
    assert!(matches!(outcome, SendOutcome::DirectBudgetStale { .. }));
    let mut bytes = [0; 2048];
    assert_eq!(
        receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(emit);

    // The existing retry owns plaintext. A fresh attempt on this unmanaged
    // Direct path omits optional padding and can deliver the original packet.
    let outcome = encrypt_then_send(
        packet, &transport, &peers, generation, true, &udps, &relays, false,
    )
    .await;
    assert!(matches!(outcome, EncryptSendOutcome::Sent));
    let (len, _) = timeout(Duration::from_secs(2), receiver.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, original.len() + 32);
    assert_eq!(remote.decrypt_from_bytes(&bytes[..len]).unwrap(), original);
}

#[test]
fn relay_queue_full_and_writer_closed_are_safe_plaintext_retries() {
    for error in [
        p2pnet_relay::RelayError::CommandQueueFull,
        p2pnet_relay::RelayError::WriterStoppedBeforeAccept,
        p2pnet_relay::RelayError::WriteBoundaryRejected,
    ] {
        let outcome = relay_send_failure(&crate::error::DaemonError::RelaySend {
            endpoint: "tcp://relay.test:1".to_string(),
            error,
        });
        assert!(matches!(
            outcome,
            SendOutcome::Retryable(RetryableSendFailure::RelaySendNotHanded { .. })
        ));
    }
}

#[test]
fn unknown_relay_failure_is_terminal_delivery_uncertain() {
    let outcome = relay_send_failure(&crate::error::DaemonError::RelaySend {
        endpoint: "tcp://relay.test:1".to_string(),
        error: p2pnet_relay::RelayError::WriteUncertain(
            "relay protocol rejected frame after write".into(),
        ),
    });
    assert!(matches!(
        outcome,
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_RELAY_DELIVERY_UNCERTAIN,
            ..
        })
    ));
}

#[test]
fn send_timeout_is_terminal_delivery_uncertain() {
    assert!(matches!(
        outbound_send_timeout_failure_for_path(REASON_RELAY_DELIVERY_UNCERTAIN),
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_RELAY_DELIVERY_UNCERTAIN,
            ..
        })
    ));
}

#[test]
fn uncertain_direct_handoff_is_terminal_and_not_relay_replayed() {
    let outcome = SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
        reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
        err: "Direct UDP send result uncertain".to_string(),
    });
    assert!(matches!(
        outcome,
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
            ..
        })
    ));
}

#[tokio::test]
async fn send_selector_accepts_authoritative_direct_before_relay_transport_publish() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let endpoint: SocketAddr = "198.51.100.50:51850".parse().unwrap();
    manager.add_peer(&test_peer("peer-a", endpoint)).await;
    let generation = manager.current_network_generation().await;

    // This is the exact startup race: relay is expected/configured, but
    // its transport object has not been published yet; Direct has already
    // completed encrypted validation.  The ACK is authoritative for the
    // Direct data path, while the relay expectation remains standby state.
    assert!(
        !manager
            .is_data_path_admitted_for_generation("peer-a", generation, true)
            .await
    );
    manager
        .record_direct_probe_success_with_latency(
            "peer-a",
            endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager
        .record_direct_success("peer-a", Some(endpoint))
        .await;

    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes: vec![0; 32],
        is_business: true,
    };
    let selection = select_outbound_path(&packet, &manager, true, false, true, None, false).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(
        selection.reason_code,
        crate::peer::REASON_PATH_DIRECT_STICKY
    );
    assert!(selection.direct_confirmed);
}

#[tokio::test]
async fn stale_generation_is_rejected_before_counter_allocation() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let expected_generation = manager.current_network_generation().await;
    manager
        .advance_network_generation("test-generation-race")
        .await;
    let transport = WireGuardTransport::new().0;
    let udp = RwLock::new(None);
    let relay = RwLock::new(None);

    let outcome = encrypt_then_send(
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0x00, 0x00, 0x14],
            trace: None,
        },
        &transport,
        &manager,
        expected_generation,
        true,
        &udp,
        &relay,
        true,
    )
    .await;

    assert!(matches!(
        outcome,
        EncryptSendOutcome::Retryable {
            reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
            ..
        }
    ));
}
