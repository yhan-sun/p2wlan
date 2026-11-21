// Actual reader → original rendezvous/daemon queue controls; neutral facts only.
// No physical publisher, authentication-owner commit, score or native TUN claim.
use super::*;

async fn receive_original_data(
    rx: &mut mpsc::Receiver<OriginalRelayDelivery>,
) -> (String, Vec<u8>, Instant) {
    timeout(Duration::from_secs(2), async {
        loop {
            let delivery = rx.recv().await.expect("original relay input closed");
            let (message, fact) = delivery.into_parts();
            match message {
                RelayMessage::Data { from_node, data } => {
                    let completed_at = fact
                        .expect("actual sourced Data must retain its read fact")
                        .completed_at();
                    assert!(completed_at <= Instant::now());
                    return (from_node, data, completed_at);
                }
                RelayMessage::Pong { .. } => assert!(fact.is_none()),
                message => panic!("unexpected original rendezvous message: {message:?}"),
            }
        }
    })
    .await
    .expect("original ciphertext must arrive through the existing merge")
}

#[tokio::test]
async fn original_read_common_hub_preserves_noise_payload_fact_and_typed_handoff() {
    use p2pnet_crypto::NodeIdentity;
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
    let one = RelayServer::start_random().await.unwrap();
    let two = RelayServer::start_random().await.unwrap();
    let common = RelayServer::start_random().await.unwrap();
    let common_endpoint = format!("tcp://{}", common.addr);
    let specs_a = [
        RelayCandidateConfig::legacy(format!("one@tcp://{}", one.addr)),
        RelayCandidateConfig::legacy(format!("common@{common_endpoint}")),
    ];
    let specs_b = [
        RelayCandidateConfig::legacy(format!("two@tcp://{}", two.addr)),
        specs_a[1].clone(),
    ];
    let cooldowns = HashMap::new();
    let a = select_relay_with_cooldowns_for_read::<OriginalRelayDelivery>(
        &specs_a,
        &["one".into()],
        Duration::from_secs(1),
        "read-a",
        peer_manager(),
        None,
        None,
        true,
        None,
        &cooldowns,
    )
    .await;
    let b = select_relay_with_cooldowns_for_read::<OriginalRelayDelivery>(
        &specs_b,
        &["two".into()],
        Duration::from_secs(1),
        "read-b",
        peer_manager(),
        None,
        None,
        true,
        None,
        &cooldowns,
    )
    .await;
    let ta = a.transport.unwrap();
    let tb = b.transport.unwrap();
    let mut ra = a.relay_rx.unwrap();
    let mut rb = b.relay_rx.unwrap();
    assert_eq!(ra.max_capacity(), 256);
    assert_eq!(rb.max_capacity(), 256);
    assert_ne!(ta.endpoint(), tb.endpoint());
    wait_for_rendezvous(&ta, 2).await;
    wait_for_rendezvous(&tb, 2).await;
    let identity_a = NodeIdentity::generate();
    let identity_b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(identity_a, identity_b.public_key(), None);
    let mut responder = HandshakeResponder::new(identity_b, None);
    let init = initiator.create_initiation().unwrap();
    let (response, keys_b) = responder.consume_initiation_and_respond(&init).unwrap();
    let mut crypto_a = TransportSession::new(initiator.consume_response(&response).unwrap());
    let mut crypto_b = TransportSession::new(keys_b);
    let request = b"actual encrypted original read through the common hub";
    let request_wire = crypto_a.encrypt_to_bytes(request).unwrap();
    let started = Instant::now();
    ta.send_packet(&EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "read-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: request_wire.clone(),
        is_business: false,
    })
    .await
    .unwrap();
    let (from, wire, read_at) = receive_original_data(&mut rb).await;
    assert_eq!(from, "read-a");
    assert_eq!(wire, request_wire);
    assert!(read_at >= started);
    let plain = crypto_b.decrypt_from_bytes(&wire).unwrap();
    assert_eq!(&plain[..request.len()], request);
    let reply = b"actual encrypted original read reply";
    let reply_wire = crypto_b.encrypt_to_bytes(reply).unwrap();
    let reply_started = Instant::now();
    tb.send_packet(&EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "read-a".into(),
        dst_ip: "10.20.0.1".into(),
        wire_bytes: reply_wire.clone(),
        is_business: false,
    })
    .await
    .unwrap();
    let (from, wire, reply_read_at) = receive_original_data(&mut ra).await;
    assert_eq!(from, "read-b");
    assert_eq!(wire, reply_wire);
    assert!(reply_read_at >= reply_started);
    let plain = crypto_a.decrypt_from_bytes(&wire).unwrap();
    assert_eq!(&plain[..reply.len()], reply);
    assert_eq!(
        ta.rendezvous
            .as_ref()
            .unwrap()
            .routes
            .lock()
            .unwrap()
            .peers
            .get("read-b"),
        Some(&common_endpoint)
    );
    assert_eq!(
        tb.rendezvous
            .as_ref()
            .unwrap()
            .routes
            .lock()
            .unwrap()
            .peers
            .get("read-a"),
        Some(&common_endpoint)
    );

    // This is the actual shared typed pool handoff, with no metadata bridge.
    let retired = Arc::downgrade(ta.rendezvous.as_ref().unwrap());
    let old_connection = ta.connection_id();
    let (replacement, rx) = RelayTransport::connect_secure_for_read::<OriginalRelayDelivery>(
        ta.endpoint(),
        ta.region(),
        "read-a",
        peer_manager(),
        None,
        true,
        None,
    )
    .await
    .unwrap();
    assert_ne!(replacement.connection_id(), old_connection);
    let (replacement, _replacement_rx) = ta.handoff_rendezvous(replacement, rx).await;
    drop(ta);
    drop(ra);
    assert!(retired.upgrade().is_none());
    wait_for_rendezvous(&replacement, 2).await;
    let next_wire = crypto_a.encrypt_to_bytes(request).unwrap();
    let after_handoff = Instant::now();
    replacement
        .send_packet(&EncryptedPeerPacket {
            room_authorization: None,
            peer_id: "read-b".into(),
            dst_ip: "10.20.0.2".into(),
            wire_bytes: next_wire.clone(),
            is_business: true,
        })
        .await
        .unwrap();
    let (_, wire, next_read_at) = receive_original_data(&mut rb).await;
    assert_eq!(wire, next_wire);
    assert!(next_read_at >= after_handoff);
    let plain = crypto_b.decrypt_from_bytes(&wire).unwrap();
    assert_eq!(&plain[..request.len()], request);
    let weak = Arc::downgrade(replacement.rendezvous.as_ref().unwrap());
    drop(replacement);
    assert!(weak.upgrade().is_none());
    tb.abort_writer();
    one.shutdown().await;
    two.shutdown().await;
    common.shutdown().await;
}

#[tokio::test]
async fn original_read_actual_daemon_queue_reuses_read_time_at_original_enqueue_g() {
    let server = RelayServer::start_random().await.unwrap();
    let endpoint = format!("tcp://{}", server.addr);
    let peers_a = peer_manager();
    let peers_b = peer_manager();
    peers_a.add_peer(&peer("queue-b", "10.20.0.2")).await;
    peers_b.add_peer(&peer("queue-a", "10.20.0.1")).await;
    let (a, _ra) =
        RelayTransport::connect_secure(&endpoint, "default", "queue-a", peers_a, None, true, None)
            .await
            .unwrap();
    let (b, rb) = RelayTransport::connect_secure_for_read::<OriginalRelayDelivery>(
        &endpoint,
        "default",
        "queue-b",
        peers_b.clone(),
        None,
        true,
        None,
    )
    .await
    .unwrap();
    assert_eq!(rb.max_capacity(), 1024);
    let expected_connection = b.connection_id();
    let original_client = b.client.clone();
    let (tx, mut rx) = mpsc::channel(1024);
    let worker = tokio::spawn(b.run_inbound_for_read(rb, tx, None));
    let bytes = vec![4, 9, 8, 7, 6, 5, 4, 3, 2, 1];
    let started = Instant::now();
    a.send_packet(&EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "queue-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: bytes.clone(),
        is_business: false,
    })
    .await
    .unwrap();
    let received = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let read_at = received
        .udp_received
        .expect("the actual original reader supplies read completion");
    let queued_at = received
        .transport_queue_send_started
        .expect("original enqueue clock remains present");
    assert!(read_at >= started);
    assert!(read_at <= queued_at);
    assert_eq!(
        received.network_generation,
        Some(peers_b.current_network_generation_sync())
    );
    assert_eq!(received.relay_connection_id, Some(expected_connection));
    assert_eq!(received.relay_endpoint.as_deref(), Some(endpoint.as_str()));
    assert_eq!(received.relay_peer_id.as_deref(), Some("queue-a"));
    assert_eq!(received.wire_bytes, bytes);
    assert!(received.physical_ingress.is_none());
    assert!(received.source.is_none());
    assert!(received.direct_socket.is_none());
    assert!(received
        .original_relay_read
        .as_ref()
        .is_some_and(
            |read| read.belongs_to_client(&original_client) && read.completed_at() == read_at
        ));
    worker.abort();
    let _ = worker.await;
    a.abort_writer();
    server.shutdown().await;
}

#[tokio::test]
async fn original_read_legacy_public_queue_keeps_unknown_read_fact() {
    let server = RelayServer::start_random().await.unwrap();
    let endpoint = server.addr.to_string();
    let peers_a = peer_manager();
    let peers_b = peer_manager();
    peers_a.add_peer(&peer("legacy-b", "10.20.0.2")).await;
    peers_b.add_peer(&peer("legacy-a", "10.20.0.1")).await;
    let (a, _ra) = RelayTransport::connect(&endpoint, "legacy-a", peers_a)
        .await
        .unwrap();
    let (b, rb): (RelayTransport, mpsc::Receiver<RelayMessage>) =
        RelayTransport::connect(&endpoint, "legacy-b", peers_b)
            .await
            .unwrap();
    let (tx, mut rx) = mpsc::channel(1024);
    let worker = tokio::spawn(b.run_inbound(rb, tx, None));
    let bytes = vec![4, 1, 3, 5, 7, 9];
    a.send_packet(&EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "legacy-b".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: bytes.clone(),
        is_business: false,
    })
    .await
    .unwrap();
    let received = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.wire_bytes, bytes);
    assert!(received.udp_received.is_none());
    assert!(received.original_relay_read.is_none());
    assert!(received.transport_queue_send_started.is_some());
    assert!(received.physical_ingress.is_none());
    assert!(received.source.is_none());
    worker.abort();
    let _ = worker.await;
    a.abort_writer();
    server.shutdown().await;
}
