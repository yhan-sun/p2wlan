use super::*;
use p2pnet_relay::{Frame, RelayMessage, RelayServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn test_daemon_creation() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let _daemon = Daemon::new(config);
}

#[test]
fn test_daemon_creation_manual_mode() {
    let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    config.network.manual = true;
    config.control.auth_token = "present-but-ignored".to_string();
    // Must not attempt control-plane registration even with a token.
    let _daemon = Daemon::new(config);
}

#[test]
fn candidate_only_offer_preserves_the_active_probe_session() {
    assert!(!peer_offer_updates_probe_session(&[], None));
    assert!(peer_offer_updates_probe_session(&[1], None));
    assert!(peer_offer_updates_probe_session(&[], Some("session-1")));
}

#[tokio::test]
async fn punch_attempt_deduplicator_allows_only_one_short_window_per_peer() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let peer_a = deduplicator.claim("peer-a").await.unwrap();
    assert!(deduplicator.claim("peer-a").await.is_none());
    let _peer_b = deduplicator.claim("peer-b").await.unwrap();
    assert_eq!(deduplicator.active_session_count(), 2);

    drop(peer_a);
    let _peer_a_replacement = deduplicator.claim("peer-a").await.unwrap();
}

#[tokio::test]
async fn punch_attempt_deduplicator_lets_synchronized_punch_override_background() {
    let deduplicator = PunchAttemptDeduplicator::default();
    let background = deduplicator
        .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
        .await
        .unwrap();
    let synchronized = deduplicator
        .claim("peer-a")
        .await
        .expect("synchronized punch should preempt a background retry");
    assert!(background.is_cancelled());
    assert!(
        deduplicator
            .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
            .await
            .is_none(),
        "background retry should not preempt an active synchronized punch"
    );
    assert!(deduplicator.claim("peer-a").await.is_none());
    assert_eq!(deduplicator.active_session_count(), 1);

    drop(background);
    assert_eq!(deduplicator.active_session_count(), 1);
    drop(synchronized);
    assert_eq!(deduplicator.active_session_count(), 0);
}

#[tokio::test]
async fn start_hole_punch_waits_for_local_candidates_before_state_change() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let remote_endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: remote_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    *daemon.udp_transport.write().await = Some(udp);

    daemon.start_hole_punch_at("node-b", None).await;

    let conn = daemon.peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.direct_health.failure_count, 0);
    assert!(conn.direct_events.iter().any(|event| {
        event.stage == "punch_delayed_local_candidates_not_ready"
            && event.candidate_count == Some(0)
    }));
}

#[test]
fn relay_assisted_punch_starts_slightly_before_advertised_time() {
    let punch_at_ms = unix_time_millis() + RELAY_ASSISTED_PUNCH_DELAY.as_millis() as u64;

    let delay = relay_assisted_punch_delay(Some(punch_at_ms));

    assert!(delay <= RELAY_ASSISTED_PUNCH_DELAY - RELAY_ASSISTED_PUNCH_LEAD);
    assert!(
        delay >= RELAY_ASSISTED_PUNCH_DELAY - RELAY_ASSISTED_PUNCH_LEAD - Duration::from_millis(50)
    );
}

#[tokio::test]
async fn encrypted_direct_validation_uses_observed_endpoint_and_wireguard_session() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(local_identity, remote_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(remote_identity, None);
    let (response, remote_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let local_keys = initiator.consume_response(&response).unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(responder.initiator_public_key().unwrap()),
            endpoint: observed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    transport
        .add_session("node-b", TransportSession::new(local_keys))
        .await;

    run_direct_encrypted_validation(
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint,
        },
        udp,
        peers.clone(),
        transport,
        "10.20.0.1",
    )
    .await;

    let mut datagram = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(
        Duration::from_secs(1),
        remote_socket.recv_from(&mut datagram),
    )
    .await
    .unwrap()
    .unwrap();
    let mut remote_session = TransportSession::new(remote_keys);
    let decrypted = remote_session.decrypt_from_bytes(&datagram[..len]).unwrap();
    let packet = Ipv4Packet::new(&decrypted).unwrap();
    assert_eq!(packet.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(packet.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
    assert!(packet
        .payload()
        .ends_with(DIRECT_ENCRYPTED_VALIDATION_PAYLOAD));

    let diagnostics = peers.diagnostics().await;
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_sent" && event.sent_probes == Some(3)));
}

#[tokio::test]
async fn direct_probe_loop_waits_for_local_candidates_before_background_retry() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_endpoint: SocketAddr = "203.0.113.10:51839".parse().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: remote_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let udp_transport = Arc::new(RwLock::new(Some(udp)));
    let local_candidates = Arc::new(RwLock::new(Vec::new()));

    let probe_task = tokio::spawn(run_direct_probe_loop(
        peers.clone(),
        udp_transport,
        local_candidates.clone(),
        PunchAttemptDeduplicator::default(),
        Duration::from_millis(20),
        Duration::from_millis(5),
        1,
    ));

    sleep(Duration::from_millis(80)).await;
    let diagnostics = peers.diagnostics().await;
    assert_eq!(diagnostics[0].direct.failure_count, 0);
    assert!(!diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "retry_punch_started"));

    local_candidates
        .write()
        .await
        .push("127.0.0.1:50000".to_string());

    let mut observed_probe_targets_due = false;
    for _ in 0..20 {
        if peers.diagnostics().await[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "retry_punch_started")
        {
            observed_probe_targets_due = true;
            break;
        }
        sleep(Duration::from_millis(25)).await;
    }

    probe_task.abort();
    let _ = probe_task.await;
    assert!(observed_probe_targets_due);
}

#[tokio::test]
async fn relay_validation_sends_encrypted_probe_through_relay() {
    let local_identity = NodeIdentity::generate();
    let remote_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(local_identity, remote_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(remote_identity, None);
    let (response, remote_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let local_keys = initiator.consume_response(&response).unwrap();

    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(responder.initiator_public_key().unwrap()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers)
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();
    transport
        .add_session("node-b", TransportSession::new(local_keys))
        .await;

    send_relay_validation_packet(
        RelayValidationPacket {
            peer_id: "node-b",
            peer_virtual_ip: "10.20.0.2",
            local_ip: Ipv4Addr::new(10, 20, 0, 1),
            peer_ip: Ipv4Addr::new(10, 20, 0, 2),
            validation_id: 7,
            sequence: 1,
        },
        &transport,
        &relay_a,
    )
    .await
    .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    let RelayMessage::Data { from_node, data } = received else {
        panic!("Expected relay Data message");
    };
    assert_eq!(from_node, "node-a");

    let mut remote_session = TransportSession::new(remote_keys);
    let decrypted = remote_session.decrypt_from_bytes(&data).unwrap();
    let packet = Ipv4Packet::new(&decrypted).unwrap();
    assert_eq!(packet.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(packet.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
    let icmp_payload = packet.payload();
    assert!(icmp_payload[8..].starts_with(b"p2wlan-relay-validation"));
    assert_eq!(
        icmp_payload[8 + b"p2wlan-relay-validation".len()..].len(),
        8
    );

    server.shutdown().await;
}

#[tokio::test]
async fn encrypted_direct_validation_skips_when_direct_is_already_confirmed() {
    let remote_identity = NodeIdentity::generate();
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(remote_identity.public_key()),
            endpoint: observed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers
        .record_direct_success("node-b", Some(observed_endpoint))
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (transport, _encrypted_rx) = WireGuardTransport::new();

    run_direct_encrypted_validation(
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint,
        },
        udp,
        peers.clone(),
        transport,
        "10.20.0.1",
    )
    .await;

    let mut datagram = vec![0u8; 2048];
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        remote_socket.recv_from(&mut datagram)
    )
    .await
    .is_err());

    let diagnostics = peers.diagnostics().await;
    assert!(diagnostics[0]
        .direct_events
        .iter()
        .any(|event| { event.stage == "encrypted_trial_skipped" && event.sent_probes == Some(0) }));
    assert!(!diagnostics[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "encrypted_trial_sent" && event.sent_probes == Some(0)));
}

#[tokio::test]
async fn scheduled_hole_punch_skips_without_degrading_already_direct_peer() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers.record_direct_success("node-b", Some(endpoint)).await;
    assert!(peers.is_direct("node-b").await);

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        "node-b".to_string(),
        Duration::from_millis(10),
        1,
        None,
    )
    .await;

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn
                .direct_events
                .iter()
                .any(|event| event.stage == "punch_skipped_already_direct")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scheduled hole punch did not skip the already-direct peer");

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert!(conn.direct_health.last_error.is_none());
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == REASON_DIRECT_PROBE_FAILED));
}

#[tokio::test]
async fn scheduled_hole_punch_ack_timeout_keeps_retrying_without_degrading() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let unused_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = unused_socket.local_addr().unwrap();
    drop(unused_socket);
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers
        .update_state("node-b", ConnectionState::HolePunching)
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        "node-b".to_string(),
        Duration::from_millis(10),
        1,
        None,
    )
    .await;

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let conn = peers.get_connection("node-b").await.unwrap();
            if conn
                .direct_events
                .iter()
                .any(|event| event.stage == "punch_ack_timeout")
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("scheduled hole punch did not record ACK timeout");

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::HolePunching);
    assert_eq!(conn.direct_health.failure_count, 0);
    assert!(conn.direct_health.last_error.is_none());
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == REASON_DIRECT_PROBE_FAILED));
}
