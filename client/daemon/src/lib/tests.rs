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

#[tokio::test]
async fn punch_attempt_deduplicator_allows_only_one_short_window_per_peer() {
    let deduplicator = PunchAttemptDeduplicator::default();
    assert!(deduplicator.claim("peer-a").await);
    assert!(!deduplicator.claim("peer-a").await);
    assert!(deduplicator.claim("peer-b").await);
}

#[tokio::test]
async fn punch_attempt_deduplicator_lets_synchronized_punch_override_background() {
    let deduplicator = PunchAttemptDeduplicator::default();
    assert!(
        deduplicator
            .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
            .await
    );
    assert!(
        deduplicator.claim("peer-a").await,
        "synchronized punch should preempt a recent background retry"
    );
    assert!(
        !deduplicator
            .claim_with_window("peer-a", DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW)
            .await,
        "background retry should not preempt a recent synchronized punch"
    );
    assert!(!deduplicator.claim("peer-a").await);
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

#[test]
fn test_advertised_udp_endpoint_uses_configured_value() {
    let local = "0.0.0.0:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(local, Some("203.0.113.10:51820"), &[]),
        Some("203.0.113.10:51820".to_string())
    );
}

#[test]
fn test_advertised_udp_endpoint_uses_public_candidate_for_unspecified_bind() {
    let local = "0.0.0.0:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(
            local,
            None,
            &[
                "192.168.1.10:51820".to_string(),
                "74.125.250.129:43000".to_string()
            ]
        ),
        Some("74.125.250.129:43000".to_string())
    );
}

#[test]
fn test_advertised_udp_endpoint_uses_specific_bind_address() {
    let local = "127.0.0.1:51820".parse().unwrap();
    assert_eq!(
        advertised_udp_endpoint(local, None, &[]),
        Some("127.0.0.1:51820".to_string())
    );
}

#[test]
fn control_endpoint_prefers_explicit_mapping_over_stun_candidate() {
    let candidates = vec!["8.8.8.8:41000".to_string(), "1.1.1.1:60207".to_string()];
    let sources = HashMap::from([
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
        ("1.1.1.1:60207".to_string(), "pcp".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("1.1.1.1:60207")
    );
}

#[test]
fn control_endpoint_does_not_publish_peer_reflexive_as_global_endpoint() {
    let candidates = vec!["1.1.1.1:42000".to_string(), "8.8.8.8:41000".to_string()];
    let sources = HashMap::from([
        ("1.1.1.1:42000".to_string(), "peer_reflexive".to_string()),
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("8.8.8.8:41000")
    );
}

#[test]
fn control_endpoint_does_not_publish_speculative_candidate() {
    let candidates = vec!["1.1.1.1:42008".to_string(), "8.8.8.8:41000".to_string()];
    let sources = HashMap::from([
        ("1.1.1.1:42008".to_string(), "predicted".to_string()),
        ("8.8.8.8:41000".to_string(), "stun_observed".to_string()),
    ]);

    assert_eq!(
        control_udp_endpoint_from_candidates(&candidates, &sources).as_deref(),
        Some("8.8.8.8:41000")
    );
}

#[test]
fn stable_control_endpoint_refresh_promotes_private_to_public() {
    assert!(should_update_stable_control_endpoint(
        Some("192.168.0.239:52633"),
        "8.8.8.8:41000"
    ));
}

#[test]
fn stable_control_endpoint_refresh_ignores_same_public_ip_port_churn() {
    assert!(!should_update_stable_control_endpoint(
        Some("8.8.8.8:41000"),
        "8.8.8.8:41037"
    ));
}

#[test]
fn signal_candidates_compact_volatile_public_ports_per_public_ip() {
    let mut candidates = vec!["192.168.1.10:51820".to_string()];
    candidates.extend((0..40).map(|index| format!("8.8.8.8:{}", 41000 + index)));
    candidates.extend(["1.1.1.1:42000".to_string(), "1.1.1.1:42009".to_string()]);
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert("192.168.1.10:51820".to_string(), "host".to_string());

    compact_volatile_public_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), 35);
    assert!(candidates.contains(&"192.168.1.10:51820".to_string()));
    assert!(candidates.contains(&"1.1.1.1:42000".to_string()));
    assert!(candidates.contains(&"1.1.1.1:42009".to_string()));
    assert_eq!(
        candidates
            .iter()
            .filter(|endpoint| endpoint.starts_with("8.8.8.8:"))
            .count(),
        MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP
    );
    assert!(candidates.contains(&"8.8.8.8:41031".to_string()));
    assert!(!candidates.contains(&"8.8.8.8:41032".to_string()));
    assert!(!candidates.contains(&"8.8.8.8:41039".to_string()));
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn signal_candidate_cap_preserves_high_teen_linear_prediction() {
    let mut candidates = vec!["192.168.1.10:51820".to_string()];
    candidates.extend((8135..=8137).map(|port| format!("220.163.6.190:{port}")));
    candidates.extend((8138..=8161).map(|port| format!("220.163.6.190:{port}")));
    let mut sources = HashMap::from([("192.168.1.10:51820".to_string(), "host".to_string())]);
    for port in 8135..=8137 {
        sources.insert(format!("220.163.6.190:{port}"), "stun_observed".to_string());
    }
    for port in 8138..=8161 {
        sources.insert(format!("220.163.6.190:{port}"), "predicted".to_string());
    }

    compact_volatile_public_signal_candidates(&mut candidates, &mut sources);
    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), 28);
    assert!(candidates.contains(&"220.163.6.190:8154".to_string()));
    assert!(candidates.contains(&"220.163.6.190:8161".to_string()));
    assert_eq!(
        sources.get("220.163.6.190:8154").map(String::as_str),
        Some("predicted")
    );
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn signal_candidate_cap_does_not_preserve_external_overlay_hosts_over_public_predictions() {
    let tailscale_v4 = "100.84.190.40:51820".to_string();
    let tailscale_v6 = "[fd7a:115c:a1e0::e136:be29]:51820".to_string();
    let p2wlan_overlay = "10.20.0.13:51820".to_string();
    let mut candidates = vec![
        tailscale_v4.clone(),
        tailscale_v6.clone(),
        p2wlan_overlay.clone(),
    ];
    candidates.extend((8135..=8170).map(|port| format!("220.163.6.190:{port}")));

    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(tailscale_v4.clone(), "host".to_string());
    sources.insert(tailscale_v6.clone(), "host".to_string());
    sources.insert(p2wlan_overlay.clone(), "host".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert!(!candidates.contains(&tailscale_v4));
    assert!(!candidates.contains(&tailscale_v6));
    assert!(!candidates.contains(&p2wlan_overlay));
    assert!(candidates
        .iter()
        .all(|endpoint| endpoint.starts_with("220.163.6.190:")));
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn signal_candidate_cap_keeps_priority_prefix_and_source_map_aligned() {
    let mut candidates = (1..=MAX_SIGNAL_CANDIDATES + 3)
        .map(|index| format!("192.0.2.{index}:51820"))
        .collect::<Vec<_>>();
    let mapped = "198.51.100.10:42000".to_string();
    candidates.insert(0, mapped.clone());
    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "host".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(mapped.clone(), "upnp".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert_eq!(candidates[0], mapped);
    assert_eq!(sources.len(), MAX_SIGNAL_CANDIDATES);
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
    assert_eq!(sources.get(&mapped).map(String::as_str), Some("upnp"));
}

#[test]
fn signal_candidate_cap_prefers_public_traversal_candidates_over_private_hosts() {
    let mut candidates = (1..=MAX_SIGNAL_CANDIDATES + 4)
        .map(|index| format!("192.168.1.{index}:51820"))
        .collect::<Vec<_>>();
    let stun = "203.0.113.10:42000".to_string();
    let predicted = "203.0.113.10:42004".to_string();
    candidates.push(stun.clone());
    candidates.push(predicted.clone());

    let mut sources = candidates
        .iter()
        .cloned()
        .map(|endpoint| (endpoint, "host".to_string()))
        .collect::<HashMap<_, _>>();
    sources.insert(stun.clone(), "stun_observed".to_string());
    sources.insert(predicted.clone(), "predicted".to_string());

    truncate_signal_candidates(&mut candidates, &mut sources);

    assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
    assert!(candidates.contains(&stun));
    assert!(candidates.contains(&predicted));
    assert_eq!(
        sources.get(&stun).map(String::as_str),
        Some("stun_observed")
    );
    assert_eq!(
        sources.get(&predicted).map(String::as_str),
        Some("predicted")
    );
    assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
}

#[test]
fn candidate_refresh_generation_ignores_stun_port_churn_on_same_public_ip() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let next = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:31999".to_string(),
    ];
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        ),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_ignores_public_source_label_churn() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);
    let next = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:31999".to_string(),
    ];
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let learned_next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        ("93.184.216.34:31999".to_string(), "learned".to_string()),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &learned_next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_ignores_private_source_label_churn() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        (
            "192.168.1.10:59288".to_string(),
            "peer_reflexive".to_string(),
        ),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let next = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:31999".to_string(),
    ];
    let next_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        ),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_ignores_external_overlay_and_public_port_churn() {
    let previous = vec![
        "100.74.65.1:60155".to_string(),
        "100.74.65.1:58770".to_string(),
        "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
        "220.163.6.190:6979".to_string(),
        "220.163.6.190:6980".to_string(),
        "220.163.6.190:6984".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("100.74.65.1:60155".to_string(), "host".to_string()),
        ("100.74.65.1:58770".to_string(), "host".to_string()),
        (
            "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
            "host".to_string(),
        ),
        (
            "220.163.6.190:6979".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "220.163.6.190:6980".to_string(),
            "stun_observed".to_string(),
        ),
        ("220.163.6.190:6984".to_string(), "predicted".to_string()),
    ]);
    let next = vec![
        "100.74.65.1:59581".to_string(),
        "100.74.65.1:60155".to_string(),
        "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
        "220.163.6.190:6981".to_string(),
        "220.163.6.190:6983".to_string(),
        "220.163.6.190:6995".to_string(),
    ];
    let next_sources = HashMap::from([
        ("100.74.65.1:59581".to_string(), "host".to_string()),
        ("100.74.65.1:60155".to_string(), "host".to_string()),
        (
            "[fd7a:115c:a1e0::b936:4102]:60155".to_string(),
            "host".to_string(),
        ),
        (
            "220.163.6.190:6981".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "220.163.6.190:6983".to_string(),
            "stun_observed".to_string(),
        ),
        ("220.163.6.190:6995".to_string(), "predicted".to_string()),
    ]);

    assert!(!candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &next,
        &next_sources,
    ));
}

#[test]
fn candidate_refresh_generation_advances_on_host_or_public_ip_change() {
    let previous = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let previous_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let host_changed = vec![
        "192.168.2.10:59288".to_string(),
        "93.184.216.34:27106".to_string(),
    ];
    let host_changed_sources = HashMap::from([
        ("192.168.2.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);
    let public_ip_changed = vec![
        "192.168.1.10:59288".to_string(),
        "93.184.216.35:27106".to_string(),
    ];
    let public_ip_changed_sources = HashMap::from([
        ("192.168.1.10:59288".to_string(), "host".to_string()),
        (
            "93.184.216.35:27106".to_string(),
            "stun_observed".to_string(),
        ),
    ]);

    assert!(candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &host_changed,
        &host_changed_sources,
    ));
    assert!(candidate_refresh_requires_network_generation_advance(
        &previous,
        &previous_sources,
        &public_ip_changed,
        &public_ip_changed_sources,
    ));
}

#[test]
fn preserve_peer_reflexive_candidates_keeps_observed_endpoint_across_refresh() {
    let previous = vec![
        "93.184.216.34:27106".to_string(),
        "93.184.216.34:45000".to_string(),
    ];
    let previous_sources = HashMap::from([
        (
            "93.184.216.34:27106".to_string(),
            "stun_observed".to_string(),
        ),
        (
            "93.184.216.34:45000".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);
    let mut next = vec!["93.184.216.34:31999".to_string()];
    let mut next_sources = HashMap::from([(
        "93.184.216.34:31999".to_string(),
        "stun_observed".to_string(),
    )]);

    preserve_peer_reflexive_candidates(&previous, &previous_sources, &mut next, &mut next_sources);

    assert_eq!(next[0], "93.184.216.34:45000");
    assert_eq!(
        next_sources.get("93.184.216.34:45000").map(String::as_str),
        Some("peer_reflexive")
    );
}

#[test]
fn preserve_peer_reflexive_candidates_drops_private_endpoint_after_refresh() {
    let previous = vec![
        "192.168.2.14:59366".to_string(),
        "93.184.216.34:45000".to_string(),
    ];
    let previous_sources = HashMap::from([
        (
            "192.168.2.14:59366".to_string(),
            "peer_reflexive".to_string(),
        ),
        (
            "93.184.216.34:45000".to_string(),
            "peer_reflexive".to_string(),
        ),
    ]);
    let mut next = vec!["10.46.107.87:59366".to_string()];
    let mut next_sources = HashMap::from([("10.46.107.87:59366".to_string(), "host".to_string())]);

    preserve_peer_reflexive_candidates(&previous, &previous_sources, &mut next, &mut next_sources);

    assert!(!next.contains(&"192.168.2.14:59366".to_string()));
    assert_eq!(
        next_sources.get("192.168.2.14:59366").map(String::as_str),
        None
    );
}

#[test]
fn preserve_peer_reflexive_candidates_drops_old_public_ip_after_refresh() {
    let previous = vec!["93.184.216.34:45000".to_string()];
    let previous_sources = HashMap::from([(
        "93.184.216.34:45000".to_string(),
        "peer_reflexive".to_string(),
    )]);
    let mut next = vec!["198.51.100.9:31999".to_string()];
    let mut next_sources = HashMap::from([(
        "198.51.100.9:31999".to_string(),
        "stun_observed".to_string(),
    )]);

    preserve_peer_reflexive_candidates(&previous, &previous_sources, &mut next, &mut next_sources);

    assert_eq!(next, vec!["198.51.100.9:31999"]);
    assert_eq!(
        next_sources.get("93.184.216.34:45000").map(String::as_str),
        None
    );
}

#[test]
fn peer_reflexive_candidate_update_is_idempotent_after_first_advertisement() {
    let mut candidates = vec!["192.168.1.10:51820".to_string()];
    let mut sources = HashMap::from([("192.168.1.10:51820".to_string(), "host".to_string())]);

    assert!(add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert_eq!(candidates[0], "93.184.216.34:45000");
    assert_eq!(
        sources.get("93.184.216.34:45000").map(String::as_str),
        Some("peer_reflexive")
    );

    assert!(!add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate.as_str() == "93.184.216.34:45000")
            .count(),
        1
    );
}

#[test]
fn peer_reflexive_candidate_update_reports_source_upgrade_once() {
    let mut candidates = vec!["93.184.216.34:45000".to_string()];
    let mut sources = HashMap::from([(
        "93.184.216.34:45000".to_string(),
        "stun_observed".to_string(),
    )]);

    assert!(add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert!(!add_peer_reflexive_candidate_to_set(
        "93.184.216.34:45000",
        &mut candidates,
        &mut sources,
    )
    .unwrap());
    assert_eq!(
        sources.get("93.184.216.34:45000").map(String::as_str),
        Some("peer_reflexive")
    );
}

#[test]
fn nat_pmp_response_parsers_accept_valid_udp_mapping() {
    let public = [0, 128, 0, 0, 0, 0, 0, 1, 93, 184, 216, 34];
    assert_eq!(
        parse_nat_pmp_public_address_response(&public),
        Some(Ipv4Addr::new(93, 184, 216, 34))
    );

    let mut mapping = [0u8; 16];
    mapping[0] = 0;
    mapping[1] = 129;
    mapping[8..10].copy_from_slice(&51820u16.to_be_bytes());
    mapping[10..12].copy_from_slice(&42000u16.to_be_bytes());
    mapping[12..16].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    assert_eq!(parse_nat_pmp_mapping_response(&mapping, 51820), Some(42000));
    assert_eq!(parse_nat_pmp_mapping_response(&mapping, 51821), None);
}

#[test]
fn pcp_response_parser_accepts_ipv4_mapped_udp_mapping() {
    let mut response = [0u8; 60];
    response[0] = 2;
    response[1] = 0x81;
    response[36] = 17;
    response[40..42].copy_from_slice(&51820u16.to_be_bytes());
    response[42..44].copy_from_slice(&42000u16.to_be_bytes());
    response[44..60].copy_from_slice(&ipv4_mapped_octets(Ipv4Addr::new(93, 184, 216, 34)));
    assert_eq!(
        parse_pcp_mapping_response(&response, 51820),
        Some("93.184.216.34:42000".parse().unwrap())
    );
    assert_eq!(parse_pcp_mapping_response(&response, 51821), None);
}

#[test]
fn default_gateway_parsers_extract_ipv4_addresses() {
    assert_eq!(
        parse_first_ipv4("default via 192.168.1.1 dev en0"),
        Some(Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(
        parse_first_ipv4("gateway: 10.0.0.1\ninterface: en0"),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn test_infer_default_relay_servers_from_public_control_host() {
    assert_eq!(
        infer_default_relay_servers("http://47.109.40.237:18080"),
        vec!["default@tcp://47.109.40.237:18081".to_string()]
    );
    assert_eq!(
        infer_default_relay_servers("https://relay.example.com/api"),
        vec!["default@tcp://relay.example.com:18081".to_string()]
    );
    assert_eq!(
        infer_default_relay_servers("http://[2001:db8::1]:18080"),
        vec!["default@tcp://[2001:db8::1]:18081".to_string()]
    );
}

#[test]
fn test_effective_relay_plaintext_policy_for_legacy_http_control() {
    let legacy_servers = vec!["default@tcp://47.109.40.237:18081".to_string()];
    assert!(effective_relay_allow_insecure_plaintext(
        "http://47.109.40.237:18080",
        &[],
        &legacy_servers,
        false,
    ));
    assert!(effective_relay_allow_insecure_plaintext(
        "https://ctrl.example.com",
        &[],
        &legacy_servers,
        true,
    ));
    assert!(!effective_relay_allow_insecure_plaintext(
        "https://ctrl.example.com",
        &[],
        &legacy_servers,
        false,
    ));

    let catalog = vec![RelayCatalogEntry {
        region: "cn".to_string(),
        audience: "relay-cn-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: None,
        udp_observer_endpoints: Vec::new(),
    }];
    assert!(!effective_relay_allow_insecure_plaintext(
        "http://47.109.40.237:18080",
        &catalog,
        &legacy_servers,
        false,
    ));
}

#[test]
fn test_relay_spec_plaintext_detection() {
    assert!(relay_spec_is_plaintext("default@47.109.40.237:18081"));
    assert!(relay_spec_is_plaintext("default@tcp://47.109.40.237:18081"));
    assert!(!relay_spec_is_plaintext("cn@tls://relay.example.com:18081"));
}

#[test]
fn relay_catalog_takes_precedence_over_legacy_servers() {
    let catalog = vec![RelayCatalogEntry {
        region: "sg".to_string(),
        audience: "relay-sg-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: Some("udp://relay.example.com:18082".to_string()),
        udp_observer_endpoints: Vec::new(),
    }];
    let legacy = vec!["default@127.0.0.1:18081".to_string()];

    let candidates = relay_candidates_from_sources(&catalog, &legacy);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].region, "sg");
    assert_eq!(candidates[0].audience.as_deref(), Some("relay-sg-1"));
    assert_eq!(candidates[0].endpoint, "tls://relay.example.com:18081");
}

#[test]
fn relay_catalog_udp_observers_are_merged_with_local_config() {
    let catalog = vec![RelayCatalogEntry {
        region: "sg".to_string(),
        audience: "relay-sg-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: Some("udp://relay.example.com:18082".to_string()),
        udp_observer_endpoints: vec![
            "udp://stun.l.google.com:19302".to_string(),
            "relay.example.com:18082".to_string(),
        ],
    }];
    let configured = vec!["203.0.113.10:18082".to_string()];

    let observers = udp_observers_from_sources(&catalog, &configured);

    assert_eq!(
        observers,
        vec![
            "203.0.113.10:18082".to_string(),
            "relay.example.com:18082".to_string(),
            "stun.l.google.com:19302".to_string()
        ]
    );
}

#[test]
fn relay_catalog_udp_observers_respect_explicit_disable() {
    let catalog = vec![RelayCatalogEntry {
        region: "sg".to_string(),
        audience: "relay-sg-1".to_string(),
        endpoint: "tls://relay.example.com:18081".to_string(),
        udp_observer_endpoint: Some("relay.example.com:18082".to_string()),
        udp_observer_endpoints: vec!["stun.l.google.com:19302".to_string()],
    }];
    let configured = vec!["off".to_string()];

    let observers = udp_observers_from_sources(&catalog, &configured);

    assert_eq!(observers, vec!["off".to_string()]);
}

#[test]
fn legacy_relay_servers_are_used_without_catalog() {
    let legacy = vec!["west@127.0.0.1:18081".to_string()];

    let candidates = relay_candidates_from_sources(&[], &legacy);

    assert_eq!(candidates.len(), 1);
    assert!(candidates[0].audience.is_none());
    assert_eq!(candidates[0].endpoint, "west@127.0.0.1:18081");
}

async fn wait_for_relay_endpoint(
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    expected_endpoint: &str,
) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let matches = relay_transport
                .read()
                .await
                .as_ref()
                .is_some_and(|relay| relay.endpoint() == expected_endpoint);
            if matches {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected relay endpoint was not published");
}

async fn accept_relay_registration(listener: &TcpListener, node_id: &str) -> TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await.unwrap();
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&header[..4], b"DERP");
    assert_eq!(header[5], p2pnet_relay::protocol::MSG_REGISTER);
    assert_eq!(payload, node_id.as_bytes());
    stream
        .write_all(&Frame::registered(node_id).encode())
        .await
        .unwrap();
    stream
}

#[tokio::test]
async fn relay_supervisor_reconnects_after_stream_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (reconnected_tx, mut reconnected_rx) = mpsc::channel(1);
    let server = tokio::spawn(async move {
        let first = accept_relay_registration(&listener, "node-a").await;
        drop(first);

        let _second = accept_relay_registration(&listener, "node-a").await;
        reconnected_tx.send(()).await.unwrap();
        std::future::pending::<()>().await;
    });

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let relay_transport = Arc::new(RwLock::new(None));
    let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![RelayCandidateConfig::legacy(endpoint)],
            preferred_regions: Vec::new(),
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            inbound_tx,
            ticket_cache: None,
            relay_ticket: None,
            allow_insecure_plaintext: true, // test
            ca_cert_path: None,
        }
        .run(),
    );

    tokio::time::timeout(Duration::from_secs(4), reconnected_rx.recv())
        .await
        .expect("relay supervisor did not reconnect")
        .expect("relay test server stopped");
    tokio::time::timeout(Duration::from_secs(1), async {
        while relay_transport.read().await.is_none() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconnected relay was not published");
    assert!(relay_selection.read().await.last_error.is_none());

    supervisor.abort();
    server.abort();
}

#[tokio::test]
async fn relay_supervisor_fails_over_to_standby_after_runtime_disconnect() {
    let primary = RelayServer::start_random().await.unwrap();
    let standby = RelayServer::start_random().await.unwrap();
    let primary_endpoint = primary.addr.to_string();
    let standby_endpoint = standby.addr.to_string();

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let relay_transport = Arc::new(RwLock::new(None));
    let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![
                RelayCandidateConfig::legacy(format!("primary@{primary_endpoint}")),
                RelayCandidateConfig::legacy(format!("standby@{standby_endpoint}")),
            ],
            preferred_regions: vec!["primary".to_string()],
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            inbound_tx,
            ticket_cache: None,
            relay_ticket: None,
            allow_insecure_plaintext: true,
            ca_cert_path: None,
        }
        .run(),
    );

    wait_for_relay_endpoint(relay_transport.clone(), &primary_endpoint).await;
    primary.shutdown().await;
    wait_for_relay_endpoint(relay_transport, &standby_endpoint).await;

    let diagnostics = relay_selection.read().await.clone();
    assert_eq!(
        diagnostics.selected_endpoint.as_deref(),
        Some(standby_endpoint.as_str())
    );
    let primary_candidate = diagnostics
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint == primary_endpoint)
        .expect("primary relay candidate should remain in diagnostics");
    assert_eq!(
        primary_candidate.error_code.as_deref(),
        Some("cooling_down")
    );
    assert!(primary_candidate.cooldown_remaining_ms.is_some());

    supervisor.abort();
    standby.shutdown().await;
}

#[test]
fn test_infer_default_relay_servers_skips_local_and_test_hosts() {
    assert!(infer_default_relay_servers("http://127.0.0.1:18080").is_empty());
    assert!(infer_default_relay_servers("http://localhost:18080").is_empty());
    assert!(infer_default_relay_servers("https://ctrl.test").is_empty());
}

#[tokio::test]
async fn test_parse_stun_servers() {
    let servers = parse_stun_servers(
        &["127.0.0.1:3478".to_string(), " 10.0.0.1:3478 ".to_string()],
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0], "127.0.0.1:3478".parse().unwrap());
    assert_eq!(servers[1], "10.0.0.1:3478".parse().unwrap());
}

#[tokio::test]
async fn test_parse_stun_servers_resolves_hostname() {
    let servers = parse_stun_servers(&["localhost:3478".to_string()], Duration::from_secs(1))
        .await
        .unwrap();
    assert!(servers
        .iter()
        .any(|server| server.ip().is_loopback() && server.port() == 3478));
}

#[tokio::test]
async fn test_parse_stun_servers_can_be_disabled() {
    assert!(
        parse_stun_servers(&["off".to_string()], Duration::from_millis(100))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_parse_stun_servers_rejects_invalid_endpoint() {
    let err = parse_stun_servers(&["not-a-socket".to_string()], Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("invalid or unresolved STUN server"));
}

#[test]
fn maintenance_offer_cancellation_keeps_rekey_initiation_alive() {
    assert!(should_cancel_maintenance_offer(false, true, false, false));
    assert!(!should_cancel_maintenance_offer(false, false, false, false));
    assert!(!should_cancel_maintenance_offer(true, true, true, false));
    assert!(!should_cancel_maintenance_offer(true, true, false, true));
    assert!(!should_cancel_maintenance_offer(true, false, false, false));
    assert!(should_cancel_maintenance_offer(true, true, false, false));
}

#[tokio::test]
async fn stale_wireguard_answer_does_not_clear_pending_handshake() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let mut daemon = Daemon::new(config);
    let peer_id = "peer-stale-answer";

    let peer_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();

    {
        let mut state = daemon.pending_handshakes.lock().await;
        state.insert(peer_id.to_string(), initiator, None, None);
        state.attempts.insert(peer_id.to_string(), 1);
    }

    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (mut stale_response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    stale_response.receiver_index ^= 0x1111_0001;

    daemon
        .handle_peer_answer(peer_id, &stale_response.to_bytes(), None, None)
        .await
        .unwrap();

    let state = daemon.pending_handshakes.lock().await;
    assert!(state.pending.contains_key(peer_id));
    assert_eq!(state.attempts.get(peer_id), Some(&1));
}

#[test]
fn handshake_start_reservation_prevents_concurrent_initiators() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-race";

    assert!(state.reserve_start(peer_id));
    assert!(state.starting.contains(peer_id));
    assert!(
        !state.reserve_start(peer_id),
        "a second trigger must not start an initiator while the first gathers candidates"
    );

    state.cancel_reservation(peer_id);
    assert!(state.reserve_start(peer_id));
}

#[tokio::test]
async fn test_network_outbound_uses_relay_when_udp_unavailable() {
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
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(None));
    let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers,
        true,
        udp_transport,
        relay_transport,
    ));

    let payload = vec![4, 9, 8, 7, 6];
    encrypted_tx
        .send(EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_network_outbound_uses_relay_until_direct_is_verified() {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let direct_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let direct_endpoint = direct_sink.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: direct_endpoint.to_string(),
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
    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(Some(udp)));
    let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers.clone(),
        true,
        udp_transport,
        relay_transport,
    ));

    let payload = vec![9, 8, 7, 6, 5];
    encrypted_tx
        .send(EncryptedPeerPacket {
            peer_id: "node-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            wire_bytes: payload.clone(),
        })
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), direct_sink.recv_from(&mut buf))
            .await
            .is_err()
    );

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.active_path(), None);
    assert_eq!(conn.relay_server, Some(relay_endpoint));
    let selection = peers.select_path_for_data("node-b", true, true).await;
    assert_eq!(selection.path, Some(peer::NetworkPath::Relay));

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_daemon_acl_check() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);

    // Default ACL allows everything
    assert!(daemon.check_acl("node1", "node2", "tcp", 80).await);
}

#[tokio::test]
async fn test_daemon_dns() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.dns.enabled = true;
    let daemon = Daemon::new(config);

    daemon
        .dns()
        .register("test", "10.20.0.5", Some("node1"))
        .await;
    let ip = daemon.dns().resolve("test").await;
    assert_eq!(ip, Some("10.20.0.5".to_string()));
}

#[tokio::test]
async fn test_daemon_port_mapping() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);

    let mapping =
        port_mapping::PortMapping::new(port_mapping::Protocol::Tcp, "127.0.0.1", 8080, 30000);
    daemon.port_mappings().create(mapping).await.unwrap();
    let list = daemon.port_mappings().list().await;
    assert_eq!(list.len(), 1);
}
