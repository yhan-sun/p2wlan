use super::super::test_support::*;
use super::*;
use crate::config::Config;

#[tokio::test]
async fn lan_direct_snapshot_is_generation_and_commit_bound() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let endpoint: SocketAddr = "192.168.2.11:51850".parse().unwrap();
    let local: SocketAddr = "192.168.2.10:51820".parse().unwrap();
    manager.add_peer(&test_peer("peer-lan", endpoint)).await;
    manager
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.2.10".parse().unwrap(),
            24,
        )])
        .await;
    manager
        .add_candidates_with_sources(
            "peer-lan",
            &[endpoint.to_string()],
            &std::collections::HashMap::from([(endpoint.to_string(), "host".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer-lan",
            endpoint,
            Some(Duration::from_millis(2)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer-lan", Some(endpoint), Some(local))
        .await;

    let generation = manager.current_network_generation_sync();
    let snapshot = manager
        .active_direct_path_snapshot("peer-lan", generation, true)
        .await
        .expect("healthy on-link Direct should publish a fast-path snapshot");
    assert_eq!(snapshot.path, NetworkPath::Direct);
    assert_eq!(snapshot.endpoint, endpoint);
    assert!(manager.active_direct_path_snapshot_is_current_sync("peer-lan", snapshot));

    manager
        .advance_network_generation("fast-path-generation-fence")
        .await;
    assert!(!manager.active_direct_path_snapshot_is_current_sync("peer-lan", snapshot));
}

#[tokio::test]
async fn public_direct_does_not_enter_lan_fast_path() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let endpoint: SocketAddr = "198.51.100.50:51850".parse().unwrap();
    manager.add_peer(&test_peer("peer-public", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer-public",
            endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager
        .record_direct_success("peer-public", Some(endpoint))
        .await;

    let generation = manager.current_network_generation_sync();
    assert!(
        manager
            .active_direct_path_snapshot("peer-public", generation, true)
            .await
            .is_none(),
        "Public Direct remains on the existing selector path"
    );
}

#[tokio::test]
async fn lan_direct_fast_path_sends_with_cached_session_and_socket() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let local_network = p2pnet_nat::LocalNetwork::new("127.0.0.1".parse().unwrap(), 8);
    peers.add_peer(&test_peer("peer-fast", endpoint)).await;
    peers
        .set_local_interface_networks(vec![local_network])
        .await;
    peers
        .add_candidates_with_sources(
            "peer-fast",
            &[endpoint.to_string()],
            &std::collections::HashMap::from([(endpoint.to_string(), "host".to_string())]),
        )
        .await;
    let local_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        !local_transport.peer_requires_direct_business_budget("peer-fast"),
        "legacy peers must remain unmanaged and use the existing Direct fast path"
    );
    let local_endpoint = local_transport.local_addr().unwrap();
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer-fast",
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local_endpoint),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(
            "peer-fast",
            Some(endpoint),
            Some(local_endpoint),
        )
        .await;

    let (transport, _outbound_rx) = WireGuardTransport::new();
    let (local_session, _remote_session) = establish_sessions();
    transport.add_session("peer-fast", local_session).await;
    let udp_transport = RwLock::new(Some(local_transport));
    let mut fast_paths = HashMap::new();
    let mut ineligible = HashMap::new();
    let counters_before = global_dataplane_profiler().fast_path_counters();
    let attempt = try_lan_direct_fast_path(
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-fast".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0, 0, 20],
            trace: None,
        },
        &transport,
        &peers,
        true,
        &udp_transport,
        &mut fast_paths,
        &mut ineligible,
    )
    .await;
    assert!(matches!(attempt, FastPathAttempt::Sent));
    assert_eq!(fast_paths.len(), 1);
    let counters_after_send = global_dataplane_profiler().fast_path_counters();
    assert!(counters_after_send.hits > counters_before.hits);
    assert!(counters_after_send.misses > counters_before.misses);

    let mut received = [0u8; 2048];
    let (received_len, source) =
        tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
            .await
            .expect("LAN Direct fast path must hand the ciphertext to the exact socket")
            .unwrap();
    assert!(received_len > 0);
    assert_eq!(source.ip(), local_endpoint.ip());

    let (replacement_session, _replacement_remote) = establish_sessions();
    transport
        .replace_session("peer-fast", replacement_session)
        .await;
    let stale_session_attempt = try_lan_direct_fast_path(
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-fast".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0, 0, 20],
            trace: None,
        },
        &transport,
        &peers,
        true,
        &udp_transport,
        &mut fast_paths,
        &mut ineligible,
    )
    .await;
    assert!(matches!(
        stale_session_attempt,
        FastPathAttempt::Fallback(_)
    ));
    assert!(fast_paths.is_empty());
    assert!(
        global_dataplane_profiler().fast_path_counters().invalidated
            > counters_after_send.invalidated
    );
}
