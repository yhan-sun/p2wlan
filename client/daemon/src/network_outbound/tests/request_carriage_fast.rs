// C07/C09/C10: actual LAN fast driver with real Noise and original UDP call.
use super::super::test_support::establish_sessions;
use super::*;
use crate::request_carriage::test_probe::{HandoffArgumentPoint, RequestHandoffArgumentProbe};
use crate::request_carriage::test_support::{mint_routed_request, PEER};

async fn direct_udp(peers: &Arc<PeerManager>, endpoint: SocketAddr) -> UdpTransport {
    peers
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "127.0.0.1".parse().unwrap(),
            8,
        )])
        .await;
    peers
        .add_candidates_with_sources(
            PEER,
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "host".to_string())]),
        )
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local = udp.local_addr().unwrap();
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            PEER,
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(PEER, Some(endpoint), Some(local))
        .await;
    assert!(!udp.peer_requires_direct_business_budget(PEER));
    assert!(peers
        .active_direct_path_snapshot(PEER, peers.current_network_generation_sync(), true)
        .await
        .is_some());
    let (_, socket) = udp
        .socket_for_peer_endpoint(Some(PEER), Some(endpoint))
        .await
        .unwrap();
    socket.writable().await.unwrap();
    udp
}

#[tokio::test]
async fn carriage_fast_driver_handoff_arguments_keep_same_a_and_actual_b() {
    let f = mint_routed_request().await;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = direct_udp(&f.peers, receiver.local_addr().unwrap()).await;
    let (session, mut remote) = establish_sessions();
    let probe = Arc::new(RequestHandoffArgumentProbe::new());
    let (transport, _raw_rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_request_handoff_probe(probe.clone());
    let life = f.record.expected_target_lifecycle().unwrap();
    let _ = transport
        .replace_session_for_lifecycle(PEER, session, life)
        .await;
    let instance = transport
        .session_status(PEER)
        .await
        .active_session_instance
        .unwrap();
    let udp_slot = RwLock::new(Some(udp));
    let mut paths = HashMap::new();
    let mut ineligible = HashMap::new();
    let before = Instant::now();
    assert!(matches!(
        try_lan_direct_fast_path(
            f.delivery.clone(),
            &transport,
            &f.peers,
            true,
            &udp_slot,
            &mut paths,
            &mut ineligible
        ),
        FastPathAttempt::Sent
    ));
    let mut wire = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let after = Instant::now();
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        f.record.original_packet()
    );
    assert_eq!(crate::transport::wire_counter(&wire[..n]), Some(0));
    let observed = probe
        .recorded
        .lock()
        .unwrap()
        .take()
        .expect("original fast UDP argument was observed");
    assert_eq!(observed.point, HandoffArgumentPoint::FastUdpCall);
    assert!(Arc::ptr_eq(
        &observed.token.unwrap().request().unwrap(),
        &f.record
    ));
    let b = observed.source.unwrap();
    assert_eq!(b.peer_id, PEER);
    assert_eq!(b.session_instance, instance);
    assert_eq!(b.authorized_peer_lifecycle, Some(life));
    assert!(b.encrypted_at >= before && b.encrypted_at <= after);
    assert!(b.belongs_to_transport);
    assert_eq!(Arc::strong_count(&f.record), 1);
}

#[tokio::test]
async fn carriage_actual_fast_would_block_retries_same_a_with_fresh_counter_and_b() {
    let f = mint_routed_request().await;
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = direct_udp(&f.peers, receiver.local_addr().unwrap()).await;
    let runtime = udp.dplpmtud_runtime();
    let udp_slot = RwLock::new(Some(udp));
    let (session, mut remote) = establish_sessions();
    let first_probe = Arc::new(RequestHandoffArgumentProbe::new());
    let (transport, _raw_rx) = WireGuardTransport::new_with_request_carriage();
    let transport = transport.with_request_handoff_probe(first_probe.clone());
    let life = f.record.expected_target_lifecycle().unwrap();
    let _ = transport
        .replace_session_for_lifecycle(PEER, session, life)
        .await;
    let mut paths = HashMap::new();
    let mut ineligible = HashMap::new();
    let outcome = runtime.with_business_publication_gate(|| {
        try_lan_direct_fast_path(
            f.delivery.clone(),
            &transport,
            &f.peers,
            true,
            &udp_slot,
            &mut paths,
            &mut ineligible,
        )
    });
    let FastPathAttempt::Fallback(retry) = outcome else {
        panic!("actual publication gate contention must be known not sent")
    };
    assert!(Arc::ptr_eq(
        &retry.binding().unwrap().token().request().unwrap(),
        &f.record
    ));
    assert_eq!(retry.packet, f.record.original_packet());
    assert_eq!(
        receiver.try_recv_from(&mut [0u8; 2048]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let first = first_probe
        .recorded
        .lock()
        .unwrap()
        .take()
        .expect("actual first encryption reached UDP argument before known not sent");
    assert_eq!(first.point, HandoffArgumentPoint::FastUdpCall);
    assert!(Arc::ptr_eq(
        &first.token.unwrap().request().unwrap(),
        &f.record
    ));
    let old_b = first.source.unwrap();
    let second_probe = Arc::new(RequestHandoffArgumentProbe::new());
    let transport = transport.with_request_handoff_probe(second_probe.clone());
    assert!(matches!(
        try_lan_direct_fast_path(
            retry,
            &transport,
            &f.peers,
            true,
            &udp_slot,
            &mut paths,
            &mut ineligible
        ),
        FastPathAttempt::Sent
    ));
    let mut wire = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(crate::transport::wire_counter(&wire[..n]), Some(1));
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..n]).unwrap(),
        f.record.original_packet()
    );
    let second = second_probe
        .recorded
        .lock()
        .unwrap()
        .take()
        .expect("fresh actual encryption reached the next UDP argument");
    assert!(Arc::ptr_eq(
        &second.token.unwrap().request().unwrap(),
        &f.record
    ));
    let fresh_b = second.source.unwrap();
    assert_eq!(fresh_b.session_instance, old_b.session_instance);
    assert_eq!(fresh_b.authorized_peer_lifecycle, Some(life));
    assert!(fresh_b.encrypted_at >= old_b.encrypted_at);
    assert!(fresh_b.belongs_to_transport);
    assert_eq!(Arc::strong_count(&f.record), 1);
}
