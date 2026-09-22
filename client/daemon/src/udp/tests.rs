include!("tests/part01a.rs");
include!("tests/part01b.rs");
include!("tests/part02a.rs");
include!("tests/part02b.rs");
include!("tests/part03.rs");
include!("tests/part04.rs");
include!("tests/part05.rs");
include!("tests/part06.rs");
include!("tests/part07.rs");
include!("tests/part08.rs");
include!("tests/part09.rs");

#[tokio::test]
async fn audit_cancel_inbound_must_release_primary_socket_with_ipv6() {
    for enable_ipv6 in [false, true] {
        let mut udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
            .await
            .unwrap();
        if enable_ipv6 && udp.ipv6_socket.is_none() {
            eprintln!("IPv6 loopback is unavailable; IPv4 cancellation was still verified");
            return;
        }
        if !enable_ipv6 {
            udp.ipv6_socket = None;
        }
        let addr = udp.local_addr().unwrap();
        let primary = Arc::downgrade(&udp.socket);
        let (tx, _rx) = mpsc::channel(4);
        let mut reader = Box::pin(udp.run_inbound(tx));
        // Drive production run_inbound through child spawning to the receive wait.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(reader.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(reader); // Equivalent to the parent task's abort at rebind/shutdown.
        timeout(Duration::from_secs(1), async {
            while primary.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled readers must release their sockets");
        let rebound = UdpSocket::bind(addr).await;
        assert!(rebound.is_ok(), "IPv6={enable_ipv6}: cancelled inbound retains {} primary socket owners and prevents rebind: {:?}",primary.strong_count(),rebound.err());
    }
}

#[tokio::test]
async fn audit_heartbeat_hook_must_release_retired_udp_socket() {
    let peers = peer_manager();
    let mut udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    // Isolate this issue from the independent IPv6 reader cancellation leak.
    udp.ipv6_socket = None;
    let addr = udp.local_addr().unwrap();
    let primary = Arc::downgrade(&udp.socket);
    peers.set_relay_backoff_heartbeat_cancel_hook(udp.relay_backoff_heartbeat_cancel_hook());
    udp.cancel_all_relay_backoff_heartbeats();
    drop(udp);
    let rebound = UdpSocket::bind(addr).await;
    let retained = primary.strong_count();
    // The installed weak callback remains safe after its registry has disappeared.
    peers.cancel_relay_backoff_heartbeat("retired-peer");
    assert!(rebound.is_ok(), "retired IPv4-only transport retained by heartbeat hook: {retained} socket owners, error={:?}",rebound.err());
}

#[tokio::test]
async fn room_authorization_is_checked_at_udp_socket_boundary() {
    let auth = crate::rooms::RoomAuthorization::new("room-udp");
    assert!(auth.replace(
        "10.21.1.2",
        [("peer-b".into(), "10.21.1.3".into())],
        std::time::Instant::now(),
        30
    ));
    let packet = EncryptedPeerPacket {
        room_authorization: auth.send_permit("peer-b", "10.21.1.3", "10.21.1.2"),
        peer_id: "peer-b".into(),
        dst_ip: "10.21.1.3".into(),
        wire_bytes: vec![4, 0, 1, 2],
        is_business: true,
    };
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peer_manager())
        .await
        .unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = receiver.local_addr().unwrap();
    udp.send_encrypted_packet_on_socket(&udp.socket, 0, &packet, target)
        .await
        .unwrap();
    let mut bytes = [0; 16];
    assert_eq!(receiver.recv_from(&mut bytes).await.unwrap().0, 4);
    auth.invalidate();
    assert!(udp
        .send_encrypted_packet_on_socket(&udp.socket, 0, &packet, target)
        .await
        .is_err());
    assert!(
        timeout(Duration::from_millis(50), receiver.recv_from(&mut bytes))
            .await
            .is_err()
    );
}

#[path = "tests/destination_budget.rs"]
mod destination_budget;
