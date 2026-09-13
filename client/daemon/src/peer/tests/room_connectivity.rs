#[tokio::test]
async fn room_old_peer_removal_does_not_erase_a_reassigned_ip_owner() {
    let peers =
        PeerManager::new(Config::generate_default("http://ctrl.test", "room-index").unwrap());
    let info = |id: &str| PeerInfo {
        node_id: id.into(),
        virtual_ip: "10.21.1.3".into(),
        public_key: "pk".into(),
        device_name: String::new(),
        app_version: String::new(),
        endpoint: String::new(),
        nat_type: String::new(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    peers.add_peer(&info("old-device")).await;
    peers.add_peer(&info("new-device")).await;
    peers.remove_peer("old-device").await;
    assert_eq!(
        peers.resolve_virtual_ip("10.21.1.3").await.as_deref(),
        Some("new-device")
    );
}

#[tokio::test]
async fn room_peer_readdress_rotates_the_session_and_replaces_ip_index() {
    let peers =
        PeerManager::new(Config::generate_default("http://ctrl.test", "room-index").unwrap());
    let mut info = PeerInfo {
        node_id: "b".into(),
        virtual_ip: "10.21.1.3".into(),
        public_key: "pk".into(),
        device_name: String::new(),
        app_version: String::new(),
        endpoint: String::new(),
        nat_type: String::new(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    peers.add_peer(&info).await;
    let old_session = peers.peer_session_generation_sync("b").unwrap();
    peers
        .record_direct_success("b", Some("1.2.3.4:5000".parse().unwrap()))
        .await;
    assert_eq!(
        peers.get_connection("b").await.unwrap().state,
        ConnectionState::Direct
    );
    info.virtual_ip = "10.21.1.4".into();
    assert!(peers.add_peer(&info).await.virtual_ip_changed);
    assert_ne!(
        peers.peer_session_generation_sync("b").unwrap(),
        old_session
    );
    assert!(!peers.peer_session_is_current_sync("b", old_session));
    assert_eq!(peers.resolve_virtual_ip("10.21.1.3").await, None);
    assert_eq!(
        peers.resolve_virtual_ip("10.21.1.4").await.as_deref(),
        Some("b")
    );
    let connection = peers.get_connection("b").await.unwrap();
    assert_ne!(connection.state, ConnectionState::Direct);
}
