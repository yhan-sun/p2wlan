#[tokio::test]
async fn test_peer_manager_active_connections() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: "1.2.3.4:5000".to_string(),
        nat_type: "FullCone".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    manager.add_peer(&peer_info).await;

    // Initially no active connections
    assert!(manager.active_connections().await.is_empty());

    manager.update_state("peer1", ConnectionState::Direct).await;
    assert_eq!(manager.active_connections().await.len(), 1);
}
