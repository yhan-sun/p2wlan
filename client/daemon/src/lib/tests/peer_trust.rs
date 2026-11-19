use super::*;
use crate::config::{PeerIdentityPin, PeerTrustConfig, PeerTrustMode};

#[tokio::test]
async fn strict_peer_trust_rechecks_initiator_snapshot_without_reservation_leak() {
    let mut config = Config::generate_default("http://127.0.0.1:1", "net-pinned").unwrap();
    config.network.manual = true;
    let info = control::PeerInfo {
        node_id: "pinned-peer".into(),
        public_key: hex::encode(NodeIdentity::generate().public_key()),
        virtual_ip: "10.20.0.2".into(),
        online: true,
        ..control::PeerInfo::default()
    };
    config.network.peer_trust = PeerTrustConfig {
        mode: PeerTrustMode::Strict,
        network_id: config.network.network_id.clone(),
        peers: vec![PeerIdentityPin {
            node_id: info.node_id.clone(),
            public_key: info.public_key.clone(),
            virtual_ip: info.virtual_ip.clone(),
        }],
    };
    let daemon = Daemon::new(config);
    daemon.peers.add_peer(&info).await;
    let mut reservation = daemon
        .reserve_event_initiator_handshake(&info.node_id)
        .expect("pinned peer can reserve its current lifecycle");
    let mut tampered_snapshot = info.clone();
    tampered_snapshot.public_key = hex::encode(NodeIdentity::generate().public_key());
    assert!(daemon
        .run_reserved_initiator_handshake(&tampered_snapshot, &mut reservation)
        .await
        .unwrap()
        .is_none());
    assert!(*reservation.cancellation.borrow());
    assert!(!daemon.transport.has_session(&info.node_id).await);
    let next = daemon
        .reserve_event_initiator_handshake(&info.node_id)
        .expect("rejected snapshot must release its exact reservation");
    daemon
        .pending_handshakes
        .lock()
        .cancel_reservation_if_current(&info.node_id, next.owner);
}

#[tokio::test]
async fn strict_peer_trust_direct_event_revokes_transport_and_membership() {
    let mut config = Config::generate_default("http://127.0.0.1:1", "net-pinned").unwrap();
    config.network.manual = true;
    let remote = NodeIdentity::generate();
    let info = control::PeerInfo {
        node_id: "pinned-peer".into(),
        public_key: hex::encode(remote.public_key()),
        virtual_ip: "10.20.0.2".into(),
        online: true,
        ..control::PeerInfo::default()
    };
    config.network.peer_trust = PeerTrustConfig {
        mode: PeerTrustMode::Strict,
        network_id: config.network.network_id.clone(),
        peers: vec![PeerIdentityPin {
            node_id: info.node_id.clone(),
            public_key: info.public_key.clone(),
            virtual_ip: info.virtual_ip.clone(),
        }],
    };
    let mut daemon = Daemon::new(config);
    assert!(daemon.peers.add_peer(&info).await.is_new);
    let original_lifecycle = daemon
        .peers
        .peer_session_generation_sync(&info.node_id)
        .unwrap();
    let (session, _) = part03_establish_sessions();
    daemon.transport.add_session(&info.node_id, session).await;
    assert!(daemon.transport.has_session(&info.node_id).await);
    let mut changed = info.clone();
    changed.public_key = hex::encode(NodeIdentity::generate().public_key());
    daemon
        .control
        .event_sender()
        .send(ControlEvent::PeerUpdated(changed))
        .unwrap();
    let peers = daemon.peers.clone();
    let transport = daemon.transport.clone();
    let shutdown = daemon.shutdown_tx.clone();
    let (net_tx, _net_rx) = mpsc::channel(4);
    let task = tokio::spawn(async move {
        daemon.run_control_event_loop(&mut false, net_tx).await;
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while peers.peer_exists_sync(&info.node_id) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("rejected direct event must complete canonical cleanup");
    assert!(!peers.peer_session_is_current_sync(&info.node_id, original_lifecycle));
    assert!(!transport.has_session(&info.node_id).await);
    shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn strict_peer_trust_invalid_direct_daemon_configuration_stops_before_run() {
    let mut config = Config::generate_default("http://127.0.0.1:1", "net-pinned").unwrap();
    config.control.auth_token = "fixture-token".into();
    config.network.peer_trust = PeerTrustConfig {
        mode: PeerTrustMode::Strict,
        network_id: "other-network".into(),
        peers: vec![],
    };
    let mut daemon = Daemon::new(config);
    assert!(matches!(daemon.run().await, Err(DaemonError::Config(_))));
    assert!(daemon.task_manager.task_statuses().await.is_empty());
}
