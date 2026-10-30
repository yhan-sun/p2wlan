//! Actual connection-map read sharing; no fake KernelRead or Full fact.
use super::*;

async fn traffic_peer() -> Arc<PeerManager> {
    let manager = Arc::new(PeerManager::new(
        Config::generate_default("http://ctrl.test", "default").unwrap(),
    ));
    manager
        .add_peer(&crate::control::PeerInfo {
            node_id: "traffic-peer".into(),
            public_key: "traffic-key".into(),
            endpoint: "127.0.0.1:41234".into(),
            virtual_ip: "10.21.1.3".into(),
            online: true,
            ..Default::default()
        })
        .await;
    manager
}

#[tokio::test]
async fn traffic_counters_share_actual_connection_reader_and_original_metadata_try() {
    let manager = traffic_peer().await;
    let held = manager.connections.read().await;
    manager.record_sent("traffic-peer", 17).await;
    manager.record_received("traffic-peer", 29).await;
    assert_eq!(held["traffic-peer"].bytes_sent.get(), 17);
    assert_eq!(held["traffic-peer"].bytes_received.get(), 29);
    assert!(manager
        .try_capture_original_kernel_read_peer(
            "traffic-peer",
            "10.21.1.3".parse().unwrap(),
            #[cfg(any(target_os = "linux", all(unix, test)))]
            None,
        )
        .is_ok());
    // This is an expectation only, never actual system-read/owner credit.
    assert!(manager.connections.try_read().is_ok());
    drop(held);
    assert!(manager.connections.try_write().is_ok());
}

#[tokio::test]
async fn traffic_connection_snapshot_is_frozen_after_later_live_byte_updates() {
    let manager = traffic_peer().await;
    manager.record_sent("traffic-peer", 3).await;
    let snapshot = manager.get_connection("traffic-peer").await.unwrap();
    manager.record_sent("traffic-peer", 5).await;
    manager.record_received("traffic-peer", 7).await;
    assert_eq!(snapshot.bytes_sent.get(), 3);
    assert_eq!(snapshot.bytes_received.get(), 0);
    let live = manager.get_connection("traffic-peer").await.unwrap();
    assert_eq!(live.bytes_sent.get(), 8);
    assert_eq!(live.bytes_received.get(), 7);
}
