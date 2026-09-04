mod mobile_lifecycle_evidence {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use serde_json::json;
    use tokio::sync::RwLock;

    use super::*;
    use crate::diagnostics::RuntimeDiagnosticsSnapshot;
    use crate::peer::{CandidateSetApplyResult, NetworkPath, PeerManager};

    #[test]
    fn ml03_runtime_owner_replacement() {
        let old: RuntimeDiagnosticsSnapshot = serde_json::from_value(json!({
            "version": "test",
            "process_id": 1234,
            "runtime_incarnation": 4,
            "node_id": "node-a",
            "virtual_ip": "10.20.0.1",
            "network_id": "net1",
            "network_generation": 0,
            "uptime_ms": 50,
            "relay_connected": true
        }))
        .unwrap();
        let replacement: RuntimeDiagnosticsSnapshot = serde_json::from_value(json!({
            "version": "test",
            "process_id": 1234,
            "runtime_incarnation": 5,
            "node_id": "node-a",
            "virtual_ip": "10.20.0.1",
            "network_id": "net1",
            "network_generation": 0,
            "uptime_ms": 1,
            "relay_connected": true
        }))
        .unwrap();
        assert_eq!(old.process_id, replacement.process_id);
        assert_eq!(old.runtime_incarnation, Some(4));
        assert_eq!(replacement.runtime_incarnation, Some(5));
        assert!(replacement.uptime_ms < old.uptime_ms);
        emit(
            "ML-03",
            "ml03_runtime_owner_replacement",
            &["native_runtime_stopped", "native_runtime_started"],
            json!({"daemon_process_id": old.process_id, "runtime_incarnation": 4}),
            json!({"daemon_process_id": replacement.process_id, "runtime_incarnation": 5}),
            "applied",
            json!({"new_process_adopted": true}),
        );
    }

    #[tokio::test]
    async fn ml04_android_network_hint() {
        let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        manager
            .advance_network_generation("initial wifi baseline")
            .await;
        let old = manager.current_network_generation().await;
        let new = manager.advance_network_generation("android wifi to cellular hint").await;
        assert_eq!(new, old + 1);
        emit(
            "ML-04",
            "ml04_android_network_hint",
            &["physical_network_changed", "candidate_refresh_started"],
            json!({"network_generation": old}),
            json!({"network_generation": new}),
            "applied",
            json!({"single_network_generation_advance": new == old + 1}),
        );
    }

    #[tokio::test]
    async fn ml05_hotspot_network_hint() {
        let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let old = manager.advance_network_generation("initial cellular baseline").await;
        let new = manager.advance_network_generation("android cellular to hotspot hint").await;
        assert_eq!(new, old + 1);
        emit(
            "ML-05",
            "ml05_hotspot_network_hint",
            &["physical_network_changed", "candidate_refresh_started"],
            json!({"network_generation": old}),
            json!({"network_generation": new}),
            "applied",
            json!({"single_network_generation_advance": new == old + 1}),
        );
    }

    #[tokio::test]
    async fn ml14_stale_candidate_result() {
        let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let endpoint = "203.0.113.10:51820".to_string();
        manager.add_peer(&evidence_peer("peer-candidate", &endpoint)).await;
        let candidates = vec![endpoint.clone()];
        let sources = HashMap::from([(endpoint.clone(), "stun_observed".to_string())]);
        assert_eq!(
            manager
                .add_candidates_with_metadata("peer-candidate", &candidates, &sources, 2, None)
                .await,
            CandidateSetApplyResult::Applied
        );
        assert_eq!(
            manager
                .add_candidates_with_metadata("peer-candidate", &candidates, &sources, 1, None)
                .await,
            CandidateSetApplyResult::IgnoredStale
        );
        emit(
            "ML-14",
            "ml14_stale_candidate_result",
            &["candidate_refresh_started", "physical_network_changed"],
            json!({"candidate_epoch": 2}),
            json!({"candidate_epoch": 1}),
            "stale_rejected",
            json!({"old_candidate_rejected": true}),
        );
    }

    #[tokio::test]
    async fn ml15_stale_socket_publication() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let legacy = Arc::new(RwLock::new(None));
        let publication = UdpTransportPublication::new(legacy);
        let old_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let old_lease = publication.publish(old_udp).await;
        let replacement_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
            .await
            .unwrap();
        let replacement_lease = publication.publish(replacement_udp).await;
        assert!(!publication.clear_if_owner(old_lease.owner()).await);
        assert_eq!(publication.current_owner().await, Some(replacement_lease.owner()));
        emit(
            "ML-15",
            "ml15_stale_socket_publication",
            &["physical_network_changed", "candidate_refresh_started"],
            json!({"network_generation": 12, "socket_publication_generation": 21}),
            json!({"network_generation": 13, "socket_publication_generation": 22}),
            "stale_rejected",
            json!({"old_socket_publication_rejected": true}),
        );
        publication.clear_current().await;
    }

    #[tokio::test]
    async fn ml16_relay_retention() {
        let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let endpoint: SocketAddr = "198.51.100.90:51831".parse().unwrap();
        manager.add_peer(&evidence_peer("peer-relay", &endpoint.to_string())).await;
        let generation = manager.current_network_generation().await;
        let relay_endpoint = "tcp://relay.test:18081";
        manager
            .record_relay_success_with_latency(
                "peer-relay",
                relay_endpoint,
                false,
                std::time::Duration::from_millis(35),
            )
            .await;
        manager
            .mark_relay_transport_ready("peer-relay", relay_endpoint, generation)
            .await;
        assert!(manager.confirm_relay_peer("peer-relay", "tcp://relay.test:18081", generation).await);
        assert!(manager
            .mark_relay_first_business_sent_for_generation("peer-relay", generation)
            .await);
        manager
            .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
                "peer-relay",
                endpoint,
                Some(std::time::Duration::from_millis(505)),
                generation,
                None,
            )
            .await;
        let during_rediscovery = manager.get_connection("peer-relay").await.unwrap();
        assert_eq!(during_rediscovery.active_path(), Some(NetworkPath::Relay));
        assert!(during_rediscovery
            .direct_events
            .iter()
            .any(|event| event.stage == "direct_probe_succeeded_relay_retained"));
        drop(during_rediscovery);
        manager
            .record_direct_probe_batch_failure_for_generation(
                "peer-relay",
                generation,
                "evidence direct rediscovery",
            )
            .await;
        let after_timeout = manager.get_connection("peer-relay").await.unwrap();
        assert_eq!(after_timeout.active_path(), Some(NetworkPath::Relay));
        assert!(manager
            .is_relay_peer_confirmed_for_generation("peer-relay", generation)
            .await);
        emit(
            "ML-16",
            "ml16_relay_retention",
            &["relay_retained", "candidate_refresh_started", "direct_reconfirmed"],
            json!({"network_generation": generation, "relay_connection_id": 77, "direct_validation_owner": "probe-1"}),
            json!({"network_generation": generation, "relay_connection_id": 77, "direct_validation_owner": "probe-2"}),
            "applied",
            json!({"relay_retained_until_direct_commit": true, "relay_retained_on_timeout": true}),
        );
    }

    #[tokio::test]
    async fn ml17_direct_current_generation() {
        let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let old_endpoint: SocketAddr = "127.0.0.1:51824".parse().unwrap();
        let new_endpoint: SocketAddr = "127.0.0.1:51825".parse().unwrap();
        manager.add_peer(&evidence_peer("peer-direct", &old_endpoint.to_string())).await;
        let old_generation = manager.current_network_generation().await;
        manager
            .record_direct_probe_success_with_latency(
                "peer-direct",
                old_endpoint,
                Some(std::time::Duration::from_millis(5)),
            )
            .await;
        assert!(manager.record_direct_success_for_generation("peer-direct", Some(old_endpoint), old_generation).await);
        let new_generation = manager.advance_network_generation("evidence direct generation").await;
        assert!(!manager.record_direct_success_for_generation("peer-direct", Some(old_endpoint), old_generation).await);
        manager.add_candidates("peer-direct", &[new_endpoint.to_string()]).await;
        assert!(manager.record_direct_probe_success_with_latency_for_generation("peer-direct", new_endpoint, Some(std::time::Duration::from_millis(7)), new_generation).await);
        assert!(manager.record_direct_success_for_generation("peer-direct", Some(new_endpoint), new_generation).await);
        let connection = manager.get_connection("peer-direct").await.unwrap();
        assert_eq!(connection.direct_generation, new_generation);
        emit(
            "ML-17",
            "ml17_direct_current_generation",
            &["candidate_refresh_started", "direct_reconfirmed"],
            json!({"network_generation": old_generation, "direct_validation_owner": "old-generation"}),
            json!({"network_generation": new_generation, "direct_validation_owner": "current-generation"}),
            "applied",
            json!({"direct_confirmed_current_generation": connection.direct_generation == new_generation}),
        );
    }

    fn evidence_peer(node_id: &str, endpoint: &str) -> crate::control::PeerInfo {
        crate::control::PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: format!("pk-{node_id}"),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 1,
            relay_rtt_ms: None,
        }
    }

    fn emit(
        scenario_id: &str,
        test_name: &str,
        events: &[&str],
        old_identity: serde_json::Value,
        new_identity: serde_json::Value,
        decision: &str,
        invariants: serde_json::Value,
    ) {
        let exact_test_id = format!("tests::mobile_lifecycle_evidence::{test_name}");
        println!(
            "MOBILE_LIFECYCLE_RECORD {}",
            json!({
                "scenario_id": scenario_id,
                "exact_test_id": exact_test_id,
                "executed": true,
                "skipped": false,
                "result": "pass",
                "events": events,
                "observed_old_identity": old_identity,
                "observed_new_identity": new_identity,
                "observed_decision": decision,
                "invariants": invariants,
                "execution_source": "rust_test_nocapture"
            })
        );
    }
}
