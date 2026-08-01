#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::*;
    use crate::control::PeerInfo;
    use crate::peer::{REASON_DIRECT_PROBE_FAILED, REASON_PATH_RELAY_UNAVAILABLE};

    #[test]
    fn cors_origin_is_restricted_to_local_dev_server() {
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\nOrigin: http://localhost:14327\r\n\r\n"),
            Some("http://localhost:14327")
        );
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\nOrigin: http://localhost:1420\r\n\r\n"),
            Some("http://localhost:1420")
        );
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\norigin: http://127.0.0.1:1420\r\n\r\n"),
            Some("http://127.0.0.1:1420")
        );
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\nOrigin: https://example.com\r\n\r\n"),
            None
        );
    }

    #[test]
    fn mtu_diagnostics_explain_relay_high_mtu_risk() {
        let default_direct = MtuDiagnostics::from_runtime(1420, false);
        assert_eq!(default_direct.profile, "default");
        assert!(!default_direct.relay_path_observed);
        assert_eq!(default_direct.suggested_safe_mtu, None);
        assert!(default_direct.risks.is_empty());

        let relay_default = MtuDiagnostics::from_runtime(1420, true);
        assert!(relay_default.relay_path_observed);
        assert_eq!(relay_default.suggested_safe_mtu, Some(RELAY_SAFE_MTU));
        assert!(relay_default
            .risks
            .iter()
            .any(|risk| risk.code == "relay_path_high_mtu"
                && risk.suggested_mtu == Some(RELAY_SAFE_MTU)));

        let jumbo = MtuDiagnostics::from_runtime(9000, false);
        assert_eq!(jumbo.profile, "jumbo_high_risk");
        assert!(jumbo
            .risks
            .iter()
            .any(|risk| risk.code == "jumbo_mtu_high_risk"
                && risk.suggested_mtu == Some(WIREGUARD_STYLE_MTU)));
    }

    #[tokio::test]
    async fn diagnostics_server_returns_status_json() {
        let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.node.node_id = "node-a".to_string();
        config.network.virtual_ip = "10.20.0.1".to_string();
        let config = Arc::new(config);
        let peers = Arc::new(PeerManager::new((*config).clone()));
        peers
            .add_peer(&PeerInfo {
                node_id: "node-b".to_string(),
                device_name: "Office Mac".to_string(),
                app_version: String::new(),
                public_key: "pk".to_string(),
                endpoint: "127.0.0.1:51820".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
        peers.record_direct_failure("node-b", "probe timeout").await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let health = HealthState::new();
        let task_manager = TaskManager::new(health.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let context = DiagnosticsContext::new(
            config,
            peers,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(GatewayMappingDiagnostics::default())),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
            health,
            task_manager,
            shutdown_tx,
        );
        let worker = tokio::spawn(serve_diagnostics(listener, context, shutdown_rx));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:1420\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"gateway_mapping\""));
        assert!(response.contains("Access-Control-Allow-Origin: http://127.0.0.1:1420\r\n"));
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let snapshot: DiagnosticsSnapshot = serde_json::from_str(body).unwrap();
        assert_eq!(snapshot.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(snapshot.process_id, std::process::id());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.network_generation, 0);
        assert_eq!(
            snapshot.protocol.handshake,
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        );
        assert_eq!(snapshot.protocol.aead, "ChaCha20-Poly1305");
        assert!(!snapshot.protocol.wireguard_interop);
        assert!(!snapshot.protocol.turn_compatible);
        assert_eq!(snapshot.protocol.security_audit, "not_completed");
        assert_eq!(snapshot.mtu.configured_mtu, 1420);
        assert_eq!(snapshot.mtu.profile, "default");
        assert_eq!(snapshot.mtu.relay_safe_mtu, 1380);
        assert!(!snapshot.mtu.automatic_pmtu);
        assert!(!snapshot.mtu.relay_path_observed);
        assert_eq!(snapshot.mtu.suggested_safe_mtu, None);
        assert!(snapshot.mtu.risks.is_empty());
        assert!(snapshot.local_candidates.is_empty());
        assert_eq!(snapshot.nat_profile, None);
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].node_id, "node-b");
        assert_eq!(snapshot.peers[0].device_name, "Office Mac");
        assert_eq!(
            snapshot.relay_selection,
            RelaySelectionDiagnostics::default()
        );
        assert_eq!(
            snapshot.peers[0].direct.last_error.as_deref(),
            Some("probe timeout")
        );
        assert_eq!(
            snapshot.peers[0].direct.last_error_code.as_deref(),
            Some(REASON_DIRECT_PROBE_FAILED)
        );
        assert_eq!(snapshot.peers[0].last_path_selection, None);
        assert!(snapshot.peers[0].path_events.is_empty());
        let current_path = snapshot.peers[0]
            .current_path_selection
            .as_ref()
            .expect("current path selection should be included in /status");
        assert_eq!(current_path.reason_code, REASON_PATH_RELAY_UNAVAILABLE);

        let mut shutdown_stream = TcpStream::connect(addr).await.unwrap();
        shutdown_stream
            .write_all(b"POST /shutdown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut shutdown_response = String::new();
        shutdown_stream
            .read_to_string(&mut shutdown_response)
            .await
            .unwrap();

        assert!(shutdown_response.starts_with("HTTP/1.1 200 OK"));
        assert!(shutdown_response.contains("shutting down"));

        worker.await.unwrap().unwrap();
    }
}
