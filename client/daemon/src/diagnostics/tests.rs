#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::*;
    use crate::control::PeerInfo;
    use crate::peer::{REASON_DIRECT_PROBE_FAILED, REASON_PATH_UNAVAILABLE};

    #[test]
    fn no_browser_cors_is_never_emitted_for_any_origin() {
        // The React/Vite web console is deleted; no browser origin is trusted.
        assert_eq!(
            no_browser_cors("GET /status HTTP/1.1\r\nOrigin: http://legacy.invalid\r\n\r\n"),
            None
        );
        assert_eq!(
            no_browser_cors("GET /status HTTP/1.1\r\nOrigin: http://legacy.invalid\r\n\r\n"),
            None
        );
        assert_eq!(
            no_browser_cors("GET /status HTTP/1.1\r\norigin: http://127.0.0.1:1420\r\n\r\n"),
            None
        );
        assert_eq!(
            no_browser_cors("GET /status HTTP/1.1\r\nOrigin: https://example.com\r\n\r\n"),
            None
        );
    }

    #[test]
    fn bearer_token_extracts_authorization_header_value() {
        assert_eq!(
            bearer_token("GET /status HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n"),
            Some("abc123")
        );
        assert_eq!(
            bearer_token("GET /status HTTP/1.1\r\nauthorization: bearer xyz\r\n\r\n"),
            Some("xyz")
        );
        assert_eq!(bearer_token("GET /status HTTP/1.1\r\n\r\n"), None);
        assert_eq!(
            bearer_token("GET /status HTTP/1.1\r\nOrigin: http://legacy.invalid\r\n\r\n"),
            None
        );
    }

    #[test]
    fn route_repair_report_never_reports_false_success() {
        use crate::route::RouteObservation;
        use crate::route::RouteState;

        let obs = |state: RouteState| RouteObservation {
            cidr: "10.20.0.0/16".to_string(),
            expected_interface: "p2wlan0".to_string(),
            actual_interface: None,
            state,
            owned: true,
        };

        // Missing -> Installed is the only "changed" outcome.
        let (status, body) = route_repair_report(obs(RouteState::Missing), obs(RouteState::Installed));
        assert_eq!(status, 200);
        assert!(body.changed);
        assert!(body.attempted);
        assert_eq!(body.after, "installed");

        // Conflict -> Installed is a real change too.
        let (status, body) = route_repair_report(obs(RouteState::Conflict), obs(RouteState::Installed));
        assert_eq!(status, 200);
        assert!(body.changed);

        // Repair that leaves the route Missing (add failed) is NOT a success.
        let (status, body) = route_repair_report(obs(RouteState::Missing), obs(RouteState::Missing));
        assert_eq!(status, 409);
        assert!(!body.changed);
        assert_eq!(body.reason, "add_failed");

        // A third-party conflict that is not removed is NOT a success, and the
        // caller must not be told the route is repaired.
        let (status, body) = route_repair_report(obs(RouteState::Conflict), obs(RouteState::Conflict));
        assert_eq!(status, 409);
        assert!(!body.changed);
        assert_eq!(body.reason, "conflict_remains");

        // Unknown stays a failure, never a success.
        let (status, body) = route_repair_report(obs(RouteState::Unknown), obs(RouteState::Unknown));
        assert_eq!(status, 503);
        assert!(!body.changed);

        // Already Installed -> no-op, success, not "changed".
        let (status, body) =
            route_repair_report(obs(RouteState::Installed), obs(RouteState::Installed));
        assert_eq!(status, 200);
        assert!(!body.changed);
        assert!(!body.attempted);

        // Every report must state that the daemon/TUN/sessions were not
        // restarted — repair is in-place only.
        for (state, after) in [
            (RouteState::Missing, RouteState::Installed),
            (RouteState::Conflict, RouteState::Installed),
            (RouteState::Missing, RouteState::Missing),
            (RouteState::Conflict, RouteState::Conflict),
            (RouteState::Unknown, RouteState::Unknown),
        ] {
            let (_, body) = route_repair_report(obs(state), obs(after));
            assert!(!body.restarted_daemon);
        }
    }

    #[test]
    fn split_request_target_separates_query_string() {
        assert_eq!(split_request_target("/status"), ("/status", None));
        assert_eq!(
            split_request_target("/speedtest?peer=10.20.0.2&duration_ms=10000"),
            ("/speedtest", Some("peer=10.20.0.2&duration_ms=10000"))
        );
    }

    #[test]
    fn speedtest_error_status_maps_expected_client_states() {
        assert_eq!(speedtest_error_status("missing peer virtual IP"), 400);
        assert_eq!(
            speedtest_error_status("peer 10.20.0.2 is not using a confirmed direct path"),
            409
        );
        assert_eq!(speedtest_error_status("download speedtest failed"), 503);
    }

    #[test]
    fn diagnostics_snapshot_timeout_is_structured_and_fail_closed() {
        let body: serde_json::Value =
            serde_json::from_str(&diagnostics_snapshot_timeout_body()).unwrap();
        assert_eq!(body["reason_code"], "status_snapshot_timeout");
        assert_eq!(body["error"], "diagnostics snapshot timed out");
    }

    #[tokio::test]
    async fn speedtest_protocol_measures_loopback_download_and_upload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let worker = tokio::spawn(serve_speedtest(listener, shutdown_rx));

        let result = run_speedtest_client(
            addr,
            "127.0.0.1".to_string(),
            Duration::from_millis(600),
        )
        .await
        .unwrap();

        assert!(result.download_bytes > 0);
        assert!(result.upload_bytes > 0);
        assert!(result.download_mbps > 0.0);
        assert!(result.upload_mbps > 0.0);
        let _ = shutdown_tx.send(true);
        worker.await.unwrap().unwrap();
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
        let route_manager = Arc::new(crate::route::RouteManager::new("p2wlan0".to_string()));
        let status_events = StatusEventBus::new();
        let context = DiagnosticsContext::new(
            config,
            peers,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(GatewayMappingDiagnostics::default())),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
            health,
            task_manager,
            route_manager,
            shutdown_tx,
            ConnectionTimeline::new("node-a", 0),
            status_events,
            None,
            Some("diag-test-token".to_string()),
        );
        let context_probe = context.clone();
        let worker = tokio::spawn(serve_diagnostics(listener, context, shutdown_rx));

        let mut health_stream = TcpStream::connect(addr).await.unwrap();
        health_stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut health_response = String::new();
        health_stream.read_to_string(&mut health_response).await.unwrap();
        assert!(health_response.starts_with("HTTP/1.1 200 OK"));

        let mut version_stream = TcpStream::connect(addr).await.unwrap();
        version_stream
            .write_all(b"GET /status.version HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut version_response = String::new();
        version_stream.read_to_string(&mut version_response).await.unwrap();
        assert!(version_response.starts_with("HTTP/1.1 200 OK"));

        let mut unauthenticated_status = TcpStream::connect(addr).await.unwrap();
        unauthenticated_status
            .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut unauthenticated_status_response = String::new();
        unauthenticated_status
            .read_to_string(&mut unauthenticated_status_response)
            .await
            .unwrap();
        assert!(unauthenticated_status_response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(unauthenticated_status_response.contains("WWW-Authenticate: Bearer"));

        let mut wrong_status = TcpStream::connect(addr).await.unwrap();
        wrong_status
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut wrong_status_response = String::new();
        wrong_status.read_to_string(&mut wrong_status_response).await.unwrap();
        assert!(wrong_status_response.starts_with("HTTP/1.1 401 Unauthorized"));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:1420\r\nAuthorization: Bearer diag-test-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"gateway_mapping\""));
        assert!(
            !response.contains("Access-Control-Allow-Origin"),
            "no browser origin may be allowed after the React console was deleted"
        );
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let snapshot: DiagnosticsSnapshot = serde_json::from_str(body).unwrap();
        assert_eq!(snapshot.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(snapshot.process_id, std::process::id());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.network_generation, 0);
        assert_eq!(
            snapshot.captured_revision, snapshot.revision,
            "peer data must carry the exact revision it was captured under"
        );
        assert_eq!(snapshot.peers.len(), 1);
        assert!(snapshot.peer_snapshot_shape.starts_with("v1:"));
        assert!(!snapshot.peer_snapshot_stale);
        assert!(snapshot.captured_at_ms <= snapshot.uptime_ms);
        assert!(snapshot.peer_snapshot_age_ms <= snapshot.uptime_ms);
        {
            let cache = context_probe
                .peer_snapshot_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let cached = cache.as_ref().expect("validated peer capture is cached");
            assert_eq!(cached.network_generation, snapshot.network_generation);
            assert_eq!(cached.capture_revision, snapshot.captured_revision);
            assert_eq!(cached.captured_at_ms, snapshot.captured_at_ms);
            assert_eq!(cached.peers.len(), snapshot.peers.len());
            assert_eq!(cached.shape, snapshot.peer_snapshot_shape);
            assert!(
                cached.captured_at.elapsed().as_millis()
                    >= snapshot.peer_snapshot_age_ms as u128
            );
        }

        // Reproduce the fair-RwLock status outage deterministically: retain a
        // reader, queue a writer behind it, then issue /status. Tokio blocks
        // new readers behind the queued writer; /status must use the validated
        // cache and remain HTTP 200 without waiting for either owner.
        let connection_reader = context_probe
            .peers
            .hold_connections_reader_for_test()
            .await;
        let queued_writer_manager = context_probe.peers.clone();
        let writer_started = Arc::new(tokio::sync::Notify::new());
        let writer_started_task = writer_started.clone();
        let queued_writer = tokio::spawn(async move {
            writer_started_task.notify_one();
            let _writer = queued_writer_manager
                .hold_connections_writer_for_test()
                .await;
        });
        writer_started.notified().await;
        for _ in 0..64 {
            if context_probe.peers.try_all_connections().is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            context_probe.peers.try_all_connections().is_none(),
            "the writer must be fairly queued before the status request"
        );

        let mut contended_status = TcpStream::connect(addr).await.unwrap();
        contended_status
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer diag-test-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut contended_response = String::new();
        tokio::time::timeout(
            Duration::from_secs(2),
            contended_status.read_to_string(&mut contended_response),
        )
        .await
        .expect("/status must not wait behind a fairly queued writer")
        .unwrap();
        assert!(contended_response.starts_with("HTTP/1.1 200 OK"));
        let contended_body = contended_response.split("\r\n\r\n").nth(1).unwrap();
        let contended_snapshot: DiagnosticsSnapshot =
            serde_json::from_str(contended_body).unwrap();
        assert!(contended_snapshot.peer_snapshot_stale);
        assert_eq!(contended_snapshot.peers.len(), snapshot.peers.len());
        assert_eq!(
            contended_snapshot.peer_snapshot_shape,
            snapshot.peer_snapshot_shape
        );

        drop(connection_reader);
        queued_writer.await.unwrap();
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
        assert_eq!(current_path.reason_code, REASON_PATH_UNAVAILABLE);

        let mut events_stream = TcpStream::connect(addr).await.unwrap();
        let previous_process_id = std::process::id().wrapping_add(1);
        events_stream
            .write_all(
                format!(
                    "GET /events?since={}&process_id={} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer diag-test-token\r\n\r\n",
                    snapshot.revision, previous_process_id
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut events_response = String::new();
        events_stream
            .read_to_string(&mut events_response)
            .await
            .unwrap();
        assert!(events_response.starts_with("HTTP/1.1 200 OK"));
        let events_body = events_response.split("\r\n\r\n").nth(1).unwrap();
        let events: EventsResponse = serde_json::from_str(events_body).unwrap();
        assert_eq!(events.process_id, std::process::id());
        assert_eq!(events.revision, snapshot.revision);
        assert!(events.reset_required);

        let mut scoped_stream = TcpStream::connect(addr).await.unwrap();
        scoped_stream
            .write_all(
                b"GET /status/peer/node-b HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer diag-test-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut scoped_response = String::new();
        scoped_stream
            .read_to_string(&mut scoped_response)
            .await
            .unwrap();
        assert!(scoped_response.starts_with("HTTP/1.1 200 OK"));
        let scoped_body = scoped_response.split("\r\n\r\n").nth(1).unwrap();
        let scoped: PeerScopedDiagnosticsSnapshot = serde_json::from_str(scoped_body).unwrap();
        assert_eq!(scoped.network_peer_count, 0);
        assert!(scoped.captured_at_ms > 0);
        assert_eq!(scoped.peer.unwrap().node_id, "node-b");

        let mut runtime_stream = TcpStream::connect(addr).await.unwrap();
        runtime_stream
            .write_all(
                b"GET /status.runtime HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer diag-test-token\r\n\r\n",
            )
            .await
            .unwrap();
        let mut runtime_response = String::new();
        runtime_stream
            .read_to_string(&mut runtime_response)
            .await
            .unwrap();
        assert!(runtime_response.starts_with("HTTP/1.1 200 OK"));
        let runtime_body = runtime_response.split("\r\n\r\n").nth(1).unwrap();
        let runtime: RuntimeDiagnosticsSnapshot = serde_json::from_str(runtime_body).unwrap();
        assert_eq!(runtime.process_id, std::process::id());
        assert_eq!(runtime.node_id, "node-a");
        assert_eq!(runtime.virtual_ip, "10.20.0.1");
        assert_eq!(runtime.network_id, "net1");
        assert!(runtime.uptime_ms > 0);

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

        // A mutation without the per-process token is rejected, never executed.
        assert!(shutdown_response.starts_with("HTTP/1.1 401 Unauthorized"));
        assert!(shutdown_response.contains("WWW-Authenticate: Bearer"));
        assert!(shutdown_response.contains("unauthorized"));
        assert!(!shutdown_response.contains("shutting down"));

        let mut logs_stream = TcpStream::connect(addr).await.unwrap();
        logs_stream
            .write_all(b"GET /logs/tail HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut logs_response = String::new();
        logs_stream.read_to_string(&mut logs_response).await.unwrap();
        assert!(logs_response.starts_with("HTTP/1.1 401 Unauthorized"));

        let mut repair_stream = TcpStream::connect(addr).await.unwrap();
        repair_stream
            .write_all(
                b"POST /routes/repair HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut repair_response = String::new();
        repair_stream.read_to_string(&mut repair_response).await.unwrap();
        assert!(repair_response.starts_with("HTTP/1.1 401 Unauthorized"));

        let mut disallowed_stream = TcpStream::connect(addr).await.unwrap();
        disallowed_stream
            .write_all(
                b"POST /status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer diag-test-token\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut disallowed_response = String::new();
        disallowed_stream
            .read_to_string(&mut disallowed_response)
            .await
            .unwrap();
        assert!(disallowed_response.starts_with("HTTP/1.1 403 Forbidden"));

        // The same request with the correct Bearer token succeeds.
        let mut authed_shutdown_stream = TcpStream::connect(addr).await.unwrap();
        authed_shutdown_stream
            .write_all(
                b"POST /shutdown HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer diag-test-token\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
        let mut authed_shutdown_response = String::new();
        authed_shutdown_stream
            .read_to_string(&mut authed_shutdown_response)
            .await
            .unwrap();

        assert!(authed_shutdown_response.starts_with("HTTP/1.1 200 OK"));
        assert!(authed_shutdown_response.contains("shutting down"));

        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stale_peer_diagnostics_shape_is_rejected_after_live_health_change() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let peers = PeerManager::new(config);
        peers
            .add_peer(&PeerInfo {
                node_id: "node-shape".to_string(),
                device_name: "Shape peer".to_string(),
                app_version: String::new(),
                public_key: "pk".to_string(),
                endpoint: "127.0.0.1:51820".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 1,
                relay_rtt_ms: None,
            })
            .await;
        let stale = peers
            .diagnostics_with_path_selection(
                true,
                false,
                DIRECT_RETRY_BASE_INTERVAL,
                None,
            )
            .await;
        assert!(peer_snapshot_core_matches(
            &stale,
            &peers.all_connections().await
        ));

        peers
            .record_direct_failure_with_code(
                "node-shape",
                REASON_DIRECT_PROBE_FAILED,
                "shape changed",
            )
            .await;
        assert!(
            !peer_snapshot_core_matches(&stale, &peers.all_connections().await),
            "an old cached latency/health shape must not validate against current peer state"
        );
    }
}
