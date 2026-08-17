#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn diagnostics_server(
        health_status: u16,
        health_body: &'static str,
        status_status: u16,
        status_body: &'static str,
        status_content_type: &'static str,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = [0_u8; 1024];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                let (status, content_type, body) = if request.starts_with("GET /health ") {
                    (health_status, "text/plain", health_body)
                } else if request.starts_with("GET /status ") {
                    (status_status, status_content_type, status_body)
                } else {
                    (404, "text/plain", "not found")
                };
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    _ => "Status",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        format!("http://{address}/status")
    }

    fn unused_local_status_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{address}/status")
    }

    #[test]
    fn diagnostics_url_only_allows_loopback_hosts() {
        assert_eq!(
            normalize_diagnostics_url("http://127.0.0.1:39277/status").unwrap(),
            "http://127.0.0.1:39277/status"
        );
        assert_eq!(
            normalize_diagnostics_url("http://localhost:39277").unwrap(),
            "http://localhost:39277/status"
        );
        assert_eq!(
            normalize_diagnostics_url("http://[::1]:39277/status").unwrap(),
            "http://[::1]:39277/status"
        );

        for url in [
            "http://0.0.0.0:39277/status",
            "http://192.168.1.8:39277/status",
            "http://example.com:39277/status",
            "http://127.0.0.1/status",
            "file://127.0.0.1:39277/status",
        ] {
            assert!(normalize_diagnostics_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn status_url_converts_to_health_url() {
        assert_eq!(
            health_url_from_status_url("http://127.0.0.1:39277/status?verbose=1#frag").unwrap(),
            "http://127.0.0.1:39277/health"
        );
        assert_eq!(
            health_url_from_status_url("http://localhost:39277").unwrap(),
            "http://localhost:39277/health"
        );
    }

    #[test]
    fn diagnostics_bind_parses_loopback_addresses() {
        assert_eq!(
            diagnostics_bind_from_url("http://127.0.0.1:39277/status").unwrap(),
            "127.0.0.1:39277"
        );
        assert_eq!(
            diagnostics_bind_from_url("http://localhost:39278/status").unwrap(),
            "127.0.0.1:39278"
        );
        assert_eq!(
            diagnostics_bind_from_url("http://[::1]:39279/status").unwrap(),
            "[::1]:39279"
        );
    }

    #[tokio::test]
    async fn client_fetch_health_returns_true_for_200() {
        let url = diagnostics_server(
            200,
            "ok\n",
            200,
            r#"{"node_id":"node-1"}"#,
            "application/json",
        )
        .await;
        let client = test_client();

        assert!(client.fetch_health(&url).await.unwrap());
    }

    #[tokio::test]
    async fn client_fetch_health_returns_false_for_500() {
        let url = diagnostics_server(
            500,
            "error\n",
            200,
            r#"{"node_id":"node-1"}"#,
            "application/json",
        )
        .await;
        let client = test_client();

        assert!(!client.fetch_health(&url).await.unwrap());
    }

    #[tokio::test]
    async fn client_fetch_health_unreachable_maps_daemon_unavailable() {
        let client = DesktopHostClient::with_timeout(Duration::from_millis(100)).unwrap();

        let error = client
            .fetch_health(&unused_local_status_url())
            .await
            .unwrap_err();

        assert_eq!(error.kind, DesktopHostErrorKind::DaemonUnavailable);
        assert!(error.recoverable);
        assert!(error.message.contains("health endpoint"));
    }

    #[tokio::test]
    async fn client_fetch_status_returns_json() {
        let url = diagnostics_server(
            200,
            "ok\n",
            200,
            r#"{"node_id":"node-1","virtual_ip":"10.20.0.2"}"#,
            "application/json",
        )
        .await;
        let client = test_client();

        let status = client.fetch_status(&url).await.unwrap();

        assert_eq!(status["node_id"], "node-1");
        assert_eq!(status["virtual_ip"], "10.20.0.2");
    }

    #[tokio::test]
    async fn client_fetch_status_non_2xx_maps_daemon_unavailable() {
        let url = diagnostics_server(200, "ok\n", 503, "busy\n", "text/plain").await;
        let client = test_client();

        let error = client.fetch_status(&url).await.unwrap_err();

        assert_eq!(error.kind, DesktopHostErrorKind::DaemonUnavailable);
        assert!(error.recoverable);
        assert!(error.message.contains("HTTP 503"));
    }

    #[tokio::test]
    async fn client_fetch_status_non_json_maps_decode_failed() {
        let url = diagnostics_server(200, "ok\n", 200, "not json\n", "text/plain").await;
        let client = test_client();

        let error = client.fetch_status(&url).await.unwrap_err();

        assert_eq!(error.kind, DesktopHostErrorKind::DaemonStatusDecodeFailed);
        assert!(error.recoverable);
        assert!(error.message.contains("valid JSON"));
    }

    fn test_client() -> DesktopHostClient {
        fn token() -> Result<String> {
            Ok("test-diagnostics-token".to_string())
        }
        DesktopHostClient::with_timeout_and_auth_reader(Duration::from_millis(500), token).unwrap()
    }

    #[test]
    fn log_tail_does_not_exceed_max_lines() {
        let path = unique_test_path("p2wlan-desktop-host-log-tail.log");
        std::fs::write(&path, "one\n\n two \nthree\nfour\n").unwrap();

        let lines = recent_daemon_log_lines(&path, 2).unwrap();
        assert_eq!(lines, vec!["three".to_string(), "four".to_string()]);

        let empty = recent_daemon_log_lines(&path, 0).unwrap();
        assert!(empty.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn serde_field_names_match_desktop_contract() {
        let options = DesktopHostStartOptions {
            diagnostics_url: Some(DEFAULT_DIAGNOSTICS_STATUS_URL.to_string()),
            control_server: Some("http://control.local".to_string()),
            auth_token: Some("token".to_string()),
            network_id: Some("default".to_string()),
            device_name: Some("this-device".to_string()),
            tun_interface: Some("p2wlan0".to_string()),
            udp_bind: Some("0.0.0.0:0".to_string()),
            udp_advertise: None,
            socket_pool: Some("3".to_string()),
            mtu: Some(1420),
        };
        let options_json = serde_json::to_value(options).unwrap();
        assert_eq!(
            options_json.get("diagnosticsUrl").unwrap(),
            DEFAULT_DIAGNOSTICS_STATUS_URL
        );
        assert!(options_json.get("controlServer").is_some());
        assert!(options_json.get("authToken").is_some());
        assert!(options_json.get("networkId").is_some());
        assert!(options_json.get("deviceName").is_some());
        assert!(options_json.get("tunInterface").is_some());
        assert!(options_json.get("udpBind").is_some());
        assert!(options_json.get("udpAdvertise").is_some());
        assert!(options_json.get("socketPool").is_some());

        let status = DesktopHostStatus {
            operation: DesktopHostOperation {
                phase: DesktopHostPhase::WaitingForDaemon,
                message: "waiting".to_string(),
                started_at_ms: 7,
                last_error: None,
            },
            diagnostics: Some(serde_json::json!({"node_id": "node-1"})),
            diagnostics_url: DEFAULT_DIAGNOSTICS_STATUS_URL.to_string(),
            diagnostics_alive: true,
            diagnostics_stale: false,
            diagnostics_error: None,
        };
        let status_json = serde_json::to_value(status).unwrap();
        assert_eq!(
            status_json
                .pointer("/operation/phase")
                .and_then(serde_json::Value::as_str),
            Some("waiting_for_daemon")
        );
        assert!(status_json.get("diagnosticsUrl").is_some());
        assert!(status_json.get("diagnosticsAlive").is_some());
        assert!(status_json.get("diagnosticsStale").is_some());
        assert!(status_json.get("diagnosticsError").is_some());

        let permission = DesktopHostPermissionStatus::unsupported("macos");
        let permission_json = serde_json::to_value(permission).unwrap();
        assert!(permission_json.get("canCreateTun").is_some());
        assert!(permission_json.get("canModifyRoutes").is_some());
        assert!(permission_json.get("needsElevation").is_some());
        assert!(permission_json.get("recommendedAction").is_some());
        assert!(permission_json.get("elevatedCommandPreview").is_some());
    }

    #[test]
    fn pure_path_helpers_match_existing_layout() {
        assert_eq!(
            config_path_from_base("/tmp/config"),
            PathBuf::from("/tmp/config/p2wlan/p2wlan-config.json")
        );
        assert_eq!(
            macos_log_dir_from_home("/Users/test"),
            PathBuf::from("/Users/test/Library/Logs/p2wlan")
        );
        assert_eq!(
            linux_log_dir_from_home("/home/test"),
            PathBuf::from("/home/test/.p2wlan/logs")
        );
        assert_eq!(
            windows_log_dir_from_local_app_data(r"C:\Users\test\AppData\Local"),
            PathBuf::from(r"C:\Users\test\AppData\Local/p2wlan/logs")
        );
        assert_eq!(
            pid_path_from_log_dir("/tmp/logs"),
            PathBuf::from("/tmp/logs/p2wlan-daemon.pid")
        );
        assert_eq!(
            endpoint_path_from_log_dir("/tmp/logs"),
            PathBuf::from("/tmp/logs/p2wlan-daemon.endpoint")
        );
    }

    fn unique_test_path(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}-{stamp}", std::process::id(), name))
    }
}
