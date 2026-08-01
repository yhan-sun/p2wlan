use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_options(diagnostics_url: String) -> DaemonStartOptions {
    DaemonStartOptions {
        diagnostics_url: Some(diagnostics_url),
        control_server: Some("http://127.0.0.1:18080".to_string()),
        auth_token: Some("test-token".to_string()),
        network_id: Some("test-network".to_string()),
        device_name: Some("test-device".to_string()),
        tun_interface: Some("p2wlan-test".to_string()),
        udp_bind: Some("0.0.0.0:60207".to_string()),
        udp_advertise: Some("203.0.113.10:60207".to_string()),
        socket_pool: Some("3".to_string()),
        mtu: Some(1420),
    }
}

async fn status_server_once(body: &'static str) -> String {
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
            if request.starts_with("GET /health ") {
                let response =
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
                stream.write_all(response.as_bytes()).await.unwrap();
            } else {
                let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        }
    });
    format!("http://{address}/status")
}

async fn health_ok_status_hangs_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 1024];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                if request.starts_with("GET /health ") {
                    let response =
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
                    stream.write_all(response.as_bytes()).await.unwrap();
                } else {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
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

fn spawn_sleep_child() -> Child {
    #[cfg(windows)]
    {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
            .spawn()
            .unwrap()
    }

    #[cfg(not(windows))]
    {
        Command::new("sleep").arg("30").spawn().unwrap()
    }
}

#[cfg(unix)]
fn spawn_daemon_named_child(bind_addr: &str) -> (tempfile::TempDir, Child) {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("p2wlan-daemon-test");
    std::fs::write(
            &script,
            "#!/bin/sh\ntrap 'kill \"$child\" 2>/dev/null' TERM EXIT\nsleep 30 &\nchild=$!\nwait \"$child\"\n",
        )
        .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let child = Command::new(&script)
        .args(["--diagnostics-bind", bind_addr])
        .spawn()
        .unwrap();
    (temp_dir, child)
}

#[test]
fn operation_phase_busy_states_are_explicit() {
    assert!(!DaemonOperationPhase::Stopped.is_busy());
    assert!(DaemonOperationPhase::Authorizing.is_busy());
    assert!(DaemonOperationPhase::Launching.is_busy());
    assert!(DaemonOperationPhase::WaitingForDaemon.is_busy());
    assert!(DaemonOperationPhase::Stopping.is_busy());
    assert!(!DaemonOperationPhase::Running.is_busy());
    assert!(!DaemonOperationPhase::Error.is_busy());
}

#[test]
fn operation_phase_busy_states_match_desktop_host_contract() {
    let pairs = [
        (
            DaemonOperationPhase::Stopped,
            p2wlan_desktop_host::DesktopHostPhase::Stopped,
        ),
        (
            DaemonOperationPhase::Authorizing,
            p2wlan_desktop_host::DesktopHostPhase::Authorizing,
        ),
        (
            DaemonOperationPhase::Launching,
            p2wlan_desktop_host::DesktopHostPhase::Launching,
        ),
        (
            DaemonOperationPhase::WaitingForDaemon,
            p2wlan_desktop_host::DesktopHostPhase::WaitingForDaemon,
        ),
        (
            DaemonOperationPhase::Running,
            p2wlan_desktop_host::DesktopHostPhase::Running,
        ),
        (
            DaemonOperationPhase::Stopping,
            p2wlan_desktop_host::DesktopHostPhase::Stopping,
        ),
        (
            DaemonOperationPhase::Error,
            p2wlan_desktop_host::DesktopHostPhase::Error,
        ),
    ];

    for (tauri_phase, host_phase) in pairs {
        assert_eq!(tauri_phase.is_busy(), host_phase.is_busy());
        assert_eq!(
            serde_json::to_value(tauri_phase).unwrap(),
            serde_json::to_value(host_phase).unwrap()
        );
    }
}

#[test]
fn persisted_endpoint_recovers_an_untracked_elevated_daemon() {
    let (url, recovered) = desktop_diagnostics_url(
        "http://127.0.0.1:39277/status".to_string(),
        false,
        Some("http://127.0.0.1:39277/status".to_string()),
        Some("http://127.0.0.1:39278/status".to_string()),
    );

    assert_eq!(url, "http://127.0.0.1:39278/status");
    assert!(recovered);
}

#[test]
fn tracked_daemon_keeps_its_selected_endpoint() {
    let (url, recovered) = desktop_diagnostics_url(
        "http://127.0.0.1:39278/status".to_string(),
        true,
        Some("http://127.0.0.1:39277/status".to_string()),
        Some("http://127.0.0.1:39279/status".to_string()),
    );

    assert_eq!(url, "http://127.0.0.1:39278/status");
    assert!(!recovered);
}

#[tokio::test]
async fn configure_updates_runtime_profile_without_persisting_to_disk() {
    let manager = DaemonManager::new();
    let diagnostics_url = unused_local_status_url();
    let operation = manager
        .configure(test_options(diagnostics_url.clone()))
        .await;

    assert_eq!(operation.phase, DaemonOperationPhase::Stopped);
    let state = manager.state.lock().await;
    assert_eq!(state.diagnostics_url, diagnostics_url);
    let options = state.last_start_options.as_ref().unwrap();
    assert_eq!(options.auth_token.as_deref(), Some("test-token"));
    assert_eq!(options.device_name.as_deref(), Some("test-device"));
}

#[tokio::test]
async fn wait_for_endpoint_down_accepts_an_unreachable_listener() {
    assert!(
        DaemonManager::wait_for_endpoint_down(
            &unused_local_status_url(),
            Duration::from_millis(100)
        )
        .await
    );
}

#[tokio::test]
async fn desktop_status_promotes_an_external_live_daemon_to_running() {
    let manager = DaemonManager::new();
    let url = status_server_once(r#"{"process_id":1234}"#).await;

    let status = manager.desktop_status(Some(url)).await;

    assert!(status.diagnostics.is_some());
    assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
    assert_eq!(status.operation.message, "TUN 已连接");
}

#[tokio::test]
async fn desktop_status_keeps_the_selected_port_while_daemon_is_running() {
    let manager = DaemonManager::new();
    let selected_url = status_server_once(r#"{"process_id":1234}"#).await;
    let stale_requested_url = unused_local_status_url();
    {
        let mut state = manager.state.lock().await;
        state.diagnostics_url = selected_url.clone();
        state.operation = DaemonOperationStatus {
            phase: DaemonOperationPhase::Running,
            message: "TUN 已连接".to_string(),
            started_at_ms: now_ms(),
            last_error: None,
        };
    }

    let status = manager.desktop_status(Some(stale_requested_url)).await;

    assert!(status.diagnostics.is_some());
    assert_eq!(status.diagnostics_url, selected_url);
}

#[tokio::test]
async fn desktop_status_keeps_running_when_health_is_alive_but_status_is_slow() {
    let manager = DaemonManager::new();
    manager
        .set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
        .await;
    let url = health_ok_status_hangs_server().await;
    manager.state.lock().await.diagnostics_url = url.clone();

    let status = manager.desktop_status(Some(url)).await;

    assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
    assert!(status.diagnostics_alive);
    assert!(status.diagnostics.is_none());
    assert!(!status.diagnostics_stale);
    assert!(status
        .diagnostics_error
        .as_deref()
        .unwrap_or_default()
        .contains("守护进程不可达"));
    assert_eq!(manager.state.lock().await.consecutive_status_failures, 0);
}

#[tokio::test]
async fn desktop_status_marks_cached_snapshot_stale_when_status_decode_fails() {
    let manager = DaemonManager::new();
    let cached = serde_json::json!({"node_id": "cached-node"});
    manager
        .set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
        .await;
    let url = status_server_once("not json").await;
    {
        let mut state = manager.state.lock().await;
        state.diagnostics_url = url.clone();
        state.last_diagnostics = Some(cached.clone());
    }

    let status = manager.desktop_status(Some(url)).await;

    assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
    assert!(status.diagnostics_alive);
    assert!(status.diagnostics_stale);
    assert_eq!(status.diagnostics, Some(cached));
    assert!(status
        .diagnostics_error
        .as_deref()
        .unwrap_or_default()
        .contains("解析守护进程状态失败"));
    assert_eq!(manager.state.lock().await.consecutive_status_failures, 0);
}

#[tokio::test]
async fn desktop_status_requires_three_failures_before_marking_running_daemon_error() {
    let manager = DaemonManager::new();
    manager
        .set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
        .await;
    let url = unused_local_status_url();
    manager.state.lock().await.diagnostics_url = url.clone();

    for expected_failures in 1..=2 {
        let status = manager.desktop_status(Some(url.clone())).await;
        assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
        assert!(!status.diagnostics_alive);
        assert!(!status.diagnostics_stale);
        assert_eq!(
            status.diagnostics_error.as_deref(),
            Some("本地健康检查端点不可访问")
        );
        assert_eq!(
            manager.state.lock().await.consecutive_status_failures,
            expected_failures
        );
    }

    let status = manager.desktop_status(Some(url)).await;
    assert_eq!(status.operation.phase, DaemonOperationPhase::Error);
    assert!(!status.diagnostics_alive);
    assert!(!status.diagnostics_stale);
    assert_eq!(
        status.diagnostics_error.as_deref(),
        Some("本地健康检查端点不可访问")
    );
    assert_eq!(
        status.operation.last_error.as_deref(),
        Some("连续 3 次无法访问本地健康检查端点")
    );
}

#[tokio::test]
async fn desktop_status_keeps_running_when_tracked_process_is_alive() {
    let manager = DaemonManager::new();
    let child = spawn_sleep_child();
    manager
        .set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
        .await;
    let url = unused_local_status_url();
    {
        let mut state = manager.state.lock().await;
        state.diagnostics_url = url.clone();
        state.started_by_app = true;
        state.child = Some(child);
    }

    for _ in 0..3 {
        let status = manager.desktop_status(Some(url.clone())).await;
        assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
        assert!(!status.diagnostics_alive);
        assert!(status
            .diagnostics_error
            .as_deref()
            .unwrap_or("")
            .contains("进程仍在运行"));
    }

    let mut state = manager.state.lock().await;
    if let Some(mut child) = state.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn desktop_status_rediscovers_daemon_by_diagnostics_bind() {
    let manager = DaemonManager::new();
    let url = unused_local_status_url();
    let bind_addr = DaemonManager::diagnostics_bind_from_url(&url);
    let (_temp_dir, mut child) = spawn_daemon_named_child(&bind_addr);
    manager
        .set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
        .await;
    manager.state.lock().await.diagnostics_url = url.clone();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let status = manager.desktop_status(Some(url)).await;

    assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
    assert!(manager.state.lock().await.elevated_started_by_app);

    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.wait();
}

#[test]
fn test_resolve_daemon_binary_priority() {
    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join(if cfg!(windows) {
        "p2wlan-daemon.exe"
    } else {
        "p2wlan-daemon"
    });
    std::fs::write(&fake_bin, "dummy binary").unwrap();

    // Check env var priority
    std::env::set_var("P2WLAN_DAEMON_BIN_TEST", fake_bin.to_str().unwrap());
    let resolved =
        DaemonManager::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN_TEST"), temp_dir.path());
    assert_eq!(resolved, Some(fake_bin.clone()));

    // Cleanup test env var
    std::env::remove_var("P2WLAN_DAEMON_BIN_TEST");
}

#[test]
fn test_diagnostics_url_parsing_logic() {
    assert_eq!(
        DaemonManager::diagnostics_bind_from_url("http://127.0.0.1:39277/status"),
        "127.0.0.1:39277"
    );
    assert_eq!(
        DaemonManager::diagnostics_bind_from_url("not a url"),
        "127.0.0.1:39277"
    );
    assert_eq!(
        DaemonManager::diagnostics_bind_from_url("http://127.0.0.1/status"),
        "127.0.0.1:39277"
    );
    assert_eq!(
        DaemonManager::diagnostics_bind_from_url("http://[::1]:39277/status"),
        "[::1]:39277"
    );
}

#[test]
fn diagnostics_helpers_match_desktop_host_for_loopback_urls() {
    for url in [
        "http://127.0.0.1:39277/status",
        "http://localhost:39278/status",
        "http://[::1]:39279/status",
    ] {
        assert_eq!(
            DaemonManager::diagnostics_bind_from_url(url),
            p2wlan_desktop_host::diagnostics_bind_from_url(url).unwrap()
        );
    }

    let normalized = p2wlan_desktop_host::normalize_diagnostics_url("http://localhost:39277")
        .expect("desktop-host should normalize a loopback diagnostics base URL");
    assert_eq!(normalized, "http://localhost:39277/status");
    assert_eq!(
        DaemonManager::diagnostics_bind_from_url(&normalized),
        p2wlan_desktop_host::diagnostics_bind_from_url(&normalized).unwrap()
    );

    let health_url =
        p2wlan_desktop_host::health_url_from_status_url("http://127.0.0.1:39277/status").unwrap();
    assert_eq!(health_url, "http://127.0.0.1:39277/health");

    assert!(DaemonManager::available_diagnostics_url("http://0.0.0.0:39277/status").is_err());
    assert!(p2wlan_desktop_host::normalize_diagnostics_url("http://0.0.0.0:39277/status").is_err());
}

#[test]
fn diagnostics_port_selection_keeps_a_free_preferred_port() {
    for _ in 0..16 {
        let preferred = unused_local_status_url();
        if DaemonManager::available_diagnostics_url(&preferred).unwrap() == preferred {
            return;
        }
    }
    panic!("could not observe an unclaimed preferred diagnostics port");
}

#[test]
fn diagnostics_port_selection_avoids_an_occupied_port() {
    let listener = (40_000..50_000)
        .find_map(|port| std::net::TcpListener::bind(("127.0.0.1", port)).ok())
        .expect("no test port available");
    let address = listener.local_addr().unwrap();
    let preferred = format!("http://{address}/status");

    let selected = DaemonManager::available_diagnostics_url(&preferred).unwrap();
    let selected_address = DaemonManager::diagnostics_socket_addr_from_url(&selected).unwrap();

    assert_ne!(selected, preferred);
    assert!(selected_address.port() > address.port());
    assert!(selected_address.port() - address.port() < DIAGNOSTICS_PORT_SCAN_LIMIT);
}

#[test]
fn diagnostics_port_selection_rejects_non_loopback_hosts() {
    let error =
        DaemonManager::available_diagnostics_url("http://0.0.0.0:39277/status").unwrap_err();
    assert!(error.contains("127.0.0.1"));
}

#[cfg(unix)]
#[test]
fn persist_diagnostics_url_recovers_from_stale_unwritable_marker() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let endpoint_path = temp_dir.path().join("p2wlan-daemon.endpoint");
    std::fs::write(&endpoint_path, "http://127.0.0.1:1/status").unwrap();
    std::fs::set_permissions(&endpoint_path, std::fs::Permissions::from_mode(0o444)).unwrap();

    DaemonManager::persist_diagnostics_url_to_path(&endpoint_path, "http://127.0.0.1:39277/status")
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(&endpoint_path).unwrap(),
        "http://127.0.0.1:39277/status"
    );
    let mode = std::fs::metadata(&endpoint_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_ne!(mode, 0o444);
}

#[test]
fn test_command_line_matches_daemon_bind() {
    assert!(DaemonManager::command_line_matches_daemon_bind(
        "/tmp/p2wlan-daemon --diagnostics-bind 127.0.0.1:39277 --control http://x",
        "127.0.0.1:39277"
    ));
    assert!(!DaemonManager::command_line_matches_daemon_bind(
        "/tmp/p2wlan-daemon --diagnostics-bind 127.0.0.1:39278",
        "127.0.0.1:39277"
    ));
    assert!(!DaemonManager::command_line_matches_daemon_bind(
        "/tmp/other --diagnostics-bind 127.0.0.1:39277",
        "127.0.0.1:39277"
    ));
}

#[test]
fn test_daemon_command_line_uses_expected_binary_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let expected = temp_dir
        .path()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "p2wlan-daemon.exe"
        } else {
            "p2wlan-daemon"
        });
    let installed = if cfg!(windows) {
        "C:\\Program Files\\p2wlan\\p2wlan-daemon.exe"
    } else {
        "/Applications/p2wlan.app/Contents/Resources/p2wlan-daemon"
    };

    assert!(DaemonManager::daemon_command_line_uses_binary(
        &format!("{} --diagnostics-bind 127.0.0.1:39277", expected.display()),
        &expected
    ));
    assert!(!DaemonManager::daemon_command_line_uses_binary(
        &format!("{installed} --diagnostics-bind 127.0.0.1:39277"),
        &expected
    ));
}

#[test]
fn test_default_config_path_uses_p2wlan_config_dir() {
    let path = DaemonManager::default_config_path();
    assert!(path.ends_with("p2wlan/p2wlan-config.json"));
}

#[test]
fn default_paths_match_desktop_host_layout() {
    let config_path = DaemonManager::default_config_path();
    assert_eq!(config_path, p2wlan_desktop_host::default_config_path());

    let log_dir = DaemonManager::default_log_dir();
    assert_eq!(log_dir, p2wlan_desktop_host::default_log_dir());
    assert_eq!(
        DaemonManager::default_pid_path(),
        p2wlan_desktop_host::pid_path_from_log_dir(&log_dir)
    );
    assert_eq!(
        DaemonManager::default_endpoint_path(),
        p2wlan_desktop_host::endpoint_path_from_log_dir(&log_dir)
    );
}

#[test]
fn test_daemon_start_options_deserialize_from_camel_case() {
    let json = serde_json::json!({
        "diagnosticsUrl": "http://127.0.0.1:39277/status",
        "controlServer": "http://127.0.0.1:8080",
        "authToken": "token",
        "networkId": "default",
        "deviceName": "mac",
        "tunInterface": "p2wlan0",
        "udpBind": "0.0.0.0:60207",
        "udpAdvertise": "203.0.113.10:60207",
        "socketPool": "3",
        "mtu": 1420
    });
    let options: DaemonStartOptions = serde_json::from_value(json).unwrap();
    assert_eq!(
        options.diagnostics_url.as_deref(),
        Some("http://127.0.0.1:39277/status")
    );
    assert_eq!(
        options.control_server.as_deref(),
        Some("http://127.0.0.1:8080")
    );
    assert_eq!(options.auth_token.as_deref(), Some("token"));
    assert_eq!(options.network_id.as_deref(), Some("default"));
    assert_eq!(options.device_name.as_deref(), Some("mac"));
    assert_eq!(options.tun_interface.as_deref(), Some("p2wlan0"));
    assert_eq!(options.udp_bind.as_deref(), Some("0.0.0.0:60207"));
    assert_eq!(options.udp_advertise.as_deref(), Some("203.0.113.10:60207"));
    assert_eq!(options.socket_pool.as_deref(), Some("3"));
    assert_eq!(options.mtu, Some(1420));
}

#[test]
fn start_options_deserialize_like_desktop_host_contract() {
    let json = serde_json::json!({
        "diagnosticsUrl": "http://127.0.0.1:39277/status",
        "controlServer": "http://127.0.0.1:8080",
        "authToken": "token",
        "networkId": "default",
        "deviceName": "mac",
        "tunInterface": "p2wlan0",
        "udpBind": "0.0.0.0:60207",
        "udpAdvertise": "203.0.113.10:60207",
        "socketPool": "3",
        "mtu": 1420
    });
    let tauri_options: DaemonStartOptions = serde_json::from_value(json.clone()).unwrap();
    let host_options: p2wlan_desktop_host::DesktopHostStartOptions =
        serde_json::from_value(json.clone()).unwrap();

    assert_eq!(tauri_options.diagnostics_url, host_options.diagnostics_url);
    assert_eq!(tauri_options.control_server, host_options.control_server);
    assert_eq!(tauri_options.auth_token, host_options.auth_token);
    assert_eq!(tauri_options.network_id, host_options.network_id);
    assert_eq!(tauri_options.device_name, host_options.device_name);
    assert_eq!(tauri_options.tun_interface, host_options.tun_interface);
    assert_eq!(tauri_options.udp_bind, host_options.udp_bind);
    assert_eq!(tauri_options.udp_advertise, host_options.udp_advertise);
    assert_eq!(tauri_options.socket_pool, host_options.socket_pool);
    assert_eq!(tauri_options.mtu, host_options.mtu);
    assert_eq!(serde_json::to_value(host_options).unwrap(), json);
}

#[test]
fn desktop_status_serializes_external_command_contract() {
    let status = DesktopStatus {
        operation: DaemonOperationStatus {
            phase: DaemonOperationPhase::Running,
            message: "TUN 已连接".to_string(),
            started_at_ms: 42,
            last_error: None,
        },
        diagnostics: Some(serde_json::json!({"node_id": "node-1"})),
        diagnostics_url: "http://127.0.0.1:39277/status".to_string(),
        diagnostics_alive: true,
        diagnostics_stale: false,
        diagnostics_error: None,
    };

    assert_eq!(
        serde_json::to_value(status).unwrap(),
        serde_json::json!({
            "operation": {
                "phase": "running",
                "message": "TUN 已连接",
                "startedAtMs": 42,
                "lastError": null
            },
            "diagnostics": {"node_id": "node-1"},
            "diagnosticsUrl": "http://127.0.0.1:39277/status",
            "diagnosticsAlive": true,
            "diagnosticsStale": false,
            "diagnosticsError": null
        })
    );
}

#[test]
fn desktop_status_json_keys_match_desktop_host_contract() {
    let tauri_status = DesktopStatus {
        operation: DaemonOperationStatus {
            phase: DaemonOperationPhase::Running,
            message: "TUN 已连接".to_string(),
            started_at_ms: 42,
            last_error: Some("last".to_string()),
        },
        diagnostics: Some(serde_json::json!({"node_id": "node-1"})),
        diagnostics_url: "http://127.0.0.1:39277/status".to_string(),
        diagnostics_alive: true,
        diagnostics_stale: true,
        diagnostics_error: Some("status decode failed".to_string()),
    };
    let host_status = p2wlan_desktop_host::DesktopHostStatus {
        operation: p2wlan_desktop_host::DesktopHostOperation {
            phase: p2wlan_desktop_host::DesktopHostPhase::Running,
            message: "TUN 已连接".to_string(),
            started_at_ms: 42,
            last_error: Some("last".to_string()),
        },
        diagnostics: Some(serde_json::json!({"node_id": "node-1"})),
        diagnostics_url: "http://127.0.0.1:39277/status".to_string(),
        diagnostics_alive: true,
        diagnostics_stale: true,
        diagnostics_error: Some("status decode failed".to_string()),
    };

    assert_eq!(
        serde_json::to_value(tauri_status).unwrap(),
        serde_json::to_value(host_status).unwrap()
    );
}

#[test]
fn test_daemon_start_args_include_udp_direct_options() {
    let options = test_options("http://127.0.0.1:39277/status".to_string());
    let args = DaemonManager::build_args(
        &options,
        "127.0.0.1:39277",
        Path::new("/tmp/p2wlan-config.json"),
    );
    assert!(args
        .windows(2)
        .any(|pair| pair == ["--udp-bind", "0.0.0.0:60207"]));
    assert!(args
        .windows(2)
        .any(|pair| pair == ["--udp-advertise", "203.0.113.10:60207"]));
    assert!(args.windows(2).any(|pair| pair == ["--socket-pool", "3"]));
    assert!(args.iter().any(|arg| arg == "--managed"));
}

#[test]
fn test_windows_command_line_arg_quote() {
    assert_eq!(
        DaemonManager::windows_command_line_arg_quote("simple"),
        "simple"
    );
    assert_eq!(
        DaemonManager::windows_command_line_arg_quote(r#"C:\Program Files\p2wlan\daemon.exe"#),
        r#""C:\Program Files\p2wlan\daemon.exe""#
    );
    assert_eq!(
        DaemonManager::windows_command_line_arg_quote(r#"name"with quote"#),
        r#""name\"with quote""#
    );
    assert_eq!(
        DaemonManager::windows_command_line_arg_quote(r#"C:\path\"#),
        r#"C:\path\"#
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_elevated_shell_does_not_use_nohup() {
    let bin_path = PathBuf::from("/tmp/p2 wlan/p2wlan-daemon");
    let config_path = PathBuf::from("/tmp/p2 wlan/config/p2wlan-config.json");
    let log_dir = PathBuf::from("/tmp/p2 wlan/logs");
    let log_path = log_dir.join("p2wlan-daemon.log");
    let args = vec![
        "--config".to_string(),
        config_path.display().to_string(),
        "--token".to_string(),
        "tok'en".to_string(),
    ];
    let shell = DaemonManager::build_macos_elevated_shell(
        &bin_path,
        &args,
        &config_path,
        &log_dir,
        &log_path,
        &log_dir.join("p2wlan-daemon.pid"),
    );
    assert!(!shell.contains("nohup"));
    assert!(shell.contains("< /dev/null &"));
    assert!(shell.contains("P2WLAN_DAEMON_BIN='/tmp/p2 wlan/p2wlan-daemon'"));
    assert!(shell.contains("'tok'\\''en'"));
}
