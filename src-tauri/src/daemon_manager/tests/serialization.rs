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
