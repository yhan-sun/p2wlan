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
