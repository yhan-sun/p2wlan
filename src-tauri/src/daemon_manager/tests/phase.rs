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
