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
