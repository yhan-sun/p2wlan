use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

use crate::daemon_manager::{DaemonOperationPhase, DesktopStatus};

#[derive(Debug, PartialEq, Eq)]
struct TrayPresentation {
    status_label: &'static str,
    virtual_ip: String,
    online: Option<u64>,
    running: bool,
    busy: bool,
    title: &'static str,
}

pub fn exit_app(app_handle: &AppHandle) {
    app_handle.exit(0);
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(900));
        std::process::exit(0);
    });
}

pub fn create_tray(app: &AppHandle) -> tauri::Result<TrayIcon> {
    let status = MenuItem::with_id(app, "status", "状态：未启动", false, None::<&str>)?;
    let network = MenuItem::with_id(
        app,
        "network",
        "虚拟 IP：— · 在线设备：—",
        false,
        None::<&str>,
    )?;
    let show = MenuItem::with_id(app, "show", "打开控制台", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "启动 TUN", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "停止 TUN", false, None::<&str>)?;
    let open_logs = MenuItem::with_id(app, "open_logs", "打开日志", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出 p2wlan", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &status,
            &network,
            &show,
            &connect,
            &disconnect,
            &open_logs,
            &quit,
        ],
    )?;

    let app_icon = app
        .default_window_icon()
        .ok_or_else(|| tauri::Error::FailedToReceiveMessage)?;
    let tray_icon = tauri::image::Image::new(app_icon.rgba(), app_icon.width(), app_icon.height());

    let tray = TrayIconBuilder::with_id("p2wlan_tray")
        .tooltip("p2wlan：未启动")
        .icon(tray_icon)
        .menu(&menu)
        .on_menu_event(
            |app_handle: &tauri::AppHandle, event| match event.id.as_ref() {
                "show" => show_main_window(app_handle),
                "connect" => {
                    if let Some(state) = app_handle.try_state::<crate::AppState>() {
                        let daemon_manager = state.daemon_manager.clone();
                        let app = app_handle.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(error) = daemon_manager.begin_start_elevated(None).await {
                                log::error!("Failed to start daemon via tray: {error}");
                                show_main_window(&app);
                            }
                        });
                    }
                }
                "disconnect" => {
                    if let Some(state) = app_handle.try_state::<crate::AppState>() {
                        let daemon_manager = state.daemon_manager.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(error) = daemon_manager.begin_stop(None).await {
                                log::error!("Failed to stop daemon via tray: {error}");
                            }
                        });
                    }
                }
                "open_logs" => {
                    if let Err(error) = crate::open_logs() {
                        log::error!("Failed to open logs via tray: {error}");
                    }
                }
                "quit" => {
                    let app = app_handle.clone();
                    if let Some(state) = app_handle.try_state::<crate::AppState>() {
                        let daemon_manager = state.daemon_manager.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(error) = daemon_manager.stop(None).await {
                                log::error!("Failed to stop daemon before tray quit: {error}");
                            }
                            exit_app(&app);
                        });
                    } else {
                        exit_app(app_handle);
                    }
                }
                _ => {}
            },
        )
        .on_tray_icon_event(|tray: &tauri::tray::TrayIcon, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    let monitor_tray = tray.clone();
    let monitor_status = status.clone();
    let monitor_network = network.clone();
    let monitor_connect = connect.clone();
    let monitor_disconnect = disconnect.clone();
    let monitor_app = app.clone();
    let daemon_manager = app.state::<crate::AppState>().daemon_manager.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let snapshot = daemon_manager.desktop_status(None).await;
            update_tray(
                &monitor_tray,
                &monitor_status,
                &monitor_network,
                &monitor_connect,
                &monitor_disconnect,
                &snapshot,
            );
            let _ = monitor_app.emit("p2wlan-status", snapshot.clone());

            let interval = if snapshot.operation.phase.is_busy() {
                std::time::Duration::from_millis(500)
            } else if snapshot.diagnostics.is_some() {
                std::time::Duration::from_secs(2)
            } else {
                std::time::Duration::from_secs(5)
            };
            tokio::time::sleep(interval).await;
        }
    });

    Ok(tray)
}

fn show_main_window(app_handle: &AppHandle) {
    if let Some(window) = app_handle.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn update_tray(
    tray: &TrayIcon,
    status_item: &MenuItem<tauri::Wry>,
    network_item: &MenuItem<tauri::Wry>,
    connect_item: &MenuItem<tauri::Wry>,
    disconnect_item: &MenuItem<tauri::Wry>,
    snapshot: &DesktopStatus,
) {
    let presentation = tray_presentation(snapshot);
    let _ = status_item.set_text(format!("状态：{}", presentation.status_label));
    let _ = network_item.set_text(match presentation.online {
        Some(count) => format!("虚拟 IP：{} · 在线设备：{count}", presentation.virtual_ip),
        None => "虚拟 IP：— · 在线设备：—".to_string(),
    });
    let _ = connect_item.set_enabled(!presentation.busy && !presentation.running);
    let _ = disconnect_item.set_enabled(presentation.running);
    let _ = tray.set_tooltip(Some(match presentation.online {
        Some(count) => format!(
            "p2wlan：{} · {} · {count} 台在线",
            presentation.status_label, presentation.virtual_ip
        ),
        None => format!("p2wlan：{}", presentation.status_label),
    }));
    let _ = tray.set_title(Some(presentation.title));
}

fn tray_presentation(snapshot: &DesktopStatus) -> TrayPresentation {
    let phase = snapshot.operation.phase;
    let status_label = match phase {
        DaemonOperationPhase::Stopped => "未启动",
        DaemonOperationPhase::Authorizing => "等待系统授权",
        DaemonOperationPhase::Launching => "正在启动",
        DaemonOperationPhase::WaitingForDaemon => "正在建立虚拟网络",
        DaemonOperationPhase::Running => "已连接",
        DaemonOperationPhase::Stopping => "正在停止",
        DaemonOperationPhase::Error => "异常",
    };
    let virtual_ip = snapshot
        .diagnostics
        .as_ref()
        .and_then(|value| value.get("virtual_ip"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("—")
        .to_string();
    let online = snapshot
        .diagnostics
        .as_ref()
        .and_then(|value| value.get("stats"))
        .map(|stats| {
            stats
                .get("direct_connections")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default()
                + stats
                    .get("relay_connections")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
        });
    let title = match phase {
        DaemonOperationPhase::Running => "●",
        DaemonOperationPhase::Authorizing
        | DaemonOperationPhase::Launching
        | DaemonOperationPhase::WaitingForDaemon
        | DaemonOperationPhase::Stopping => "…",
        DaemonOperationPhase::Error => "!",
        DaemonOperationPhase::Stopped => "",
    };

    TrayPresentation {
        status_label,
        virtual_ip,
        online,
        running: snapshot.diagnostics.is_some() && phase == DaemonOperationPhase::Running,
        busy: phase.is_busy(),
        title,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_manager::DaemonOperationStatus;

    fn snapshot(
        phase: DaemonOperationPhase,
        diagnostics: Option<serde_json::Value>,
    ) -> DesktopStatus {
        DesktopStatus {
            operation: DaemonOperationStatus {
                phase,
                message: "test".to_string(),
                started_at_ms: 1,
                last_error: None,
            },
            diagnostics,
        }
    }

    #[test]
    fn running_tray_presentation_includes_network_state() {
        let presentation = tray_presentation(&snapshot(
            DaemonOperationPhase::Running,
            Some(serde_json::json!({
                "virtual_ip": "10.20.0.5",
                "stats": {
                    "direct_connections": 2,
                    "relay_connections": 1
                }
            })),
        ));

        assert_eq!(presentation.status_label, "已连接");
        assert_eq!(presentation.virtual_ip, "10.20.0.5");
        assert_eq!(presentation.online, Some(3));
        assert!(presentation.running);
        assert!(!presentation.busy);
        assert_eq!(presentation.title, "●");
    }

    #[test]
    fn transitional_tray_presentation_disables_conflicting_actions() {
        let presentation = tray_presentation(&snapshot(DaemonOperationPhase::Authorizing, None));

        assert_eq!(presentation.status_label, "等待系统授权");
        assert_eq!(presentation.online, None);
        assert!(!presentation.running);
        assert!(presentation.busy);
        assert_eq!(presentation.title, "…");
    }
}
