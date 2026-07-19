use std::net::IpAddr;

#[cfg(target_os = "macos")]
use tauri::menu::{IconMenuItem, NativeIcon};
use tauri::{
    menu::{Menu, MenuItem, Submenu},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

use crate::daemon_manager::{DaemonOperationPhase, DesktopStatus};

const COPY_PEER_IP_PREFIX: &str = "copy_peer_ip:";
const MAX_TRAY_DEVICES: usize = 12;

#[derive(Debug, PartialEq, Eq)]
struct TrayPresentation {
    status_label: &'static str,
    virtual_ip: String,
    online: Option<u64>,
    running: bool,
    busy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayDevice {
    node_id: String,
    name: String,
    virtual_ip: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrayDeviceMenu {
    devices: Vec<TrayDevice>,
    total: usize,
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
    let no_devices = MenuItem::with_id(app, "no_devices", "暂无在线设备", false, None::<&str>)?;
    let devices = Submenu::with_id_and_items(app, "devices", "设备", true, &[&no_devices])?;
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
            &devices,
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
                id => {
                    if let Some(ip) = copy_ip_from_menu_id(id) {
                        if let Err(error) = copy_ip(ip) {
                            log::error!("Failed to copy peer IP from tray: {error}");
                        }
                    }
                }
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
    let monitor_devices = devices.clone();
    let monitor_app = app.clone();
    let daemon_manager = app.state::<crate::AppState>().daemon_manager.clone();
    tauri::async_runtime::spawn(async move {
        let mut previous_devices = None;
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

            let device_menu = tray_device_menu(&snapshot);
            if previous_devices.as_ref() != Some(&device_menu) {
                match rebuild_device_menu(&monitor_app, &monitor_devices, &device_menu) {
                    Ok(()) => previous_devices = Some(device_menu),
                    Err(error) => log::error!("Failed to update tray device menu: {error}"),
                }
            }
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
    TrayPresentation {
        status_label,
        virtual_ip,
        online,
        running: snapshot.diagnostics.is_some() && phase == DaemonOperationPhase::Running,
        busy: phase.is_busy(),
    }
}

fn tray_device_menu(snapshot: &DesktopStatus) -> TrayDeviceMenu {
    let Some(peers) = snapshot
        .diagnostics
        .as_ref()
        .and_then(|diagnostics| diagnostics.get("peers"))
        .and_then(serde_json::Value::as_array)
    else {
        return TrayDeviceMenu::default();
    };

    let mut devices = peers
        .iter()
        .filter_map(|peer| {
            let virtual_ip = peer.get("virtual_ip").and_then(serde_json::Value::as_str)?;
            virtual_ip.parse::<IpAddr>().ok()?;

            let node_id = peer
                .get("node_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let device_name = peer
                .get("device_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();

            Some(TrayDevice {
                node_id: node_id.to_string(),
                name: display_device_name(device_name, node_id),
                virtual_ip: virtual_ip.to_string(),
            })
        })
        .collect::<Vec<_>>();

    devices.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.virtual_ip.cmp(&right.virtual_ip))
    });
    devices.dedup_by(|left, right| left.virtual_ip == right.virtual_ip);

    let total = devices.len();
    devices.truncate(MAX_TRAY_DEVICES);
    TrayDeviceMenu { devices, total }
}

fn display_device_name(device_name: &str, node_id: &str) -> String {
    let normalized = device_name.split_whitespace().collect::<Vec<_>>().join(" ");
    let fallback = if node_id.is_empty() {
        "未知设备".to_string()
    } else {
        node_id.chars().take(12).collect()
    };
    let name = if normalized.is_empty() {
        fallback
    } else {
        normalized
    };

    let mut chars = name.chars();
    let visible = chars.by_ref().take(28).collect::<String>();
    if chars.next().is_some() {
        format!("{visible}…")
    } else {
        visible
    }
}

fn rebuild_device_menu(
    app: &AppHandle,
    submenu: &Submenu<tauri::Wry>,
    device_menu: &TrayDeviceMenu,
) -> tauri::Result<()> {
    while !submenu.items()?.is_empty() {
        submenu.remove_at(0)?;
    }

    submenu.set_text(format!("设备（{}）", device_menu.total))?;
    if device_menu.devices.is_empty() {
        let empty = MenuItem::with_id(app, "no_devices", "暂无在线设备", false, None::<&str>)?;
        return submenu.append(&empty);
    }

    for device in &device_menu.devices {
        append_device_item(app, submenu, device)?;
    }

    if device_menu.total > device_menu.devices.len() {
        let remaining = device_menu.total - device_menu.devices.len();
        let overflow = MenuItem::with_id(
            app,
            "more_devices",
            format!("另有 {remaining} 台设备，请在控制台查看"),
            false,
            None::<&str>,
        )?;
        submenu.append(&overflow)?;
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn append_device_item(
    app: &AppHandle,
    submenu: &Submenu<tauri::Wry>,
    device: &TrayDevice,
) -> tauri::Result<()> {
    let item = IconMenuItem::with_id_and_native_icon(
        app,
        format!("{COPY_PEER_IP_PREFIX}{}", device.virtual_ip),
        format!("{} · {}", device.name, device.virtual_ip),
        true,
        Some(NativeIcon::MultipleDocuments),
        None::<&str>,
    )?;
    submenu.append(&item)
}

#[cfg(not(target_os = "macos"))]
fn append_device_item(
    app: &AppHandle,
    submenu: &Submenu<tauri::Wry>,
    device: &TrayDevice,
) -> tauri::Result<()> {
    let item = MenuItem::with_id(
        app,
        format!("{COPY_PEER_IP_PREFIX}{}", device.virtual_ip),
        format!("复制 {} · {}", device.name, device.virtual_ip),
        true,
        None::<&str>,
    )?;
    submenu.append(&item)
}

fn copy_ip_from_menu_id(id: &str) -> Option<&str> {
    let ip = id.strip_prefix(COPY_PEER_IP_PREFIX)?;
    ip.parse::<IpAddr>().ok().map(|_| ip)
}

fn copy_ip(ip: &str) -> Result<(), String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|error| error.to_string())?;
    clipboard
        .set_text(ip.to_string())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_manager::DaemonOperationStatus;

    fn snapshot(
        phase: DaemonOperationPhase,
        diagnostics: Option<serde_json::Value>,
    ) -> DesktopStatus {
        let diagnostics_alive = diagnostics.is_some();
        DesktopStatus {
            operation: DaemonOperationStatus {
                phase,
                message: "test".to_string(),
                started_at_ms: 1,
                last_error: None,
            },
            diagnostics,
            diagnostics_url: "http://127.0.0.1:39277/status".to_string(),
            diagnostics_alive,
            diagnostics_stale: false,
            diagnostics_error: None,
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
    }

    #[test]
    fn transitional_tray_presentation_disables_conflicting_actions() {
        let presentation = tray_presentation(&snapshot(DaemonOperationPhase::Authorizing, None));

        assert_eq!(presentation.status_label, "等待系统授权");
        assert_eq!(presentation.online, None);
        assert!(!presentation.running);
        assert!(presentation.busy);
    }

    #[test]
    fn tray_device_menu_uses_device_name_and_falls_back_to_node_id() {
        let menu = tray_device_menu(&snapshot(
            DaemonOperationPhase::Running,
            Some(serde_json::json!({
                "peers": [
                    {
                        "node_id": "node-b-123456789",
                        "device_name": "Office Mac",
                        "virtual_ip": "10.20.0.5"
                    },
                    {
                        "node_id": "node-a-123456789",
                        "virtual_ip": "10.20.0.3"
                    }
                ]
            })),
        ));

        assert_eq!(menu.total, 2);
        assert_eq!(menu.devices[0].name, "node-a-12345");
        assert_eq!(menu.devices[1].name, "Office Mac");
    }

    #[test]
    fn copy_menu_id_only_accepts_ip_addresses() {
        assert_eq!(
            copy_ip_from_menu_id("copy_peer_ip:10.20.0.5"),
            Some("10.20.0.5")
        );
        assert_eq!(copy_ip_from_menu_id("copy_peer_ip:not-an-ip"), None);
        assert_eq!(copy_ip_from_menu_id("quit"), None);
    }
}
