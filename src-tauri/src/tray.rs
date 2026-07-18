use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

pub fn create_tray(app: &AppHandle) -> tauri::Result<TrayIcon> {
    // 1. Build menu items
    let show = MenuItem::with_id(app, "show", "打开控制台", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "启动 TUN", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "停止 TUN", true, None::<&str>)?;
    let open_logs = MenuItem::with_id(app, "open_logs", "打开日志", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出 p2wlan", true, None::<&str>)?;

    // 2. Combine into a menu
    let menu = Menu::with_items(app, &[&show, &connect, &disconnect, &open_logs, &quit])?;

    // 3. Build Tray icon
    let js_img = app
        .default_window_icon()
        .ok_or_else(|| tauri::Error::FailedToReceiveMessage)?; // use a standard error variant
    let tray_icon = tauri::image::Image::new(js_img.rgba(), js_img.width(), js_img.height());

    TrayIconBuilder::with_id("p2wlan_tray")
        .tooltip("p2wlan 控制台")
        .icon(tray_icon)
        .menu(&menu)
        .on_menu_event(|app_handle: &tauri::AppHandle, event| {
            let id = event.id.as_ref();
            match id {
                "show" => {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "connect" => {
                    if let Some(state) = app_handle.try_state::<crate::AppState>() {
                        let daemon_manager = &state.daemon_manager;
                        let daemon_manager = daemon_manager.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(e) = daemon_manager.start(None).await {
                                log::error!("Failed to start daemon via tray connect: {}", e);
                            }
                        });
                    }
                }
                "disconnect" => {
                    if let Some(state) = app_handle.try_state::<crate::AppState>() {
                        let daemon_manager = &state.daemon_manager;
                        let daemon_manager = daemon_manager.clone();
                        tauri::async_runtime::spawn(async move {
                            if let Err(e) = daemon_manager.stop(None).await {
                                log::error!("Failed to stop daemon via tray disconnect: {}", e);
                            }
                        });
                    }
                }
                "open_logs" => {
                    if let Err(e) = crate::open_logs() {
                        log::error!("Failed to open logs via tray menu: {}", e);
                    }
                }
                "quit" => {
                    if let Some(state) = app_handle.try_state::<crate::AppState>() {
                        state.daemon_manager.cleanup();
                    }
                    app_handle.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray: &tauri::tray::TrayIcon, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app_handle = tray.app_handle();
                if let Some(window) = app_handle.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)
}
