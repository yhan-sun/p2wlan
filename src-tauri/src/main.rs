// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod control_auth;
mod daemon_manager;
mod permissions;
mod tray;

use control_auth::{ControlAuthRequest, ControlAuthSession};
use daemon_manager::{DaemonManager, DaemonOperationStatus, DaemonStartOptions, DesktopStatus};
use std::path::PathBuf;
use tauri::{Manager, State};

pub struct AppState {
    pub daemon_manager: DaemonManager,
}

#[tauri::command]
fn permission_status() -> Result<permissions::PermissionStatus, String> {
    Ok(permissions::check_permission_status())
}

#[tauri::command]
async fn daemon_status(
    state: State<'_, AppState>,
    diagnostics_url: Option<String>,
) -> Result<serde_json::Value, String> {
    state.daemon_manager.status(diagnostics_url).await
}

#[tauri::command]
async fn desktop_status(
    state: State<'_, AppState>,
    diagnostics_url: Option<String>,
) -> Result<DesktopStatus, String> {
    Ok(state.daemon_manager.desktop_status(diagnostics_url).await)
}

#[tauri::command]
async fn daemon_configure(
    state: State<'_, AppState>,
    options: DaemonStartOptions,
) -> Result<DaemonOperationStatus, String> {
    Ok(state.daemon_manager.configure(options).await)
}

#[tauri::command]
async fn daemon_start(
    state: State<'_, AppState>,
    options: Option<DaemonStartOptions>,
) -> Result<String, String> {
    state.daemon_manager.start(options).await
}

#[tauri::command]
async fn daemon_start_elevated(
    state: State<'_, AppState>,
    options: Option<DaemonStartOptions>,
) -> Result<DaemonOperationStatus, String> {
    state.daemon_manager.begin_start_elevated(options).await
}

#[tauri::command]
async fn daemon_stop(
    state: State<'_, AppState>,
    diagnostics_url: Option<String>,
) -> Result<DaemonOperationStatus, String> {
    state.daemon_manager.begin_stop(diagnostics_url).await
}

#[tauri::command]
async fn control_authenticate(request: ControlAuthRequest) -> Result<ControlAuthSession, String> {
    control_auth::authenticate(request).await
}

#[tauri::command]
fn open_logs() -> Result<String, String> {
    // Determine log directory:
    // macOS: ~/Library/Logs/p2wlan
    // Linux: ~/.p2wlan/logs
    // Windows: %LOCALAPPDATA%/p2wlan/logs
    let log_dir = if cfg!(target_os = "macos") {
        dirs::home_dir()
            .map(|h| h.join("Library").join("Logs").join("p2wlan"))
            .ok_or_else(|| "无法定位 macOS 日志目录".to_string())?
    } else if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .map(|l| PathBuf::from(l).join("p2wlan").join("logs"))
            .map_err(|_| "无法读取 Windows LOCALAPPDATA 环境变量".to_string())?
    } else {
        dirs::home_dir()
            .map(|h| h.join(".p2wlan").join("logs"))
            .ok_or_else(|| "无法定位用户主目录".to_string())?
    };

    if !log_dir.exists() {
        std::fs::create_dir_all(&log_dir).map_err(|e| {
            format!(
                "Failed to create log directory {}: {}",
                log_dir.display(),
                e
            )
        })?;
    }

    // Open path using platform command
    let open_result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(&log_dir).spawn()
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("explorer").arg(&log_dir).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(&log_dir).spawn()
    };

    open_result
        .map(|_| format!("已打开日志目录：{}", log_dir.display()))
        .map_err(|e| format!("打开日志目录失败：{}", e))
}

#[tauri::command]
fn daemon_log_tail(max_lines: Option<usize>) -> Vec<String> {
    DaemonManager::recent_daemon_log_lines(max_lines.unwrap_or(120).min(300))
}

#[tauri::command]
async fn app_quit(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    diagnostics_url: Option<String>,
) -> Result<String, String> {
    let daemon_manager = state.daemon_manager.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = daemon_manager.stop(diagnostics_url).await {
            log::error!("Failed to stop daemon while quitting: {error}");
        }
        tray::exit_app(&app);
    });
    Ok("正在停止 TUN 并退出 p2wlan。".to_string())
}

#[tauri::command]
fn window_chrome_ready(_app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    if let Some(window) = _app.get_webview_window("main") {
        window
            .set_decorations(false)
            .map_err(|error| format!("无法隐藏系统标题栏：{error}"))?;
    }
    Ok(())
}

fn main() {
    let daemon_manager = DaemonManager::new();
    let app_state = AppState { daemon_manager };

    let app = tauri::Builder::default()
        .manage(app_state)
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            // Create native tray. Fail the app startup if this cannot be installed,
            // otherwise the desktop shell would silently lose its primary control path.
            tray::create_tray(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            daemon_status,
            desktop_status,
            daemon_configure,
            daemon_start,
            daemon_start_elevated,
            daemon_stop,
            control_authenticate,
            open_logs,
            daemon_log_tail,
            permission_status,
            app_quit,
            window_chrome_ready
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(state) = app_handle.try_state::<AppState>() {
                state.daemon_manager.cleanup();
            }
        }
    });
}
