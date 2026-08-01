use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

const DIAGNOSTICS_PORT_SCAN_LIMIT: u16 = 32;
/// A cold elevated start may need to create the TUN device, collect STUN
/// candidates, and reconnect the control plane before diagnostics is ready.
/// Keep this aligned with the desktop UI's elevated-start outcome window.
#[cfg(target_os = "macos")]
const MACOS_ELEVATED_READY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonStartOptions {
    pub diagnostics_url: Option<String>,
    pub control_server: Option<String>,
    pub auth_token: Option<String>,
    pub network_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_interface: Option<String>,
    pub udp_bind: Option<String>,
    pub udp_advertise: Option<String>,
    pub socket_pool: Option<String>,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonOperationPhase {
    Stopped,
    Authorizing,
    Launching,
    WaitingForDaemon,
    Running,
    Stopping,
    Error,
}

impl DaemonOperationPhase {
    pub fn is_busy(self) -> bool {
        matches!(
            self,
            Self::Authorizing | Self::Launching | Self::WaitingForDaemon | Self::Stopping
        )
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonOperationStatus {
    pub phase: DaemonOperationPhase,
    pub message: String,
    pub started_at_ms: u64,
    pub last_error: Option<String>,
}

impl DaemonOperationStatus {
    fn stopped() -> Self {
        Self {
            phase: DaemonOperationPhase::Stopped,
            message: "TUN 未启动".to_string(),
            started_at_ms: now_ms(),
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStatus {
    pub operation: DaemonOperationStatus,
    pub diagnostics: Option<serde_json::Value>,
    pub diagnostics_url: String,
    pub diagnostics_alive: bool,
    pub diagnostics_stale: bool,
    pub diagnostics_error: Option<String>,
}

pub struct ManagedDaemonState {
    pub child: Option<Child>,
    pub started_by_app: bool,
    pub elevated_started_by_app: bool,
    pub diagnostics_url: String,
    pub last_error: Option<String>,
    pub operation: DaemonOperationStatus,
    pub last_start_options: Option<DaemonStartOptions>,
    pub consecutive_status_failures: u8,
    pub last_diagnostics: Option<serde_json::Value>,
}

impl ManagedDaemonState {
    pub fn new() -> Self {
        Self {
            child: None,
            started_by_app: false,
            elevated_started_by_app: false,
            diagnostics_url: "http://127.0.0.1:39277/status".to_string(),
            last_error: None,
            operation: DaemonOperationStatus::stopped(),
            last_start_options: None,
            consecutive_status_failures: 0,
            last_diagnostics: None,
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

/// Choose the endpoint the desktop shell should poll. An elevated macOS
/// daemon can outlive the desktop process, while its PID marker may be
/// missing (for example after a manual restart). In that case the persisted
/// endpoint remains the authoritative way to rediscover the live daemon.
fn desktop_diagnostics_url(
    state_url: String,
    tracks_daemon: bool,
    requested_url: Option<String>,
    persisted_url: Option<String>,
) -> (String, bool) {
    if tracks_daemon {
        return (state_url, false);
    }
    if let Some(url) = persisted_url {
        return (url, true);
    }
    (requested_url.unwrap_or(state_url), false)
}

#[derive(Clone)]
pub struct DaemonManager {
    state: Arc<Mutex<ManagedDaemonState>>,
}

mod files;
mod launch_args;
mod lifecycle;
mod process;
mod start;
mod startup_wait;
mod status;
mod stop;

#[cfg(target_os = "windows")]
fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("unix:{secs}")
}

#[cfg(test)]
#[path = "daemon_manager/tests.rs"]
mod tests;
