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

impl DaemonManager {
    pub fn new() -> Self {
        #[cfg(test)]
        let managed_state = ManagedDaemonState::new();
        #[cfg(not(test))]
        let managed_state = {
            let mut managed_state = ManagedDaemonState::new();
            let pid_path = Self::default_pid_path();
            if let Some(url) = Self::read_persisted_diagnostics_url() {
                // Do not require the PID marker here. Root-owned daemon
                // launches can lose that marker while the health endpoint is
                // still live on a non-default port.
                managed_state.diagnostics_url = url;
            }
            if let Some(pid) = Self::read_pid_file(&pid_path) {
                let is_daemon = Self::process_exists(pid)
                    && Self::process_command_line(pid)
                        .map(|command_line| command_line.contains("p2wlan-daemon"))
                        .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
                if is_daemon {
                    if Self::read_persisted_diagnostics_url().is_some() {
                        managed_state.elevated_started_by_app = true;
                        managed_state.operation = DaemonOperationStatus {
                            phase: DaemonOperationPhase::Running,
                            message: "检测到后台 TUN".to_string(),
                            started_at_ms: now_ms(),
                            last_error: None,
                        };
                    }
                } else {
                    Self::remove_pid_file(&pid_path);
                    Self::remove_persisted_diagnostics_url();
                }
            }
            managed_state
        };
        Self {
            state: Arc::new(Mutex::new(managed_state)),
        }
    }

    async fn set_operation(
        &self,
        phase: DaemonOperationPhase,
        message: impl Into<String>,
        last_error: Option<String>,
    ) -> DaemonOperationStatus {
        let mut state = self.state.lock().await;
        state.operation = DaemonOperationStatus {
            phase,
            message: message.into(),
            started_at_ms: now_ms(),
            last_error,
        };
        if matches!(
            phase,
            DaemonOperationPhase::Running | DaemonOperationPhase::Stopped
        ) {
            state.consecutive_status_failures = 0;
        }
        if phase == DaemonOperationPhase::Stopped {
            state.last_diagnostics = None;
        }
        state.operation.clone()
    }

    pub async fn operation_status(&self) -> DaemonOperationStatus {
        self.state.lock().await.operation.clone()
    }

    async fn tracked_daemon_process_alive(&self) -> bool {
        let mut state = self.state.lock().await;
        if state.started_by_app {
            if let Some(child) = state.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        state.child = None;
                        state.started_by_app = false;
                        return false;
                    }
                    Ok(None) => return true,
                    Err(_) => return true,
                }
            }
        }

        let should_rediscover =
            state.elevated_started_by_app || state.operation.phase != DaemonOperationPhase::Stopped;
        if state.elevated_started_by_app {
            let pid_path = Self::default_pid_path();
            if let Some(pid) = Self::read_pid_file(&pid_path) {
                let is_daemon = Self::process_exists(pid)
                    && Self::process_command_line(pid)
                        .map(|command_line| command_line.contains("p2wlan-daemon"))
                        .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
                if is_daemon {
                    return true;
                }
                Self::remove_pid_file(&pid_path);
            }
        }

        if should_rediscover {
            let bind_addr = Self::diagnostics_bind_from_url(&state.diagnostics_url);
            if let Some(pid) = Self::find_daemon_pid_by_diagnostics_bind(&bind_addr) {
                state.elevated_started_by_app = true;
                #[cfg(not(test))]
                {
                    let pid_path = Self::default_pid_path();
                    if let Some(parent) = pid_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(pid_path, pid.to_string());
                }
                log::info!("Recovered running p2wlan-daemon PID {pid} for diagnostics {bind_addr}");
                return true;
            }
        }

        state.elevated_started_by_app = false;
        false
    }

    pub async fn configure(&self, options: DaemonStartOptions) -> DaemonOperationStatus {
        let mut state = self.state.lock().await;
        let tracks_daemon = state.started_by_app
            || state.elevated_started_by_app
            || state.operation.phase != DaemonOperationPhase::Stopped;
        if !tracks_daemon {
            if let Some(url) = options.diagnostics_url.as_ref() {
                state.diagnostics_url = url.clone();
            }
        }
        state.last_start_options = Some(options);
        state.operation.clone()
    }

    pub async fn desktop_status(&self, diagnostics_url: Option<String>) -> DesktopStatus {
        let (state_url, tracks_daemon) = {
            let state = self.state.lock().await;
            let tracks_daemon = state.started_by_app
                || state.elevated_started_by_app
                || state.operation.phase != DaemonOperationPhase::Stopped;
            (state.diagnostics_url.clone(), tracks_daemon)
        };
        let (target_url, recovered_persisted_url) = desktop_diagnostics_url(
            state_url,
            tracks_daemon,
            diagnostics_url,
            (!tracks_daemon)
                .then(Self::read_persisted_diagnostics_url)
                .flatten(),
        );
        let diagnostics_alive = Self::check_endpoint(&target_url).await;
        let tracked_process_alive = if diagnostics_alive {
            false
        } else {
            self.tracked_daemon_process_alive().await
        };
        let mut diagnostics_error = None;
        let mut diagnostics_stale = false;
        let diagnostics = if diagnostics_alive {
            match self.status(Some(target_url.clone())).await {
                Ok(value) => {
                    let mut state = self.state.lock().await;
                    state.last_diagnostics = Some(value.clone());
                    Some(value)
                }
                Err(error) => {
                    diagnostics_error = Some(error);
                    let cached = self.state.lock().await.last_diagnostics.clone();
                    diagnostics_stale = cached.is_some();
                    cached
                }
            }
        } else {
            diagnostics_error = Some(if tracked_process_alive {
                "本地健康检查端点暂不可访问，但守护进程仍在运行".to_string()
            } else {
                "本地健康检查端点不可访问".to_string()
            });
            None
        };

        if diagnostics_alive {
            let mut state = self.state.lock().await;
            if recovered_persisted_url {
                state.diagnostics_url = target_url.clone();
                state.elevated_started_by_app = true;
            }
            state.consecutive_status_failures = 0;
            if !state.operation.phase.is_busy()
                && state.operation.phase != DaemonOperationPhase::Running
            {
                state.operation = DaemonOperationStatus {
                    phase: DaemonOperationPhase::Running,
                    message: "TUN 已连接".to_string(),
                    started_at_ms: now_ms(),
                    last_error: None,
                };
            }
        } else {
            let mut state = self.state.lock().await;
            if state.operation.phase == DaemonOperationPhase::Running {
                state.consecutive_status_failures =
                    state.consecutive_status_failures.saturating_add(1);
                if state.consecutive_status_failures >= 3 {
                    if tracked_process_alive {
                        state.operation = DaemonOperationStatus {
                            phase: DaemonOperationPhase::Running,
                            message: "TUN 已连接".to_string(),
                            started_at_ms: state.operation.started_at_ms,
                            last_error: None,
                        };
                    } else {
                        state.last_diagnostics = None;
                        state.operation = DaemonOperationStatus {
                            phase: DaemonOperationPhase::Error,
                            message: "守护进程未响应".to_string(),
                            started_at_ms: now_ms(),
                            last_error: Some("连续 3 次无法访问本地健康检查端点".to_string()),
                        };
                    }
                }
            }
        }

        DesktopStatus {
            operation: self.operation_status().await,
            diagnostics,
            diagnostics_url: target_url,
            diagnostics_alive,
            diagnostics_stale,
            diagnostics_error,
        }
    }

    pub async fn begin_start_elevated(
        &self,
        options: Option<DaemonStartOptions>,
    ) -> Result<DaemonOperationStatus, String> {
        let resolved_options = {
            let mut state = self.state.lock().await;
            if state.operation.phase.is_busy() {
                return Err(format!("当前正在{}，请稍候。", state.operation.message));
            }
            let options = options
                .or_else(|| state.last_start_options.clone())
                .ok_or_else(|| "请先打开控制台并登录，再从托盘启动 TUN。".to_string())?;
            if options
                .auth_token
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err("请先打开控制台并登录，再启动 TUN。".to_string());
            }
            if let Some(url) = options.diagnostics_url.as_ref() {
                state.diagnostics_url = url.clone();
            }
            state.last_start_options = Some(options.clone());
            state.operation = DaemonOperationStatus {
                phase: DaemonOperationPhase::Authorizing,
                message: Self::authorization_message(),
                started_at_ms: now_ms(),
                last_error: None,
            };
            options
        };

        let manager = self.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = manager.start_elevated(Some(resolved_options)).await {
                manager
                    .set_operation(DaemonOperationPhase::Error, "TUN 启动失败", Some(error))
                    .await;
            }
        });

        Ok(self.operation_status().await)
    }

    pub async fn begin_stop(
        &self,
        diagnostics_url: Option<String>,
    ) -> Result<DaemonOperationStatus, String> {
        {
            let state = self.state.lock().await;
            if state.operation.phase.is_busy()
                && state.operation.phase != DaemonOperationPhase::Stopping
            {
                return Err(format!("当前正在{}，请稍候。", state.operation.message));
            }
            if state.operation.phase == DaemonOperationPhase::Stopping {
                return Ok(state.operation.clone());
            }
        }

        let status = self
            .set_operation(DaemonOperationPhase::Stopping, "正在停止 TUN", None)
            .await;
        let manager = self.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(error) = manager.stop(diagnostics_url).await {
                manager
                    .set_operation(DaemonOperationPhase::Error, "TUN 停止失败", Some(error))
                    .await;
            }
        });
        Ok(status)
    }

    pub fn resolve_daemon_binary(env_var: Option<&str>, current_dir: &Path) -> Option<PathBuf> {
        // 1. Env var P2WLAN_DAEMON_BIN
        if let Some(var) = env_var {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    let path = PathBuf::from(val);
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }

        // 2. Side-by-side release layout next to the desktop executable.
        let binary_name = if cfg!(windows) {
            "p2wlan-daemon.exe"
        } else {
            "p2wlan-daemon"
        };
        if let Ok(current_exe) = std::env::current_exe() {
            if let Some(exe_dir) = current_exe.parent() {
                let side_by_side = exe_dir.join(binary_name);
                if side_by_side.exists() {
                    return Some(side_by_side);
                }
                if let Some(contents_dir) = exe_dir.parent() {
                    let bundled_resource = contents_dir.join("Resources").join(binary_name);
                    if bundled_resource.exists() {
                        return Some(bundled_resource);
                    }
                }
            }
        }

        // 3. Dev locations relative to project root
        // Let's check target/debug/p2wlan-daemon or target/release/p2wlan-daemon relative to project root or workspace dirs

        // If target is inside workspace target
        // Let's traverse up to find target/debug or target/release
        let mut check_dir = current_dir.to_path_buf();
        for _ in 0..4 {
            let debug_path = check_dir.join("target").join("debug").join(binary_name);
            if debug_path.exists() {
                return Some(debug_path);
            }
            let release_path = check_dir.join("target").join("release").join(binary_name);
            if release_path.exists() {
                return Some(release_path);
            }
            if let Some(parent) = check_dir.parent() {
                check_dir = parent.to_path_buf();
            } else {
                break;
            }
        }

        // 4. PATH search
        if let Ok(path) = which::which("p2wlan-daemon") {
            return Some(path);
        }

        None
    }

    pub async fn check_endpoint(url: &str) -> bool {
        // Simple client request to the lightweight health endpoint.
        // Full `/status` snapshots can be briefly slow while peer/relay state is changing.
        let Ok(client) =
            p2wlan_desktop_host::DesktopHostClient::with_timeout(Duration::from_millis(1500))
        else {
            return false;
        };
        client.fetch_health(url).await.unwrap_or(false)
    }

    pub async fn status(
        &self,
        diagnostics_url: Option<String>,
    ) -> Result<serde_json::Value, String> {
        let url = match diagnostics_url {
            Some(u) => u,
            None => {
                let state = self.state.lock().await;
                state.diagnostics_url.clone()
            }
        };

        let client =
            p2wlan_desktop_host::DesktopHostClient::with_timeout(Duration::from_millis(2500))
                .map_err(Self::desktop_host_status_error)?;
        client
            .fetch_status(&url)
            .await
            .map_err(Self::desktop_host_status_error)
    }

    fn desktop_host_status_error(error: p2wlan_desktop_host::DesktopHostError) -> String {
        match error.kind {
            p2wlan_desktop_host::DesktopHostErrorKind::DaemonStatusDecodeFailed => {
                let detail = error.details.first().unwrap_or(&error.message);
                format!("解析守护进程状态失败：{detail}")
            }
            p2wlan_desktop_host::DesktopHostErrorKind::DaemonUnavailable => {
                if let Some(status) = error
                    .message
                    .strip_prefix("Daemon status endpoint returned ")
                {
                    format!("守护进程返回异常状态码：{status}")
                } else {
                    let detail = error.details.first().unwrap_or(&error.message);
                    format!("守护进程不可达：{detail}")
                }
            }
            p2wlan_desktop_host::DesktopHostErrorKind::InvalidDiagnosticsUrl => {
                format!("诊断地址无效：{}", error.message)
            }
            _ => error.message,
        }
    }

    async fn diagnostics_process_id(url: &str) -> Option<u32> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(800))
            .build()
            .ok()?;
        let json = client
            .get(url)
            .send()
            .await
            .ok()?
            .json::<serde_json::Value>()
            .await
            .ok()?;
        let pid = json.get("process_id")?.as_u64()?;
        u32::try_from(pid).ok()
    }

    fn shutdown_url_from_status_url(url: &str) -> Option<String> {
        let mut parsed = url::Url::parse(url).ok()?;
        parsed.set_path("/shutdown");
        parsed.set_query(None);
        Some(parsed.to_string())
    }

    fn health_url_from_status_url(url: &str) -> Option<String> {
        let mut parsed = url::Url::parse(url).ok()?;
        parsed.set_path("/health");
        parsed.set_query(None);
        Some(parsed.to_string())
    }

    async fn request_daemon_shutdown(url: &str) -> bool {
        let Some(shutdown_url) = Self::shutdown_url_from_status_url(url) else {
            return false;
        };
        let client = match reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(800))
            .build()
        {
            Ok(client) => client,
            Err(_) => return false,
        };
        client
            .post(shutdown_url)
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }

    fn local_http_status_blocking(url: &str, method: &str, timeout: Duration) -> Option<u16> {
        let parsed = url::Url::parse(url).ok()?;
        let address = Self::diagnostics_socket_addr_from_url(url)?;
        let path = match parsed.query() {
            Some(query) => format!("{}?{query}", parsed.path()),
            None => parsed.path().to_string(),
        };
        let host = match parsed.host()? {
            url::Host::Ipv4(ip) => format!("{ip}:{}", address.port()),
            url::Host::Ipv6(ip) => format!("[{ip}]:{}", address.port()),
            url::Host::Domain(host) => format!("{host}:{}", address.port()),
        };
        let mut stream = TcpStream::connect_timeout(&address, timeout).ok()?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).ok()?;
        let mut response = [0_u8; 128];
        let n = stream.read(&mut response).ok()?;
        let response = std::str::from_utf8(&response[..n]).ok()?;
        let status_line = response.lines().next()?;
        status_line.split_whitespace().nth(1)?.parse::<u16>().ok()
    }

    fn request_daemon_shutdown_blocking(url: &str) -> bool {
        let Some(shutdown_url) = Self::shutdown_url_from_status_url(url) else {
            return false;
        };
        Self::local_http_status_blocking(&shutdown_url, "POST", Duration::from_millis(800))
            .is_some_and(|code| (200..300).contains(&code))
    }

    fn check_endpoint_blocking(url: &str) -> bool {
        let health_url = Self::health_url_from_status_url(url).unwrap_or_else(|| url.to_string());
        Self::local_http_status_blocking(&health_url, "GET", Duration::from_millis(800))
            .is_some_and(|code| (200..300).contains(&code))
    }

    fn wait_for_endpoint_down_blocking(url: &str, timeout: Duration) -> bool {
        let start_time = Instant::now();
        while start_time.elapsed() < timeout {
            if !Self::check_endpoint_blocking(url) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        !Self::check_endpoint_blocking(url)
    }

    pub fn diagnostics_bind_from_url(url: &str) -> String {
        p2wlan_desktop_host::diagnostics_bind_from_url(url)
            .unwrap_or_else(|_| "127.0.0.1:39277".to_string())
    }

    fn diagnostics_socket_addr_from_url(url: &str) -> Option<SocketAddr> {
        p2wlan_desktop_host::diagnostics_socket_addr_from_url(url).ok()
    }

    fn available_diagnostics_url(preferred_url: &str) -> Result<String, String> {
        let mut parsed = url::Url::parse(preferred_url)
            .map_err(|error| format!("本地诊断 URL 无效：{error}"))?;
        let preferred = Self::diagnostics_socket_addr_from_url(preferred_url).ok_or_else(|| {
            "本地诊断地址必须使用带端口的 127.0.0.1、[::1] 或 localhost".to_string()
        })?;

        for offset in 0..DIAGNOSTICS_PORT_SCAN_LIMIT {
            let Some(port) = preferred.port().checked_add(offset) else {
                break;
            };
            let candidate = SocketAddr::new(preferred.ip(), port);
            match TcpListener::bind(candidate) {
                Ok(listener) => {
                    drop(listener);
                    parsed
                        .set_port(Some(port))
                        .map_err(|_| "无法写入自动选择的诊断端口".to_string())?;
                    return Ok(parsed.to_string());
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(error) => {
                    return Err(format!("无法检测本地诊断端口 {candidate}：{error}"));
                }
            }
        }

        Err(format!(
            "诊断端口 {} 及后续 {} 个端口均已被占用",
            preferred.port(),
            DIAGNOSTICS_PORT_SCAN_LIMIT - 1
        ))
    }

    pub fn default_config_path() -> PathBuf {
        p2wlan_desktop_host::default_config_path()
    }

    #[cfg(unix)]
    fn has_network_admin_privileges() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    fn has_network_admin_privileges() -> bool {
        Command::new("net")
            .arg("session")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    fn has_network_admin_privileges() -> bool {
        false
    }

    fn authorization_message() -> String {
        #[cfg(target_os = "windows")]
        {
            if Self::has_network_admin_privileges() {
                "已具备 Windows 管理员权限，正在启动 TUN".to_string()
            } else {
                "等待 Windows UAC 管理员授权".to_string()
            }
        }

        #[cfg(target_os = "macos")]
        {
            if Self::has_network_admin_privileges() {
                "已具备 macOS 管理员权限，正在启动 TUN".to_string()
            } else {
                "等待 macOS 系统授权".to_string()
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            "等待系统授权".to_string()
        }
    }

    #[cfg(target_os = "macos")]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[cfg(target_os = "macos")]
    fn applescript_quote(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    pub fn default_log_dir() -> PathBuf {
        p2wlan_desktop_host::default_log_dir()
    }

    fn default_pid_path() -> PathBuf {
        p2wlan_desktop_host::pid_path_from_log_dir(Self::default_log_dir())
    }

    fn default_endpoint_path() -> PathBuf {
        p2wlan_desktop_host::endpoint_path_from_log_dir(Self::default_log_dir())
    }

    fn persist_diagnostics_url(url: &str) -> Result<(), String> {
        let path = Self::default_endpoint_path();
        Self::persist_diagnostics_url_to_path(&path, url)
    }

    fn persist_diagnostics_url_to_path(path: &Path, url: &str) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("无法创建诊断端点目录 {}：{error}", parent.display()))?;
        }
        match std::fs::write(path, url) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // Older elevated launches could leave this marker owned by root. The
                // desktop app owns the parent log directory, so removing the stale marker
                // and recreating it is safe and avoids blocking an otherwise healthy TUN.
                std::fs::remove_file(path).map_err(|remove_error| {
                    format!(
                        "无法重置旧诊断端点 {}：写入失败：{error}；删除失败：{remove_error}",
                        path.display()
                    )
                })?;
                std::fs::write(path, url).map_err(|retry_error| {
                    format!(
                        "无法记录诊断端点 {}：已删除旧文件但重新写入失败：{retry_error}",
                        path.display()
                    )
                })
            }
            Err(error) => Err(format!("无法记录诊断端点 {}：{error}", path.display())),
        }
    }

    #[cfg(not(test))]
    fn read_persisted_diagnostics_url() -> Option<String> {
        let url = std::fs::read_to_string(Self::default_endpoint_path()).ok()?;
        let url = url.trim().to_string();
        Self::diagnostics_socket_addr_from_url(&url)?;
        Some(url)
    }

    #[cfg(test)]
    fn read_persisted_diagnostics_url() -> Option<String> {
        // Keep unit tests isolated from a real desktop daemon that may be
        // running on the developer machine.
        None
    }

    fn remove_persisted_diagnostics_url() {
        let path = Self::default_endpoint_path();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    #[allow(dead_code)]
    fn log_tail(path: &Path, max_lines: usize) -> Option<String> {
        let raw = std::fs::read_to_string(path).ok()?;
        let lines = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        if lines.is_empty() {
            return None;
        }
        let start = lines.len().saturating_sub(max_lines);
        Some(lines[start..].join("\n"))
    }

    pub fn recent_daemon_log_lines(max_lines: usize) -> Vec<String> {
        let log_path = Self::default_log_dir().join("p2wlan-daemon.log");
        p2wlan_desktop_host::recent_daemon_log_lines(log_path, max_lines).unwrap_or_default()
    }

    #[allow(dead_code)]
    fn timeout_message_with_log(prefix: &str, log_path: &Path) -> String {
        match Self::log_tail(log_path, 30) {
            Some(tail) => format!(
                "{prefix}\n日志文件：{}\n\n最近日志：\n{}",
                log_path.display(),
                tail
            ),
            None => format!(
                "{prefix} 请查看日志：{}（当前没有读到日志内容）",
                log_path.display()
            ),
        }
    }

    #[cfg(target_os = "windows")]
    fn append_launcher_log(log_path: &Path, line: &str) -> Result<(), String> {
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("无法创建守护进程日志目录 {}: {e}", parent.display()))?;
        }
        let stamp = chrono_like_timestamp();
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|e| format!("无法写入守护进程日志 {}: {e}", log_path.display()))?;
        writeln!(file, "{stamp}  desktop-launcher: {line}")
            .map_err(|e| format!("无法写入守护进程日志 {}: {e}", log_path.display()))
    }

    fn read_pid_file(pid_path: &Path) -> Option<u32> {
        let raw = std::fs::read_to_string(pid_path).ok()?;
        raw.trim().parse::<u32>().ok()
    }

    fn remove_pid_file(pid_path: &Path) {
        if pid_path.exists() {
            let _ = std::fs::remove_file(pid_path);
        }
    }

    fn process_exists(pid: u32) -> bool {
        #[cfg(unix)]
        {
            Command::new("kill")
                .args(["-0", &pid.to_string()])
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        }

        #[cfg(windows)]
        {
            let output = Self::windows_hidden_command("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
                .output();
            let Ok(output) = output else {
                return false;
            };
            if !output.status.success() {
                return false;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.lines().any(|line| {
                line.contains(&format!("\",\"{pid}\",")) || line.contains(&format!(",\"{pid}\","))
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = pid;
            false
        }
    }

    fn process_name_matches_daemon(pid: u32) -> bool {
        if let Some(command_line) = Self::process_command_line(pid) {
            return command_line.contains("p2wlan-daemon");
        }

        #[cfg(windows)]
        {
            let output = Self::windows_hidden_command("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
                .output();
            let Ok(output) = output else {
                return false;
            };
            if !output.status.success() {
                return false;
            }
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            stdout.contains("p2wlan-daemon.exe")
        }

        #[cfg(not(windows))]
        {
            false
        }
    }

    fn process_command_line(pid: u32) -> Option<String> {
        #[cfg(unix)]
        {
            let output = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "command="])
                .output();
            output
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .filter(|line| !line.is_empty())
        }

        #[cfg(windows)]
        {
            let script = format!(
                "(Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\").CommandLine"
            );
            let output = Self::windows_hidden_command("powershell.exe")
                .args(["-NoProfile", "-Command", &script])
                .output();
            output
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                .filter(|line| !line.is_empty())
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = pid;
            None
        }
    }

    fn daemon_command_line_uses_binary(command_line: &str, expected_bin: &Path) -> bool {
        let expected = expected_bin.display().to_string();
        if !expected.is_empty() && command_line.contains(&expected) {
            return true;
        }

        if let Ok(canonical) = expected_bin.canonicalize() {
            let canonical = canonical.display().to_string();
            if !canonical.is_empty() && command_line.contains(&canonical) {
                return true;
            }
        }

        if expected_bin.is_relative() {
            if let Ok(current_dir) = std::env::current_dir() {
                let absolute = current_dir.join(expected_bin).display().to_string();
                if !absolute.is_empty() && command_line.contains(&absolute) {
                    return true;
                }
            }
        }

        false
    }

    fn existing_daemon_binary_conflict(pid: u32, expected_bin: &Path) -> Option<String> {
        let command_line = Self::process_command_line(pid)?;
        if Self::daemon_command_line_uses_binary(&command_line, expected_bin) {
            return None;
        }

        Some(format!(
            "检测到已有 p2wlan-daemon 占用诊断端点，但它不是当前客户端要启动的守护进程。\n当前运行 PID：{pid}\n当前运行命令：{command_line}\n当前需要：{}\n请先停止 TUN，或执行：sudo kill {pid}",
            expected_bin.display()
        ))
    }

    fn command_line_matches_daemon_bind(command_line: &str, bind_addr: &str) -> bool {
        command_line.contains("p2wlan-daemon")
            && command_line.contains("--diagnostics-bind")
            && command_line.contains(bind_addr)
    }

    fn find_daemon_pid_by_diagnostics_bind(bind_addr: &str) -> Option<u32> {
        #[cfg(unix)]
        {
            let output = Command::new("ps")
                .args(["ax", "-o", "pid=", "-o", "command="])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }

            let current_pid = std::process::id();
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim_start();
                let Some(split_at) = trimmed.find(char::is_whitespace) else {
                    continue;
                };
                let Ok(pid) = trimmed[..split_at].trim().parse::<u32>() else {
                    continue;
                };
                if pid == current_pid {
                    continue;
                }
                let command_line = trimmed[split_at..].trim_start();
                if Self::command_line_matches_daemon_bind(command_line, bind_addr) {
                    return Some(pid);
                }
            }
            None
        }

        #[cfg(windows)]
        {
            let escaped_bind = bind_addr.replace('\'', "''");
            let script = format!(
                "$p = Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*p2wlan-daemon*' -and $_.CommandLine -like '*--diagnostics-bind*' -and $_.CommandLine -like '*{escaped_bind}*' }} | Select-Object -First 1 -ExpandProperty ProcessId; if ($p) {{ $p }}"
            );
            let output = Self::windows_hidden_command("powershell.exe")
                .args(["-NoProfile", "-Command", &script])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = bind_addr;
            None
        }
    }

    fn find_single_daemon_pid() -> Option<u32> {
        #[cfg(unix)]
        {
            let output = Command::new("ps")
                .args(["ax", "-o", "pid=", "-o", "command="])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let current_pid = std::process::id();
            let mut matches = Vec::new();
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim_start();
                let Some(split_at) = trimmed.find(char::is_whitespace) else {
                    continue;
                };
                let Ok(pid) = trimmed[..split_at].trim().parse::<u32>() else {
                    continue;
                };
                if pid == current_pid {
                    continue;
                }
                let command_line = trimmed[split_at..].trim_start();
                if command_line.contains("p2wlan-daemon") {
                    matches.push(pid);
                }
            }
            (matches.len() == 1).then_some(matches[0])
        }

        #[cfg(windows)]
        {
            let output = Self::windows_hidden_command("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    "Get-CimInstance Win32_Process -Filter \"Name = 'p2wlan-daemon.exe'\" | Select-Object -ExpandProperty ProcessId",
                ])
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let matches = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect::<Vec<_>>();
            (matches.len() == 1).then_some(matches[0])
        }

        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }

    fn terminate_pid(pid: u32) -> Result<(), String> {
        #[cfg(windows)]
        {
            let output = Self::windows_hidden_command("taskkill")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .output()
                .map_err(|e| format!("无法执行 taskkill: {e}"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return Err(if stderr.is_empty() {
                    format!("taskkill 未能结束进程 {pid}")
                } else {
                    format!("taskkill 未能结束进程 {pid}: {stderr}")
                });
            }
        }

        #[cfg(unix)]
        {
            let output = Command::new("kill")
                .arg(pid.to_string())
                .output()
                .map_err(|e| format!("无法执行 kill: {e}"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return Err(if stderr.is_empty() {
                    format!("kill 未能结束进程 {pid}")
                } else {
                    format!("kill 未能结束进程 {pid}: {stderr}")
                });
            }
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = pid;
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn terminate_pid_with_system_authorization(pid: u32) -> Result<(), String> {
        match Self::terminate_pid(pid) {
            Ok(()) => Ok(()),
            Err(err) => {
                use std::mem::size_of;
                use windows_sys::Win32::Foundation::GetLastError;
                use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
                use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

                let verb = Self::windows_wide_str("runas");
                let file = Self::windows_wide_str("taskkill.exe");
                let parameters = Self::windows_wide_str(&format!("/PID {pid} /T /F"));
                let mut info = unsafe { std::mem::zeroed::<SHELLEXECUTEINFOW>() };
                info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
                info.lpVerb = verb.as_ptr();
                info.lpFile = file.as_ptr();
                info.lpParameters = parameters.as_ptr();
                info.nShow = SW_HIDE;

                let launched = unsafe { ShellExecuteExW(&mut info) };
                if launched != 0 {
                    return Ok(());
                }
                let code = unsafe { GetLastError() };
                if code == 1223 {
                    return Err("已取消 Windows 管理员授权，TUN 守护进程仍在运行。".to_string());
                }
                Err(format!(
                    "无法通过 Windows UAC 停止守护进程，错误码：{code}；原始错误：{err}"
                ))
            }
        }
    }

    fn terminate_recorded_daemon(pid_path: &Path) -> Result<bool, String> {
        let Some(pid) = Self::read_pid_file(pid_path) else {
            return Ok(false);
        };
        if !Self::process_exists(pid) {
            Self::remove_pid_file(pid_path);
            return Ok(false);
        }
        let verified = Self::process_command_line(pid)
            .map(|command_line| command_line.contains("p2wlan-daemon"))
            .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
        if !verified {
            Self::remove_pid_file(pid_path);
            return Err(format!(
                "PID 文件指向的进程不是 p2wlan-daemon，已拒绝结束进程：{}",
                pid_path.display()
            ));
        }
        Self::terminate_pid(pid)?;
        Self::remove_pid_file(pid_path);
        Ok(true)
    }

    fn build_args(
        options: &DaemonStartOptions,
        bind_addr: &str,
        config_path: &Path,
    ) -> Vec<String> {
        let mut args = vec![
            "--config".to_string(),
            config_path.display().to_string(),
            "--diagnostics-bind".to_string(),
            bind_addr.to_string(),
        ];
        fn push_pair(args: &mut Vec<String>, flag: &str, value: Option<&str>) {
            if let Some(value) = value {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    args.push(flag.to_string());
                    args.push(trimmed.to_string());
                }
            }
        }

        push_pair(&mut args, "--control", options.control_server.as_deref());
        if options
            .auth_token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty())
        {
            args.push("--managed".to_string());
        }
        push_pair(&mut args, "--token", options.auth_token.as_deref());
        push_pair(&mut args, "--network", options.network_id.as_deref());
        push_pair(&mut args, "--device-name", options.device_name.as_deref());
        push_pair(&mut args, "--interface", options.tun_interface.as_deref());
        push_pair(&mut args, "--udp-bind", options.udp_bind.as_deref());
        push_pair(
            &mut args,
            "--udp-advertise",
            options.udp_advertise.as_deref(),
        );
        push_pair(&mut args, "--socket-pool", options.socket_pool.as_deref());
        if let Some(mtu) = options.mtu {
            args.push("--mtu".to_string());
            args.push(mtu.to_string());
        }
        args
    }

    #[cfg(target_os = "macos")]
    fn build_macos_elevated_shell(
        bin_path: &Path,
        args: &[String],
        config_path: &Path,
        log_dir: &Path,
        log_path: &Path,
        pid_path: &Path,
    ) -> String {
        let args_shell = args
            .iter()
            .map(|arg| Self::shell_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "mkdir -p {config_dir} {log_dir}; : > {log}; chmod 644 {log}; (P2WLAN_DAEMON_BIN={bin} {bin} {args} >> {log} 2>&1 < /dev/null & echo $! > {pid})",
            config_dir = Self::shell_quote(
                &config_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .display()
                    .to_string()
            ),
            log_dir = Self::shell_quote(&log_dir.display().to_string()),
            log = Self::shell_quote(&log_path.display().to_string()),
            pid = Self::shell_quote(&pid_path.display().to_string()),
            bin = Self::shell_quote(&bin_path.display().to_string()),
            args = args_shell,
        )
    }

    #[cfg(any(target_os = "windows", test))]
    fn windows_command_line_arg_quote(value: &str) -> String {
        if !value.is_empty()
            && !value
                .chars()
                .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '"')
        {
            return value.to_string();
        }

        let mut quoted = String::from("\"");
        let mut backslashes = 0;
        for ch in value.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                    quoted.push('"');
                    backslashes = 0;
                }
                _ => {
                    quoted.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                    quoted.push(ch);
                }
            }
        }
        quoted.push_str(&"\\".repeat(backslashes * 2));
        quoted.push('"');
        quoted
    }

    #[cfg(target_os = "windows")]
    fn windows_wide_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[cfg(target_os = "windows")]
    fn windows_hidden_command(program: &str) -> Command {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut command = Command::new(program);
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    #[cfg(target_os = "windows")]
    fn windows_wide_path(value: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;

        value
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    #[cfg(target_os = "windows")]
    fn launch_windows_elevated_daemon(
        bin_path: &Path,
        args: &[String],
        log_dir: &Path,
        pid_path: &Path,
    ) -> Result<(), String> {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
        use windows_sys::Win32::System::Threading::GetProcessId;
        use windows_sys::Win32::UI::Shell::{
            ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

        std::fs::create_dir_all(log_dir)
            .map_err(|e| format!("无法创建 Windows 日志目录 {}: {e}", log_dir.display()))?;

        let verb = Self::windows_wide_str("runas");
        let file = Self::windows_wide_path(bin_path);
        let parameters = Self::windows_wide_str(
            &args
                .iter()
                .map(|arg| Self::windows_command_line_arg_quote(arg))
                .collect::<Vec<_>>()
                .join(" "),
        );
        let directory = bin_path
            .parent()
            .map(Self::windows_wide_path)
            .unwrap_or_else(|| Self::windows_wide_str(""));

        let mut info = unsafe { std::mem::zeroed::<SHELLEXECUTEINFOW>() };
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = parameters.as_ptr();
        info.lpDirectory = directory.as_ptr();
        info.nShow = SW_HIDE;

        let launched = unsafe { ShellExecuteExW(&mut info) };
        if launched == 0 {
            let code = unsafe { GetLastError() };
            return if code == 1223 {
                Err("已取消 Windows 管理员授权。".to_string())
            } else {
                Err(format!("无法通过 Windows UAC 启动守护进程，错误码：{code}"))
            };
        }

        if !info.hProcess.is_null() {
            let pid = unsafe { GetProcessId(info.hProcess) };
            unsafe {
                CloseHandle(info.hProcess);
            }
            if pid != 0 {
                std::fs::write(pid_path, pid.to_string()).map_err(|e| {
                    format!(
                        "无法写入 Windows 守护进程 PID 文件 {}: {e}",
                        pid_path.display()
                    )
                })?;
            }
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn wait_for_endpoint(url: &str, timeout: Duration) -> bool {
        let start_time = Instant::now();
        while start_time.elapsed() < timeout {
            if Self::check_endpoint(url).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }

    async fn wait_for_endpoint_down(url: &str, timeout: Duration) -> bool {
        let start_time = Instant::now();
        while start_time.elapsed() < timeout {
            if !Self::check_endpoint(url).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        !Self::check_endpoint(url).await
    }

    #[cfg(target_os = "windows")]
    async fn cleanup_stale_windows_daemon_before_start(
        preferred_url: &str,
        log_path: &Path,
    ) -> Result<(), String> {
        if Self::diagnostics_process_id(preferred_url).await.is_some() {
            return Ok(());
        }

        let pid_path = Self::default_pid_path();
        let bind_addr = Self::diagnostics_bind_from_url(preferred_url);
        let mut terminated = false;

        if let Some(pid) = Self::read_pid_file(&pid_path) {
            if Self::process_exists(pid) {
                let verified = Self::process_command_line(pid)
                    .map(|command_line| command_line.contains("p2wlan-daemon"))
                    .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
                if verified {
                    let _ = Self::append_launcher_log(
                        log_path,
                        &format!("stopping stale recorded daemon PID {pid} before relaunch"),
                    );
                    Self::terminate_pid_with_system_authorization(pid)?;
                    terminated = true;
                } else {
                    Self::remove_pid_file(&pid_path);
                }
            } else {
                Self::remove_pid_file(&pid_path);
            }
        }

        if !terminated {
            if let Some(pid) = Self::find_daemon_pid_by_diagnostics_bind(&bind_addr) {
                let _ = Self::append_launcher_log(
                    log_path,
                    &format!(
                        "stopping stale daemon PID {pid} bound to diagnostics {bind_addr} before relaunch"
                    ),
                );
                Self::terminate_pid_with_system_authorization(pid)?;
                terminated = true;
            }
        }

        if terminated {
            let _ = Self::wait_for_endpoint_down(preferred_url, Duration::from_secs(3)).await;
            Self::remove_pid_file(&pid_path);
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn wait_for_endpoint_or_pid_exit(
        url: &str,
        timeout: Duration,
        pid_path: &Path,
        log_path: &Path,
    ) -> Result<(), String> {
        let start_time = Instant::now();
        let mut observed_pid = None;
        while start_time.elapsed() < timeout {
            if Self::check_endpoint(url).await {
                return Ok(());
            }
            if let Some(pid) = Self::read_pid_file(pid_path) {
                observed_pid = Some(pid);
                if !Self::process_exists(pid) {
                    Self::remove_pid_file(pid_path);
                    return Err(Self::timeout_message_with_log(
                        &format!(
                            "守护进程已获得系统授权，但进程很快退出（PID {pid}），诊断端点未响应。"
                        ),
                        log_path,
                    ));
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let prefix = match observed_pid {
            Some(pid) => format!(
                "已完成系统授权，守护进程仍在运行（PID {pid}），但 {timeout:?} 内未响应诊断端点。"
            ),
            None => {
                format!("已完成系统授权，但没有读到守护进程 PID，{timeout:?} 内也未响应诊断端点。")
            }
        };
        Err(Self::timeout_message_with_log(&prefix, log_path))
    }

    pub async fn start(&self, options: Option<DaemonStartOptions>) -> Result<String, String> {
        let mut options = options.unwrap_or(DaemonStartOptions {
            diagnostics_url: None,
            control_server: None,
            auth_token: None,
            network_id: None,
            device_name: None,
            tun_interface: None,
            udp_bind: None,
            udp_advertise: None,
            socket_pool: None,
            mtu: None,
        });
        let preferred_url = {
            let state = self.state.lock().await;
            options
                .diagnostics_url
                .clone()
                .unwrap_or_else(|| state.diagnostics_url.clone())
        };

        // Resolve the daemon binary before accepting an already-running endpoint. In dev
        // mode this prevents a stale installed app daemon from being mistaken for the
        // freshly built target/debug daemon.
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let bin_path = Self::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN"), &current_dir)
            .ok_or_else(|| "找不到 p2wlan-daemon 可执行文件。请确认它与桌面客户端在同一目录，或设置 P2WLAN_DAEMON_BIN。".to_string())?;

        // 1. Is daemon already running?
        if let Some(pid) = Self::diagnostics_process_id(&preferred_url).await {
            if let Some(error) = Self::existing_daemon_binary_conflict(pid, &bin_path) {
                return Err(error);
            }
            return Ok("守护进程已经运行。".to_string());
        }

        if !Self::has_network_admin_privileges() {
            return Err(
                "当前桌面客户端没有网络管理权限，不能直接创建 TUN 网卡或修改路由。请在配置向导中复制 sudo 命令启动 p2wlan-daemon，或先保持一个外部 sudo daemon 运行。"
                    .to_string(),
            );
        }

        let target_url = Self::available_diagnostics_url(&preferred_url)?;
        options.diagnostics_url = Some(target_url.clone());

        // 3. Extract bind address from URL (default 127.0.0.1:39277)
        let bind_addr = Self::diagnostics_bind_from_url(&target_url);
        let config_path = Self::default_config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("创建守护进程配置目录失败 {}：{}", parent.display(), e))?;
        }

        let args = Self::build_args(&options, &bind_addr, &config_path);

        // 4. Start command
        let mut cmd = Command::new(&bin_path);
        cmd.args(&args);

        // Under Windows, we don't open console window if not debug.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("启动守护进程失败：{}", e))?;
        if let Err(error) = Self::persist_diagnostics_url(&target_url) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        // 5. Update state
        {
            let mut state = self.state.lock().await;
            state.child = Some(child);
            state.started_by_app = true;
            state.elevated_started_by_app = false;
            state.diagnostics_url = target_url.clone();
            state.last_start_options = Some(options.clone());
            state.last_error = None;
        }

        // 6. Wait for daemon to become ready (up to 5s)
        let start_time = Instant::now();
        let timeout = Duration::from_secs(5);
        let mut is_ready = false;

        while start_time.elapsed() < timeout {
            // Check if child process died early
            {
                let mut state = self.state.lock().await;
                if let Some(ref mut c) = state.child {
                    if let Ok(Some(exit_status)) = c.try_wait() {
                        let err_msg = format!("守护进程提前退出，状态：{}", exit_status);
                        state.last_error = Some(err_msg.clone());
                        state.child = None;
                        state.started_by_app = false;
                        state.elevated_started_by_app = false;
                        return Err(err_msg);
                    }
                }
            }

            if Self::check_endpoint(&target_url).await {
                is_ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        if is_ready {
            Ok("守护进程已启动并可访问。".to_string())
        } else {
            // Did not become ready in 5 seconds
            self.stop(Some(target_url)).await?;
            Err("守护进程已启动，但 5 秒内没有绑定或响应诊断端点。".to_string())
        }
    }

    pub async fn start_elevated(
        &self,
        options: Option<DaemonStartOptions>,
    ) -> Result<String, String> {
        let mut options = options.unwrap_or(DaemonStartOptions {
            diagnostics_url: None,
            control_server: None,
            auth_token: None,
            network_id: None,
            device_name: None,
            tun_interface: None,
            udp_bind: None,
            udp_advertise: None,
            socket_pool: None,
            mtu: None,
        });
        let preferred_url = {
            let state = self.state.lock().await;
            options
                .diagnostics_url
                .clone()
                .unwrap_or_else(|| state.diagnostics_url.clone())
        };

        // Resolve the daemon binary before accepting an already-running endpoint. In dev
        // mode this prevents a stale installed app daemon from being mistaken for the
        // freshly built target/debug daemon.
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let bin_path = Self::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN"), &current_dir)
            .ok_or_else(|| "找不到 p2wlan-daemon 可执行文件。".to_string())?;

        if let Some(pid) = Self::diagnostics_process_id(&preferred_url).await {
            if let Some(error) = Self::existing_daemon_binary_conflict(pid, &bin_path) {
                return Err(error);
            }
            self.set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
                .await;
            return Ok("守护进程已经运行。".to_string());
        }
        if options
            .auth_token
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err("请先登录或注册控制面账号，再提权启动 TUN 模式。".to_string());
        }

        #[cfg(target_os = "windows")]
        {
            let log_path = Self::default_log_dir().join("p2wlan-daemon.log");
            Self::cleanup_stale_windows_daemon_before_start(&preferred_url, &log_path).await?;
            if let Some(pid) = Self::diagnostics_process_id(&preferred_url).await {
                if let Some(error) = Self::existing_daemon_binary_conflict(pid, &bin_path) {
                    return Err(error);
                }
                self.set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
                    .await;
                return Ok("守护进程已经运行。".to_string());
            }
        }

        let target_url = Self::available_diagnostics_url(&preferred_url)?;
        options.diagnostics_url = Some(target_url.clone());
        {
            let mut state = self.state.lock().await;
            state.diagnostics_url = target_url.clone();
            state.last_start_options = Some(options.clone());
        }

        #[cfg(target_os = "macos")]
        {
            self.set_operation(
                DaemonOperationPhase::Authorizing,
                "等待 macOS 系统授权",
                None,
            )
            .await;
            let bind_addr = Self::diagnostics_bind_from_url(&target_url);
            let config_path = Self::default_config_path();
            let log_dir = Self::default_log_dir();
            let log_path = log_dir.join("p2wlan-daemon.log");
            let pid_path = Self::default_pid_path();
            Self::remove_pid_file(&pid_path);

            let args = Self::build_args(&options, &bind_addr, &config_path);
            let shell = Self::build_macos_elevated_shell(
                &bin_path,
                &args,
                &config_path,
                &log_dir,
                &log_path,
                &pid_path,
            );
            let script = format!(
                "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
                Self::applescript_quote(&shell),
                Self::applescript_quote("p2wlan 需要管理员权限以创建虚拟网卡并安装 Overlay 路由。p2wlan 不会读取或保存你的密码。")
            );

            let output = tokio::task::spawn_blocking(move || {
                Command::new("osascript").arg("-e").arg(script).output()
            })
            .await
            .map_err(|e| format!("系统授权任务异常结束：{e}"))?
            .map_err(|e| format!("无法打开系统授权弹窗：{e}"))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if stderr.contains("-128") {
                    return Err("已取消管理员授权。".to_string());
                }
                return Err(if stderr.is_empty() {
                    "管理员授权启动失败。".to_string()
                } else {
                    format!("管理员授权启动失败：{stderr}")
                });
            }
            Self::persist_diagnostics_url(&target_url)?;

            self.set_operation(
                DaemonOperationPhase::WaitingForDaemon,
                "正在连接控制面并创建 TUN",
                None,
            )
            .await;

            {
                let mut state = self.state.lock().await;
                state.child = None;
                state.started_by_app = false;
                state.elevated_started_by_app = true;
                state.diagnostics_url = target_url.clone();
                state.last_error = None;
            }

            if Self::wait_for_endpoint(&target_url, MACOS_ELEVATED_READY_TIMEOUT).await {
                self.set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
                    .await;
                Ok("TUN 模式已通过管理员权限启动。".to_string())
            } else {
                let mut state = self.state.lock().await;
                state.elevated_started_by_app = false;
                Err(Self::timeout_message_with_log(
                    "已完成管理员授权，但守护进程未在 60 秒内响应诊断端点。",
                    &log_path,
                ))
            }
        }

        #[cfg(target_os = "windows")]
        {
            self.set_operation(
                DaemonOperationPhase::Authorizing,
                Self::authorization_message(),
                None,
            )
            .await;
            let bind_addr = Self::diagnostics_bind_from_url(&target_url);
            let config_path = Self::default_config_path();
            let log_dir = Self::default_log_dir();
            let log_path = log_dir.join("p2wlan-daemon.log");
            let pid_path = Self::default_pid_path();
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "无法创建 Windows 守护进程配置目录 {}: {e}",
                        parent.display()
                    )
                })?;
            }
            std::fs::create_dir_all(&log_dir)
                .map_err(|e| format!("无法创建 Windows 日志目录 {}: {e}", log_dir.display()))?;
            std::fs::write(&log_path, "").map_err(|e| {
                format!(
                    "无法初始化 Windows 守护进程日志 {}: {e}",
                    log_path.display()
                )
            })?;
            Self::remove_pid_file(&pid_path);

            let mut args = Self::build_args(&options, &bind_addr, &config_path);
            args.push("--log-file".to_string());
            args.push(log_path.display().to_string());

            Self::append_launcher_log(
                &log_path,
                &format!(
                    "launching {} with diagnostics {} and interface {}",
                    bin_path.display(),
                    bind_addr,
                    options.tun_interface.as_deref().unwrap_or("(default)")
                ),
            )?;
            Self::launch_windows_elevated_daemon(&bin_path, &args, &log_dir, &pid_path)?;
            Self::persist_diagnostics_url(&target_url)?;

            self.set_operation(
                DaemonOperationPhase::WaitingForDaemon,
                "正在初始化 Wintun 并连接控制面",
                None,
            )
            .await;

            {
                let mut state = self.state.lock().await;
                state.child = None;
                state.started_by_app = false;
                state.elevated_started_by_app = true;
                state.diagnostics_url = target_url.clone();
                state.last_error = None;
            }

            match Self::wait_for_endpoint_or_pid_exit(
                &target_url,
                Duration::from_secs(45),
                &pid_path,
                &log_path,
            )
            .await
            {
                Ok(()) => {
                    Self::append_launcher_log(&log_path, "diagnostics endpoint is ready")?;
                    self.set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
                        .await;
                    Ok("TUN 模式已通过 Windows 管理员权限启动。".to_string())
                }
                Err(err) => {
                    let mut state = self.state.lock().await;
                    state.elevated_started_by_app = false;
                    Err(err)
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Err("当前平台尚未接入图形化提权启动；请使用 sudo/polkit 手动启动 daemon。".to_string())
        }
    }

    pub async fn stop(&self, diagnostics_url: Option<String>) -> Result<String, String> {
        self.set_operation(DaemonOperationPhase::Stopping, "正在停止 TUN", None)
            .await;
        let target_url = {
            let state = self.state.lock().await;
            if state.started_by_app
                || state.elevated_started_by_app
                || state.operation.phase != DaemonOperationPhase::Stopped
            {
                state.diagnostics_url.clone()
            } else {
                diagnostics_url.unwrap_or_else(|| state.diagnostics_url.clone())
            }
        };

        {
            let mut state = self.state.lock().await;
            if let Some(mut child) = state.child.take() {
                let _ = child.kill();
                let _ = child.wait();
                state.started_by_app = false;
                state.elevated_started_by_app = false;
                Self::remove_pid_file(&Self::default_pid_path());
                state.operation = DaemonOperationStatus::stopped();
                state.consecutive_status_failures = 0;
                state.last_diagnostics = None;
                Self::remove_persisted_diagnostics_url();
                return Ok("守护进程已停止。".to_string());
            }
        }

        if Self::request_daemon_shutdown(&target_url).await
            && Self::wait_for_endpoint_down(&target_url, Duration::from_secs(2)).await
        {
            let mut state = self.state.lock().await;
            state.started_by_app = false;
            state.elevated_started_by_app = false;
            Self::remove_pid_file(&Self::default_pid_path());
            state.operation = DaemonOperationStatus::stopped();
            state.consecutive_status_failures = 0;
            state.last_diagnostics = None;
            Self::remove_persisted_diagnostics_url();
            return Ok("已停止 TUN 守护进程。".to_string());
        }

        let pid_path = Self::default_pid_path();
        let mut terminated = false;
        let mut last_termination_error = None;
        if let Some(pid) = Self::diagnostics_process_id(&target_url).await {
            let verified = Self::process_command_line(pid)
                .map(|command_line| command_line.contains("p2wlan-daemon"))
                .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
            if verified {
                match Self::terminate_pid(pid) {
                    Ok(()) => terminated = true,
                    Err(error) => last_termination_error = Some(error),
                }
            }
        }
        if !terminated {
            match Self::terminate_recorded_daemon(&pid_path) {
                Ok(value) => terminated = value,
                Err(error) => last_termination_error = Some(error),
            }
        }
        if !terminated {
            let bind_addr = Self::diagnostics_bind_from_url(&target_url);
            if let Some(pid) = Self::find_daemon_pid_by_diagnostics_bind(&bind_addr) {
                match Self::terminate_pid(pid) {
                    Ok(()) => terminated = true,
                    Err(error) => last_termination_error = Some(error),
                }
            }
        }
        if !terminated {
            if let Some(pid) = Self::find_single_daemon_pid() {
                match Self::terminate_pid(pid) {
                    Ok(()) => terminated = true,
                    Err(error) => last_termination_error = Some(error),
                }
            }
        }

        let stopped = Self::wait_for_endpoint_down(&target_url, Duration::from_secs(3)).await;

        {
            let mut state = self.state.lock().await;
            state.started_by_app = false;
            state.elevated_started_by_app = false;
            if stopped {
                state.operation = DaemonOperationStatus::stopped();
                state.consecutive_status_failures = 0;
                state.last_diagnostics = None;
                Self::remove_persisted_diagnostics_url();
            }
        }

        if terminated && stopped {
            Ok("已停止 TUN 守护进程。".to_string())
        } else if stopped {
            Ok("守护进程已经停止。".to_string())
        } else {
            let detail = last_termination_error
                .map(|error| format!(" 普通关闭/结束进程失败：{error}"))
                .unwrap_or_default();
            Err(format!(
                "已请求守护进程关闭，但它仍在运行。关闭路径不会再次请求管理员授权。{detail} 请手动执行 sudo kill <p2wlan-daemon PID>，或重启后再启动 TUN。诊断地址：{}",
                target_url
            ))
        }
    }

    pub fn cleanup(&self) {
        let Ok(mut state) = self.state.try_lock() else {
            return;
        };
        let mut child = state.child.take();
        let elevated_started_by_app = state.elevated_started_by_app;
        let target_url = state.diagnostics_url.clone();
        state.started_by_app = false;
        state.elevated_started_by_app = false;
        state.last_diagnostics = None;
        drop(state);

        if let Some(child) = child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
            Self::remove_pid_file(&Self::default_pid_path());
            Self::remove_persisted_diagnostics_url();
            return;
        }

        if elevated_started_by_app {
            let mut stopped = Self::request_daemon_shutdown_blocking(&target_url)
                && Self::wait_for_endpoint_down_blocking(&target_url, Duration::from_secs(3));
            if !stopped {
                let pid_path = Self::default_pid_path();
                let _ = Self::terminate_recorded_daemon(&pid_path);
                stopped =
                    Self::wait_for_endpoint_down_blocking(&target_url, Duration::from_secs(2));
            }
            if !stopped {
                let bind_addr = Self::diagnostics_bind_from_url(&target_url);
                if let Some(pid) = Self::find_daemon_pid_by_diagnostics_bind(&bind_addr) {
                    let _ = Self::terminate_pid(pid);
                    stopped =
                        Self::wait_for_endpoint_down_blocking(&target_url, Duration::from_secs(2));
                }
            }
            if stopped {
                Self::remove_pid_file(&Self::default_pid_path());
                Self::remove_persisted_diagnostics_url();
            }
        }
    }
}

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
