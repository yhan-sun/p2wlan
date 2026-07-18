use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonStartOptions {
    pub diagnostics_url: Option<String>,
    pub control_server: Option<String>,
    pub auth_token: Option<String>,
    pub network_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_interface: Option<String>,
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
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct DaemonManager {
    state: Arc<Mutex<ManagedDaemonState>>,
}

impl DaemonManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ManagedDaemonState::new())),
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
        state.operation.clone()
    }

    pub async fn operation_status(&self) -> DaemonOperationStatus {
        self.state.lock().await.operation.clone()
    }

    pub async fn configure(&self, options: DaemonStartOptions) -> DaemonOperationStatus {
        let mut state = self.state.lock().await;
        if let Some(url) = options.diagnostics_url.as_ref() {
            state.diagnostics_url = url.clone();
        }
        state.last_start_options = Some(options);
        state.operation.clone()
    }

    pub async fn desktop_status(&self, diagnostics_url: Option<String>) -> DesktopStatus {
        let target_url = match diagnostics_url {
            Some(url) => url,
            None => self.state.lock().await.diagnostics_url.clone(),
        };
        let diagnostics = self.status(Some(target_url)).await.ok();

        if diagnostics.is_some() {
            let mut state = self.state.lock().await;
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
                    state.operation = DaemonOperationStatus {
                        phase: DaemonOperationPhase::Error,
                        message: "守护进程未响应".to_string(),
                        started_at_ms: now_ms(),
                        last_error: Some("连续 3 次无法访问本地诊断端点".to_string()),
                    };
                }
            }
        }

        DesktopStatus {
            operation: self.operation_status().await,
            diagnostics,
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
                message: "等待系统授权".to_string(),
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
            "p2pnet-daemon.exe"
        } else {
            "p2pnet-daemon"
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
        // Let's check target/debug/p2pnet-daemon or target/release/p2pnet-daemon relative to project root or workspace dirs

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
        if let Ok(path) = which::which("p2pnet-daemon") {
            return Some(path);
        }

        None
    }

    pub async fn check_endpoint(url: &str) -> bool {
        // Simple client request to the health/status endpoint.
        // We use reqwest client with 500ms timeout
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(500))
            .build();
        if let Ok(client) = client {
            if let Ok(res) = client.get(url).send().await {
                return res.status().is_success();
            }
        }
        false
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

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(800))
            .build()
            .map_err(|e| e.to_string())?;

        let res = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("守护进程不可达：{}", e))?;

        if !res.status().is_success() {
            return Err(format!("守护进程返回异常状态码：{}", res.status()));
        }

        let json = res
            .json::<serde_json::Value>()
            .await
            .map_err(|e| format!("解析守护进程状态失败：{}", e))?;

        Ok(json)
    }

    async fn diagnostics_process_id(url: &str) -> Option<u32> {
        let client = reqwest::Client::builder()
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

    async fn request_daemon_shutdown(url: &str) -> bool {
        let Some(shutdown_url) = Self::shutdown_url_from_status_url(url) else {
            return false;
        };
        let client = match reqwest::Client::builder()
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

    pub fn diagnostics_bind_from_url(url: &str) -> String {
        url::Url::parse(url)
            .ok()
            .and_then(|parsed| {
                let host = parsed.host_str()?.to_string();
                let port = parsed.port()?;
                Some(format!("{host}:{port}"))
            })
            .unwrap_or_else(|| "127.0.0.1:39277".to_string())
    }

    pub fn default_config_path() -> PathBuf {
        let base = dirs::config_dir()
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("p2wlan").join("p2pnet-config.json")
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

    #[cfg(target_os = "macos")]
    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[cfg(target_os = "macos")]
    fn applescript_quote(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    pub fn default_log_dir() -> PathBuf {
        if cfg!(target_os = "macos") {
            dirs::home_dir()
                .map(|h| h.join("Library").join("Logs").join("p2wlan"))
                .unwrap_or_else(|| PathBuf::from("."))
        } else if cfg!(target_os = "windows") {
            std::env::var("LOCALAPPDATA")
                .map(|l| PathBuf::from(l).join("p2wlan").join("logs"))
                .unwrap_or_else(|_| PathBuf::from("."))
        } else {
            dirs::home_dir()
                .map(|h| h.join(".p2wlan").join("logs"))
                .unwrap_or_else(|| PathBuf::from("."))
        }
    }

    fn default_pid_path() -> PathBuf {
        Self::default_log_dir().join("p2pnet-daemon.pid")
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
            return command_line.contains("p2pnet-daemon");
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
            stdout.contains("p2pnet-daemon.exe")
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

    fn command_line_matches_daemon_bind(command_line: &str, bind_addr: &str) -> bool {
        command_line.contains("p2pnet-daemon")
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
                "$p = Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*p2pnet-daemon*' -and $_.CommandLine -like '*--diagnostics-bind*' -and $_.CommandLine -like '*{escaped_bind}*' }} | Select-Object -First 1 -ExpandProperty ProcessId; if ($p) {{ $p }}"
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
                if command_line.contains("p2pnet-daemon") {
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
                    "Get-CimInstance Win32_Process -Filter \"Name = 'p2pnet-daemon.exe'\" | Select-Object -ExpandProperty ProcessId",
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

    fn terminate_pid_with_system_authorization(pid: u32) -> Result<(), String> {
        match Self::terminate_pid(pid) {
            Ok(()) => Ok(()),
            Err(err) => {
                #[cfg(target_os = "macos")]
                {
                    let shell = format!(
                        "kill -TERM {pid} 2>/dev/null || true; sleep 2; kill -KILL {pid} 2>/dev/null || true"
                    );
                    let script = format!(
                        "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
                        Self::applescript_quote(&shell),
                        Self::applescript_quote("p2wlan 需要管理员权限以停止 TUN 守护进程。p2wlan 不会读取或保存你的密码。")
                    );
                    let output = Command::new("osascript")
                        .arg("-e")
                        .arg(script)
                        .output()
                        .map_err(|e| format!("无法打开系统授权停止守护进程：{e}"))?;
                    if output.status.success() {
                        return Ok(());
                    }
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    if stderr.contains("-128") {
                        return Err("已取消管理员授权，TUN 守护进程仍在运行。".to_string());
                    }
                    Err(if stderr.is_empty() {
                        format!("管理员授权停止守护进程失败：{err}")
                    } else {
                        format!("管理员授权停止守护进程失败：{stderr}")
                    })
                }

                #[cfg(target_os = "windows")]
                {
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
                    return Err(format!(
                        "无法通过 Windows UAC 停止守护进程，错误码：{code}；原始错误：{err}"
                    ));
                }

                #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                {
                    Err(err)
                }
            }
        }
    }

    fn terminate_daemons_by_name_with_system_authorization() -> Result<bool, String> {
        #[cfg(target_os = "macos")]
        {
            let shell =
                "pkill -TERM -x p2pnet-daemon 2>/dev/null || true; sleep 2; pkill -KILL -x p2pnet-daemon 2>/dev/null || true";
            let script = format!(
                "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
                Self::applescript_quote(shell),
                Self::applescript_quote("p2wlan 需要管理员权限以停止残留的 TUN 守护进程。p2wlan 不会读取或保存你的密码。")
            );
            let output = Command::new("osascript")
                .arg("-e")
                .arg(script)
                .output()
                .map_err(|e| format!("无法打开系统授权停止残留守护进程：{e}"))?;
            if output.status.success() {
                return Ok(true);
            }
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.contains("-128") {
                return Err("已取消管理员授权，TUN 守护进程仍在运行。".to_string());
            }
            Err(if stderr.is_empty() {
                "管理员授权停止残留守护进程失败。".to_string()
            } else {
                format!("管理员授权停止残留守护进程失败：{stderr}")
            })
        }

        #[cfg(target_os = "windows")]
        {
            use std::mem::size_of;
            use windows_sys::Win32::Foundation::GetLastError;
            use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
            use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

            let script = "Get-Process -Name p2pnet-daemon -ErrorAction SilentlyContinue | Stop-Process -Force";
            let verb = Self::windows_wide_str("runas");
            let file = Self::windows_wide_str("powershell.exe");
            let parameters = Self::windows_wide_str(&format!(
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command {}",
                Self::windows_command_line_arg_quote(script)
            ));
            let mut info = unsafe { std::mem::zeroed::<SHELLEXECUTEINFOW>() };
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = parameters.as_ptr();
            info.nShow = SW_HIDE;

            let launched = unsafe { ShellExecuteExW(&mut info) };
            if launched != 0 {
                return Ok(true);
            }
            let code = unsafe { GetLastError() };
            if code == 1223 {
                return Err("已取消 Windows 管理员授权，TUN 守护进程仍在运行。".to_string());
            }
            return Err(format!(
                "无法通过 Windows UAC 停止残留守护进程，错误码：{code}"
            ));
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(false)
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
            .map(|command_line| command_line.contains("p2pnet-daemon"))
            .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
        if !verified {
            Self::remove_pid_file(pid_path);
            return Err(format!(
                "PID 文件指向的进程不是 p2pnet-daemon，已拒绝结束进程：{}",
                pid_path.display()
            ));
        }
        Self::terminate_pid_with_system_authorization(pid)?;
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
        let mut push_pair = |flag: &str, value: Option<&str>| {
            if let Some(value) = value {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    args.push(flag.to_string());
                    args.push(trimmed.to_string());
                }
            }
        };
        push_pair("--control", options.control_server.as_deref());
        push_pair("--token", options.auth_token.as_deref());
        push_pair("--network", options.network_id.as_deref());
        push_pair("--device-name", options.device_name.as_deref());
        push_pair("--interface", options.tun_interface.as_deref());
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
        let options = options.unwrap_or(DaemonStartOptions {
            diagnostics_url: None,
            control_server: None,
            auth_token: None,
            network_id: None,
            device_name: None,
            tun_interface: None,
            mtu: None,
        });
        let target_url = {
            let state = self.state.lock().await;
            options
                .diagnostics_url
                .clone()
                .unwrap_or_else(|| state.diagnostics_url.clone())
        };

        // 1. Is daemon already running?
        if Self::check_endpoint(&target_url).await {
            return Ok("守护进程已经运行。".to_string());
        }

        if !Self::has_network_admin_privileges() {
            return Err(
                "当前桌面客户端没有网络管理权限，不能直接创建 TUN 网卡或修改路由。请在配置向导中复制 sudo 命令启动 p2pnet-daemon，或先保持一个外部 sudo daemon 运行。"
                    .to_string(),
            );
        }

        // 2. Resolve binary path
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let bin_path = Self::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN"), &current_dir)
            .ok_or_else(|| "找不到 p2pnet-daemon 可执行文件。请确认它与桌面客户端在同一目录，或设置 P2WLAN_DAEMON_BIN。".to_string())?;

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

        let child = cmd
            .spawn()
            .map_err(|e| format!("启动守护进程失败：{}", e))?;

        // 5. Update state
        {
            let mut state = self.state.lock().await;
            state.child = Some(child);
            state.started_by_app = true;
            state.elevated_started_by_app = false;
            state.diagnostics_url = target_url.clone();
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
        let options = options.unwrap_or(DaemonStartOptions {
            diagnostics_url: None,
            control_server: None,
            auth_token: None,
            network_id: None,
            device_name: None,
            tun_interface: None,
            mtu: None,
        });
        let target_url = {
            let state = self.state.lock().await;
            options
                .diagnostics_url
                .clone()
                .unwrap_or_else(|| state.diagnostics_url.clone())
        };

        if Self::check_endpoint(&target_url).await {
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

        #[cfg(target_os = "macos")]
        {
            self.set_operation(
                DaemonOperationPhase::Authorizing,
                "等待 macOS 系统授权",
                None,
            )
            .await;
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let bin_path = Self::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN"), &current_dir)
                .ok_or_else(|| "找不到 p2pnet-daemon 可执行文件。".to_string())?;
            let bind_addr = Self::diagnostics_bind_from_url(&target_url);
            let config_path = Self::default_config_path();
            let log_dir = Self::default_log_dir();
            let log_path = log_dir.join("p2pnet-daemon.log");
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

            if Self::wait_for_endpoint(&target_url, Duration::from_secs(20)).await {
                self.set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
                    .await;
                Ok("TUN 模式已通过管理员权限启动。".to_string())
            } else {
                let mut state = self.state.lock().await;
                state.elevated_started_by_app = false;
                Err(Self::timeout_message_with_log(
                    "已完成管理员授权，但守护进程未在 20 秒内响应诊断端点。",
                    &log_path,
                ))
            }
        }

        #[cfg(target_os = "windows")]
        {
            self.set_operation(
                DaemonOperationPhase::Authorizing,
                "等待 Windows 管理员授权",
                None,
            )
            .await;
            let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let bin_path = Self::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN"), &current_dir)
                .ok_or_else(|| "找不到 p2pnet-daemon.exe 可执行文件。".to_string())?;
            let bind_addr = Self::diagnostics_bind_from_url(&target_url);
            let config_path = Self::default_config_path();
            let log_dir = Self::default_log_dir();
            let log_path = log_dir.join("p2pnet-daemon.log");
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
            diagnostics_url.unwrap_or_else(|| state.diagnostics_url.clone())
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
            return Ok("已停止 TUN 守护进程。".to_string());
        }

        let pid_path = Self::default_pid_path();
        let mut terminated = false;
        if let Some(pid) = Self::diagnostics_process_id(&target_url).await {
            let verified = Self::process_command_line(pid)
                .map(|command_line| command_line.contains("p2pnet-daemon"))
                .unwrap_or_else(|| Self::process_name_matches_daemon(pid));
            if verified {
                Self::terminate_pid_with_system_authorization(pid)?;
                terminated = true;
            }
        }
        if !terminated {
            terminated = Self::terminate_recorded_daemon(&pid_path)?;
        }
        if !terminated {
            let bind_addr = Self::diagnostics_bind_from_url(&target_url);
            if let Some(pid) = Self::find_daemon_pid_by_diagnostics_bind(&bind_addr) {
                Self::terminate_pid_with_system_authorization(pid)?;
                terminated = true;
            }
        }
        if !terminated {
            if let Some(pid) = Self::find_single_daemon_pid() {
                Self::terminate_pid_with_system_authorization(pid)?;
                terminated = true;
            }
        }

        let mut stopped = Self::wait_for_endpoint_down(&target_url, Duration::from_secs(3)).await;
        if !stopped {
            terminated = Self::terminate_daemons_by_name_with_system_authorization()? || terminated;
            stopped = Self::wait_for_endpoint_down(&target_url, Duration::from_secs(3)).await;
        }

        {
            let mut state = self.state.lock().await;
            state.started_by_app = false;
            state.elevated_started_by_app = false;
            if stopped {
                state.operation = DaemonOperationStatus::stopped();
                state.consecutive_status_failures = 0;
            }
        }

        if terminated && stopped {
            Ok("已停止 TUN 守护进程。".to_string())
        } else if stopped {
            Ok("守护进程已经停止。".to_string())
        } else {
            Err(format!(
                "检测到守护进程仍在运行，但没有找到可安全结束的客户端记录。请手动结束 p2pnet-daemon，或重启后再启动 TUN。诊断地址：{}",
                target_url
            ))
        }
    }

    pub fn cleanup(&self) {
        if let Ok(mut state) = self.state.try_lock() {
            if state.started_by_app {
                if let Some(mut child) = state.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            } else if state.elevated_started_by_app {
                let pid_path = Self::default_pid_path();
                if Self::terminate_recorded_daemon(&pid_path) != Ok(true) {
                    let bind_addr = Self::diagnostics_bind_from_url(&state.diagnostics_url);
                    if let Some(pid) = Self::find_daemon_pid_by_diagnostics_bind(&bind_addr) {
                        let _ = Self::terminate_pid_with_system_authorization(pid);
                    }
                }
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
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_options(diagnostics_url: String) -> DaemonStartOptions {
        DaemonStartOptions {
            diagnostics_url: Some(diagnostics_url),
            control_server: Some("http://127.0.0.1:18080".to_string()),
            auth_token: Some("test-token".to_string()),
            network_id: Some("test-network".to_string()),
            device_name: Some("test-device".to_string()),
            tun_interface: Some("p2wlan-test".to_string()),
            mtu: Some(1420),
        }
    }

    async fn status_server_once(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}/status")
    }

    fn unused_local_status_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        format!("http://{address}/status")
    }

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
    async fn desktop_status_requires_three_failures_before_marking_running_daemon_error() {
        let manager = DaemonManager::new();
        manager
            .set_operation(DaemonOperationPhase::Running, "TUN 已连接", None)
            .await;
        let url = unused_local_status_url();

        for expected_failures in 1..=2 {
            let status = manager.desktop_status(Some(url.clone())).await;
            assert_eq!(status.operation.phase, DaemonOperationPhase::Running);
            assert_eq!(
                manager.state.lock().await.consecutive_status_failures,
                expected_failures
            );
        }

        let status = manager.desktop_status(Some(url)).await;
        assert_eq!(status.operation.phase, DaemonOperationPhase::Error);
        assert_eq!(
            status.operation.last_error.as_deref(),
            Some("连续 3 次无法访问本地诊断端点")
        );
    }

    #[test]
    fn test_resolve_daemon_binary_priority() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fake_bin = temp_dir.path().join(if cfg!(windows) {
            "p2pnet-daemon.exe"
        } else {
            "p2pnet-daemon"
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
    }

    #[test]
    fn test_command_line_matches_daemon_bind() {
        assert!(DaemonManager::command_line_matches_daemon_bind(
            "/tmp/p2pnet-daemon --diagnostics-bind 127.0.0.1:39277 --control http://x",
            "127.0.0.1:39277"
        ));
        assert!(!DaemonManager::command_line_matches_daemon_bind(
            "/tmp/p2pnet-daemon --diagnostics-bind 127.0.0.1:39278",
            "127.0.0.1:39277"
        ));
        assert!(!DaemonManager::command_line_matches_daemon_bind(
            "/tmp/other --diagnostics-bind 127.0.0.1:39277",
            "127.0.0.1:39277"
        ));
    }

    #[test]
    fn test_default_config_path_uses_p2wlan_config_dir() {
        let path = DaemonManager::default_config_path();
        assert!(path.ends_with("p2wlan/p2pnet-config.json"));
    }

    #[test]
    fn test_daemon_start_options_deserialize_from_camel_case() {
        let json = serde_json::json!({
            "diagnosticsUrl": "http://127.0.0.1:39277/status",
            "controlServer": "http://127.0.0.1:8080",
            "authToken": "token",
            "networkId": "default",
            "deviceName": "mac",
            "tunInterface": "p2pnet0",
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
        assert_eq!(options.tun_interface.as_deref(), Some("p2pnet0"));
        assert_eq!(options.mtu, Some(1420));
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
        let bin_path = PathBuf::from("/tmp/p2 wlan/p2pnet-daemon");
        let config_path = PathBuf::from("/tmp/p2 wlan/config/p2pnet-config.json");
        let log_dir = PathBuf::from("/tmp/p2 wlan/logs");
        let log_path = log_dir.join("p2pnet-daemon.log");
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
            &log_dir.join("p2pnet-daemon.pid"),
        );
        assert!(!shell.contains("nohup"));
        assert!(shell.contains("< /dev/null &"));
        assert!(shell.contains("P2WLAN_DAEMON_BIN='/tmp/p2 wlan/p2pnet-daemon'"));
        assert!(shell.contains("'tok'\\''en'"));
    }
}
