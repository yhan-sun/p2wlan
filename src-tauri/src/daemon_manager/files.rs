use super::*;

impl DaemonManager {
    #[cfg(unix)]
    pub(super) fn has_network_admin_privileges() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    pub(super) fn has_network_admin_privileges() -> bool {
        Command::new("net")
            .arg("session")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    pub(super) fn has_network_admin_privileges() -> bool {
        false
    }

    pub(super) fn authorization_message() -> String {
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
    pub(super) fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[cfg(target_os = "macos")]
    pub(super) fn applescript_quote(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    pub fn default_log_dir() -> PathBuf {
        p2wlan_desktop_host::default_log_dir()
    }

    pub(super) fn default_pid_path() -> PathBuf {
        p2wlan_desktop_host::pid_path_from_log_dir(Self::default_log_dir())
    }

    pub(super) fn default_endpoint_path() -> PathBuf {
        p2wlan_desktop_host::endpoint_path_from_log_dir(Self::default_log_dir())
    }

    pub(super) fn persist_diagnostics_url(url: &str) -> Result<(), String> {
        let path = Self::default_endpoint_path();
        Self::persist_diagnostics_url_to_path(&path, url)
    }

    pub(super) fn persist_diagnostics_url_to_path(path: &Path, url: &str) -> Result<(), String> {
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
    pub(super) fn read_persisted_diagnostics_url() -> Option<String> {
        let url = std::fs::read_to_string(Self::default_endpoint_path()).ok()?;
        let url = url.trim().to_string();
        Self::diagnostics_socket_addr_from_url(&url)?;
        Some(url)
    }

    #[cfg(test)]
    pub(super) fn read_persisted_diagnostics_url() -> Option<String> {
        // Keep unit tests isolated from a real desktop daemon that may be
        // running on the developer machine.
        None
    }

    pub(super) fn remove_persisted_diagnostics_url() {
        let path = Self::default_endpoint_path();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }

    #[allow(dead_code)]
    pub(super) fn log_tail(path: &Path, max_lines: usize) -> Option<String> {
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
    pub(super) fn timeout_message_with_log(prefix: &str, log_path: &Path) -> String {
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
    pub(super) fn append_launcher_log(log_path: &Path, line: &str) -> Result<(), String> {
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

    pub(super) fn read_pid_file(pid_path: &Path) -> Option<u32> {
        let raw = std::fs::read_to_string(pid_path).ok()?;
        raw.trim().parse::<u32>().ok()
    }

    pub(super) fn remove_pid_file(pid_path: &Path) {
        if pid_path.exists() {
            let _ = std::fs::remove_file(pid_path);
        }
    }
}
