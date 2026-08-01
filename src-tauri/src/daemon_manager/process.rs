use super::*;

impl DaemonManager {
    pub(super) fn process_exists(pid: u32) -> bool {
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

    pub(super) fn process_name_matches_daemon(pid: u32) -> bool {
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

    pub(super) fn process_command_line(pid: u32) -> Option<String> {
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

    pub(super) fn daemon_command_line_uses_binary(command_line: &str, expected_bin: &Path) -> bool {
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

    pub(super) fn existing_daemon_binary_conflict(pid: u32, expected_bin: &Path) -> Option<String> {
        let command_line = Self::process_command_line(pid)?;
        if Self::daemon_command_line_uses_binary(&command_line, expected_bin) {
            return None;
        }

        Some(format!(
            "检测到已有 p2wlan-daemon 占用诊断端点，但它不是当前客户端要启动的守护进程。\n当前运行 PID：{pid}\n当前运行命令：{command_line}\n当前需要：{}\n请先停止 TUN，或执行：sudo kill {pid}",
            expected_bin.display()
        ))
    }

    pub(super) fn command_line_matches_daemon_bind(command_line: &str, bind_addr: &str) -> bool {
        command_line.contains("p2wlan-daemon")
            && command_line.contains("--diagnostics-bind")
            && command_line.contains(bind_addr)
    }

    pub(super) fn find_daemon_pid_by_diagnostics_bind(bind_addr: &str) -> Option<u32> {
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

    pub(super) fn find_single_daemon_pid() -> Option<u32> {
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

    pub(super) fn terminate_pid(pid: u32) -> Result<(), String> {
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
    pub(super) fn terminate_pid_with_system_authorization(pid: u32) -> Result<(), String> {
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

    pub(super) fn terminate_recorded_daemon(pid_path: &Path) -> Result<bool, String> {
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
}
