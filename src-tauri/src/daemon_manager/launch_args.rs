use super::*;

impl DaemonManager {
    pub(super) fn build_args(
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
    pub(super) fn build_macos_elevated_shell(
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
    pub(super) fn windows_command_line_arg_quote(value: &str) -> String {
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
    pub(super) fn windows_wide_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    #[cfg(target_os = "windows")]
    pub(super) fn windows_hidden_command(program: &str) -> Command {
        use std::os::windows::process::CommandExt;

        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut command = Command::new(program);
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    #[cfg(target_os = "windows")]
    pub(super) fn windows_wide_path(value: &Path) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;

        value
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    #[cfg(target_os = "windows")]
    pub(super) fn launch_windows_elevated_daemon(
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
    pub(super) async fn wait_for_endpoint(url: &str, timeout: Duration) -> bool {
        let start_time = Instant::now();
        while start_time.elapsed() < timeout {
            if Self::check_endpoint(url).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        false
    }
}
