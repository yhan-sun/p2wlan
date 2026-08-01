use super::*;

impl DaemonManager {
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
}
