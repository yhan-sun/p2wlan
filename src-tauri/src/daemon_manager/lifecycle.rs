use super::*;

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

    pub(super) async fn set_operation(
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

    pub(super) async fn tracked_daemon_process_alive(&self) -> bool {
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
}
