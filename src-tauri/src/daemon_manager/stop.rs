use super::*;

impl DaemonManager {
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
