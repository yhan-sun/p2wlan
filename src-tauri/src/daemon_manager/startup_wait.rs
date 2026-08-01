use super::*;

impl DaemonManager {
    pub(super) async fn wait_for_endpoint_down(url: &str, timeout: Duration) -> bool {
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
    pub(super) async fn cleanup_stale_windows_daemon_before_start(
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
    pub(super) async fn wait_for_endpoint_or_pid_exit(
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
}
