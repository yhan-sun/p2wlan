use super::*;

impl DaemonManager {
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

    pub(super) fn desktop_host_status_error(
        error: p2wlan_desktop_host::DesktopHostError,
    ) -> String {
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

    pub(super) async fn diagnostics_process_id(url: &str) -> Option<u32> {
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

    pub(super) fn shutdown_url_from_status_url(url: &str) -> Option<String> {
        let mut parsed = url::Url::parse(url).ok()?;
        parsed.set_path("/shutdown");
        parsed.set_query(None);
        Some(parsed.to_string())
    }

    pub(super) fn health_url_from_status_url(url: &str) -> Option<String> {
        let mut parsed = url::Url::parse(url).ok()?;
        parsed.set_path("/health");
        parsed.set_query(None);
        Some(parsed.to_string())
    }

    pub(super) async fn request_daemon_shutdown(url: &str) -> bool {
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

    pub(super) fn local_http_status_blocking(
        url: &str,
        method: &str,
        timeout: Duration,
    ) -> Option<u16> {
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

    pub(super) fn request_daemon_shutdown_blocking(url: &str) -> bool {
        let Some(shutdown_url) = Self::shutdown_url_from_status_url(url) else {
            return false;
        };
        Self::local_http_status_blocking(&shutdown_url, "POST", Duration::from_millis(800))
            .is_some_and(|code| (200..300).contains(&code))
    }

    pub(super) fn check_endpoint_blocking(url: &str) -> bool {
        let health_url = Self::health_url_from_status_url(url).unwrap_or_else(|| url.to_string());
        Self::local_http_status_blocking(&health_url, "GET", Duration::from_millis(800))
            .is_some_and(|code| (200..300).contains(&code))
    }

    pub(super) fn wait_for_endpoint_down_blocking(url: &str, timeout: Duration) -> bool {
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

    pub(super) fn diagnostics_socket_addr_from_url(url: &str) -> Option<SocketAddr> {
        p2wlan_desktop_host::diagnostics_socket_addr_from_url(url).ok()
    }

    pub(super) fn available_diagnostics_url(preferred_url: &str) -> Result<String, String> {
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
}
