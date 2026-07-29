//! Read-only desktop host helpers shared by P2WLAN desktop shells.
//!
//! This crate is the narrow P2.1 extraction surface. It contains data types,
//! diagnostics URL helpers, read-only local diagnostics clients, path helpers,
//! and log-tail helpers. It intentionally does not include daemon lifecycle,
//! privilege prompts, process control, or system network changes.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_DIAGNOSTICS_STATUS_URL: &str = "http://127.0.0.1:39277/status";
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_millis(2500);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopHostStartOptions {
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DesktopHostPhase {
    Stopped,
    Authorizing,
    Launching,
    WaitingForDaemon,
    Running,
    Stopping,
    Error,
}

impl DesktopHostPhase {
    pub fn is_busy(self) -> bool {
        matches!(
            self,
            Self::Authorizing | Self::Launching | Self::WaitingForDaemon | Self::Stopping
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopHostOperation {
    pub phase: DesktopHostPhase,
    pub message: String,
    pub started_at_ms: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopHostStatus {
    pub operation: DesktopHostOperation,
    pub diagnostics: Option<serde_json::Value>,
    pub diagnostics_url: String,
    pub diagnostics_alive: bool,
    pub diagnostics_stale: bool,
    pub diagnostics_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopHostPermissionCheck {
    pub id: String,
    pub label: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopHostPermissionStatus {
    pub platform: String,
    pub can_create_tun: String,
    pub can_modify_routes: String,
    pub needs_elevation: bool,
    pub recommended_action: String,
    pub elevated_command_preview: Option<String>,
    pub details: Vec<String>,
    pub checks: Vec<DesktopHostPermissionCheck>,
}

impl DesktopHostPermissionStatus {
    pub fn unsupported(platform: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            can_create_tun: "unknown".to_string(),
            can_modify_routes: "unknown".to_string(),
            needs_elevation: true,
            recommended_action:
                "Desktop permission probing is not wired in this P2.1 helper crate.".to_string(),
            elevated_command_preview: None,
            details: vec![
                "P2.1 exposes the serde model only; platform probes remain in Tauri.".to_string(),
            ],
            checks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DesktopHostErrorKind {
    InvalidDiagnosticsUrl,
    DaemonUnavailable,
    DaemonStatusDecodeFailed,
    PermissionDenied,
    ElevationCancelled,
    DaemonBinaryNotFound,
    ExistingDaemonConflict,
    StartTimeout,
    StopTimeout,
    UnsafePidRefused,
    PlatformUnsupported,
    Io,
    Internal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("{message}")]
pub struct DesktopHostError {
    pub kind: DesktopHostErrorKind,
    pub message: String,
    pub recoverable: bool,
    pub details: Vec<String>,
}

impl DesktopHostError {
    pub fn new(kind: DesktopHostErrorKind, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            kind,
            message: message.into(),
            recoverable,
            details: Vec::new(),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.details.push(detail.into());
        self
    }
}

pub type Result<T> = std::result::Result<T, DesktopHostError>;

#[derive(Debug, Clone)]
pub struct DesktopHostClient {
    client: reqwest::Client,
    timeout: Duration,
}

impl DesktopHostClient {
    pub fn new() -> Result<Self> {
        Self::with_timeout(DEFAULT_REQUEST_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|error| {
                DesktopHostError::new(
                    DesktopHostErrorKind::Internal,
                    "Failed to create diagnostics HTTP client",
                    false,
                )
                .with_detail(error.to_string())
            })?;
        Ok(Self { client, timeout })
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn fetch_health(&self, diagnostics_url: &str) -> Result<bool> {
        let health_url = health_url_from_status_url(diagnostics_url)?;
        let response = self.client.get(health_url).send().await.map_err(|error| {
            DesktopHostError::new(
                DesktopHostErrorKind::DaemonUnavailable,
                "Daemon health endpoint is unreachable",
                true,
            )
            .with_detail(error.to_string())
        })?;
        Ok(response.status().is_success())
    }

    pub async fn fetch_status(&self, diagnostics_url: &str) -> Result<serde_json::Value> {
        let status_url = normalize_diagnostics_url(diagnostics_url)?;
        let response = self.client.get(status_url).send().await.map_err(|error| {
            DesktopHostError::new(
                DesktopHostErrorKind::DaemonUnavailable,
                "Daemon status endpoint is unreachable",
                true,
            )
            .with_detail(error.to_string())
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(DesktopHostError::new(
                DesktopHostErrorKind::DaemonUnavailable,
                format!("Daemon status endpoint returned HTTP {status}"),
                true,
            ));
        }

        response.json::<serde_json::Value>().await.map_err(|error| {
            DesktopHostError::new(
                DesktopHostErrorKind::DaemonStatusDecodeFailed,
                "Daemon status endpoint did not return valid JSON",
                true,
            )
            .with_detail(error.to_string())
        })
    }
}

pub fn normalize_diagnostics_url(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(invalid_url("Diagnostics URL is required"));
    }

    let mut parsed = url::Url::parse(trimmed).map_err(|error| {
        invalid_url("Diagnostics URL is invalid").with_detail(error.to_string())
    })?;

    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(invalid_url("Diagnostics URL must use http or https")),
    }

    diagnostics_socket_addr_from_url(parsed.as_str())?;

    if parsed.path().is_empty() || parsed.path() == "/" {
        parsed.set_path("/status");
    }
    parsed.set_fragment(None);

    Ok(parsed.to_string())
}

pub fn health_url_from_status_url(value: &str) -> Result<String> {
    let normalized = normalize_diagnostics_url(value)?;
    let mut parsed = url::Url::parse(&normalized).map_err(|error| {
        invalid_url("Diagnostics URL is invalid").with_detail(error.to_string())
    })?;
    parsed.set_path("/health");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

pub fn diagnostics_bind_from_url(value: &str) -> Result<String> {
    Ok(diagnostics_socket_addr_from_url(value)?.to_string())
}

pub fn diagnostics_socket_addr_from_url(value: &str) -> Result<SocketAddr> {
    let parsed = url::Url::parse(value).map_err(|error| {
        invalid_url("Diagnostics URL is invalid").with_detail(error.to_string())
    })?;

    let ip = match parsed.host() {
        Some(url::Host::Ipv4(ip)) => IpAddr::V4(ip),
        Some(url::Host::Ipv6(ip)) => IpAddr::V6(ip),
        Some(url::Host::Domain(host)) if host.eq_ignore_ascii_case("localhost") => {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }
        Some(_) => {
            return Err(invalid_url(
                "Diagnostics URL host must be 127.0.0.1, [::1], or localhost",
            ))
        }
        None => return Err(invalid_url("Diagnostics URL must include a host")),
    };

    if !ip.is_loopback() {
        return Err(invalid_url("Diagnostics URL host must be loopback"));
    }

    let Some(port) = parsed.port() else {
        return Err(invalid_url("Diagnostics URL must include a port"));
    };

    Ok(SocketAddr::new(ip, port))
}

pub fn config_path_from_base(base: impl AsRef<Path>) -> PathBuf {
    base.as_ref().join("p2wlan").join("p2pnet-config.json")
}

pub fn default_config_path() -> PathBuf {
    let base = dirs::config_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    config_path_from_base(base)
}

pub fn macos_log_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join("Library").join("Logs").join("p2wlan")
}

pub fn linux_log_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join(".p2wlan").join("logs")
}

pub fn windows_log_dir_from_local_app_data(local_app_data: impl AsRef<Path>) -> PathBuf {
    local_app_data.as_ref().join("p2wlan").join("logs")
}

pub fn default_log_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        dirs::home_dir()
            .map(macos_log_dir_from_home)
            .unwrap_or_else(|| PathBuf::from("."))
    } else if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .map(windows_log_dir_from_local_app_data)
            .unwrap_or_else(|_| PathBuf::from("."))
    } else {
        dirs::home_dir()
            .map(linux_log_dir_from_home)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

pub fn pid_path_from_log_dir(log_dir: impl AsRef<Path>) -> PathBuf {
    log_dir.as_ref().join("p2pnet-daemon.pid")
}

pub fn endpoint_path_from_log_dir(log_dir: impl AsRef<Path>) -> PathBuf {
    log_dir.as_ref().join("p2pnet-daemon.endpoint")
}

pub fn recent_daemon_log_lines(path: impl AsRef<Path>, max_lines: usize) -> Result<Vec<String>> {
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path.as_ref()).map_err(|error| {
        DesktopHostError::new(
            DesktopHostErrorKind::Io,
            "Failed to read daemon log file",
            true,
        )
        .with_detail(error.to_string())
    })?;
    let lines = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].to_vec())
}

fn invalid_url(message: impl Into<String>) -> DesktopHostError {
    DesktopHostError::new(DesktopHostErrorKind::InvalidDiagnosticsUrl, message, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn diagnostics_server(
        health_status: u16,
        health_body: &'static str,
        status_status: u16,
        status_body: &'static str,
        status_content_type: &'static str,
    ) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for _ in 0..8 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = [0_u8; 1024];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                let (status, content_type, body) = if request.starts_with("GET /health ") {
                    (health_status, "text/plain", health_body)
                } else if request.starts_with("GET /status ") {
                    (status_status, status_content_type, status_body)
                } else {
                    (404, "text/plain", "not found")
                };
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    _ => "Status",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
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
    fn diagnostics_url_only_allows_loopback_hosts() {
        assert_eq!(
            normalize_diagnostics_url("http://127.0.0.1:39277/status").unwrap(),
            "http://127.0.0.1:39277/status"
        );
        assert_eq!(
            normalize_diagnostics_url("http://localhost:39277").unwrap(),
            "http://localhost:39277/status"
        );
        assert_eq!(
            normalize_diagnostics_url("http://[::1]:39277/status").unwrap(),
            "http://[::1]:39277/status"
        );

        for url in [
            "http://0.0.0.0:39277/status",
            "http://192.168.1.8:39277/status",
            "http://example.com:39277/status",
            "http://127.0.0.1/status",
            "file://127.0.0.1:39277/status",
        ] {
            assert!(normalize_diagnostics_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn status_url_converts_to_health_url() {
        assert_eq!(
            health_url_from_status_url("http://127.0.0.1:39277/status?verbose=1#frag").unwrap(),
            "http://127.0.0.1:39277/health"
        );
        assert_eq!(
            health_url_from_status_url("http://localhost:39277").unwrap(),
            "http://localhost:39277/health"
        );
    }

    #[test]
    fn diagnostics_bind_parses_loopback_addresses() {
        assert_eq!(
            diagnostics_bind_from_url("http://127.0.0.1:39277/status").unwrap(),
            "127.0.0.1:39277"
        );
        assert_eq!(
            diagnostics_bind_from_url("http://localhost:39278/status").unwrap(),
            "127.0.0.1:39278"
        );
        assert_eq!(
            diagnostics_bind_from_url("http://[::1]:39279/status").unwrap(),
            "[::1]:39279"
        );
    }

    #[tokio::test]
    async fn client_fetch_health_returns_true_for_200() {
        let url = diagnostics_server(
            200,
            "ok\n",
            200,
            r#"{"node_id":"node-1"}"#,
            "application/json",
        )
        .await;
        let client = DesktopHostClient::with_timeout(Duration::from_millis(500)).unwrap();

        assert!(client.fetch_health(&url).await.unwrap());
    }

    #[tokio::test]
    async fn client_fetch_health_returns_false_for_500() {
        let url = diagnostics_server(
            500,
            "error\n",
            200,
            r#"{"node_id":"node-1"}"#,
            "application/json",
        )
        .await;
        let client = DesktopHostClient::with_timeout(Duration::from_millis(500)).unwrap();

        assert!(!client.fetch_health(&url).await.unwrap());
    }

    #[tokio::test]
    async fn client_fetch_health_unreachable_maps_daemon_unavailable() {
        let client = DesktopHostClient::with_timeout(Duration::from_millis(100)).unwrap();

        let error = client
            .fetch_health(&unused_local_status_url())
            .await
            .unwrap_err();

        assert_eq!(error.kind, DesktopHostErrorKind::DaemonUnavailable);
        assert!(error.recoverable);
        assert!(error.message.contains("health endpoint"));
    }

    #[tokio::test]
    async fn client_fetch_status_returns_json() {
        let url = diagnostics_server(
            200,
            "ok\n",
            200,
            r#"{"node_id":"node-1","virtual_ip":"10.20.0.2"}"#,
            "application/json",
        )
        .await;
        let client = DesktopHostClient::with_timeout(Duration::from_millis(500)).unwrap();

        let status = client.fetch_status(&url).await.unwrap();

        assert_eq!(status["node_id"], "node-1");
        assert_eq!(status["virtual_ip"], "10.20.0.2");
    }

    #[tokio::test]
    async fn client_fetch_status_non_2xx_maps_daemon_unavailable() {
        let url = diagnostics_server(200, "ok\n", 503, "busy\n", "text/plain").await;
        let client = DesktopHostClient::with_timeout(Duration::from_millis(500)).unwrap();

        let error = client.fetch_status(&url).await.unwrap_err();

        assert_eq!(error.kind, DesktopHostErrorKind::DaemonUnavailable);
        assert!(error.recoverable);
        assert!(error.message.contains("HTTP 503"));
    }

    #[tokio::test]
    async fn client_fetch_status_non_json_maps_decode_failed() {
        let url = diagnostics_server(200, "ok\n", 200, "not json\n", "text/plain").await;
        let client = DesktopHostClient::with_timeout(Duration::from_millis(500)).unwrap();

        let error = client.fetch_status(&url).await.unwrap_err();

        assert_eq!(error.kind, DesktopHostErrorKind::DaemonStatusDecodeFailed);
        assert!(error.recoverable);
        assert!(error.message.contains("valid JSON"));
    }

    #[test]
    fn log_tail_does_not_exceed_max_lines() {
        let path = unique_test_path("p2wlan-desktop-host-log-tail.log");
        std::fs::write(&path, "one\n\n two \nthree\nfour\n").unwrap();

        let lines = recent_daemon_log_lines(&path, 2).unwrap();
        assert_eq!(lines, vec!["three".to_string(), "four".to_string()]);

        let empty = recent_daemon_log_lines(&path, 0).unwrap();
        assert!(empty.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn serde_field_names_match_desktop_contract() {
        let options = DesktopHostStartOptions {
            diagnostics_url: Some(DEFAULT_DIAGNOSTICS_STATUS_URL.to_string()),
            control_server: Some("http://control.local".to_string()),
            auth_token: Some("token".to_string()),
            network_id: Some("default".to_string()),
            device_name: Some("this-device".to_string()),
            tun_interface: Some("p2pnet0".to_string()),
            udp_bind: Some("0.0.0.0:0".to_string()),
            udp_advertise: None,
            socket_pool: Some("3".to_string()),
            mtu: Some(1420),
        };
        let options_json = serde_json::to_value(options).unwrap();
        assert_eq!(
            options_json.get("diagnosticsUrl").unwrap(),
            DEFAULT_DIAGNOSTICS_STATUS_URL
        );
        assert!(options_json.get("controlServer").is_some());
        assert!(options_json.get("authToken").is_some());
        assert!(options_json.get("networkId").is_some());
        assert!(options_json.get("deviceName").is_some());
        assert!(options_json.get("tunInterface").is_some());
        assert!(options_json.get("udpBind").is_some());
        assert!(options_json.get("udpAdvertise").is_some());
        assert!(options_json.get("socketPool").is_some());

        let status = DesktopHostStatus {
            operation: DesktopHostOperation {
                phase: DesktopHostPhase::WaitingForDaemon,
                message: "waiting".to_string(),
                started_at_ms: 7,
                last_error: None,
            },
            diagnostics: Some(serde_json::json!({"node_id": "node-1"})),
            diagnostics_url: DEFAULT_DIAGNOSTICS_STATUS_URL.to_string(),
            diagnostics_alive: true,
            diagnostics_stale: false,
            diagnostics_error: None,
        };
        let status_json = serde_json::to_value(status).unwrap();
        assert_eq!(
            status_json
                .pointer("/operation/phase")
                .and_then(serde_json::Value::as_str),
            Some("waiting_for_daemon")
        );
        assert!(status_json.get("diagnosticsUrl").is_some());
        assert!(status_json.get("diagnosticsAlive").is_some());
        assert!(status_json.get("diagnosticsStale").is_some());
        assert!(status_json.get("diagnosticsError").is_some());

        let permission = DesktopHostPermissionStatus::unsupported("macos");
        let permission_json = serde_json::to_value(permission).unwrap();
        assert!(permission_json.get("canCreateTun").is_some());
        assert!(permission_json.get("canModifyRoutes").is_some());
        assert!(permission_json.get("needsElevation").is_some());
        assert!(permission_json.get("recommendedAction").is_some());
        assert!(permission_json.get("elevatedCommandPreview").is_some());
    }

    #[test]
    fn pure_path_helpers_match_existing_layout() {
        assert_eq!(
            config_path_from_base("/tmp/config"),
            PathBuf::from("/tmp/config/p2wlan/p2pnet-config.json")
        );
        assert_eq!(
            macos_log_dir_from_home("/Users/test"),
            PathBuf::from("/Users/test/Library/Logs/p2wlan")
        );
        assert_eq!(
            linux_log_dir_from_home("/home/test"),
            PathBuf::from("/home/test/.p2wlan/logs")
        );
        assert_eq!(
            windows_log_dir_from_local_app_data(r"C:\Users\test\AppData\Local"),
            PathBuf::from(r"C:\Users\test\AppData\Local/p2wlan/logs")
        );
        assert_eq!(
            pid_path_from_log_dir("/tmp/logs"),
            PathBuf::from("/tmp/logs/p2pnet-daemon.pid")
        );
        assert_eq!(
            endpoint_path_from_log_dir("/tmp/logs"),
            PathBuf::from("/tmp/logs/p2pnet-daemon.endpoint")
        );
    }

    fn unique_test_path(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}-{stamp}", std::process::id(), name))
    }
}
