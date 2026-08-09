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
                "P2.1 exposes the serde model only; platform probes remain in the native client."
                    .to_string(),
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
