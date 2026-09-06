#[derive(Debug, Clone, PartialEq, Eq)]
enum UserEvent {
    Refresh,
    State(DaemonState),
    DaemonActionFinished {
        action: DaemonAction,
        error: Option<String>,
    },
    StartDaemon,
    StopDaemon,
    OpenClient,
    OpenLogs,
    CopyPeerIp(String),
    Quit,
    StatusInfo,
    NetworkInfo,
    NoDevices,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonAction {
    Start,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayDevice {
    name: String,
    virtual_ip: String,
    path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrayDeviceMenu {
    devices: Vec<TrayDevice>,
    total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonState {
    running: bool,
    busy: bool,
    status_label: String,
    virtual_ip: String,
    online: Option<u64>,
    latency_ms: Option<u64>,
    total_bytes: Option<u64>,
    speed_bytes_per_second: Option<u64>,
    devices: TrayDeviceMenu,
    tooltip: String,
}

impl DaemonState {
    fn offline() -> Self {
        Self {
            running: false,
            busy: false,
            status_label: "未启动".to_string(),
            virtual_ip: "—".to_string(),
            online: None,
            latency_ms: None,
            total_bytes: None,
            speed_bytes_per_second: None,
            devices: TrayDeviceMenu::default(),
            tooltip: "p2wlan：未启动".to_string(),
        }
    }

    fn session_error(message: String) -> Self {
        Self {
            running: true,
            busy: false,
            status_label: "诊断会话不可用".to_string(),
            virtual_ip: "—".to_string(),
            online: None,
            latency_ms: None,
            total_bytes: None,
            speed_bytes_per_second: None,
            devices: TrayDeviceMenu::default(),
            tooltip: format!("p2wlan：{message}"),
        }
    }
}
