#[derive(Debug)]
enum UserEvent {
    Menu(MenuEvent),
    Refresh,
    State(DaemonState),
    DaemonActionFinished {
        action: DaemonAction,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Copy)]
enum DaemonAction {
    Start,
    Stop,
}

#[derive(Clone)]
struct TrayMenu {
    status: MenuItem,
    network: MenuItem,
    devices: Submenu,
    start_daemon: MenuItem,
    stop_daemon: MenuItem,
    open_client: MenuItem,
    open_logs: MenuItem,
    quit: MenuItem,
}

impl TrayMenu {
    fn new() -> Result<(Self, Menu), Box<dyn Error>> {
        let status = MenuItem::with_id("status", "状态：未启动", false, None);
        let network = MenuItem::with_id(
            "network",
            "虚拟 IP：— · 在线设备：— · 延迟：— · 速度：—",
            false,
            None,
        );
        let open_client = MenuItem::with_id("open-client", "打开控制台", true, None);
        let start_daemon = MenuItem::with_id("start-daemon", "启动 TUN", true, None);
        let stop_daemon = MenuItem::with_id("stop-daemon", "停止 TUN", false, None);
        let no_devices = MenuItem::with_id("no-devices", "暂无在线设备", false, None);
        let devices = Submenu::with_id_and_items("devices", "设备（0）", true, &[&no_devices])?;
        let open_logs = MenuItem::with_id("open-logs", "打开日志", true, None);
        let quit = MenuItem::with_id("quit", "退出 p2wlan", true, None);
        let separator = PredefinedMenuItem::separator();
        let separator2 = PredefinedMenuItem::separator();
        let menu = Menu::with_items(&[
            &status,
            &network,
            &separator,
            &open_client,
            &start_daemon,
            &stop_daemon,
            &devices,
            &separator,
            &open_logs,
            &separator2,
            &quit,
        ])?;
        Ok((
            Self {
                status,
                network,
                devices,
                start_daemon,
                stop_daemon,
                open_client,
                open_logs,
                quit,
            },
            menu,
        ))
    }

    fn id_for(&self, event: &MenuEvent) -> MenuAction {
        let id = event.id().0.as_str();
        if id == self.start_daemon.id().0.as_str() {
            MenuAction::StartDaemon
        } else if id == self.stop_daemon.id().0.as_str() {
            MenuAction::StopDaemon
        } else if id == self.open_client.id().0.as_str() {
            MenuAction::OpenClient
        } else if id == self.open_logs.id().0.as_str() {
            MenuAction::OpenLogs
        } else if id == self.quit.id().0.as_str() {
            MenuAction::Quit
        } else if let Some(ip) = copy_ip_from_menu_id(id) {
            MenuAction::CopyPeerIp(ip.to_string())
        } else {
            MenuAction::None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MenuAction {
    None,
    StartDaemon,
    StopDaemon,
    OpenClient,
    OpenLogs,
    CopyPeerIp(String),
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrayDevice {
    name: String,
    virtual_ip: String,
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
