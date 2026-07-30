use std::{
    env,
    error::Error,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};

use tao::{
    event::{Event, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder},
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    Icon, TrayIcon, TrayIconBuilder,
};

const STATUS_URL: &str = p2wlan_desktop_host::DEFAULT_DIAGNOSTICS_STATUS_URL;
const COPY_PEER_IP_PREFIX: &str = "copy-peer-ip:";
const MAX_TRAY_DEVICES: usize = 12;
const DAEMON_NAME: &str = if cfg!(windows) {
    "p2wlan-daemon.exe"
} else {
    "p2wlan-daemon"
};

#[derive(Debug)]
enum UserEvent {
    Menu(MenuEvent),
    Refresh,
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
        let network = MenuItem::with_id("network", "虚拟 IP：— · 在线设备：—", false, None);
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
            devices: TrayDeviceMenu::default(),
            tooltip: "p2wlan：未启动".to_string(),
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("p2wlan-tray failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    configure_platform_event_loop(&mut event_loop);

    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    let proxy = event_loop.create_proxy();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        if proxy.send_event(UserEvent::Refresh).is_err() {
            break;
        }
    });

    let (menu_items, menu) = TrayMenu::new()?;
    let tray_icon = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("P2WLAN")
        .with_icon(tray_icon_image(false)?)
        .with_icon_as_template(false)
        .build()?;

    let mut app = TrayApp {
        menu: menu_items,
        tray_icon,
        last_state: DaemonState::offline(),
    };
    app.refresh_state();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) | Event::UserEvent(UserEvent::Refresh) => {
                app.refresh_state();
            }
            Event::UserEvent(UserEvent::Menu(event)) => match app.menu.id_for(&event) {
                MenuAction::StartDaemon => app.start_daemon(),
                MenuAction::StopDaemon => app.stop_daemon(),
                MenuAction::OpenClient => app.open_client(),
                MenuAction::OpenLogs => app.open_logs(),
                MenuAction::CopyPeerIp(ip) => app.copy_peer_ip(&ip),
                MenuAction::Quit => {
                    app.quit_p2wlan();
                    *control_flow = ControlFlow::Exit;
                }
                MenuAction::None => {}
            },
            _ => {}
        }
    });
}

#[cfg(target_os = "macos")]
fn configure_platform_event_loop(event_loop: &mut tao::event_loop::EventLoop<UserEvent>) {
    use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
    event_loop.set_activation_policy(ActivationPolicy::Accessory);
    event_loop.set_dock_visibility(false);
}

#[cfg(not(target_os = "macos"))]
fn configure_platform_event_loop(_event_loop: &mut tao::event_loop::EventLoop<UserEvent>) {}

struct TrayApp {
    menu: TrayMenu,
    tray_icon: TrayIcon,
    last_state: DaemonState,
}

impl TrayApp {
    fn refresh_state(&mut self) {
        self.last_state = query_daemon_state();
        self.apply_state();
    }

    fn apply_state(&mut self) {
        self.menu
            .status
            .set_text(format!("状态：{}", self.last_state.status_label));
        self.menu.network.set_text(match self.last_state.online {
            Some(count) => format!(
                "虚拟 IP：{} · 在线设备：{count}",
                self.last_state.virtual_ip
            ),
            None => "虚拟 IP：— · 在线设备：—".to_string(),
        });
        self.menu.stop_daemon.set_enabled(self.last_state.running);
        self.menu
            .start_daemon
            .set_enabled(!self.last_state.running && !self.last_state.busy);
        rebuild_device_menu(&self.menu.devices, &self.last_state.devices);
        let _ = self
            .tray_icon
            .set_tooltip(Some(self.last_state.tooltip.as_str()));
        let _ = self.tray_icon.set_icon(Some(
            tray_icon_image(self.last_state.running).expect("static tray icon should be valid"),
        ));
    }

    fn start_daemon(&mut self) {
        self.set_status("状态：正在启动");
        match start_daemon() {
            Ok(()) => self.set_status("状态：正在建立虚拟网络"),
            Err(error) => {
                eprintln!("p2wlan-tray start failed: {error}");
                self.set_status(format!("启动失败：{error}"));
            }
        }
        thread::sleep(Duration::from_millis(700));
        self.refresh_state();
    }

    fn stop_daemon(&mut self) {
        self.set_status("状态：正在停止");
        match stop_daemon() {
            Ok(()) => self.set_status("状态：停止请求已发送"),
            Err(error) => self.set_status(format!("停止失败：{error}")),
        }
        thread::sleep(Duration::from_millis(700));
        self.refresh_state();
    }

    fn open_client(&mut self) {
        if let Err(error) = open_flutter_client() {
            eprintln!("p2wlan-tray open client failed: {error}");
            self.set_status(format!("打开控制台失败：{error}"));
        }
    }

    fn open_logs(&mut self) {
        if let Err(error) = open_log_directory() {
            self.set_status(format!("打开日志失败：{error}"));
        }
    }

    fn copy_peer_ip(&mut self, ip: &str) {
        if let Err(error) = copy_to_clipboard(ip) {
            self.set_status(format!("复制失败：{error}"));
        }
    }

    fn quit_p2wlan(&mut self) {
        self.set_status("状态：正在退出");
        let _ = stop_daemon();
    }

    fn set_status(&self, text: impl AsRef<str>) {
        self.menu.status.set_text(text.as_ref());
        let _ = self.tray_icon.set_tooltip(Some(text.as_ref()));
    }
}

fn query_daemon_state() -> DaemonState {
    let client = match reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(1200))
        .build()
    {
        Ok(client) => client,
        Err(_) => return DaemonState::offline(),
    };
    let status_url = match p2wlan_desktop_host::normalize_diagnostics_url(STATUS_URL) {
        Ok(url) => url,
        Err(_) => return DaemonState::offline(),
    };
    let health_url = match p2wlan_desktop_host::health_url_from_status_url(&status_url) {
        Ok(url) => url,
        Err(_) => return DaemonState::offline(),
    };
    let Ok(health) = client.get(health_url).send() else {
        return DaemonState::offline();
    };
    if !health.status().is_success() {
        return DaemonState::offline();
    }
    let status = client
        .get(status_url)
        .send()
        .ok()
        .and_then(|response| response.json::<serde_json::Value>().ok());
    let virtual_ip = status
        .as_ref()
        .and_then(|value| value.get("virtual_ip"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("—")
        .to_string();
    let online = status.as_ref().and_then(|value| {
        let stats = value.get("stats")?;
        Some(
            stats
                .get("direct_connections")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default()
                + stats
                    .get("relay_connections")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
        )
    });
    let peer_count = status
        .as_ref()
        .and_then(|value| value.get("stats"))
        .and_then(|stats| stats.get("total_peers"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let devices = status.as_ref().map(tray_device_menu).unwrap_or_default();
    DaemonState {
        running: true,
        busy: false,
        status_label: "已连接".to_string(),
        virtual_ip: virtual_ip.clone(),
        online,
        devices,
        tooltip: match online {
            Some(count) => format!("p2wlan：已连接 · {virtual_ip} · {count} 台在线"),
            None => format!("p2wlan：已连接 · {peer_count} 台设备"),
        },
    }
}

fn tray_device_menu(status: &serde_json::Value) -> TrayDeviceMenu {
    let Some(peers) = status.get("peers").and_then(serde_json::Value::as_array) else {
        return TrayDeviceMenu::default();
    };

    let mut devices = peers
        .iter()
        .filter_map(|peer| {
            let virtual_ip = peer.get("virtual_ip").and_then(serde_json::Value::as_str)?;
            virtual_ip.parse::<IpAddr>().ok()?;
            let node_id = peer
                .get("node_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let device_name = peer
                .get("device_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            Some(TrayDevice {
                name: display_device_name(device_name, node_id),
                virtual_ip: virtual_ip.to_string(),
            })
        })
        .collect::<Vec<_>>();

    devices.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.virtual_ip.cmp(&right.virtual_ip))
    });
    devices.dedup_by(|left, right| left.virtual_ip == right.virtual_ip);

    let total = devices.len();
    devices.truncate(MAX_TRAY_DEVICES);
    TrayDeviceMenu { devices, total }
}

fn display_device_name(device_name: &str, node_id: &str) -> String {
    let normalized = device_name.split_whitespace().collect::<Vec<_>>().join(" ");
    let fallback = if node_id.is_empty() {
        "未知设备".to_string()
    } else {
        node_id.chars().take(12).collect()
    };
    let name = if normalized.is_empty() {
        fallback
    } else {
        normalized
    };

    let mut chars = name.chars();
    let visible = chars.by_ref().take(28).collect::<String>();
    if chars.next().is_some() {
        format!("{visible}...")
    } else {
        visible
    }
}

fn rebuild_device_menu(submenu: &Submenu, device_menu: &TrayDeviceMenu) {
    while !submenu.items().is_empty() {
        let _ = submenu.remove_at(0);
    }

    submenu.set_text(format!("设备（{}）", device_menu.total));
    if device_menu.devices.is_empty() {
        let empty = MenuItem::with_id("no-devices", "暂无在线设备", false, None);
        let _ = submenu.append(&empty);
        return;
    }

    for device in &device_menu.devices {
        let item = MenuItem::with_id(
            format!("{COPY_PEER_IP_PREFIX}{}", device.virtual_ip),
            format!("{} · {}", device.name, device.virtual_ip),
            true,
            None,
        );
        let _ = submenu.append(&item);
    }

    if device_menu.total > device_menu.devices.len() {
        let remaining = device_menu.total - device_menu.devices.len();
        let overflow = MenuItem::with_id(
            "more-devices",
            format!("另有 {remaining} 台设备，请在控制台查看"),
            false,
            None,
        );
        let _ = submenu.append(&overflow);
    }
}

fn copy_ip_from_menu_id(id: &str) -> Option<&str> {
    let ip = id.strip_prefix(COPY_PEER_IP_PREFIX)?;
    ip.parse::<IpAddr>().ok().map(|_| ip)
}

fn stop_daemon() -> Result<(), Box<dyn Error>> {
    let shutdown_url = shutdown_url()?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()?
        .post(shutdown_url)
        .send()?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("daemon returned HTTP {}", response.status()).into())
    }
}

fn shutdown_url() -> Result<String, Box<dyn Error>> {
    let status_url = p2wlan_desktop_host::normalize_diagnostics_url(STATUS_URL)?;
    let mut parsed = reqwest::Url::parse(&status_url)?;
    parsed.set_path("/shutdown");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

fn start_daemon() -> Result<(), Box<dyn Error>> {
    if query_daemon_state().running {
        return Ok(());
    }
    let daemon = locate_daemon_binary().ok_or("p2wlan-daemon not found")?;
    let config_path = p2wlan_desktop_host::default_config_path();
    let log_dir = p2wlan_desktop_host::default_log_dir();
    let log_path = log_dir.join("p2wlan-daemon.log");
    let pid_path = p2wlan_desktop_host::pid_path_from_log_dir(&log_dir);
    let bind = p2wlan_desktop_host::diagnostics_bind_from_url(STATUS_URL)?;
    let managed = config_has_token(&config_path);

    fs::create_dir_all(&log_dir)?;
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut args = vec![
        "--config".to_string(),
        config_path.display().to_string(),
        "--diagnostics-bind".to_string(),
        bind,
        "--log-file".to_string(),
        log_path.display().to_string(),
    ];
    if managed {
        args.push("--managed".to_string());
    } else {
        args.push("--manual".to_string());
    }

    start_daemon_platform(&daemon, &args, &config_path, &log_dir, &log_path, &pid_path)
}

#[cfg(target_os = "macos")]
fn start_daemon_platform(
    daemon: &Path,
    args: &[String],
    config_path: &Path,
    log_dir: &Path,
    log_path: &Path,
    pid_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let owner = user_owner_for_paths();
    let repair = owner.as_ref().map(|owner| {
        format!(
            "owner={}; group=\"$(/usr/bin/id -gn \"$owner\" 2>/dev/null || /bin/echo staff)\"; /usr/sbin/chown -R \"$owner:$group\" {} {} >/dev/null 2>&1 || true; ",
            shell_quote(owner),
            shell_quote(&config_dir.display().to_string()),
            shell_quote(&log_dir.display().to_string())
        )
    });
    let repair_before = repair.clone().unwrap_or_default();
    let repair_after = repair
        .map(|repair| format!("; /bin/sleep 1; {repair}"))
        .unwrap_or_default();
    let args = args
        .iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let command = format!(
        "mkdir -p {config_dir} {log_dir}; {repair_before}: > {log}; chmod 644 {log}; \
         if [ -f {pid} ]; then oldpid=\"$(/bin/cat {pid} 2>/dev/null || true)\"; \
         case \"$oldpid\" in \"\"|*[!0-9]*) ;; *) \
         if /bin/ps -p \"$oldpid\" -o command= 2>/dev/null | /usr/bin/grep -q p2wlan-daemon; then \
         /bin/kill \"$oldpid\" >/dev/null 2>&1 || true; /bin/sleep 1; fi ;; esac; fi; \
         (P2WLAN_DAEMON_BIN={daemon} {daemon} {args} >> {log} 2>&1 < /dev/null & echo $! > {pid}){repair_after}",
        config_dir = shell_quote(&config_dir.display().to_string()),
        log_dir = shell_quote(&log_dir.display().to_string()),
        log = shell_quote(&log_path.display().to_string()),
        pid = shell_quote(&pid_path.display().to_string()),
        daemon = shell_quote(&daemon.display().to_string()),
    );
    let script = format!(
        "do shell script \"{}\" with administrator privileges with prompt \"{}\"",
        applescript_quote(&command),
        applescript_quote("p2wlan-tray needs administrator permission to start p2wlan-daemon.")
    );
    let output = Command::new("osascript").arg("-e").arg(script).output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if stderr.contains("-128") {
            "administrator authorization cancelled".into()
        } else if stderr.is_empty() {
            "administrator launch failed".into()
        } else {
            stderr.into()
        })
    }
}

#[cfg(not(target_os = "macos"))]
fn start_daemon_platform(
    daemon: &Path,
    args: &[String],
    _config_path: &Path,
    _log_dir: &Path,
    log_path: &Path,
    _pid_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    Command::new(daemon)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log.try_clone()?))
        .stderr(std::process::Stdio::from(log))
        .spawn()?;
    Ok(())
}

fn config_has_token(path: &Path) -> bool {
    let Ok(raw) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    value
        .get("control")
        .and_then(|control| control.get("auth_token"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|token| !token.trim().is_empty())
}

fn locate_daemon_binary() -> Option<PathBuf> {
    if let Some(path) = env::var_os("P2WLAN_DAEMON_BIN").map(PathBuf::from) {
        if path.exists() {
            return Some(path);
        }
    }

    let mut candidates = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join(DAEMON_NAME));
            if let Some(contents) = dir.parent() {
                candidates.push(contents.join("Resources").join(DAEMON_NAME));
            }
        }
    }
    if let Ok(current_dir) = env::current_dir() {
        let mut dir = current_dir.as_path();
        for _ in 0..6 {
            candidates.push(dir.join("target").join("debug").join(DAEMON_NAME));
            candidates.push(dir.join("target").join("release").join(DAEMON_NAME));
            let Some(parent) = dir.parent() else {
                break;
            };
            dir = parent;
        }
    }
    if let Some(root) = find_repo_root() {
        candidates.push(root.join("target").join("debug").join(DAEMON_NAME));
        candidates.push(root.join("target").join("release").join(DAEMON_NAME));
    }

    candidates
        .into_iter()
        .find(|path| path.exists())
        .or_else(which_daemon)
}

fn which_daemon() -> Option<PathBuf> {
    let command = if cfg!(windows) { "where" } else { "which" };
    let output = Command::new(command).arg(DAEMON_NAME).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(PathBuf::from)
}

fn open_flutter_client() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    {
        let app = find_flutter_app()
            .ok_or("未找到 Flutter 版 P2WLAN.app；请先运行 flutter build macos --debug")?;
        let status = Command::new("open").arg(app).status()?;
        if status.success() {
            return Ok(());
        }
        return Err("open command failed".into());
    }

    #[cfg(not(target_os = "macos"))]
    {
        let binary = if cfg!(windows) {
            "P2WLAN.exe"
        } else {
            "p2wlan_flutter_client"
        };
        Command::new(binary).spawn()?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn find_flutter_app() -> Option<PathBuf> {
    if let Some(path) = env::var_os("P2WLAN_FLUTTER_APP").map(PathBuf::from) {
        if path.exists() {
            return Some(path);
        }
    }
    let root = find_repo_root()?;
    [
        root.join("apps/flutter_client/build/macos/Build/Products/Debug/P2WLAN.app"),
        root.join("apps/flutter_client/build/macos/Build/Products/Release/P2WLAN.app"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn find_repo_root() -> Option<PathBuf> {
    let mut starts = Vec::new();
    if let Ok(current_dir) = env::current_dir() {
        starts.push(current_dir);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            starts.push(parent.to_path_buf());
        }
    }

    for mut dir in starts {
        for _ in 0..12 {
            if dir.join("Cargo.toml").exists() && dir.join("client").exists() {
                return Some(dir);
            }
            if !dir.pop() {
                break;
            }
        }
    }
    None
}

fn open_log_directory() -> Result<(), Box<dyn Error>> {
    let dir = p2wlan_desktop_host::default_log_dir();
    fs::create_dir_all(&dir)?;
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("open").arg(&dir).status()?;
        if status.success() {
            return Ok(());
        }
        return Err("open logs command failed".into());
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer").arg(&dir).spawn()?;
        Ok(())
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        Command::new("xdg-open").arg(&dir).spawn()?;
        Ok(())
    }
}

fn copy_to_clipboard(value: &str) -> Result<(), Box<dyn Error>> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(value.to_string())?;
    Ok(())
}

fn tray_icon_image(running: bool) -> Result<Icon, Box<dyn Error>> {
    let size = 32_u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let primary = if running {
        [0x16, 0xa3, 0x4a, 0xff]
    } else {
        [0x94, 0xa3, 0xb8, 0xff]
    };
    for y in 0..size {
        for x in 0..size {
            let dx = x as i32 - 16;
            let dy = y as i32 - 16;
            let distance_sq = dx * dx + dy * dy;
            let pixel = if distance_sq <= 12 * 12 && distance_sq >= 7 * 7 {
                primary
            } else if (12..=20).contains(&x) && (12..=20).contains(&y) {
                [0x0f, 0x17, 0x2a, 0xff]
            } else {
                [0, 0, 0, 0]
            };
            rgba.extend_from_slice(&pixel);
        }
    }
    Ok(Icon::from_rgba(rgba, size, size)?)
}

#[cfg(target_os = "macos")]
fn user_owner_for_paths() -> Option<String> {
    for key in ["SUDO_USER", "USER", "LOGNAME"] {
        let value = env::var(key).ok()?;
        if !value.trim().is_empty() && value != "root" {
            return Some(value);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
