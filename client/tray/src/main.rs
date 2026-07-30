use std::{
    env,
    error::Error,
    fs,
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
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};

const STATUS_URL: &str = p2wlan_desktop_host::DEFAULT_DIAGNOSTICS_STATUS_URL;
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
    refresh: MenuItem,
    start_daemon: MenuItem,
    stop_daemon: MenuItem,
    open_client: MenuItem,
    quit: MenuItem,
}

impl TrayMenu {
    fn new() -> Result<(Self, Menu), Box<dyn Error>> {
        let status = MenuItem::with_id("status", "P2WLAN: checking...", false, None);
        let refresh = MenuItem::with_id("refresh", "Refresh Status", true, None);
        let start_daemon = MenuItem::with_id("start-daemon", "Start Daemon", true, None);
        let stop_daemon = MenuItem::with_id("stop-daemon", "Stop Daemon", true, None);
        let open_client = MenuItem::with_id("open-client", "Open P2WLAN", true, None);
        let quit = MenuItem::with_id("quit", "Quit Tray", true, None);
        let separator = PredefinedMenuItem::separator();
        let separator2 = PredefinedMenuItem::separator();
        let menu = Menu::with_items(&[
            &status,
            &refresh,
            &separator,
            &start_daemon,
            &stop_daemon,
            &open_client,
            &separator2,
            &quit,
        ])?;
        Ok((
            Self {
                status,
                refresh,
                start_daemon,
                stop_daemon,
                open_client,
                quit,
            },
            menu,
        ))
    }

    fn id_for(&self, event: &MenuEvent) -> MenuAction {
        let id = event.id();
        if id == self.refresh.id() {
            MenuAction::Refresh
        } else if id == self.start_daemon.id() {
            MenuAction::StartDaemon
        } else if id == self.stop_daemon.id() {
            MenuAction::StopDaemon
        } else if id == self.open_client.id() {
            MenuAction::OpenClient
        } else if id == self.quit.id() {
            MenuAction::Quit
        } else {
            MenuAction::None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuAction {
    None,
    Refresh,
    StartDaemon,
    StopDaemon,
    OpenClient,
    Quit,
}

#[derive(Debug, Clone)]
struct DaemonState {
    running: bool,
    label: String,
    tooltip: String,
}

impl DaemonState {
    fn offline() -> Self {
        Self {
            running: false,
            label: "P2WLAN: offline".to_string(),
            tooltip: "p2wlan-daemon is not responding".to_string(),
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
                MenuAction::Refresh => app.refresh_state(),
                MenuAction::StartDaemon => app.start_daemon(),
                MenuAction::StopDaemon => app.stop_daemon(),
                MenuAction::OpenClient => app.open_client(),
                MenuAction::Quit => *control_flow = ControlFlow::Exit,
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

    fn apply_state(&self) {
        self.menu.status.set_text(&self.last_state.label);
        self.menu.stop_daemon.set_enabled(self.last_state.running);
        self.menu.start_daemon.set_enabled(!self.last_state.running);
        let _ = self
            .tray_icon
            .set_tooltip(Some(self.last_state.tooltip.as_str()));
        let _ = self.tray_icon.set_icon(Some(
            tray_icon_image(self.last_state.running).expect("static tray icon should be valid"),
        ));
    }

    fn start_daemon(&mut self) {
        self.set_status("P2WLAN: starting...");
        match start_daemon() {
            Ok(()) => self.set_status("P2WLAN: daemon launched"),
            Err(error) => self.set_status(format!("Start failed: {error}")),
        }
        thread::sleep(Duration::from_millis(700));
        self.refresh_state();
    }

    fn stop_daemon(&mut self) {
        self.set_status("P2WLAN: stopping...");
        match stop_daemon() {
            Ok(()) => self.set_status("P2WLAN: stop requested"),
            Err(error) => self.set_status(format!("Stop failed: {error}")),
        }
        thread::sleep(Duration::from_millis(700));
        self.refresh_state();
    }

    fn open_client(&mut self) {
        if let Err(error) = open_flutter_client() {
            self.set_status(format!("Open failed: {error}"));
        }
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
        .unwrap_or("no IP");
    let peers = status
        .as_ref()
        .and_then(|value| value.get("stats"))
        .and_then(|stats| stats.get("total_peers"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    DaemonState {
        running: true,
        label: format!("P2WLAN: connected ({virtual_ip})"),
        tooltip: format!("p2wlan-daemon running, peers: {peers}"),
    }
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
        let repo_app = find_repo_root()
            .map(|root| {
                root.join("apps/flutter_client/build/macos/Build/Products/Release/P2WLAN.app")
            })
            .filter(|path| path.exists());
        let status = if let Some(app) = repo_app {
            Command::new("open").arg(app).status()?
        } else {
            Command::new("open").args(["-a", "P2WLAN"]).status()?
        };
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

fn find_repo_root() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    for _ in 0..8 {
        if dir.join("Cargo.toml").exists() && dir.join("client").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    None
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
