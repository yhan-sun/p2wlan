use clap::{Args, Parser, Subcommand};
use p2pnet_daemon::Config;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_CONTROL_SERVER: &str = "http://47.109.40.237:18080";
const DEFAULT_NETWORK: &str = "default";
const DEFAULT_DIAGNOSTICS_BIND: &str = "127.0.0.1:39277";
const DEFAULT_UPDATE_REPO: &str = "yhan-sun/p2wlan";
const DEFAULT_INSTALL_DIR: &str = "/usr/local/bin";
const SUPPORTED_CONFIG_KEYS: &str = "control、network、device-name、interface、mtu、udp-bind、udp-advertise、stun、diagnostics、relay、relay-policy、direct-timeout";

#[derive(Parser, Debug)]
#[command(name = "p2wlan", version, about = "p2wlan Linux command-line client")]
struct Cli {
    /// Use a custom daemon configuration file
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Log in to the control server and save the session
    Login(AuthArgs),
    /// Create an account and save the session
    Register(AuthArgs),
    /// Remove the saved control-server session
    Logout,
    /// Start the TUN daemon in the background
    #[command(alias = "start")]
    Up,
    /// Stop the running TUN daemon
    #[command(alias = "stop")]
    Down,
    /// Show daemon and peer status
    Status {
        /// Print the complete diagnostics response as JSON
        #[arg(long)]
        json: bool,
    },
    /// Read daemon logs
    Logs {
        /// Number of recent lines to print
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
        /// Continue following the log file
        #[arg(short = 'f', long)]
        follow: bool,
    },
    /// View or update persistent settings
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Diagnose local config, daemon status, direct UDP, and relay fallback
    Doctor,
    /// Download and install the latest Linux CLI release
    Update(UpdateArgs),
    /// Internal elevated launcher used by `p2wlan up`
    #[command(name = "__start-daemon", hide = true)]
    InternalStart(InternalStartArgs),
}

#[derive(Args, Debug)]
struct AuthArgs {
    /// Account email address
    #[arg(short = 'u', long = "username", alias = "email")]
    username: String,
    /// Account password. Omit this option to enter it without terminal echo.
    #[arg(short = 'p', long)]
    password: Option<String>,
    /// Control server URL
    #[arg(short = 's', long, value_name = "URL")]
    server: Option<String>,
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Show the effective configuration with secrets redacted
    Show,
    /// Print the configuration file path
    Path,
    /// Set one supported configuration value
    Set {
        /// control, network, device-name, interface, mtu, udp-bind, udp-advertise, stun, diagnostics, relay, relay-policy, or direct-timeout
        key: String,
        value: String,
    },
}

#[derive(Args, Debug)]
struct UpdateArgs {
    /// GitHub repository, for example yhan-sun/p2wlan
    #[arg(long, default_value = DEFAULT_UPDATE_REPO)]
    repo: String,
    /// Install a specific release tag instead of the latest release
    #[arg(long, value_name = "TAG")]
    version: Option<String>,
    /// Installation directory for p2wlan and p2pnet-daemon
    #[arg(long, value_name = "DIR")]
    install_dir: Option<PathBuf>,
    /// Only print what would be installed
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct InternalStartArgs {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    state_dir: PathBuf,
    #[arg(long)]
    daemon: PathBuf,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    success: Option<bool>,
    token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: Option<String>,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("错误：{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let config_path = cli.config.unwrap_or_else(default_config_path);
    match cli.command {
        Commands::Login(args) => authenticate(&config_path, args, false).await,
        Commands::Register(args) => authenticate(&config_path, args, true).await,
        Commands::Logout => logout(&config_path),
        Commands::Up => start(&config_path).await,
        Commands::Down => stop(&config_path).await,
        Commands::Status { json } => status(&config_path, json).await,
        Commands::Logs { lines, follow } => logs(lines, follow),
        Commands::Config { command } => config_command(&config_path, command),
        Commands::Doctor => doctor(&config_path).await,
        Commands::Update(args) => update(&config_path, args).await,
        Commands::InternalStart(args) => start_daemon_as_root(args).await,
    }
}

async fn authenticate(path: &Path, args: AuthArgs, register: bool) -> Result<(), String> {
    reject_sudo_config_write()?;
    let email = args.username.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err("请输入有效邮箱地址".to_string());
    }
    let password = match args.password {
        Some(password) => password,
        None => rpassword::prompt_password("密码: ")
            .map_err(|error| format!("无法从终端读取密码：{error}"))?,
    };
    if password.len() < 6 {
        return Err("密码至少需要 6 个字符".to_string());
    }

    let existing = if path.exists() {
        Some(load_config(path)?)
    } else {
        None
    };
    let server = args
        .server
        .or_else(|| {
            existing
                .as_ref()
                .map(|config| config.control.server_url.clone())
        })
        .unwrap_or_else(|| DEFAULT_CONTROL_SERVER.to_string());
    let server = normalize_control_server(&server)?;
    let endpoint = format!(
        "{server}/api/v1/{}",
        if register { "register" } else { "login" }
    );
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| format!("无法初始化网络请求：{error}"))?
        .post(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "连接控制服务器超时".to_string()
            } else {
                format!("无法连接控制服务器：{error}")
            }
        })?;
    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|error| format!("无法读取控制服务器响应：{error}"))?;
    let body: AuthResponse = serde_json::from_str(&body_text)
        .map_err(|_| format!("控制服务器返回了无效响应（HTTP {status}）"))?;
    if !status.is_success() || body.success != Some(true) {
        return Err(auth_error(
            body.error.as_deref().unwrap_or(&body_text),
            status.as_u16(),
        ));
    }
    let token = body
        .token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| "控制服务器没有返回有效 token".to_string())?;

    let mut config = match existing {
        Some(config) => config,
        None => Config::generate_default(&server, DEFAULT_NETWORK)
            .map_err(|error| format!("无法生成配置：{error}"))?,
    };
    config.control.server_url = server.clone();
    config.control.auth_token = token;
    config.control.device_credential.clear();
    config.control.credential_issued = false;
    config.diagnostics.enabled = true;
    config.diagnostics.bind = DEFAULT_DIAGNOSTICS_BIND.to_string();
    save_config(&config, path)?;

    println!(
        "{}成功：{}\n控制服务器：{}\n配置文件：{}",
        if register { "注册" } else { "登录" },
        email,
        server,
        path.display()
    );
    Ok(())
}

fn logout(path: &Path) -> Result<(), String> {
    reject_sudo_config_write()?;
    let mut config = load_config(path)?;
    config.control.auth_token.clear();
    config.control.device_credential.clear();
    config.control.credential_issued = false;
    save_config(&config, path)?;
    println!("已退出登录，设备身份密钥和网络设置已保留。");
    Ok(())
}

async fn start(config_path: &Path) -> Result<(), String> {
    let config = load_config(config_path)?;
    if config.control.auth_token.trim().is_empty() {
        return Err("尚未登录，请先运行 p2wlan login -u <邮箱>".to_string());
    }
    if fetch_status(&status_url(&config)).await.is_ok() {
        println!("p2wlan 已经在运行。");
        return Ok(());
    }

    let args = InternalStartArgs {
        config: absolute_path(config_path)?,
        state_dir: state_dir(),
        daemon: locate_daemon()?,
    };
    if is_root() {
        return start_daemon_as_root(args).await;
    }

    fs::create_dir_all(&args.state_dir)
        .map_err(|error| format!("无法创建运行目录 {}：{error}", args.state_dir.display()))?;
    let current_exe = env::current_exe().map_err(|error| format!("无法定位 p2wlan：{error}"))?;
    println!("需要管理员权限创建 Linux TUN 和路由，正在请求 sudo...");
    let result = Command::new("sudo")
        .arg(current_exe)
        .arg("__start-daemon")
        .arg("--config")
        .arg(&args.config)
        .arg("--state-dir")
        .arg(&args.state_dir)
        .arg("--daemon")
        .arg(&args.daemon)
        .status()
        .map_err(|error| format!("无法执行 sudo：{error}"))?;
    if !result.success() {
        return Err(format!(
            "管理员启动失败（退出码 {}）",
            result.code().unwrap_or(1)
        ));
    }
    Ok(())
}

async fn start_daemon_as_root(args: InternalStartArgs) -> Result<(), String> {
    if !is_root() {
        return Err("内部启动命令必须以 root 运行".to_string());
    }
    let config = load_config(&args.config)?;
    let url = status_url(&config);
    if fetch_status(&url).await.is_ok() {
        println!("p2wlan 已经在运行。");
        return Ok(());
    }

    fs::create_dir_all(&args.state_dir)
        .map_err(|error| format!("无法创建运行目录 {}：{error}", args.state_dir.display()))?;
    let log_path = args.state_dir.join("p2pnet-daemon.log");
    let pid_path = args.state_dir.join("p2pnet-daemon.pid");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("无法打开日志 {}：{error}", log_path.display()))?;
    make_world_readable(&log)?;

    let mut command = Command::new(&args.daemon);
    command
        .arg("--config")
        .arg(&args.config)
        .arg("--diagnostics-bind")
        .arg(&config.diagnostics.bind)
        .arg("--log-file")
        .arg(&log_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("无法启动 {}：{error}", args.daemon.display()))?;
    fs::write(&pid_path, child.id().to_string())
        .map_err(|error| format!("无法写入 PID 文件：{error}"))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(exit) = child
            .try_wait()
            .map_err(|error| format!("无法检查 daemon 状态：{error}"))?
        {
            return Err(format!(
                "daemon 启动后立即退出（{exit}）。请运行 p2wlan logs 查看原因"
            ));
        }
        if let Ok(snapshot) = fetch_status(&url).await {
            println!(
                "p2wlan 已启动：{}（PID {}）",
                snapshot
                    .get("virtual_ip")
                    .and_then(Value::as_str)
                    .unwrap_or("等待地址分配"),
                child.id()
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err("daemon 已启动，但 30 秒内诊断端点没有就绪。请运行 p2wlan logs".to_string())
}

async fn stop(config_path: &Path) -> Result<(), String> {
    let config = load_config(config_path)?;
    let url = format!(
        "http://{}/shutdown",
        normalized_diagnostics_bind(&config.diagnostics.bind)
    );
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| error.to_string())?
        .post(url)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            println!("已发送停止请求。");
            Ok(())
        }
        _ => {
            let pid_path = state_dir().join("p2pnet-daemon.pid");
            let Some(pid) = verified_recorded_daemon(&pid_path)? else {
                println!("p2wlan 未运行。");
                return Ok(());
            };
            println!("诊断端点不可访问，正在向已校验的 daemon PID {pid} 发送 SIGTERM...");
            terminate_daemon(pid)?;
            Ok(())
        }
    }
}

async fn status(config_path: &Path, json: bool) -> Result<(), String> {
    let config = load_config(config_path)?;
    match fetch_status(&status_url(&config)).await {
        Ok(snapshot) if json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshot).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        Ok(snapshot) => {
            let peers = snapshot
                .get("peers")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            println!("状态：运行中");
            println!("虚拟 IP：{}", value_text(&snapshot, "virtual_ip", "未知"));
            println!("网络：{}", value_text(&snapshot, "network_id", "未知"));
            println!("节点：{}", value_text(&snapshot, "node_id", "未知"));
            println!("Peer：{peers}");
            println!(
                "Relay：{}",
                if snapshot
                    .get("relay_connected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "已连接"
                } else {
                    "未连接"
                }
            );
            Ok(())
        }
        Err(error) => {
            println!("状态：未运行");
            Err(error)
        }
    }
}

async fn doctor(config_path: &Path) -> Result<(), String> {
    println!("p2wlan doctor");
    println!("版本：{}", env!("CARGO_PKG_VERSION"));
    println!("配置文件：{}", config_path.display());

    if !config_path.exists() {
        println!("配置：不存在");
        println!("建议：先运行 p2wlan login -u <邮箱>");
        return Ok(());
    }

    let config = load_config(config_path)?;
    let mut suggestions = Vec::new();
    println!(
        "登录：{}",
        if config.control.auth_token.is_empty() {
            suggestions.push("运行 p2wlan login -u <邮箱> 完成登录".to_string());
            "no"
        } else {
            "yes"
        }
    );
    println!("控制面：{}", config.control.server_url);
    println!("网络：{}", config.network.network_id);
    println!(
        "虚拟网卡：{} MTU {}",
        config.network.interface, config.network.mtu
    );
    println!("UDP bind：{}", config.network.udp_bind);
    println!(
        "UDP advertise：{}",
        config
            .network
            .udp_advertise
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("(unset)")
    );
    println!(
        "Relay policy：{}",
        if config.relay.prefer_direct {
            "auto/direct-first"
        } else {
            "relay-only"
        }
    );

    if let Ok(bind) = config.network.udp_bind.parse::<SocketAddr>() {
        if bind.port() == 0 {
            suggestions.push(
                "云服务器建议固定 UDP 端口，例如：p2wlan config set udp-bind 0.0.0.0:60207"
                    .to_string(),
            );
        }
    } else {
        suggestions.push("修正 udp-bind，它必须是 ip:port".to_string());
    }
    if config
        .network
        .udp_advertise
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .is_none()
    {
        suggestions.push(
            "云服务器需要发布公网 UDP 地址，例如：p2wlan config set udp-advertise <公网IP>:60207"
                .to_string(),
        );
    }
    if !config.relay.prefer_direct {
        suggestions
            .push("如果希望优先直连，请运行：p2wlan config set relay-policy auto".to_string());
    }

    match fetch_status(&status_url(&config)).await {
        Ok(snapshot) => {
            println!("Daemon：运行中");
            println!("虚拟 IP：{}", value_text(&snapshot, "virtual_ip", "未知"));
            println!(
                "UDP local：{}",
                value_text(&snapshot, "udp_local_addr", "未知")
            );
            println!(
                "Relay：{}",
                if snapshot
                    .get("relay_connected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "已连接"
                } else {
                    "未连接"
                }
            );
            let stats = snapshot.get("stats").unwrap_or(&Value::Null);
            println!(
                "Peer：total={} direct={} relay={}",
                value_u64(stats, "total_peers"),
                value_u64(stats, "direct_connections"),
                value_u64(stats, "relay_connections")
            );
            print_peer_diagnostics(&snapshot);
            suggestions.extend(peer_direct_suggestions(&snapshot));
            if value_u64(stats, "relay_connections") > 0
                && value_u64(stats, "direct_connections") == 0
            {
                suggestions.push(
                    "当前 Peer 只走 Relay。请确认两端云厂商安全组和系统防火墙都放行同一个 UDP 端口"
                        .to_string(),
                );
            }
        }
        Err(error) => {
            println!("Daemon：未运行（{error}）");
            suggestions.push("运行 p2wlan up 启动 TUN daemon".to_string());
        }
    }

    println!("建议：");
    if suggestions.is_empty() {
        println!("- 暂无明显配置问题；如果仍只走 Relay，请检查对端防火墙和云安全组 UDP 入站规则。");
    } else {
        for suggestion in dedupe_strings(suggestions) {
            println!("- {suggestion}");
        }
    }
    Ok(())
}

async fn update(config_path: &Path, args: UpdateArgs) -> Result<(), String> {
    let arch = linux_release_arch()?;
    let install_dir = args
        .install_dir
        .or_else(|| env::var_os("P2WLAN_INSTALL_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_INSTALL_DIR));
    let release = fetch_github_release(&args.repo, args.version.as_deref()).await?;
    let asset_name = format!("p2wlan-linux-{arch}-cli.tar.gz");
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| format!("release {} 没有找到资产 {asset_name}", release.tag_name))?;

    println!("当前版本：{}", env!("CARGO_PKG_VERSION"));
    println!("目标版本：{}", release.tag_name);
    println!("安装目录：{}", install_dir.display());
    if let Some(url) = &release.html_url {
        println!("Release：{url}");
    }

    let target_version = release.tag_name.trim_start_matches('v');
    if args.version.is_none() && target_version == env!("CARGO_PKG_VERSION") {
        println!("已经是最新版本。");
        return Ok(());
    }
    if args.dry_run {
        println!("dry-run：将下载并安装 {}", asset.name);
        return Ok(());
    }

    let daemon_running = match load_config(config_path) {
        Ok(config) => fetch_status(&status_url(&config)).await.is_ok(),
        Err(_) => false,
    };

    let work_dir = temp_update_dir()?;
    fs::create_dir_all(&work_dir)
        .map_err(|error| format!("无法创建临时目录 {}：{error}", work_dir.display()))?;
    let archive_path = work_dir.join(&asset.name);
    download_to_file(&asset.browser_download_url, &archive_path).await?;
    extract_tar_gz(&archive_path, &work_dir)?;

    let package_dir = work_dir.join(format!("p2wlan-linux-{arch}-cli"));
    install_release_binaries(&package_dir, &install_dir)?;
    let _ = fs::remove_dir_all(&work_dir);

    println!("已更新到 {}。", release.tag_name);
    if daemon_running {
        println!("提示：daemon 正在运行，执行 p2wlan down && p2wlan up 后会使用新版 daemon。");
    }
    Ok(())
}

fn logs(lines: usize, follow: bool) -> Result<(), String> {
    let path = state_dir().join("p2pnet-daemon.log");
    if follow {
        let status = Command::new("tail")
            .arg("-n")
            .arg(lines.to_string())
            .arg("-f")
            .arg(&path)
            .status()
            .map_err(|error| format!("无法执行 tail：{error}"))?;
        if !status.success() {
            return Err(format!("tail 退出，状态：{status}"));
        }
        return Ok(());
    }
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("无法读取日志 {}：{error}", path.display()))?;
    let all = content.lines().collect::<Vec<_>>();
    for line in all.iter().skip(all.len().saturating_sub(lines)) {
        println!("{line}");
    }
    Ok(())
}

fn config_command(path: &Path, command: ConfigCommand) -> Result<(), String> {
    match command {
        ConfigCommand::Path => {
            println!("{}", path.display());
            Ok(())
        }
        ConfigCommand::Show => {
            let config = load_config(path)?;
            println!("配置文件：{}", path.display());
            println!("control = {}", config.control.server_url);
            println!(
                "logged-in = {}",
                if config.control.auth_token.is_empty() {
                    "no"
                } else {
                    "yes"
                }
            );
            println!("network = {}", config.network.network_id);
            println!("device-name = {}", config.node.device_name);
            println!("interface = {}", config.network.interface);
            println!("mtu = {}", config.network.mtu);
            println!("udp-bind = {}", config.network.udp_bind);
            println!(
                "udp-advertise = {}",
                config
                    .network
                    .udp_advertise
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("(unset)")
            );
            println!(
                "stun = {}",
                if config.network.stun_servers.is_empty() {
                    "(default)".to_string()
                } else if config
                    .network
                    .stun_servers
                    .iter()
                    .all(|value| is_clear_value(value))
                {
                    "(disabled)".to_string()
                } else {
                    config.network.stun_servers.join(",")
                }
            );
            println!("relay = {}", config.relay.servers.join(","));
            println!(
                "relay-policy = {}",
                if config.relay.prefer_direct {
                    "auto"
                } else {
                    "relay"
                }
            );
            println!("direct-timeout = {}ms", config.relay.fallback_timeout_ms);
            println!("diagnostics = {}", config.diagnostics.bind);
            Ok(())
        }
        ConfigCommand::Set { key, value } => {
            reject_sudo_config_write()?;
            let mut config = load_or_create_config(path)?;
            set_config_value(&mut config, &key, &value)?;
            save_config(&config, path)?;
            println!("已更新 {key}。重启 p2wlan 后生效。");
            Ok(())
        }
    }
}

fn set_config_value(config: &mut Config, key: &str, value: &str) -> Result<(), String> {
    match key {
        "control" => {
            let server = normalize_control_server(value)?;
            if server != config.control.server_url {
                config.control.server_url = server;
                config.control.auth_token.clear();
                clear_device_credential(config);
            }
        }
        "network" => {
            if value.trim().is_empty() {
                return Err("network 不能为空".to_string());
            }
            let network = value.trim();
            if network != config.network.network_id {
                config.network.network_id = network.to_string();
                clear_device_credential(config);
            }
        }
        "device-name" => {
            if value.trim().is_empty() {
                return Err("device-name 不能为空".to_string());
            }
            let name = value.trim();
            if name != config.node.device_name {
                config.node.device_name = name.to_string();
                clear_device_credential(config);
            }
        }
        "interface" => {
            if value.trim().is_empty() || value.len() > 15 {
                return Err("Linux interface 名称必须为 1 到 15 个字符".to_string());
            }
            config.network.interface = value.trim().to_string();
        }
        "mtu" => {
            let mtu = value
                .parse::<u32>()
                .map_err(|_| "mtu 必须是整数".to_string())?;
            if !(576..=65535).contains(&mtu) {
                return Err("mtu 必须在 576 到 65535 之间".to_string());
            }
            config.network.mtu = mtu;
        }
        "udp-bind" => {
            let endpoint = parse_socket_addr(value, "udp-bind")?;
            config.network.udp_bind = endpoint.to_string();
        }
        "udp-advertise" => {
            if is_clear_value(value) {
                config.network.udp_advertise = None;
            } else {
                let endpoint = parse_socket_addr(value, "udp-advertise")?;
                if endpoint.ip().is_unspecified() || endpoint.port() == 0 {
                    return Err("udp-advertise 必须是可被其他设备访问的 ip:port".to_string());
                }
                config.network.udp_advertise = Some(endpoint.to_string());
            }
        }
        "stun" => {
            if is_clear_value(value) {
                config.network.stun_servers = vec!["off".to_string()];
            } else {
                let servers = value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| parse_stun_server_spec(item).map(ToString::to_string))
                    .collect::<Result<Vec<_>, _>>()?;
                config.network.stun_servers = servers;
            }
        }
        "diagnostics" => {
            let endpoint = parse_socket_addr(value, "diagnostics")?;
            if !endpoint.ip().is_loopback() {
                return Err("diagnostics 必须绑定在 127.0.0.1 或 ::1".to_string());
            }
            config.diagnostics.enabled = true;
            config.diagnostics.bind = endpoint.to_string();
        }
        "relay" => {
            config.relay.servers = value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToString::to_string)
                .collect();
        }
        "relay-policy" => match value {
            "auto" | "direct" => config.relay.prefer_direct = true,
            "relay" => config.relay.prefer_direct = false,
            _ => return Err("relay-policy 只支持 auto、direct 或 relay".to_string()),
        },
        "direct-timeout" => {
            let timeout = parse_millis(value, "direct-timeout")?;
            if !(100..=60000).contains(&timeout) {
                return Err("direct-timeout 必须在 100ms 到 60000ms 之间".to_string());
            }
            config.relay.fallback_timeout_ms = timeout;
        }
        _ => {
            return Err(format!(
                "不支持的配置项 {key}；可用项：{SUPPORTED_CONFIG_KEYS}"
            ))
        }
    }
    Ok(())
}

fn parse_socket_addr(value: &str, label: &str) -> Result<SocketAddr, String> {
    value
        .trim()
        .parse::<SocketAddr>()
        .map_err(|error| format!("{label} 必须是有效 ip:port：{error}"))
}

fn parse_stun_server_spec(value: &str) -> Result<&str, String> {
    let spec = value.trim();
    if spec.parse::<SocketAddr>().is_ok() {
        return Ok(spec);
    }
    let Some((host, port)) = spec.rsplit_once(':') else {
        return Err("stun 必须是有效 host:port 或 ip:port".to_string());
    };
    if host.is_empty()
        || host.contains(char::is_whitespace)
        || host.contains('/')
        || host.contains('@')
    {
        return Err("stun host 不能为空，且不能包含空白、/ 或 @".to_string());
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| "stun 端口必须是 1 到 65535 的整数".to_string())?;
    if port == 0 {
        return Err("stun 端口必须是 1 到 65535 的整数".to_string());
    }
    Ok(spec)
}

fn parse_millis(value: &str, label: &str) -> Result<u64, String> {
    let trimmed = value.trim().trim_end_matches("ms");
    trimmed
        .parse::<u64>()
        .map_err(|_| format!("{label} 必须是毫秒整数，例如 5000 或 5000ms"))
}

fn is_clear_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "none" | "off" | "false" | "clear" | "unset" | "disable" | "disabled"
    )
}

fn load_or_create_config(path: &Path) -> Result<Config, String> {
    if path.exists() {
        load_config(path)
    } else {
        Config::generate_default(DEFAULT_CONTROL_SERVER, DEFAULT_NETWORK)
            .map_err(|error| format!("无法生成配置：{error}"))
    }
}

fn load_config(path: &Path) -> Result<Config, String> {
    Config::load_from_file(path).map_err(|error| {
        if path.exists() {
            format!("无法读取配置 {}：{error}", path.display())
        } else {
            format!(
                "配置不存在：{}。请先运行 p2wlan login -u <邮箱>",
                path.display()
            )
        }
    })
}

fn save_config(config: &Config, path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "配置路径无效".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("无法创建配置目录 {}：{error}", parent.display()))?;
    config
        .save_to_file(path)
        .map_err(|error| format!("无法保存配置 {}：{error}", path.display()))
}

fn normalize_control_server(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('/');
    let parsed = Url::parse(trimmed).map_err(|_| "控制服务器必须是有效 URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("控制服务器必须使用 http 或 https".to_string());
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn auth_error(message: &str, status: u16) -> String {
    let lower = message.to_lowercase();
    if lower.contains("invalid credentials") {
        "邮箱或密码错误".to_string()
    } else if lower.contains("invalid email") {
        "邮箱格式不正确".to_string()
    } else if lower.contains("invalid password") {
        "密码不符合要求，至少需要 6 个字符".to_string()
    } else if status == 409 {
        "账号已存在".to_string()
    } else if status >= 500 {
        "控制服务器内部错误，请稍后重试".to_string()
    } else {
        format!("认证失败（HTTP {status}）：{message}")
    }
}

fn clear_device_credential(config: &mut Config) {
    config.control.device_credential.clear();
    config.control.credential_issued = false;
}

fn print_peer_diagnostics(snapshot: &Value) {
    let Some(peers) = snapshot.get("peers").and_then(Value::as_array) else {
        return;
    };
    if peers.is_empty() {
        return;
    }

    println!("Peer details：");
    for peer in peers.iter().take(12) {
        let node_id = peer
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let name = peer
            .get("device_name")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(node_id);
        let virtual_ip = peer
            .get("virtual_ip")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let state = peer
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let active_path = peer
            .get("active_path")
            .and_then(Value::as_str)
            .unwrap_or("none");
        let endpoint = peer
            .get("endpoint")
            .and_then(Value::as_str)
            .unwrap_or("(none)");
        let candidate_count = peer
            .get("candidates")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let candidates = peer_candidate_strings(peer);
        let candidate_preview = endpoint_preview(&candidates, 3);
        println!(
            "- {} ({}) state={} path={} endpoint={} candidates={}{}",
            short_text(name, 24),
            virtual_ip,
            state,
            active_path,
            endpoint,
            candidate_count,
            candidate_preview
        );
        if let Some(error) = peer
            .get("direct")
            .and_then(|direct| direct.get("last_error"))
            .and_then(Value::as_str)
        {
            println!("  direct-error={error}");
        }
    }
}

fn peer_direct_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(peers) = snapshot.get("peers").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut private_only_peers = Vec::new();
    let mut direct_failures = 0_u64;
    for peer in peers {
        let has_direct_error = peer
            .get("direct")
            .and_then(|direct| direct.get("last_error"))
            .and_then(Value::as_str)
            .is_some();
        if has_direct_error {
            direct_failures += 1;
        }

        let endpoints = peer_diagnostic_endpoints(peer);
        if endpoints.is_empty() {
            continue;
        }
        let has_public_endpoint = endpoints.iter().any(is_public_udp_endpoint);
        let has_private_or_local_endpoint = endpoints
            .iter()
            .any(|endpoint| is_private_or_local_ip(endpoint.ip()));
        if has_direct_error && !has_public_endpoint && has_private_or_local_endpoint {
            private_only_peers.push(peer_display_name(peer));
        }
    }

    let mut suggestions = Vec::new();
    if !private_only_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 只上报了私网/回环 UDP 候选；请在对应设备配置 udp-advertise <公网IP>:<端口>，并放行同一个 UDP 入站端口。",
            private_only_peers.join("、")
        ));
    } else if direct_failures > 0 {
        suggestions.push(
            "检测到 Direct UDP 探测失败；请确认两端 udp-bind/udp-advertise、云安全组和系统防火墙使用同一个 UDP 端口。"
                .to_string(),
        );
    }
    suggestions
}

fn peer_diagnostic_endpoints(peer: &Value) -> Vec<SocketAddr> {
    let mut endpoints = Vec::new();
    if let Some(endpoint) = peer.get("endpoint").and_then(Value::as_str) {
        push_socket_addr(&mut endpoints, endpoint);
    }
    for candidate in peer_candidate_strings(peer) {
        push_socket_addr(&mut endpoints, &candidate);
    }
    endpoints
}

fn peer_candidate_strings(peer: &Value) -> Vec<String> {
    peer.get("candidates")
        .and_then(Value::as_array)
        .map(|candidates| {
            candidates
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn push_socket_addr(endpoints: &mut Vec<SocketAddr>, value: &str) {
    if let Ok(endpoint) = value.parse::<SocketAddr>() {
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
}

fn is_public_udp_endpoint(endpoint: &SocketAddr) -> bool {
    endpoint.port() != 0 && !is_private_or_local_ip(endpoint.ip())
}

fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

fn peer_display_name(peer: &Value) -> String {
    let node_id = peer
        .get("node_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let name = peer
        .get("device_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(node_id);
    let virtual_ip = peer
        .get("virtual_ip")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    format!("{}({})", short_text(name, 18), virtual_ip)
}

fn endpoint_preview(endpoints: &[String], max_items: usize) -> String {
    if endpoints.is_empty() {
        return String::new();
    }
    let preview = endpoints
        .iter()
        .take(max_items)
        .map(|endpoint| short_text(endpoint, 32))
        .collect::<Vec<_>>()
        .join(",");
    if endpoints.len() > max_items {
        format!(" [{}…]", preview)
    } else {
        format!(" [{preview}]")
    }
}

fn short_text(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max_len).collect::<String>())
    }
}

fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}

async fn fetch_github_release(repo: &str, tag: Option<&str>) -> Result<GitHubRelease, String> {
    let endpoint = github_release_endpoint(repo, tag)?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("无法初始化更新请求：{error}"))?
        .get(endpoint)
        .header(
            reqwest::header::USER_AGENT,
            format!("p2wlan-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|error| format!("无法连接 GitHub Releases：{error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("GitHub Releases 返回 HTTP {status}"));
    }
    response
        .json::<GitHubRelease>()
        .await
        .map_err(|error| format!("GitHub Releases 响应无效：{error}"))
}

fn github_release_endpoint(repo: &str, tag: Option<&str>) -> Result<String, String> {
    let repo = repo.trim();
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| "repo 必须形如 owner/name".to_string())?;
    if !is_github_slug(owner) || !is_github_slug(name) {
        return Err("repo 只能包含字母、数字、点、下划线和短横线".to_string());
    }
    if let Some(tag) = tag {
        let tag = tag.trim();
        if tag.is_empty() || !is_github_slug(tag) {
            return Err("version 只能包含字母、数字、点、下划线和短横线".to_string());
        }
        Ok(format!(
            "https://api.github.com/repos/{owner}/{name}/releases/tags/{tag}"
        ))
    } else {
        Ok(format!(
            "https://api.github.com/repos/{owner}/{name}/releases/latest"
        ))
    }
}

fn is_github_slug(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn linux_release_arch() -> Result<&'static str, String> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x64"),
        ("linux", "aarch64") => Ok("arm64"),
        (os, arch) => Err(format!(
            "update 目前仅支持 Linux x64/arm64，当前是 {os}/{arch}"
        )),
    }
}

fn temp_update_dir() -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("系统时间异常：{error}"))?
        .as_millis();
    Ok(env::temp_dir().join(format!("p2wlan-update-{}-{now}", std::process::id())))
}

async fn download_to_file(url: &str, path: &Path) -> Result<(), String> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|error| format!("无法初始化下载请求：{error}"))?
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            format!("p2wlan-cli/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .map_err(|error| format!("下载更新包失败：{error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("下载更新包返回 HTTP {status}"));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("读取更新包失败：{error}"))?;
    fs::write(path, bytes.as_ref())
        .map_err(|error| format!("无法写入更新包 {}：{error}", path.display()))
}

fn extract_tar_gz(archive: &Path, directory: &Path) -> Result<(), String> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(directory)
        .status()
        .map_err(|error| format!("无法执行 tar：{error}"))?;
    if !status.success() {
        return Err(format!("解压更新包失败（{status}）"));
    }
    Ok(())
}

fn install_release_binaries(package_dir: &Path, install_dir: &Path) -> Result<(), String> {
    let cli = package_dir.join("p2wlan");
    let daemon = package_dir.join("p2pnet-daemon");
    if !cli.is_file() || !daemon.is_file() {
        return Err(format!(
            "更新包缺少 p2wlan 或 p2pnet-daemon：{}",
            package_dir.display()
        ));
    }
    if !is_root() {
        println!(
            "需要管理员权限安装到 {}，正在请求 sudo...",
            install_dir.display()
        );
    }
    run_install_command(vec![
        OsString::from("-d"),
        install_dir.as_os_str().to_os_string(),
    ])?;
    run_install_command(vec![
        OsString::from("-m"),
        OsString::from("0755"),
        cli.as_os_str().to_os_string(),
        install_dir.join("p2wlan").as_os_str().to_os_string(),
    ])?;
    run_install_command(vec![
        OsString::from("-m"),
        OsString::from("0755"),
        daemon.as_os_str().to_os_string(),
        install_dir.join("p2pnet-daemon").as_os_str().to_os_string(),
    ])?;
    Ok(())
}

fn run_install_command(args: Vec<OsString>) -> Result<(), String> {
    let mut command = if is_root() {
        Command::new("install")
    } else {
        let mut command = Command::new("sudo");
        command.arg("install");
        command
    };
    let status = command
        .args(args)
        .status()
        .map_err(|error| format!("无法执行 install：{error}"))?;
    if !status.success() {
        return Err(format!("安装文件失败（{status}）"));
    }
    Ok(())
}

async fn fetch_status(url: &str) -> Result<Value, String> {
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| error.to_string())?
        .get(url)
        .send()
        .await
        .map_err(|error| format!("无法连接本地诊断端点：{error}"))?;
    if !response.status().is_success() {
        return Err(format!("本地诊断端点返回 HTTP {}", response.status()));
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| format!("本地诊断响应无效：{error}"))
}

fn status_url(config: &Config) -> String {
    format!(
        "http://{}/status",
        normalized_diagnostics_bind(&config.diagnostics.bind)
    )
}

fn normalized_diagnostics_bind(bind: &str) -> &str {
    if bind.trim().is_empty() {
        DEFAULT_DIAGNOSTICS_BIND
    } else {
        bind.trim()
    }
}

fn value_text<'a>(value: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or(fallback)
}

fn default_config_path() -> PathBuf {
    if let Some(path) = env::var_os("P2WLAN_CONFIG") {
        return PathBuf::from(path);
    }
    config_dir().join("p2pnet-config.json")
}

fn config_dir() -> PathBuf {
    if let Some(path) = env::var_os("P2WLAN_HOME") {
        return PathBuf::from(path);
    }
    if env::var_os("SUDO_USER").is_none() {
        if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(path).join("p2wlan");
        }
    }
    user_home().join(".config").join("p2wlan")
}

fn state_dir() -> PathBuf {
    if let Some(path) = env::var_os("P2WLAN_STATE_DIR") {
        return PathBuf::from(path);
    }
    if env::var_os("SUDO_USER").is_none() {
        if let Some(path) = env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(path).join("p2wlan");
        }
    }
    user_home().join(".local").join("state").join("p2wlan")
}

fn user_home() -> PathBuf {
    if let Ok(user) = env::var("SUDO_USER") {
        if user != "root" {
            if let Ok(mut passwd) = File::open("/etc/passwd") {
                let mut contents = String::new();
                if passwd.read_to_string(&mut contents).is_ok() {
                    for line in contents.lines() {
                        let fields = line.split(':').collect::<Vec<_>>();
                        if fields.len() >= 6 && fields[0] == user {
                            return PathBuf::from(fields[5]);
                        }
                    }
                }
            }
        }
    }
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn locate_daemon() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("P2WLAN_DAEMON") {
        return absolute_path(Path::new(&path));
    }
    let sibling = env::current_exe()
        .map_err(|error| format!("无法定位当前程序：{error}"))?
        .with_file_name("p2pnet-daemon");
    if sibling.is_file() {
        return Ok(sibling);
    }
    find_in_path("p2pnet-daemon").ok_or_else(|| {
        "找不到 p2pnet-daemon；请保持它与 p2wlan 位于同一目录，或设置 P2WLAN_DAEMON".to_string()
    })
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|path| path.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("无法解析路径 {}：{error}", path.display()))
    }
}

fn reject_sudo_config_write() -> Result<(), String> {
    if is_root() && env::var_os("SUDO_USER").is_some() {
        return Err(
            "login/logout/config 请不要使用 sudo；只有 p2wlan up 需要管理员权限".to_string(),
        );
    }
    Ok(())
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn verified_recorded_daemon(pid_path: &Path) -> Result<Option<i32>, String> {
    let Ok(raw) = fs::read_to_string(pid_path) else {
        return Ok(None);
    };
    let Ok(pid) = raw.trim().parse::<i32>() else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        if unsafe { libc::kill(pid, 0) } != 0 {
            return Ok(None);
        }
        let command_line = fs::read(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .split(|byte| *byte == 0)
            .filter_map(|part| std::str::from_utf8(part).ok())
            .collect::<Vec<_>>()
            .join(" ");
        if !command_line.contains("p2pnet-daemon") {
            return Err(format!(
                "PID 文件 {} 指向的不是 p2pnet-daemon，拒绝结束进程",
                pid_path.display()
            ));
        }
        Ok(Some(pid))
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Ok(None)
    }
}

fn terminate_daemon(pid: i32) -> Result<(), String> {
    if is_root() {
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            println!("已发送停止请求。");
            return Ok(());
        }
        return Err(format!(
            "无法结束 daemon PID {pid}：{}",
            io::Error::last_os_error()
        ));
    }
    let status = Command::new("sudo")
        .arg("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .map_err(|error| format!("无法执行 sudo kill：{error}"))?;
    if !status.success() {
        return Err(format!("无法结束 daemon PID {pid}（{status}）"));
    }
    println!("已发送停止请求。");
    Ok(())
}

fn make_world_readable(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .metadata()
            .map_err(|error| format!("无法读取日志权限：{error}"))?
            .permissions();
        permissions.set_mode(0o644);
        file.set_permissions(permissions)
            .map_err(|error| format!("无法设置日志权限：{error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parses_login_short_options() {
        let cli = Cli::try_parse_from([
            "p2wlan",
            "login",
            "-u",
            "you@example.com",
            "-p",
            "password123",
        ])
        .unwrap();
        let Commands::Login(args) = cli.command else {
            panic!("expected login command");
        };
        assert_eq!(args.username, "you@example.com");
        assert_eq!(args.password.as_deref(), Some("password123"));
    }

    #[test]
    fn parses_help_subcommand_without_side_effects() {
        let error = Cli::try_parse_from(["p2wlan", "help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn parses_update_options() {
        let cli = Cli::try_parse_from([
            "p2wlan",
            "update",
            "--dry-run",
            "--version",
            "v0.1.24",
            "--install-dir",
            "/tmp/bin",
        ])
        .unwrap();
        let Commands::Update(args) = cli.command else {
            panic!("expected update command");
        };
        assert!(args.dry_run);
        assert_eq!(args.version.as_deref(), Some("v0.1.24"));
        assert_eq!(args.install_dir.as_deref(), Some(Path::new("/tmp/bin")));
    }

    #[test]
    fn validates_and_sets_safe_config_values() {
        let mut config = Config::generate_default(DEFAULT_CONTROL_SERVER, DEFAULT_NETWORK).unwrap();
        set_config_value(&mut config, "mtu", "1380").unwrap();
        set_config_value(&mut config, "relay-policy", "relay").unwrap();
        set_config_value(&mut config, "device-name", "linux-server").unwrap();
        set_config_value(&mut config, "udp-bind", "0.0.0.0:60207").unwrap();
        set_config_value(&mut config, "udp-advertise", "203.0.113.10:60207").unwrap();
        set_config_value(
            &mut config,
            "stun",
            "stun.l.google.com:19302,74.125.250.129:19302",
        )
        .unwrap();
        set_config_value(&mut config, "direct-timeout", "7000ms").unwrap();
        assert_eq!(config.network.mtu, 1380);
        assert!(!config.relay.prefer_direct);
        assert_eq!(config.node.device_name, "linux-server");
        assert_eq!(config.network.udp_bind, "0.0.0.0:60207");
        assert_eq!(
            config.network.udp_advertise.as_deref(),
            Some("203.0.113.10:60207")
        );
        assert_eq!(config.network.stun_servers.len(), 2);
        assert_eq!(config.network.stun_servers[0], "stun.l.google.com:19302");
        assert_eq!(config.relay.fallback_timeout_ms, 7000);
        set_config_value(&mut config, "udp-advertise", "off").unwrap();
        assert!(config.network.udp_advertise.is_none());
        set_config_value(&mut config, "stun", "off").unwrap();
        assert_eq!(config.network.stun_servers, vec!["off".to_string()]);
        assert!(set_config_value(&mut config, "mtu", "10").is_err());
        assert!(set_config_value(&mut config, "udp-advertise", "0.0.0.0:60207").is_err());
        assert!(set_config_value(&mut config, "diagnostics", "0.0.0.0:39277").is_err());
        assert!(set_config_value(&mut config, "auth-token", "secret").is_err());
    }

    #[test]
    fn doctor_suggests_udp_advertise_for_private_only_peer_candidates() {
        let snapshot = serde_json::json!({
            "peers": [{
                "node_id": "peer1",
                "device_name": "windows-cloud",
                "virtual_ip": "10.20.0.5",
                "endpoint": "192.168.2.4:49877",
                "candidates": ["192.168.2.4:49877", "127.0.0.1:60207"],
                "direct": { "last_error": "no UDP punch ACK after 30 probes" }
            }]
        });
        let suggestions = peer_direct_suggestions(&snapshot);
        assert_eq!(suggestions.len(), 1);
        assert!(suggestions[0].contains("windows-cloud(10.20.0.5)"));
        assert!(suggestions[0].contains("udp-advertise"));
    }

    #[test]
    fn doctor_does_not_flag_peer_with_public_candidate_as_private_only() {
        let snapshot = serde_json::json!({
            "peers": [{
                "node_id": "peer1",
                "device_name": "linux-server",
                "virtual_ip": "10.20.0.7",
                "endpoint": "203.0.113.10:60207",
                "candidates": ["203.0.113.10:60207"],
                "direct": { "last_error": "no direct probe ACK after 6 retry probes" }
            }]
        });
        let suggestions = peer_direct_suggestions(&snapshot);
        assert_eq!(suggestions.len(), 1);
        assert!(suggestions[0].contains("Direct UDP 探测失败"));
        assert!(!suggestions[0].contains("只上报了私网/回环"));
    }

    #[test]
    fn normalizes_control_url() {
        assert_eq!(
            normalize_control_server(" http://127.0.0.1:18080/// ").unwrap(),
            "http://127.0.0.1:18080"
        );
        assert!(normalize_control_server("file:///tmp/control").is_err());
    }

    #[tokio::test]
    async fn login_saves_token_from_control_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let count = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..count]);
            assert!(request.starts_with("POST /api/v1/login "));
            assert!(request.contains("\"email\":\"user@example.com\""));
            let body = r#"{"success":true,"token":"test-token"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = env::temp_dir().join(format!("p2wlan-cli-login-{unique}"));
        let path = directory.join("p2pnet-config.json");
        authenticate(
            &path,
            AuthArgs {
                username: "USER@example.com".to_string(),
                password: Some("password123".to_string()),
                server: Some(format!("http://{address}")),
            },
            false,
        )
        .await
        .unwrap();
        server.await.unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.control.auth_token, "test-token");
        assert_eq!(config.control.server_url, format!("http://{address}"));
        assert!(config.diagnostics.enabled);
        let _ = fs::remove_dir_all(directory);
    }
}
