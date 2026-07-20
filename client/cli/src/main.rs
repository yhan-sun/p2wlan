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
                "网络代际：{}",
                snapshot
                    .get("network_generation")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            );
            println!(
                "UDP local：{}",
                value_text(&snapshot, "udp_local_addr", "未知")
            );
            print_nat_diagnostics(&snapshot);
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
            print_relay_diagnostics(&snapshot);
            print_peer_diagnostics(&snapshot);
            suggestions.extend(nat_profile_suggestions(
                &snapshot,
                config
                    .network
                    .udp_advertise
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty()),
            ));
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

fn print_nat_diagnostics(snapshot: &Value) {
    let candidates = local_candidate_strings(snapshot);
    if !candidates.is_empty() {
        println!(
            "UDP candidates：{}{}",
            candidates.len(),
            endpoint_preview(&candidates, 4)
        );
    }

    if let Some(summary) = nat_profile_summary(snapshot) {
        println!("NAT：{summary}");
        for observation in stun_observation_summaries(snapshot, 3) {
            println!("STUN：{observation}");
        }
    } else {
        println!("NAT：未采集");
    }
}

fn nat_profile_summary(snapshot: &Value) -> Option<String> {
    let profile = snapshot.get("nat_profile")?.as_object()?;
    let mapping = profile
        .get("mapping_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let public_endpoint = profile
        .get("public_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let (stun_success, stun_total) = stun_observation_counts(snapshot);
    let confidence = profile
        .get("confidence")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    Some(format!(
        "mapping={mapping} public={public_endpoint} stun={stun_success}/{stun_total} confidence={confidence} symmetric={} port_preserved={}",
        nat_bool_text(profile.get("likely_symmetric")),
        nat_bool_text(profile.get("port_preserved"))
    ))
}

fn stun_observation_summaries(snapshot: &Value, limit: usize) -> Vec<String> {
    let Some(observations) = snapshot
        .get("nat_profile")
        .and_then(|profile| profile.get("observations"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    observations
        .iter()
        .take(limit)
        .map(|observation| {
            let server = observation
                .get("server")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if let Some(mapped) = observation.get("mapped_address").and_then(Value::as_str) {
                let rtt = observation
                    .get("rtt_ms")
                    .and_then(Value::as_u64)
                    .map(|ms| format!("{ms}ms"))
                    .unwrap_or_else(|| "unknown".to_string());
                format!("server={server} mapped={mapped} rtt={rtt}")
            } else {
                let error = observation
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                format!("server={server} error={error}")
            }
        })
        .collect()
}

fn nat_profile_suggestions(snapshot: &Value, udp_advertise_configured: bool) -> Vec<String> {
    let mut suggestions = Vec::new();
    let candidates = local_candidate_strings(snapshot);
    let has_public_candidate = candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .any(|endpoint| is_public_udp_endpoint(&endpoint));

    let Some(profile) = snapshot.get("nat_profile").and_then(Value::as_object) else {
        if candidates.is_empty() {
            suggestions.push(
                "daemon 尚未采集到 UDP candidate/NAT profile；如果刚启动，请等待几秒或检查 STUN 配置。"
                    .to_string(),
            );
        }
        return suggestions;
    };

    if profile
        .get("udp_blocked")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        suggestions.push(
            "本机 STUN 全失败，可能 UDP 被防火墙、安全组、运营商或公司网络阻断；直连会高度依赖 Relay。"
                .to_string(),
        );
    }

    let mapping = profile
        .get("mapping_behavior")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let likely_symmetric = profile
        .get("likely_symmetric")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if likely_symmetric || mapping == "address_or_port_dependent" {
        suggestions.push(
            "本机疑似对称/地址端口相关 NAT；当前基础打洞成功率有限，后续应启用 peer-reflexive、端口预测和 birthday probing。"
                .to_string(),
        );
    }

    if !udp_advertise_configured
        && profile
            .get("public_endpoint")
            .and_then(Value::as_str)
            .is_none()
    {
        suggestions.push(
            "未发现本机公网 UDP endpoint；云服务器或固定公网主机建议配置 udp-advertise <公网IP>:<端口>。"
                .to_string(),
        );
    }

    if !udp_advertise_configured && !candidates.is_empty() && !has_public_candidate {
        suggestions.push(
            "本机当前只上报私网/回环 UDP candidate；跨公网直连通常需要 STUN 成功或显式 udp-advertise。"
                .to_string(),
        );
    }

    suggestions
}

fn local_candidate_strings(snapshot: &Value) -> Vec<String> {
    snapshot
        .get("local_candidates")
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

fn stun_observation_counts(snapshot: &Value) -> (usize, usize) {
    let Some(observations) = snapshot
        .get("nat_profile")
        .and_then(|profile| profile.get("observations"))
        .and_then(Value::as_array)
    else {
        return (0, 0);
    };
    let success = observations
        .iter()
        .filter(|observation| {
            observation
                .get("mapped_address")
                .and_then(Value::as_str)
                .is_some()
        })
        .count();
    (success, observations.len())
}

fn nat_bool_text(value: Option<&Value>) -> &'static str {
    match value.and_then(Value::as_bool) {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
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
        let direct_generation = peer
            .get("direct_generation")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let pair_summary = candidate_pair_summary(peer);
        println!(
            "- {} ({}) state={} path={} endpoint={} candidates={}{} direct_gen={}{}",
            short_text(name, 24),
            virtual_ip,
            state,
            active_path,
            endpoint,
            candidate_count,
            candidate_preview,
            direct_generation,
            pair_summary
        );
        if let Some(stage) = direct_failure_stage(peer) {
            println!("  direct-stage={stage}");
        }
        if let Some(summary) = direct_health_summary(peer) {
            println!("  direct-health={summary}");
        }
        if let Some(retry) = direct_retry_summary(peer) {
            println!("  direct-retry={retry}");
        }
        if let Some(selection) = path_selection_summary(peer, "current_path_selection") {
            println!("  path-selection={selection}");
        }
        if let Some(selection) = path_selection_summary(peer, "last_path_selection") {
            println!("  last-path-selection={selection}");
        }
        for event in path_event_summaries(peer, 3) {
            println!("  path-event={event}");
        }
        if let Some(reason) = relay_path_reason(snapshot, peer) {
            println!("  relay-reason={reason}");
        }
    }
}

fn print_relay_diagnostics(snapshot: &Value) {
    let Some(relay) = snapshot
        .get("relay_selection")
        .filter(|value| value.is_object())
    else {
        return;
    };

    let selected_region = relay
        .get("selected_region")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let selected_endpoint = relay
        .get("selected_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let latency = relay
        .get("selected_connect_latency_ms")
        .and_then(Value::as_u64)
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "unknown".to_string());
    let candidate_count = relay
        .get("candidates")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    println!(
        "Relay selection：region={} endpoint={} latency={} candidates={}",
        selected_region, selected_endpoint, latency, candidate_count
    );
    if let Some(health) = relay_health_summary(relay) {
        println!("Relay health：{health}");
    }
    for cooldown in relay_cooldown_summaries(relay).into_iter().take(3) {
        println!("Relay cooldown：{cooldown}");
    }

    if let Some(error) = relay.get("last_error").and_then(Value::as_str) {
        let code = relay
            .get("last_error_code")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        println!("Relay error：code={code} message={error}");
    }
}

fn relay_health_summary(relay: &Value) -> Option<String> {
    let pong_count = relay
        .get("selected_pong_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let error_count = relay
        .get("selected_error_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if pong_count == 0 && error_count == 0 {
        return None;
    }

    let last_rtt = relay_ms_text(relay, "selected_last_pong_rtt_ms");
    let rtt_ewma = relay_ms_text(relay, "selected_rtt_ewma_ms");
    let jitter = relay_ms_text(relay, "selected_jitter_ms");
    let last_pong = relay
        .get("selected_last_pong_age_ms")
        .and_then(Value::as_u64)
        .map(|ms| format!("{ms}ms_ago"))
        .unwrap_or_else(|| "never".to_string());

    Some(format!(
        "pong={} errors={} last_rtt={} rtt_ewma={} jitter={} last_pong={}",
        pong_count, error_count, last_rtt, rtt_ewma, jitter, last_pong
    ))
}

fn relay_ms_text(relay: &Value, field: &str) -> String {
    relay
        .get(field)
        .and_then(Value::as_u64)
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn relay_cooldown_summaries(relay: &Value) -> Vec<String> {
    let Some(candidates) = relay.get("candidates").and_then(Value::as_array) else {
        return Vec::new();
    };

    candidates
        .iter()
        .filter(|candidate| {
            candidate
                .get("error_code")
                .and_then(Value::as_str)
                .is_some_and(|code| code == "cooling_down" || code.starts_with("runtime_"))
        })
        .map(|candidate| {
            let region = candidate
                .get("region")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let endpoint = candidate
                .get("endpoint")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let remaining = candidate
                .get("cooldown_remaining_ms")
                .and_then(Value::as_u64)
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "unknown".to_string());
            format!("region={region} endpoint={endpoint} remaining={remaining}")
        })
        .collect()
}

fn peer_direct_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(peers) = snapshot.get("peers").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut private_only_peers = Vec::new();
    let mut generation_changed_peers = Vec::new();
    let mut handshake_timeout_peers = Vec::new();
    let mut direct_send_failed_peers = Vec::new();
    let mut generic_direct_failures = 0_u64;
    for peer in peers {
        let direct_error_code = direct_error_code(peer);
        let has_direct_error = direct_failure_stage(peer).is_some();
        if has_direct_error && matches!(direct_error_code, Some("direct_probe_failed") | None) {
            generic_direct_failures += 1;
        }
        match direct_error_code {
            Some("network_generation_changed") => {
                generation_changed_peers.push(peer_display_name(peer))
            }
            Some("handshake_timeout") => handshake_timeout_peers.push(peer_display_name(peer)),
            Some("direct_send_failed") => direct_send_failed_peers.push(peer_display_name(peer)),
            _ => {}
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
    if !generation_changed_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 的 Direct 状态来自旧网络代际，已切回 Relay；等待新的 UDP candidate/ACK 后会自动重新选择直连。",
            generation_changed_peers.join("、")
        ));
    }
    if !handshake_timeout_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} UDP 探测后 WireGuard 握手超时；通常是单向 UDP、防火墙状态表或对端会话未及时刷新。",
            handshake_timeout_peers.join("、")
        ));
    }
    if !direct_send_failed_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 的 Direct 发送失败，daemon 已降级 Relay；请重点查看网络切换、防火墙和 UDP endpoint 是否漂移。",
            direct_send_failed_peers.join("、")
        ));
    }
    if !private_only_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 只上报了私网/回环 UDP 候选；请在对应设备配置 udp-advertise <公网IP>:<端口>，并放行同一个 UDP 入站端口。",
            private_only_peers.join("、")
        ));
    } else if generic_direct_failures > 0 {
        suggestions.push(
            "检测到 Direct UDP 探测失败；请确认两端 udp-bind/udp-advertise、云安全组和系统防火墙使用同一个 UDP 端口。"
                .to_string(),
        );
    }
    suggestions
}

fn relay_path_reason(snapshot: &Value, peer: &Value) -> Option<String> {
    let active_path = peer.get("active_path").and_then(Value::as_str);
    let state = peer.get("state").and_then(Value::as_str);
    let relayish = matches!(active_path, Some("relay"))
        || matches!(state, Some("relay" | "fallback_to_relay"));
    if !relayish {
        return None;
    }

    if let Some(reason) = path_selection_reason(peer) {
        return Some(reason);
    }

    if let Some(stage) = direct_failure_stage(peer) {
        return Some(format!("Direct 不可用：{stage}"));
    }

    let snapshot_generation = snapshot
        .get("network_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let direct_generation = peer
        .get("direct_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if direct_generation < snapshot_generation {
        return Some(format!(
            "Direct 成功属于旧网络代际 {direct_generation}，当前代际 {snapshot_generation} 正在重新探测"
        ));
    }

    let candidates = peer_candidate_strings(peer);
    if candidates.is_empty() {
        return Some("对端暂无 UDP candidate".to_string());
    }

    if let Some(relay) = snapshot
        .get("relay_selection")
        .filter(|value| value.is_object())
    {
        let region = relay
            .get("selected_region")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let endpoint = relay
            .get("selected_endpoint")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(format!(
            "Relay 已选中 {region} / {endpoint}，Direct 尚未确认"
        ));
    }

    Some("Relay fallback 已生效，Direct 尚未确认".to_string())
}

fn path_selection_summary(peer: &Value, field: &str) -> Option<String> {
    let selection = peer.get(field)?.as_object()?;
    let path = selection
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let endpoint = selection
        .get("direct_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let reason_code = selection.get("reason_code").and_then(Value::as_str)?;
    let reason = selection
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("");
    let confirmed = selection
        .get("direct_confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let direct_score = selection_score_text(selection.get("direct_score"));
    let relay_score = selection_score_text(selection.get("relay_score"));

    Some(format!(
        "path={path} endpoint={endpoint} confirmed={confirmed} direct_score={direct_score} relay_score={relay_score} code={reason_code} reason={reason}"
    ))
}

fn selection_score_text(score: Option<&Value>) -> String {
    let Some(score) = score.and_then(Value::as_object) else {
        return "n/a".to_string();
    };
    let value = score
        .get("score")
        .and_then(Value::as_i64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let reason = score.get("reason").and_then(Value::as_str).unwrap_or("");
    if reason.is_empty() {
        value
    } else {
        format!("{value}({reason})")
    }
}

fn path_event_summaries(peer: &Value, limit: usize) -> Vec<String> {
    let Some(events) = peer.get("path_events").and_then(Value::as_array) else {
        return Vec::new();
    };
    let start = events.len().saturating_sub(limit);
    events[start..]
        .iter()
        .filter_map(path_event_summary)
        .collect()
}

fn path_event_summary(event: &Value) -> Option<String> {
    let age = event
        .get("selected_age_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let generation = event
        .get("network_generation")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let previous = event
        .get("previous_path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let selected = event
        .get("selected_path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let endpoint = event
        .get("direct_endpoint")
        .and_then(Value::as_str)
        .unwrap_or("(none)");
    let reason_code = event.get("reason_code").and_then(Value::as_str)?;
    let direct_score = selection_score_text(event.get("direct_score"));
    let relay_score = selection_score_text(event.get("relay_score"));

    Some(format!(
        "age={}ms gen={} {}->{} endpoint={} direct_score={} relay_score={} code={}",
        age, generation, previous, selected, endpoint, direct_score, relay_score, reason_code
    ))
}

fn direct_health_summary(peer: &Value) -> Option<String> {
    let direct = peer.get("direct")?.as_object()?;
    let success_count = direct
        .get("success_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let failure_count = direct
        .get("failure_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let ewma = direct.get("rtt_ewma_ms").and_then(Value::as_u64);
    let jitter = direct.get("jitter_ms").and_then(Value::as_u64);
    if success_count == 0 && failure_count == 0 && ewma.is_none() && jitter.is_none() {
        return None;
    }

    Some(format!(
        "success={} failure={} rtt_ewma={} jitter={}",
        success_count,
        failure_count,
        ewma.map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "unknown".to_string()),
        jitter
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "unknown".to_string())
    ))
}

fn direct_retry_summary(peer: &Value) -> Option<String> {
    let retry_after = peer.get("direct_retry_after_ms").and_then(Value::as_u64)?;
    let remaining = peer
        .get("direct_retry_remaining_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if retry_after == 0 || remaining == 0 {
        return None;
    }
    Some(format!(
        "next_probe_in={}ms backoff={}ms",
        remaining, retry_after
    ))
}

fn path_selection_reason(peer: &Value) -> Option<String> {
    let selection = peer
        .get("current_path_selection")
        .or_else(|| peer.get("last_path_selection"))?
        .as_object()?;
    let path = selection
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let reason_code = selection.get("reason_code").and_then(Value::as_str)?;
    let reason = selection
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("");

    let path_label = match path {
        "direct" => "Direct",
        "relay" => "Relay",
        _ => "无可用路径",
    };
    Some(format!(
        "Path selector 选择 {path_label}：{}（{reason_code}）：{reason}",
        path_reason_label(reason_code)
    ))
}

fn direct_failure_stage(peer: &Value) -> Option<String> {
    let direct = peer.get("direct")?;
    let error = direct.get("last_error").and_then(Value::as_str);
    let code = direct.get("last_error_code").and_then(Value::as_str);
    match (code, error) {
        (Some(code), Some(error)) => Some(format!("{}：{}", reason_label(code), error)),
        (Some(code), None) => Some(reason_label(code).to_string()),
        (None, Some(error)) => Some(error.to_string()),
        (None, None) => None,
    }
}

fn direct_error_code(peer: &Value) -> Option<&str> {
    peer.get("direct")
        .and_then(|direct| direct.get("last_error_code"))
        .and_then(Value::as_str)
}

fn reason_label(code: &str) -> &'static str {
    match code {
        "network_generation_changed" => "网络切换后 Direct 状态失效",
        "direct_probe_failed" => "UDP 探测未确认",
        "direct_send_failed" => "Direct UDP 发送失败",
        "handshake_timeout" => "WireGuard 握手超时",
        _ => "Direct 失败",
    }
}

fn path_reason_label(code: &str) -> &'static str {
    match code {
        "path_direct_confirmed" => "Direct UDP pair 已确认",
        "path_direct_trial" => "Direct 最近成功，处于试探窗口",
        "path_relay_unavailable" => "Relay 不可用，尝试 Direct",
        "path_direct_disabled" => "策略禁用 Direct",
        "path_direct_no_endpoint" => "没有 Direct UDP endpoint",
        "path_direct_not_confirmed" => "Direct UDP 尚未确认",
        "path_direct_degraded" => "Direct 质量低于 Relay",
        "path_unavailable" => "没有可用数据路径",
        _ => "路径选择原因",
    }
}

fn candidate_pair_summary(peer: &Value) -> String {
    let Some(pairs) = peer.get("candidate_pairs").and_then(Value::as_array) else {
        return String::new();
    };
    if pairs.is_empty() {
        return String::new();
    }

    let mut selected = 0;
    let mut succeeded = 0;
    let mut probing = 0;
    let mut failed = 0;
    let mut degraded = 0;
    for pair in pairs {
        match pair
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
        {
            "selected" => selected += 1,
            "succeeded" => succeeded += 1,
            "probing" => probing += 1,
            "failed" => failed += 1,
            "degraded" => degraded += 1,
            _ => {}
        }
    }

    let mut parts = Vec::new();
    if selected > 0 {
        parts.push(format!("selected={selected}"));
    }
    if succeeded > 0 {
        parts.push(format!("succeeded={succeeded}"));
    }
    if probing > 0 {
        parts.push(format!("probing={probing}"));
    }
    if failed > 0 {
        parts.push(format!("failed={failed}"));
    }
    if degraded > 0 {
        parts.push(format!("degraded={degraded}"));
    }
    if parts.is_empty() {
        format!(" pairs={}", pairs.len())
    } else {
        format!(" pairs={}({})", pairs.len(), parts.join(","))
    }
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
    fn relay_health_summary_reports_runtime_measurements() {
        let relay = serde_json::json!({
            "selected_pong_count": 3,
            "selected_error_count": 1,
            "selected_last_pong_age_ms": 250,
            "selected_last_pong_rtt_ms": 42,
            "selected_rtt_ewma_ms": 39,
            "selected_jitter_ms": 5
        });

        assert_eq!(
            relay_health_summary(&relay).as_deref(),
            Some("pong=3 errors=1 last_rtt=42ms rtt_ewma=39ms jitter=5ms last_pong=250ms_ago")
        );
    }

    #[test]
    fn relay_cooldown_summary_reports_skipped_candidates() {
        let relay = serde_json::json!({
            "candidates": [{
                "region": "cn-east",
                "endpoint": "relay-a.example.com:443",
                "cooldown_remaining_ms": 8_500,
                "error_code": "cooling_down"
            }, {
                "region": "cn-south",
                "endpoint": "relay-b.example.com:443",
                "error_code": null
            }]
        });

        assert_eq!(
            relay_cooldown_summaries(&relay),
            vec!["region=cn-east endpoint=relay-a.example.com:443 remaining=8500ms".to_string()]
        );
    }

    #[test]
    fn nat_profile_summary_formats_stable_mapping() {
        let snapshot = serde_json::json!({
            "local_candidates": ["192.168.2.4:60207", "203.0.113.10:62000"],
            "nat_profile": {
                "mapping_behavior": "endpoint_independent",
                "udp_blocked": false,
                "public_endpoint": "203.0.113.10:62000",
                "likely_symmetric": false,
                "port_preserved": false,
                "confidence": 70,
                "observations": [{
                    "server": "stun-a.example:3478",
                    "mapped_address": "203.0.113.10:62000",
                    "rtt_ms": 12,
                    "error": null
                }, {
                    "server": "stun-b.example:3478",
                    "mapped_address": "203.0.113.10:62000",
                    "rtt_ms": 18,
                    "error": null
                }, {
                    "server": "stun-c.example:3478",
                    "mapped_address": null,
                    "rtt_ms": null,
                    "error": "timeout"
                }]
            }
        });

        assert_eq!(
            nat_profile_summary(&snapshot).as_deref(),
            Some("mapping=endpoint_independent public=203.0.113.10:62000 stun=2/3 confidence=70 symmetric=false port_preserved=false")
        );
        assert_eq!(
            stun_observation_summaries(&snapshot, 2),
            vec![
                "server=stun-a.example:3478 mapped=203.0.113.10:62000 rtt=12ms".to_string(),
                "server=stun-b.example:3478 mapped=203.0.113.10:62000 rtt=18ms".to_string(),
            ]
        );
        assert!(nat_profile_suggestions(&snapshot, false).is_empty());
    }

    #[test]
    fn nat_profile_suggestions_explain_udp_blocked_and_symmetric() {
        let blocked = serde_json::json!({
            "local_candidates": ["192.168.2.4:60207"],
            "nat_profile": {
                "mapping_behavior": "udp_blocked",
                "udp_blocked": true,
                "public_endpoint": null,
                "likely_symmetric": null,
                "port_preserved": null,
                "confidence": 60,
                "observations": [{
                    "server": "stun-a.example:3478",
                    "mapped_address": null,
                    "rtt_ms": null,
                    "error": "timeout"
                }]
            }
        });
        let suggestions = nat_profile_suggestions(&blocked, false);
        assert!(suggestions.iter().any(|item| item.contains("STUN 全失败")));
        assert!(suggestions
            .iter()
            .any(|item| item.contains("udp-advertise")));
        assert!(suggestions
            .iter()
            .any(|item| item.contains("只上报私网/回环")));

        let symmetric = serde_json::json!({
            "local_candidates": ["198.51.100.10:62000", "198.51.100.10:62008"],
            "nat_profile": {
                "mapping_behavior": "address_or_port_dependent",
                "udp_blocked": false,
                "public_endpoint": "198.51.100.10:62000",
                "likely_symmetric": true,
                "port_preserved": false,
                "confidence": 70,
                "observations": []
            }
        });
        let suggestions = nat_profile_suggestions(&symmetric, false);
        assert!(suggestions.iter().any(|item| item.contains("端口预测")));
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
    fn doctor_explains_relay_reason_with_stable_reason_code() {
        let snapshot = serde_json::json!({
            "network_generation": 3,
            "relay_selection": {
                "selected_region": "cn-east",
                "selected_endpoint": "relay.example.com:443",
                "selected_connect_latency_ms": 42,
                "candidates": []
            },
            "peers": [{
                "node_id": "peer1",
                "device_name": "laptop",
                "virtual_ip": "10.20.0.5",
                "state": "fallback_to_relay",
                "active_path": "relay",
                "direct_generation": 3,
                "candidates": ["203.0.113.10:60207"],
                "direct": {
                    "last_error_code": "handshake_timeout",
                    "last_error": "handshake timed out"
                }
            }]
        });
        let peer = &snapshot["peers"][0];

        assert_eq!(
            direct_failure_stage(peer).as_deref(),
            Some("WireGuard 握手超时：handshake timed out")
        );
        assert_eq!(
            relay_path_reason(&snapshot, peer).as_deref(),
            Some("Direct 不可用：WireGuard 握手超时：handshake timed out")
        );
        let suggestions = peer_direct_suggestions(&snapshot);
        assert!(suggestions
            .iter()
            .any(|item| item.contains("WireGuard 握手超时")));
    }

    #[test]
    fn doctor_prefers_explicit_path_selection_reason() {
        let snapshot = serde_json::json!({
            "network_generation": 3,
            "relay_selection": {
                "selected_region": "cn-east",
                "selected_endpoint": "relay.example.com:443"
            },
            "peers": [{
                "node_id": "peer1",
                "device_name": "laptop",
                "virtual_ip": "10.20.0.5",
                "state": "relay",
                "active_path": "relay",
                "direct_generation": 3,
                "candidates": [],
                "current_path_selection": {
                    "path": "relay",
                    "direct_endpoint": null,
                    "reason_code": "path_direct_no_endpoint",
                    "reason": "direct UDP has no candidate endpoint",
                    "direct_confirmed": false,
                    "direct_score": null,
                    "relay_score": {
                        "path": "relay",
                        "score": 55,
                        "reachable": true,
                        "reachability_score": 55,
                        "preference_score": 0,
                        "latency_score": 0,
                        "stability_score": 0,
                        "penalty_score": 0,
                        "reason": "relay_available=true rtt=unknown jitter=unknown failures=0"
                    }
                },
                "direct": {
                    "last_error_code": "handshake_timeout",
                    "last_error": "old direct failure"
                }
            }]
        });
        let peer = &snapshot["peers"][0];

        assert_eq!(
            path_selection_summary(peer, "current_path_selection").as_deref(),
            Some("path=relay endpoint=(none) confirmed=false direct_score=n/a relay_score=55(relay_available=true rtt=unknown jitter=unknown failures=0) code=path_direct_no_endpoint reason=direct UDP has no candidate endpoint")
        );
        assert_eq!(
            relay_path_reason(&snapshot, peer).as_deref(),
            Some("Path selector 选择 Relay：没有 Direct UDP endpoint（path_direct_no_endpoint）：direct UDP has no candidate endpoint")
        );
    }

    #[test]
    fn doctor_formats_direct_health_and_retry_backoff() {
        let snapshot = serde_json::json!({
            "peers": [{
                "node_id": "peer1",
                "device_name": "laptop",
                "virtual_ip": "10.20.0.5",
                "direct_retry_after_ms": 10000,
                "direct_retry_remaining_ms": 4200,
                "direct": {
                    "success_count": 3,
                    "failure_count": 2,
                    "rtt_ewma_ms": 18,
                    "jitter_ms": 5
                }
            }]
        });
        let peer = &snapshot["peers"][0];

        assert_eq!(
            direct_health_summary(peer).as_deref(),
            Some("success=3 failure=2 rtt_ewma=18ms jitter=5ms")
        );
        assert_eq!(
            direct_retry_summary(peer).as_deref(),
            Some("next_probe_in=4200ms backoff=10000ms")
        );
    }

    #[test]
    fn doctor_formats_recent_path_events() {
        let snapshot = serde_json::json!({
            "peers": [{
                "node_id": "peer1",
                "device_name": "laptop",
                "virtual_ip": "10.20.0.5",
                "path_events": [{
                    "selected_age_ms": 250,
                    "network_generation": 2,
                    "previous_path": "relay",
                    "selected_path": "direct",
                    "direct_endpoint": "203.0.113.10:60207",
                    "reason_code": "path_direct_confirmed",
                    "reason": "direct UDP pair is confirmed; score=102",
                    "direct_confirmed": true,
                    "direct_score": {
                        "path": "direct",
                        "score": 102,
                        "reachable": true,
                        "reachability_score": 80,
                        "preference_score": 10,
                        "latency_score": 10,
                        "stability_score": 2,
                        "penalty_score": 0,
                        "reason": "reachable=true confirmed=true trial=true rtt=9ms jitter=0ms failures=0"
                    },
                    "relay_score": null
                }]
            }]
        });
        let peer = &snapshot["peers"][0];

        assert_eq!(
            path_event_summaries(peer, 3),
            vec!["age=250ms gen=2 relay->direct endpoint=203.0.113.10:60207 direct_score=102(reachable=true confirmed=true trial=true rtt=9ms jitter=0ms failures=0) relay_score=n/a code=path_direct_confirmed".to_string()]
        );
    }

    #[test]
    fn doctor_reports_generation_reprobe_reason() {
        let snapshot = serde_json::json!({
            "network_generation": 4,
            "relay_selection": {
                "selected_region": "cn-east",
                "selected_endpoint": "relay.example.com:443"
            },
            "peers": [{
                "node_id": "peer1",
                "device_name": "phone-hotspot",
                "virtual_ip": "10.20.0.9",
                "state": "relay",
                "active_path": "relay",
                "direct_generation": 3,
                "candidates": ["198.51.100.20:45000"],
                "direct": {
                    "last_error_code": "network_generation_changed",
                    "last_error": "network_generation_changed: refreshed UDP candidates"
                }
            }]
        });
        let peer = &snapshot["peers"][0];

        assert_eq!(
            relay_path_reason(&snapshot, peer).as_deref(),
            Some("Direct 不可用：网络切换后 Direct 状态失效：network_generation_changed: refreshed UDP candidates")
        );
        let suggestions = peer_direct_suggestions(&snapshot);
        assert!(suggestions.iter().any(|item| item.contains("旧网络代际")));
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
