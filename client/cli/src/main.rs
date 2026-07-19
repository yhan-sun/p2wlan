use clap::{Args, Parser, Subcommand};
use p2pnet_daemon::Config;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_CONTROL_SERVER: &str = "http://47.109.40.237:18080";
const DEFAULT_NETWORK: &str = "default";
const DEFAULT_DIAGNOSTICS_BIND: &str = "127.0.0.1:39277";

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
        /// control, network, device-name, interface, mtu, relay, or relay-policy
        key: String,
        value: String,
    },
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
            println!("relay = {}", config.relay.servers.join(","));
            println!(
                "relay-policy = {}",
                if config.relay.prefer_direct {
                    "auto"
                } else {
                    "relay"
                }
            );
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
        _ => {
            return Err(format!(
                "不支持的配置项 {key}；可用项：control、network、device-name、interface、mtu、relay、relay-policy"
            ))
        }
    }
    Ok(())
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
        let cli =
            Cli::try_parse_from(["p2wlan", "login", "-u", "pyu@qq.com", "-p", "pyu01234"]).unwrap();
        let Commands::Login(args) = cli.command else {
            panic!("expected login command");
        };
        assert_eq!(args.username, "pyu@qq.com");
        assert_eq!(args.password.as_deref(), Some("pyu01234"));
    }

    #[test]
    fn parses_help_subcommand_without_side_effects() {
        let error = Cli::try_parse_from(["p2wlan", "help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn validates_and_sets_safe_config_values() {
        let mut config = Config::generate_default(DEFAULT_CONTROL_SERVER, DEFAULT_NETWORK).unwrap();
        set_config_value(&mut config, "mtu", "1380").unwrap();
        set_config_value(&mut config, "relay-policy", "relay").unwrap();
        set_config_value(&mut config, "device-name", "linux-server").unwrap();
        assert_eq!(config.network.mtu, 1380);
        assert!(!config.relay.prefer_direct);
        assert_eq!(config.node.device_name, "linux-server");
        assert!(set_config_value(&mut config, "mtu", "10").is_err());
        assert!(set_config_value(&mut config, "auth-token", "secret").is_err());
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
