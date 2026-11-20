#[derive(Subcommand, Debug, Clone, Copy)]
enum WakeProxyAction {
    /// Enable the wake proxy on the next daemon start
    On,
    /// Disable the wake proxy on the next daemon start
    Off,
}

#[derive(Subcommand, Debug)]
enum WakeTargetCommand {
    /// Add a Wake-on-LAN target without installing p2wlan on it
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        mac: p2pnet_netbind::wake::MacAddress,
        /// Control network ID. Defaults to the configured network.
        #[arg(long)]
        network: Option<String>,
    },
    /// List manual targets without printing MAC addresses
    List {
        /// Control network ID. Defaults to the configured network.
        #[arg(long)]
        network: Option<String>,
    },
    /// Remove a manual target by ID
    Remove { id: String },
}

#[derive(Deserialize)]
struct WakeLocalStatus {
    proxy: bool,
    allow_remote: bool,
    proxy_state: String,
    target_state: String,
}

#[derive(Deserialize)]
struct ManualWakeTarget {
    id: String,
    name: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct ManualWakeTargets {
    targets: Vec<ManualWakeTarget>,
}

async fn wake_status(config_path: &Path) -> Result<(), String> {
    let config = load_config(config_path)?;
    if !config.diagnostics.enabled {
        return Err("本地诊断未启用。使用 p2wlan config set diagnostics <回环地址:端口> 启用后重启对应实例。".to_string());
    }
    let bind = parse_socket_addr(
        normalized_diagnostics_bind(&config.diagnostics.bind),
        "diagnostics",
    )?;
    if !bind.ip().is_loopback() {
        return Err("远程开机诊断只接受本机回环地址".to_string());
    }
    let endpoint = diagnostics_endpoint(&config, "/wake");
    let (status, body) = diagnostics_request(
        &endpoint,
        &state_dir_for_config(config_path),
        reqwest::Method::GET,
    )
    .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err("当前 daemon 不支持远程开机诊断".to_string());
    }
    if !status.is_success() {
        return Err(format!("远程开机诊断失败（HTTP {status}）"));
    }
    let state: WakeLocalStatus =
        serde_json::from_str(&body).map_err(|_| "远程开机诊断响应无效".to_string())?;
    println!(
        "代理={} ({})",
        state.proxy,
        state.proxy_state.escape_debug()
    );
    println!(
        "允许远程开机={} ({})",
        state.allow_remote,
        state.target_state.escape_debug()
    );
    Ok(())
}

fn wake_proxy(config_path: &Path, action: WakeProxyAction) -> Result<(), String> {
    reject_sudo_config_write()?;
    let mut config = load_config(config_path)?;
    config.wake.proxy = matches!(action, WakeProxyAction::On);
    save_config(&config, config_path)?;
    println!("已保存唤醒代理设置。重启对应 daemon 实例后生效。");
    Ok(())
}

async fn wake_targets(config_path: &Path, command: WakeTargetCommand) -> Result<(), String> {
    let mut config = load_config(config_path)?;
    hydrate_cli_session_token(config_path, &mut config)?;
    match command {
        WakeTargetCommand::Add { name, mac, network } => {
            let path = wake_target_list_path(&config, network.as_deref())?;
            let value = wake_control_request(
                &config,
                reqwest::Method::POST,
                &path,
                Some(serde_json::json!({"name": name, "mac": mac.to_string()})),
            )
            .await?;
            let target: ManualWakeTarget = serde_json::from_value(value)
                .map_err(|_| "服务器返回的唤醒目标无效".to_string())?;
            println!("已添加唤醒目标 {}", target.id.escape_debug());
        }
        WakeTargetCommand::List { network } => {
            let path = wake_target_list_path(&config, network.as_deref())?;
            let value = wake_control_request(&config, reqwest::Method::GET, &path, None).await?;
            let list: ManualWakeTargets = serde_json::from_value(value)
                .map_err(|_| "服务器返回的唤醒目标列表无效".to_string())?;
            for target in list.targets {
                let state = if target.enabled { "启用" } else { "停用" };
                println!(
                    "{}  {}  {state}",
                    target.id.escape_debug(),
                    target.name.escape_debug()
                );
            }
        }
        WakeTargetCommand::Remove { id } => {
            validate_wake_path_segment("id", &id)?;
            wake_control_request(
                &config,
                reqwest::Method::DELETE,
                &format!("/wake-targets/{id}"),
                None,
            )
            .await?;
            println!("已删除唤醒目标。");
        }
    }
    Ok(())
}

fn validate_wake_path_segment(label: &str, value: &str) -> Result<(), String> {
    validate_path_segment(label, value)?;
    if matches!(value, "." | "..") {
        return Err(format!("{label} 包含无效字符"));
    }
    Ok(())
}

fn wake_target_list_path(config: &Config, network: Option<&str>) -> Result<String, String> {
    let network = network.unwrap_or(&config.network.network_id);
    validate_wake_path_segment("network", network)?;
    Ok(format!("/networks/{network}/wake-targets"))
}

async fn wake_control_request(
    config: &Config,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    require_control_auth(config)?;
    let server = normalize_room_control_server(&config.control.server_url)?;
    let url = Url::parse(&server).map_err(|_| "唤醒控制服务器地址无效".to_string())?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]"));
    if url.scheme() != "https" && !loopback {
        return Err("远程开机要求 Control 使用 HTTPS".to_string());
    }
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .redirect(reqwest::redirect::Policy::none());
    if loopback || config.control.proxy_mode.as_label() == "direct" {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|_| "无法初始化唤醒请求".to_string())?;
    let mut request = client
        .request(method, format!("{server}/api/v1{path}"))
        .bearer_auth(&config.control.auth_token)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(body) = body {
        request = request.json(&body);
    }
    let mut response = request
        .send()
        .await
        .map_err(|_| "无法访问唤醒服务".to_string())?;
    let status = response.status();
    if !status.is_success() {
        let message = match status {
            reqwest::StatusCode::BAD_REQUEST => "唤醒目标参数无效",
            reqwest::StatusCode::UNAUTHORIZED => "登录状态已失效，请重新登录",
            reqwest::StatusCode::FORBIDDEN => "无权管理该网络的唤醒目标",
            reqwest::StatusCode::NOT_FOUND => "唤醒目标不可用，或当前 Control 尚未支持远程开机",
            reqwest::StatusCode::CONFLICT => "唤醒目标与当前网络设置冲突",
            reqwest::StatusCode::TOO_MANY_REQUESTS => "已达到唤醒操作限额，请稍后重试",
            _ => "唤醒请求失败",
        };
        return Err(format!("{message}（HTTP {status}）"));
    }
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }
    const MAX_WAKE_RESPONSE_BYTES: usize = 1024 * 1024;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "读取唤醒服务响应失败".to_string())?
    {
        if bytes.len() + chunk.len() > MAX_WAKE_RESPONSE_BYTES {
            return Err("唤醒服务响应过大".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "唤醒服务响应无效".to_string())
}
