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

fn parse_bool_config(value: &str, label: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "enable" | "enabled" => Ok(true),
        "0" | "false" | "no" | "off" | "disable" | "disabled" => Ok(false),
        _ => Err(format!("{label} 只支持 on/off、true/false 或 yes/no")),
    }
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
