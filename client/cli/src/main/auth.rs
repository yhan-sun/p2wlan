async fn authenticate(path: &Path, args: AuthArgs, register: bool) -> Result<(), String> {
    reject_sudo_config_write()?;
    let identifier = args.username.trim().to_string();
    if identifier.is_empty() {
        return Err("请输入邮箱或用户名".to_string());
    }
    let identifier = if register || identifier.contains('@') {
        let email = identifier.to_lowercase();
        if register && !email.contains('@') {
            return Err("注册必须使用有效邮箱地址".to_string());
        }
        email
    } else {
        identifier
    };

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
        .unwrap_or_default();
    if server.trim().is_empty() {
        return Err(
            "尚未配置控制服务器，请先使用 `p2wlan config set control https://你的服务器`"
                .to_string(),
        );
    }
    let server = normalize_control_server(&server)?;

    let password = match args.password {
        Some(password) => password,
        None => rpassword::prompt_password("密码: ")
            .map_err(|error| format!("无法从终端读取密码：{error}"))?,
    };
    if password.len() < 6 {
        return Err("密码至少需要 6 个字符".to_string());
    }

    let endpoint = format!(
        "{server}/api/v1/{}",
        if register { "register" } else { "login" }
    );
    // The control server login never goes through a proxy: the request is a
    // one-shot credential exchange with the control plane itself, and a
    // system-level HTTP proxy would otherwise intercept loopback/LAN control
    // servers (some proxy clients even answer 502 for loopback).  HTTP(S)_PROXY
    // environment variables are deliberately NOT consulted here either.
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .build()
        .map_err(|error| format!("无法初始化网络请求：{error}"))?
        .post(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "identifier": identifier.clone(),
            "email": identifier.clone(),
            "password": password
        }))
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
    config.control.auth_token = token.clone();
    config.control.device_credential.clear();
    config.control.credential_issued = false;
    config.control.registration_seq = None;
    config.diagnostics.enabled = true;
    config.diagnostics.bind = DEFAULT_DIAGNOSTICS_BIND.to_string();
    save_config(&config, path)?;
    save_cli_session_token(path, &server, &token)?;

    println!(
        "{}成功：{}\n控制服务器：{}\n配置文件：{}",
        if register { "注册" } else { "登录" },
        identifier,
        server,
        path.display()
    );
    Ok(())
}

async fn logout(path: &Path) -> Result<(), String> {
    reject_sudo_config_write()?;
    let mut config = load_config(path)?;
    // Stop local data-plane instances before removing credentials.  A local
    // stop remains useful while the control server is unavailable; remote
    // revocation is reported separately below.
    if let Err(error) = stop(path).await {
        eprintln!("警告：无法停止主 daemon：{error}");
    }
    if let Some(room_root) = path.parent().map(|parent| parent.join("rooms")) {
        if let Ok(entries) = fs::read_dir(&room_root) {
            for entry in entries.flatten() {
                let profile = entry.path();
                let room_config = profile.join("p2wlan-config.json");
                if !room_config.is_file() {
                    continue;
                }
                let name = profile
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default();
                let room_state = room_state_dir_for_config(path, name);
                if let Err(error) = stop_with_state_dir(&room_config, &room_state).await {
                    eprintln!("警告：无法停止房间实例 {name}：{error}");
                }
            }
        }
    }
    if let Err(error) = revoke_current_device_credential(&config).await {
        eprintln!("警告：无法撤销远端设备凭证：{error}");
    }
    config.control.auth_token.clear();
    config.control.device_credential.clear();
    config.control.credential_issued = false;
    config.control.registration_seq = None;
    save_config(&config, path)?;
    clear_cli_session_token(path)?;
    println!("已退出登录，设备身份密钥和网络设置已保留。");
    Ok(())
}

async fn account_command(path: &Path, command: AccountCommand) -> Result<(), String> {
    let mut config = load_config(path)?;
    hydrate_cli_session_token(path, &mut config)?;
    require_control_auth(&config)?;
    let server = normalize_control_server(&config.control.server_url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| format!("无法初始化账号请求：{error}"))?;
    let response = client
        .get(format!("{server}/api/v1/profile"))
        .bearer_auth(&config.control.auth_token)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| format!("无法访问账号服务：{error}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("读取账号响应失败：{error}"))?;
    let value: Value =
        serde_json::from_str(&body).map_err(|error| format!("账号服务返回了无效响应：{error}"))?;
    if !status.is_success() {
        return Err(format!("账号请求失败（HTTP {status}）"));
    }
    let user = value.get("user").cloned().unwrap_or(Value::Null);
    let public = serde_json::json!({
        "schema_version": 1,
        "server": server,
        "user": {
            "id": user.get("id").and_then(Value::as_str).unwrap_or(""),
            "email": user.get("email").and_then(Value::as_str).unwrap_or(""),
            "username": user.get("username").and_then(Value::as_str).unwrap_or(""),
        }
    });
    match command {
        AccountCommand::Show { json: true } => println!(
            "{}",
            serde_json::to_string_pretty(&public).map_err(|error| error.to_string())?
        ),
        AccountCommand::Show { json: false } => {
            let user = &public["user"];
            println!("账号服务器：{}", public["server"].as_str().unwrap_or(""));
            println!("用户 ID：{}", user["id"].as_str().unwrap_or("(unknown)"));
            println!(
                "用户名：{}",
                user["username"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .unwrap_or("(未设置)")
            );
            println!(
                "邮箱：{}",
                user["email"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .unwrap_or("(未返回)")
            );
        }
    }
    Ok(())
}

/// Keep the account JWT available to user-facing control-plane commands even
/// after the daemon exchanges it for a durable device credential and removes
/// the JWT from its runtime config. The sidecar is never passed to the daemon
/// and is always owner-readable only on Unix.
fn cli_session_path(config_path: &Path) -> PathBuf {
    config_path.with_extension("session")
}

fn save_cli_session_token(config_path: &Path, server: &str, token: &str) -> Result<(), String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("控制服务器返回了空的 CLI 会话 token".to_string());
    }
    let path = cli_session_path(config_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("无法创建 CLI 会话目录 {}：{error}", parent.display()))?;
    }
    let temp = path.with_extension("session.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temp)
        .map_err(|error| format!("无法创建 CLI 会话文件 {}：{error}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .metadata()
            .map_err(|error| format!("无法读取 CLI 会话文件权限：{error}"))?
            .permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)
            .map_err(|error| format!("无法设置 CLI 会话文件权限：{error}"))?;
    }
    let record = CliSessionRecord {
        server: server.to_string(),
        token: token.to_string(),
    };
    let encoded =
        serde_json::to_vec(&record).map_err(|error| format!("无法编码 CLI 会话文件：{error}"))?;
    file.write_all(&encoded)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("无法写入 CLI 会话文件：{error}"))?;
    drop(file);
    fs::rename(&temp, &path)
        .map_err(|error| format!("无法保存 CLI 会话文件 {}：{error}", path.display()))
}

#[cfg(test)]
fn read_cli_session_token(config_path: &Path) -> Result<Option<String>, String> {
    Ok(read_cli_session_record(config_path)?.map(|record| record.token))
}

fn read_cli_session_record(config_path: &Path) -> Result<Option<CliSessionRecord>, String> {
    let path = cli_session_path(config_path);
    #[cfg(unix)]
    if let Ok(metadata) = fs::metadata(&path) {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "CLI 会话文件 {} 权限过宽，请设置为 0600 或重新登录",
                path.display()
            ));
        }
    }
    match fs::read_to_string(&path) {
        Ok(value) => {
            let record = serde_json::from_str::<CliSessionRecord>(value.trim()).map_err(|_| {
                format!(
                    "CLI 会话文件 {} 使用旧格式或已损坏，请重新登录",
                    path.display()
                )
            })?;
            if record.server.trim().is_empty() || record.token.trim().is_empty() {
                Err(format!("CLI 会话文件 {} 为空，请重新登录", path.display()))
            } else {
                Ok(Some(record))
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("无法读取 CLI 会话文件 {}：{error}", path.display())),
    }
}

fn hydrate_cli_session_token(config_path: &Path, config: &mut Config) -> Result<(), String> {
    if config.control.auth_token.trim().is_empty() {
        if let Some(record) = read_cli_session_record(config_path)? {
            let configured = normalize_control_server(&config.control.server_url)?;
            if configured != record.server {
                return Err("CLI 会话属于另一台控制服务器，请重新登录当前服务器".to_string());
            }
            config.control.auth_token = record.token;
        }
    }
    Ok(())
}

fn cli_session_available(config_path: &Path, config: &Config) -> Result<bool, String> {
    if !config.control.auth_token.trim().is_empty() {
        return Ok(true);
    }
    let Some(record) = read_cli_session_record(config_path)? else {
        return Ok(false);
    };
    let configured = config.control.server_url.trim();
    if configured.is_empty() {
        return Ok(false);
    }
    Ok(normalize_control_server(configured).ok().as_deref() == Some(record.server.as_str()))
}

fn clear_cli_session_token(config_path: &Path) -> Result<(), String> {
    let path = cli_session_path(config_path);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("无法删除 CLI 会话文件 {}：{error}", path.display())),
    }
}

async fn revoke_current_device_credential(config: &Config) -> Result<(), String> {
    let credential = config.control.device_credential.trim();
    if credential.is_empty() {
        return Ok(());
    }
    let server = normalize_control_server(&config.control.server_url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()
        .map_err(|error| format!("无法初始化网络请求：{error}"))?;
    let mut request = client
        .delete(format!("{server}/api/v1/devices/credential"))
        .bearer_auth(credential);
    if let Some(sequence) = config.control.registration_seq.filter(|seq| *seq > 0) {
        request = request.header("X-P2WLAN-Registration-Seq", sequence.to_string());
    }
    let response = request
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                "连接控制服务器超时".to_string()
            } else {
                format!("无法连接控制服务器：{error}")
            }
        })?;
    if response.status().is_success() || response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Ok(());
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(format!("HTTP {status}: {body}"))
}
