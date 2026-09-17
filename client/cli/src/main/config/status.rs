async fn fetch_status_at(url: &str, instance_state_dir: &Path) -> Result<Value, String> {
    let (status, body) = diagnostics_request(url, instance_state_dir, reqwest::Method::GET).await?;
    if !status.is_success() {
        return Err(format!("本地诊断端点返回 HTTP {}", status));
    }
    serde_json::from_str(&body).map_err(|error| format!("本地诊断响应无效：{error}"))
}

/// Send an authenticated request to a daemon diagnostics endpoint.
///
/// The diagnostics token is per-process, so callers must read it from the
/// instance-specific state directory for every retry. This is shared by the
/// main daemon, room daemons, route repair, and support-bundle collection.
async fn diagnostics_request(
    url: &str,
    instance_state_dir: &Path,
    method: reqwest::Method,
) -> Result<(reqwest::StatusCode, String), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()
        .map_err(|error| error.to_string())?;
    for attempt in 0..2 {
        let token = read_diagnostics_auth_token_at(instance_state_dir)?;
        let response = client
            .request(method.clone(), url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| format!("无法连接本地诊断端点：{error}"))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
            continue;
        }
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("读取本地诊断响应失败：{error}"))?;
        return Ok((status, body));
    }
    Err("本地诊断会话已变化，请重新启动 daemon 后重试".to_string())
}

fn read_diagnostics_auth_token_at(instance_state_dir: &Path) -> Result<String, String> {
    let path = instance_state_dir.join("p2wlan-daemon.diag-auth");
    match fs::read_to_string(path) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        Ok(_) => Err("diagnostics session token file is empty".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
            "diagnostics session token file is missing; daemon session may have changed"
                .to_string(),
        ),
        Err(error) => Err(format!("failed to read diagnostics session token: {error}")),
    }
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
