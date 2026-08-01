
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
