use std::time::Duration;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlAuthRequest {
    pub mode: String,
    pub control_server: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ControlAuthUser {
    pub id: Option<String>,
    pub email: Option<String>,
    pub created_at: Option<i64>,
    #[serde(rename = "createdAt")]
    pub created_at_camel: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlAuthSession {
    pub token: String,
    pub user: Option<ControlAuthUser>,
    pub control_server: String,
}

#[derive(Debug, serde::Deserialize)]
struct ControlAuthResponse {
    success: Option<bool>,
    token: Option<String>,
    user: Option<ControlAuthUser>,
    error: Option<String>,
}

pub fn normalize_control_server(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("控制服务器不能为空".to_string());
    }
    let parsed =
        reqwest::Url::parse(trimmed).map_err(|_| "控制服务器必须是有效 URL".to_string())?;
    match parsed.scheme() {
        "http" | "https" => Ok(parsed.to_string().trim_end_matches('/').to_string()),
        _ => Err("控制服务器必须使用 http 或 https".to_string()),
    }
}

fn zh_auth_error(message: &str, status: Option<reqwest::StatusCode>) -> String {
    let normalized = message.to_lowercase();
    if normalized.contains("invalid credentials") {
        return "邮箱或密码错误".to_string();
    }
    if normalized.contains("invalid email") {
        return "邮箱格式不正确".to_string();
    }
    if normalized.contains("invalid password") {
        return "密码不符合要求，至少需要 6 个字符".to_string();
    }
    if normalized.contains("registration failed") {
        return "注册失败，邮箱可能已存在".to_string();
    }
    if normalized.contains("rate limit") || normalized.contains("too many") {
        return "请求过于频繁，请稍后再试".to_string();
    }
    match status.map(|s| s.as_u16()) {
        Some(401) => "认证失败，请检查邮箱和密码".to_string(),
        Some(409) => "账号已存在".to_string(),
        Some(404) => "控制服务器接口不存在，请确认服务器版本正确".to_string(),
        Some(500..=599) => "控制服务器内部错误，请稍后再试".to_string(),
        _ => {
            if message.trim().is_empty() {
                "控制服务器请求失败".to_string()
            } else {
                message.to_string()
            }
        }
    }
}

pub async fn authenticate(req: ControlAuthRequest) -> Result<ControlAuthSession, String> {
    let mode = match req.mode.as_str() {
        "login" | "register" => req.mode.as_str(),
        _ => return Err("认证模式无效".to_string()),
    };
    let control_server = normalize_control_server(&req.control_server)?;
    let email = req.email.trim().to_lowercase();
    if email.is_empty() {
        return Err("请输入邮箱".to_string());
    }
    if req.password.is_empty() {
        return Err("请输入密码".to_string());
    }
    if req.password.len() < 6 {
        return Err("密码至少需要 6 个字符".to_string());
    }

    let endpoint = format!(
        "{}/api/v1/{}",
        control_server,
        if mode == "register" {
            "register"
        } else {
            "login"
        }
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| format!("初始化控制面请求失败：{e}"))?;

    let res = client
        .post(endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&serde_json::json!({
            "email": email,
            "password": req.password,
        }))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                "连接控制服务器超时".to_string()
            } else if e.is_connect() {
                format!("无法连接控制服务器，请检查服务器地址或网络：{e}")
            } else {
                format!("控制服务器请求失败：{e}")
            }
        })?;

    let status = res.status();
    let body_text = res
        .text()
        .await
        .map_err(|e| format!("读取控制服务器响应失败：{e}"))?;
    let body = serde_json::from_str::<ControlAuthResponse>(&body_text).ok();

    if !status.is_success() {
        return Err(zh_auth_error(
            body.as_ref()
                .and_then(|b| b.error.as_deref())
                .unwrap_or(&body_text),
            Some(status),
        ));
    }

    let body = body.ok_or_else(|| "控制服务器响应不是有效 JSON".to_string())?;
    if body.success != Some(true) {
        return Err(zh_auth_error(
            body.error.as_deref().unwrap_or(""),
            Some(status),
        ));
    }
    let token = body
        .token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| "控制服务器没有返回有效 token".to_string())?;

    Ok(ControlAuthSession {
        token,
        user: body.user,
        control_server,
    })
}

#[cfg(test)]
mod tests {
    use super::{normalize_control_server, zh_auth_error};

    #[test]
    fn normalize_control_server_trims_trailing_slashes() {
        assert_eq!(
            normalize_control_server(" http://47.109.40.237:18080/// ").unwrap(),
            "http://47.109.40.237:18080"
        );
    }

    #[test]
    fn normalize_control_server_rejects_non_http() {
        assert!(normalize_control_server("ws://127.0.0.1:18080").is_err());
    }

    #[test]
    fn zh_auth_error_maps_common_server_errors() {
        assert_eq!(zh_auth_error("invalid credentials", None), "邮箱或密码错误");
        assert_eq!(
            zh_auth_error("invalid password", None),
            "密码不符合要求，至少需要 6 个字符"
        );
    }
}
