pub(super) fn normalize_http_base_url(server_url: &str) -> String {
    let trimmed = server_url.trim().trim_end_matches('/');
    if trimmed.starts_with("ws://") {
        format!("http://{}", trimmed.trim_start_matches("ws://"))
    } else if trimmed.starts_with("wss://") {
        format!("https://{}", trimmed.trim_start_matches("wss://"))
    } else {
        trimmed.to_string()
    }
}

pub(super) async fn register_device(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
) -> Result<(String, String, String, Vec<String>, Vec<RelayCatalogEntry>)> {
    let res = http
        .post(format!("{base_url}/api/v1/devices"))
        .timeout(CONTROL_REQUEST_TIMEOUT)
        .bearer_auth(token)
        .json(&register_device_payload(config))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("register request failed: {e}")))?;

    if !res.status().is_success() {
        let status = res.status();
        let detail = control_error_detail(res).await;
        return Err(DaemonError::ControlPlane(format!(
            "register request returned HTTP {status}: {detail}"
        )));
    }

    let body: RegisterDeviceResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("register response decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "device registration failed".to_string()),
        ));
    }

    let node_id = body
        .node_id
        .ok_or_else(|| DaemonError::ControlPlane("register response missing node_id".into()))?;
    let virtual_ip = body
        .virtual_ip
        .ok_or_else(|| DaemonError::ControlPlane("register response missing virtual_ip".into()))?;
    let cidr = body.cidr.unwrap_or_else(|| "10.20.0.0/16".to_string());

    Ok((
        node_id,
        virtual_ip,
        cidr,
        body.relay_servers,
        body.relay_catalog,
    ))
}

pub(super) fn register_device_payload(config: &Config) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "public_key": config.node.public_key,
        "ed25519_public_key": config.node.ed25519_public_key,
        "device_name": config.node.device_name,
        "platform": config.node.platform,
        "app_version": env!("CARGO_PKG_VERSION"),
        "network_id": config.network.network_id,
    });

    if config.network.manual {
        let virtual_ip = config.network.virtual_ip.trim();
        if !virtual_ip.is_empty() {
            payload["virtual_ip"] = serde_json::Value::String(virtual_ip.to_string());
        }
    }

    payload
}

async fn control_error_detail(res: reqwest::Response) -> String {
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        return status.to_string();
    }
    match serde_json::from_str::<ControlErrorResponse>(&text) {
        Ok(body) => body.error.unwrap_or(text),
        Err(_) => text,
    }
}

pub(super) async fn update_endpoint(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    endpoint: &str,
    nat_type: &str,
    relay_rtt_ms: Option<u64>,
) -> Result<()> {
    let res = http
        .patch(format!("{base_url}/api/v1/devices/{device_id}/endpoint"))
        .timeout(CONTROL_REQUEST_TIMEOUT)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "endpoint": endpoint,
            "nat_type": nat_type,
            "relay_rtt_ms": relay_rtt_ms,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("endpoint update request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "endpoint update returned HTTP {}",
            res.status()
        )));
    }

    let body: EndpointUpdateResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("endpoint update decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "endpoint update failed".to_string()),
        ));
    }

    Ok(())
}

pub(super) async fn release_presence(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
) -> Result<()> {
    let res = http
        .post(format!("{base_url}/api/v1/devices/{device_id}/offline"))
        .timeout(PRESENCE_RELEASE_TIMEOUT)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("presence release request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "presence release returned HTTP {}",
            res.status()
        )));
    }

    let body: EndpointUpdateResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("presence release decode failed: {e}")))?;
    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "presence release failed".to_string()),
        ));
    }
    Ok(())
}
