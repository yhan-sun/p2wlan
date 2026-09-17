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

/// Server-verified registration session header carried by a daemon after it
/// has completed an incarnation-aware registration.  Unlike the peer-visible
/// NAT `l=` label, this header is an authenticated control-plane fence and is
/// therefore used for every device-credential control action.
pub(super) const REGISTRATION_SEQUENCE_HEADER: &str = "X-P2WLAN-Registration-Seq";

pub(super) fn with_registration_sequence(
    request: reqwest::RequestBuilder,
    registration_seq: Option<u64>,
) -> reqwest::RequestBuilder {
    match registration_seq.filter(|seq| *seq > 0) {
        Some(seq) => request.header(REGISTRATION_SEQUENCE_HEADER, seq.to_string()),
        None => request,
    }
}

pub(super) async fn register_device(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
) -> Result<(
    String,
    String,
    String,
    Vec<String>,
    Vec<RelayCatalogEntry>,
    Option<u64>,
)> {
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
        let (detail, error_code, registration_seq) = control_error_detail(res).await;
        if let Some(error) =
            registration_conflict_error(status, error_code, registration_seq, &detail)
        {
            return Err(error);
        }
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
    let local_incarnation = crate::incarnation::local_incarnation();
    // Old servers omit both fields.  Once either lifecycle field is present,
    // accepting a partial response would make this daemon publish unauthenticated
    // control actions without a server-issued session proof.
    if body.registration_incarnation.is_some() || body.registration_seq.is_some() {
        let server_incarnation = body.registration_incarnation.ok_or_else(|| {
            DaemonError::ControlPlane(
                "registration response included lifecycle data but omitted registration_incarnation"
                    .into(),
            )
        })?;
        let registration_seq = body
            .registration_seq
            .filter(|seq| *seq > 0)
            .ok_or_else(|| {
                DaemonError::ControlPlane(
                "registration response included lifecycle data but omitted a valid registration_seq"
                    .into(),
            )
            })?;
        if local_incarnation == 0 || server_incarnation != local_incarnation {
            return Err(DaemonError::ControlPlane(format!(
                "registration conflict (registration_incarnation_mismatch) local={local_incarnation} server={server_incarnation}"
            )));
        }
        return Ok((
            node_id,
            virtual_ip,
            cidr,
            body.relay_servers,
            body.relay_catalog,
            Some(registration_seq),
        ));
    }

    Ok((
        node_id,
        virtual_ip,
        cidr,
        body.relay_servers,
        body.relay_catalog,
        body.registration_seq,
    ))
}

pub(super) fn register_device_payload(config: &Config) -> serde_json::Value {
    register_device_payload_with_incarnation(config, crate::incarnation::local_incarnation())
}

pub(super) fn register_device_payload_with_incarnation(
    config: &Config,
    incarnation: u64,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "public_key": config.node.public_key,
        "ed25519_public_key": config.node.ed25519_public_key,
        "device_name": config.node.device_name,
        "platform": config.node.platform,
        "app_version": env!("CARGO_PKG_VERSION"),
        "network_id": config.network.network_id,
    });

    // A zero value means the durable state file was unavailable. Do not invent
    // a wall-clock fallback: doing so could make an old daemon appear newer.
    // Older servers also accept the missing optional field during rollout.
    if incarnation != 0 {
        payload["registration_incarnation"] = serde_json::json!(incarnation);
    }

    if config.network.network_id.starts_with("room-") {
        payload["room_protocol_version"] = serde_json::json!(1);
    }

    if config.network.manual && !config.network.network_id.starts_with("room-") {
        let virtual_ip = config.network.virtual_ip.trim();
        if !virtual_ip.is_empty() {
            payload["virtual_ip"] = serde_json::Value::String(virtual_ip.to_string());
        }
    }

    payload
}

pub(super) async fn control_error_detail(
    res: reqwest::Response,
) -> (String, Option<String>, Option<u64>) {
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        return (status.to_string(), None, None);
    }
    match serde_json::from_str::<ControlErrorResponse>(&text) {
        Ok(body) => (
            body.error.unwrap_or(text),
            body.error_code,
            body.registration_seq,
        ),
        Err(_) => (text, None, None),
    }
}

pub(super) fn registration_conflict_error(
    status: reqwest::StatusCode,
    error_code: Option<String>,
    registration_seq: Option<u64>,
    detail: &str,
) -> Option<DaemonError> {
    if status != reqwest::StatusCode::CONFLICT {
        return None;
    }
    let code = error_code?;
    if !matches!(
        code.as_str(),
        "registration_conflict"
            | "registration_protocol_upgrade_required"
            | "registration_incarnation_mismatch"
            | "registration_lifecycle_conflict"
    ) {
        return None;
    }
    Some(DaemonError::ControlPlane(format!(
        "registration conflict ({code}) current_registration_seq={}: {detail}",
        registration_seq
            .map(|sequence| sequence.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    )))
}

/// Add the server-issued registration sequence to an endpoint NAT label.
///
/// The control server uses `l=` as a compare-and-swap fence for endpoint
/// metadata. This final HTTP-boundary canonicalizer covers the ordinary,
/// heartbeat, and critical lanes even when an older candidate source emitted
/// a label without lifecycle metadata. An existing `l=` is replaced rather
/// than trusted, since only the registration response is authoritative.
pub(super) fn control_label_with_registration_seq(
    nat_type: &str,
    registration_seq: Option<u64>,
) -> String {
    let Some(registration_seq) = registration_seq else {
        return nat_type.to_string();
    };

    let trimmed = nat_type.trim();
    let seed = if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        "p2v2:"
    } else {
        trimmed
    };
    let mut fields: Vec<String> = seed
        .split(';')
        .map(str::trim)
        .filter(|field| !field.is_empty())
        .filter(|field| {
            let field = field
                .strip_prefix("p2v2:")
                .or_else(|| field.strip_prefix("p2:"))
                .unwrap_or(field);
            !field.starts_with("l=")
        })
        .map(ToOwned::to_owned)
        .collect();
    if fields.is_empty()
        || fields
            .iter()
            .all(|field| field == "p2v2:" || field == "p2:")
    {
        fields.clear();
        fields.push("p2v2:".to_string());
    }

    let append_lifecycle = |fields: &mut Vec<String>| {
        if fields.last().is_some_and(|field| field.ends_with(':')) {
            let last = fields.last_mut().expect("last checked above");
            last.push_str(&format!("l={registration_seq}"));
        } else {
            fields.push(format!("l={registration_seq}"));
        }
    };
    append_lifecycle(&mut fields);

    // Device NAT metadata is capped at 128 bytes by the server. Keep the
    // ordering fences and traversal-relevant fields, dropping optional
    // diagnostics in the same order as NatProfile's producer does.
    for optional_key in ["h=", "c=", "f=", "r="] {
        let label = fields.join(";");
        if label.len() <= 128 {
            return label;
        }
        if let Some(position) = fields.iter().position(|field| {
            field
                .strip_prefix("p2v2:")
                .or_else(|| field.strip_prefix("p2:"))
                .unwrap_or(field)
                .starts_with(optional_key)
        }) {
            fields.remove(position);
        }
    }
    let label = fields.join(";");
    if label.len() <= 128 {
        label
    } else {
        // Preserve the registration CAS fence even for a malformed or
        // unusually long legacy value. The peer will conservatively fall back
        // from structured NAT inference until a normal candidate update wins.
        format!("p2v2:l={registration_seq}")
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn update_endpoint(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    endpoint: &str,
    nat_type: &str,
    relay_rtt_ms: Option<u64>,
    registration_seq: Option<u64>,
) -> Result<()> {
    let res = with_registration_sequence(
        http.patch(format!("{base_url}/api/v1/devices/{device_id}/endpoint"))
            .timeout(CONTROL_REQUEST_TIMEOUT)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "endpoint": endpoint,
                "nat_type": nat_type,
                "relay_rtt_ms": relay_rtt_ms,
            })),
        registration_seq,
    )
    .send()
    .await
    .map_err(|e| DaemonError::ControlPlane(format!("endpoint update request failed: {e}")))?;

    if !res.status().is_success() {
        let status = res.status();
        let (detail, error_code, current_seq) = control_error_detail(res).await;
        if let Some(error) = registration_conflict_error(status, error_code, current_seq, &detail) {
            return Err(error);
        }
        return Err(DaemonError::ControlPlane(format!(
            "endpoint update returned HTTP {status}: {detail}",
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
    registration_seq: Option<u64>,
) -> Result<()> {
    let res = with_registration_sequence(
        http.post(format!("{base_url}/api/v1/devices/{device_id}/offline"))
            .timeout(PRESENCE_RELEASE_TIMEOUT)
            .bearer_auth(token)
            .json(&serde_json::json!({
                "registration_seq": registration_seq,
            })),
        registration_seq,
    )
    .send()
    .await
    .map_err(|e| DaemonError::ControlPlane(format!("presence release request failed: {e}")))?;

    if !res.status().is_success() {
        let status = res.status();
        let (detail, error_code, current_seq) = control_error_detail(res).await;
        if let Some(error) = registration_conflict_error(status, error_code, current_seq, &detail) {
            return Err(error);
        }
        return Err(DaemonError::ControlPlane(format!(
            "presence release returned HTTP {status}: {detail}",
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
