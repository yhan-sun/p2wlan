pub(super) async fn obtain_device_credential(
    http: &reqwest::Client,
    base_url: &str,
    user_token: &str,
    device_id: &str,
    ed25519_private_key_hex: &str,
    ed25519_public_key_hex: &str,
) -> Result<String> {
    // Step 1: Request a challenge
    let challenge_resp = http
        .post(format!("{base_url}/api/v1/challenges"))
        .bearer_auth(user_token)
        .json(&serde_json::json!({
            "device_id": device_id,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("challenge request failed: {e}")))?;

    if !challenge_resp.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "challenge request returned HTTP {}",
            challenge_resp.status()
        )));
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct ChallengeResponse {
        challenge_id: String,
        challenge: String,
        expires_at: i64,
    }

    let challenge_body: ChallengeResponse = challenge_resp
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("challenge decode failed: {e}")))?;

    let challenge_bytes = hex::decode(&challenge_body.challenge)
        .map_err(|e| DaemonError::ControlPlane(format!("challenge hex decode failed: {e}")))?;

    // Step 2: Sign the challenge with Ed25519
    let ed25519_private_key = hex::decode(ed25519_private_key_hex).map_err(|e| {
        DaemonError::ControlPlane(format!("ed25519 private key hex decode failed: {e}"))
    })?;

    if ed25519_private_key.len() != 32 {
        return Err(DaemonError::ControlPlane(
            "invalid ed25519 private key length".into(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&ed25519_private_key);
    let keypair = p2pnet_crypto::Ed25519KeyPair::from_private_key(&key_bytes);
    let signature = keypair.sign(&challenge_bytes);
    let signature_hex = hex::encode(signature);

    // Step 3: Submit the signed challenge to get a device credential
    let cred_resp = http
        .post(format!("{base_url}/api/v1/devices/credential"))
        .bearer_auth(user_token)
        .json(&serde_json::json!({
            "device_id": device_id,
            "ed25519_public_key": ed25519_public_key_hex,
            "challenge_id": challenge_body.challenge_id,
            "challenge_signature": signature_hex,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("credential request failed: {e}")))?;

    if !cred_resp.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "credential request returned HTTP {}",
            cred_resp.status()
        )));
    }

    #[derive(Deserialize)]
    struct CredentialResponse {
        success: bool,
        device_credential: Option<String>,
        error: Option<String>,
    }

    let cred_body: CredentialResponse = cred_resp.json().await.map_err(|e| {
        DaemonError::ControlPlane(format!("credential response decode failed: {e}"))
    })?;

    if !cred_body.success {
        return Err(DaemonError::ControlPlane(
            cred_body
                .error
                .unwrap_or_else(|| "credential request failed".to_string()),
        ));
    }

    cred_body.device_credential.ok_or_else(|| {
        DaemonError::ControlPlane("credential response missing device_credential".into())
    })
}

#[derive(Debug, Deserialize)]
struct RelayTicketResponse {
    ticket: Option<String>,
    expires_at: Option<i64>,
    error: Option<String>,
}

pub(super) async fn fetch_relay_ticket_http(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    audience: &str,
    region: &str,
) -> Result<FetchRelayTicketResponse> {
    let resp = http
        .post(format!("{base_url}/api/v1/relay/tickets"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "audience": audience,
            "region": region,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("relay ticket request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body: RelayTicketResponse = resp.json().await.unwrap_or(RelayTicketResponse {
            ticket: None,
            expires_at: None,
            error: Some(format!("HTTP {status}")),
        });
        let msg = body.error.unwrap_or_else(|| format!("HTTP {status}"));
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(DaemonError::ControlPlane(format!("permanent auth: {msg}")));
        }
        return Err(DaemonError::ControlPlane(format!(
            "relay ticket request: {msg}"
        )));
    }

    let body: RelayTicketResponse = resp
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("relay ticket decode: {e}")))?;

    let ticket = body
        .ticket
        .ok_or_else(|| DaemonError::ControlPlane("relay ticket response missing ticket".into()))?;
    let expires_at = body.expires_at.unwrap_or(0);

    Ok(FetchRelayTicketResponse { ticket, expires_at })
}
