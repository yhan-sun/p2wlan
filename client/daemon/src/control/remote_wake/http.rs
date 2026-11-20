use std::time::Duration;

use p2pnet_netbind::wake::MacAddress;
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::time::{timeout_at, Instant};

use super::{CriticalControlAuth, WakeResult};
use crate::control::http::with_registration_sequence;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const JOB_LIMIT: usize = 4;
const BODY_LIMIT: usize = 4 * 1024;
const REGISTRATION_BODY_LIMIT: usize = 64 * 1024;
const MAX_CLAIM_LEASE_MS: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WakeHttpError {
    Unsupported,
    Unavailable,
    InvalidResponse,
}

#[derive(Deserialize)]
struct ActivationResponse {
    success: bool,
    node_id: String,
    registration_seq: u64,
    registration_incarnation: u64,
    #[serde(default)]
    accepted_peer_capabilities: ActivationCapabilities,
}

#[derive(Default, Deserialize)]
struct ActivationCapabilities {
    #[serde(default)]
    wake_proxy_v1: bool,
}

#[derive(Deserialize)]
struct JobList {
    jobs: Vec<QueuedJob>,
}

#[derive(Deserialize)]
struct QueuedJob {
    id: String,
}

#[derive(Deserialize)]
struct ClaimResponse {
    mac: String,
    lease_ms: u64,
    claim_token: String,
}

pub(super) struct WakeClaim {
    pub(super) mac: String,
    pub(super) deadline: Instant,
    claim_token: String,
}

pub(super) struct WakeHttp<'a> {
    http: &'a reqwest::Client,
    auth: &'a CriticalControlAuth,
    registration_seq: u64,
}

impl<'a> WakeHttp<'a> {
    pub(super) fn new(
        http: &'a reqwest::Client,
        auth: &'a CriticalControlAuth,
        registration_seq: u64,
    ) -> Self {
        Self {
            http,
            auth,
            registration_seq,
        }
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        with_registration_sequence(
            self.http
                .request(method, format!("{}{}", self.auth.base_url, path))
                .timeout(REQUEST_TIMEOUT)
                .bearer_auth(&self.auth.token),
            Some(self.registration_seq),
        )
    }

    pub(super) async fn activate_proxy(
        &self,
        payload: &serde_json::Value,
    ) -> Result<bool, WakeHttpError> {
        let response = send(self.request(Method::POST, "/api/v1/devices").json(payload))
            .await
            .and_then(require_success)?;
        let activated: ActivationResponse = read(response, REGISTRATION_BODY_LIMIT).await?;
        if !activated.success
            || activated.node_id != self.auth.self_node_id
            || activated.registration_seq != self.registration_seq
            || Some(activated.registration_incarnation)
                != payload["registration_incarnation"].as_u64()
        {
            return Err(WakeHttpError::InvalidResponse);
        }
        Ok(activated.accepted_peer_capabilities.wake_proxy_v1)
    }

    fn target_path(&self) -> Result<String, WakeHttpError> {
        let id = &self.auth.self_node_id;
        if !valid_id(id) {
            return Err(WakeHttpError::InvalidResponse);
        }
        Ok(format!("/api/v1/devices/{id}/wake"))
    }

    pub(super) async fn put_target(&self, mac: MacAddress, nic: &str) -> Result<(), WakeHttpError> {
        send(
            self.request(Method::PUT, &self.target_path()?)
                .json(&serde_json::json!({"mac": mac.to_string(), "nic": nic})),
        )
        .await
        .and_then(require_success)
        .map(|_| ())
    }

    pub(super) async fn delete_target(&self) -> Result<(), WakeHttpError> {
        send(self.request(Method::DELETE, &self.target_path()?))
            .await
            .and_then(require_success)
            .map(|_| ())
    }

    pub(super) async fn jobs(&self) -> Result<Vec<String>, WakeHttpError> {
        let response = send(self.request(Method::GET, "/api/v1/wake/jobs?state=queued&limit=4"))
            .await
            .and_then(require_success)?;
        let body: JobList = read(response, BODY_LIMIT).await?;
        if body.jobs.len() > JOB_LIMIT || body.jobs.iter().any(|job| !valid_id(&job.id)) {
            return Err(WakeHttpError::InvalidResponse);
        }
        Ok(body.jobs.into_iter().map(|job| job.id).collect())
    }

    pub(super) async fn claim(&self, id: &str) -> Result<Option<WakeClaim>, WakeHttpError> {
        let started = Instant::now();
        let response =
            send(self.request(Method::POST, &format!("/api/v1/wake/jobs/{id}/claim"))).await?;
        if matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::CONFLICT | StatusCode::GONE
        ) {
            return Ok(None);
        }
        let body: ClaimResponse = read(require_success(response)?, BODY_LIMIT).await?;
        if body.lease_ms == 0 || body.lease_ms > MAX_CLAIM_LEASE_MS || !valid_id(&body.claim_token)
        {
            return Err(WakeHttpError::InvalidResponse);
        }
        // The reported remaining lease started on Control. Starting it before
        // the HTTP request conservatively subtracts the entire round trip.
        let deadline = started + Duration::from_millis(body.lease_ms);
        Ok((Instant::now() < deadline).then_some(WakeClaim {
            mac: body.mac,
            deadline,
            claim_token: body.claim_token,
        }))
    }

    pub(super) async fn result(
        &self,
        id: &str,
        claim: &WakeClaim,
        result: WakeResult,
    ) -> Result<(), WakeHttpError> {
        let (state, reason) = result.wire();
        let request = || {
            self.request(Method::POST, &format!("/api/v1/wake/jobs/{id}/result"))
                .json(&serde_json::json!({"state": state, "reason": reason, "claim_token": claim.claim_token}))
        };
        // A lost reply can be retried with exactly the same claim token and
        // result. If both fail, a reclaimed job reuses the cached disposition.
        for attempt in 0..2 {
            match timeout_at(claim.deadline, send(request())).await {
                Ok(Ok(response)) if response.status().is_success() => return Ok(()),
                Ok(Ok(response))
                    if matches!(
                        response.status(),
                        StatusCode::CONFLICT | StatusCode::GONE | StatusCode::NOT_FOUND
                    ) =>
                {
                    return Ok(())
                }
                _ if attempt == 0 => continue,
                _ => return Err(WakeHttpError::Unavailable),
            }
        }
        Err(WakeHttpError::Unavailable)
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

async fn send(request: RequestBuilder) -> Result<Response, WakeHttpError> {
    request.send().await.map_err(|_| WakeHttpError::Unavailable)
}

fn require_success(response: Response) -> Result<Response, WakeHttpError> {
    match response.status() {
        code if code.is_success() => Ok(response),
        StatusCode::NOT_FOUND => Err(WakeHttpError::Unsupported),
        _ => Err(WakeHttpError::Unavailable),
    }
}

async fn read<T: DeserializeOwned>(
    mut response: Response,
    limit: usize,
) -> Result<T, WakeHttpError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| WakeHttpError::Unavailable)?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(WakeHttpError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| WakeHttpError::InvalidResponse)
}
