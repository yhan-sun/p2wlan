#[derive(Debug, Clone)]
pub struct DesktopHostClient {
    client: reqwest::Client,
    timeout: Duration,
    auth_token_reader: fn() -> Result<String>,
}

impl DesktopHostClient {
    pub fn new() -> Result<Self> {
        Self::with_timeout(DEFAULT_REQUEST_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        Self::with_timeout_and_auth_reader(timeout, read_diagnostics_auth_token)
    }

    pub fn with_timeout_and_auth_reader(
        timeout: Duration,
        auth_token_reader: fn() -> Result<String>,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(timeout)
            .build()
            .map_err(|error| {
                DesktopHostError::new(
                    DesktopHostErrorKind::Internal,
                    "Failed to create diagnostics HTTP client",
                    false,
                )
                .with_detail(error.to_string())
            })?;
        Ok(Self {
            client,
            timeout,
            auth_token_reader,
        })
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn fetch_health(&self, diagnostics_url: &str) -> Result<bool> {
        let health_url = health_url_from_status_url(diagnostics_url)?;
        let response = self.client.get(health_url).send().await.map_err(|error| {
            DesktopHostError::new(
                DesktopHostErrorKind::DaemonUnavailable,
                "Daemon health endpoint is unreachable",
                true,
            )
            .with_detail(error.to_string())
        })?;
        Ok(response.status().is_success())
    }

    pub async fn fetch_status(&self, diagnostics_url: &str) -> Result<serde_json::Value> {
        let status_url = normalize_diagnostics_url(diagnostics_url)?;
        for attempt in 0..2 {
            let token = (self.auth_token_reader)()?;
            let response = self
                .client
                .get(status_url.clone())
                .bearer_auth(token)
                .send()
                .await
                .map_err(|error| {
                    DesktopHostError::new(
                        DesktopHostErrorKind::DaemonUnavailable,
                        "Daemon status endpoint is unreachable",
                        true,
                    )
                    .with_detail(error.to_string())
                })?;

            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                continue;
            }
            if !status.is_success() {
                return Err(DesktopHostError::new(
                    DesktopHostErrorKind::DaemonUnavailable,
                    format!("Daemon status endpoint returned HTTP {status}"),
                    true,
                ));
            }

            return response.json::<serde_json::Value>().await.map_err(|error| {
                DesktopHostError::new(
                    DesktopHostErrorKind::DaemonStatusDecodeFailed,
                    "Daemon status endpoint did not return valid JSON",
                    true,
                )
                .with_detail(error.to_string())
            });
        }
        Err(DesktopHostError::new(
            DesktopHostErrorKind::DaemonUnavailable,
            "Daemon diagnostics session changed; retry after restarting the daemon",
            true,
        ))
    }
}

/// Read the current per-process diagnostics session secret. Long-lived control
/// credentials are never used for this local IPC session.
pub fn read_diagnostics_auth_token() -> Result<String> {
    let mut candidates = vec![default_log_dir()];
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".local/state/p2wlan"));
    }
    for directory in candidates {
        let path = directory.join("p2wlan-daemon.diag-auth");
        if let Ok(value) = std::fs::read_to_string(path) {
            let token = value.trim();
            if !token.is_empty() {
                return Ok(token.to_string());
            }
        }
    }
    Err(DesktopHostError::new(
        DesktopHostErrorKind::DaemonUnavailable,
        "Diagnostics session token file is missing; the daemon session may have changed",
        true,
    ))
}
