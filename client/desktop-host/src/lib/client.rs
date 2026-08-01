#[derive(Debug, Clone)]
pub struct DesktopHostClient {
    client: reqwest::Client,
    timeout: Duration,
}

impl DesktopHostClient {
    pub fn new() -> Result<Self> {
        Self::with_timeout(DEFAULT_REQUEST_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Result<Self> {
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
        Ok(Self { client, timeout })
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
        let response = self.client.get(status_url).send().await.map_err(|error| {
            DesktopHostError::new(
                DesktopHostErrorKind::DaemonUnavailable,
                "Daemon status endpoint is unreachable",
                true,
            )
            .with_detail(error.to_string())
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(DesktopHostError::new(
                DesktopHostErrorKind::DaemonUnavailable,
                format!("Daemon status endpoint returned HTTP {status}"),
                true,
            ));
        }

        response.json::<serde_json::Value>().await.map_err(|error| {
            DesktopHostError::new(
                DesktopHostErrorKind::DaemonStatusDecodeFailed,
                "Daemon status endpoint did not return valid JSON",
                true,
            )
            .with_detail(error.to_string())
        })
    }
}
