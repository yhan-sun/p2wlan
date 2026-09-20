//! Asynchronous delivery worker for active-path telemetry.
//!
//! Delivers dirty active-path observations to the Control server.
//! Provides an HTTP fallback worker for environments where WebSocket signaling
//! is disabled, reconnecting, or HTTP REST is preferred.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tracing::{debug, warn};

use super::hub::{PathTelemetryHub, DEFAULT_BATCH_OBSERVATIONS};
use crate::error::{DaemonError, Result};

pub const TELEMETRY_HTTP_PATH: &str = "/api/v1/telemetry/paths";
pub const TELEMETRY_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
pub const TELEMETRY_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// RAII handle for the background telemetry worker that aborts on drop.
pub struct PathTelemetryWorkerTask {
    handle: tokio::task::JoinHandle<()>,
}

impl PathTelemetryWorkerTask {
    pub fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for PathTelemetryWorkerTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Active-path telemetry HTTP delivery client.
#[derive(Clone)]
pub struct PathTelemetrySender {
    hub: Arc<PathTelemetryHub>,
    http: Client,
    base_url: String,
    token: String,
    telemetry_supported: Arc<AtomicBool>,
}

impl PathTelemetrySender {
    /// Create a new sender.
    pub fn new(hub: Arc<PathTelemetryHub>, base_url: String, token: String) -> Self {
        Self {
            hub,
            http: Client::builder()
                .timeout(TELEMETRY_REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            telemetry_supported: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Check if telemetry endpoint is supported by the server.
    pub fn is_supported(&self) -> bool {
        self.telemetry_supported.load(Ordering::Acquire)
    }

    /// Flush pending dirty observations via HTTP POST.
    pub async fn flush_http(&self) -> Result<usize> {
        if !self.is_supported() {
            return Ok(0);
        }

        let observations = self.hub.drain_dirty(DEFAULT_BATCH_OBSERVATIONS);
        if observations.is_empty() {
            return Ok(0);
        }

        let count = observations.len();
        let payload = self.hub.build_payload(observations);
        let url = format!("{}{}", self.base_url, TELEMETRY_HTTP_PATH);

        let mut req = self.http.post(&url).bearer_auth(&self.token).json(&payload);

        let reg_seq = self.hub.registration_seq();
        if reg_seq > 0 {
            req = req.header("X-P2WLAN-Registration-Seq", reg_seq.to_string());
        }

        let res = match req.send().await {
            Ok(res) => res,
            Err(err) => {
                self.hub.record_send_failure();
                debug!("Path telemetry HTTP transmission failed: {err}");
                return Err(DaemonError::ControlPlane(format!(
                    "telemetry post failed: {err}"
                )));
            }
        };

        if res.status().as_u16() == 404 {
            // Older control server without telemetry route
            self.telemetry_supported.store(false, Ordering::Release);
            debug!("Path telemetry endpoint not found on server; disabling HTTP telemetry");
            return Ok(0);
        }

        if !res.status().is_success() {
            self.hub.record_send_failure();
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            warn!("Path telemetry HTTP post returned status {status}: {text}");
            return Err(DaemonError::ControlPlane(format!(
                "telemetry post returned {status}: {text}"
            )));
        }

        self.hub.record_sent_batch(count);
        self.hub.record_ack(payload.sent_at);
        Ok(count)
    }

    /// Spawn a background task to flush dirty path telemetry periodically or on notification.
    pub fn spawn_worker(self: Arc<Self>, ws_active: Arc<AtomicBool>) -> PathTelemetryWorkerTask {
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TELEMETRY_FLUSH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = self.hub.wait_for_dirty() => {}
                }

                // If WebSocket is active and handling telemetry, skip HTTP delivery
                if ws_active.load(Ordering::Acquire) {
                    continue;
                }

                if self.hub.has_dirty() {
                    let _ = self.flush_http().await;
                }
            }
        });
        PathTelemetryWorkerTask { handle }
    }
}
