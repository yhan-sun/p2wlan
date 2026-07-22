//! Runtime state and diagnostics for gateway-created UDP mappings.
//!
//! This is deliberately separate from `port_mapping`, which represents
//! user-created relay tunnels.  These mappings are short-lived NAT traversal
//! candidates opened on the local gateway through UPnP IGD, PCP, or NAT-PMP.

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One gateway mapping method's externally visible state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayMappingMethodDiagnostics {
    /// `idle`, `success`, `unavailable`, or `failed`.
    pub status: String,
    /// Sanitized error detail from the most recent attempt.
    pub last_error: Option<String>,
    /// Number of attempts made since this daemon started.
    pub attempts: u64,
    /// Age of the last attempt, if any.
    pub last_attempt_age_ms: Option<u64>,
    /// Age of the last successful result, if any.
    pub last_success_age_ms: Option<u64>,
}

impl Default for GatewayMappingMethodDiagnostics {
    fn default() -> Self {
        Self {
            status: "idle".to_string(),
            last_error: None,
            attempts: 0,
            last_attempt_age_ms: None,
            last_success_age_ms: None,
        }
    }
}

/// Serializable gateway mapping state included in `/status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayMappingDiagnostics {
    pub enabled: bool,
    pub local_endpoint: Option<String>,
    pub candidate_endpoint: Option<String>,
    pub candidate_source: Option<String>,
    pub lease_seconds: u32,
    pub renewal_remaining_ms: Option<u64>,
    pub next_discovery_remaining_ms: Option<u64>,
    pub upnp: GatewayMappingMethodDiagnostics,
    pub pcp: GatewayMappingMethodDiagnostics,
    pub nat_pmp: GatewayMappingMethodDiagnostics,
}

impl GatewayMappingDiagnostics {
    pub fn disabled(lease_seconds: u32) -> Self {
        Self {
            enabled: false,
            lease_seconds,
            ..Self::default()
        }
    }
}

impl Default for GatewayMappingDiagnostics {
    fn default() -> Self {
        Self {
            enabled: true,
            local_endpoint: None,
            candidate_endpoint: None,
            candidate_source: None,
            lease_seconds: 0,
            renewal_remaining_ms: None,
            next_discovery_remaining_ms: None,
            upnp: GatewayMappingMethodDiagnostics::default(),
            pcp: GatewayMappingMethodDiagnostics::default(),
            nat_pmp: GatewayMappingMethodDiagnostics::default(),
        }
    }
}

/// Local, non-serializable cache for a successful gateway mapping.
#[derive(Debug, Clone, Default)]
pub struct GatewayMappingRuntime {
    pub local_endpoint: Option<SocketAddr>,
    pub candidate_endpoint: Option<String>,
    pub candidate_source: Option<&'static str>,
    pub renew_at: Option<Instant>,
    pub retry_at: Option<Instant>,
}

impl GatewayMappingRuntime {
    pub fn needs_discovery(&self, local_endpoint: SocketAddr, now: Instant) -> bool {
        self.local_endpoint != Some(local_endpoint)
            || (self.candidate_endpoint.is_none()
                && self.retry_at.is_none_or(|retry_at| now >= retry_at))
            || self.renew_at.is_some_and(|renew_at| now >= renew_at)
    }

    pub fn retain_candidate(&self, local_endpoint: SocketAddr, now: Instant) -> bool {
        self.local_endpoint == Some(local_endpoint)
            && self.candidate_endpoint.is_some()
            && self.renew_at.is_some_and(|renew_at| now < renew_at)
    }

    pub fn record_success(
        &mut self,
        local_endpoint: SocketAddr,
        candidate_endpoint: String,
        candidate_source: &'static str,
        lease: Duration,
    ) {
        self.local_endpoint = Some(local_endpoint);
        self.candidate_endpoint = Some(candidate_endpoint);
        self.candidate_source = Some(candidate_source);
        // Renew at half the requested lease.  This provides a retry window
        // without issuing a full discovery on every candidate refresh.
        self.renew_at = Instant::now().checked_add(lease / 2);
        self.retry_at = None;
    }

    pub fn record_failure(&mut self, local_endpoint: SocketAddr, retry_after: Duration) {
        self.local_endpoint = Some(local_endpoint);
        self.candidate_endpoint = None;
        self.candidate_source = None;
        self.renew_at = None;
        self.retry_at = Instant::now().checked_add(retry_after);
    }

    pub fn snapshot(
        &self,
        enabled: bool,
        lease_seconds: u32,
        mut diagnostics: GatewayMappingDiagnostics,
    ) -> GatewayMappingDiagnostics {
        let now = Instant::now();
        diagnostics.enabled = enabled;
        diagnostics.lease_seconds = lease_seconds;
        diagnostics.local_endpoint = self.local_endpoint.map(|endpoint| endpoint.to_string());
        diagnostics.candidate_endpoint = self.candidate_endpoint.clone();
        diagnostics.candidate_source = self.candidate_source.map(str::to_string);
        diagnostics.renewal_remaining_ms = self
            .renew_at
            .and_then(|at| at.checked_duration_since(now))
            .map(duration_ms);
        diagnostics.next_discovery_remaining_ms = self
            .retry_at
            .and_then(|at| at.checked_duration_since(now))
            .map(duration_ms);
        diagnostics
    }
}

/// Update a method diagnostic after one discovery operation.
pub fn record_method_result(
    method: &mut GatewayMappingMethodDiagnostics,
    result: std::result::Result<(), String>,
) {
    method.attempts = method.attempts.saturating_add(1);
    method.last_attempt_age_ms = Some(0);
    match result {
        Ok(()) => {
            method.status = "success".to_string();
            method.last_error = None;
            method.last_success_age_ms = Some(0);
        }
        Err(error) => {
            method.status = "failed".to_string();
            method.last_error = Some(error);
        }
    }
}

/// Refresh ages at snapshot time without exposing absolute wall-clock times.
pub fn refresh_diagnostic_ages(diagnostics: &mut GatewayMappingDiagnostics, elapsed: Duration) {
    for method in [
        &mut diagnostics.upnp,
        &mut diagnostics.pcp,
        &mut diagnostics.nat_pmp,
    ] {
        method.last_attempt_age_ms = method
            .last_attempt_age_ms
            .map(|age| age.saturating_add(duration_ms(elapsed)));
        method.last_success_age_ms = method
            .last_success_age_ms
            .map(|age| age.saturating_add(duration_ms(elapsed)));
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// Monotonic diagnostic clock used for tests and runtime snapshots.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_cache_reuses_a_valid_lease_and_then_renews() {
        let local = "192.168.1.7:51820".parse().unwrap();
        let mut runtime = GatewayMappingRuntime::default();
        runtime.record_success(
            local,
            "203.0.113.8:51820".to_string(),
            "upnp",
            Duration::from_secs(120),
        );
        assert!(runtime.retain_candidate(local, Instant::now()));
        assert!(!runtime.needs_discovery(local, Instant::now()));
        runtime.renew_at = Some(Instant::now() - Duration::from_millis(1));
        assert!(runtime.needs_discovery(local, Instant::now()));
    }

    #[test]
    fn method_diagnostics_keep_failure_reason() {
        let mut method = GatewayMappingMethodDiagnostics::default();
        record_method_result(&mut method, Err("gateway search timed out".to_string()));
        assert_eq!(method.status, "failed");
        assert_eq!(method.attempts, 1);
        assert_eq!(
            method.last_error.as_deref(),
            Some("gateway search timed out")
        );
    }
}
