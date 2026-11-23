//! Runtime state and diagnostics for gateway-created UDP mappings.
//!
//! This is deliberately separate from `port_mapping`, which represents
//! user-created relay tunnels.  These mappings are short-lived NAT traversal
//! candidates opened on the local gateway through UPnP IGD, PCP, or NAT-PMP.

use std::net::{Ipv4Addr, SocketAddr};
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

/// Exact discovery scope. Equal private endpoints on two networks do not
/// authorize reusing either a gateway lease or a failed-discovery backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GatewayMappingIdentity {
    pub(crate) bind_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) gateway: Option<Ipv4Addr>,
    pub(crate) network_generation: u64,
    pub(crate) transport_instance: u64,
    pub(crate) publication_owner: u64,
}

/// One local, non-serializable gateway mapping cache, scoped to its discovery
/// identity. Replacing the identity also drops the old failure backoff.
#[derive(Debug, Clone, Default)]
pub struct GatewayMappingRuntime {
    identity: Option<GatewayMappingIdentity>,
    pub local_endpoint: Option<SocketAddr>,
    pub candidate_endpoint: Option<String>,
    pub candidate_source: Option<&'static str>,
    granted_lease_seconds: Option<u32>,
    pcp_nonce: Option<PcpMappingNonce>,
    pub renew_at: Option<Instant>,
    pub retry_at: Option<Instant>,
}

#[derive(Clone, Copy)]
struct PcpMappingNonce([u8; 12]);

impl std::fmt::Debug for PcpMappingNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PcpMappingNonce(redacted)")
    }
}

impl GatewayMappingRuntime {
    pub(crate) fn bind_identity(&mut self, identity: GatewayMappingIdentity) {
        if self.identity != Some(identity) {
            *self = Self {
                identity: Some(identity),
                local_endpoint: Some(identity.local_endpoint),
                pcp_nonce: Some(PcpMappingNonce(rand::random())),
                ..Self::default()
            };
        }
    }

    /// Renewals and retries on the same gateway reuse its mapping nonce.
    pub(crate) fn pcp_request(&self) -> Option<([u8; 12], Option<SocketAddr>)> {
        let suggested = self
            .candidate_endpoint
            .as_deref()
            .filter(|_| self.candidate_source == Some("pcp"))
            .and_then(|address| address.parse().ok());
        Some((self.pcp_nonce?.0, suggested))
    }

    pub(crate) fn matches_identity(&self, identity: GatewayMappingIdentity) -> bool {
        self.identity == Some(identity)
    }

    pub(crate) fn needs_discovery(&self, identity: GatewayMappingIdentity, now: Instant) -> bool {
        !self.matches_identity(identity)
            || (self.candidate_endpoint.is_none()
                && self.retry_at.is_none_or(|retry_at| now >= retry_at))
            || self.renew_at.is_some_and(|renew_at| now >= renew_at)
    }

    pub(crate) fn retain_candidate(&self, identity: GatewayMappingIdentity, now: Instant) -> bool {
        self.matches_identity(identity)
            && self.candidate_endpoint.is_some()
            && self.renew_at.is_some_and(|renew_at| now < renew_at)
    }

    pub(crate) fn record_success(
        &mut self,
        identity: GatewayMappingIdentity,
        candidate_endpoint: String,
        candidate_source: &'static str,
        lease: Duration,
    ) -> bool {
        if !self.matches_identity(identity) {
            return false;
        }
        self.local_endpoint = Some(identity.local_endpoint);
        self.candidate_endpoint = Some(candidate_endpoint);
        self.candidate_source = Some(candidate_source);
        self.granted_lease_seconds = Some(lease.as_secs().min(u64::from(u32::MAX)) as u32);
        // Renew at half the granted lease.  This provides a retry window
        // without issuing a full discovery on every candidate refresh.
        self.renew_at = Instant::now().checked_add(lease / 2);
        self.retry_at = None;
        true
    }

    pub(crate) fn record_failure(
        &mut self,
        identity: GatewayMappingIdentity,
        retry_after: Duration,
    ) -> bool {
        if !self.matches_identity(identity) {
            return false;
        }
        self.local_endpoint = Some(identity.local_endpoint);
        self.candidate_endpoint = None;
        self.candidate_source = None;
        self.renew_at = None;
        self.granted_lease_seconds = None;
        self.retry_at = Instant::now().checked_add(retry_after);
        true
    }

    pub fn snapshot(
        &self,
        enabled: bool,
        lease_seconds: u32,
        mut diagnostics: GatewayMappingDiagnostics,
    ) -> GatewayMappingDiagnostics {
        let now = Instant::now();
        diagnostics.enabled = enabled;
        diagnostics.lease_seconds = self.granted_lease_seconds.unwrap_or(lease_seconds);
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

    fn identity() -> GatewayMappingIdentity {
        GatewayMappingIdentity {
            bind_endpoint: "0.0.0.0:51820".parse().unwrap(),
            local_endpoint: "192.168.1.7:51820".parse().unwrap(),
            gateway: Some("192.168.1.1".parse().unwrap()),
            network_generation: 4,
            transport_instance: 2,
            publication_owner: 3,
        }
    }

    #[test]
    fn mapping_cache_reuses_a_valid_lease_and_then_renews() {
        let mut runtime = GatewayMappingRuntime::default();
        let identity = identity();
        runtime.bind_identity(identity);
        assert!(runtime.record_success(
            identity,
            "203.0.113.8:51820".to_string(),
            "upnp",
            Duration::from_secs(120),
        ));
        assert!(runtime.retain_candidate(identity, Instant::now()));
        assert!(!runtime.needs_discovery(identity, Instant::now()));
        runtime.renew_at = Some(Instant::now() - Duration::from_millis(1));
        assert!(runtime.needs_discovery(identity, Instant::now()));
    }

    #[test]
    fn changed_discovery_scope_drops_success_and_failure_for_the_same_private_endpoint() {
        let original = identity();
        let replacements = [
            GatewayMappingIdentity {
                network_generation: 5,
                ..original
            },
            GatewayMappingIdentity {
                transport_instance: 9,
                ..original
            },
            GatewayMappingIdentity {
                publication_owner: 8,
                ..original
            },
            GatewayMappingIdentity {
                gateway: Some("192.168.1.254".parse().unwrap()),
                ..original
            },
            GatewayMappingIdentity {
                bind_endpoint: "192.168.1.7:51820".parse().unwrap(),
                ..original
            },
            GatewayMappingIdentity {
                local_endpoint: "192.168.1.8:51820".parse().unwrap(),
                ..original
            },
        ];
        for replacement in replacements {
            for success in [false, true] {
                let mut runtime = GatewayMappingRuntime::default();
                runtime.bind_identity(original);
                if success {
                    assert!(runtime.record_success(
                        original,
                        "203.0.113.8:51820".into(),
                        "upnp",
                        Duration::from_secs(120)
                    ));
                } else {
                    assert!(runtime.record_failure(original, Duration::from_secs(60)));
                }
                assert!(!runtime.needs_discovery(original, Instant::now()));
                runtime.bind_identity(replacement);
                assert!(runtime.needs_discovery(replacement, Instant::now()));
                assert!(!runtime.retain_candidate(replacement, Instant::now()));
                assert!(runtime.candidate_endpoint.is_none());
                assert!(runtime.retry_at.is_none());
            }
        }
    }

    #[test]
    fn delayed_old_discovery_cannot_overwrite_replacement_success_or_backoff() {
        let original = identity();
        let replacement = GatewayMappingIdentity {
            network_generation: 5,
            transport_instance: 8,
            publication_owner: 9,
            ..original
        };
        let mut runtime = GatewayMappingRuntime::default();
        runtime.bind_identity(original);
        runtime.bind_identity(replacement);
        assert!(runtime.record_success(
            replacement,
            "203.0.113.9:51820".into(),
            "pcp",
            Duration::from_secs(120)
        ));
        assert!(!runtime.record_success(
            original,
            "203.0.113.8:51820".into(),
            "upnp",
            Duration::from_secs(120)
        ));
        assert!(!runtime.record_failure(original, Duration::from_secs(60)));
        assert_eq!(
            runtime.candidate_endpoint.as_deref(),
            Some("203.0.113.9:51820")
        );
        assert!(runtime.retry_at.is_none());
        assert!(runtime.record_failure(replacement, Duration::from_secs(60)));
        let retry_at = runtime.retry_at;
        assert!(!runtime.record_success(
            original,
            "203.0.113.8:51820".into(),
            "upnp",
            Duration::from_secs(120)
        ));
        assert_eq!(runtime.retry_at, retry_at);
        assert!(runtime.candidate_endpoint.is_none());
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
