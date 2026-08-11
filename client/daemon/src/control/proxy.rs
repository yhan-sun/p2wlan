// Control-plane HTTP client construction and explicit proxy policy.
//
// The daemon must be explicit about whether its control-plane HTTP traffic
// reads the process environment's `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
// variables.  `ControlProxyMode::Direct` (the default) builds a client with
// `.no_proxy()` so an ambient proxy can never capture control traffic;
// `ControlProxyMode::Environment` opts in to the reqwest default system-proxy
// matcher.
//
// The SAME builder backs both the ordinary control loop and the independent
// critical (handshake) lane, so the two HTTP lanes can never disagree on proxy
// policy.
//
// WebSocket signaling is intentionally NOT covered by this policy: the pinned
// tokio-tungstenite client has no proxy support, so it is always direct-only.
// Diagnostics record only the mode and whether it reads the environment —
// never the proxy URL, tokens, or authentication headers.

// This file is `include!`d into `http.rs`, so `DaemonError`/`Result` and the
// config types come from the enclosing module scope.

/// Short, non-sensitive label for diagnostics/structured events describing the
/// HTTP proxy behavior selected by a mode.
pub fn proxy_http_behavior_label(mode: ControlProxyMode) -> &'static str {
    match mode {
        ControlProxyMode::Direct => "no_proxy",
        ControlProxyMode::Environment => "env_proxy",
    }
}

/// Whether the mode actually consults the process environment proxies for
/// control-plane HTTP traffic.
pub fn proxy_consults_environment(mode: ControlProxyMode) -> bool {
    matches!(mode, ControlProxyMode::Environment)
}

/// Build the single control-plane HTTP client for a proxy mode.
///
/// This is the ONLY place the control plane constructs a `reqwest::Client`;
/// both `run_control_loop` and `run_critical_control_loop` obtain their client
/// from here so the two lanes share one policy.
pub fn control_http_client(mode: ControlProxyMode) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder();
    let client = match mode {
        ControlProxyMode::Direct => builder.no_proxy().build(),
        ControlProxyMode::Environment => builder.build(),
    };
    client.map_err(|err| {
        DaemonError::ControlPlane(format!(
            "failed to build control-plane HTTP client for proxy mode {}: {err}",
            mode.as_label()
        ))
    })
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    #[test]
    fn behavior_labels_are_stable() {
        assert_eq!(proxy_http_behavior_label(ControlProxyMode::Direct), "no_proxy");
        assert_eq!(
            proxy_http_behavior_label(ControlProxyMode::Environment),
            "env_proxy"
        );
        assert!(!proxy_consults_environment(ControlProxyMode::Direct));
        assert!(proxy_consults_environment(ControlProxyMode::Environment));
    }
}
