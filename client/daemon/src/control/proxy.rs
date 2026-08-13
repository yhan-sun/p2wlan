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

    /// Serializes the two ambient-proxy tests: reqwest resolves the system
    /// proxy at REQUEST time from the process environment, so both tests must
    /// never mutate HTTP_PROXY concurrently (their requests would observe each
    /// other's proxy address).
    static PROXY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// Spin up a fake HTTP proxy that records every request line it sees and
    /// answers everything with 200.  Returns the proxy address and a channel
    /// carrying each observed request line.
    async fn fake_proxy() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (seen_tx, seen_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    let head = String::from_utf8_lossy(&buf[..n]).to_string();
                    let first_line = head.lines().next().unwrap_or_default().to_string();
                    let _ = seen_tx.send(first_line);
                    let body = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok";
                    let _ = socket.write_all(body.as_bytes()).await;
                });
            }
        });
        (addr, seen_rx)
    }

    async fn http_get_through(client: &reqwest::Client, url: &str) -> bool {
        match client.get(url).send().await {
            Ok(resp) => resp.status().is_success() || !resp.status().is_server_error(),
            Err(_) => false,
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn direct_mode_never_uses_ambient_http_proxy() {
        // The default policy is no_proxy: an ambient HTTP_PROXY must never
        // capture control-plane HTTP traffic.  The fake proxy must see ZERO
        // requests from the Direct-mode client even though the environment
        // points at it.
        let (proxy_addr, mut seen) = fake_proxy().await;
        let _lock = PROXY_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::env::var("HTTP_PROXY").ok();
        unsafe {
            std::env::set_var("HTTP_PROXY", proxy_addr.clone());
            std::env::set_var("http_proxy", proxy_addr.clone());
        }
        let direct = control_http_client(ControlProxyMode::Direct)
            .expect("Direct-mode client must build");
        // The control endpoint is unreachable here; what matters is that the
        // request goes DIRECT (fails to connect) instead of via the proxy —
        // the fake proxy must never see a request.
        let _ = http_get_through(&direct, "http://127.0.0.1:1/control/health").await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            seen.try_recv().is_err(),
            "the Direct-mode (no_proxy) client must never contact an ambient HTTP proxy, got {:?}",
            seen.try_recv()
        );
        match old {
            Some(old) => unsafe { std::env::set_var("HTTP_PROXY", old) },
            None => unsafe { std::env::remove_var("HTTP_PROXY") },
        }
        std::env::remove_var("http_proxy");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn environment_mode_uses_ambient_http_proxy() {
        // Explicitly opting into the environment must route control HTTP via
        // the ambient proxy (the proxy observes the request).
        let (proxy_addr, mut seen) = fake_proxy().await;
        let _lock = PROXY_ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::env::var("HTTP_PROXY").ok();
        unsafe {
            std::env::set_var("HTTP_PROXY", proxy_addr.clone());
            std::env::set_var("http_proxy", proxy_addr.clone());
        }
        let env_client = control_http_client(ControlProxyMode::Environment)
            .expect("Environment-mode client must build");
        let _ = http_get_through(&env_client, "http://example.invalid/control/health").await;
        let line = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            seen.recv(),
        )
        .await
        .expect("the Environment-mode client must reach the ambient proxy")
        .unwrap();
        assert!(
            line.contains("example.invalid") || line.starts_with("CONNECT"),
            "the proxy must observe the proxied control request, got: {line}"
        );
        match old {
            Some(old) => unsafe { std::env::set_var("HTTP_PROXY", old) },
            None => std::env::remove_var("HTTP_PROXY"),
        }
        std::env::remove_var("http_proxy");
    }
}
