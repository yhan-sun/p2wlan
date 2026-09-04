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
    control_http_client_for_server(mode, None)
}

/// Build a control-plane client and, for direct mode, pin public TCP sockets
/// to the physical default interface. `.no_proxy()` alone only bypasses HTTP
/// proxy discovery; it does not bypass routes installed by a TUN client.
pub fn control_http_client_for_server(
    mode: ControlProxyMode,
    server_url: Option<&str>,
) -> Result<reqwest::Client> {
    let binding = control_route_binding(mode, server_url);
    if binding.fail_closed {
        return Err(DaemonError::ControlPlane(
            "refusing unbound control HTTP socket while a foreign TUN captures public routes"
                .into(),
        ));
    }
    build_control_http_client(mode, server_url, binding.outbound_interface.as_deref())
}

fn build_control_http_client(
    mode: ControlProxyMode,
    server_url: Option<&str>,
    outbound_interface: Option<&str>,
) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder();

    // `reqwest::ClientBuilder::interface` is unavailable on Windows. Keep
    // the binding code behind the same target gate so a Windows build does
    // not report the builder as unnecessarily mutable or the interface as an
    // unused variable.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ))]
    let builder = {
        let mut builder = builder;
        if mode == ControlProxyMode::Direct
            && server_url.is_some_and(|url| !control_server_is_local(url))
        {
            if let Some(interface) = outbound_interface {
                builder = builder.interface(interface);
            }
        }
        builder
    };

    #[cfg(not(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    )))]
    let builder = {
        let _ = outbound_interface;
        let _ = server_url;
        builder
    };

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ControlRouteBinding {
    signature: Vec<String>,
    outbound_interface: Option<String>,
    fail_closed: bool,
}

fn control_route_binding(mode: ControlProxyMode, server_url: Option<&str>) -> ControlRouteBinding {
    let route_aware = mode == ControlProxyMode::Direct
        && server_url.is_some_and(|url| !control_server_is_local(url));
    if !route_aware {
        return ControlRouteBinding {
            signature: Vec::new(),
            outbound_interface: None,
            fail_closed: false,
        };
    }

    let routes = crate::netenv::direct_route_snapshot(&[]);
    ControlRouteBinding {
        signature: routes.signature,
        outbound_interface: routes.physical_route_interface.clone(),
        fail_closed: routes.tun_capture && routes.physical_route_interface.is_none(),
    }
}

#[derive(Clone)]
struct ControlHttpPoolState {
    primary: Option<Arc<reqwest::Client>>,
    candidate: Option<Arc<reqwest::Client>>,
    unavailable_reason: Option<String>,
}

#[derive(Clone, Copy)]
enum ControlHttpLane {
    Primary,
    Candidate,
}

/// Cheap handle to the current control-plane connection pool. A request takes
/// an `Arc` snapshot, so replacing the pool never holds a lock across network
/// I/O and in-flight requests may finish while all new requests use the new
/// route binding.
#[derive(Clone)]
pub(super) struct RouteAwareControlHttpClient {
    state_rx: tokio::sync::watch::Receiver<ControlHttpPoolState>,
    lane: ControlHttpLane,
    force_network_change_tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
}

impl RouteAwareControlHttpClient {
    pub(super) fn current(&self) -> Result<Arc<reqwest::Client>> {
        let state = self.state_rx.borrow();
        let client = match self.lane {
            ControlHttpLane::Primary => state.primary.clone(),
            ControlHttpLane::Candidate => state.candidate.clone(),
        };
        client.ok_or_else(|| {
            DaemonError::ControlPlane(
                state
                    .unavailable_reason
                    .clone()
                    .unwrap_or_else(|| "control HTTP route is unavailable".to_string()),
            )
        })
    }

    pub(super) fn notify_network_changed(&self) {
        if let Some(sender) = &self.force_network_change_tx {
            let _ = sender.send(());
        }
    }
}

fn build_control_http_pools(
    mode: ControlProxyMode,
    server_url: &str,
    binding: ControlRouteBinding,
) -> ControlHttpPoolState {
    if binding.fail_closed {
        return ControlHttpPoolState {
            primary: None,
            candidate: None,
            unavailable_reason: Some(
                "control HTTP blocked: foreign TUN capture detected but no physical route interface is available"
                    .to_string(),
            ),
        };
    }

    let primary = build_control_http_client(
        mode,
        Some(server_url),
        binding.outbound_interface.as_deref(),
    );
    let candidate = build_control_http_client(
        mode,
        Some(server_url),
        binding.outbound_interface.as_deref(),
    );
    match (primary, candidate) {
        (Ok(primary), Ok(candidate)) => ControlHttpPoolState {
            primary: Some(Arc::new(primary)),
            candidate: Some(Arc::new(candidate)),
            unavailable_reason: None,
        },
        (primary, candidate) => {
            let error = primary
                .err()
                .or_else(|| candidate.err())
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown client construction error".to_string());
            ControlHttpPoolState {
                primary: None,
                candidate: None,
                unavailable_reason: Some(format!(
                    "control HTTP client construction failed: {error}"
                )),
            }
        }
    }
}

const CONTROL_ROUTE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const CONTROL_ROUTE_STABILITY_SAMPLES: u8 = 2;

fn observe_stable_route_change(
    active: &ControlRouteBinding,
    pending: &mut Option<(ControlRouteBinding, u8)>,
    observed: ControlRouteBinding,
) -> Option<ControlRouteBinding> {
    if &observed == active {
        *pending = None;
        return None;
    }
    match pending {
        Some((candidate, samples)) if *candidate == observed => {
            *samples = samples.saturating_add(1);
            if *samples >= CONTROL_ROUTE_STABILITY_SAMPLES {
                *pending = None;
                Some(observed)
            } else {
                None
            }
        }
        _ => {
            *pending = Some((observed, 1));
            None
        }
    }
}

/// Create two independently pooled clients whose binding is replaced after a
/// route/interface/gateway signature change is observed twice consecutively.
/// Direct mode fails closed under foreign TUN capture when no physical bypass
/// interface can be selected. Environment-proxy mode preserves the user's
/// explicit proxy choice and is intentionally not pinned.
pub(super) fn route_aware_control_http_clients(
    mode: ControlProxyMode,
    server_url: &str,
) -> (RouteAwareControlHttpClient, RouteAwareControlHttpClient) {
    let route_aware = mode == ControlProxyMode::Direct && !control_server_is_local(server_url);
    let initial_binding = control_route_binding(mode, Some(server_url));
    let initial_state = build_control_http_pools(mode, server_url, initial_binding.clone());
    if let Some(reason) = &initial_state.unavailable_reason {
        warn!("{reason}");
    }
    let (state_tx, state_rx) = tokio::sync::watch::channel(initial_state);
    let (force_network_change_tx, mut force_network_change_rx) =
        tokio::sync::mpsc::unbounded_channel::<()>();
    let primary = RouteAwareControlHttpClient {
        state_rx: state_rx.clone(),
        lane: ControlHttpLane::Primary,
        force_network_change_tx: route_aware.then_some(force_network_change_tx.clone()),
    };
    let candidate = RouteAwareControlHttpClient {
        state_rx,
        lane: ControlHttpLane::Candidate,
        force_network_change_tx: route_aware.then_some(force_network_change_tx.clone()),
    };

    if route_aware {
        let server_url = server_url.to_string();
        tokio::spawn(async move {
            let mut active_binding = initial_binding;
            let mut pending = None;
            let mut ticker = tokio::time::interval(CONTROL_ROUTE_POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let forced = tokio::select! {
                    _ = ticker.tick() => false,
                    forced = force_network_change_rx.recv() => {
                        if forced.is_none() {
                            return;
                        }
                        true
                    }
                };
                if state_tx.is_closed() {
                    return;
                }
                let inspection_url = server_url.clone();
                let observed = match tokio::task::spawn_blocking(move || {
                    control_route_binding(mode, Some(&inspection_url))
                })
                .await
                {
                    Ok(binding) if forced || !binding.signature.is_empty() => binding,
                    Ok(_) => {
                        pending = None;
                        continue;
                    }
                    Err(error) => {
                        pending = None;
                        warn!("Control-plane route inspection task failed: {error}");
                        continue;
                    }
                };
                if forced {
                    let replacement = build_control_http_pools(mode, &server_url, observed.clone());
                    if let Some(reason) = &replacement.unavailable_reason {
                        warn!("Control-plane HTTP pools forced to rebuild after Android network change; {reason}");
                    } else {
                        info!(
                            "Rebuilt control-plane HTTP pools after Android physical network change; outbound_interface={:?}",
                            observed.outbound_interface
                        );
                    }
                    active_binding = observed;
                    pending = None;
                    state_tx.send_replace(replacement);
                    continue;
                }
                let replacement =
                    observe_stable_route_change(&active_binding, &mut pending, observed.clone());
                if let Some(binding) = replacement {
                    let replacement = build_control_http_pools(mode, &server_url, binding.clone());
                    if let Some(reason) = &replacement.unavailable_reason {
                        warn!("Control-plane route changed; {reason}");
                    } else {
                        info!(
                            "Rebuilt control-plane HTTP pools after network route change; outbound_interface={:?}",
                            binding.outbound_interface
                        );
                    }
                    active_binding = binding;
                    state_tx.send_replace(replacement);
                    continue;
                }

                // A transient client-builder failure should heal without
                // requiring another network change. TUN fail-closed states do
                // not retry construction until route inspection says a bypass
                // is available.
                if observed == active_binding
                    && !active_binding.fail_closed
                    && state_tx.borrow().primary.is_none()
                {
                    let retry = build_control_http_pools(mode, &server_url, active_binding.clone());
                    if retry.primary.is_some() {
                        info!("Recovered control-plane HTTP client construction");
                        state_tx.send_replace(retry);
                    }
                }
            }
        });
    }

    (primary, candidate)
}

fn control_server_is_local(server_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(server_url) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.eq_ignore_ascii_case("localhost")
        || unbracketed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
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
        assert_eq!(
            proxy_http_behavior_label(ControlProxyMode::Direct),
            "no_proxy"
        );
        assert_eq!(
            proxy_http_behavior_label(ControlProxyMode::Environment),
            "env_proxy"
        );
        assert!(!proxy_consults_environment(ControlProxyMode::Direct));
        assert!(proxy_consults_environment(ControlProxyMode::Environment));
    }

    #[test]
    fn local_control_urls_are_not_forced_onto_a_physical_interface() {
        assert!(control_server_is_local("http://127.0.0.1:8080"));
        assert!(control_server_is_local("https://[::1]:8443"));
        assert!(control_server_is_local("http://localhost:8080"));
        assert!(!control_server_is_local("https://control.example.com"));
    }

    fn test_binding(signature: &str, interface: Option<&str>) -> ControlRouteBinding {
        ControlRouteBinding {
            signature: vec![signature.to_string()],
            outbound_interface: interface.map(str::to_string),
            fail_closed: false,
        }
    }

    #[test]
    fn route_pool_rebuild_requires_two_consecutive_observations() {
        let active = test_binding("network-a", Some("en0"));
        let replacement = test_binding("network-b", Some("en1"));
        let mut pending = None;

        assert!(observe_stable_route_change(&active, &mut pending, replacement.clone(),).is_none());
        assert!(observe_stable_route_change(&active, &mut pending, active.clone()).is_none());
        assert!(
            pending.is_none(),
            "a transient route sample must be cleared"
        );

        assert!(observe_stable_route_change(&active, &mut pending, replacement.clone(),).is_none());
        assert_eq!(
            observe_stable_route_change(&active, &mut pending, replacement.clone()),
            Some(replacement)
        );
    }

    #[test]
    fn tun_capture_without_physical_interface_fails_closed() {
        let state = build_control_http_pools(
            ControlProxyMode::Direct,
            "https://control.example.com",
            ControlRouteBinding {
                signature: vec!["1.1.1.1:utun23".to_string()],
                outbound_interface: None,
                fail_closed: true,
            },
        );
        assert!(state.primary.is_none());
        assert!(state.candidate.is_none());
        assert!(state
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("foreign TUN capture")));
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
        let _lock = PROXY_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::env::var("HTTP_PROXY").ok();
        unsafe {
            std::env::set_var("HTTP_PROXY", proxy_addr.clone());
            std::env::set_var("http_proxy", proxy_addr.clone());
        }
        let direct =
            control_http_client(ControlProxyMode::Direct).expect("Direct-mode client must build");
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
        let _lock = PROXY_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = std::env::var("HTTP_PROXY").ok();
        unsafe {
            std::env::set_var("HTTP_PROXY", proxy_addr.clone());
            std::env::set_var("http_proxy", proxy_addr.clone());
        }
        let env_client = control_http_client(ControlProxyMode::Environment)
            .expect("Environment-mode client must build");
        let _ = http_get_through(&env_client, "http://example.invalid/control/health").await;
        let line = tokio::time::timeout(std::time::Duration::from_secs(2), seen.recv())
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
