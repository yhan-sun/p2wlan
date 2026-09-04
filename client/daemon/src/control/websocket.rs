//! WebSocket signaling transport for the control plane.
//!
//! Subscribes to push notifications (`ready` / `signals_available`) so the
//! REST long-poll can wake immediately when a new signal lands, instead of
//! waiting a full tick. Split out of `control.rs`.
//!
//! PROXY POLICY: WebSocket signaling is ALWAYS direct-only. In addition to
//! ignoring HTTP proxy variables, its TCP socket is pinned to the physical
//! default interface so a kernel-level TUN route cannot capture it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
use tracing::{debug, info, warn};

use crate::error::{DaemonError, Result};

const SIGNAL_WS_MAX_BACKOFF: Duration = Duration::from_secs(30);
const SIGNAL_WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNAL_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SIGNAL_WS_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const SIGNAL_WS_ROUTE_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const SIGNAL_WS_ROUTE_STABILITY_SAMPLES: u8 = 2;
pub(super) const SIGNAL_WS_PROTOCOL: &str = "p2wlan.signaling.v1";
const SIGNAL_WS_PROTOCOL_VERSION: u8 = 1;

/// Stable diagnostic label of the WebSocket proxy policy.  Always
/// `direct_only` today: the pinned tokio-tungstenite client cannot use a
/// proxy, so signaling never rides an ambient proxy and the REST lane's proxy
/// mode is never silently mirrored here.
pub fn websocket_proxy_policy_label() -> &'static str {
    "direct_only"
}

/// Owner of the current signaling WebSocket connection. A late task cleanup
/// can only clear the connected bit while its connection generation is still
/// current, so a reconnect cannot be torn down by the old task.
#[derive(Clone)]
pub(super) struct SignalConnectionLifecycle {
    generation: Arc<Mutex<u64>>,
    connected: Arc<AtomicBool>,
}

impl SignalConnectionLifecycle {
    pub(super) fn new(connected: Arc<AtomicBool>) -> Self {
        Self {
            generation: Arc::new(Mutex::new(0)),
            connected,
        }
    }

    pub(super) fn begin(&self) -> u64 {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *generation = generation.saturating_add(1);
        *generation
    }

    pub(super) fn mark_connected(&self, owner: u64) -> bool {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *generation != owner {
            return false;
        }
        self.connected.store(true, Ordering::Release);
        true
    }

    pub(super) fn mark_disconnected(&self, owner: u64) {
        let generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *generation == owner {
            self.connected.store(false, Ordering::Release);
        }
    }

    pub(super) fn close(&self) {
        let mut generation = self
            .generation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *generation = generation.saturating_add(1);
        self.connected.store(false, Ordering::Release);
    }
}

#[derive(Debug, Deserialize)]
struct SignalWebSocketMessage {
    #[serde(rename = "type")]
    message_type: String,
    protocol_version: u8,
    #[serde(default)]
    node_id: String,
    #[serde(default)]
    network_id: String,
    #[serde(default)]
    sequence: u64,
    #[serde(default)]
    server_time_ms: u64,
}

pub(super) struct SignalWebSocketTask {
    handle: tokio::task::JoinHandle<()>,
    lifecycle: SignalConnectionLifecycle,
}

impl SignalWebSocketTask {
    pub(super) fn abort(&self) {
        self.lifecycle.close();
        self.handle.abort();
    }
}

impl Drop for SignalWebSocketTask {
    fn drop(&mut self) {
        self.lifecycle.close();
        self.handle.abort();
    }
}

pub(super) fn spawn_signal_websocket(
    base_url: &str,
    token: &str,
    node_id: &str,
    network_id: &str,
    wake_tx: mpsc::Sender<()>,
    connected: Arc<AtomicBool>,
) -> SignalWebSocketTask {
    let lifecycle = SignalConnectionLifecycle::new(connected);
    let task_lifecycle = lifecycle.clone();
    let base_url = base_url.to_string();
    let token = token.to_string();
    let node_id = node_id.to_string();
    let network_id = network_id.to_string();
    let handle = tokio::spawn(async move {
        run_signal_websocket_with_lifecycle(
            &base_url,
            &token,
            &node_id,
            &network_id,
            wake_tx,
            task_lifecycle,
        )
        .await;
    });
    SignalWebSocketTask { handle, lifecycle }
}

#[cfg(test)]
pub(super) async fn run_signal_websocket(
    base_url: &str,
    token: &str,
    expected_node_id: &str,
    expected_network_id: &str,
    wake_tx: mpsc::Sender<()>,
    connected: Arc<AtomicBool>,
) {
    run_signal_websocket_with_lifecycle(
        base_url,
        token,
        expected_node_id,
        expected_network_id,
        wake_tx,
        SignalConnectionLifecycle::new(connected),
    )
    .await;
}

async fn run_signal_websocket_with_lifecycle(
    base_url: &str,
    token: &str,
    expected_node_id: &str,
    expected_network_id: &str,
    wake_tx: mpsc::Sender<()>,
    lifecycle: SignalConnectionLifecycle,
) {
    let ws_url = match signal_websocket_url(base_url) {
        Ok(url) => url,
        Err(err) => {
            warn!("WebSocket signaling disabled: {err}");
            return;
        }
    };
    let authorization = match HeaderValue::from_str(&format!("Bearer {token}")) {
        Ok(value) => value,
        Err(_) => {
            warn!("WebSocket signaling disabled: invalid credential header");
            return;
        }
    };

    let mut attempt = 0u32;
    loop {
        let connection_generation = lifecycle.begin();
        lifecycle.mark_disconnected(connection_generation);
        let mut request = match ws_url.as_str().into_client_request() {
            Ok(request) => request,
            Err(err) => {
                warn!("WebSocket signaling request construction failed: {err}");
                return;
            }
        };
        request
            .headers_mut()
            .insert(AUTHORIZATION, authorization.clone());
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(SIGNAL_WS_PROTOCOL),
        );

        // Proxy policy: WebSocket signaling is ALWAYS direct-only. The raw
        // TCP socket is created explicitly so direct-only also means bypassing
        // a system TUN route, not merely ignoring HTTP_PROXY variables.
        let target = websocket_tcp_target(&ws_url);
        let route_snapshot =
            tokio::task::spawn_blocking(|| crate::netenv::direct_route_snapshot(&[])).await;
        let outbound_interface = if target
            .as_ref()
            .is_ok_and(|(host, _)| websocket_host_is_local(host))
        {
            Ok(None)
        } else {
            route_snapshot
                .as_ref()
                .map_err(|error| format!("route inspection task failed: {error}"))
                .and_then(|snapshot| snapshot.direct_socket_interface())
        };
        let connected_route_signature = route_snapshot
            .as_ref()
            .map(|snapshot| snapshot.signature.clone())
            .unwrap_or_default();

        match time::timeout(SIGNAL_WS_CONNECT_TIMEOUT, async {
            let outbound_interface = outbound_interface.map_err(|error| {
                tokio_tungstenite::tungstenite::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NetworkUnreachable,
                    error,
                ))
            })?;
            let (host, port) = target.map_err(|error| {
                tokio_tungstenite::tungstenite::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    error,
                ))
            })?;
            let stream =
                p2pnet_netbind::connect_tcp_host(&host, port, outbound_interface.as_deref())
                    .await
                    .map_err(tokio_tungstenite::tungstenite::Error::Io)?;
            tokio_tungstenite::client_async_tls(request, stream).await
        })
        .await
        {
            Ok(Ok((mut socket, response))) => {
                let negotiated = response
                    .headers()
                    .get(SEC_WEBSOCKET_PROTOCOL)
                    .and_then(|value| value.to_str().ok());
                if negotiated != Some(SIGNAL_WS_PROTOCOL) {
                    warn!(
                        "WebSocket signaling rejected required subprotocol; negotiated={negotiated:?}"
                    );
                    let _ = time::timeout(SIGNAL_WS_WRITE_TIMEOUT, socket.close(None)).await;
                } else {
                    info!("WebSocket signaling connected at {ws_url}");
                    attempt = 0;
                    let mut ready = false;
                    let mut last_sequence = 0u64;
                    let mut last_message_at = std::time::Instant::now();
                    let mut next_route_check =
                        std::time::Instant::now() + SIGNAL_WS_ROUTE_CHECK_INTERVAL;
                    let mut pending_route_change = None;
                    loop {
                        let now = std::time::Instant::now();
                        let idle_remaining = SIGNAL_WS_IDLE_TIMEOUT
                            .saturating_sub(now.saturating_duration_since(last_message_at));
                        if idle_remaining.is_zero() {
                            debug!("WebSocket signaling connection became idle");
                            break;
                        }
                        let route_wait = next_route_check.saturating_duration_since(now);
                        let wait = idle_remaining.min(route_wait);
                        let next_message = time::timeout(wait, socket.next()).await;

                        let now = std::time::Instant::now();
                        if now >= next_route_check {
                            next_route_check = now + SIGNAL_WS_ROUTE_CHECK_INTERVAL;
                            let observed = tokio::task::spawn_blocking(|| {
                                crate::netenv::network_route_signature(&[])
                            })
                            .await
                            .unwrap_or_default();
                            if stable_websocket_route_change(
                                &connected_route_signature,
                                &mut pending_route_change,
                                observed,
                            ) {
                                info!(
                                    "WebSocket signaling route changed; reconnecting on the new physical path"
                                );
                                break;
                            }
                        }

                        let message = match next_message {
                            Ok(Some(message)) => message,
                            Ok(None) => break,
                            Err(_) => continue,
                        };
                        last_message_at = now;
                        let message = match message {
                            Ok(message) => message,
                            Err(err) => {
                                debug!("WebSocket signaling read failed: {err}");
                                break;
                            }
                        };
                        match message {
                            WebSocketMessage::Text(text) => {
                                if text.len() > 4096 {
                                    warn!("WebSocket signaling message exceeded client limit");
                                    break;
                                }
                                let message: SignalWebSocketMessage =
                                    match serde_json::from_str(text.as_str()) {
                                        Ok(message) => message,
                                        Err(err) => {
                                            warn!(
                                                "Ignoring invalid WebSocket signaling JSON: {err}"
                                            );
                                            break;
                                        }
                                    };
                                if message.protocol_version != SIGNAL_WS_PROTOCOL_VERSION {
                                    warn!(
                                        "WebSocket signaling protocol mismatch: server={} client={}",
                                        message.protocol_version, SIGNAL_WS_PROTOCOL_VERSION
                                    );
                                    break;
                                }
                                match message.message_type.as_str() {
                                    "ready" if !ready => {
                                        if message.node_id != expected_node_id
                                            || message.network_id != expected_network_id
                                        {
                                            warn!(
                                                "WebSocket signaling identity mismatch; closing connection"
                                            );
                                            break;
                                        }
                                        ready = true;
                                        if !lifecycle.mark_connected(connection_generation) {
                                            break;
                                        }
                                        debug!(
                                            "WebSocket signaling ready for node {} at server_time_ms={}",
                                            expected_node_id, message.server_time_ms
                                        );
                                        if wake_tx.try_send(()).is_err() && wake_tx.is_closed() {
                                            return;
                                        }
                                    }
                                    "signals_available" if ready => {
                                        if message.sequence == 0 {
                                            warn!("WebSocket signaling rejected zero notification sequence");
                                            break;
                                        }
                                        if message.sequence <= last_sequence {
                                            continue;
                                        }
                                        last_sequence = message.sequence;
                                        if wake_tx.try_send(()).is_err() && wake_tx.is_closed() {
                                            return;
                                        }
                                    }
                                    other => {
                                        warn!(
                                            "Unexpected WebSocket signaling message '{other}' before/after readiness"
                                        );
                                        break;
                                    }
                                }
                            }
                            WebSocketMessage::Ping(payload) => {
                                if !matches!(
                                    time::timeout(
                                        SIGNAL_WS_WRITE_TIMEOUT,
                                        socket.send(WebSocketMessage::Pong(payload)),
                                    )
                                    .await,
                                    Ok(Ok(()))
                                ) {
                                    break;
                                }
                            }
                            WebSocketMessage::Close(_) => break,
                            WebSocketMessage::Binary(_) => {
                                warn!("WebSocket signaling rejected unexpected binary message");
                                break;
                            }
                            WebSocketMessage::Pong(_) | WebSocketMessage::Frame(_) => {}
                        }
                    }
                }
            }
            Ok(Err(err)) => {
                debug!(
                    "WebSocket signaling connection failed; HTTP fallback remains active: {err}"
                );
            }
            Err(_) => {
                debug!("WebSocket signaling connection timed out; HTTP fallback remains active");
            }
        }

        lifecycle.mark_disconnected(connection_generation);
        attempt = attempt.saturating_add(1);
        let exponent = attempt.saturating_sub(1).min(5);
        let base = Duration::from_secs(1u64 << exponent).min(SIGNAL_WS_MAX_BACKOFF);
        let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..=500));
        time::sleep(base.saturating_add(jitter)).await;
    }
}

fn websocket_tcp_target(url: &str) -> std::result::Result<(String, u16), String> {
    let parsed = reqwest::Url::parse(url).map_err(|error| error.to_string())?;
    let host = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "WebSocket URL has no host".to_string())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "WebSocket URL has no port".to_string())?;
    Ok((host.to_string(), port))
}

fn websocket_host_is_local(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.eq_ignore_ascii_case("localhost")
        || unbracketed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn stable_websocket_route_change(
    active: &[String],
    pending: &mut Option<(Vec<String>, u8)>,
    observed: Vec<String>,
) -> bool {
    if observed.is_empty() {
        *pending = None;
        return false;
    }
    if observed == active {
        *pending = None;
        return false;
    }
    match pending {
        Some((candidate, samples)) if *candidate == observed => {
            *samples = samples.saturating_add(1);
            if *samples >= SIGNAL_WS_ROUTE_STABILITY_SAMPLES {
                *pending = None;
                true
            } else {
                false
            }
        }
        _ => {
            *pending = Some((observed, 1));
            false
        }
    }
}

pub(super) fn signal_websocket_url(base_url: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(base_url).map_err(|err| {
        DaemonError::ControlPlane(format!(
            "invalid control URL for WebSocket signaling: {err}"
        ))
    })?;
    let ws_scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        "ws" => "ws",
        "wss" => "wss",
        scheme => {
            return Err(DaemonError::ControlPlane(format!(
                "unsupported control URL scheme for WebSocket signaling: {scheme}"
            )))
        }
    };
    url.set_scheme(ws_scheme).map_err(|_| {
        DaemonError::ControlPlane("failed to construct WebSocket signaling URL".to_string())
    })?;
    url.set_path("/api/v1/signals/ws");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

#[cfg(test)]
mod route_tests {
    use super::*;

    #[test]
    fn local_websocket_hosts_are_recognized_without_interface_binding() {
        assert!(websocket_host_is_local("localhost"));
        assert!(websocket_host_is_local("127.0.0.1"));
        assert!(websocket_host_is_local("[::1]"));
        assert!(!websocket_host_is_local("control.example.com"));
    }

    #[test]
    fn websocket_route_change_requires_two_stable_samples() {
        let active = vec!["default:en0:192.168.1.1".to_string()];
        let replacement = vec!["default:en1:192.168.2.1".to_string()];
        let mut pending = None;
        assert!(!stable_websocket_route_change(
            &active,
            &mut pending,
            Vec::new(),
        ));
        assert!(!stable_websocket_route_change(
            &active,
            &mut pending,
            replacement.clone(),
        ));
        assert!(!stable_websocket_route_change(
            &active,
            &mut pending,
            active.clone(),
        ));
        assert!(pending.is_none());
        assert!(!stable_websocket_route_change(
            &active,
            &mut pending,
            replacement.clone(),
        ));
        assert!(stable_websocket_route_change(
            &active,
            &mut pending,
            replacement,
        ));
    }

    #[test]
    fn new_control_connection_survives_old_task_teardown() {
        let connected = Arc::new(AtomicBool::new(false));
        let lifecycle = SignalConnectionLifecycle::new(connected.clone());
        let old = lifecycle.begin();
        assert!(lifecycle.mark_connected(old));
        let current = lifecycle.begin();
        assert!(lifecycle.mark_connected(current));

        lifecycle.mark_disconnected(old);
        assert!(connected.load(Ordering::Acquire));
        lifecycle.mark_disconnected(current);
        assert!(!connected.load(Ordering::Acquire));
    }

    #[test]
    fn evidence_ml12_control_reconnect() {
        let connected = Arc::new(AtomicBool::new(false));
        let lifecycle = SignalConnectionLifecycle::new(connected.clone());
        let old = lifecycle.begin();
        assert!(lifecycle.mark_connected(old));
        let current = lifecycle.begin();
        assert!(lifecycle.mark_connected(current));
        assert!(connected.load(Ordering::Acquire));
        println!(
            "MOBILE_LIFECYCLE_RECORD {{\"scenario_id\":\"ML-12\",\"exact_test_id\":\"control::websocket::route_tests::evidence_ml12_control_reconnect\",\"executed\":true,\"skipped\":false,\"result\":\"pass\",\"events\":[\"control_disconnected\",\"control_reconnected\"],\"observed_old_identity\":{{\"control_connection_generation\":{old}}},\"observed_new_identity\":{{\"control_connection_generation\":{current}}},\"observed_decision\":\"applied\",\"invariants\":{{\"new_control_generation_adopted\":true}},\"execution_source\":\"rust_test_nocapture\"}}"
        );
    }

    #[test]
    fn evidence_ml13_stale_control_message() {
        let connected = Arc::new(AtomicBool::new(false));
        let lifecycle = SignalConnectionLifecycle::new(connected.clone());
        let old = lifecycle.begin();
        let current = lifecycle.begin();
        assert!(!lifecycle.mark_connected(old));
        assert!(lifecycle.mark_connected(current));
        println!(
            "MOBILE_LIFECYCLE_RECORD {{\"scenario_id\":\"ML-13\",\"exact_test_id\":\"control::websocket::route_tests::evidence_ml13_stale_control_message\",\"executed\":true,\"skipped\":false,\"result\":\"pass\",\"events\":[\"control_reconnected\"],\"observed_old_identity\":{{\"control_connection_generation\":{old}}},\"observed_new_identity\":{{\"control_connection_generation\":{current}}},\"observed_decision\":\"stale_rejected\",\"invariants\":{{\"old_control_message_rejected\":true}},\"execution_source\":\"rust_test_nocapture\"}}"
        );
    }
}
