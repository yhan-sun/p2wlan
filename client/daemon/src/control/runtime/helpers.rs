fn has_control_credential(config: &Config) -> bool {
    !config.control.auth_token.trim().is_empty()
        || !config.control.device_credential.trim().is_empty()
}

/// Maximum exponential-backoff delay before giving up.
const MAX_BACKOFF_SECS: u64 = 300;
const INITIAL_BACKOFF_SECS: u64 = 2;
/// Signaling carries WireGuard handshake offers/answers. Keep the REST
/// reconcile cadence short even when WebSocket signaling is connected: the
/// WebSocket is an acceleration hint, not the delivery path.  Legacy staging
/// servers can complete the WebSocket handshake but fail to emit a wake-up
/// after POST /signals; disabling REST fallback in that case strands the only
/// WireGuard initiation until the next registration.
const SIGNAL_LONG_POLL_WAIT_MS: u64 = 900;
const SIGNAL_FALLBACK_TICK: Duration = Duration::from_millis(250);
const SIGNAL_WS_WAKE_QUEUE: usize = 32;
/// Peer roster changes are a dataplane trigger, not a lease heartbeat. Keep
/// the roster poll bounded independently of the operator-selected heartbeat
/// interval so a daemon restart cannot hide a newly online peer for five or
/// more seconds before relay-first session setup starts.
const PEER_ROSTER_POLL_INTERVAL_SECS: u64 = 1;

/// Compute exponential backoff with jitter, capped at MAX_BACKOFF_SECS.
/// attempt 0 → ~2s, attempt 1 → ~4s, attempt 2 → ~8s, …
fn backoff_delay(attempt: u32) -> Duration {
    let exp = attempt.min(8);
    let base = INITIAL_BACKOFF_SECS
        .saturating_mul(1u64 << exp)
        .min(MAX_BACKOFF_SECS);
    let jitter = rand::thread_rng().gen_range(0.0..=0.5) * base as f64;
    Duration::from_secs_f64(base as f64 + jitter)
}

/// WebSocket notifications only reduce the time to start a poll.  They never
/// disable the REST reconcile loop because a partially deployed/legacy
/// control plane may accept the WebSocket connection without publishing a
/// notification for every durable signal.
fn signal_poll_wait_ms(websocket_connected: bool) -> u64 {
    if websocket_connected {
        0
    } else {
        SIGNAL_LONG_POLL_WAIT_MS
    }
}

#[cfg(test)]
mod signal_schedule_tests {
    use super::*;

    #[test]
    fn websocket_connection_keeps_rest_signal_reconcile_enabled() {
        assert_eq!(signal_poll_wait_ms(true), 0);
        assert_eq!(signal_poll_wait_ms(false), SIGNAL_LONG_POLL_WAIT_MS);
    }

    #[test]
    fn signal_reconcile_cadence_is_below_one_second() {
        assert!(SIGNAL_FALLBACK_TICK < Duration::from_secs(1));
    }
}

fn is_permanent_auth_error(err: &str) -> bool {
    // Explicit HTTP 401/403 from our error messages.
    err.contains("HTTP 401")
        || err.contains("HTTP 403")
        || err.contains("register request returned HTTP 401")
        || err.contains("register request returned HTTP 403")
        || err.contains("list nodes request returned HTTP 401")
        || err.contains("list nodes request returned HTTP 403")
        || err.contains("list signals returned HTTP 401")
        || err.contains("list signals returned HTTP 403")
        || err.contains("permanent auth")
}

async fn current_relay_rtt_ms(
    relay_selection: Option<&Arc<RwLock<RelaySelectionDiagnostics>>>,
) -> Option<u64> {
    let relay_selection = relay_selection?;
    let diagnostics = relay_selection.read().await;
    diagnostics
        .selected_rtt_ewma_ms
        .or(diagnostics.selected_last_pong_rtt_ms)
        .or(diagnostics.selected_connect_latency_ms)
}
