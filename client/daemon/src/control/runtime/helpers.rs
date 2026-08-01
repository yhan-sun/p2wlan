fn has_control_credential(config: &Config) -> bool {
    !config.control.auth_token.trim().is_empty()
        || !config.control.device_credential.trim().is_empty()
}

/// Maximum exponential-backoff delay before giving up.
const MAX_BACKOFF_SECS: u64 = 300;
const INITIAL_BACKOFF_SECS: u64 = 2;
/// Signaling carries WireGuard handshake offers/answers. Keep it close to
/// continuous long-polling so early responses do not wait almost a full second
/// for the next tick before scheduling the synchronized UDP punch window.
const SIGNAL_LONG_POLL_WAIT_MS: u64 = 900;
const SIGNAL_FALLBACK_TICK: Duration = Duration::from_secs(1);
const SIGNAL_WS_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const SIGNAL_WS_WAKE_QUEUE: usize = 32;
const MIN_PEER_POLL_INTERVAL_SECS: u64 = 5;

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
