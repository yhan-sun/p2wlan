fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn update_latency_ewma(ewma_ms: &mut Option<u64>, jitter_ms: &mut Option<u64>, sample_ms: u64) {
    match *ewma_ms {
        Some(previous) => {
            let delta = sample_ms.abs_diff(previous);
            let next_ewma = ((previous as u128 * 7) + sample_ms as u128).div_ceil(8) as u64;
            let next_jitter = match *jitter_ms {
                Some(previous_jitter) => {
                    ((previous_jitter as u128 * 3) + delta as u128).div_ceil(4) as u64
                }
                None => delta,
            };
            *ewma_ms = Some(next_ewma);
            *jitter_ms = Some(next_jitter);
        }
        None => {
            *ewma_ms = Some(sample_ms);
            *jitter_ms = Some(0);
        }
    }
}

fn record_relay_pong(
    diagnostics: &mut RelaySelectionDiagnostics,
    received_at_ms: u64,
    round_trip_time: Duration,
) {
    let rtt_ms = duration_millis(round_trip_time);
    diagnostics.selected_last_pong_at_unix_ms = Some(received_at_ms);
    diagnostics.selected_last_pong_age_ms = Some(0);
    diagnostics.selected_last_pong_rtt_ms = Some(rtt_ms);
    diagnostics.selected_pong_count = diagnostics.selected_pong_count.saturating_add(1);
    update_latency_ewma(
        &mut diagnostics.selected_rtt_ewma_ms,
        &mut diagnostics.selected_jitter_ms,
        rtt_ms,
    );
}

fn relay_error_code_name(code: u16) -> String {
    p2pnet_relay::RelayErrorCode::from_u16(code)
        .map(|ec| ec.to_snake_case().to_string())
        .unwrap_or_else(|| format!("error_{code}"))
}

fn relay_error_peer_id(message: &str) -> Option<&str> {
    message
        .strip_prefix("peer not found: ")
        .or_else(|| message.strip_prefix("peer disconnected: "))
        .or_else(|| message.strip_prefix("peer backpressure: "))
        .map(str::trim)
        .filter(|peer_id| !peer_id.is_empty())
}

/// Machine-readable label for a classified relay close reason, surfaced in
/// the relay selection diagnostics and the supervisor's reconnect warning so
/// the production "relay connection closed; reconnecting" line can be
/// attributed (server EOF, TCP reset, idle timeout, server close frame,
/// local write failure, ticket-expiry close arrives as a server EOF).
fn relay_close_reason_label(reason: p2pnet_relay::RelayCloseReason) -> &'static str {
    match reason {
        p2pnet_relay::RelayCloseReason::ServerCloseFrame => "server_close_frame",
        p2pnet_relay::RelayCloseReason::ServerEof => "server_eof",
        p2pnet_relay::RelayCloseReason::TcpReset => "tcp_reset",
        p2pnet_relay::RelayCloseReason::IdleTimeout => "idle_timeout",
        p2pnet_relay::RelayCloseReason::LocalWriteFailed => "local_write_failed",
        p2pnet_relay::RelayCloseReason::LocalShutdown => "local_shutdown",
        p2pnet_relay::RelayCloseReason::IoError => "io_error",
        p2pnet_relay::RelayCloseReason::Unknown => "unknown",
    }
}
