fn direct_probe_ack_grace(probe_interval: Duration) -> Duration {
    probe_interval
        .saturating_mul(2)
        .clamp(Duration::from_secs(1), Duration::from_secs(2))
}

/// Return a bounded, de-duplicated immediate candidate window.
///
/// Candidate ordering is already produced by the peer candidate selector: the
/// first entries carry the strongest authenticated/learned evidence. The fast
/// window intentionally does not reorder or expand that set. A later
/// synchronized/scatter stage still owns the complete candidate coverage.
fn direct_fast_probe_candidates(candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    direct_fast_probe_candidates_with_preferred(candidates, &[])
}

/// Build the bounded fast window, preferring an immutable fresh-prediction
/// snapshot when one is available.
///
/// The ordinary candidate selector deliberately keeps trusted, non-predicted
/// candidates first for the broad sweep. That ordering is correct for the
/// fallback plan, but it can hide the exact port window just advertised by a
/// fresh mapping signal from the first latency-sensitive probes. Prefer only
/// the already-accepted prediction snapshot here; all remaining candidates
/// retain their normal order and the synchronized sweep still covers the full
/// set.
fn direct_fast_probe_candidates_with_preferred(
    candidates: &[SocketAddr],
    preferred: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut selected = Vec::with_capacity(DIRECT_FAST_PROBE_MAX_CANDIDATES);
    for candidate in preferred.iter().chain(candidates) {
        if selected.contains(candidate) {
            continue;
        }
        selected.push(*candidate);
        if selected.len() == DIRECT_FAST_PROBE_MAX_CANDIDATES {
            break;
        }
    }
    selected
}

fn direct_fast_probe_is_safe(remote_scatter_pool: bool, stable_remote_scatter: bool) -> bool {
    !remote_scatter_pool && !stable_remote_scatter
}

/// A fresh prediction is an explicitly signaled, generation-bound rendezvous
/// window. It is safe to probe a small prefix immediately even when the broad
/// target set is classified as remote scatter; an unqualified scatter target
/// still requires the synchronized window below.
fn direct_fast_probe_is_allowed(
    remote_scatter_pool: bool,
    stable_remote_scatter: bool,
    has_fresh_prediction_window: bool,
) -> bool {
    direct_fast_probe_is_safe(remote_scatter_pool, stable_remote_scatter)
        || has_fresh_prediction_window
}

/// Hard deadline for one owned punch session.
///
/// Remote-scatter sweeps cover hundreds of ports across every bound socket and
/// need the schedule-derived deadline (bounded at 10s); every other session keeps
/// the fixed 24s bound.
fn punch_session_deadline(
    candidates: &[SocketAddr],
    probe_interval: Duration,
    attempts: u32,
    remote_scatter_pool: bool,
    socket_count: usize,
) -> Duration {
    if remote_scatter_pool {
        estimate_remote_scatter_punch_deadline(
            candidates,
            probe_interval,
            attempts,
            socket_count,
            direct_probe_ack_grace(probe_interval),
        )
    } else {
        PUNCH_SESSION_HARD_DEADLINE
    }
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn relay_assisted_punch_at_ms() -> u64 {
    unix_time_millis().saturating_add(RELAY_ASSISTED_PUNCH_DELAY.as_millis() as u64)
}

fn new_probe_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn new_probe_ephemeral_keypair() -> (DhKeyPair, String) {
    let keypair = DhKeyPair::generate();
    let public_key_hex = hex::encode(keypair.public_key());
    (keypair, public_key_hex)
}

fn derive_probe_ephemeral_shared(
    local_keypair: &DhKeyPair,
    peer_public_key_hex: &str,
) -> Result<[u8; 32]> {
    let peer_public = decode_x25519_key(peer_public_key_hex, "probe ephemeral public key")?;
    local_keypair
        .diffie_hellman(&peer_public)
        .map_err(|e| DaemonError::Peer(format!("probe ephemeral X25519 failed: {e}")))
}

fn relay_assisted_punch_delay(punch_at_ms: Option<u64>) -> Duration {
    let Some(punch_at_ms) = punch_at_ms else {
        return Duration::ZERO;
    };
    let now = unix_time_millis();
    if punch_at_ms > now {
        return Duration::from_millis(punch_at_ms - now).saturating_sub(RELAY_ASSISTED_PUNCH_LEAD);
    }
    let stale_by = Duration::from_millis(now - punch_at_ms);
    if stale_by > RELAY_ASSISTED_PUNCH_STALE_AFTER {
        debug!(
            "Relay-assisted punch window is stale by {}ms; punching immediately",
            stale_by.as_millis()
        );
    }
    Duration::ZERO
}

async fn log_inbound_packets_without_tun(mut inbound_rx: mpsc::Receiver<InboundPacket>) {
    while let Some(packet) = inbound_rx.recv().await {
        debug!(
            "Dropping {} decrypted inbound bytes from peer {} because TUN is disabled",
            packet.packet.len(),
            packet.peer_id
        );
    }
}

fn decode_x25519_key(hex_value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_value.trim())
        .map_err(|e| DaemonError::Config(format!("invalid {label} hex: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        DaemonError::Config(format!(
            "invalid {label} length: expected 32 bytes, got {} bytes",
            bytes.len()
        ))
    })
}
