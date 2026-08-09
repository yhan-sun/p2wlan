// ============================================================
// Stale-peer quarantine: authoritative isolation of relay 404 peers
// ============================================================
//
// A relay `peer_not_found` (404) is authoritative evidence that the
// destination is not registered on the relay — it is gone, restarted, or
// left the network.  Continuing to scan such a peer on every retry tick
// wastes shared NAT, CPU, log and scheduler capacity and starves the other
// peers' recovery.
//
// A quarantined peer:
//   - cannot start fresh-mapping generations, candidate plans, sessions or
//     HTTP publishes;
//   - cannot push the network generation (quarantine never advances it);
//   - has its recovery epoch, pending targets and fresh-mapping state
//     cancelled;
//   - is only re-opened by authoritative control-plane evidence: a new
//     `add_peer` with online/endpoint/incarnation/offer changes
//     (`unquarantine_peer`), never by retry churn.
//
// Repeated 404s apply an exponential quarantine backoff (base 60s, cap
// 30min) with event deduplication, so the peer cannot keep logging a
// warning or a scan every second.



/// Base quarantine duration for a stale/404 peer.
pub(crate) const STALE_PEER_QUARANTINE_BASE: Duration = Duration::from_secs(60);
/// Long-term cap for the quarantine backoff.
pub(crate) const STALE_PEER_QUARANTINE_MAX: Duration = Duration::from_secs(30 * 60);

/// Per-peer quarantine state.
#[derive(Debug, Clone)]
pub(crate) struct PeerQuarantineState {
    /// When the current quarantine expires (`None` when not quarantined).
    pub until: Option<Instant>,
    /// Consecutive quarantine episodes, driving the exponential backoff.
    pub consecutive: u32,
    /// Last time a `peer_not_found` was recorded (for deduplication).
    pub last_peer_not_found_at: Option<Instant>,
    /// Reason of the current quarantine episode.
    pub reason: Option<String>,
}

impl PeerQuarantineState {
    fn new() -> Self {
        Self {
            until: None,
            consecutive: 0,
            last_peer_not_found_at: None,
            reason: None,
        }
    }
}

impl PeerManager {
    /// Quarantine a peer after authoritative relay `peer_not_found` evidence.
    ///
    /// Idempotent within one quarantine episode: repeated 404s for the same
    /// active quarantine only refresh the expiry (bounded by the cap) and
    /// are deduplicated in the event stream.  The peer's recovery epoch,
    /// pending targets and fresh-mapping state are cancelled; the network
    /// generation is never touched; the active punch session (if any) is
    /// cancelled through the registered hook.
    pub(crate) async fn quarantine_peer(&self, peer_id: &str, reason: &str) {
        let now = Instant::now();
        let mut fresh = false;
        let backoff;
        {
            let mut quarantined = self.quarantined_peers.lock().await;
            let state = quarantined
                .entry(peer_id.to_string())
                .or_insert_with(PeerQuarantineState::new);
            let already_quarantined = state.until.is_some_and(|until| now < until);
            if !already_quarantined {
                state.consecutive = state.consecutive.saturating_add(1);
                fresh = true;
            }
            let exponent = state.consecutive.saturating_sub(1).min(5);
            backoff = STALE_PEER_QUARANTINE_BASE
                .checked_mul(1_u32 << exponent)
                .unwrap_or(STALE_PEER_QUARANTINE_MAX)
                .min(STALE_PEER_QUARANTINE_MAX);
            state.until = Some(now + backoff);
            state.last_peer_not_found_at = Some(now);
            state.reason = Some(reason.to_string());
        }

        // Cancel the recovery plan and the fresh-mapping state; the network
        // generation is deliberately untouched.
        self.recovery_epoch_end(peer_id, "stale_peer_quarantined").await;
        self.clear_fresh_mapping(peer_id, "stale_peer_quarantined").await;
        if let Some(hook) = self
            .punch_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            hook(peer_id);
        }

        if fresh {
            let consecutive = self.quarantine_consecutive(peer_id).await;
            info!(
                event = "stale_peer_quarantined",
                peer_id = %peer_id,
                backoff_ms = backoff.as_millis(),
                consecutive = consecutive,
                reason = %reason,
                "stale_peer_quarantined peer_id={} backoff_ms={} consecutive={} reason={}",
                peer_id,
                backoff.as_millis(),
                consecutive,
                reason,
            );
            self.record_direct_event(
                peer_id,
                "stale_peer_quarantined",
                None,
                None,
                None,
                format!(
                    "peer quarantined after authoritative relay peer_not_found; recovery frozen for {}ms: {reason}",
                    backoff.as_millis()
                ),
            )
            .await;
        } else {
            debug!(
                event = "stale_peer_quarantine_refreshed",
                peer_id = %peer_id,
                backoff_ms = backoff.as_millis(),
                "stale_peer_quarantine_refreshed peer_id={} backoff_ms={}",
                peer_id,
                backoff.as_millis(),
            );
        }
    }

    /// Re-open recovery for a quarantined peer on authoritative control-plane
    /// evidence (new online state, endpoint, incarnation or offer).
    pub(crate) async fn unquarantine_peer(&self, peer_id: &str, reason: &str) {
        let removed = {
            let mut quarantined = self.quarantined_peers.lock().await;
            quarantined.remove(peer_id).is_some()
        };
        if removed {
            info!(
                event = "stale_peer_unquarantined",
                peer_id = %peer_id,
                reason = %reason,
                "stale_peer_unquarantined peer_id={} reason={}",
                peer_id,
                reason,
            );
            self.record_direct_event(
                peer_id,
                "stale_peer_unquarantined",
                None,
                None,
                None,
                format!("peer recovery re-opened by authoritative control-plane evidence: {reason}"),
            )
            .await;
        }
    }

    /// Whether the peer is currently quarantined (async).
    #[cfg(test)]
    pub(crate) async fn peer_quarantined(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        self.quarantined_peers
            .lock()
            .await
            .get(peer_id)
            .is_some_and(|state| state.until.is_some_and(|until| now < until))
    }

    /// Lock-free quarantine check for paths that already hold other locks.
    pub(crate) fn peer_quarantined_sync(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        self.quarantined_peers
            .try_lock()
            .map(|quarantined| {
                quarantined
                    .get(peer_id)
                    .is_some_and(|state| state.until.is_some_and(|until| now < until))
            })
            .unwrap_or(false)
    }

    /// Consecutive quarantine episodes for a peer (0 when none).
    pub(crate) async fn quarantine_consecutive(&self, peer_id: &str) -> u32 {
        self.quarantined_peers
            .lock()
            .await
            .get(peer_id)
            .map(|state| state.consecutive)
            .unwrap_or(0)
    }

    /// Register the hook used to cancel an active punch session when a peer
    /// is quarantined.  The daemon registers its `PunchAttemptDeduplicator`
    /// here once at startup.
    pub(crate) fn set_punch_cancel_hook(
        &self,
        hook: Arc<dyn Fn(&str) + Send + Sync>,
    ) {
        *self
            .punch_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }
}

/// Internal helper type alias to keep the struct field declaration compact.
pub(crate) type PunchCancelHook =
    Arc<dyn Fn(&str) + Send + Sync>;
pub(crate) type PunchCancelHookSlot =
    Arc<std::sync::Mutex<Option<PunchCancelHook>>>;
