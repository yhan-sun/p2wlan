// ============================================================
// Stale-peer quarantine: authoritative isolation of relay 404 peers
// ============================================================
//
// A relay `peer_not_found` (404) is evidence that the destination is not
// currently registered on this relay.  Registration handoff/reconnects can
// leave a short 404 window while the control plane still reports the same
// incarnation online, so relay errors are first held in a bounded grace state
// (see `RelayNotFoundGraceState`) before the destructive quarantine below.
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
// Repeated confirmed 404s apply an exponential quarantine backoff (base 60s,
// cap 30min) with event deduplication, so the peer cannot keep logging a
// warning or a scan every second.

/// Confirmation window for a relay registration handoff/reconnect.
///
/// This is deliberately much shorter than the quarantine itself, but longer
/// than the synchronized first-punch window: an online peer gets a relay
/// reconnect/renewal attempt without losing that current Direct recovery
/// session, while a genuinely offline peer is isolated as soon as the control
/// plane says it is offline (or once this window expires).
pub(crate) const RELAY_PEER_NOT_FOUND_GRACE: Duration = Duration::from_secs(15);

/// Identity/evidence snapshot captured at the first transient relay 404.
///
/// Only the public key is kept as evidence: `last_seen` growth and NAT
/// endpoint churn belong to the SAME stale incarnation and must not restart
/// the registration-grace window (v0.1.116 authority boundary).
#[derive(Debug, Clone)]
pub(crate) struct RelayNotFoundGraceState {
    pub started_at: Instant,
    pub public_key: String,
    /// Keep the grace event itself one-per-window.  Relay diagnostics perform
    /// an additional error-level deduplication, but peer timeline events must
    /// also stay bounded when the relay sends repeated 404 frames.
    pub event_recorded: bool,
}



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
    /// Drop a pending relay registration grace window after fresh control-plane
    /// evidence or peer removal.  This never touches quarantine state.
    pub(crate) async fn clear_relay_not_found_grace(&self, peer_id: &str) {
        self.relay_not_found_grace.lock().await.remove(peer_id);
    }

    #[cfg(test)]
    pub(crate) async fn test_force_relay_not_found_grace_elapsed(&self, peer_id: &str) {
        if let Some(state) = self.relay_not_found_grace.lock().await.get_mut(peer_id) {
            state.started_at = Instant::now() - RELAY_PEER_NOT_FOUND_GRACE;
        }
    }

    /// Quarantine a peer after authoritative relay `peer_not_found` evidence.
    ///
    /// Idempotent within one quarantine episode: repeated 404s for the same
    /// active quarantine only refresh the expiry (bounded by the cap) and
    /// are deduplicated in the event stream.  The peer's recovery epoch,
    /// pending targets and fresh-mapping state are cancelled; the network
    /// generation is never touched; the active punch session (if any) is
    /// cancelled through the registered hook.
    pub(crate) async fn quarantine_peer(&self, peer_id: &str, reason: &str) {
        // A confirmed quarantine supersedes any transient registration grace;
        // keeping the old grace would let a later stale relay error mutate the
        // new incarnation's state.
        self.clear_relay_not_found_grace(peer_id).await;
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
        // Drop the forced-relay expectation together with the quarantined
        // recovery state.  This makes quarantine a terminal boundary for the
        // old relay registration: a late ACK has no token to consume, and a
        // future incarnation must register a fresh expectation.
        self.relay_probe_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(peer_id);
        if let Some(hook) = self
            .punch_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            hook(peer_id);
        }
        self.cancel_relay_backoff_heartbeat(peer_id);

        // A sustained relay peer_not_found (the 404 quarantine path) revokes
        // the peer's RelayPeerConfirmed: the peer is not registered on the
        // relay, so a future relay path needs a fresh forced-probe
        // confirmation.  Direct stays authoritative.
        let relay_confirm_revoked = {
            let mut conns = self.connections.write().await;
            match conns.get_mut(peer_id) {
                Some(conn) if conn.relay_confirmed_at.is_some() => {
                    conn.relay_confirmed_at = None;
                    conn.relay_confirmed_generation = None;
                    conn.relay_confirmed_endpoint = None;
                    conn.relay_confirmed_connection_id = None;
                    conn.relay_first_gate_generation = None;
                    conn.relay_first_gate_started_at = None;
                    conn.relay_first_business_sent_generation = None;
                    conn.relay_ready_generation = None;
                    conn.relay_ready_at = None;
                    conn.relay_ready_endpoint = None;
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    if conn.state == ConnectionState::Relay {
                        conn.transition(ConnectionState::FallbackToRelay);
                    }
                    true
                }
                _ => false,
            }
        };
        if relay_confirm_revoked {
            self.bump_relay_confirm_seq(peer_id);
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
    ///
    /// This is a production dataplane predicate, not just a test helper:
    /// relay probe/validation scheduling and ACK admission must use the same
    /// authoritative quarantine state as the recovery scheduler.  In
    /// particular, a peer that has been isolated after a sustained relay 404
    /// must not keep receiving probe attempts or be re-confirmed by a late
    /// ACK from the old registration.
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

    /// Register the transport hook that revokes one relay-backoff heartbeat
    /// owner. The hook must be nonblocking: callers may invoke it immediately
    /// after releasing a peer-manager lock, and the transport only signals a
    /// cancellation channel plus removes its owner lease.
    pub(crate) fn set_relay_backoff_heartbeat_cancel_hook(
        &self,
        hook: Arc<dyn Fn(&str) + Send + Sync>,
    ) {
        *self
            .relay_backoff_heartbeat_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Revoke the current heartbeat owner for a peer, if a transport has
    /// registered one. Owner cleanup is conditional in the transport, so an
    /// old worker that is still unwinding cannot remove a replacement owner.
    pub(crate) fn cancel_relay_backoff_heartbeat(&self, peer_id: &str) {
        if let Some(hook) = self
            .relay_backoff_heartbeat_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        {
            hook(peer_id);
        }
    }
}

/// Internal helper type alias to keep the struct field declaration compact.
pub(crate) type PunchCancelHook =
    Arc<dyn Fn(&str) + Send + Sync>;
pub(crate) type PunchCancelHookSlot =
    Arc<std::sync::Mutex<Option<PunchCancelHook>>>;
