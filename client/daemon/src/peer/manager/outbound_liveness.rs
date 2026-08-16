// ============================================================
// Outbound-UDP liveness decision state
// ============================================================
//
// Cache for the (peer, generation) -> verdict liveness diagnostic.  Written by
// the spawned probe task, consumed at the next tick's admission.  The 3-state
// decision methods (evaluate / probe-due / probe / commit) live below.

/// One cached outbound-UDP liveness verdict for a `(peer, generation)` pair.
/// Written by the spawned probe task; the `verdict`/`consumed`/`probed_at`
/// fields are read by `apply_cached_liveness_block` and the read-only
/// evaluation paths at the next admission tick.  `per_target`/`total_elapsed_ms`
/// are stored for per-target observability but are write-only in the current
/// build (no reader reads them back from the cache yet), hence the targeted
/// `#[allow(dead_code)]` below.
#[derive(Debug)]
struct LivenessCacheEntry {
    /// The 3-state verdict (Ok / Blocked / Unknown).
    verdict: p2pnet_nat::outbound_liveness::LivenessVerdict,
    /// Per-target detail (ip:port, responded, elapsed) for observability.
    /// Written-only for now: kept in the cache but not yet read back.
    #[allow(dead_code)]
    per_target: Vec<p2pnet_nat::outbound_liveness::LivenessTargetResult>,
    /// Total wall time of the probe in milliseconds.  Written-only for now:
    /// kept in the cache but not yet read back.
    #[allow(dead_code)]
    total_elapsed_ms: u64,
    /// When this verdict was produced; TTL-bounded before re-probing.
    probed_at: Instant,
    /// Whether a `Blocked` verdict has already been consumed (applied) by a
    /// subsequent admission tick — applied exactly once.
    consumed: bool,
}

impl PeerManager {
    /// Read the current cached outbound-UDP liveness verdict for
    /// `(peer_id, generation)` if it is fresh (within TTL).  Returns
    /// `None` on a cache miss or TTL expiry.  Used by the pre-flight gate
    /// (`pre_flight_liveness_blocked`) — read-only, never spawns, never
    /// writes.
    pub(crate) async fn evaluate_outbound_liveness(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> Option<p2pnet_nat::outbound_liveness::LivenessVerdict> {
        let cfg = &self.config.network;
        if !cfg.udp_liveness_enabled {
            return None;
        }
        let key = (peer_id.to_string(), generation);
        let cache = self.outbound_liveness_cache.read().await;
        let entry = cache.get(&key)?;
        let ttl = Duration::from_millis(cfg.udp_liveness_ttl_ms as u64);
        if entry.probed_at.elapsed() < ttl {
            Some(entry.verdict) // fresh: cache hit
        } else {
            None // expired: treat as no verdict
        }
    }

    /// Whether a liveness probe should be SPAWNED for `(peer, generation)`
    /// right now: feature enabled AND no fresh (within-TTL) cached verdict.
    /// Side-effect-free.  The caller (the probe_loop 0-ACK trigger) does
    /// the spawn.
    pub(crate) async fn liveness_probe_due(&self, peer_id: &str, generation: u64) -> bool {
        let cfg = &self.config.network;
        if !cfg.udp_liveness_enabled {
            return false;
        }
        let key = (peer_id.to_string(), generation);
        let cache = self.outbound_liveness_cache.read().await;
        match cache.get(&key) {
            Some(entry) => {
                let ttl = Duration::from_millis(cfg.udp_liveness_ttl_ms as u64);
                entry.probed_at.elapsed() >= ttl // expired → re-probe
            }
            None => true, // no entry → probe
        }
    }

    /// The spawned probe task (P1).  Holds NO peers write lock across the
    /// socket I/O: the `probe()` call (socket I/O) runs with no lock held;
    /// only `commit_liveness` afterwards takes short scoped locks.  Spawned
    /// (not awaited) by the probe_loop ScatterExtended 0-ACK trigger.
    pub(crate) async fn run_outbound_liveness_probe(&self, peer_id: &str, generation: u64) {
        // Stale-generation guard: a generation advance makes the probe moot.
        if self.current_network_generation().await != generation {
            return;
        }
        let cfg = &self.config.network;
        let targets: Vec<SocketAddr> = cfg
            .udp_liveness_targets
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        if targets.is_empty() {
            return;
        }
        let timeout = Duration::from_millis(cfg.udp_liveness_timeout_ms as u64);
        let probe_cfg = p2pnet_nat::outbound_liveness::LivenessConfig {
            targets: targets.clone(),
            timeout,
            retries: cfg.udp_liveness_retries,
        };
        // Per (round, target): bind a FRESH socket so `recv_from` is isolated to
        // that target — a shared socket would let target A's answer be consumed
        // by target B's recv, corrupting the per-target attribution (the verdict
        // itself is unaffected, but the detail table would mislead operators).
        // A bind failure is a SocketError for that target.  Each call builds
        // owned data inside the async block so the returned future is 'static.
        let outcome = p2pnet_nat::outbound_liveness::probe(&probe_cfg, |_round, target| {
            let data = p2pnet_nat::outbound_liveness::build_dns_a_query(0xdead, "a"); // owned per call
            async move {
                let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
                    return p2pnet_nat::outbound_liveness::TargetProbeResult::SocketError;
                };
                let send_start = std::time::Instant::now();
                if socket.send_to(&data, target).await.is_err() {
                    return p2pnet_nat::outbound_liveness::TargetProbeResult::SocketError;
                }
                let mut recv_buf = [0u8; 512];
                match tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf)).await {
                    Ok(Ok(_)) => p2pnet_nat::outbound_liveness::TargetProbeResult::Responded {
                        elapsed: send_start.elapsed(),
                    },
                    Ok(Err(_)) => {
                        // A recv_from I/O error is a system fault (Unknown),
                        // not silence: only a clean timeout certifies a
                        // target as unresponsive (Blocked contributor).
                        p2pnet_nat::outbound_liveness::TargetProbeResult::SocketError
                    }
                    Err(_elapsed) => p2pnet_nat::outbound_liveness::TargetProbeResult::NoResponse,
                }
                // socket dropped here → isolation restored
            }
        })
        .await;
        self.commit_liveness(
            peer_id,
            generation,
            outcome.verdict,
            outcome.per_target,
            outcome.total_elapsed_ms,
        )
        .await;
    }

    /// Write cache + `PathHealth.last_liveness` + record a diagnostic event.
    /// Does NOT touch the recovery stage — that is consumed at the next
    /// admission tick (P1/P3), keeping the probe task free of the
    /// recovery-epoch write lock.  Called by the probe task
    /// (`run_outbound_liveness_probe`).
    pub(crate) async fn commit_liveness(
        &self,
        peer_id: &str,
        generation: u64,
        verdict: p2pnet_nat::outbound_liveness::LivenessVerdict,
        per_target: Vec<p2pnet_nat::outbound_liveness::LivenessTargetResult>,
        total_elapsed_ms: u64,
    ) {
        let key = (peer_id.to_string(), generation);
        {
            let mut cache = self.outbound_liveness_cache.write().await;
            cache.insert(
                key,
                LivenessCacheEntry {
                    verdict,
                    per_target: per_target.clone(),
                    total_elapsed_ms,
                    probed_at: Instant::now(),
                    consumed: false,
                },
            );
        }
        {
            let mut conns = self.connections.write().await;
            if let Some(conn) = conns.get_mut(peer_id) {
                conn.direct_health.last_liveness = Some(verdict);
            }
        }
        let detail = format_liveness_detail(&per_target, verdict, total_elapsed_ms);
        self.record_direct_event(
            peer_id,
            "outbound_liveness",
            None,
            None,
            None,
            detail.clone(),
        )
        .await;
        info!(
            event = "outbound_liveness",
            peer_id = %peer_id,
            generation,
            verdict = verdict_str(verdict),
            total_elapsed_ms,
            detail = %detail,
            "outbound UDP liveness verdict recorded"
        );
    }

    /// Consume a fresh `Blocked` liveness verdict for `peer_id` at the next
    /// admission tick.  Applied EXACTLY ONCE per `(peer, generation)` (the
    /// `consumed` flag): stamps the `firewall_blocked` attribution on the
    /// direct-path health and moves the recovery stage into the bounded
    /// `RelayBackoff` regime — which is what stops the wide scatter for the
    /// epoch (P1: the probe task itself never did this; it only wrote the
    /// cache, so the probe stays off the recovery-epoch write lock).
    ///
    /// `Ok`/`Unknown` verdicts are recorded (Task 6) but never applied here:
    /// only `Blocked` may accelerate the path (conservative invariant).
    ///
    /// Called from `recovery_epoch_admit` BEFORE that function takes the
    /// `recovery_epochs` write lock — `mark_recovery_relay_backoff` below
    /// re-takes that lock, so nesting the call after the lock would deadlock
    /// (tokio RwLock is not reentrant).
    pub(crate) async fn apply_cached_liveness_block(&self, peer_id: &str) {
        // Only act once the recovery epoch already exists.  In production the
        // probe fires at ScatterExtended (epoch long-established), so this is a
        // no-op guard; it prevents the very first admit from consuming the
        // verdict before any stage exists to move (or_insert happens after
        // this call in recovery_epoch_admit).  Read-only, dropped before the
        // cache write below — no lock held across mark_recovery_relay_backoff.
        if !self.recovery_epochs.read().await.contains_key(peer_id) {
            return;
        }
        let generation = self.current_network_generation().await;
        let key = (peer_id.to_string(), generation);
        let should_apply = {
            let mut cache = self.outbound_liveness_cache.write().await;
            match cache.get_mut(&key) {
                Some(e)
                    if e.verdict == p2pnet_nat::outbound_liveness::LivenessVerdict::Blocked
                        && !e.consumed
                        && e.probed_at.elapsed()
                            < Duration::from_millis(
                                self.config.network.udp_liveness_ttl_ms as u64,
                            ) =>
                {
                    e.consumed = true;
                    true
                }
                _ => false,
            }
        };
        if !should_apply {
            return;
        }
        let detail =
            "outbound UDP liveness Blocked; stopping wide scatter, accelerating to relay fallback"
                .to_string();
        {
            let mut conns = self.connections.write().await;
            if let Some(conn) = conns.get_mut(peer_id) {
                conn.direct_health
                    .record_failure(REASON_DIRECT_FIREWALL_BLOCKED, detail.clone());
            }
        }
        self.mark_recovery_relay_backoff(peer_id, "outbound_liveness_blocked")
            .await;
        self.record_direct_event(
            peer_id,
            "outbound_liveness_applied",
            None,
            None,
            None,
            detail,
        )
        .await;
    }

    /// Pre-flight gate (default OFF).  Returns true ONLY when
    /// `udp_liveness_pre_flight` is enabled AND a FRESH (within-TTL) `Blocked`
    /// liveness verdict already exists for `(peer, gen)` — meaning the punch
    /// should be skipped because relay carries the data plane.
    ///
    /// READ-ONLY: never spawns a probe (the sole spawn path is the 0-ACK
    /// trigger, Task 8) and never takes the recovery_epochs lock.  On a cache
    /// miss or an expired verdict it returns false (proceed with the punch).
    /// The TTL is what lets a transient "blocked" self-heal instead of
    /// permanently stopping punching.
    pub(crate) async fn pre_flight_liveness_blocked(&self, peer_id: &str, generation: u64) -> bool {
        if !self.config.network.udp_liveness_pre_flight {
            return false; // default OFF
        }
        self.evaluate_outbound_liveness(peer_id, generation).await
            == Some(p2pnet_nat::outbound_liveness::LivenessVerdict::Blocked)
    }

    /// Test-only: seed a cached liveness verdict for `(peer, generation)` with
    /// a back-dated `probed_at` (age_ms).  Lets the TTL / generation tests
    /// drive the cache without opening real sockets.
    #[cfg(test)]
    pub(crate) async fn test_seed_liveness(
        &self,
        peer_id: &str,
        generation: u64,
        verdict: p2pnet_nat::outbound_liveness::LivenessVerdict,
        age_ms: u64,
    ) {
        let key = (peer_id.to_string(), generation);
        let mut cache = self.outbound_liveness_cache.write().await;
        let probed_at = Instant::now()
            .checked_sub(Duration::from_millis(age_ms))
            .unwrap_or_else(Instant::now);
        cache.insert(
            key,
            LivenessCacheEntry {
                verdict,
                per_target: Vec::new(),
                total_elapsed_ms: 0,
                probed_at,
                consumed: false,
            },
        );
    }

    /// Test-only: read the current direct-path failure reason code, if any.
    /// Consumed by the part15 integration tests.
    #[cfg(test)]
    pub(crate) async fn direct_health_error_code(&self, peer_id: &str) -> Option<String> {
        let conns = self.connections.read().await;
        conns
            .get(peer_id)
            .and_then(|c| c.direct_health.last_error_code.clone())
    }

    /// Test-only: count `outbound_liveness_applied` diagnostic events for a
    /// peer, so the exactly-once guarantee is directly observable.
    #[cfg(test)]
    pub(crate) async fn direct_liveness_event_count(&self, peer_id: &str) -> usize {
        let conns = self.connections.read().await;
        conns
            .get(peer_id)
            .map(|c| {
                c.direct_events
                    .iter()
                    .filter(|e| e.stage == "outbound_liveness_applied")
                    .count()
            })
            .unwrap_or(0)
    }
}

/// Render the per-target liveness detail string for observability:
/// `ip:port responded=<bool> ms=<opt>` per target + total + verdict.
/// Used by `commit_liveness` for the diagnostic event + log line.
fn format_liveness_detail(
    per_target: &[p2pnet_nat::outbound_liveness::LivenessTargetResult],
    verdict: p2pnet_nat::outbound_liveness::LivenessVerdict,
    total_elapsed_ms: u64,
) -> String {
    let per = per_target
        .iter()
        .map(|t| {
            format!(
                "{} responded={} ms={}",
                t.target,
                t.responded,
                t.elapsed_ms
                    .map_or_else(|| "-".to_string(), |m| m.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "verdict={} total_ms={} targets=[{}]",
        verdict_str(verdict),
        total_elapsed_ms,
        per
    )
}

fn verdict_str(v: p2pnet_nat::outbound_liveness::LivenessVerdict) -> &'static str {
    match v {
        p2pnet_nat::outbound_liveness::LivenessVerdict::Ok => "ok",
        p2pnet_nat::outbound_liveness::LivenessVerdict::Blocked => "blocked",
        p2pnet_nat::outbound_liveness::LivenessVerdict::Unknown => "unknown",
    }
}
