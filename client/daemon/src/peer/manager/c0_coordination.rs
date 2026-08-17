// ============================================================
// C=0 coordinated fresh-fresh endpoint pairs — bounded ledger
// ============================================================
//
// Dual-APD NAT (both ends `m=address_or_port_dependent`) has no
// mutually-admitted endpoint pair to knock on: the ordinary wide scatter can
// exhaust its window with zero matches, yet outbound UDP is healthy (liveness
// reports `Ok`).  The C=0 path reuses the existing synchronized rendezvous
// machinery (see `docs/superpowers/plans/2026-08-17-c0-design.md`) to knock
// with the two sides' FRESH sockets at the SAME `punch_at_ms`, and must do so
// under a bounded "attempted (local_fresh, remote_fresh) pair" budget so it
// can never turn into an unbounded scatter (the paper's explicit anti-pattern,
// which wastes the shared CGNAT NAT budget).
//
// This module owns the per-(peer, generation) ledger and the admission
// decisions.  It reuses, and never rebuilds:
//   - `claim_for_epoch_with_rendezvous` dedup (multi-epoch retry is made legal
//     by advancing the recovery epoch / `punch_at_ms`),
//   - the existing encrypted-validation Direct promotion (hit == matched ACK),
//   - relay-first availability (C=0 never gates the relay).
//
// The single bounded invariant: for a given (peer, generation), no more than
// `MAX_C0_PAIRS_PER_GENERATION` distinct fresh-fresh endpoint pairs are ever
// attempted; exhaustion is attributed as `c0_pairs_exhausted` and the relay
// keeps carrying the data plane.

/// Hard upper bound on distinct fresh-fresh endpoint pairs attempted per
/// (peer, network-generation).  Each pair costs one fresh measurement, one
/// HTTP signal and one ≤3 s synchronized window against the shared CGNAT NAT
/// budget, so the bound is deliberately small — large enough to distinguish
/// a true C=0 from a transient miss, small enough to not hold the NAT budget
/// hostage.
pub(crate) const MAX_C0_PAIRS_PER_GENERATION: usize = 4;

/// One attempted fresh-fresh synchronized endpoint pair for a peer in a
/// network generation.  `outcome` is filled by the caller once the encrypted
/// validation verdict is known (`hit` = Direct promoted / `miss`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct C0PairAttempt {
    /// Incremental index within the ledger (0-based).
    pub(crate) pair_index: u32,
    /// The recovery epoch this fresh-fresh pair was attempted in.
    pub(crate) epoch: u64,
    /// The local side's fresh socket mapped endpoint at try time.
    pub(crate) local_fresh_endpoint: String,
    /// The remote side's fresh predicted endpoint at try time.
    pub(crate) remote_fresh_endpoint: String,
    /// The shared synchronized wall-clock deadline for this pair.
    pub(crate) punch_at_ms: Option<u64>,
    /// hit (encrypted validation on this pair) or miss.
    pub(crate) outcome: C0PairOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum C0PairOutcome {
    /// The fresh-fresh pair produced a matched encrypted validation ACK and
    /// the Direct path was promoted (or is being promoted) — stop all further
    /// C=0 attempts for this (peer, generation).
    Hit,
    /// No encrypted validation on this pair; the budget may continue (unless
    /// exhausted).
    Miss,
}

/// Per-(peer, generation) bounded ledger of C=0 fresh-fresh attempts.
#[derive(Debug, Default, Clone)]
pub(crate) struct C0PairLedger {
    attempted_pairs: Vec<C0PairAttempt>,
    exhausted: bool,
}

impl C0PairLedger {
    /// Create a ledger pre-seeded with `attempts` (all treated as tried) and
    /// finished at the exact budget cap.  Test-only helper so a budget test
    /// does not have to simulate N real punch windows.
    #[cfg(test)]
    pub(crate) fn seeded_exhausted(attempts: Vec<C0PairAttempt>) -> Self {
        let exhausted = attempts.len() >= MAX_C0_PAIRS_PER_GENERATION;
        Self {
            attempted_pairs: attempts,
            exhausted,
        }
    }
}

impl PeerManager {
    /// Whether a fresh-fresh synchronized pair may be attempted for `peer_id`
    /// in `generation` right now.  `false` once the bounded budget is
    /// exhausted for that (peer, generation).  Generation change resets the
    /// ledger because the new egress IP invalidates every old pair (same
    /// reset semantics as the adaptive port-learner and liveness caches).
    pub(crate) async fn c0_pair_admission(&self, peer_id: &str, generation: u64) -> bool {
        let ledgers = self.c0_pair_ledgers.read().await;
        let Some(ledger) = ledgers.get(&(peer_id.to_string(), generation)) else {
            return true; // never tried: budget untouched
        };
        !ledger.exhausted
    }

    /// Record a fresh-fresh pair attempt for `(peer, generation)`.
    /// Exhaustion (`attempts >= MAX_C0_PAIRS_PER_GENERATION`) is attributed as
    /// `c0_pairs_exhausted` and recorded via `record_direct_event` + an
    /// `info!` stdout marker so field tools (which grep stdout) observe it.
    /// `Hit` also marks the ledger exhausted (no further C=0 attempts after a
    /// confirmed Direct) and returns `true` so the caller can stop.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn c0_pair_attempt(
        &self,
        peer_id: &str,
        generation: u64,
        epoch: u64,
        local_fresh_endpoint: &str,
        remote_fresh_endpoint: &str,
        punch_at_ms: Option<u64>,
        outcome: C0PairOutcome,
    ) -> bool {
        let key = (peer_id.to_string(), generation);
        // Already exhausted (or finished by a hit): reject without recording
        // another attempt.  Short-circuit before the ledger write lock.
        if !self.c0_pair_admission(peer_id, generation).await {
            return true;
        }
        let (pair_index, exhausted_now, hit) = {
            let mut ledgers = self.c0_pair_ledgers.write().await;
            let ledger = ledgers.entry(key.clone()).or_default();
            let hit = outcome == C0PairOutcome::Hit;
            ledger.attempted_pairs.push(C0PairAttempt {
                pair_index: ledger.attempted_pairs.len() as u32,
                epoch,
                local_fresh_endpoint: local_fresh_endpoint.to_string(),
                remote_fresh_endpoint: remote_fresh_endpoint.to_string(),
                punch_at_ms,
                outcome,
            });
            let pair_index = ledger.attempted_pairs.len() - 1;
            // A hit finishes the ledger immediately; otherwise exhaustion is
            // reaching the bounded cap.
            let exhausted_now = hit || ledger.attempted_pairs.len() >= MAX_C0_PAIRS_PER_GENERATION;
            if exhausted_now {
                ledger.exhausted = true;
            }
            (pair_index, exhausted_now, hit)
        };
        let c_total = pair_index + 1;
        let detail = format!(
            "fresh-fresh synchronized pair attempted: pair_index={pair_index} local_fresh={local_fresh_endpoint} remote_fresh={remote_fresh_endpoint} punch_at_ms={punch_at_ms:?} epoch={epoch} C={c_total}/{} outcome={}",
            MAX_C0_PAIRS_PER_GENERATION,
            outcome_label(outcome),
        );
        self.record_direct_event(
            peer_id,
            "c0_attempt",
            None,
            None,
            None,
            detail.clone(),
        )
        .await;
        // Exhaustion attribution is only for the bounded-cap case (misses);
        // a hit stops attempts via the ledger but is success, not depletion.
        if exhausted_now && !hit {
            self.record_c0_exhaustion(peer_id, generation, epoch, &key).await;
        }
        exhausted_now
    }

    async fn record_c0_exhaustion(
        &self,
        peer_id: &str,
        generation: u64,
        epoch: u64,
        key: &(String, u64),
    ) {
        let requested = {
            let ledgers = self.c0_pair_ledgers.read().await;
            let ledger = ledgers.get(key);
            ledger.map(|l| l.attempted_pairs.clone()).unwrap_or_default()
        };
        let pairs = requested
            .iter()
            .map(|p| {
                format!(
                    "({}, {})",
                    p.local_fresh_endpoint, p.remote_fresh_endpoint
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let detail = format!(
            "no mutually-admitted (local_fresh, remote_fresh) pair found across C={} epochs -> relay fallback is correct (C=0); attempted_pairs=[{pairs}]",
            MAX_C0_PAIRS_PER_GENERATION,
        );
        self.record_direct_event(peer_id, "c0_pairs_exhausted", None, None, None, detail.clone())
            .await;
        info!(
            event = "c0_pairs_exhausted",
            peer_id = %peer_id,
            generation,
            epoch,
            detail = %detail,
            "C=0 fresh-fresh budget exhausted: no mutually-admitted endpoint pair; relay fallback is correct",
        );
    }

    /// Read the current C=0 ledger for `(peer, generation)`.  Test-only and
    /// diagnostics.
    #[cfg(test)]
    pub(crate) async fn c0_ledger_snapshot(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> Option<C0PairLedger> {
        self.c0_pair_ledgers
            .read()
            .await
            .get(&(peer_id.to_string(), generation))
            .cloned()
    }

    /// Test-only: count `c0_attempt` / `c0_pairs_exhausted` diagnostic events
    /// for a peer so the attribution and exactly-once exhaustion are directly
    /// observable (same pattern as `direct_liveness_event_count`).
    #[cfg(test)]
    pub(crate) async fn c0_event_count(&self, peer_id: &str, stage: &str) -> usize {
        let conns = self.connections.read().await;
        conns
            .get(peer_id)
            .map(|c| {
                c.direct_events
                    .iter()
                    .filter(|e| e.stage == stage)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Test-only: install a pre-built ledger for `(peer, generation)` so a
    /// budget test can start from a seeded state without simulating N real
    /// punch windows (paired with `C0PairLedger::seeded_exhausted`).
    #[cfg(test)]
    pub(crate) async fn c0_set_ledger(&self, peer_id: &str, generation: u64, ledger: C0PairLedger) {
        self.c0_pair_ledgers
            .write()
            .await
            .insert((peer_id.to_string(), generation), ledger);
    }
}

impl C0PairLedger {
    /// Number of distinct pairs already attempted in this ledger.
    #[cfg(test)]
    pub(crate) fn attempted_count(&self) -> usize {
        self.attempted_pairs.len()
    }

    /// Whether the budget is exhausted (or a hit already finished attempts).
    #[cfg(test)]
    pub(crate) fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

fn outcome_label(outcome: C0PairOutcome) -> &'static str {
    match outcome {
        C0PairOutcome::Hit => "hit",
        C0PairOutcome::Miss => "miss",
    }
}