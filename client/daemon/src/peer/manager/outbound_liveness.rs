// ============================================================
// Outbound-UDP liveness decision state
// ============================================================
//
// Cache for the (peer, generation) -> verdict liveness diagnostic.  Written by
// the spawned probe task, consumed at the next tick's admission.  The methods
// that read/write this (evaluate / probe / commit / apply) are added in a
// follow-up change; this file currently holds the entry type only.

/// One cached outbound-UDP liveness verdict for a `(peer, generation)` pair.
#[derive(Debug)]
struct LivenessCacheEntry {
    /// The 3-state verdict (Ok / Blocked / Unknown).
    verdict: p2pnet_nat::outbound_liveness::LivenessVerdict,
    /// Per-target detail (ip:port, responded, elapsed) for observability.
    per_target: Vec<p2pnet_nat::outbound_liveness::LivenessTargetResult>,
    /// Total wall time of the probe in milliseconds.
    total_elapsed_ms: u64,
    /// When this verdict was produced; TTL-bounded before re-probing.
    probed_at: Instant,
    /// Whether a `Blocked` verdict has already been consumed (applied) by a
    /// subsequent admission tick — applied exactly once.
    consumed: bool,
}
