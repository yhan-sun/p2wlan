/// Immutable telemetry captured when a trigger is admitted or folded into an
/// existing rendezvous. The endpoints themselves remain in the peer's normal
/// candidate diagnostics; this record only carries a stable hash and source
/// categories so logs can explain a replacement without exposing additional
/// candidate material.
#[derive(Clone)]
struct PunchCandidateSnapshot {
    candidates: Vec<SocketAddr>,
    /// Candidate sources already authenticated or learned by this daemon.
    /// These are safe to prioritize in the bounded immediate prefix, while
    /// `candidates` remains the authoritative FIFO for the full punch plan.
    preferred_fast_candidates: Vec<SocketAddr>,
    hash: u64,
    /// Number of candidate endpoints for which provenance was captured.  An
    /// unknown provenance is deliberately retained as an explicit category
    /// rather than silently omitted, so this is always auditable against the
    /// snapshot's candidate count.
    source_count: usize,
    /// Number of distinct provenance categories represented by `source_count`.
    /// Kept separately because a count of categories is not a count of
    /// candidate endpoints.
    source_category_count: usize,
    source_summary: String,
}

async fn punch_candidate_snapshot(
    peers: &PeerManager,
    peer_id: &str,
    candidates: Vec<SocketAddr>,
) -> PunchCandidateSnapshot {
    let mut canonical = candidates
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    canonical.sort_unstable();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for endpoint in &canonical {
        for byte in endpoint
            .as_bytes()
            .iter()
            .copied()
            .chain(std::iter::once(0))
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    let connection = peers.get_connection(peer_id).await;
    let mut source_counts = HashMap::<String, usize>::new();
    let preferred_fast_candidates = connection
        .as_ref()
        .map(|connection| connection.preferred_fast_candidates(&candidates))
        .unwrap_or_default();
    for candidate in &candidates {
        let source = connection
            .as_ref()
            .and_then(|connection| connection.candidate_sources.get(&candidate.to_string()))
            .map(|source| format!("{source:?}"))
            .unwrap_or_else(|| "Unknown".to_string());
        *source_counts.entry(source).or_default() += 1;
    }
    let source_count = source_counts.values().sum();
    let source_category_count = source_counts.len();
    let mut source_summary = source_counts.into_iter().collect::<Vec<_>>();
    source_summary.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let source_summary = source_summary
        .into_iter()
        .map(|(source, count)| format!("{source}:{count}"))
        .collect::<Vec<_>>()
        .join(",");

    PunchCandidateSnapshot {
        candidates,
        preferred_fast_candidates,
        hash,
        source_count,
        source_category_count,
        source_summary,
    }
}
