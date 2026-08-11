// ============================================================
// Candidate snapshot lease: single-flight, TTL-bound live gathers
// ============================================================

/// How long a freshly gathered candidate snapshot stays valid for signaling
/// purposes.  Within the lease no signal path may re-run a live STUN gather.
///
/// The lease must stay SHORT: on an address/port-dependent CGNAT the
/// predicted-port window the punch targets is derived from the latest STUN
/// observation, and a stale window misses the peer's actual mapping.  A 2s
/// lease still single-flights concurrent initiators while keeping punch
/// windows fresh; rekeys default to the cached snapshot as required.
const CANDIDATE_SNAPSHOT_TTL: Duration = Duration::from_secs(2);

/// The cached local candidate snapshot shared by every signaling path.
///
/// Only the periodic candidate refresh and the first-ever gather may run a
/// live STUN gather; every offer/answer/rekey path reads this lease and
/// re-gathers only when the snapshot expired or the network identity changed.
#[derive(Debug, Clone)]
pub(crate) struct CandidateSnapshotLease {
    pub(crate) candidates: Vec<String>,
    pub(crate) candidate_sources: HashMap<String, String>,
    pub(crate) network_identity: Vec<String>,
    pub(crate) version: u64,
    pub(crate) hash: u64,
    gathered_at: Instant,
}

impl CandidateSnapshotLease {
    /// Whether the lease is still fresh: inside the TTL no signaling path may
    /// re-run a live STUN gather (single-flight).
    fn is_fresh(&self) -> bool {
        self.gathered_at.elapsed() <= CANDIDATE_SNAPSHOT_TTL
    }
}

impl Daemon {
    /// Read the current snapshot lease without gathering.
    async fn cached_candidate_snapshot(&self) -> Option<CandidateSnapshotLease> {
        self.candidate_snapshot.read().await.clone()
    }

    /// Whether a fresh snapshot lease exists (single-flight gate for live
    /// gathers).
    async fn candidate_snapshot_is_fresh(&self) -> bool {
        self.candidate_snapshot
            .read()
            .await
            .as_ref()
            .is_some_and(CandidateSnapshotLease::is_fresh)
    }

    /// Test helper: publish a snapshot with a synthetic age (for TTL expiry
    /// tests).
    #[cfg(test)]
    async fn publish_candidate_snapshot_with_age(
        &self,
        candidates: Vec<String>,
        candidate_sources: HashMap<String, String>,
        age: Duration,
    ) {
        let mut lease = CandidateSnapshotLease {
            candidates,
            candidate_sources,
            network_identity: Vec::new(),
            version: self
                .candidate_snapshot
                .read()
                .await
                .as_ref()
                .map_or(1, |current| current.version.saturating_add(1)),
            hash: 0,
            gathered_at: Instant::now(),
        };
        lease.hash = candidate_set_hash(&lease.candidates, &lease.candidate_sources);
        lease.gathered_at -= age;
        *self.candidate_snapshot.write().await = Some(lease);
    }

    /// Store a freshly gathered/committed snapshot as the shared lease.
    async fn publish_candidate_snapshot(
        &self,
        candidates: Vec<String>,
        candidate_sources: HashMap<String, String>,
        network_identity: Vec<String>,
    ) {
        publish_candidate_snapshot_to_store(
            &self.candidate_snapshot,
            candidates,
            candidate_sources,
            network_identity,
        )
        .await;
    }

    /// The candidate set a signal may use, WITHOUT forcing a live gather:
    ///
    /// - a fresh lease is returned as-is (cached candidates are never
    ///   re-gathered inside the TTL);
    /// - a stale lease is returned too (bounded old snapshot) so a slow
    ///   refresh failure never blocks an answer/offer;
    /// - `None` only when no snapshot exists yet (the first gather still
    ///   happens through the explicit refresh paths).
    async fn leased_candidate_set(&self) -> Option<(Vec<String>, HashMap<String, String>)> {
        let lease = self.cached_candidate_snapshot().await?;
        Some((lease.candidates, lease.candidate_sources))
    }

    async fn fresh_candidate_set(&self) -> Option<(Vec<String>, HashMap<String, String>)> {
        let lease = self.cached_candidate_snapshot().await?;
        // The lease owns the network identity that was committed with its
        // candidates and sources. Readers must not reconstruct this tuple
        // from the legacy mirror locks while a refresh is being committed.
        (lease.is_fresh() && !lease.candidates.is_empty())
            .then_some((lease.candidates, lease.candidate_sources))
    }
}

/// Commit a candidate snapshot independently of the Daemon methods so the UDP
/// supervisor can publish the exact same atomic lease immediately after its
/// initial gather.
async fn publish_candidate_snapshot_to_store(
    store: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    network_identity: Vec<String>,
) {
    let mut current = store.write().await;
    let version = current
        .as_ref()
        .map_or(1, |previous| previous.version.saturating_add(1));
    let hash = candidate_set_hash(&candidates, &candidate_sources);
    *current = Some(CandidateSnapshotLease {
        candidates,
        candidate_sources,
        network_identity,
        version,
        hash,
        gathered_at: Instant::now(),
    });
}
