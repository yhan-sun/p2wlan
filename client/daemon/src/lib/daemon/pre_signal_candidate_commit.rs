/// A snapshot of the existing UDP publication and network generation. Control
/// queues carry it to their actual request/response boundaries; it owns no
/// independently evolving network state and cannot revoke an in-flight HTTP.
#[derive(Clone)]
pub(crate) struct EndpointPublicationFence {
    publication_owner: std::sync::Weak<std::sync::atomic::AtomicU64>,
    peers: std::sync::Weak<PeerManager>,
    owner: u64,
    generation: u64,
}

impl EndpointPublicationFence {
    pub(crate) fn new(udp: &UdpTransport, peers: &Arc<PeerManager>) -> Self {
        Self::from_identity(
            udp,
            peers,
            udp.inbound_publication_owner(),
            peers.current_network_generation_sync(),
        )
    }

    pub(crate) fn from_identity(
        udp: &UdpTransport,
        peers: &Arc<PeerManager>,
        owner: u64,
        generation: u64,
    ) -> Self {
        Self {
            publication_owner: udp.inbound_publication_owner_weak(),
            peers: Arc::downgrade(peers),
            owner,
            generation,
        }
    }

    pub(crate) fn is_current(&self) -> bool {
        let (Some(owner), Some(peers)) = (self.publication_owner.upgrade(), self.peers.upgrade())
        else {
            return false;
        };
        self.owner != 0
            && owner.load(std::sync::atomic::Ordering::Acquire) == self.owner
            && peers.current_network_generation_sync() == self.generation
    }
}

struct PreSignalCandidateCommitContext<'a> {
    publication: &'a UdpTransportPublication,
    peers: &'a Arc<PeerManager>,
    nat_profile: &'a Arc<RwLock<Option<NatProfile>>>,
    snapshot: &'a Arc<RwLock<Option<CandidateSnapshotLease>>>,
    candidates: &'a Arc<RwLock<Vec<String>>>,
    sources: &'a Arc<RwLock<HashMap<String, String>>>,
    network_identity: &'a Arc<RwLock<Vec<String>>>,
}

struct PreSignalCandidateCommit {
    candidates: Vec<String>,
    sources: HashMap<String, String>,
    nat_type: String,
    endpoint_fence: EndpointPublicationFence,
    snapshot_version: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CandidateCommitMode {
    PreSignal,
    Periodic,
}

struct CandidateReportCommit {
    publication: PreSignalCandidateCommit,
    nat_publication: crate::peer::NatProfilePublication,
    profile_changed: bool,
    snapshot_changed: bool,
    generation_changed: bool,
    public_readiness_changed: bool,
    previous_candidates: Vec<String>,
    previous_hash: u64,
    change_reason: &'static str,
}

async fn commit_pre_signal_candidates(
    context: PreSignalCandidateCommitContext<'_>,
    refresh_guard: &tokio::sync::MutexGuard<'_, ()>,
    gather_fence: &crate::candidate_refresh::CandidateGatherFence,
    udp: &UdpTransport,
    report: p2pnet_nat::CandidateGatherReport,
    candidates: Vec<String>,
    sources: HashMap<String, String>,
) -> Option<PreSignalCandidateCommit> {
    commit_candidate_report(
        context,
        refresh_guard,
        gather_fence,
        udp,
        report,
        candidates,
        sources,
        CandidateCommitMode::PreSignal,
    )
    .await
    .map(|committed| committed.publication)
}

/// Existing refresh single-flight -> local writers -> epoch/publication try
/// guards. All awaited preparation shares 100ms; failed preparation changes
/// nothing. Both authoritative guards are try-only after local writers, so
/// neither waits while holding a lock needed by a competing lifecycle path.
/// STUN and HTTP stay outside. Once local mutation begins, complete the original
/// generation transition: timing it out after its atomic increment would leave
/// peer state only partly invalidated. That existing transition performs local
/// state cleanup, with no network I/O, task join, or candidate-lock acquisition.
#[allow(clippy::too_many_arguments)]
async fn commit_candidate_report(
    context: PreSignalCandidateCommitContext<'_>,
    _refresh_guard: &tokio::sync::MutexGuard<'_, ()>,
    gather_fence: &crate::candidate_refresh::CandidateGatherFence,
    udp: &UdpTransport,
    report: p2pnet_nat::CandidateGatherReport,
    mut candidates: Vec<String>,
    mut sources: HashMap<String, String>,
    mode: CandidateCommitMode,
) -> Option<CandidateReportCommit> {
    let prepared = timeout(Duration::from_millis(100), async {
        let profile = context.nat_profile.write().await;
        let peer_profile = context.peers.lock_local_nat_profile_for_commit().await;
        let snapshot = context.snapshot.write().await;
        let candidates = context.candidates.write().await;
        let sources = context.sources.write().await;
        let identity = context.network_identity.write().await;
        (
            profile,
            peer_profile,
            snapshot,
            candidates,
            sources,
            identity,
        )
    })
    .await;
    let Ok((
        mut profile,
        peer_profile,
        mut snapshot,
        mut candidates_mirror,
        mut sources_mirror,
        mut identity_mirror,
    )) = prepared
    else {
        debug!(
            event = "candidate_gather_discarded",
            reason = "candidate_commit_contended"
        );
        return None;
    };
    let epoch_gate = context.peers.network_epoch_gate();
    let Ok(epoch) = epoch_gate.try_lock() else {
        debug!(
            event = "candidate_gather_discarded",
            reason = "network_epoch_contended"
        );
        return None;
    };
    let Ok(publication) = context.publication.inner.state.try_lock() else {
        debug!(
            event = "candidate_gather_discarded",
            reason = "udp_publication_contended"
        );
        return None;
    };
    if publication.current_owner != Some(UdpTransportOwner(udp.inbound_publication_owner())) {
        debug!(
            event = "candidate_gather_discarded",
            reason = "udp_transport_replaced"
        );
        return None;
    }
    if let Some(reason) = gather_fence.stale_reason_for_commit(
        snapshot.as_ref().map(|snapshot| snapshot.version),
        udp,
        context.peers,
    ) {
        debug!(event = "candidate_gather_discarded", reason);
        return None;
    }
    let previous_candidates = snapshot
        .as_ref()
        .map(|snapshot| snapshot.candidates.as_slice())
        .unwrap_or_default();
    let empty_sources = HashMap::new();
    let previous_sources = snapshot
        .as_ref()
        .map(|snapshot| &snapshot.candidate_sources)
        .unwrap_or(&empty_sources);
    let next_identity = prepare_signal_candidates_and_network_identity(
        previous_candidates,
        previous_sources,
        &mut candidates,
        &mut sources,
    );
    let previous_identity = snapshot
        .as_ref()
        .map(|snapshot| snapshot.network_identity.as_slice())
        .unwrap_or_default();
    let advance_generation = network_identity_changed(previous_identity, &next_identity);

    let change_reason =
        candidate_set_change_reason(previous_candidates, &candidates, previous_sources, &sources);
    let previous_hash = candidate_set_hash(previous_candidates, previous_sources);
    let public_readiness_changed = crate::candidate_refresh::public_candidate_readiness_changed(
        previous_candidates,
        previous_sources,
        &candidates,
        &sources,
    );
    let previous_candidates = previous_candidates.to_vec();
    let snapshot_changed = mode == CandidateCommitMode::PreSignal
        || snapshot.is_none()
        || candidate_refresh_requires_commit(
            !matches!(change_reason, "no_change" | "order_only"),
            advance_generation,
        );
    let profile_changed = profile.as_ref() != Some(&report.nat_profile);

    // All report side effects begin only after the original gather identity
    // has passed the writers and both authoritative lifecycle guards.
    if mode == CandidateCommitMode::Periodic {
        udp.apply_candidate_report_socket_pool_policy(&report);
    }
    let nat_publication = context
        .peers
        .update_nat_profile_with_guard(report.nat_profile.clone(), peer_profile)
        .await;
    *profile = Some(report.nat_profile.clone());
    let mut version = snapshot.as_ref().map_or(0, |snapshot| snapshot.version);
    if snapshot_changed {
        version = version.saturating_add(1);
        *snapshot = Some(CandidateSnapshotLease {
            hash: candidate_set_hash(&candidates, &sources),
            candidates: candidates.clone(),
            candidate_sources: sources.clone(),
            network_identity: next_identity.clone(),
            version,
            gathered_at: Instant::now(),
            initial_gather_complete: true,
        });
        *candidates_mirror = candidates.clone();
        *sources_mirror = sources.clone();
        *identity_mirror = next_identity;
    }
    // A periodic measurement with unchanged candidates renews NAT evidence
    // (g/o) without renewing the snapshot lease, version or startup readiness.
    if advance_generation {
        context
            .peers
            .advance_network_generation_in_epoch(&epoch, "UDP network identity changed")
            .await;
    }
    let endpoint_fence = EndpointPublicationFence::new(udp, context.peers);
    let publication = PreSignalCandidateCommit {
        candidates,
        sources,
        nat_type: report
            .nat_profile
            .control_label_with_generation_and_observation(
                nat_publication.generation,
                nat_publication.observation,
            ),
        endpoint_fence,
        snapshot_version: version,
    };
    Some(CandidateReportCommit {
        publication,
        nat_publication,
        profile_changed,
        snapshot_changed,
        generation_changed: advance_generation,
        public_readiness_changed,
        previous_candidates,
        previous_hash,
        change_reason,
    })
}
