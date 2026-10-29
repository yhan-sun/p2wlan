/// Candidates and their identity are copied together, never reconstructed by
/// reading the latest version after an await with an older candidate tuple.
struct CandidateSignalSet {
    candidates: Vec<String>,
    sources: HashMap<String, String>,
    snapshot_version: u64,
    endpoint_fence: EndpointPublicationFence,
}

impl CandidateSignalSet {
    fn from_snapshot(
        snapshot: CandidateSnapshotLease,
        endpoint_fence: EndpointPublicationFence,
    ) -> Self {
        Self {
            candidates: snapshot.candidates,
            sources: snapshot.candidate_sources,
            snapshot_version: snapshot.version,
            endpoint_fence,
        }
    }

    async fn is_current(&self, daemon: &Daemon) -> bool {
        let current = daemon.candidate_snapshot.read().await;
        self.endpoint_fence.is_current()
            && current
                .as_ref()
                .is_some_and(|snapshot| snapshot.version == self.snapshot_version)
    }

    fn publication_fence(
        &self,
        daemon: &Daemon,
        peer_id: &str,
        peer_session: PeerSessionGeneration,
    ) -> Arc<control::CandidatePublicationFence> {
        control::CandidatePublicationFence::new(
            daemon.peers.clone(),
            Some(daemon.candidate_snapshot.clone()),
            peer_id.to_string(),
            self.endpoint_fence.generation,
            peer_session,
            candidate_set_hash(&self.candidates, &self.sources),
        )
        .with_endpoint(self.endpoint_fence.clone(), self.snapshot_version)
    }
}

impl Daemon {
    async fn candidate_signal_set_for_publication(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<CandidateSignalSet> {
        let endpoint_fence = EndpointPublicationFence::new(udp, &self.peers);
        let initial = self.cached_candidate_snapshot().await;
        if initial
            .as_ref()
            .is_some_and(|snapshot| !snapshot.initial_gather_complete)
        {
            wait_for_initial_candidate_set_from_store(&self.candidate_snapshot).await;
        }
        if !endpoint_fence.is_current() {
            return None;
        }
        if let Some(snapshot) = self.cached_candidate_snapshot().await {
            if !snapshot.candidates.is_empty() {
                return endpoint_fence
                    .is_current()
                    .then(|| CandidateSignalSet::from_snapshot(snapshot, endpoint_fence));
            }
        }
        // Only bootstrap without candidates may gather inline. A superseded
        // gather returns None all the way to the caller: no stale fallback.
        if !endpoint_fence.is_current() {
            return None;
        }
        self.refresh_local_candidates_for_imminent_signal(udp, reason)
            .await
    }

    async fn add_local_peer_reflexive_candidate(
        &self,
        work: &PendingPeerReflexive,
    ) -> Option<(bool, CandidateSignalSet)> {
        let endpoint_fence = work.endpoint_fence.as_ref()?;
        let peer_session = work.peer_session_generation?;
        // Preparation is bounded and makes no mutation. Match the gather
        // transaction's lock order; epoch/publication acquisition is try-only
        // after local writers, so a competing lifecycle never waits in a cycle.
        let prepared = timeout(Duration::from_millis(100), async {
            let refresh = self.candidate_refresh_lock.lock().await;
            let snapshot = self.candidate_snapshot.write().await;
            let candidates = self.local_candidates.write().await;
            let sources = self.local_candidate_sources.write().await;
            (refresh, snapshot, candidates, sources)
        })
        .await
        .ok()?;
        let (_refresh, mut snapshot, mut candidates_mirror, mut sources_mirror) = prepared;
        let epoch_gate = self.peers.network_epoch_gate();
        let _epoch = epoch_gate.try_lock().ok()?;
        let publication = self.udp_transport_publication.inner.state.try_lock().ok()?;
        if !endpoint_fence.is_current()
            || publication.current_owner != Some(UdpTransportOwner(endpoint_fence.owner))
            || !self
                .peers
                .peer_session_is_current_sync(&work.from_node_id, peer_session)
        {
            return None;
        }
        // An observation cannot fabricate readiness or a network identity
        // before the authoritative startup writer has published any snapshot.
        let current = snapshot.as_mut()?;
        let changed = match add_peer_reflexive_candidate_to_set(
            &work.observed_endpoint,
            &mut current.candidates,
            &mut current.candidate_sources,
        ) {
            Ok(changed) => changed,
            Err(err) => {
                warn!("Ignoring invalid relay-assisted peer-reflexive endpoint: {err}");
                return None;
            }
        };
        if changed {
            current.version = current.version.saturating_add(1);
            current.hash = candidate_set_hash(&current.candidates, &current.candidate_sources);
            // Keep identity, gather age and readiness: observing our source
            // does not complete or renew the authoritative STUN measurement.
            *candidates_mirror = current.candidates.clone();
            *sources_mirror = current.candidate_sources.clone();
        }
        Some((
            changed,
            CandidateSignalSet::from_snapshot(current.clone(), endpoint_fence.clone()),
        ))
    }
}

#[cfg(test)]
include!("candidate_signal_handover_tests.rs");
