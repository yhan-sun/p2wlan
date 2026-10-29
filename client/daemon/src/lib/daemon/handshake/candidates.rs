impl Daemon {
    /// Build the optional signaling context for fresh-mapping punch
    /// generations.  Present whenever the UDP transport, control plane and
    /// STUN observers are available.
    async fn hole_punch_signal_context(&self) -> Option<HolePunchSignalContext> {
        Some(HolePunchSignalContext {
            control: self.control.clone(),
            candidate_snapshot: self.candidate_snapshot.clone(),
            stun_servers: self.runtime_stun_servers.read().await.clone(),
            stun_timeout: *self.runtime_stun_timeout.read().await,
            boot_epoch_ms: self.boot_epoch_ms,
        })
    }

    async fn current_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        self.leased_candidate_set()
            .await
            .unwrap_or_else(|| (Vec::new(), HashMap::new()))
    }

    async fn wait_for_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(50);
        let timeout = Duration::from_millis(CANDIDATE_READY_TIMEOUT_MS);

        loop {
            let (candidates, candidate_sources) = self.current_local_candidate_set().await;
            if !candidates.is_empty() {
                return (candidates, candidate_sources);
            }
            if waited >= timeout {
                warn!(
                    "Proceeding with WireGuard signaling before UDP candidates are ready after {} ms",
                    timeout.as_millis()
                );
                return (candidates, candidate_sources);
            }
            sleep(step).await;
            waited += step;
        }
    }

    /// Return the first full startup snapshot when it is already committed.
    ///
    /// The UDP startup path intentionally publishes host candidates before
    /// STUN completes. A non-empty lease therefore does not, by itself, mean
    /// that the candidate set is ready for the first peer offer.
    async fn initial_candidate_set_if_ready(
        &self,
    ) -> Option<(Vec<String>, HashMap<String, String>)> {
        let snapshot = self.cached_candidate_snapshot().await?;
        snapshot
            .initial_gather_complete
            .then_some((snapshot.candidates, snapshot.candidate_sources))
    }

    /// Wait briefly for the first full STUN/prediction snapshot, then fall
    /// back to the newest committed set if discovery is unavailable. This is
    /// deliberately separate from `wait_for_local_candidate_set`: responders
    /// and candidate-only publication may use the provisional host snapshot,
    /// while a brand-new offer benefits from the complete startup window.
    async fn wait_for_initial_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        wait_for_initial_candidate_set_from_store(&self.candidate_snapshot).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn local_candidate_set_for_signal(
        &self,
        reason: &str,
    ) -> (Vec<String>, HashMap<String, String>) {
        // Signal paths prefer the shared snapshot lease: cached candidates
        // are never re-gathered inside the TTL, so concurrent initiators,
        // rekeys and offers share ONE gather instead of each running a live
        // STUN refresh (which would churn the local source/port mapping).
        if let Some(fresh) = self.fresh_candidate_set().await {
            if !fresh.0.is_empty() {
                return fresh;
            }
        }
        let stale = self.leased_candidate_set().await;
        let udp = self.udp_transport.read().await.clone();
        if let Some(udp) = udp {
            if let Some(refreshed) = self
                .refresh_local_candidates_for_imminent_signal(&udp, reason)
                .await
            {
                return (refreshed.candidates, refreshed.sources);
            }
            // A failed owner-fenced refresh cannot revive the old lease.
            return (Vec::new(), HashMap::new());
        }
        if let Some(stale) = stale {
            if !stale.0.is_empty() {
                return stale;
            }
        }
        self.wait_for_local_candidate_set().await
    }

    async fn publish_current_candidates_to_peer(&self, node_id: &str, reason: &str) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!(
                "UDP transport is not ready; skipping {reason} candidate publication to {node_id}"
            );
            return;
        };
        let Some(peer_session) = self.peers.peer_session_generation_sync(node_id) else {
            return;
        };
        let Some(selected) = self
            .candidate_signal_set_for_publication(&udp, reason)
            .await
        else {
            return;
        };
        let publication_fence = selected.publication_fence(self, node_id, peer_session);
        let candidates = selected.candidates;
        let candidate_sources = selected.sources;
        if !publication_fence.is_current().await {
            return;
        }
        if candidates.is_empty() {
            debug!("Local UDP candidates are not ready; skipping {reason} candidate publication to {node_id}");
            return;
        }

        if self.peers.hard_hard_experiment_only() {
            // The dedicated Hard↔Hard matrix must not let the ordinary offer
            // lane advance candidate epochs or consume the shared recovery
            // quota before the planner sees both live NAT profiles. This does
            // not force Hard↔Hard: the regular worker still runs every
            // planner/generation/session gate and Relay remains the fallback.
            self.peers
                .record_direct_event(
                    node_id,
                    "hard_hard_experiment_trigger",
                    None,
                    Some(candidates.len()),
                    None,
                    format!(
                        "suppressed ordinary {reason} candidate offer; invoking planner-gated Hard↔Hard experiment lane"
                    ),
                )
                .await;
            let attempts = self
                .peers
                .recommended_punch_attempts(self.config.network.punch_attempts)
                .await;
            let signal = self.hole_punch_signal_context().await;
            spawn_hole_punch_task_with_lifecycle(
                udp,
                self.peers.clone(),
                self.punch_attempts.clone(),
                node_id.to_string(),
                Duration::from_millis(self.config.network.punch_interval_ms),
                attempts,
                None,
                signal,
                None,
                None,
                None,
                Some(publication_fence),
            )
            .await;
            return;
        }
        let punch_at_ms = Some(relay_assisted_punch_at_ms());

        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_and_punch_at_fenced(
                node_id,
                &candidates,
                &candidate_sources,
                &[],
                punch_at_ms,
                None,
                Some(publication_fence.clone()),
            )
            .await
        {
            warn!("Failed to publish {reason} UDP candidates to peer {node_id}: {error}");
            return;
        }

        info!(
            "Published {reason} UDP candidates to peer {node_id} ({} candidates) punch_at_ms={punch_at_ms:?}",
            candidates.len()
        );
        if self.peers.should_defer_relay_assisted_punch(node_id).await {
            debug!(
                "Skipping relay-assisted punch for {node_id}: healthy confirmed Direct path is active"
            );
            return;
        }
        let attempts = self
            .peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        let signal = self.hole_punch_signal_context().await;
        spawn_hole_punch_task_with_lifecycle(
            udp,
            self.peers.clone(),
            self.punch_attempts.clone(),
            node_id.to_string(),
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
            signal,
            None,
            None,
            None,
            Some(publication_fence),
        )
        .await;
    }

    async fn refresh_local_candidates_for_imminent_signal(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<CandidateSignalSet> {
        // Even an expired lease is reusable, but its socket, generation and
        // exact snapshot version must travel with the copied candidates.
        let endpoint_fence = EndpointPublicationFence::new(udp, &self.peers);
        if let Some(snapshot) = self.cached_candidate_snapshot().await {
            if !snapshot.candidates.is_empty() {
                return endpoint_fence
                    .is_current()
                    .then(|| CandidateSignalSet::from_snapshot(snapshot, endpoint_fence));
            }
        }
        if !endpoint_fence.is_current() {
            return None;
        }
        let refreshed = self.refresh_local_candidates_core(udp, reason).await?;
        if let Some(endpoint) =
            control_udp_endpoint_from_candidates(&refreshed.candidates, &refreshed.sources)
        {
            match tokio::time::timeout(
                Duration::from_millis(PRE_SIGNAL_ENDPOINT_PUBLISH_BUDGET_MS),
                self.control.update_endpoint_for_handshake_fenced(
                    &endpoint,
                    &refreshed.nat_type,
                    refreshed.endpoint_fence.clone(),
                ),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!("Failed to publish pre-signal UDP endpoint '{endpoint}': {err}")
                }
                Err(_) => {
                    debug!("Pre-signal UDP endpoint publish '{endpoint}' exceeded its budget")
                }
            }
        }
        // An endpoint request may have waited behind authentication or HTTP.
        // Cancellation never permits its old tuple to fall through to signal.
        let selected = CandidateSignalSet {
            candidates: refreshed.candidates,
            sources: refreshed.sources,
            snapshot_version: refreshed.snapshot_version,
            endpoint_fence: refreshed.endpoint_fence,
        };
        selected.is_current(self).await.then_some(selected)
    }

    async fn refresh_local_candidates_core(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<PreSignalCandidateCommit> {
        let entry_fence = EndpointPublicationFence::new(udp, &self.peers);
        let refresh_guard = self.candidate_refresh_lock.lock().await;
        if !entry_fence.is_current() {
            return None;
        }
        // Another initiator may have completed the gather while this caller
        // waited for the single-flight lock. Re-check the lease after lock
        // acquisition or concurrent offers will serialize duplicate STUN
        // gathers and churn the public mapping again.
        if let Some(leased) = self.cached_candidate_snapshot().await {
            if leased.is_fresh() && !leased.candidates.is_empty() {
                debug!(
                    "Pre-signal UDP candidates reused after refresh lock handoff for {reason} ({} candidates)",
                    leased.candidates.len()
                );
                let nat_type = self
                    .nat_profile
                    .read()
                    .await
                    .as_ref()
                    .map(|profile| {
                        profile.control_label_with_generation_and_observation(
                            self.peers.current_local_profile_generation_sync(),
                            self.peers.current_local_profile_observation_sync(),
                        )
                    })
                    .unwrap_or_else(|| "unknown".into());
                if !entry_fence.is_current() {
                    return None;
                }
                return Some(PreSignalCandidateCommit {
                    candidates: leased.candidates,
                    sources: leased.candidate_sources,
                    nat_type,
                    endpoint_fence: entry_fence,
                    snapshot_version: leased.version,
                });
            }
        }
        let gather_fence = crate::candidate_refresh::CandidateGatherFence::capture(
            &refresh_guard,
            udp,
            &self.peers,
            &self.candidate_snapshot,
        )
        .await;
        let stun_servers = self.runtime_stun_servers.read().await.clone();
        if stun_servers.is_empty() {
            return None;
        }
        let stun_timeout = *self.runtime_stun_timeout.read().await;
        let report = match udp
            .gather_candidate_report_live_parallel(stun_servers, stun_timeout)
            .await
        {
            Ok(report) => report,
            Err(err) => {
                warn!("Pre-signal UDP candidate refresh failed for {reason}: {err}");
                return None;
            }
        };

        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        let include_host_candidate = self.peers.gather_host_candidates().await;
        if let Some(endpoint) = udp.local_addr().ok().and_then(|local_addr| {
            advertised_udp_endpoint(
                local_addr,
                self.config.network.udp_advertise.as_deref(),
                &candidates,
                &candidate_sources,
                include_host_candidate,
            )
        }) {
            // The advertised endpoint is the peer's PRIMARY punch target and
            // must be FIRST in the signaled order; the public mapping is
            // already present from gathering, so move it to the front (see
            // the same fix in `udp_direct` / `candidate_refresh`).
            if let Some(index) = candidates.iter().position(|c| c == &endpoint) {
                candidates.remove(index);
            }
            candidates.insert(0, endpoint.clone());
            candidate_sources
                .entry(endpoint.clone())
                .or_insert_with(|| {
                    if self
                        .config
                        .network
                        .udp_advertise
                        .as_deref()
                        .is_some_and(|configured| {
                            !configured.trim().is_empty() && configured.trim() == endpoint
                        })
                    {
                        "manual".to_string()
                    } else {
                        "host".to_string()
                    }
                });
        }

        commit_pre_signal_candidates(
            PreSignalCandidateCommitContext {
                publication: &self.udp_transport_publication,
                peers: &self.peers,
                nat_profile: &self.nat_profile,
                snapshot: &self.candidate_snapshot,
                candidates: &self.local_candidates,
                sources: &self.local_candidate_sources,
                network_identity: &self.local_network_identity,
            },
            &refresh_guard,
            &gather_fence,
            udp,
            report,
            candidates,
            candidate_sources,
        )
        .await
    }

    async fn start_hole_punch(&self, node_id: &str) {
        self.start_hole_punch_at(node_id, None, None, None).await;
    }

    /// Start a synchronized hole punch for `node_id`.
    ///
    /// `frozen_targets` is only Some for a fresh-mapping prediction session:
    /// the immutable candidate snapshot frozen when the fresh signal arrived.
    /// A later ordinary refresh may update the shared candidate set, but it
    /// must never change the target of a running fresh session.
    async fn start_hole_punch_at(
        &self,
        node_id: &str,
        punch_at_ms: Option<u64>,
        fresh_prediction: Option<FreshPredictionId>,
        frozen_targets: Option<Vec<SocketAddr>>,
    ) {
        let _ = self
            .start_hole_punch_at_with_lock_policy(
                node_id,
                punch_at_ms,
                fresh_prediction,
                frozen_targets,
                false,
            )
            .await;
    }

    /// Candidate work is polled cooperatively by the control-event loop. It
    /// must report connection-map contention to its bounded owner instead of
    /// queueing a lock waiter that can block an inline PeerUpdated commit.
    async fn start_hole_punch_at_for_candidate_work(
        &self,
        node_id: &str,
        punch_at_ms: Option<u64>,
        fresh_prediction: Option<FreshPredictionId>,
        frozen_targets: Option<Vec<SocketAddr>>,
    ) -> HolePunchStartOutcome {
        self.start_hole_punch_at_with_lock_policy(
            node_id,
            punch_at_ms,
            fresh_prediction,
            frozen_targets,
            true,
        )
        .await
    }

    async fn start_hole_punch_at_with_lock_policy(
        &self,
        node_id: &str,
        punch_at_ms: Option<u64>,
        fresh_prediction: Option<FreshPredictionId>,
        frozen_targets: Option<Vec<SocketAddr>>,
        non_queuing_peer_commit: bool,
    ) -> HolePunchStartOutcome {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!("UDP transport is not ready; skipping hole punch for {node_id}");
            return HolePunchStartOutcome::NotReady;
        };

        if !non_queuing_peer_commit && self.peers.get_connection(node_id).await.is_none() {
            debug!("No peer connection for {node_id}; skipping hole punch");
            return HolePunchStartOutcome::PeerMissing;
        }
        let observed_generation = self.peers.current_network_generation_sync();
        let observed_commit_seq = self.peers.direct_commit_seq_sync(node_id);

        if !non_queuing_peer_commit && self.peers.should_defer_relay_assisted_punch(node_id).await {
            debug!(
                "Skipping relay-assisted punch for {node_id}: healthy confirmed Direct path is active"
            );
            return HolePunchStartOutcome::HealthyDirect;
        }

        if self
            .leased_candidate_set()
            .await
            .is_none_or(|(candidates, _)| candidates.is_empty())
        {
            self.peers
                .record_direct_event(
                    node_id,
                    "punch_delayed_local_candidates_not_ready",
                    None,
                    Some(0),
                    None,
                    "delayed UDP punch until local candidates are ready",
                )
                .await;
            debug!("Local UDP candidates are not ready; delaying hole punch for {node_id}");
            return HolePunchStartOutcome::NotReady;
        }

        // The UDP supervisor publishes a provisional host-only snapshot as
        // soon as the socket binds. Do not start a synchronized punch from
        // that snapshot: the corresponding first offer may still be waiting
        // for the public/predicted candidates that the startup gather commits
        // a moment later. Relay-first signaling can establish the encrypted
        // session immediately; the initial candidate publication will start
        // the Direct punch once this readiness fence is open.
        if self
            .cached_candidate_snapshot()
            .await
            .is_some_and(|snapshot| !snapshot.initial_gather_complete)
        {
            self.peers
                .record_direct_event(
                    node_id,
                    "punch_delayed_initial_candidates_not_ready",
                    None,
                    None,
                    None,
                    "delayed synchronized UDP punch until the first full candidate snapshot was committed",
                )
                .await;
            debug!(
                "Initial UDP candidate snapshot is provisional; delaying hole punch for {node_id}"
            );
            return HolePunchStartOutcome::NotReady;
        }

        let begin_outcome = if non_queuing_peer_commit {
            self.peers.try_begin_hole_punch_if_current(
                node_id,
                observed_generation,
                observed_commit_seq,
            )
        } else if self
            .peers
            .begin_hole_punch_if_current(node_id, observed_generation, observed_commit_seq)
            .await
        {
            HolePunchStartOutcome::Started
        } else {
            HolePunchStartOutcome::Stale
        };
        match begin_outcome {
            HolePunchStartOutcome::Started => {}
            HolePunchStartOutcome::ContendedEpoch
            | HolePunchStartOutcome::ContendedConnections
            | HolePunchStartOutcome::PeerMissing
            | HolePunchStartOutcome::HealthyDirect => return begin_outcome,
            HolePunchStartOutcome::Stale => {
                self.peers
                    .record_direct_event(
                        node_id,
                        "hole_punch_start_skipped_stale_state",
                        None,
                        None,
                        None,
                        format!(
                            "state/generation/commit changed before punch start; observed_generation={observed_generation} observed_direct_commit_seq={observed_commit_seq:?}"
                        ),
                    )
                    .await;
                return HolePunchStartOutcome::Stale;
            }
            HolePunchStartOutcome::NotReady => unreachable!("begin never returns NotReady"),
        }

        let peer_id = node_id.to_string();
        let peers = self.peers.clone();
        let attempts = peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        let signal = self.hole_punch_signal_context().await;
        spawn_hole_punch_task(
            udp,
            peers,
            self.punch_attempts.clone(),
            peer_id,
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
            signal,
            fresh_prediction,
            frozen_targets,
        )
        .await;
        HolePunchStartOutcome::Started
    }
}

/// Select the candidate payload for the relay-first handshake fast path.
///
/// A committed candidate snapshot is safe to signal immediately.  When no
/// snapshot exists, an already connected relay still permits an encrypted
/// WireGuard session to be established with an empty candidate list; later
/// candidate refreshes are a Direct-upgrade concern.  `None` means the caller
/// should wait briefly for the first candidate snapshot while relay selection
/// is still racing startup.
pub(crate) fn relay_first_candidate_shortcut(
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    relay_available: bool,
) -> Option<(Vec<String>, HashMap<String, String>)> {
    if !candidates.is_empty() {
        Some((candidates, candidate_sources))
    } else if relay_available {
        Some((Vec::new(), HashMap::new()))
    } else {
        None
    }
}

include!("candidate_signal_lease.rs");
