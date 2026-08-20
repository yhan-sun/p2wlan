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

    /// Snapshot the cached candidate set WITHOUT taking the refresh lock.
    ///
    /// Used by the responder answer path: a live STUN refresh must never delay
    /// the answer. The lease is the one committed candidate/source tuple.
    async fn cached_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        if let Some(leased) = self.leased_candidate_set().await {
            return leased;
        }
        (Vec::new(), HashMap::new())
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
        if let Some(udp) = self.udp_transport.read().await.clone() {
            if let Some(refreshed) = self
                .refresh_local_candidates_for_imminent_signal(&udp, reason)
                .await
            {
                return refreshed;
            }
        }
        if let Some(stale) = stale {
            if !stale.0.is_empty() {
                return stale;
            }
        }
        self.wait_for_local_candidate_set().await
    }

    async fn add_local_peer_reflexive_candidate(&self, observed_endpoint: &str) -> bool {
        let _refresh_guard = self.candidate_refresh_lock.lock().await;
        let current = self.cached_candidate_snapshot().await;
        let mut candidates = current
            .as_ref()
            .map(|snapshot| snapshot.candidates.clone())
            .unwrap_or_default();
        let mut candidate_sources = current
            .as_ref()
            .map(|snapshot| snapshot.candidate_sources.clone())
            .unwrap_or_default();
        match add_peer_reflexive_candidate_to_set(
            observed_endpoint,
            &mut candidates,
            &mut candidate_sources,
        ) {
            Ok(true) => {
                let network_identity = current
                    .as_ref()
                    .map(|snapshot| snapshot.network_identity.clone())
                    .unwrap_or_default();
                publish_candidate_snapshot_to_store(
                    &self.candidate_snapshot,
                    candidates.clone(),
                    candidate_sources.clone(),
                    network_identity,
                )
                .await;
                // Compatibility mirrors are written only after the coherent
                // snapshot commit and are never used to assemble signal data.
                *self.local_candidates.write().await = candidates;
                *self.local_candidate_sources.write().await = candidate_sources;
                info!(
                    "Updated relay-assisted peer-reflexive local UDP candidate {}",
                    observed_endpoint
                );
                true
            }
            Ok(false) => false,
            Err(err) => {
                warn!(
                    "Ignoring invalid relay-assisted peer-reflexive endpoint '{}': {err}",
                    observed_endpoint
                );
                false
            }
        }
    }

    async fn publish_current_candidates_to_peer(&self, node_id: &str, reason: &str) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!(
                "UDP transport is not ready; skipping {reason} candidate publication to {node_id}"
            );
            return;
        };
        // Publication reuses the snapshot lease: a fresh lease means the
        // current committed set is already live — no re-gather, no endpoint
        // re-publish (the gather path already published it).
        let (candidates, candidate_sources) = if let Some(leased) = self.fresh_candidate_set().await
        {
            leased
        } else if let Some(refreshed) = self
            .refresh_local_candidates_for_imminent_signal(&udp, reason)
            .await
        {
            refreshed
        } else if let Some(stale) = self.leased_candidate_set().await {
            stale
        } else {
            self.current_local_candidate_set().await
        };
        if candidates.is_empty() {
            debug!("Local UDP candidates are not ready; skipping {reason} candidate publication to {node_id}");
            return;
        }
        let punch_at_ms = Some(relay_assisted_punch_at_ms());

        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_and_punch_at(
                node_id,
                &candidates,
                &candidate_sources,
                &[],
                punch_at_ms,
                None,
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
        spawn_hole_punch_task(
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
        )
        .await;
    }

    async fn refresh_local_candidates_for_imminent_signal(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<(Vec<String>, HashMap<String, String>)> {
        // Single-flight lease: cached candidates are never re-gathered inside
        // the TTL, so multiple peers' offers cannot rewrite the local
        // source/port mapping in a tight loop.  A non-empty committed
        // snapshot remains usable after the lease expires; signal paths must
        // not start an inline STUN gather and join a startup convoy.  The
        // periodic candidate-refresh worker owns refreshes.  Only the
        // no-snapshot bootstrap case gathers synchronously here.
        if let Some(leased) = self.leased_candidate_set().await {
            if !leased.0.is_empty() {
                if self.candidate_snapshot_is_fresh().await {
                    debug!(
                        "Pre-signal UDP candidates reused from the fresh snapshot lease for {reason} ({} candidates); no live STUN gather",
                        leased.0.len()
                    );
                } else {
                    // A peer event must not join a convoy of live STUN
                    // gathers after the short lease expires.  The UDP
                    // candidate-refresh worker owns refreshes; the signal
                    // path can use the bounded last snapshot immediately and
                    // let that worker publish the newer set asynchronously.
                    // This is especially important during startup when the
                    // control roster can enqueue dozens of peer events while
                    // the first gather still owns candidate_refresh_lock.
                    debug!(
                        "Pre-signal UDP candidates reused from the stale snapshot for {reason} ({} candidates); avoiding an inline STUN refresh convoy",
                        leased.0.len()
                    );
                }
                return Some(leased);
            }
        }
        let refreshed = self.refresh_local_candidates_core(udp, reason).await?;
        if let Some(endpoint) = control_udp_endpoint_from_candidates(&refreshed.0, &refreshed.1) {
            let nat_type = self
                .nat_profile
                .read()
                .await
                .as_ref()
                .map(p2pnet_nat::NatProfile::control_label)
                .unwrap_or_else(|| "unknown".to_string());
            // The endpoint publish travels the handshake control lane with a
            // short caller budget: the ordinary lane may be congested by
            // candidate-only traffic and must never delay the signal that
            // follows this refresh.
            match tokio::time::timeout(
                Duration::from_millis(PRE_SIGNAL_ENDPOINT_PUBLISH_BUDGET_MS),
                self.control
                    .update_endpoint_for_handshake(&endpoint, &nat_type),
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
        Some(refreshed)
    }

    async fn refresh_local_candidates_core(
        &self,
        udp: &UdpTransport,
        reason: &str,
    ) -> Option<(Vec<String>, HashMap<String, String>)> {
        let _refresh_guard = self.candidate_refresh_lock.lock().await;
        // Another initiator may have completed the gather while this caller
        // waited for the single-flight lock. Re-check the lease after lock
        // acquisition or concurrent offers will serialize duplicate STUN
        // gathers and churn the public mapping again.
        if let Some(leased) = self.fresh_candidate_set().await {
            if !leased.0.is_empty() {
                debug!(
                    "Pre-signal UDP candidates reused after refresh lock handoff for {reason} ({} candidates)",
                    leased.0.len()
                );
                return Some(leased);
            }
        }
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

        self.peers
            .update_nat_profile(report.nat_profile.clone())
            .await;
        *self.nat_profile.write().await = Some(report.nat_profile.clone());

        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        let include_host_candidate = self.peers.gather_host_candidates().await;
        if let Some(endpoint) = udp.local_addr().ok().and_then(|local_addr| {
            advertised_udp_endpoint(
                local_addr,
                self.config.network.udp_advertise.as_deref(),
                &candidates,
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

        let previous_snapshot = self.cached_candidate_snapshot().await;
        let previous_candidates = previous_snapshot
            .as_ref()
            .map(|snapshot| snapshot.candidates.clone())
            .unwrap_or_default();
        let previous_candidate_sources = previous_snapshot
            .as_ref()
            .map(|snapshot| snapshot.candidate_sources.clone())
            .unwrap_or_default();
        let next_network_identity = prepare_signal_candidates_and_network_identity(
            &previous_candidates,
            &previous_candidate_sources,
            &mut candidates,
            &mut candidate_sources,
        );
        let previous_network_identity = previous_snapshot
            .as_ref()
            .map(|snapshot| snapshot.network_identity.clone())
            .unwrap_or_default();
        let should_advance_generation =
            network_identity_changed(&previous_network_identity, &next_network_identity);
        let change_reason = candidate_set_change_reason(
            &previous_candidates,
            &candidates,
            &previous_candidate_sources,
            &candidate_sources,
        );
        let old_hash = candidate_set_hash(&previous_candidates, &previous_candidate_sources);
        let new_hash = candidate_set_hash(&candidates, &candidate_sources);
        let old_candidate_count = previous_candidates.len();
        let new_candidate_count = candidates.len();
        let real_change = change_reason != "no_change" && change_reason != "order_only";

        if candidate_refresh_requires_commit(real_change, should_advance_generation) {
            // The committed set becomes the shared snapshot lease: every
            // signaling path for the next TTL reuses it without a live gather.
            self.publish_candidate_snapshot(
                candidates.clone(),
                candidate_sources.clone(),
                next_network_identity.clone(),
            )
            .await;
            *self.local_candidates.write().await = candidates.clone();
            *self.local_candidate_sources.write().await = candidate_sources.clone();
            *self.local_network_identity.write().await = next_network_identity.clone();
            if should_advance_generation {
                self.peers
                    // A replaced physical/public identity is a true network
                    // handover.  Fully invalidate the old Direct proof so
                    // the imminent signal cannot be suppressed as an
                    // already-healthy Direct path.
                    .advance_network_generation("pre-signal UDP network identity changed")
                    .await;
            }
            info!(
                "Pre-signal UDP candidates refreshed for {reason}; {} candidates (mapping={:?}, public={:?}, old_hash={old_hash}, new_hash={new_hash}, changed_reason={change_reason}, old_candidate_count={old_candidate_count}, new_candidate_count={new_candidate_count})",
                candidates.len(),
                report.nat_profile.mapping_behavior,
                report.nat_profile.public_endpoint
            );
            debug!(
                "Pre-signal UDP candidate set diff for {reason}: changed_reason={change_reason} old_candidates={previous_candidates:?} new_candidates={candidates:?}"
            );
        } else {
            debug!(
                "Pre-signal UDP candidate refresh for {reason} kept the existing {} candidates (old_hash={old_hash} new_hash={new_hash} changed_reason={change_reason})",
                candidates.len()
            );
            // Even an unchanged gather refreshes the lease so later signals
            // reuse this snapshot instead of gathering again.
            self.publish_candidate_snapshot(
                candidates.clone(),
                candidate_sources.clone(),
                next_network_identity,
            )
            .await;
        }

        Some((candidates, candidate_sources))
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
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!("UDP transport is not ready; skipping hole punch for {node_id}");
            return;
        };

        let Some(_conn) = self.peers.get_connection(node_id).await else {
            debug!("No peer connection for {node_id}; skipping hole punch");
            return;
        };
        let observed_generation = self.peers.current_network_generation().await;
        let observed_commit_seq = self.peers.direct_commit_seq_sync(node_id);

        if self.peers.should_defer_relay_assisted_punch(node_id).await {
            debug!(
                "Skipping relay-assisted punch for {node_id}: healthy confirmed Direct path is active"
            );
            return;
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
            return;
        }

        if !self
            .peers
            .begin_hole_punch_if_current(node_id, observed_generation, observed_commit_seq)
            .await
        {
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
            return;
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
