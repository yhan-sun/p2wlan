pub(super) struct UdpCandidateRefreshContext {
    pub(super) udp: UdpTransport,
    pub(super) stun_servers: Vec<SocketAddr>,
    pub(super) stun_timeout: Duration,
    pub(super) udp_advertise: Option<String>,
    pub(super) upnp_enabled: bool,
    pub(super) published_endpoint: Option<String>,
    pub(super) local_candidates: Arc<RwLock<Vec<String>>>,
    pub(super) local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    pub(super) local_network_identity: Arc<RwLock<Vec<String>>>,
    pub(super) candidate_refresh_lock: Arc<Mutex<()>>,
    pub(super) nat_profile: Arc<RwLock<Option<NatProfile>>>,
    pub(super) gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    pub(super) gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    pub(super) punch_deduplicator: PunchAttemptDeduplicator,
    pub(super) control: ControlClient,
    pub(super) peers: Arc<PeerManager>,
    pub(super) probe_interval: Duration,
    pub(super) punch_attempts: u32,
    pub(super) boot_epoch_ms: u64,
}

/// Volatile candidate churn (source-only or short-lived port changes on the
/// same public IP) is coalesced newest-wins and published at most once per
/// debounce window.  Pure port jitter must not fan out an offer plus a
/// synchronized punch session to every non-Direct peer on every refresh.
const VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE: Duration = Duration::from_secs(30);

/// Decision a volatile churn takes against the coalescer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VolatileChurnAction {
    /// The churn produced the exact set that was already published: nothing
    /// to schedule, no fan-out.
    SuppressIdentical,
    /// A newer volatile set replaced the pending one while the debounce
    /// window is still open: newest-wins, still no immediate fan-out.
    CoalescedNewest,
    /// The churn opened a new debounce window; the pending set publishes once
    /// when the window elapses.
    SchedulePublish,
}

/// Newest-wins coalescing for volatile-only candidate publications.
///
/// Kept as a pure state machine so the "no fan-out per refresh" invariant is
/// directly testable without a control plane.
#[derive(Debug, Default)]
pub(super) struct VolatilePublishCoalescer {
    last_published_hash: Option<u64>,
    pending_hash: Option<u64>,
    debounce_until: Option<Instant>,
}

impl VolatilePublishCoalescer {
    /// Apply one volatile churn.  `now` is only used for debounce window
    /// expiry; the coalescer never publishes itself.
    pub(super) fn on_churn(&mut self, hash: u64, now: Instant) -> VolatileChurnAction {
        if self.last_published_hash == Some(hash) {
            return VolatileChurnAction::SuppressIdentical;
        }
        if self.pending_hash.is_some() {
            // Newest-wins: any churn inside the open debounce window replaces
            // the pending set and slides the window; still no fan-out.
            self.pending_hash = Some(hash);
            self.debounce_until = Some(now + VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE);
            return VolatileChurnAction::CoalescedNewest;
        }
        self.pending_hash = Some(hash);
        self.debounce_until = Some(now + VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE);
        VolatileChurnAction::SchedulePublish
    }

    /// Whether a pending publication's debounce window has elapsed.
    pub(super) fn pending_due(&self, now: Instant) -> bool {
        self.pending_hash.is_some() && self.debounce_until.is_some_and(|until| now >= until)
    }

    /// Take the pending hash whose window elapsed.
    pub(super) fn take_due(&mut self, now: Instant) -> Option<u64> {
        if !self.pending_due(now) {
            return None;
        }
        self.debounce_until = None;
        self.pending_hash.take()
    }

    /// Remember a hash that was actually published.
    pub(super) fn record_published(&mut self, hash: u64) {
        self.last_published_hash = Some(hash);
    }
}

/// Newest-wins pending publication for volatile-only candidate changes.
struct VolatileCandidatePublish {
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    debounce_until: Instant,
}

pub(super) async fn run_udp_candidate_refresh(context: UdpCandidateRefreshContext) {
    let UdpCandidateRefreshContext {
        udp,
        stun_servers,
        stun_timeout,
        udp_advertise,
        upnp_enabled,
        mut published_endpoint,
        local_candidates,
        local_candidate_sources,
        local_network_identity,
        candidate_refresh_lock,
        nat_profile,
        gateway_mapping_runtime,
        gateway_mapping_diagnostics,
        punch_deduplicator,
        control,
        peers,
        probe_interval,
        punch_attempts,
        boot_epoch_ms,
    } = context;
    let mut ticker = interval(CANDIDATE_REFRESH_INTERVAL);
    ticker.tick().await;
    let mut pending_volatile: Option<VolatileCandidatePublish> = None;
    let mut volatile_coalescer = VolatilePublishCoalescer::default();

    loop {
        ticker.tick().await;

        // Flush a coalesced volatile publication whose debounce window
        // elapsed.  The pending set is the newest committed candidate set;
        // identical re-publication is suppressed via the published hash.
        if let Some(hash) = volatile_coalescer.take_due(Instant::now()) {
            let pending = pending_volatile
                .take()
                .expect("pending volatile publication verified above");
            let payload_hash = candidate_set_hash(&pending.candidates, &pending.candidate_sources);
            if payload_hash == hash {
                publish_local_candidates_to_known_peers(
                    &control,
                    peers.clone(),
                    udp.clone(),
                    punch_deduplicator.clone(),
                    &pending.candidates,
                    &pending.candidate_sources,
                    probe_interval,
                    punch_attempts,
                    "UDP volatile candidate refresh",
                    Some(HolePunchSignalContext {
                        control: control.clone(),
                        local_candidates: local_candidates.clone(),
                        local_candidate_sources: local_candidate_sources.clone(),
                        stun_servers: stun_servers.clone(),
                        stun_timeout,
                        boot_epoch_ms,
                    }),
                )
                .await;
                volatile_coalescer.record_published(hash);
                info!(
                    "Published coalesced volatile UDP candidate refresh (hash={hash}, candidates={})",
                    pending.candidates.len()
                );
            } else {
                debug!(
                    "Suppressed volatile UDP candidate publication: coalesced set is identical to the last published set (hash={payload_hash})"
                );
            }
        }

        let refresh_guard = candidate_refresh_lock.lock().await;

        let report = match udp
            .gather_candidate_report_live(stun_servers.clone(), stun_timeout)
            .await
        {
            Ok(report) => report,
            Err(err) => {
                warn!("Periodic UDP candidate refresh failed: {err}");
                continue;
            }
        };
        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        peers.update_nat_profile(report.nat_profile.clone()).await;
        let profile_changed = {
            let mut current_profile = nat_profile.write().await;
            if current_profile.as_ref() == Some(&report.nat_profile) {
                false
            } else {
                *current_profile = Some(report.nat_profile.clone());
                true
            }
        };

        let include_host_candidate = peers.gather_host_candidates().await;
        let advertised_endpoint = udp.local_addr().ok().and_then(|local_addr| {
            advertised_udp_endpoint(
                local_addr,
                udp_advertise.as_deref(),
                &candidates,
                include_host_candidate,
            )
        });
        if let Some(endpoint) = advertised_endpoint.as_ref() {
            if !candidates.contains(endpoint) {
                candidates.insert(0, endpoint.clone());
            }
            candidate_sources
                .entry(endpoint.clone())
                .or_insert_with(|| {
                    if udp_advertise.as_deref().is_some_and(|configured| {
                        !configured.trim().is_empty() && configured.trim() == endpoint
                    }) {
                        "manual".to_string()
                    } else {
                        "host".to_string()
                    }
                });
        }

        if upnp_enabled {
            maybe_add_port_mapping_udp_candidate(
                udp.local_addr().ok(),
                &mut candidates,
                &mut candidate_sources,
                gateway_mapping_runtime.clone(),
                gateway_mapping_diagnostics.clone(),
            )
            .await;
        }
        let previous_candidates = local_candidates.read().await.clone();
        let previous_candidate_sources = local_candidate_sources.read().await.clone();
        let next_network_identity = prepare_signal_candidates_and_network_identity(
            &previous_candidates,
            &previous_candidate_sources,
            &mut candidates,
            &mut candidate_sources,
        );
        let previous_network_identity = local_network_identity.read().await.clone();
        let should_advance_generation = !previous_network_identity.is_empty()
            && previous_network_identity != next_network_identity;

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
        if !candidate_refresh_requires_commit(real_change, should_advance_generation) {
            if profile_changed {
                debug!(
                    "UDP NAT profile changed without advertised candidate endpoint changes: mapping={:?} public={:?}",
                    report.nat_profile.mapping_behavior,
                    report.nat_profile.public_endpoint
                );
            }
            debug!(
                "UDP candidate refresh kept the existing {} candidates: changed_reason={change_reason} old_hash={old_hash} new_hash={new_hash} old_candidate_count={old_candidate_count} new_candidate_count={new_candidate_count}",
                candidates.len()
            );
            continue;
        }

        {
            let mut current = local_candidates.write().await;
            *current = candidates.clone();
            *local_candidate_sources.write().await = candidate_sources.clone();
            *local_network_identity.write().await = next_network_identity.clone();
        }

        info!(
            "UDP candidates changed after network update; refreshed {} candidates (mapping={:?}, public={:?}, old_hash={old_hash}, new_hash={new_hash}, changed_reason={change_reason}, old_candidate_count={old_candidate_count}, new_candidate_count={new_candidate_count})",
            candidates.len(),
            report.nat_profile.mapping_behavior,
            report.nat_profile.public_endpoint
        );
        debug!(
            "UDP candidate set diff: changed_reason={change_reason} old_candidates={previous_candidates:?} new_candidates={candidates:?}"
        );
        let endpoint = control_udp_endpoint_from_candidates(&candidates, &candidate_sources)
            .or(advertised_endpoint)
            .unwrap_or_default();
        if should_advance_generation {
            peers
                .advance_candidate_refresh_generation("refreshed UDP candidates")
                .await;
        }
        drop(refresh_guard);

        if !should_advance_generation {
            debug!(
                "UDP candidate refresh changed only volatile reflexive ports; keeping network generation and signaling stable"
            );
            if should_update_stable_control_endpoint(published_endpoint.as_deref(), &endpoint) {
                if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
                    warn!("Failed to publish refreshed UDP endpoint '{endpoint}': {err}");
                } else {
                    published_endpoint = Some(endpoint);
                }
            }
            // Volatile-only churn is coalesced newest-wins and published at
            // most once per debounce window instead of fanning out an offer
            // plus a synchronized punch session to every non-Direct peer on
            // every refresh.  The committed candidate set above is already
            // the newest state; only the offer/punch publication is deferred.
            let hash = candidate_set_hash(&candidates, &candidate_sources);
            let now = Instant::now();
            match volatile_coalescer.on_churn(hash, now) {
                VolatileChurnAction::SuppressIdentical => {
                    debug!(
                        "Volatile candidate refresh suppressed: candidate set is identical to the last published set (hash={hash}); no offer fan-out"
                    );
                }
                VolatileChurnAction::CoalescedNewest => {
                    let pending = pending_volatile
                        .as_mut()
                        .expect("coalesced pending verified above");
                    pending.candidates = candidates.clone();
                    pending.candidate_sources = candidate_sources.clone();
                    pending.debounce_until =
                        now + VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE;
                    debug!(
                        "Volatile candidate churn coalesced newest-wins (hash={hash}); resetting the {}-s debounce window without offer fan-out",
                        VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE.as_secs()
                    );
                }
                VolatileChurnAction::SchedulePublish => {
                    pending_volatile = Some(VolatileCandidatePublish {
                        candidates: candidates.clone(),
                        candidate_sources: candidate_sources.clone(),
                        debounce_until: now + VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE,
                    });
                    debug!(
                        "Volatile candidate churn (hash={hash}) will be published once after the {}-s debounce window",
                        VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE.as_secs()
                    );
                }
            }
            continue;
        }
        if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
            warn!("Failed to publish refreshed UDP endpoint '{endpoint}': {err}");
        } else if !endpoint.is_empty() {
            published_endpoint = Some(endpoint.clone());
        }

        publish_local_candidates_to_known_peers(
            &control,
            peers.clone(),
            udp.clone(),
            punch_deduplicator.clone(),
            &candidates,
            &candidate_sources,
            probe_interval,
            punch_attempts,
            "UDP candidate refresh",
            Some(HolePunchSignalContext {
                control: control.clone(),
                local_candidates: local_candidates.clone(),
                local_candidate_sources: local_candidate_sources.clone(),
                stun_servers: stun_servers.clone(),
                stun_timeout,
                boot_epoch_ms,
            }),
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn publish_local_candidates_to_known_peers(
    control: &ControlClient,
    peers: Arc<PeerManager>,
    udp: UdpTransport,
    punch_deduplicator: PunchAttemptDeduplicator,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    probe_interval: Duration,
    attempts: u32,
    reason: &str,
    signal: Option<HolePunchSignalContext>,
) {
    if candidates.is_empty() {
        debug!("Skipping {reason} candidate publication because local candidate set is empty");
        return;
    }

    let attempts = peers.recommended_punch_attempts(attempts).await;

    for (peer_id, peer_info) in control.peers().await {
        if !peer_info.online {
            continue;
        }
        // A healthy confirmed Direct peer is converged: neither a refreshed
        // candidate offer nor a synchronized punch session may be re-created
        // for it (the punch task would otherwise run a fresh-mapping
        // measurement and a full candidate sweep on a live path every
        // refresh).  Recovery re-opens the Exploring window when the Direct
        // path loses health (keepalive/consent failure) or the network
        // generation changes.
        if peers.should_defer_relay_assisted_punch(&peer_id).await {
            peers
                .record_direct_event(
                    &peer_id,
                    "candidate_publish_skipped_direct",
                    None,
                    Some(candidates.len()),
                    None,
                    "skipped candidate offer and synchronized punch for a healthy confirmed Direct peer",
                )
                .await;
            debug!(
                "Skipping {reason} candidate publication to peer {peer_id}: healthy confirmed Direct path is active"
            );
            continue;
        }
        let punch_at_ms = Some(relay_assisted_punch_at_ms());
        if let Err(error) = control
            .send_peer_offer_with_sources_and_punch_at(
                &peer_id,
                candidates,
                candidate_sources,
                &[],
                punch_at_ms,
                None,
            )
            .await
        {
            warn!("Failed to publish {reason} UDP candidates to peer {peer_id}: {error}");
            continue;
        }

        debug!(
            "Published {reason} UDP candidates to peer {peer_id} with punch_at_ms={punch_at_ms:?}"
        );
        spawn_hole_punch_task(
            udp.clone(),
            peers.clone(),
            punch_deduplicator.clone(),
            peer_id,
            probe_interval,
            attempts,
            punch_at_ms,
            signal.clone(),
            None,
            None,
        )
        .await;
    }
}
