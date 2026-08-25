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
    pub(super) candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
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

/// The reason that woke the candidate-refresh scheduler.
///
/// These reasons are intentionally kept separate: a volatile publication is
/// a control-plane flush of an already gathered snapshot, while a periodic
/// wake is the only event allowed to start a full STUN/gateway gather.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RefreshWakeReason {
    Periodic,
    VolatileDeadline,
}

impl RefreshWakeReason {
    fn permits_full_gather(self) -> bool {
        matches!(self, Self::Periodic)
    }
}

/// Mirror the ordering used by the biased Tokio `select!` below.  Keeping the
/// decision pure makes the simultaneous-ready behavior deterministic in unit
/// tests: a periodic tick is never lost when it is ready at the same time as a
/// volatile deadline.
#[cfg(test)]
fn refresh_wake_reason(
    periodic_ready: bool,
    volatile_deadline_ready: bool,
) -> Option<RefreshWakeReason> {
    if periodic_ready {
        Some(RefreshWakeReason::Periodic)
    } else if volatile_deadline_ready {
        Some(RefreshWakeReason::VolatileDeadline)
    } else {
        None
    }
}

/// Volatile candidate churn (source-only or short-lived port changes on the
/// same public IP) is coalesced newest-wins and published at most once per
/// short, fixed debounce window.  This is deliberately sub-second: a NAT
/// mapping change is direct-path evidence, and holding it for tens of seconds
/// recreates the observed "old ping packets arrive one second apart" failure.
/// The window is fixed from the first change rather than sliding on every
/// subsequent observation, so continuous port churn cannot starve publication.
const VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE: Duration = Duration::from_millis(500);

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
            // the pending set, but the original deadline remains fixed. This
            // bounds how long a new candidate can wait even when the NAT keeps
            // allocating ports.
            self.pending_hash = Some(hash);
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

    pub(super) fn pending_deadline(&self) -> Option<Instant> {
        self.pending_hash
            .is_some()
            .then_some(self.debounce_until)
            .flatten()
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
        candidate_snapshot,
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
    let initial_snapshot = candidate_snapshot.read().await.clone();
    let initial_nat_profile = nat_profile.read().await.clone();
    let initial_refresh_needs_public_retry = initial_snapshot.as_ref().is_none_or(|snapshot| {
        !has_reliable_public_candidate(
            initial_nat_profile.as_ref(),
            &snapshot.candidates,
            &snapshot.candidate_sources,
        )
    });
    let initial_pool_mapping_warmup = should_warm_mapping_dependent_socket_pool(
        udp.socket_count(),
        udp.socket_pool_active(),
        initial_nat_profile.as_ref(),
    );
    let initial_refresh_needs_fast_retry =
        initial_refresh_needs_public_retry || initial_pool_mapping_warmup;
    let mut fast_retry_active = initial_refresh_needs_fast_retry;
    let mut ticker = interval(if fast_retry_active {
        CANDIDATE_REFRESH_NO_PUBLIC_RETRY_INTERVAL
    } else {
        CANDIDATE_REFRESH_INTERVAL
    });
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    if initial_refresh_needs_fast_retry {
        // The startup gather intentionally has a short budget.  If it only
        // produced a host candidate (or only an observer-specific mapping on
        // a hard NAT), retry discovery promptly instead of waiting for the
        // regular 15-second refresh interval.
        sleep(CANDIDATE_REFRESH_INITIAL_RETRY_DELAY).await;
    }
    // The initial UDP setup already committed the first full candidate
    // snapshot.  When that snapshot already contains a real public mapping,
    // consume Tokio's immediate first tick so startup does not launch a
    // duplicate refresh in the middle of peer/session establishment.  A
    // host-only snapshot deliberately keeps the immediate tick: it is the
    // first bounded retry that can discover a public mapping without waiting
    // for the normal 15-second cadence.
    if !initial_refresh_needs_fast_retry {
        ticker.tick().await;
    }
    let mut pending_volatile: Option<VolatileCandidatePublish> = None;
    let mut volatile_coalescer = VolatilePublishCoalescer::default();

    loop {
        // A 15-second refresh cadence must not become the publication
        // cadence for a volatile candidate.  Wait for either the normal
        // gather tick or the fixed debounce deadline, whichever comes first.
        // The latter is what prevents a changed NAT mapping from sitting in
        // the committed snapshot while the peer keeps using an old endpoint.
        let wake_reason = if let Some(deadline) = volatile_coalescer.pending_deadline() {
            tokio::select! {
                // Prefer a periodic refresh when both futures are ready. The
                // volatile publication is flushed below before the periodic
                // gather, so neither event is lost and only the periodic
                // branch may start STUN/gateway discovery.
                biased;
                _ = ticker.tick() => RefreshWakeReason::Periodic,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => RefreshWakeReason::VolatileDeadline,
            }
        } else {
            ticker.tick().await;
            RefreshWakeReason::Periodic
        };

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
                        candidate_snapshot: candidate_snapshot.clone(),
                        stun_servers: stun_servers.clone(),
                        stun_timeout,
                        boot_epoch_ms,
                    }),
                )
                .await;
                volatile_coalescer.record_published(hash);
                debug!(
                    target: "p2wlan_daemon::candidate_refresh",
                    event = "candidate_volatile_publish_completed",
                    hash,
                    candidate_count = pending.candidates.len(),
                    "Published coalesced volatile UDP candidate refresh"
                );
            } else {
                debug!(
                    "Suppressed volatile UDP candidate publication: coalesced set is identical to the last published set (hash={payload_hash})"
                );
            }
        }

        // A volatile deadline only flushes the already committed newest
        // candidate set. It must return to the scheduler here: falling
        // through into the gather below turns every debounce expiry into a
        // full STUN refresh and recreates the observed refresh storm. If a
        // periodic tick was simultaneously ready, `biased` selected it above
        // and this branch deliberately falls through to the legitimate gather.
        if !wake_reason.permits_full_gather() {
            debug!(
                target: "p2wlan_daemon::candidate_refresh",
                event = "candidate_volatile_publish_completed",
                wake_reason = ?wake_reason,
                "volatile candidate publication completed without a full gather"
            );
            continue;
        }

        let gather_started = Instant::now();
        debug!(
            target: "p2wlan_daemon::candidate_refresh",
            event = "candidate_gather_started",
            wake_reason = ?wake_reason,
            network_generation = peers.current_network_generation_sync(),
            stun_query_count = stun_servers.len(),
            pool_socket_count = udp.socket_count(),
            "UDP candidate refresh started"
        );

        // STUN and gateway mapping are both slow, best-effort discovery
        // operations. Run them concurrently without holding the shared
        // candidate lock. A peer signal must be able to reuse the last
        // committed snapshot while either discovery path is in flight.
        let mapping_future = async {
            if !upnp_enabled {
                return (Vec::new(), HashMap::new());
            }
            let mapping_started = Instant::now();
            debug!(
                target: "p2wlan_daemon::candidate_refresh",
                "UDP candidate refresh gateway mapping started outside refresh lock"
            );
            let mut discovered = Vec::new();
            let mut discovered_sources = HashMap::new();
            maybe_add_port_mapping_udp_candidate(
                udp.local_addr().ok(),
                &mut discovered,
                &mut discovered_sources,
                gateway_mapping_runtime.clone(),
                gateway_mapping_diagnostics.clone(),
            )
            .await;
            info!(
                target: "p2wlan_daemon::candidate_refresh",
                mapping_elapsed_ms = mapping_started.elapsed().as_millis() as u64,
                candidate_count = discovered.len(),
                "UDP candidate refresh gateway mapping completed"
            );
            (discovered, discovered_sources)
        };
        let profiler = crate::dataplane::global_dataplane_profiler();
        profiler.set_candidate_gather_active(true);
        let (report_result, (mapped_candidates, mapped_sources)) = tokio::join!(
            udp.gather_candidate_report_live_parallel_full(stun_servers.clone(), stun_timeout),
            mapping_future,
        );
        profiler.set_candidate_gather_active(false);
        let gather_elapsed_ms = gather_started.elapsed().as_millis() as u64;
        let refresh_lock_wait_started = Instant::now();
        let refresh_guard = candidate_refresh_lock.lock().await;
        let refresh_lock_wait_ms = refresh_lock_wait_started.elapsed().as_millis() as u64;

        let report = match report_result {
            Ok(report) => report,
            Err(err) => {
                warn!(
                    target: "p2wlan_daemon::candidate_refresh",
                    event = "candidate_gather_completed",
                    wake_reason = ?wake_reason,
                    refresh_lock_wait_ms,
                    gather_elapsed_ms,
                    stun_query_count = stun_servers.len(),
                    pool_socket_count = udp.socket_count(),
                    candidate_count = 0,
                    "Periodic UDP candidate refresh failed: {err}"
                );
                continue;
            }
        };
        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        debug!(
            target: "p2wlan_daemon::candidate_refresh",
            event = "candidate_gather_completed",
            wake_reason = ?wake_reason,
            refresh_lock_wait_ms,
            gather_elapsed_ms,
            stun_query_count = report.nat_profile.observations.len(),
            pool_socket_count = udp.socket_count(),
            candidate_count = candidates.len(),
            "UDP candidate refresh gather completed"
        );
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
                &candidate_sources,
                include_host_candidate,
            )
        });
        if let Some(endpoint) = advertised_endpoint.as_ref() {
            // The advertised endpoint is the peer's PRIMARY punch target and
            // must be FIRST in the signaled order (the receiver preserves
            // signal order as its probe priority).  A private host candidate
            // first made the peer punch an unreachable private address
            // (field evidence: v0.1.116 acceptance rounds timed out at
            // ~102 s); moving the public mapping to the front unconditionally
            // (it is already present from gathering) fixes the priority.
            if let Some(index) = candidates
                .iter()
                .position(|candidate| candidate == endpoint)
            {
                candidates.remove(index);
            }
            candidates.insert(0, endpoint.clone());
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

        for endpoint in mapped_candidates {
            if !candidates.contains(&endpoint) {
                candidates.push(endpoint.clone());
            }
            if let Some(source) = mapped_sources.get(&endpoint) {
                candidate_sources.insert(endpoint, source.clone());
            }
        }

        // The Gather cadence is a state machine, not a one-shot startup
        // smoothing.  An intermittent UDP blackhole can flip the profile to
        // `UdpBlocked` (or lose the public mapping) after startup already
        // recovered; without a re-entry path the next discovery attempt would
        // wait for the full 15-second interval.  Re-enter the fast retry
        // cadence whenever the committed profile stops providing a reliable
        // public mapping (field evidence: fresh-mapping acceptance rounds
        // where a recovered NAT still took 8-26s to converge because
        // discovery had stepped back to the slow cadence).
        let reliable_public = has_reliable_public_candidate(
            Some(&report.nat_profile),
            &candidates,
            &candidate_sources,
        );
        let want_fast = !reliable_public;
        if want_fast != fast_retry_active {
            fast_retry_active = want_fast;
            let interval_ms = if fast_retry_active {
                CANDIDATE_REFRESH_NO_PUBLIC_RETRY_INTERVAL
            } else {
                CANDIDATE_REFRESH_INTERVAL
            };
            ticker = interval(interval_ms);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Consume the new interval's immediate tick; the next periodic
            // refresh happens one full cadence later.
            ticker.tick().await;
            if reliable_public {
                info!(
                    target: "p2wlan_daemon::candidate_refresh",
                    "UDP candidate refresh found a real public candidate; returning to the normal refresh interval"
                );
            } else {
                info!(
                    target: "p2wlan_daemon::candidate_refresh",
                    "UDP candidate refresh lost its reliable public mapping (mapping={:?}, public={:?}, stun={}/{}); re-entering the fast retry interval",
                    report.nat_profile.mapping_behavior,
                    report.nat_profile.public_endpoint,
                    report
                        .nat_profile
                        .observations
                        .iter()
                        .filter(|observation| observation.mapped_address.is_some())
                        .count(),
                    report.nat_profile.observations.len(),
                );
            }
        }
        let previous_snapshot = candidate_snapshot.read().await.clone();
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
        let public_candidate_readiness_changed = public_candidate_readiness_changed(
            &previous_candidates,
            &previous_candidate_sources,
            &candidates,
            &candidate_sources,
        );

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

        publish_candidate_snapshot_to_store(
            &candidate_snapshot,
            candidates.clone(),
            candidate_sources.clone(),
            next_network_identity.clone(),
        )
        .await;
        // These mirrors remain for legacy diagnostics and readiness checks;
        // all coherent candidate/source/identity reads use the committed
        // snapshot above.
        *local_candidates.write().await = candidates.clone();
        *local_candidate_sources.write().await = candidate_sources.clone();
        *local_network_identity.write().await = next_network_identity.clone();

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
                // `network_identity_changed` only becomes true when an
                // existing physical/public identity was replaced.  That is
                // a real handover, not ordinary candidate churn: carrying a
                // confirmed Direct pair into the new generation would make
                // the fan-out below skip the offer/punch that must rebuild
                // the path on the new network.
                .advance_network_generation("UDP network identity changed")
                .await;
        }
        drop(refresh_guard);

        // A pending volatile publication belongs to the old candidate state.
        // Do not allow it to reappear after a generation or public-readiness
        // transition and reintroduce an obsolete endpoint.
        if should_advance_generation || public_candidate_readiness_changed {
            pending_volatile = None;
            volatile_coalescer = VolatilePublishCoalescer::default();
        }

        let should_update_endpoint = should_advance_generation
            || should_update_stable_control_endpoint(
                published_endpoint.as_deref(),
                &endpoint,
                report.nat_profile.mapping_behavior,
            );
        if should_update_endpoint {
            let nat_type = report
                .nat_profile
                .control_label_with_generation(peers.current_local_profile_generation_sync());
            if let Err(err) = control.update_endpoint(&endpoint, &nat_type).await {
                warn!("Failed to publish refreshed UDP endpoint '{endpoint}': {err}");
            } else if !endpoint.is_empty() {
                published_endpoint = Some(endpoint.clone());
            }
        }

        if !should_advance_generation && !public_candidate_readiness_changed {
            debug!(
                "UDP candidate refresh changed only volatile reflexive ports; keeping network generation and signaling stable"
            );
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
                    debug!(
                        "Volatile candidate churn coalesced newest-wins (hash={hash}); retaining the fixed {}-ms publication deadline without offer fan-out",
                        VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE.as_millis()
                    );
                }
                VolatileChurnAction::SchedulePublish => {
                    pending_volatile = Some(VolatileCandidatePublish {
                        candidates: candidates.clone(),
                        candidate_sources: candidate_sources.clone(),
                    });
                    debug!(
                        "Volatile candidate churn (hash={hash}) will be published once after the {}-ms fixed debounce window",
                        VOLATILE_CANDIDATE_PUBLISH_DEBOUNCE.as_millis()
                    );
                }
            }
            continue;
        }

        if public_candidate_readiness_changed {
            info!(
                "UDP candidate readiness changed; publishing immediately instead of volatile debounce (has_real_public_candidate={})",
                has_real_public_candidate(&candidates, &candidate_sources)
            );
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
                candidate_snapshot: candidate_snapshot.clone(),
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

    let fanout_permits = Arc::new(tokio::sync::Semaphore::new(4));
    let mut fanout_workers = tokio::task::JoinSet::new();
    for (peer_id, peer_info) in control.peers().await {
        // The control roster can retain historical devices and may still
        // report them as online for one poll interval after their daemon has
        // gone away.  Candidate refresh is a dataplane wake-up, not a roster
        // cleanup job: sending offers to those records creates relay
        // `peer_not_found` traffic and, with a bounded fan-out semaphore,
        // delays the live peer's fresh public endpoint.  Lifecycle state in
        // PeerManager is the authoritative local admission gate.
        if !peer_info.online || !peers.peer_online(&peer_id).await {
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
        let Ok(permit) = fanout_permits.clone().acquire_owned().await else {
            break;
        };
        let control = control.clone();
        let peers = peers.clone();
        let udp = udp.clone();
        let punch_deduplicator = punch_deduplicator.clone();
        let candidates = candidates.to_vec();
        let candidate_sources = candidate_sources.clone();
        let signal = signal.clone();
        let reason = reason.to_string();
        fanout_workers.spawn(async move {
            let _permit = permit;
            let punch_at_ms = Some(relay_assisted_punch_at_ms());
            if let Err(error) = control
                .send_peer_offer_with_sources_and_punch_at(
                    &peer_id,
                    &candidates,
                    &candidate_sources,
                    &[],
                    punch_at_ms,
                    None,
                )
                .await
            {
                warn!("Failed to publish {reason} UDP candidates to peer {peer_id}: {error}");
                return;
            }

            debug!(
                "Published {reason} UDP candidates to peer {peer_id} with punch_at_ms={punch_at_ms:?}"
            );
            spawn_hole_punch_task(
                udp,
                peers,
                punch_deduplicator,
                peer_id,
                probe_interval,
                attempts,
                punch_at_ms,
                signal,
                None,
                None,
            )
            .await;
        });
    }
    while let Some(result) = fanout_workers.join_next().await {
        if let Err(error) = result {
            debug!(?error, "background candidate fan-out worker stopped");
        }
    }
}
