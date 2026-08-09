impl UdpTransport {
    /// Keep mapping-dependent local NAT bindings warm toward one stable peer endpoint.
    ///
    /// This is intentionally separate from the bounded candidate punch: a
    /// symmetric/hard NAT side should maintain one destination-specific binding
    /// from every bound traversal socket while the easier peer scans the hard
    /// side's predicted/birthday window.
    pub async fn spawn_nat_binding_maintainer(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        interval: Duration,
        duration: Duration,
    ) -> bool {
        if interval.is_zero() || duration.is_zero() {
            return false;
        }

        let now = Instant::now();
        let expires_at = now + duration;
        let socket_count = self.socket_count();
        if socket_count == 0 {
            return false;
        }

        let mut started_socket_leases = Vec::with_capacity(socket_count);
        let mut suppressed_socket_indices = Vec::new();
        {
            let mut maintainers = self.nat_maintainers.lock().await;
            maintainers.retain(|_, lease| lease.expires_at > now);

            for socket_index in 0..socket_count {
                let key = (peer_id.to_string(), endpoint, socket_index);
                if let Some(existing_lease) = maintainers.get_mut(&key) {
                    existing_lease.renew_until(expires_at);
                    suppressed_socket_indices.push(socket_index);
                    continue;
                }
                let lease = NatMaintainerLease::new(expires_at);
                let worker_token = lease.worker_token.clone();
                maintainers.insert(key, lease);
                started_socket_leases.push((socket_index, worker_token));
            }
        }

        if !suppressed_socket_indices.is_empty() {
            self.peers
                .record_direct_event(
                    peer_id,
                    "nat_maintainer_suppressed",
                    Some(endpoint),
                    Some(socket_count),
                    None,
                    format!(
                        "suppressed overlapping NAT-state maintainer sockets={suppressed_socket_indices:?} target={endpoint}"
                    ),
                )
                .await;
        }

        if started_socket_leases.is_empty() {
            return false;
        }

        for (socket_index, worker_token) in started_socket_leases {
            let transport = self.clone();
            let peers = self.peers.clone();
            let peer_id = peer_id.to_string();
            let key = (peer_id.clone(), endpoint, socket_index);
            let initial_delay = nat_maintainer_initial_delay(interval, socket_index, socket_count);
            tokio::spawn(async move {
                peers
                    .record_direct_event(
                        &peer_id,
                        "nat_maintainer_started",
                        Some(endpoint),
                        Some(socket_count),
                        None,
                        format!(
                            "maintaining hard-NAT binding socket_index={socket_index} target={endpoint} for {}ms every {}ms initial_delay_ms={}",
                            duration.as_millis(),
                            interval.as_millis(),
                            initial_delay.as_millis()
                        ),
                    )
                    .await;

                let mut sent = 0u32;
                let mut skipped = 0u32;
                let mut last_skip_reason = None;
                let mut stop_reason = "duration_elapsed";
                let mut lease_finished = false;

                if !initial_delay.is_zero() {
                    let lease_status = {
                        let mut maintainers = transport.nat_maintainers.lock().await;
                        nat_maintainer_lease_status(
                            &mut maintainers,
                            &key,
                            &worker_token,
                            Instant::now(),
                        )
                    };
                    match lease_status {
                        NatMaintainerLeaseStatus::Active(deadline) => {
                            let remaining =
                                deadline.saturating_duration_since(Instant::now());
                            if !remaining.is_zero() {
                                sleep(initial_delay.min(remaining)).await;
                            }
                        }
                        NatMaintainerLeaseStatus::Expired => {
                            lease_finished = true;
                        }
                        NatMaintainerLeaseStatus::Replaced => {
                            stop_reason = "lease_replaced";
                            lease_finished = true;
                        }
                    }
                }

                loop {
                    if lease_finished {
                        break;
                    }
                    if peers.is_direct(&peer_id).await {
                        stop_reason = "direct_confirmed";
                        break;
                    }
                    let lease_status = {
                        let mut maintainers = transport.nat_maintainers.lock().await;
                        nat_maintainer_lease_status(
                            &mut maintainers,
                            &key,
                            &worker_token,
                            Instant::now(),
                        )
                    };
                    match lease_status {
                        NatMaintainerLeaseStatus::Active(_) => {}
                        NatMaintainerLeaseStatus::Expired => break,
                        NatMaintainerLeaseStatus::Replaced => {
                            stop_reason = "lease_replaced";
                            break;
                        }
                    }

                    match transport
                        .admit_outbound_connectivity_probe(&peer_id, endpoint, socket_index)
                        .await
                    {
                        OutboundProbeAdmission::Accepted => {
                            match transport
                                .send_probe_from_socket(socket_index, Some(&peer_id), endpoint)
                                .await
                            {
                                Ok(_) => {
                                    sent = sent.saturating_add(1);
                                    transport
                                        .update_socket_diagnostics(socket_index, |metrics| {
                                            metrics.nat_maintainer_probes_sent = metrics
                                                .nat_maintainer_probes_sent
                                                .saturating_add(1);
                                        })
                                        .await;
                                    peers.record_direct_probe_sent(&peer_id, endpoint).await;
                                }
                                Err(err) => {
                                    stop_reason = "send_error";
                                    peers
                                        .record_direct_event(
                                            &peer_id,
                                            "nat_maintainer_send_error",
                                            Some(endpoint),
                                            Some(socket_count),
                                            Some(sent),
                                            format!(
                                                "NAT-state maintainer send failed socket_index={socket_index} target={endpoint}: {err}"
                                            ),
                                        )
                                        .await;
                                    break;
                                }
                            }
                        }
                        limited => {
                            skipped = skipped.saturating_add(1);
                            last_skip_reason = Some(outbound_probe_admission_reason(limited));
                            transport
                                .update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.nat_maintainer_probe_skips =
                                        metrics.nat_maintainer_probe_skips.saturating_add(1);
                                })
                                .await;
                        }
                    }

                    let lease_status = {
                        let mut maintainers = transport.nat_maintainers.lock().await;
                        nat_maintainer_lease_status(
                            &mut maintainers,
                            &key,
                            &worker_token,
                            Instant::now(),
                        )
                    };
                    match lease_status {
                        NatMaintainerLeaseStatus::Active(deadline) => {
                            let remaining =
                                deadline.saturating_duration_since(Instant::now());
                            sleep(interval.min(remaining)).await;
                        }
                        NatMaintainerLeaseStatus::Expired => break,
                        NatMaintainerLeaseStatus::Replaced => {
                            stop_reason = "lease_replaced";
                            break;
                        }
                    }
                }

                {
                    let mut maintainers = transport.nat_maintainers.lock().await;
                    remove_nat_maintainer_lease_if_owned(
                        &mut maintainers,
                        &key,
                        &worker_token,
                    );
                }

                peers
                    .record_direct_event(
                        &peer_id,
                        "nat_maintainer_stopped",
                        Some(endpoint),
                        Some(socket_count),
                        Some(sent),
                        format!(
                            "stopped NAT-state maintainer socket_index={socket_index} target={endpoint} reason={stop_reason} sent={sent} skipped={skipped} last_skip_reason={}",
                            last_skip_reason.unwrap_or("none")
                        ),
                    )
                    .await;
            });
        }

        true
    }

    /// Send active UDP probes to every candidate for a peer.
    pub async fn punch_candidates(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        self.punch_candidates_with_socket_policy(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::ActivePool,
        )
        .await
        .map(|report| report.packets_sent)
    }

    /// Remote-scatter variant of [`Self::punch_candidates_until_not_direct`]:
    /// wide sweeps must also stop within one probe once the peer turns
    /// Direct instead of finishing their multi-thousand-probe window.
    #[cfg(test)]
    pub(crate) async fn punch_candidates_remote_scatter_pool_until_not_direct(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        self.punch_candidates_remote_scatter_pool_until_not_direct_report(
            peer_id,
            candidates,
            probe_interval,
            attempts,
        )
        .await
        .map(|report| report.packets_sent)
    }

    /// Report-preserving variant of
    /// [`Self::punch_candidates_remote_scatter_pool_until_not_direct`]: the
    /// caller needs the budget/epoch verdicts to schedule the next recovery
    /// step instead of swallowing a zero-send session.
    pub(crate) async fn punch_candidates_remote_scatter_pool_until_not_direct_report(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        let gate_peer = peer_id.to_string();
        let peers = self.peers.clone();
        self.punch_candidates_with_socket_policy_and_direct_gate(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::RemoteScatterPool,
            &move || !peers.is_direct_sync(&gate_peer),
        )
        .await
    }

    /// Stable-unique-scatter variant of
    /// [`Self::punch_candidates_until_not_direct`].
    pub(crate) async fn punch_candidates_stable_unique_scatter_until_not_direct(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        let gate_peer = peer_id.to_string();
        let peers = self.peers.clone();
        self.punch_candidates_with_socket_policy_and_direct_gate(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::StableUniqueScatter,
            &move || !peers.is_direct_sync(&gate_peer),
        )
        .await
    }

    /// Punch through the active pool with a per-probe Direct gate.
    ///
    /// The synchronized punch tasks use this so a session scheduled before
    /// Direct confirmation stops within one probe once the peer turns Direct:
    /// the ordinary `punch_candidates` is not enough, because a 96-candidate
    /// sweep can keep emitting for ~2 s after the promotion lands.
    pub(crate) async fn punch_candidates_until_not_direct(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        self.punch_candidates_until_not_direct_report(peer_id, candidates, probe_interval, attempts)
            .await
            .map(|report| report.packets_sent)
    }

    /// Report-preserving variant of
    /// [`Self::punch_candidates_until_not_direct`]: the caller needs the
    /// budget/epoch verdicts to schedule the next recovery step instead of
    /// swallowing a zero-send session.
    pub(crate) async fn punch_candidates_until_not_direct_report(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        let gate_peer = peer_id.to_string();
        let peers = self.peers.clone();
        self.punch_candidates_with_socket_policy_and_direct_gate(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::ActivePool,
            &move || !peers.is_direct_sync(&gate_peer),
        )
        .await
    }

    /// Send active UDP probes only from the primary socket.
    ///
    /// This is reserved for explicit single-socket diagnostics and tests. The
    /// hard-NAT binding maintainer sends on socket 0 directly, while normal
    /// synchronized/retry punching uses the active pool so alternate sockets
    /// can open peer-specific NAT filter state instead of only publishing
    /// STUN-observed mappings.
    pub async fn punch_candidates_primary_socket(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        self.punch_candidates_with_socket_policy(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::PrimaryOnly,
        )
        .await
        .map(|report| report.packets_sent)
    }

    async fn punch_candidates_with_socket_policy(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        socket_policy: PunchSocketPolicy,
    ) -> Result<PunchSendReport> {
        self.punch_candidates_with_socket_policy_and_direct_gate(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            socket_policy,
            &|| true,
        )
        .await
    }

    /// The shared punch core with a per-probe Direct gate.
    ///
    /// `direct_gate` is re-evaluated before every probe emission so a session
    /// that was scheduled before Direct confirmation stops within one probe
    /// (~6 ms pacing) once the peer's state turns Direct.  The gate must be
    /// cheap and synchronous; the punch loops pass
    /// `peers.is_direct_sync(&peer_id)`, which only locks the peer-state
    /// mirror.
    async fn punch_candidates_with_socket_policy_and_direct_gate(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        socket_policy: PunchSocketPolicy,
        direct_gate: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<PunchSendReport> {
        if candidates.is_empty() || attempts == 0 {
            return Ok(PunchSendReport::default());
        }

        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        trace!(
            "Built adaptive UDP probe schedule for peer {}: {} rounds across {} candidates",
            peer_id,
            schedule.len(),
            candidates.len()
        );

        let mut packets_sent = 0;
        let mut budget_skipped = 0u32;
        let mut wholesale_rejections = 0u32;
        let mut last_budget_reason = None;
        let mut session_capped = false;
        let mut epoch_budget_exhausted = false;
        let mut candidate_iteration_capped = false;
        let mut generation_changed_abort = false;
        let mut commit_seq_changed_abort = false;
        let mut sent_endpoints = HashSet::new();
        let mut sent_ports = HashSet::new();
        let mut socket0_sent = 0u32;
        let mut alt_socket_sent = 0u32;
        let socket_count = socket_policy.socket_count(self);
        let generation_at_start = self.peers.current_network_generation_sync();
        // Monotonic direct-commit sequence snapshot: a promotion (or a
        // direct-endpoint change) bumps this sequence synchronously inside
        // the network-epoch critical section, so the per-probe gate below can
        // abort the sweep within one probe even when `yield_now()` would not
        // have let the inbound handler preempt this task.
        let commit_seq_at_start = self.peers.direct_commit_seq_sync(peer_id);
        let session_probe_cap = match socket_policy {
            PunchSocketPolicy::RemoteScatterPool | PunchSocketPolicy::StableUniqueScatter => {
                MAX_REMOTE_SCATTER_PUNCH_PROBES_PER_SESSION
            }
            PunchSocketPolicy::ActivePool | PunchSocketPolicy::PrimaryOnly => {
                MAX_PUNCH_PROBES_PER_SESSION
            }
        };
        // The combined gate: Direct confirmed, a newer direct commit, or a
        // network-generation change aborts the sweep immediately.
        let commit_aborted = |transport: &UdpTransport| {
            transport.peers.direct_commit_seq_sync(peer_id) != commit_seq_at_start
        };
        'schedule: for (round_index, round) in schedule.iter().enumerate() {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }

            let probe_order = match socket_policy {
                PunchSocketPolicy::ActivePool | PunchSocketPolicy::RemoteScatterPool
                    if socket_count > 1 =>
                {
                    // Hard NAT traversal needs the alternate sockets to send real
                    // peer-directed traffic, not just STUN probes. Candidate-major
                    // ordering gives every high-priority remote port a chance from
                    // each active local socket before the per-peer/IP budget or
                    // session cap is exhausted.
                    let mut order = Vec::with_capacity(round.endpoints.len() * socket_count);
                    for &candidate in &round.endpoints {
                        for socket_index in 0..socket_count {
                            order.push((socket_index, candidate));
                        }
                    }
                    order
                }
                _ => {
                    // Primary-only scans and single-socket fallback keep the
                    // original stable source-port sweep semantics.
                    let mut order = Vec::with_capacity(round.endpoints.len() * socket_count);
                    for socket_index in 0..socket_count {
                        for &candidate in &round.endpoints {
                            order.push((socket_index, candidate));
                        }
                    }
                    order
                }
            };

            // The sweep is split into finite batches.  Every batch boundary
            // yields the scheduler and re-checks Direct, the network
            // generation and the session cap, so a large candidate set can
            // never be emitted in one non-preemptible burst and a Direct
            // promotion or a network change always lands before the next
            // batch starts.
            let mut cursor = 0usize;
            loop {
                if !direct_gate() {
                    // Direct was confirmed while this session was in flight:
                    // stop emitting peer-directed probes immediately instead
                    // of completing the stale sweep on a confirmed path.
                    trace!(
                        "Aborting UDP punch session for peer {peer_id}: Direct was confirmed mid-session"
                    );
                    break 'schedule;
                }
                if commit_aborted(self) {
                    // The direct-commit sequence advanced (promotion or
                    // direct-endpoint change): every later probe would be a
                    // post-promotion send, so the sweep stops within one
                    // probe of the commit.
                    commit_seq_changed_abort = true;
                    trace!(
                        "Aborting UDP punch session for peer {peer_id}: direct_commit_seq advanced past {commit_seq_at_start:?} mid-session"
                    );
                    break 'schedule;
                }
                if self.peers.current_network_generation_sync() != generation_at_start {
                    generation_changed_abort = true;
                    break 'schedule;
                }
                if packets_sent >= session_probe_cap {
                    session_capped = true;
                    break 'schedule;
                }
                if cursor >= probe_order.len() {
                    break;
                }

                let mut batch_sent = 0usize;
                while cursor < probe_order.len() && batch_sent < OUTBOUND_PROBE_BATCH_SIZE {
                    let (socket_index, candidate) = probe_order[cursor];
                    cursor += 1;
                    if !direct_gate() {
                        // Direct was confirmed while this session was in
                        // flight: stop emitting peer-directed probes
                        // immediately instead of completing the stale sweep
                        // on a confirmed path.
                        trace!(
                            "Aborting UDP punch session for peer {peer_id}: Direct was confirmed mid-session"
                        );
                        break 'schedule;
                    }
                    if commit_aborted(self) {
                        commit_seq_changed_abort = true;
                        trace!(
                            "Aborting UDP punch session for peer {peer_id}: direct_commit_seq advanced past {commit_seq_at_start:?} mid-session"
                        );
                        break 'schedule;
                    }
                    if packets_sent >= session_probe_cap {
                        session_capped = true;
                        break 'schedule;
                    }
                    // The recovery epoch's hard candidate-iteration budget:
                    // every endpoint enumerated here consumes one unit, so a
                    // budget-rejected session can never keep traversing the
                    // whole 778/3072-entry endpoint list.  A capped epoch
                    // stops enumerating immediately.
                    if !self
                        .peers
                        .try_consume_recovery_candidate_iterations(peer_id, 1)
                        .await
                    {
                        candidate_iteration_capped = true;
                        break 'schedule;
                    }
                    // A wholesale-rejected sweep must not keep enumerating
                    // candidates: after this many consecutive persistent
                    // rejections without a single send the window is refused
                    // across the whole epoch and the caller must enter the
                    // budget-exhausted backoff instead of re-planning.  The
                    // short 1-second sliding budgets (network/peer/remote-IP)
                    // refill while a wide scatter sweep is still in flight, so
                    // their pacing rejections must NOT trip this abort; only
                    // the persistent long-window limits never refill within
                    // the session.
                    if wholesale_rejections >= MAX_BUDGET_REJECTIONS_PER_SESSION {
                        break 'schedule;
                    }
                    if socket_policy == PunchSocketPolicy::StableUniqueScatter
                        && sent_endpoints.len() < candidates.len()
                        && sent_endpoints.contains(&candidate)
                    {
                        continue;
                    }
                    match self
                        .admit_outbound_connectivity_probe(peer_id, candidate, socket_index)
                        .await
                    {
                        OutboundProbeAdmission::Accepted => {
                            wholesale_rejections = 0;
                        }
                        OutboundProbeAdmission::NetworkRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("network_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::PeerRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("peer_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::RemoteIpRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("remote_ip_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalNetworkRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_network_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalPeerRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_peer_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalRemoteIpRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_remote_ip_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalNetworkPersistentRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            wholesale_rejections = wholesale_rejections.saturating_add(1);
                            last_budget_reason = Some("global_network_persistent_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: persistent network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalPeerPersistentRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            wholesale_rejections = wholesale_rejections.saturating_add(1);
                            last_budget_reason = Some("global_peer_persistent_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: persistent peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalRemoteIpPersistentRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            wholesale_rejections = wholesale_rejections.saturating_add(1);
                            last_budget_reason = Some("global_remote_ip_persistent_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: persistent remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalPeerSocketPersistentRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            wholesale_rejections = wholesale_rejections.saturating_add(1);
                            last_budget_reason = Some("global_peer_socket_persistent_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: persistent peer socket probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::EpochCreditExhausted => {
                            // The recovery-epoch probe credit is a hard total:
                            // it cannot refill within the epoch, so the whole
                            // sweep must stop now instead of enumerating the
                            // rest of the window.  The caller turns this into
                            // the budget-exhausted backoff.
                            epoch_budget_exhausted = true;
                            last_budget_reason = Some("recovery_epoch_credit_exhausted");
                            trace!(
                                "Stopping UDP punch session for peer {peer_id}: recovery-epoch probe credit exhausted"
                            );
                            break 'schedule;
                        }
                    }

                    match self
                        .send_probe_from_socket(socket_index, Some(peer_id), candidate)
                        .await
                    {
                        Ok(_) => {
                            packets_sent += 1;
                            batch_sent = batch_sent.saturating_add(1);
                            if socket_index == 0 {
                                socket0_sent = socket0_sent.saturating_add(1);
                            } else {
                                alt_socket_sent = alt_socket_sent.saturating_add(1);
                            }
                            sent_endpoints.insert(candidate);
                            sent_ports.insert(candidate.port());
                            self.peers
                                .record_direct_probe_sent(peer_id, candidate)
                                .await;
                            trace!(
                                "Sent adaptive punch probe round {} from socket {} to peer {} candidate {} commit_seq={:?}",
                                round_index + 1,
                                socket_index,
                                peer_id,
                                candidate,
                                commit_seq_at_start
                            );
                            if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                                sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                            }
                        }
                        Err(err) => {
                            debug!(
                                "Failed to send punch probe from socket {} to peer {} candidate {}: {}",
                                socket_index, peer_id, candidate, err
                            );
                        }
                    }
                }

                // Batch boundary: yield so Direct promotion, network
                // generation advances and other tasks run before the next
                // batch is re-validated above.
                tokio::task::yield_now().await;
            }
        }

        if generation_changed_abort {
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_batch_generation_changed",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "stopped UDP punch after the network generation changed mid-session (expected {generation_at_start}); sent {packets_sent}"
                    ),
                )
                .await;
        }

        if commit_seq_changed_abort {
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_batch_commit_seq_changed",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "stopped UDP punch after direct_commit_seq advanced past {commit_seq_at_start:?} mid-session; sent {packets_sent} (all sends carried commit_seq={commit_seq_at_start:?})"
                    ),
                )
                .await;
        }

        if session_capped {
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_session_capped",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!("stopped UDP punch after the {session_probe_cap}-probe session cap"),
                )
                .await;
        }

        if candidate_iteration_capped {
            self.peers
                .record_direct_event(
                    peer_id,
                    "recovery_candidate_iteration_budget_exhausted",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "stopped enumerating UDP candidates after the recovery epoch's candidate-iteration budget was exhausted; sent {packets_sent}"
                    ),
                )
                .await;
        }

        if epoch_budget_exhausted {
            self.peers
                .record_direct_event(
                    peer_id,
                    "recovery_epoch_credit_exhausted",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "stopped UDP punch after the recovery epoch's probe credit was exhausted; sent {packets_sent} skipped {budget_skipped}"
                    ),
                )
                .await;
        }

        if budget_skipped > 0 {
            let reason = last_budget_reason.unwrap_or("probe_budget_limited");
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_budget_limited",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "skipped {budget_skipped} UDP punch probes due to outbound {reason}; sent {packets_sent}"
                    ),
                )
                .await;
        }

        let unique_target_ports = u32::try_from(sent_ports.len()).unwrap_or(u32::MAX);
        let repeated_target_ports = packets_sent.saturating_sub(unique_target_ports);
        let stage = match socket_policy {
            PunchSocketPolicy::ActivePool if socket_count > 1 => "active_pool_scan_completed",
            PunchSocketPolicy::RemoteScatterPool if socket_count > 1 => {
                "active_pool_scan_completed"
            }
            PunchSocketPolicy::ActivePool => "single_socket_scan_completed",
            PunchSocketPolicy::RemoteScatterPool => "single_socket_scan_completed",
            PunchSocketPolicy::StableUniqueScatter => "stable_unique_scan_completed",
            PunchSocketPolicy::PrimaryOnly => "primary_socket_scan_completed",
        };
        self.peers
            .record_direct_event_with_probe_coverage(
                peer_id,
                stage,
                candidates.first().copied(),
                Some(candidates.len()),
                Some(packets_sent),
                format!(
                    "scan_socket_policy={} active_sockets={} punch_sockets={} candidate_count={} attempts={} unique_target_endpoints={} unique_target_ports={} repeated_target_ports={} budget_skipped={budget_skipped} epoch_budget_exhausted={epoch_budget_exhausted} candidate_iteration_capped={candidate_iteration_capped} commit_seq={commit_seq_at_start:?} commit_seq_changed_abort={commit_seq_changed_abort}",
                    socket_policy.label(),
                    self.socket_count(),
                    socket_count,
                    candidates.len(),
                    attempts,
                    sent_endpoints.len(),
                    sent_ports.len(),
                    repeated_target_ports
                ),
                socket0_sent,
                alt_socket_sent,
                unique_target_ports,
                repeated_target_ports,
            )
            .await;
        info!(
            "{stage} peer_id={} scan_socket_policy={} active_sockets={} punch_sockets={} candidate_count={} attempts={} sent={} socket0_sent={} alt_socket_sent={} unique_target_endpoints={} unique_target_ports={} repeated_target_ports={} budget_skipped={budget_skipped} epoch_budget_exhausted={epoch_budget_exhausted} candidate_iteration_capped={candidate_iteration_capped} session_capped={session_capped} commit_seq={commit_seq_at_start:?} commit_seq_changed_abort={commit_seq_changed_abort}",
            peer_id,
            socket_policy.label(),
            self.socket_count(),
            socket_count,
            candidates.len(),
            attempts,
            packets_sent,
            socket0_sent,
            alt_socket_sent,
            sent_endpoints.len(),
            sent_ports.len(),
            repeated_target_ports,
        );

        Ok(PunchSendReport {
            packets_sent,
            unique_target_endpoints: u32::try_from(sent_endpoints.len()).unwrap_or(u32::MAX),
            budget_skipped,
            epoch_budget_exhausted,
            candidate_iteration_capped,
        })
    }

    /// Send a single encrypted packet.
    ///
    /// Returns `Ok(Some(bytes))` when sent, `Ok(None)` when no endpoint is known
    /// for the destination peer, and `Err` for socket-level failures.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<Option<usize>> {
        let Some(endpoint) = self.peers.direct_endpoint_for_send(&packet.peer_id).await else {
            trace!(
                "No UDP endpoint for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        self.send_packet_to(packet, endpoint).await.map(Some)
    }

    /// Send a single encrypted packet to a selector-provided direct endpoint.
    pub async fn send_packet_to(
        &self,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
        let (socket_index, socket) = match self.socket_for_peer(Some(&packet.peer_id)).await {
            Some(resolved) => resolved,
            None => return Err(DaemonError::Network(format!(
                "no UDP socket available for peer {}",
                packet.peer_id
            ))),
        };
        let sent = socket
            .send_to(&packet.wire_bytes, endpoint)
            .await
            .map_err(|e| {
                DaemonError::Network(format!(
                    "UDP send to {} for peer {} failed: {}",
                    endpoint, packet.peer_id, e
                ))
            })?;

        if sent != packet.wire_bytes.len() {
            return Err(DaemonError::Network(format!(
                "short UDP send to {} for peer {}: sent {} of {} bytes",
                endpoint,
                packet.peer_id,
                sent,
                packet.wire_bytes.len()
            )));
        }

        self.update_socket_diagnostics(socket_index, |metrics| metrics.encrypted_packets_sent += 1)
            .await;

        debug!(
            "Sent {} encrypted bytes to peer {} at {} (dst={})",
            sent, packet.peer_id, endpoint, packet.dst_ip
        );
        Ok(sent)
    }

    /// Consume encrypted packets until the channel closes.
    pub async fn run_outbound(self, mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
        while let Some(packet) = encrypted_rx.recv().await {
            match self.send_packet(&packet).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    debug!(
                        "Encrypted packet for peer {} has no UDP endpoint yet",
                        packet.peer_id
                    );
                }
                Err(err) => {
                    warn!("UDP transport send failed: {err}");
                }
            }
        }
    }

    /// Periodically refresh direct UDP NAT mappings.
    pub async fn run_keepalives(self, keepalive_interval: Duration) {
        if keepalive_interval.is_zero() {
            return;
        }

        let mut ticker = interval(keepalive_interval);
        loop {
            ticker.tick().await;

            self.run_keepalive_round(DIRECT_KEEPALIVE_ACK_TIMEOUT).await;
        }
    }

    async fn run_keepalive_round(&self, ack_timeout: Duration) {
        let mut sent = Vec::new();

        for (peer_id, endpoint) in self.peers.direct_endpoints().await {
            let socket_index = self.socket_index_for_peer(Some(&peer_id)).await;
            match self
                .send_probe_from_socket_with_nomination(
                    socket_index,
                    Some(&peer_id),
                    endpoint,
                    false,
                    PendingProbePurpose::ConsentCheck,
                )
                .await
            {
                Ok(nonce) => {
                    let local_endpoint = self
                        .pending_probes
                        .lock()
                        .await
                        .get(&nonce)
                        .and_then(|pending| pending.local_endpoint);
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "consent_check_sent",
                            Some(endpoint),
                            Some(1),
                            Some(1),
                            format!(
                                "sent direct UDP consent check to {endpoint} local_endpoint={}",
                                format_optional_endpoint(local_endpoint)
                            ),
                        )
                        .await;
                    trace!("Sent direct UDP keepalive to peer {peer_id} at {endpoint}");
                    sent.push((peer_id, endpoint, nonce));
                }
                Err(err) => {
                    self.peers
                        .record_direct_failure_with_code(
                            &peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            format!("direct keepalive to {endpoint} failed: {err}"),
                        )
                        .await;
                    debug!(
                        "Failed to send direct UDP keepalive to peer {peer_id} at {endpoint}: {err}"
                    );
                }
            }
        }

        if sent.is_empty() {
            return;
        }

        sleep(ack_timeout).await;
        for (peer_id, endpoint, nonce) in sent {
            let unanswered = self.pending_probes.lock().await.remove(&nonce);
            let Some(pending) = unanswered else {
                continue;
            };
            if pending.peer_id.as_deref() != Some(peer_id.as_str()) || pending.endpoint != endpoint
            {
                continue;
            }
            if pending.purpose == PendingProbePurpose::ConsentCheck {
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "consent_timeout",
                        Some(endpoint),
                        Some(1),
                        None,
                        format!(
                            "direct UDP consent ACK timed out for {endpoint} local_endpoint={}",
                            format_optional_endpoint(pending.local_endpoint)
                        ),
                    )
                    .await;
            }

            if self
                .peers
                .record_direct_keepalive_timeout_for_generation_with_local_endpoint(
                    &peer_id,
                    endpoint,
                    pending.generation,
                    pending.local_endpoint,
                )
                .await
            {
                debug!("Direct UDP keepalive ACK timed out for peer {peer_id} at {endpoint}");
            }
        }
    }
}

fn nat_maintainer_initial_delay(
    interval: Duration,
    socket_index: usize,
    socket_count: usize,
) -> Duration {
    if socket_index == 0 || socket_count <= 1 {
        return Duration::ZERO;
    }

    interval.mul_f64(socket_index as f64 / socket_count as f64)
}
