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

                    // The maintainer uses its own dedicated small budget and
                    // never consumes the recovery-epoch traversal credit or
                    // the shared outbound probe budgets: binding maintenance
                    // is not traversal work, and burning the epoch credit
                    // here would starve the real punches within minutes.
                    if transport
                        .admit_nat_maintainer_probe(&peer_id, socket_index)
                        .await
                    {
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
                    } else {
                        skipped = skipped.saturating_add(1);
                        last_skip_reason = Some("nat_maintainer_budget_limited");
                        transport
                            .update_socket_diagnostics(socket_index, |metrics| {
                                metrics.nat_maintainer_probe_skips =
                                    metrics.nat_maintainer_probe_skips.saturating_add(1);
                            })
                            .await;
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
            &|| true,
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
            &|| true,
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
            &|| true,
        )
        .await
    }

    /// Send the bounded latency-sensitive Direct prefix through every socket
    /// that is already bound, without enabling the transport-wide ActivePool
    /// policy for later peers or later recovery stages.
    pub(crate) async fn punch_candidates_fast_prefix_until_not_direct_report(
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
            PunchSocketPolicy::FastPrefixPool,
            &move || !peers.is_direct_sync(&gate_peer),
            &|| true,
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

    /// Send a deliberately tiny, cancellation-owned rendezvous window from
    /// one socket.  Peer-reflexive signaling uses this instead of the normal
    /// active-pool sweep: a shared rendezvous must not expand one fresh
    /// endpoint into candidate × socket traffic, and a revoked owner must
    /// stop before the next physical send.
    pub(crate) async fn punch_candidates_primary_socket_until_not_direct_gated_report(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        owner_gate: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<PunchSendReport> {
        let gate_peer = peer_id.to_string();
        let peers = self.peers.clone();
        self.punch_candidates_with_socket_policy_and_direct_gate(
            peer_id,
            candidates,
            probe_interval,
            attempts,
            PunchSocketPolicy::PrimaryOnly,
            &move || !peers.is_direct_sync(&gate_peer),
            owner_gate,
        )
        .await
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
    ///
    /// `owner_gate` is an additional per-probe gate that ordinary punches
    /// pass as `&|| true`.  The relay-backoff heartbeat worker passes its
    /// owner/cancel/peer/relay revalidation here so the sweep aborts within
    /// one probe once the worker's ownership was revoked, and re-checks it
    /// immediately before every actual UDP send.
    #[allow(clippy::too_many_arguments)]
    async fn punch_candidates_with_socket_policy_and_direct_gate(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        socket_policy: PunchSocketPolicy,
        direct_gate: &(dyn Fn() -> bool + Send + Sync),
        owner_gate: &(dyn Fn() -> bool + Send + Sync),
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
        // `packets_sent` intentionally remains the logical probe count used
        // by recovery accounting.  Keep actual kernel datagrams separately
        // so diagnostics can distinguish a legacy compatibility copy from a
        // second candidate attempt and report the socket that really sent.
        let mut first_send_at_ms = None;
        let mut per_socket_sent = HashMap::<usize, u32>::new();
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
            PunchSocketPolicy::FastPrefixPool
            | PunchSocketPolicy::ActivePool
            | PunchSocketPolicy::PrimaryOnly => {
                MAX_PUNCH_PROBES_PER_SESSION
            }
            PunchSocketPolicy::RelayBackoffHeartbeat => {
                RELAY_BACKOFF_HEARTBEAT_MAX_PROBES_PER_BEAT
            }
        };
        // The combined gate: Direct confirmed, a newer direct commit, or a
        // network-generation change aborts the sweep immediately.  The
        // heartbeat's owner gate is part of every gate decision so a revoked
        // owner stops at the same probe boundary.
        let commit_aborted = |transport: &UdpTransport| {
            transport.peers.direct_commit_seq_sync(peer_id) != commit_seq_at_start
        };
        let gates_ok = || direct_gate() && owner_gate();
        'schedule: for (round_index, round) in schedule.iter().enumerate() {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }

            let probe_order = match socket_policy {
                PunchSocketPolicy::FastPrefixPool
                | PunchSocketPolicy::ActivePool
                | PunchSocketPolicy::RemoteScatterPool
                | PunchSocketPolicy::RelayBackoffHeartbeat
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
                if !gates_ok() {
                    // Direct was confirmed or the heartbeat owner was revoked
                    // while this session was in flight: stop emitting
                    // peer-directed probes immediately instead of completing
                    // the stale sweep on a confirmed/revoked path.
                    trace!(
                        "Aborting UDP punch session for peer {peer_id}: Direct was confirmed or owner revoked mid-session"
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
                    if !gates_ok() {
                        // Direct was confirmed or the heartbeat owner was
                        // revoked while this session was in flight: stop
                        // emitting peer-directed probes immediately instead
                        // of completing the stale sweep on a
                        // confirmed/revoked path.
                        trace!(
                            "Aborting UDP punch session for peer {peer_id}: Direct was confirmed or owner revoked mid-session"
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
                    if self
                        .peers
                        .direct_probe_endpoint_quarantined(
                            peer_id,
                            candidate,
                            generation_at_start,
                        )
                        .await
                    {
                        budget_skipped = budget_skipped.saturating_add(1);
                        last_budget_reason = Some("direct_slow_relay_retained");
                        trace!(
                            "Skipped UDP punch probe from socket {} to peer {} candidate {}: recent slow ACK quarantine",
                            socket_index, peer_id, candidate
                        );
                        continue;
                    }
                    // The recovery epoch's hard candidate-iteration budget:
                    // every endpoint enumerated here consumes one unit, so a
                    // budget-rejected session can never keep traversing the
                    // whole 778/3072-entry endpoint list.  A capped epoch
                    // stops enumerating immediately.
                    if socket_policy != PunchSocketPolicy::RelayBackoffHeartbeat
                        && !self
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
                    let admission = if socket_policy == PunchSocketPolicy::RelayBackoffHeartbeat {
                        // Relay-backoff heartbeats deliberately do not use
                        // this generic candidate × socket sweep. Their
                        // dedicated path picks one endpoint group and one
                        // rotating local socket, then commits the budget only
                        // after the UDP send succeeds. Keep this branch
                        // closed so a future caller cannot restore the old
                        // multiplication storm.
                        OutboundProbeAdmission::HeartbeatBudgetLimited
                    } else {
                        self.admit_outbound_connectivity_probe(peer_id, candidate, socket_index)
                            .await
                    };
                    match admission {
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
                        OutboundProbeAdmission::HeartbeatBudgetLimited => {
                            // The heartbeat's dedicated budget is spent for
                            // this window; the next beat retries.  This is
                            // NOT a zero-send failure of the recovery epoch.
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("relay_backoff_heartbeat_budget_limited");
                            trace!(
                                "Skipped UDP heartbeat probe from socket {} to peer {} candidate {}: heartbeat budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                    }

                    let send_result = if socket_policy == PunchSocketPolicy::RelayBackoffHeartbeat {
                        // The owner gate is re-validated immediately before
                        // the actual UDP send: a cancel that landed between
                        // the batch checks and this point must still abort
                        // the beat without emitting one more packet.
                        if !owner_gate() {
                            trace!(
                                "Aborting heartbeat beat for peer {peer_id}: owner revoked before send"
                            );
                            break 'schedule;
                        }
                        #[cfg(test)]
                        {
                            let gate = self
                                .heartbeat_send_gate
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .clone();
                            if let Some(gate) = gate {
                                // Park the worker right before the send. The
                                // deterministic tests cancel the owner while
                                // it is parked and then release it: the
                                // re-validation below proves a cancelled
                                // worker never emits a post-cancel packet.
                                gate.reached.notify_one();
                                let _ = gate.release.wait().await;
                                if !owner_gate() {
                                    trace!(
                                        "Aborting heartbeat beat for peer {peer_id}: owner revoked while parked before send"
                                    );
                                    break 'schedule;
                                }
                            }
                        }
                        self.send_heartbeat_probe_from_socket(socket_index, peer_id, candidate)
                            .await
                    } else {
                        self.send_probe_from_socket_with_nomination_result(
                            socket_index,
                            Some(peer_id),
                            candidate,
                            false,
                            PendingProbePurpose::ConnectivityCheck,
                        )
                        .await
                    };
                    match send_result {
                        Ok(sent) => {
                            packets_sent += 1;
                            batch_sent = batch_sent.saturating_add(1);
                            if let Some(sent_at_ms) = sent.first_send_at_ms {
                                first_send_at_ms.get_or_insert(sent_at_ms);
                            }
                            let socket_datagrams = per_socket_sent.entry(sent.socket_index).or_default();
                            *socket_datagrams = socket_datagrams
                                .saturating_add(u32::from(sent.datagrams_sent));
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
        let mut per_socket_sent = per_socket_sent.into_iter().collect::<Vec<_>>();
        per_socket_sent.sort_unstable_by_key(|(socket_index, _)| *socket_index);
        let per_socket_summary = per_socket_sent
            .iter()
            .map(|(socket_index, sent)| format!("{socket_index}:{sent}"))
            .collect::<Vec<_>>()
            .join(",");
        let stage = match socket_policy {
            PunchSocketPolicy::FastPrefixPool => "fast_prefix_pool_scan_completed",
            PunchSocketPolicy::ActivePool if socket_count > 1 => "active_pool_scan_completed",
            PunchSocketPolicy::RemoteScatterPool if socket_count > 1 => {
                "active_pool_scan_completed"
            }
            PunchSocketPolicy::ActivePool => "single_socket_scan_completed",
            PunchSocketPolicy::RemoteScatterPool => "single_socket_scan_completed",
            PunchSocketPolicy::StableUniqueScatter => "stable_unique_scan_completed",
            PunchSocketPolicy::PrimaryOnly => "primary_socket_scan_completed",
            PunchSocketPolicy::RelayBackoffHeartbeat => "relay_backoff_heartbeat_beat_completed",
        };
        self.peers
            .record_direct_event_with_probe_coverage(
                peer_id,
                stage,
                candidates.first().copied(),
                Some(candidates.len()),
                Some(packets_sent),
                format!(
                    "scan_socket_policy={} active_sockets={} punch_sockets={} candidate_count={} attempts={} unique_target_endpoints={} unique_target_ports={} repeated_target_ports={} first_send_at_ms={first_send_at_ms:?} per_socket_actual_datagrams={per_socket_summary} budget_skipped={budget_skipped} epoch_budget_exhausted={epoch_budget_exhausted} candidate_iteration_capped={candidate_iteration_capped} commit_seq={commit_seq_at_start:?} commit_seq_changed_abort={commit_seq_changed_abort}",
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
            "{stage} peer_id={} scan_socket_policy={} active_sockets={} punch_sockets={} candidate_count={} attempts={} sent={} socket0_sent={} alt_socket_sent={} unique_target_endpoints={} unique_target_ports={} repeated_target_ports={} first_send_at_ms={first_send_at_ms:?} per_socket_actual_datagrams={per_socket_summary} budget_skipped={budget_skipped} epoch_budget_exhausted={epoch_budget_exhausted} candidate_iteration_capped={candidate_iteration_capped} session_capped={session_capped} commit_seq={commit_seq_at_start:?} commit_seq_changed_abort={commit_seq_changed_abort}",
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
            first_send_at_ms,
            per_socket_sent,
            budget_skipped,
            epoch_budget_exhausted,
            candidate_iteration_capped,
        })
    }

    /// Low-rate relay-backed recovery heartbeat for one peer.
    ///
    /// The relay carries the data plane while the direct path is down, so a
    /// double-NAT / rotating-egress pair can wait a long time for the rare
    /// five-tuple match that re-establishes Direct.  This task keeps probing
    /// the peer's trusted endpoints at a small sustained rate, independent of
    /// the recovery epoch's one-time credit and plan quotas (a frozen or
    /// quota-exhausted epoch can never silence it).  The heartbeat stops when
    /// the peer turns Direct or the relay safety net closes.
    pub(crate) async fn spawn_relay_backoff_heartbeat(
        &self,
        peer_id: &str,
        interval: Duration,
    ) -> bool {
        self.try_spawn_relay_backoff_heartbeat_worker(peer_id, interval)
    }

    /// Sync spawn entry point shared by the public async wrapper and the
    /// worker's own pending-restart path.
    ///
    /// It must be a plain function: the worker task that a pending restart
    /// spawns calls back into this same function, and a nested async block
    /// calling its own enclosing async fn would make the future type
    /// recursive (the worker block's future would contain the spawn
    /// function's future, which contains the worker block's future, ...)
    /// and could never satisfy `Send`.
    fn try_spawn_relay_backoff_heartbeat_worker(
        &self,
        peer_id: &str,
        interval: Duration,
    ) -> bool {
        if interval.is_zero() {
            return false;
        }
        let Some((owner_token, mut cancel_rx)) =
            self.register_relay_backoff_heartbeat(peer_id, interval)
        else {
            return false;
        };

        let transport = self.clone();
        let peers = self.peers.clone();
        let peer_id = peer_id.to_string();
        tokio::spawn(async move {
            let mut beats = 0u32;
            loop {
                if *cancel_rx.borrow()
                    || peers.is_direct_sync(&peer_id)
                    || !peers.peer_exists_sync(&peer_id)
                {
                    break;
                }
                let targets = peers.relay_backoff_heartbeat_targets_for(&peer_id).await;
                let Some(targets) = targets else {
                    // No relay safety net / peer gone: nothing to keep warm.
                    break;
                };
                if targets.is_empty() {
                    // A Relay peer without a trusted target has nothing for
                    // a heartbeat to maintain. Stop and release the owner so
                    // a later candidate signal can safely start a fresh one.
                    break;
                }
                // Per-send owner gate: before EVERY probe the sweep
                // re-validates that this worker is still the registered
                // owner, was not cancelled, and the peer/relay conditions
                // still hold.  A cancelled owner's lease has already been
                // moved to the registry's quitting set, so the gate fails at
                // the next probe boundary even if the worker was inside a
                // beat when the cancellation was requested.
                let owner_gate = {
                    let transport = transport.clone();
                    let peers = peers.clone();
                    let cancel_rx = cancel_rx.clone();
                    let peer_id = peer_id.clone();
                    move || {
                        if *cancel_rx.borrow() {
                            return false;
                        }
                        if !peers.peer_exists_sync(&peer_id)
                            || peers.is_direct_sync(&peer_id)
                            || !peers.relay_backoff_heartbeat_available_sync(&peer_id)
                        {
                            return false;
                        }
                        transport.relay_backoff_heartbeat_owner_valid_sync(
                            &peer_id,
                            owner_token,
                        )
                    }
                };
                let _ = transport
                    .punch_candidates_relay_backoff_heartbeat_gated(
                        &peer_id,
                        targets,
                        &owner_gate,
                    )
                    .await;
                beats = beats.saturating_add(1);
                if beats.is_multiple_of(15) {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "relay_backoff_heartbeat_active",
                            None,
                            None,
                            None,
                            format!(
                                "relay-backed recovery heartbeat beat {beats}: keeping the direct punch windows warm at {}ms cadence",
                                interval.as_millis()
                            ),
                        )
                        .await;
                }
                tokio::select! {
                    changed = cancel_rx.changed() => {
                        if changed.is_err() || *cancel_rx.borrow_and_update() {
                            break;
                        }
                    }
                    _ = sleep(interval) => {}
                }
            }
            if let Some(interval) =
                transport.complete_relay_backoff_heartbeat_exit(&peer_id, owner_token)
            {
                // A recovery trigger arrived while this worker was quitting:
                // the old worker has now confirmed it stopped sending, so
                // exactly one replacement may take over.
                transport.try_spawn_relay_backoff_heartbeat_worker(&peer_id, interval);
            }
        });
        true
    }

    /// Registration transaction for one heartbeat worker.
    ///
    /// Returns `Some((owner_token, cancel_rx))` only when the registry can
    /// make this worker send-capable immediately: no other worker is active
    /// for the peer, none is still quitting, and the transport has not been
    /// withdrawn.  A recovery trigger arriving while the old worker is still
    /// quitting is NOT lost: it is recorded as a pending restart and the old
    /// worker's exit path starts exactly one replacement.
    fn register_relay_backoff_heartbeat(
        &self,
        peer_id: &str,
        interval: Duration,
    ) -> Option<(u64, watch::Receiver<bool>)> {
        let mut registry = self
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.is_closed() {
            return None;
        }
        if registry.active.contains_key(peer_id) {
            return None;
        }
        if registry.quitting.contains_key(peer_id) {
            registry.pending_restarts.insert(
                peer_id.to_string(),
                PendingRelayBackoffHeartbeatRestart { interval },
            );
            return None;
        }
        let owner_token = next_relay_backoff_heartbeat_owner_token();
        #[cfg(test)]
        let started_at = Instant::now();
        let (cancel_tx, cancel_rx) = watch::channel(false);
        registry.active.insert(
            peer_id.to_string(),
            RelayBackoffHeartbeatLease {
                owner_token,
                #[cfg(test)]
                started_at,
                cancel_tx,
            },
        );
        Some((owner_token, cancel_rx))
    }

    #[cfg(test)]
    fn age_relay_backoff_heartbeat_for_test(&self, peer_id: &str, age: Duration) {
        let mut registry = self
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lease) = registry.active.get_mut(peer_id) {
            lease.started_at = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
        }
    }

    /// Cancel a peer's heartbeat immediately.
    ///
    /// The lease is moved from the send-capable set to the quitting set
    /// BEFORE the worker is signalled: the old worker's per-send owner gate
    /// fails from that instant, and a replacement can only be requested by a
    /// caller or a pending restart after the old worker has confirmed exit.
    /// Returns whether an active lease was revoked.
    pub(crate) fn cancel_relay_backoff_heartbeat(&self, peer_id: &str) -> bool {
        let mut registry = self
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(lease) = registry.active.remove(peer_id) else {
            return false;
        };
        let _ = lease.cancel_tx.send(true);
        registry.quitting.insert(peer_id.to_string(), lease);
        true
    }

    /// Cancel every heartbeat owned by this UDP transport instance during
    /// rebind or shutdown.  The registry is closed permanently: no worker may
    /// start or restart after the transport is withdrawn.
    pub(crate) fn cancel_all_relay_backoff_heartbeats(&self) {
        let leases = {
            let mut registry = self
                .relay_backoff_heartbeats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.mark_closed();
            registry.pending_restarts.clear();
            let mut leases = registry
                .active
                .drain()
                .map(|(_, lease)| lease)
                .collect::<Vec<_>>();
            leases.extend(registry.quitting.drain().map(|(_, lease)| lease));
            leases
        };
        for lease in leases {
            let _ = lease.cancel_tx.send(true);
        }
    }

    /// Worker exit handshake.
    ///
    /// Called exactly once by a worker that has stopped sending.  Removes the
    /// worker's own lease (from the active or the quitting set, owner-typed so
    /// a late exit can never erase a replacement) and returns the interval of
    /// a pending restart that arrived during the quit handshake, so the
    /// caller starts exactly one replacement.
    fn complete_relay_backoff_heartbeat_exit(
        &self,
        peer_id: &str,
        owner_token: u64,
    ) -> Option<Duration> {
        let mut registry = self
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = remove_heartbeat_lease_if_owned(&mut registry.active, peer_id, owner_token)
            || remove_heartbeat_lease_if_owned(&mut registry.quitting, peer_id, owner_token);
        if !removed {
            return None;
        }
        registry
            .pending_restarts
            .remove(peer_id)
            .map(|pending| pending.interval)
    }

    /// Whether `owner_token` is the current send-capable owner for the peer.
    ///
    /// The heartbeat's per-send gate calls this synchronously; once the lease
    /// leaves the active set (cancel, shutdown), the worker must stop sending
    /// at the next probe boundary.
    fn relay_backoff_heartbeat_owner_valid_sync(&self, peer_id: &str, owner_token: u64) -> bool {
        let registry = self
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry
            .active
            .get(peer_id)
            .is_some_and(|lease| lease.owner_token == owner_token)
    }

    /// Park at the final heartbeat send boundary in deterministic tests, then
    /// re-check ownership.  This preserves the quit-handshake invariant: a
    /// replacement is never allowed to overlap an old owner's UDP sends, and
    /// a cancellation while a worker is parked cannot leak one last packet.
    async fn relay_backoff_heartbeat_send_allowed(
        &self,
        peer_id: &str,
        generation: u64,
        owner_gate: &(dyn Fn() -> bool + Send + Sync),
    ) -> bool {
        let path_valid = || {
            owner_gate()
                && self.peers.peer_exists_sync(peer_id)
                && !self.peers.is_direct_sync(peer_id)
                && self.peers.current_network_generation_sync() == generation
        };
        if !path_valid() {
            return false;
        }
        #[cfg(test)]
        {
            let gate = self
                .heartbeat_send_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(gate) = gate {
                gate.reached.notify_one();
                let _ = gate.release.wait().await;
                if !path_valid() {
                    return false;
                }
            }
        }
        true
    }

    /// Emit diagnostics for exactly one relay-backoff heartbeat service beat.
    /// `packets_sent` is physical UDP datagrams accepted by the socket, not a
    /// candidate/socket attempt count.
    async fn record_relay_backoff_heartbeat_beat(
        &self,
        peer_id: &str,
        targets: &crate::peer::RelayBackoffHeartbeatTargetSet,
        target: Option<probe_budget::RelayBackoffHeartbeatTarget>,
        packets_sent: u32,
        budget_skipped: u32,
        reason: &str,
    ) {
        let endpoint = target.map(|target| target.endpoint);
        let socket_index = target.map(|target| target.socket_index);
        let target_group = target
            .map(|target| target.group.label())
            .unwrap_or("none");
        let socket0_sent = if socket_index == Some(0) {
            packets_sent
        } else {
            0
        };
        let alt_socket_sent = if socket_index.is_some_and(|index| index != 0) {
            packets_sent
        } else {
            0
        };
        let unique_target_endpoints = u32::from(endpoint.is_some() && packets_sent > 0);
        let unique_target_ports = unique_target_endpoints;
        let stage = if budget_skipped > 0 {
            "relay_backoff_heartbeat_beat_deferred"
        } else if packets_sent == 0 {
            "relay_backoff_heartbeat_send_error"
        } else {
            "relay_backoff_heartbeat_beat_completed"
        };
        self.peers
            .record_direct_event_with_probe_coverage(
                peer_id,
                stage,
                endpoint,
                Some(targets.candidate_count()),
                Some(packets_sent),
                format!(
                    "scan_socket_policy=relay_backoff_heartbeat candidate_count={} priority_candidates={} predicted_candidates={} fallback_candidates={} selected_target_group={target_group} selected_socket_index={} actual_kernel_datagrams={packets_sent} unique_target_endpoints={unique_target_endpoints} budget_skipped={budget_skipped} reason={reason} generation={}",
                    targets.candidate_count(),
                    targets.priority.len(),
                    targets.predicted.len(),
                    targets.fallback.len(),
                    socket_index.map_or_else(|| "none".to_string(), |index| index.to_string()),
                    targets.generation,
                ),
                socket0_sent,
                alt_socket_sent,
                unique_target_ports,
                0,
            )
            .await;
    }

    /// One bounded relay-backed heartbeat beat.  This intentionally selects
    /// the endpoint group before the local socket and sends at most one
    /// logical probe transaction (one or two physical datagrams only for a
    /// legacy peer).  It never constructs a candidate × socket work list.
    async fn punch_relay_backoff_heartbeat_target_set_gated(
        &self,
        peer_id: &str,
        targets: crate::peer::RelayBackoffHeartbeatTargetSet,
        owner_gate: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<PunchSendReport> {
        if targets.is_empty()
            || !self.peers.peer_exists_sync(peer_id)
            || self.peers.is_direct_sync(peer_id)
            || self.peers.current_network_generation_sync() != targets.generation
            || !owner_gate()
        {
            return Ok(PunchSendReport::default());
        }

        let Some(target) = self.relay_backoff_heartbeat_budget.next_target(
            peer_id,
            targets.generation,
            &targets.priority,
            &targets.predicted,
            &targets.fallback,
            self.socket_count(),
        ) else {
            return Ok(PunchSendReport::default());
        };

        let reservation = match self
            .reserve_relay_backoff_heartbeat_probe(peer_id, target.endpoint)
            .await
        {
            Ok(reservation) => reservation,
            Err(rejection) => {
                self.record_relay_backoff_heartbeat_beat(
                    peer_id,
                    &targets,
                    Some(target),
                    0,
                    1,
                    rejection.reason(),
                )
                .await;
                trace!(
                    peer_id,
                    target = %target.endpoint,
                    socket_index = target.socket_index,
                    target_group = target.group.label(),
                    reason = rejection.reason(),
                    "Deferred relay-backoff heartbeat endpoint group"
                );
                return Ok(PunchSendReport {
                    budget_skipped: 1,
                    ..PunchSendReport::default()
                });
            }
        };

        // Reservation is deliberately obtained before this final owner gate
        // so concurrent workers cannot oversubscribe.  A revoked owner drops
        // it without committing a phantom packet.
        if !self
            .relay_backoff_heartbeat_send_allowed(peer_id, targets.generation, owner_gate)
            .await
        {
            self.record_relay_backoff_heartbeat_beat(
                peer_id,
                &targets,
                Some(target),
                0,
                0,
                "heartbeat_owner_or_path_revoked_before_send",
            )
            .await;
            return Ok(PunchSendReport::default());
        }

        match self
            .send_heartbeat_probe_from_socket(target.socket_index, peer_id, target.endpoint)
            .await
        {
                Ok(sent) => {
                    let packets_sent = u32::from(sent.datagrams_sent);
                    reservation.commit(usize::from(sent.datagrams_sent));
                self.peers
                    .record_direct_probe_sent(peer_id, target.endpoint)
                    .await;
                self.record_relay_backoff_heartbeat_beat(
                    peer_id,
                    &targets,
                    Some(target),
                    packets_sent,
                    0,
                    "actual_kernel_datagrams_committed",
                )
                .await;
                Ok(PunchSendReport {
                    packets_sent,
                    unique_target_endpoints: 1,
                    first_send_at_ms: sent.first_send_at_ms,
                    per_socket_sent: vec![(sent.socket_index, packets_sent)],
                    ..PunchSendReport::default()
                })
            }
            Err(error) => {
                // The reservation's Drop implementation releases every
                // packet slot because no UDP datagram was accepted.
                debug!(
                    peer_id,
                    target = %target.endpoint,
                    socket_index = target.socket_index,
                    target_group = target.group.label(),
                    error = %error,
                    "Relay-backoff heartbeat UDP send failed"
                );
                self.record_relay_backoff_heartbeat_beat(
                    peer_id,
                    &targets,
                    Some(target),
                    0,
                    0,
                    "udp_send_error_reservation_released",
                )
                .await;
                Ok(PunchSendReport::default())
            }
        }
    }

    /// One heartbeat beat with a per-send owner gate.  The worker passes the
    /// categorized target snapshot so candidate refreshes cannot recreate the
    /// old generic sweep.
    pub(crate) async fn punch_candidates_relay_backoff_heartbeat_gated(
        &self,
        peer_id: &str,
        targets: crate::peer::RelayBackoffHeartbeatTargetSet,
        owner_gate: &(dyn Fn() -> bool + Send + Sync),
    ) -> Result<PunchSendReport> {
        self.punch_relay_backoff_heartbeat_target_set_gated(peer_id, targets, owner_gate)
            .await
    }

    /// Test-only convenience wrapper.  Its raw endpoint list is treated as a
    /// predicted window, which lets deterministic tests exercise cursor
    /// coverage without needing a control-plane candidate snapshot.
    #[cfg(test)]
    pub(crate) async fn punch_candidates_relay_backoff_heartbeat(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        _attempts: u32,
    ) -> Result<PunchSendReport> {
        self.punch_relay_backoff_heartbeat_target_set_gated(
            peer_id,
            crate::peer::RelayBackoffHeartbeatTargetSet {
                generation: self.peers.current_network_generation_sync(),
                priority: Vec::new(),
                predicted: candidates,
                fallback: Vec::new(),
            },
            &|| true,
        )
        .await
    }

    /// Send one encrypted packet.
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
        self.send_encrypted_packet_on_socket(&socket, socket_index, packet, endpoint)
            .await
    }

    /// Send an encrypted packet on the exact socket identified by the
    /// receiving UDP envelope.  This is reserved for direct validation ACKs:
    /// selecting by peer affinity can choose a different NAT mapping after a
    /// concurrent candidate observation, so it is not equivalent.
    pub(crate) async fn send_packet_on_socket_index(
        &self,
        packet: &EncryptedPeerPacket,
        socket_index: usize,
        endpoint: SocketAddr,
    ) -> Result<usize> {
        let socket = self
            .socket_for_inbound_peer_index(&packet.peer_id, socket_index)
            .await
            .ok_or_else(|| {
                DaemonError::Network(format!(
                    "receiving UDP socket {socket_index} is no longer live for peer {}",
                    packet.peer_id
                ))
            })?;
        self.send_encrypted_packet_on_socket(&socket, socket_index, packet, endpoint)
            .await
    }

    /// Send one encrypted packet on an EXPLICIT socket that was resolved and
    /// leased by the caller (`prepare_direct_validation_send`).
    ///
    /// No re-resolution happens here: the validation expectation is keyed to
    /// `socket_index`, so the send must use exactly the resolved socket or a
    /// detach/affinity switch between registration and send would make the
    /// ACK unmatchable.
    pub(crate) async fn send_encrypted_packet_on_socket(
        &self,
        socket: &Arc<UdpSocket>,
        socket_index: usize,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
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
