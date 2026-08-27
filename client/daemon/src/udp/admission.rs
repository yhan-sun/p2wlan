use probe_budget::{
    RelayBackoffHeartbeatReservation, RelayBackoffHeartbeatReservationRejection,
};

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeSendTestAction {
    Fail,
    Blackhole,
}

#[cfg(test)]
#[derive(Debug)]
struct ProbeSendTestHook {
    action: ProbeSendTestAction,
    selected_attempts: Option<HashSet<usize>>,
    physical_send_attempt: usize,
}

#[cfg(test)]
pub(crate) struct ProbeSendTestGuard {
    hook: Arc<std::sync::Mutex<Option<ProbeSendTestHook>>>,
    enabled: Arc<AtomicBool>,
}

#[cfg(test)]
impl Drop for ProbeSendTestGuard {
    fn drop(&mut self) {
        *self.hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        self.enabled.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
struct ProbeSendFailure {
    error: DaemonError,
    kind: ProbeSendFailureKind,
    physical_send_errors: u8,
}

impl ProbeSendFailure {
    fn new(kind: ProbeSendFailureKind, error: DaemonError) -> Self {
        Self {
            error,
            kind,
            physical_send_errors: 0,
        }
    }

    fn with_physical_send_error(error: DaemonError) -> Self {
        Self {
            error,
            kind: ProbeSendFailureKind::PhysicalSend,
            physical_send_errors: 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProbeSendResult {
    nonce: ProbeNonce,
    /// Physical datagrams accepted by the UDP socket during this synchronous
    /// send transaction.  Heartbeats have no retransmit burst, so this is the
    /// exact quantity that must be committed to their low-rate budget.
    datagrams_sent: u8,
    /// Actual socket selected after dynamic-socket resolution.  Keeping this
    /// beside the send result lets session telemetry account for the socket
    /// that really emitted the packet, even if a requested dynamic index was
    /// detached and fell back to a pool member.
    socket_index: usize,
    /// Wall-clock timestamp sampled immediately after the first successful
    /// kernel send.  This is deliberately not the dispatch timestamp.
    first_send_at_ms: Option<u64>,
    /// Physical sends which returned an error during this logical probe. A
    /// compatibility-copy failure can coexist with a successful primary.
    physical_send_errors: u8,
}

impl UdpTransport {
    async fn admit_authenticated_punch(
        &self,
        peer_id: &str,
        generation: u64,
        kind: PunchPacketKind,
        nonce: ProbeNonce,
        source: SocketAddr,
    ) -> AuthenticatedPunchAdmission {
        let now = Instant::now();
        let mut rate = self.authenticated_punch_rate.lock().await;
        rate.retain(|_, seen| {
            while seen
                .front()
                .is_some_and(|seen_at| now.duration_since(*seen_at) >= AUTH_PUNCH_RATE_WINDOW)
            {
                seen.pop_front();
            }
            !seen.is_empty()
        });
        let seen = rate.entry((peer_id.to_string(), source)).or_default();
        while seen
            .front()
            .is_some_and(|seen_at| now.duration_since(*seen_at) >= AUTH_PUNCH_RATE_WINDOW)
        {
            seen.pop_front();
        }
        if seen.len() >= AUTH_PUNCH_RATE_LIMIT_PER_SOURCE {
            return AuthenticatedPunchAdmission::RateLimited;
        }
        seen.push_back(now);
        drop(rate);

        {
            let mut replay = self.authenticated_punch_replay.lock().await;
            replay.retain(|_, seen_at| seen_at.elapsed() < AUTH_PUNCH_REPLAY_WINDOW);
            let key = (
                peer_id.to_string(),
                generation,
                nonce,
                punch_kind_code(kind),
            );
            if replay.contains_key(&key) {
                return AuthenticatedPunchAdmission::Replay;
            }
            replay.insert(key, now);

            if replay.len() > AUTH_PUNCH_REPLAY_MAX_ENTRIES {
                let mut entries = replay
                    .iter()
                    .map(|(key, seen_at)| (key.clone(), *seen_at))
                    .collect::<Vec<_>>();
                entries.sort_by_key(|(_, seen_at)| *seen_at);
                let remove_count = replay
                    .len()
                    .saturating_sub(AUTH_PUNCH_REPLAY_TARGET_ENTRIES);
                for (key, _) in entries.into_iter().take(remove_count) {
                    replay.remove(&key);
                }
            }
        }

        AuthenticatedPunchAdmission::Accepted
    }

    async fn rollback_authenticated_punch_replay_admission(
        &self,
        peer_id: &str,
        generation: u64,
        kind: PunchPacketKind,
        nonce: ProbeNonce,
    ) {
        self.authenticated_punch_replay.lock().await.remove(&(
            peer_id.to_string(),
            generation,
            nonce,
            punch_kind_code(kind),
        ));
    }

    async fn admit_outbound_connectivity_probe(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
        socket_index: usize,
    ) -> OutboundProbeAdmission {
        let now = Instant::now();
        let network_key = OutboundProbeBudgetKey::Network;
        let peer_key = OutboundProbeBudgetKey::Peer(peer_id.to_string());
        let remote_ip_key =
            OutboundProbeBudgetKey::PeerRemoteIp(peer_id.to_string(), peer_addr.ip());
        let mut budget = self.outbound_probe_budget.lock().await;
        retain_live_budget_entries(&mut budget, now);

        if budget.get(&network_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_NETWORK {
            return OutboundProbeAdmission::NetworkRateLimited;
        }
        if budget.get(&peer_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_PEER {
            return OutboundProbeAdmission::PeerRateLimited;
        }
        if budget.get(&remote_ip_key).map_or(0, VecDeque::len)
            >= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP
        {
            return OutboundProbeAdmission::RemoteIpRateLimited;
        }

        if let Some(global_budget) = self.global_outbound_probe_budget.as_ref() {
            match global_budget.admit(peer_id, peer_addr, socket_index).await {
                OutboundProbeAdmission::Accepted => {}
                limited => return limited,
            }
        }

        // The recovery-epoch credit is the hard per-epoch TOTAL: it cannot be
        // refilled by per-second windows or new candidate offers, so a failing
        // peer's whole recovery episode stays bounded regardless of how many
        // punch sessions or fresh-mapping generations start.
        if !self
            .peers
            .try_consume_recovery_probe_credit(peer_id)
            .await
        {
            return OutboundProbeAdmission::EpochCreditExhausted;
        }

        budget.entry(network_key).or_default().push_back(now);
        budget.entry(peer_key).or_default().push_back(now);
        budget.entry(remote_ip_key).or_default().push_back(now);
        OutboundProbeAdmission::Accepted
    }

    /// Admit one NAT-state binding maintainer probe.
    ///
    /// The maintainer uses its own small per-(peer, socket) budget and never
    /// touches the recovery-epoch traversal credit or the shared outbound
    /// probe budgets: keeping bindings warm is not traversal work, and on a
    /// failing hard-NAT peer it would otherwise exhaust the epoch's whole
    /// one-time probe credit within minutes, starving the real punches.
    /// A skipped beat simply repeats at the next maintainer interval.
    async fn admit_nat_maintainer_probe(&self, peer_id: &str, socket_index: usize) -> bool {
        let now = Instant::now();
        let mut budget = self.nat_maintainer_budget.lock().await;
        budget.retain(|_, sent| {
            while sent
                .front()
                .is_some_and(|sent_at| now.duration_since(*sent_at) >= NAT_MAINTAINER_BUDGET_WINDOW)
            {
                sent.pop_front();
            }
            !sent.is_empty()
        });
        let key = (peer_id.to_string(), socket_index);
        let sent = budget.entry(key).or_default();
        if sent.len() >= NAT_MAINTAINER_BUDGET_PER_PEER_SOCKET {
            return false;
        }
        sent.push_back(now);
        true
    }

    /// Reserve one relay-backoff heartbeat endpoint/socket send.
    ///
    /// Heartbeats never consume recovery-epoch credit or the foreground
    /// per-peer budgets. They do consume a process-wide low-priority reserve,
    /// keyed by actual remote IP and peer, so socket-pool/target multiplication
    /// and many relay peers cannot create an unbounded probe storm.
    async fn reserve_relay_backoff_heartbeat_probe(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
    ) -> std::result::Result<
        RelayBackoffHeartbeatReservation,
        RelayBackoffHeartbeatReservationRejection,
    > {
        let local_busy = {
            let budget = self.outbound_probe_budget.lock().await;
            budget
                .get(&OutboundProbeBudgetKey::Network)
                .map_or(0, VecDeque::len)
                >= OUTBOUND_PROBE_BUDGET_PER_NETWORK
                    .saturating_sub(RELAY_BACKOFF_HEARTBEAT_FOREGROUND_RESERVE)
        };
        if local_busy {
            return Err(RelayBackoffHeartbeatReservationRejection::ForegroundYield);
        }
        if let Some(global_budget) = self.global_outbound_probe_budget.as_ref() {
            if global_budget.foreground_burst_active().await {
                return Err(RelayBackoffHeartbeatReservationRejection::ForegroundYield);
            }
        }
        // A legacy-compatible peer receives both the authenticated probe and
        // a PNCH-v1 compatibility datagram. Reserve both before the send so
        // the aggregate cap is expressed in actual UDP packets, not logical
        // candidates.
        let packet_cost = if self.peers.peer_requires_legacy_probe(peer_id).await {
            2
        } else {
            1
        };
        self.relay_backoff_heartbeat_budget
            .reserve(peer_id, peer_addr.ip(), packet_cost)
    }

    #[cfg(test)]
    async fn admit_relay_backoff_heartbeat_probe(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
    ) -> bool {
        self.reserve_relay_backoff_heartbeat_probe(peer_id, peer_addr)
            .await
            .is_ok()
    }

    async fn notify_peer_reflexive_observation(&self, peer_id: &str, observed_endpoint: SocketAddr) {
        // A converged Direct peer needs no outbound peer-reflexive signal: the
        // relayed HTTP signal and the fast punch would only re-create
        // speculative traversal work on a path that is already confirmed.
        // Recovery resumes through the Exploring window that opens on Direct
        // health failure or a network-generation change.
        if self.peers.is_direct_sync(peer_id) {
            return;
        }
        // Feed the peer-scope adaptive learner: the observed source port is the
        // peer's real public mapping toward us, which is the authoritative
        // allocation-direction evidence for THAT peer (audit P1-B).  STUN-only
        // learning can diverge from the real peer direction on a complex CGNAT.
        let generation = self.peers.current_network_generation().await;
        self.observe_peer_scope(peer_id, observed_endpoint.port(), generation)
            .await;
        let Some(ingress) = self.peer_reflexive_ingress.as_ref() else {
            return;
        };
        if !ingress.submit(PeerReflexiveObservation {
            peer_id: peer_id.to_string(),
            observed_endpoint,
        }) {
            debug!(
                peer_id = %peer_id,
                observed_endpoint = %observed_endpoint,
                max_pending_peers = MAX_PENDING_PEER_REFLEXIVE_INGRESS_PEERS,
                "dropping peer-reflexive observation for a new peer because the coalesced ingress is full"
            );
        }
    }

    /// Admit one reverse connectivity check for a peer.  Endpoint and socket
    /// churn update the one peer record but cannot allocate another in-flight
    /// check or bypass the peer-level cooldown.
    fn admit_triggered_check(
        checks: &mut HashMap<String, TriggeredCheckRecord>,
        peer_id: &str,
        observed_endpoint: SocketAddr,
        now: Instant,
    ) -> Option<SocketAddr> {
        checks.retain(|_, record| {
            record.in_flight
                || now.saturating_duration_since(record.last_sent_at) < TRIGGERED_CHECK_COOLDOWN
        });

        let record = checks
            .entry(peer_id.to_string())
            .or_insert_with(|| TriggeredCheckRecord {
                latest_endpoint: observed_endpoint,
                last_sent_at: now
                    .checked_sub(TRIGGERED_CHECK_COOLDOWN)
                    .unwrap_or(now),
                in_flight: false,
            });
        record.latest_endpoint = observed_endpoint;
        if record.in_flight
            || now.saturating_duration_since(record.last_sent_at) < TRIGGERED_CHECK_COOLDOWN
        {
            return None;
        }
        record.in_flight = true;
        Some(record.latest_endpoint)
    }

    /// Complete the admitted reverse check.  The record remains until the
    /// cooldown expires so a newer endpoint observed while the send was in
    /// flight is retained for the next admission.
    fn complete_triggered_check(
        checks: &mut HashMap<String, TriggeredCheckRecord>,
        peer_id: &str,
        sent_at: Instant,
    ) {
        if let Some(record) = checks.get_mut(peer_id) {
            record.in_flight = false;
            record.last_sent_at = sent_at;
        }
    }

    async fn trigger_peer_reflexive_check(
        &self,
        socket_index: usize,
        peer_id: &str,
        observed_endpoint: SocketAddr,
    ) {
        // The reverse connectivity check only serves the Exploring/Validating
        // states: it probes the observed endpoint so the peer's pending probe
        // gets ACKed and encrypted validation can promote. Once Direct is
        // confirmed the check is pure post-convergence noise (one probe per
        // cooldown window per inbound punch), so it is suppressed at the
        // source instead of sending into a confirmed path.
        if self.peers.is_direct_sync(peer_id) {
            return;
        }
        let admitted_endpoint = {
            let mut checks = self.triggered_checks.lock().await;
            Self::admit_triggered_check(
                &mut checks,
                peer_id,
                observed_endpoint,
                Instant::now(),
            )
        };
        let Some(admitted_endpoint) = admitted_endpoint else {
            return;
        };

        let local_endpoint = self
            .socket_for_peer(Some(peer_id))
            .await
            .and_then(|(_, socket)| socket.local_addr().ok());
        let result = self
            .send_probe_from_socket(socket_index, Some(peer_id), admitted_endpoint)
            .await;
        {
            let mut checks = self.triggered_checks.lock().await;
            Self::complete_triggered_check(&mut checks, peer_id, Instant::now());
        }
        match result {
            Ok(_) => info!(
                event = "candidate_pair_triggered_check",
                peer_id = %peer_id,
                local_endpoint = %local_endpoint.map(|endpoint| endpoint.to_string()).unwrap_or_else(|| "unknown".to_string()),
                remote_endpoint = %admitted_endpoint,
                candidate_source = "peer_reflexive",
                reason = "authenticated inbound punch observed",
                "candidate_pair_triggered_check peer_id={} remote_endpoint={} reason=authenticated inbound punch observed",
                peer_id,
                admitted_endpoint
            ),
            Err(err) => debug!(
                "Failed triggered UDP check from socket {socket_index} to peer {peer_id} at {admitted_endpoint}: {err}"
            ),
        }
    }

    #[cfg(test)]
    async fn send_probe(&self, peer_id: Option<&str>, peer_addr: SocketAddr) -> Result<ProbeNonce> {
        let socket_index = self.socket_index_for_peer(peer_id).await;
        self.send_probe_from_socket_with_nomination(
            socket_index,
            peer_id,
            peer_addr,
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
    }

    async fn send_probe_from_socket(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
    ) -> Result<ProbeNonce> {
        self.send_probe_from_socket_with_nomination(
            socket_index,
            peer_id,
            peer_addr,
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
    }

    async fn send_heartbeat_probe_from_socket(
        &self,
        socket_index: usize,
        peer_id: &str,
        peer_addr: SocketAddr,
    ) -> Result<ProbeSendResult> {
        self.send_probe_from_socket_with_nomination_result(
            socket_index,
            Some(peer_id),
            peer_addr,
            false,
            PendingProbePurpose::RelayBackoffHeartbeat,
        )
        .await
    }

    async fn send_probe_from_socket_with_nomination(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
    ) -> Result<ProbeNonce> {
        self.send_probe_from_socket_with_nomination_result(
            socket_index,
            peer_id,
            peer_addr,
            use_candidate,
            purpose,
        )
        .await
        .map(|result| result.nonce)
    }

    async fn send_probe_from_socket_with_nomination_result(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
    ) -> Result<ProbeSendResult> {
        let (actual_index, socket, _lease) = self
            .socket_for_index_or_dynamic(socket_index, peer_id)
            .await
            .ok_or_else(|| {
                DaemonError::Network(format!(
                    "UDP socket pool member {socket_index} is unavailable"
                ))
            })?;
        // The pending probe records the ACTUAL sending socket: when the
        // requested dynamic socket was detached concurrently, the resolver
        // falls back to the peer's pool socket and the ACK will arrive there.
        self.send_probe_on_socket_result(
            actual_index,
            socket,
            peer_id,
            peer_addr,
            use_candidate,
            purpose,
        )
        .await
    }

    /// Resolve a socket by fixed pool index, falling back to the peer's
    /// dedicated punch socket when the index is a dynamic one, and finally to
    /// the peer's resolved pool socket when the dynamic socket is gone.
    ///
    /// Returns the actual index together with the socket so callers record
    /// the real sending socket: a dynamic socket detached between two
    /// separate resolve calls would otherwise leave a pending probe indexed to
    /// a socket that never sent, and the ACK would never match.  Never holds
    /// the socket-state lock while resolving the peer's socket:
    /// `socket_for_peer` re-acquires the same lock, and this function must
    /// not hold it across that call.
    ///
    /// A dynamic socket is only handed out when it still belongs to the peer,
    /// is Committed and matches the current network generation, and the
    /// returned lease keeps the reader alive until the send completes.
    async fn socket_for_index_or_dynamic(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        if socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            let socket = self.active_sockets().get(socket_index)?.clone();
            // Pool sockets need no lease; hand out a never-blocking lease for
            // a uniform return type.
            return Some((
                socket_index,
                socket,
                DynamicSocketSendLease::noop(socket_index),
            ));
        }
        let peer_id = peer_id?;
        // Validate peer ownership, phase and network generation, and hold a
        // send lease that keeps the reader alive through the send.
        if let Some(resolved) = self.resolve_dynamic_socket_for_send(peer_id).await {
            return Some(resolved);
        }
        // The dynamic socket is gone (or belongs to someone else): fall back
        // to the peer's resolved pool socket.
        self.socket_for_peer(Some(peer_id)).await.map(|(index, socket)| {
            (index, socket, DynamicSocketSendLease::noop(index))
        })
    }

    /// Resolve exactly `socket_index` for a peer-directed send.
    ///
    /// Unlike [`Self::socket_for_index_or_dynamic`], this method never falls
    /// back to a pool socket and never follows the peer's affinity pin.  A
    /// synchronized fresh-mapping session must fail closed if the socket that
    /// produced its measured mapping has been detached or superseded: sending
    /// the same predicted window from another socket would invalidate the
    /// measurement rather than provide a safe retry.
    pub(crate) async fn resolve_dynamic_socket_index_for_send(
        &self,
        peer_id: &str,
        socket_index: usize,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        if socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let state = self.socket_state.lock().await;
        let dynamic = state.dynamic.get(&socket_index)?;
        if dynamic.peer_id != peer_id
            || !dynamic.phase.is_usable()
            || dynamic.network_generation != self.peers.current_network_generation_sync()
        {
            return None;
        }
        let leases = dynamic.send_leases.clone();
        let socket = dynamic.socket.clone();
        leases.acquire();
        drop(state);
        Some((
            socket_index,
            socket,
            DynamicSocketSendLease {
                state: leases,
                socket_index,
            },
        ))
    }

    /// Classify an exact dynamic-socket lookup failure without substituting a
    /// pool socket.  This is used by the bounded Hard↔Hard scheduler so a
    /// detached member, a revoked owner and a stale network generation remain
    /// distinguishable in the terminal report.
    pub(crate) async fn classify_dynamic_socket_failure_kind(
        &self,
        peer_id: &str,
        socket_index: usize,
    ) -> ProbeSendFailureKind {
        if socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return ProbeSendFailureKind::SocketUnavailable;
        }
        let state = self.socket_state.lock().await;
        let Some(dynamic) = state.dynamic.get(&socket_index) else {
            return ProbeSendFailureKind::SocketUnavailable;
        };
        if dynamic.peer_id != peer_id || !dynamic.phase.is_usable() {
            return ProbeSendFailureKind::SocketRevoked;
        }
        if dynamic.network_generation != self.peers.current_network_generation_sync() {
            return ProbeSendFailureKind::NetworkGenerationChanged;
        }
        ProbeSendFailureKind::SocketUnavailable
    }

    /// Send one authenticated/legacy probe from an explicit socket.
    ///
    /// This is the shared core for pool sockets and dedicated punch sockets:
    /// the pending-probe bookkeeping, MAC/nonce construction and retransmit
    /// burst are identical for both.  The pending entry records the affinity
    /// evidence epoch at send time so a matched ACK can only adopt the
    /// sending socket when nothing newer committed meanwhile.
    ///
    /// The send is one consistent transaction: the network generation, the
    /// affinity evidence epoch and the peer's cleanup epoch are snapshotted
    /// under the socket-state lock, the payload is built from that snapshot,
    /// and the snapshot is RE-VERIFIED under the lock before the pending
    /// entry is registered — a cleanup or a network-generation change that
    /// landed between the snapshot and the registration invalidates the WHOLE
    /// probe (the stale payload is never stamped with the new epoch and never
    /// sent).
    async fn send_probe_on_socket(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
    ) -> Result<ProbeNonce> {
        self.send_probe_on_socket_result(
            socket_index,
            socket,
            peer_id,
            peer_addr,
            use_candidate,
            purpose,
        )
        .await
        .map(|result| result.nonce)
    }

    async fn send_probe_on_socket_result(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
    ) -> Result<ProbeSendResult> {
        self.send_probe_on_socket_result_with_hard_hard_token(
            socket_index,
            socket,
            peer_id,
            peer_addr,
            use_candidate,
            purpose,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_probe_on_socket_result_with_hard_hard_token(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
        hard_hard_session_token: Option<&str>,
    ) -> Result<ProbeSendResult> {
        self.send_probe_on_socket_result_with_hard_hard_token_classified(
            socket_index,
            socket,
            peer_id,
            peer_addr,
            use_candidate,
            purpose,
            hard_hard_session_token,
            false,
            None,
        )
        .await
        .map_err(|failure| failure.error)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_probe_on_socket_result_with_hard_hard_token_classified(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
        hard_hard_session_token: Option<&str>,
        require_exact_dynamic_owner: bool,
        live_recorder: Option<BirthdayLiveRecorder>,
    ) -> std::result::Result<ProbeSendResult, ProbeSendFailure> {
        let remote_candidate_epoch = match peer_id {
            Some(peer_id) => self
                .peers
                .current_remote_candidate_epoch(peer_id)
                .await
                .unwrap_or(0),
            None => 0,
        };
        // Consistent peer snapshot under one lock acquisition: generation
        // (lock-free mirror), affinity evidence epoch and cleanup epoch.
        let (generation, socket_epoch, cleanup_epoch) = {
            let state = self.socket_state.lock().await;
            let generation = self.peers.current_network_generation_sync();
            let socket_epoch = match peer_id {
                Some(peer_id) => state
                    .affinity
                    .get(peer_id)
                    .map(|pin| pin.epoch)
                    .unwrap_or(0),
                None => 0,
            };
            let cleanup_epoch = peer_id
                .and_then(|peer_id| state.probe_cleanup_epochs.get(peer_id).copied())
                .unwrap_or(0);
            (generation, socket_epoch, cleanup_epoch)
        };
        let requires_legacy_probe = match peer_id {
            Some(peer_id) => self.peers.peer_requires_legacy_probe(peer_id).await,
            None => true,
        };
        let should_retransmit = use_candidate || purpose == PendingProbePurpose::ConsentCheck;
        let heartbeat_probe = purpose == PendingProbePurpose::RelayBackoffHeartbeat;
        let authenticated_probe = match (peer_id, self.local_node_id.as_deref()) {
            (Some(peer_id), Some(local_node_id))
                if local_node_id.len() <= u8::MAX as usize && peer_id.len() <= u8::MAX as usize =>
            {
                self.peers
                    .probe_key_and_session_for_peer(peer_id)
                    .await
                    .map(|(key, probe_session_id)| {
                        let (bytes, nonce) = build_authenticated_punch_packet_with_nomination(
                            local_node_id,
                            peer_id,
                            generation,
                            use_candidate,
                            &key,
                        );
                        (bytes, nonce, probe_session_id)
                    })
            }
            _ => None,
        };

        let (
            bytes,
            nonce,
            accepts_authenticated_ack,
            accepts_legacy_ack,
            compat_legacy_probe,
            probe_session_id,
        ) =
            if let Some((bytes, nonce, probe_session_id)) = authenticated_probe {
                // Compatibility bridge for pre-v2 peers. v0.1.24 and older only
                // understand PNCH v1 and otherwise forward PNCH v2 into the
                // WireGuard parser, producing "invalid message type: 80".
                // Send a legacy probe with the same nonce so either ACK form clears
                // the same pending probe without weakening the v2 path between
                // upgraded peers.
                (
                    bytes,
                    nonce,
                    true,
                    requires_legacy_probe,
                    requires_legacy_probe
                        .then(|| build_punch_packet_with_nonce(nonce).to_vec()),
                    probe_session_id,
                )
            } else {
                let bytes = build_punch_packet();
                let nonce = decode_punch_packet(&bytes)
                    .map(|packet| packet.nonce)
                    .ok_or_else(|| {
                        ProbeSendFailure::new(
                            ProbeSendFailureKind::ProbeEncodingFailed,
                            DaemonError::Network(
                                "failed to create UDP probe".to_string(),
                            ),
                        )
                    })?;
                (bytes.to_vec(), nonce, false, true, None, None)
            };

        // Re-verify the snapshot and register the pending probe as one
        // transaction under the socket-state lock and the pending lock (in
        // that order everywhere): a cleanup or network-generation change that
        // ran between the snapshot and here invalidates the whole probe —
        // the old payload must never be stamped with the new cleanup epoch.
        // The send lease for a dynamic socket is registered in this same
        // critical section: the detach path can only drain after removing the
        // entry under this same lock, so it always observes this lease.
        //
        // The registration also holds the shared network-epoch gate: a
        // generation advance can never bump the generation between the
        // re-verification read and the pending insert, so an old-generation
        // probe can never be registered once the generation moved on.
        let send_lease = {
            let _epoch_gate = self.network_epoch_gate.lock().await;
            let current_remote_candidate_epoch = match peer_id {
                Some(peer_id) => self
                    .peers
                    .current_remote_candidate_epoch(peer_id)
                    .await
                    .unwrap_or(0),
                None => 0,
            };
            if current_remote_candidate_epoch != remote_candidate_epoch {
                return Err(ProbeSendFailure::new(
                    ProbeSendFailureKind::CandidateEpochChanged,
                    DaemonError::Network(
                        "probe invalidated: remote candidate generation changed".to_string(),
                    ),
                ));
            }
            let state = self.socket_state.lock().await;
            if self.peers.current_network_generation_sync() != generation {
                debug!(
                    "Probe to {} invalidated: the network generation changed while the packet was built",
                    peer_addr
                );
                return Err(ProbeSendFailure::new(
                    ProbeSendFailureKind::NetworkGenerationChanged,
                    DaemonError::Network(
                        "probe invalidated: network generation changed".to_string(),
                    ),
                ));
            }
            let current_cleanup_epoch = peer_id
                .and_then(|peer_id| state.probe_cleanup_epochs.get(peer_id).copied())
                .unwrap_or(0);
            if current_cleanup_epoch != cleanup_epoch {
                debug!(
                    "Probe to {} invalidated: the peer was cleaned up while the packet was built (epoch {cleanup_epoch} -> {current_cleanup_epoch})",
                    peer_addr
                );
                return Err(ProbeSendFailure::new(
                    ProbeSendFailureKind::PeerSessionChanged,
                    DaemonError::Network("probe invalidated: peer cleanup raced the send".to_string()),
                ));
            }
            if require_exact_dynamic_owner && socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
                let Some(peer_id) = peer_id else {
                    return Err(ProbeSendFailure::new(
                        ProbeSendFailureKind::SocketRevoked,
                        DaemonError::Network(
                            "probe invalidated: dynamic socket has no peer owner".to_string(),
                        ),
                    ));
                };
                let Some(dynamic) = state.dynamic.get(&socket_index) else {
                    return Err(ProbeSendFailure::new(
                        ProbeSendFailureKind::SocketUnavailable,
                        DaemonError::Network(format!(
                            "UDP socket pool member {socket_index} is unavailable"
                        )),
                    ));
                };
                if dynamic.peer_id != peer_id || !dynamic.phase.is_usable() {
                    return Err(ProbeSendFailure::new(
                        ProbeSendFailureKind::SocketRevoked,
                        DaemonError::Network(format!(
                            "UDP socket pool member {socket_index} is no longer owned by peer"
                        )),
                    ));
                }
                if dynamic.network_generation != generation {
                    return Err(ProbeSendFailure::new(
                        ProbeSendFailureKind::NetworkGenerationChanged,
                        DaemonError::Network(
                            "probe invalidated: dynamic socket generation changed".to_string(),
                        ),
                    ));
                }
            }
            let send_lease = if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
                state.dynamic.get(&socket_index).map(|entry| {
                    entry.send_leases.acquire();
                    DynamicSocketSendLease {
                        state: entry.send_leases.clone(),
                        socket_index,
                    }
                })
            } else {
                None
            };
            let mut pending = self.pending_probes.lock().await;
            pending.retain(|_, pending| {
                pending.sent_at.elapsed() < Duration::from_secs(60)
                    && pending.generation == generation
            });
            let sent_at = Instant::now();
            pending.insert(
                nonce,
                PendingProbe {
                    sent_at,
                    // A punch/heartbeat ACK that arrives after this bound is
                    // terminally stale.  The old 60-second map-retention
                    // window is only a cleanup guard; it must not turn a
                    // delayed queued packet into current connectivity proof.
                    expires_at: sent_at + DIRECT_KEEPALIVE_ACK_TIMEOUT,
                    endpoint: peer_addr,
                    local_endpoint: socket.local_addr().ok(),
                    socket_index,
                    generation,
                    remote_candidate_epoch,
                    probe_session_id,
                    peer_id: peer_id.map(str::to_string),
                    purpose,
                    accepts_authenticated_ack,
                    accepts_legacy_ack,
                    socket_epoch,
                    cleanup_epoch,
                    direct_commit_seq: peer_id
                        .and_then(|peer_id| self.peers.direct_commit_seq_sync(peer_id))
                        .unwrap_or(0),
                },
            );
            let mut hard_hard_bindings = self.hard_hard_probe_bindings.lock().await;
            hard_hard_bindings.retain(|pending_nonce, _| pending.contains_key(pending_nonce));
            // Keep the Hard↔Hard token in a local-only side table. The wire
            // packet remains the existing authenticated Probe-v2 packet, but
            // its ACK must still belong to the exact bounded rendezvous that
            // created this nonce.
            if let Some(token) = hard_hard_session_token {
                hard_hard_bindings.insert(nonce, token.to_string());
            }
            send_lease
        };

        let first_send_at_ms = match self.send_probe_datagram(&socket, &bytes, peer_addr).await {
            Ok(_) => {
                let sent_at_ms = monotonic_millis();
                // This is the physical send commit point.  It must precede
                // the test gate, diagnostics update, lease cleanup, and every
                // other follow-up await so a cancelled worker cannot lose a
                // datagram that the kernel already accepted.
                if let Some(recorder) = live_recorder.as_ref() {
                    recorder.record_primary_success(socket_index, peer_addr, sent_at_ms);
                }
                #[cfg(test)]
                wait_for_probe_post_send_gate_for_test().await;
                Some(sent_at_ms)
            }
            Err(error) => {
                // The primary send failed, but the physical error must still
                // survive a cancellation racing the pending-probe cleanup.
                if let Some(recorder) = live_recorder.as_ref() {
                    recorder.record_primary_error();
                }
                #[cfg(test)]
                wait_for_probe_post_send_gate_for_test().await;
                self.pending_probes.lock().await.remove(&nonce);
                self.clear_hard_hard_pending_probe_token(nonce).await;
                return Err(ProbeSendFailure::with_physical_send_error(DaemonError::Network(
                    format!("UDP probe send to {peer_addr} failed: {error}"),
                )));
            }
        };
        // The send completed: release the in-flight send lease.  The pending
        // entry itself keeps the detach waiting until the ACK arrives or the
        // bounded drain timeout expires.
        drop(send_lease);

        self.update_socket_diagnostics(socket_index, |metrics| metrics.probes_sent += 1)
            .await;
        if heartbeat_probe {
            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.relay_backoff_heartbeat_probes_sent = metrics
                    .relay_backoff_heartbeat_probes_sent
                    .saturating_add(1);
            })
            .await;
        }

        let mut datagrams_sent = 1u8;
        let mut physical_send_errors = 0u8;
        if let Some(legacy_probe) = compat_legacy_probe.clone() {
            match self
                .send_probe_datagram(&socket, &legacy_probe, peer_addr)
                .await
            {
                Ok(_) => {
                    datagrams_sent = datagrams_sent.saturating_add(1);
                    if let Some(recorder) = live_recorder.as_ref() {
                        recorder.record_compatibility_success(socket_index, monotonic_millis());
                    }
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.probes_sent += 1
                    })
                    .await;
                    if heartbeat_probe {
                        self.update_socket_diagnostics(socket_index, |metrics| {
                            metrics.relay_backoff_heartbeat_probes_sent = metrics
                                .relay_backoff_heartbeat_probes_sent
                                .saturating_add(1);
                        })
                        .await;
                    }
                    trace!(
                        "Sent compatibility legacy UDP punch probe to peer {} at {}",
                        peer_id.unwrap_or("unknown"),
                        peer_addr
                    );
                    if should_retransmit {
                        self.retransmit_probe_burst(
                            socket.clone(),
                            socket_index,
                            legacy_probe,
                            peer_addr,
                            peer_id.map(str::to_string),
                        );
                    }
                }
                Err(err) => {
                    physical_send_errors = physical_send_errors.saturating_add(1);
                    if let Some(recorder) = live_recorder.as_ref() {
                        recorder.record_compatibility_error();
                    }
                    debug!(
                        "Failed to send compatibility legacy UDP punch probe to peer {} at {}: {}",
                        peer_id.unwrap_or("unknown"),
                        peer_addr,
                        err
                    );
                }
            }
        }

        if should_retransmit {
            self.retransmit_probe_burst(
                socket,
                socket_index,
                bytes,
                peer_addr,
                peer_id.map(str::to_string),
            );
        }
        Ok(ProbeSendResult {
            nonce,
            datagrams_sent,
            socket_index,
            first_send_at_ms,
            physical_send_errors,
        })
    }

    async fn send_probe_datagram(
        &self,
        socket: &UdpSocket,
        bytes: &[u8],
        peer_addr: SocketAddr,
    ) -> std::io::Result<usize> {
        #[cfg(test)]
        match self.probe_send_action_for_test() {
            Some(ProbeSendTestAction::Fail) => {
                return Err(std::io::Error::other(
                    "test-injected physical probe send failure",
                ));
            }
            Some(ProbeSendTestAction::Blackhole) => return Ok(bytes.len()),
            None => {}
        }
        socket.send_to(bytes, peer_addr).await
    }

    #[cfg(test)]
    fn probe_send_action_for_test(&self) -> Option<ProbeSendTestAction> {
        if !self
            .probe_send_test_hook_enabled
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        let mut hook = self
            .probe_send_test_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hook = hook.as_mut()?;
        hook.physical_send_attempt = hook.physical_send_attempt.saturating_add(1);
        match hook.selected_attempts.as_ref() {
            Some(selected) if !selected.contains(&hook.physical_send_attempt) => None,
            _ => Some(hook.action),
        }
    }

    /// Send an authenticated ICE-style nominated connectivity check for a direct trial.
    pub async fn send_nomination_probe(&self, peer_id: &str, peer_addr: SocketAddr) -> Result<()> {
        let socket_index = self.socket_index_for_peer(Some(peer_id)).await;
        self.send_probe_from_socket_with_nomination(
            socket_index,
            Some(peer_id),
            peer_addr,
            true,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await?;
        Ok(())
    }

    fn retransmit_probe_burst(
        &self,
        socket: Arc<UdpSocket>,
        socket_index: usize,
        probe: Vec<u8>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
    ) {
        let peer_label = peer_id.unwrap_or_else(|| peer_addr.to_string());
        let diagnostics = self.socket_pool_diagnostics.clone();
        tokio::spawn(async move {
            for delay_ms in PUNCH_PROBE_RETRANSMIT_DELAYS_MS {
                sleep(Duration::from_millis(delay_ms)).await;
                match socket.send_to(&probe, peer_addr).await {
                    Ok(_) => {
                        if let Some(metrics) = diagnostics.lock().await.get_mut(socket_index) {
                            metrics.probe_retransmissions_sent += 1;
                        }
                        trace!(
                            "Retransmitted UDP punch probe to peer {} at {} after {}ms",
                            peer_label,
                            peer_addr,
                            delay_ms
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to retransmit UDP punch probe to peer {} at {} after {}ms: {}",
                            peer_label, peer_addr, delay_ms, err
                        );
                        break;
                    }
                }
            }
        });
    }

    async fn send_punch_ack_burst(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        ack: Vec<u8>,
        source: SocketAddr,
        peer_label: impl Into<String>,
    ) -> std::io::Result<()> {
        socket.send_to(&ack, source).await?;
        self.update_socket_diagnostics(socket_index, |metrics| metrics.probe_acks_sent += 1)
            .await;

        let peer_label = peer_label.into();
        let diagnostics = self.socket_pool_diagnostics.clone();
        tokio::spawn(async move {
            for delay_ms in PUNCH_ACK_RETRANSMIT_DELAYS_MS {
                sleep(Duration::from_millis(delay_ms)).await;
                match socket.send_to(&ack, source).await {
                    Ok(_) => {
                        if let Some(metrics) = diagnostics.lock().await.get_mut(socket_index) {
                            metrics.probe_ack_retransmissions_sent += 1;
                        }
                        trace!(
                            "Retransmitted UDP punch ACK to peer {} at {} after {}ms",
                            peer_label,
                            source,
                            delay_ms
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to retransmit UDP punch ACK to peer {} at {} after {}ms: {}",
                            peer_label, source, delay_ms, err
                        );
                        break;
                    }
                }
            }
        });
        Ok(())
    }
}
