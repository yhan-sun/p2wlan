use p2pnet_nat::mapping::{
    build_model_for_batch, predict_ports_for_elapsed, MappingBatch, MappingObservation,
    ModelRejection, PortModelKind,
};

const MEASUREMENT_SOFTWARE_TAG: &str = "P2WLAN/0.2";

impl UdpTransport {
    /// Bind a brand-new dedicated punch socket for one fresh-mapping generation.
    ///
    /// The socket is intentionally fresh: it has never contacted any observer
    /// or peer, so its next mappings follow the NAT's allocation sequence from
    /// a clean slate.
    pub(crate) async fn bind_fresh_punch_socket(&self) -> Result<(usize, Arc<UdpSocket>)> {
        let bind_addr = match self.socket.local_addr() {
            Ok(addr) if !addr.ip().is_unspecified() => SocketAddr::new(addr.ip(), 0),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|error| {
            DaemonError::Network(format!(
                "failed to bind fresh-mapping punch socket at {bind_addr}: {error}"
            ))
        })?;
        let socket_index = self.next_dynamic_index();
        Ok((socket_index, Arc::new(socket)))
    }

    /// Register a dedicated punch socket with the transport and return the
    /// cancellation-safe ownership guard for its generation.
    ///
    /// Spawns an inbound reader for the socket so STUN responses, peer
    /// punches and ACKs all flow through the ordinary receive pipeline from
    /// the first measurement request onward.  The socket is inserted in
    /// `Provisional` phase and the ownership watcher exists BEFORE the map
    /// insert: there is no await between the map insert and the watcher
    /// becoming alive, and no await at all before it — a generation future
    /// dropped at any await point is always covered by the guard's watcher.
    /// The guard is returned directly by this function; only `commit_and_pin`
    /// (via [`ProvisionalSocketGuard`]) may disarm its pre-commit cleanup,
    /// and its drop / cancellation always cleans up the provisional
    /// generation.
    ///
    /// The capacity check, eviction selection, removal and insert are one
    /// transaction under the single socket-state lock: concurrent attaches
    /// can never exceed MAX_DYNAMIC_PUNCH_SOCKETS, evict the same entry
    /// twice, or tear down the old socket this peer still needs.  The
    /// nonevictable set (same peer's predecessor, Direct peers) is
    /// re-verified INSIDE the lock against the peer manager's synchronous
    /// Direct mirror — the async snapshot taken before the lock is only an
    /// ordering hint and can never be the sole authority.  Reader aborts for
    /// evicted sockets happen outside the lock.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn attach_dynamic_punch_socket(
        &self,
        peer_id: &str,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        network_generation: u64,
        punch_generation: u64,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> std::result::Result<ProvisionalSocketGuard, DynamicSocketAttachError> {
        if self.inbound_channel().is_none() {
            return Err(DynamicSocketAttachError::NoInboundChannel);
        }
        // Ordering hint for the eviction selection only.  The authoritative
        // nonevictable re-check runs under the socket-state lock against the
        // synchronous Direct mirror (`is_direct_sync`).
        let direct_peers = self.peers.direct_peer_ids().await;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reader_handle = {
            let transport = self.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                transport
                    .run_dynamic_inbound_socket(socket_index, socket, shutdown_rx)
                    .await
            })
        };
        // The reader handle is only moved into the map on the successful
        // insert path; the rejection path below still owns it.
        let mut reader_handle = Some(reader_handle);

        // The ownership watcher is created BEFORE the map insert: from this
        // moment any drop of this future — at this very await point or any
        // later one — fires the guard's stop signal and the watcher detaches
        // the provisional entry.  There is never a provisional socket without
        // a watcher.  The reader task observes the shutdown channel closure
        // even when the entry was never inserted (the reader selects on it
        // while parked in recv_from), so a drop before the insert can never
        // leak a reader parked in `recv_from` forever.
        let provisional_guard = ProvisionalSocketGuard::spawn(
            self.clone(),
            socket_index,
            peer_id.to_string(),
            cancellation.cloned().unwrap_or_default(),
        );

        // The whole cap check, eviction selection, removal and insert run
        // under one lock acquisition.  Reader aborts for evicted sockets are
        // deferred until after the lock is released; the map entries are
        // already gone, so the cap can never be exceeded even while another
        // attach runs concurrently.
        let mut evicted = Vec::new();
        let capacity_ok = {
            let mut state = self.socket_state.lock().await;
            if state.dynamic.len() >= MAX_DYNAMIC_PUNCH_SOCKETS {
                let mut candidates = state
                    .dynamic
                    .iter()
                    .map(|(index, entry)| (*index, entry.peer_id.clone(), entry.created_at))
                    .collect::<Vec<_>>();
                candidates.sort_by_key(|(_, _, created_at)| *created_at);
                for (evict_index, evicted_peer, _) in candidates {
                    // Never evict the previous generation's socket for the peer we
                    // are about to attach a new generation for: the old mapping is
                    // the peer's current working path until the new generation
                    // commits.  Direct peers are never evicted either — and the
                    // Direct check is re-verified here, under this lock, against
                    // the synchronous mirror: a peer that became Direct after the
                    // pre-lock snapshot must not lose its dedicated socket.
                    // The Direct check is re-verified here, under this lock,
                    // against the peer manager's synchronous mirror: a peer
                    // that became Direct after the pre-lock snapshot must not
                    // lose its dedicated socket.
                    if evicted_peer == peer_id || self.peers.is_direct_sync(&evicted_peer) {
                        continue;
                    }
                    let _ = direct_peers; // ordering hint only
                    let evicted_entry = state
                        .dynamic
                        .remove(&evict_index)
                        .expect("eviction candidate still present under the socket-state lock");
                    // Drop any affinity that pointed at the evicted socket so the
                    // peer cleanly falls back to its pool socket.
                    if state
                        .affinity
                        .get(&evicted_peer)
                        .is_some_and(|pin| pin.socket_index == evict_index)
                    {
                        state.affinity.remove(&evicted_peer);
                    }
                    evicted.push(evicted_entry);
                    if state.dynamic.len() < MAX_DYNAMIC_PUNCH_SOCKETS {
                        break;
                    }
                }
                if state.dynamic.len() >= MAX_DYNAMIC_PUNCH_SOCKETS {
                    false
                } else {
                    state.dynamic.insert(
                        socket_index,
                        DynamicPunchSocket {
                            socket_index,
                            socket: socket.clone(),
                            peer_id: peer_id.to_string(),
                            network_generation,
                            punch_generation,
                            created_at: Instant::now(),
                            phase: DynamicSocketPhase::Provisional,
                            shutdown_tx,
                            reader: reader_handle.take().expect("reader handle owned"),
                            send_leases: Arc::new(DynamicSocketLeaseState::default()),
                        },
                    );
                    true
                }
            } else {
                state.dynamic.insert(
                    socket_index,
                    DynamicPunchSocket {
                        socket_index,
                        socket: socket.clone(),
                        peer_id: peer_id.to_string(),
                        network_generation,
                        punch_generation,
                        created_at: Instant::now(),
                        phase: DynamicSocketPhase::Provisional,
                        shutdown_tx,
                        reader: reader_handle.take().expect("reader handle owned"),
                        send_leases: Arc::new(DynamicSocketLeaseState::default()),
                    },
                );
                true
            }
        };
        if !capacity_ok {
            if let Some(reader) = reader_handle {
                reader.abort();
            }
            // The guard's stop fires on drop; the watcher finds no entry (or
            // one that was never inserted) and no-ops.
            drop(provisional_guard);
            for entry in evicted {
                self.detach_dynamic_entry(entry, "dynamic_socket_cap_reached")
                    .await;
            }
            return Err(DynamicSocketAttachError::CapacityRejected);
        }
        for entry in evicted {
            self.detach_dynamic_entry(entry, "dynamic_socket_cap_reached")
                .await;
        }
        self.dynamic_socket_diagnostics.lock().await.insert(
            socket_index,
            UdpSocketPoolMemberDiagnostics {
                socket_index,
                ..Default::default()
            },
        );
        debug!(
            "Attached fresh-mapping punch socket index={socket_index} local={} peer={peer_id} network_generation={network_generation} punch_generation={punch_generation}",
            format_optional_endpoint(socket.local_addr().ok())
        );
        // The ownership guard already exists (created before the insert), so
        // from this point on the generation is always covered by the watcher,
        // even if the future is dropped at the very next await point.
        Ok(provisional_guard)
    }

    /// Remove a dynamic socket entry and stop its reader.
    ///
    /// The entry is removed from the map by the caller before this runs.  The
    /// reader abort is deferred until every outstanding send lease drained
    /// (the in-flight `resolve -> send` race) AND every pending probe that
    /// was sent from this socket has been removed (a matched ACK or the
    /// bounded timeout), so the ACK of a probe that raced the detach still
    /// arrives at a live reader.  After [`DYNAMIC_SOCKET_LEASE_DRAIN_TIMEOUT`]
    /// the socket's pending probes are dropped and the reader is aborted.
    async fn detach_dynamic_entry(&self, entry: DynamicPunchSocket, reason: &str) {
        entry.shutdown_tx.send_replace(true);
        let drained = tokio::time::timeout(
            DYNAMIC_SOCKET_LEASE_DRAIN_TIMEOUT,
            self.wait_for_detach_drain(entry.socket_index, &entry.send_leases),
        )
        .await
        .is_ok();
        if !drained {
            // The bound is the probe retransmission window plus the caller's
            // ACK grace: an ACK that has not arrived by now will never be
            // matched, so its pending entry can no longer block the reader
            // abort.
            self.drop_pending_probes_for_socket(entry.socket_index).await;
        }
        entry.reader.abort();
        self.dynamic_socket_diagnostics.lock().await.remove(&entry.socket_index);
        debug!(
            "Detached fresh-mapping punch socket index={} local={} peer={} network_generation={} punch_generation={} reason={reason}",
            entry.socket_index,
            format_optional_endpoint(entry.local_endpoint()),
            entry.peer_id,
            entry.network_generation,
            entry.punch_generation
        );
    }

    /// Wait until no send lease and no pending probe referencing
    /// `socket_index` remains.
    ///
    /// The lease covers a probe whose `resolve -> send` is still in flight;
    /// the pending-probe scan covers the probe's ACK wait: while the pending
    /// entry exists the reader must stay alive so the ACK can be matched and
    /// the entry removed.  Only when both are clear is the reader aborted.
    async fn wait_for_detach_drain(&self, socket_index: usize, leases: &DynamicSocketLeaseState) {
        loop {
            let pending_clear = self
                .pending_probes
                .lock()
                .await
                .iter()
                .all(|(_, pending)| pending.socket_index != socket_index);
            if leases.outstanding() == 0 && pending_clear {
                return;
            }
            sleep(Duration::from_millis(5)).await;
        }
    }

    /// Remove one dynamic socket by index without touching the peer affinity.
    ///
    /// Used when a fresh-mapping generation fails: the new socket is useless,
    /// while the previous generation's socket (still pinned via affinity)
    /// must keep serving the peer.  If the deleted socket was still pinned,
    /// the affinity is cleared so the next lookup falls back to the pool
    /// instead of resolving to a dead socket.  Idempotent: a socket that was
    /// already detached (e.g. by the provisional watcher) is a no-op.
    async fn detach_dynamic_socket_by_index(&self, socket_index: usize, reason: &str) {
        let entry = {
            let mut state = self.socket_state.lock().await;
            let Some(entry) = state.dynamic.remove(&socket_index) else {
                return;
            };
            if state
                .affinity
                .get(&entry.peer_id)
                .is_some_and(|pin| pin.socket_index == socket_index)
            {
                state.affinity.remove(&entry.peer_id);
            }
            entry
        };
        self.detach_dynamic_entry(entry, reason).await;
    }

    /// Detach a superseded generation's predecessor socket, unless the
    /// predecessor was re-pinned by authenticated traffic since the commit.
    ///
    /// The re-pin check compares the socket INDEX, not the full pin: inbound
    /// evidence that re-pins the same socket stamps a new epoch (the affinity
    /// epoch moves on every adoption), so comparing the whole pin would fail
    /// to recognize the very socket the peer's traffic demonstrably works on
    /// and delete it.  A dynamic index is never reused, so index equality is
    /// unambiguous ownership evidence.  The entry is additionally verified to
    /// still belong to `peer_id` before it is removed.
    ///
    /// Must only be called after the new socket's durable handoff finalized:
    /// until then a cancellation rolls the peer back to the predecessor and
    /// the predecessor must stay attached.
    async fn detach_predecessor_unless_repinned(
        &self,
        peer_id: &str,
        predecessor: PeerSocketPin,
        our_socket_index: usize,
        reason: &str,
    ) {
        let entry = {
            let mut state = self.socket_state.lock().await;
            let repinned = state
                .affinity
                .get(peer_id)
                .is_some_and(|pin| pin.socket_index == predecessor.socket_index);
            if repinned {
                debug!(
                    "predecessor detach skipped for socket index={} peer={peer_id}: the predecessor socket was re-pinned by traffic after the commit",
                    predecessor.socket_index
                );
                return;
            }
            let Some(entry) = state.dynamic.get(&predecessor.socket_index) else {
                return;
            };
            if entry.peer_id != peer_id {
                // The entry was re-purposed for another peer in between (an
                // index can only be re-used by a counter wrap): never touch
                // another peer's socket.
                return;
            }
            let entry = state
                .dynamic
                .remove(&predecessor.socket_index)
                .expect("predecessor entry verified above");
            if state
                .affinity
                .get(&entry.peer_id)
                .is_some_and(|pin| pin.socket_index == predecessor.socket_index)
            {
                state.affinity.remove(&entry.peer_id);
            }
            let _ = our_socket_index;
            entry
        };
        self.detach_dynamic_entry(entry, reason).await;
    }

    /// Detach the dedicated punch socket(s) for a peer, if any.
    ///
    /// Removes every dynamic socket owned by the peer (an old generation's
    /// socket may coexist with a provisional one) and clears the affinity.
    /// Reader aborts run outside the lock.
    pub(crate) async fn detach_dynamic_punch_socket(&self, peer_id: &str, reason: &str) {
        let entries = {
            let mut state = self.socket_state.lock().await;
            let indices = state
                .dynamic
                .iter()
                .filter(|(_, entry)| entry.peer_id == peer_id)
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let mut entries = Vec::with_capacity(indices.len());
            for index in indices {
                if let Some(entry) = state.dynamic.remove(&index) {
                    entries.push(entry);
                }
            }
            state.affinity.remove(peer_id);
            entries
        };
        for entry in entries {
            self.detach_dynamic_entry(entry, reason).await;
        }
    }

    /// Detach the provisional socket and report the generation as superseded
    /// when the owning punch session was cancelled.  Returns whether the
    /// generation must abort.
    async fn abort_generation_if_cancelled(
        &self,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
        peer_id: &str,
        socket_index: usize,
    ) -> bool {
        if !cancellation.is_some_and(|c| c.is_cancelled()) {
            return false;
        }
        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                None,
                None,
                "fresh-mapping generation cancelled by a superseding punch session",
            )
            .await;
        self.detach_dynamic_socket_by_index(socket_index, "generation_cancelled")
            .await;
        true
    }

    /// Detach every dedicated punch socket (daemon shutdown / teardown).
    pub(crate) async fn detach_all_dynamic_punch_sockets(&self, reason: &str) {
        let entries = {
            let mut state = self.socket_state.lock().await;
            let entries = state.dynamic.drain().map(|(_, entry)| entry).collect::<Vec<_>>();
            state
                .affinity
                .retain(|_, pin| pin.socket_index < DYNAMIC_SOCKET_INDEX_BASE);
            entries
        };
        self.dynamic_socket_diagnostics.lock().await.clear();
        for entry in entries {
            self.detach_dynamic_entry(entry, reason).await;
        }
    }

    /// Measure the NAT's public port sequence with a dedicated socket.
    ///
    /// Requests are sent strictly sequentially: the next STUN request only
    /// goes out after the previous response arrived (or its budget ran out).
    /// This makes the observed send-order sequence the actual allocation order
    /// of the CGNAT for this socket; with back-to-back sends a shared CGNAT
    /// can allocate ports for the different destinations in an order that has
    /// nothing to do with our request order, producing deltas like
    /// [-1,+3,-1] that look like a negative step.
    /// Between the last request and the caller's first peer-directed punch
    /// this socket is exclusively owned by the generation: no refresh,
    /// maintainer or relay traffic may consume the next mapping.
    async fn measure_fresh_mapping_batch(
        &self,
        socket: &Arc<UdpSocket>,
        observers: &[SocketAddr],
        stun_timeout: Duration,
    ) -> Vec<MappingObservation> {
        let started_ms = monotonic_millis();
        let mut observations = Vec::with_capacity(observers.len());
        for (sequence, observer) in observers.iter().enumerate() {
            let budget_elapsed_ms = monotonic_millis().saturating_sub(started_ms) as u128;
            let remaining_budget_ms = FRESH_MAPPING_MEASURE_BUDGET
                .as_millis()
                .saturating_sub(budget_elapsed_ms);
            let remaining_samples = observers.len().saturating_sub(sequence).max(1) as u128;
            let per_sample_timeout = stun_timeout
                .min(FRESH_MAPPING_STUN_TIMEOUT)
                .min(Duration::from_millis(
                    remaining_budget_ms.saturating_div(remaining_samples).min(u64::MAX as u128) as u64,
                ));

            let mut request = StunMessage::binding_request();
            request.add_attribute(StunAttribute::Software(MEASUREMENT_SOFTWARE_TAG.to_string()));
            let transaction_id = request.transaction_id;
            let encoded = request.encode();
            let (response_tx, response_rx) = oneshot::channel();
            self.stun_waiters.lock().await.insert(transaction_id, response_tx);
            let sent_at_ms = monotonic_millis();
            if let Err(error) = socket.send_to(&encoded, observer).await {
                self.stun_waiters.lock().await.remove(&transaction_id);
                debug!(
                    "Fresh-mapping STUN send {sequence} to {observer} failed: {error}"
                );
                continue;
            }
            let result = tokio::time::timeout(per_sample_timeout, response_rx).await;
            let responded_at_ms = monotonic_millis();
            let parsed = match result {
                Ok(Ok((data, source))) if source == *observer => {
                    match StunMessage::decode(&data) {
                        Ok(response)
                            if response.transaction_id == transaction_id
                                && response.msg_type == p2pnet_nat::BINDING_RESPONSE =>
                        {
                            response.get_reflexive_address()
                        }
                        Ok(_) => None,
                        Err(_) => None,
                    }
                }
                _ => None,
            };
            if let Some(observed) = parsed {
                observations.push(MappingObservation {
                    sequence: sequence as u16,
                    observer: *observer,
                    observed,
                    sent_at_ms,
                    responded_at_ms,
                    local_endpoint: socket.local_addr().ok().unwrap_or_else(|| {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                    }),
                });
            } else {
                debug!(
                    "Fresh-mapping STUN {sequence} to {observer} got no usable response within {:?}",
                    per_sample_timeout
                );
            }
        }
        observations
    }

    /// Run one atomic fresh-mapping punch generation for a peer.
    ///
    /// 1. Bind a fresh dedicated socket (never used before).
    /// 2. Measure 3-4 distinct STUN observers in send order.
    /// 3. Model the port sequence and build the rank-ordered prediction.
    /// 4. Punch the peer's stable public endpoint from the same socket,
    ///    creating the peer-facing mapping predicted by the model.
    ///
    /// The dedicated socket stays attached for the peer, so a successful
    /// Direct path continues to use it (and only it) as the data socket.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_fresh_mapping_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        stable_targets: &[SocketAddr],
        probe_interval: Duration,
        attempts: u32,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> FreshMappingOutcome {
        if !self.peers.local_nat_requires_fresh_mapping_punch().await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat);
        }
        if cancellation.is_some_and(|c| c.is_cancelled()) {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        let stable_targets = stable_targets
            .iter()
            .copied()
            .filter(|endpoint| fresh_mapping_target_eligible(*endpoint))
            .collect::<Vec<_>>();
        if stable_targets.is_empty() {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::NoStablePeerEndpoint);
        }
        if self.local_node_id.is_none()
            || self.peers.probe_key_for_peer(peer_id).await.is_none()
        {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::MissingProbeKey);
        }
        if self.peers.is_direct(peer_id).await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }

        // The previous generation's dedicated socket stays attached until the
        // new one is measured, modeled and punched: if this generation fails
        // (insufficient STUN samples, rejected model, superseded by an older
        // session), the old peer-facing mapping must keep working instead of
        // being destroyed preemptively.

        let network_generation = self.peers.current_network_generation().await;
        let punch_generation = self.peers.next_punch_generation(peer_id).await;
        let (socket_index, socket) = match self.bind_fresh_punch_socket().await {
            Ok(bound) => bound,
            Err(error) => {
                warn!("Fresh-mapping punch socket bind failed for peer {peer_id}: {error}");
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BindFailed);
            }
        };
        // The attach returns the ownership guard directly: the map insert and
        // the guard's creation happen without any await in between, so there
        // is never a provisional socket without a watcher, even if this future
        // is dropped at the very next await point.
        let provisional_guard = match self
            .attach_dynamic_punch_socket(
                peer_id,
                socket_index,
                socket.clone(),
                network_generation,
                punch_generation,
                cancellation,
            )
            .await
        {
            Ok(guard) => guard,
            Err(error) => {
                warn!("Failed to attach fresh-mapping punch socket for peer {peer_id}: {error:?}");
                return FreshMappingOutcome::Rejected(match error {
                    DynamicSocketAttachError::CapacityRejected => {
                        FreshMappingRejection::CapacityRejected
                    }
                    DynamicSocketAttachError::NoInboundChannel => FreshMappingRejection::BindFailed,
                });
            }
        };
        // From here on the socket is provisional: if the owning session is
        // preempted while this future is dropped at an await point, the
        // watcher detaches it unless the generation commits.  The commit is
        // an atomic phase transition under the socket-state lock, so the
        // watcher and the generation can never disagree about ownership.
        // Without a session cancellation handle the watcher still covers a
        // dropped future via the guard's own stop signal.

        let observers = observers
            .iter()
            .copied()
            .filter(|observer| observer.is_ipv4())
            .take(FRESH_MAPPING_OBSERVERS_PER_BATCH)
            .collect::<Vec<_>>();
        if observers.len() < 3 {
            self.detach_dynamic_socket_by_index(socket_index, "insufficient_observers").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
        }

        let local_endpoint = socket
            .local_addr()
            .ok()
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_generation_started",
                None,
                Some(observers.len()),
                None,
                format!(
                    "punch_generation={punch_generation} network_generation={network_generation} socket_local={local_endpoint} socket_index={socket_index} observers={} targets={}",
                    observers.len(),
                    stable_targets.len()
                ),
            )
            .await;

        let started_ms = monotonic_millis();
        let observations = self
            .measure_fresh_mapping_batch(&socket, &observers, stun_timeout)
            .await;
        let finished_ms = monotonic_millis();
        if self
            .abort_generation_if_cancelled(cancellation, peer_id, socket_index)
            .await
        {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        let batch = MappingBatch {
            generation: punch_generation,
            network_generation,
            socket_identity: local_endpoint,
            observations,
            started_at_ms: started_ms,
            finished_at_ms: finished_ms,
        };
        let sample_count = batch.successful_samples();

        for observation in &batch.observations {
            info!(
                event = "fresh_mapping_observer",
                peer_id = %peer_id,
                network_generation = network_generation,
                punch_generation = punch_generation,
                socket_local = %observation.local_endpoint,
                sequence = observation.sequence,
                observer = %observation.observer,
                srflx = %observation.observed,
                rtt_ms = observation.rtt_ms().unwrap_or(0),
                "fresh_mapping_observer peer_id={} punch_generation={} seq={} observer={} srflx={} rtt_ms={}",
                peer_id,
                punch_generation,
                observation.sequence,
                observation.observer,
                observation.observed,
                observation.rtt_ms().unwrap_or(0)
            );
        }

        if sample_count < 3 {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    "insufficient STUN samples for a mapping model",
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "insufficient_samples").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
        }

        if batch.public_ip().is_none() {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    "observed public IP changed across the measurement batch",
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "public_ip_changed").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
        }

        let now_ms = monotonic_millis();
        let model = match build_model_for_batch(&batch, FRESH_MAPPING_MODEL_MAX_AGE, now_ms) {
            Ok(model) => model,
            Err(ModelRejection::BatchStale) => {
                self.detach_dynamic_socket_by_index(socket_index, "batch_stale").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
            }
            Err(ModelRejection::InconsistentBatch) => {
                self.detach_dynamic_socket_by_index(socket_index, "inconsistent_batch").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InconsistentBatch);
            }
            Err(ModelRejection::InsufficientSamples) => {
                self.detach_dynamic_socket_by_index(socket_index, "insufficient_samples").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
            }
            Err(ModelRejection::PublicIpChanged) => {
                self.detach_dynamic_socket_by_index(socket_index, "public_ip_changed").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
            }
            Err(ModelRejection::NarrowRandom | ModelRejection::NoConsistentStep) => {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "fresh_mapping_rejected",
                        None,
                        Some(sample_count),
                        None,
                        format!(
                            "port sequence is not consistently linear: sequence={:?} deltas={:?}",
                            batch.ordered_ports(),
                            model_deltas(&batch)
                        ),
                    )
                    .await;
                self.detach_dynamic_socket_by_index(socket_index, "unpredictable_sequence").await;
                return FreshMappingOutcome::Rejected(
                    FreshMappingRejection::UnpredictableSequence,
                );
            }
        };

        let step = match &model.kind {
            PortModelKind::FixedStep { step } | PortModelKind::Linear { step }
            | PortModelKind::NoisyLinear { step } => Some(*step),
            _ => None,
        };
        if step.is_some_and(|step| u32::from(step.unsigned_abs()) > FRESH_MAPPING_MAX_ABS_STEP as u32) {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    format!(
                        "model step {} exceeds the {FRESH_MAPPING_MAX_ABS_STEP} bound; treating as unpredictable",
                        step.unwrap_or(0)
                    ),
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "unpredictable_sequence").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::UnpredictableSequence);
        }

        let ports = batch.ordered_ports();
        let last = *ports.last().expect("three or more samples");
        // The peer-facing mapping is fixed when the first peer-directed punch
        // goes out.  The window must cover the ports a shared CGNAT consumed
        // between the last STUN allocation (request send, not response) and
        // that punch; signal propagation time does not move our own mapping.
        let first_sent_at_ms = batch
            .observations
            .first()
            .map(|observation| observation.sent_at_ms)
            .unwrap_or(batch.started_at_ms);
        let last_sent_at_ms = batch
            .observations
            .last()
            .map(|observation| observation.sent_at_ms)
            .unwrap_or(batch.finished_at_ms);
        let measurement_span_ms = last_sent_at_ms.saturating_sub(first_sent_at_ms);
        let probe_gap_ms = now_ms.saturating_sub(last_sent_at_ms);
        let predicted = predict_ports_for_elapsed(&model, last, measurement_span_ms, probe_gap_ms);
        let predicted_ports = predicted.iter().map(|candidate| candidate.port).collect::<Vec<_>>();
        let public_ip = batch.public_ip();

        let sequence_label = format!("{:?}", ports);
        let deltas_label = format!("{:?}", model.deltas);
        info!(
            event = "fresh_mapping_model",
            peer_id = %peer_id,
            network_generation = network_generation,
            punch_generation = punch_generation,
            socket_local = %local_endpoint,
            model = ?model.kind,
            confidence = model.confidence,
            sequence = %sequence_label,
            deltas = %deltas_label,
            sample_age_ms = now_ms.saturating_sub(batch.started_at_ms),
            predicted = ?predicted_ports,
            "fresh_mapping_model peer_id={} punch_generation={} model={:?} confidence={} sequence={} deltas={} predicted={:?}",
            peer_id,
            punch_generation,
            model.kind,
            model.confidence,
            sequence_label,
            deltas_label,
            predicted_ports
        );
        // The fresh-mapping model is only recorded after ownership, network
        // and direct-path validations below pass and the generation commits:
        // a stale generation must never overwrite the fresh state a newer
        // generation already recorded.

        // Re-validate ownership before touching any shared state: the ~1s
        // measurement may have seen the peer go Direct through the previous
        // socket, the network generation change, or this session be
        // superseded.  Never tear down a working path or commit a stale
        // mapping on top of it.
        if self
            .abort_generation_if_cancelled(cancellation, peer_id, socket_index)
            .await
        {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        if self.peers.is_direct(peer_id).await {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    None,
                    None,
                    None,
                    "peer became Direct while the fresh-mapping generation measured; keeping the working data path",
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "peer_became_direct")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        if self.peers.current_network_generation().await != network_generation {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    None,
                    None,
                    None,
                    format!(
                        "network generation changed during the fresh-mapping measurement (expected {network_generation}); discarding the batch"
                    ),
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "network_generation_changed")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
        }

        // The peer-facing punch loop: only sends from the dedicated socket
        // may claim success.  The mapping is fixed when the first peer-facing
        // probe enters the kernel send queue.
        let first_punch_sent_at_ms = monotonic_millis();
        let mut sent = 0u32;
        for round in 0..attempts {
            if cancellation.is_some_and(|c| c.is_cancelled()) {
                debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; session superseded"
                );
                break;
            }
            for target in &stable_targets {
                match self
                    .send_probe_on_socket(
                        socket_index,
                        socket.clone(),
                        Some(peer_id),
                        *target,
                        true,
                        PendingProbePurpose::ConnectivityCheck,
                    )
                    .await
                {
                    Ok(_) => {
                        sent = sent.saturating_add(1);
                        if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                            sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                        }
                    }
                    Err(error) => {
                        debug!(
                            "Fresh-mapping punch from socket {socket_index} to {} failed: {error}",
                            target
                        );
                    }
                }
                if round + 1 < attempts && !probe_interval.is_zero() {
                    sleep(probe_interval.min(Duration::from_millis(50))).await;
                }
            }
        }
        let last_punch_sent_at_ms = monotonic_millis();

        // No peer-facing probe ever entered the kernel queue: the generation
        // must not claim success.  The provisional socket is detached while
        // the previous generation's socket (the peer's working path) stays.
        if sent == 0 {
            let cancelled = cancellation.is_some_and(|c| c.is_cancelled());
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    stable_targets.first().copied(),
                    Some(stable_targets.len()),
                    None,
                    format!(
                        "fresh-mapping generation sent no peer-facing probe (attempts={attempts}); keeping the previous generation's socket"
                    ),
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "no_peer_facing_probe")
                .await;
            return FreshMappingOutcome::Rejected(if cancelled {
                FreshMappingRejection::Superseded
            } else {
                FreshMappingRejection::NoProbesSent
            });
        }

        // The new generation is now established (measurement, model and at
        // least one peer-facing punch all completed).  Commit the socket and
        // pin the affinity as one atomic phase transition under the
        // socket-state lock: the provisional watcher can never detach a
        // committed socket, and a cancelled generation can never commit.
        // The commit re-validates ownership (peer, socket index, network
        // generation, per-peer committed-generation high-water) and returns
        // the predecessor pin so a cancellation that lands right after the
        // commit can roll the peer back to its old path — conditionally, by
        // the watcher, only while the affinity still equals this commit's pin.
        let commit_outcome = provisional_guard
            .commit_and_pin(
                self,
                peer_id,
                socket_index,
                network_generation,
                punch_generation,
            )
            .await;
        if !commit_outcome.committed {
            // The watcher already detached the provisional socket (session
            // cancelled while this future was dropped at an await point, or
            // the commit raced cancellation): abort without touching the
            // previous generation's socket.
            self.detach_dynamic_socket_by_index(socket_index, "generation_abandoned")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        // Cancellation may still have arrived between the final pre-commit
        // check and the commit.  The durable handoff is skipped: when this
        // future ends, the guard drops and its watcher performs the
        // conditional rollback (restores the predecessor pin and detaches
        // this socket — only while the affinity still equals the pin this
        // commit installed, so a newer commit can never be downgraded).
        if cancellation.is_some_and(|c| c.is_cancelled()) {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    stable_targets.first().copied(),
                    Some(stable_targets.len()),
                    None,
                    "fresh-mapping generation committed after its punch session was superseded; the watcher restores the previous generation's pin and detaches the socket",
                )
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }

        // Final ownership verification before claiming success: the committed
        // socket must still be attached in a usable phase and still pinned
        // for this peer.  A network-generation change or a superseding
        // generation can detach it during the punch; an Accepted outcome must
        // never correspond to a detached socket.  The generation's guard is
        // returned with the outcome: the durable handoff (`finalize`) runs in
        // the caller AFTER the fresh prediction was advertised to the peer,
        // so an advertise failure or a session cancellation between the
        // commit and the advertise can still roll the socket back.
        let still_owned = {
            let state = self.socket_state.lock().await;
            state.dynamic.get(&socket_index).is_some_and(|entry| {
                entry.phase.is_usable() && entry.peer_id == peer_id
            }) && state
                .affinity
                .get(peer_id)
                .is_some_and(|pin| pin.socket_index == socket_index)
        };
        if !still_owned {
            self.detach_dynamic_socket_by_index(socket_index, "ownership_lost_before_accept")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }

        // Record the fresh mapping only now that ownership, network and
        // direct-path validations passed and the socket is committed.
        self.peers
            .record_fresh_mapping(
                peer_id,
                p2pnet_nat::mapping::PortModel::clone(&model),
                predicted_ports.clone(),
                local_endpoint,
                public_ip,
                punch_generation,
                network_generation,
            )
            .await;

        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_punch_sent",
                stable_targets.first().copied(),
                Some(stable_targets.len()),
                Some(sent),
                format!(
                    "punch_generation={punch_generation} socket_local={local_endpoint} first_sent_ms={first_punch_sent_at_ms} last_sent_ms={last_punch_sent_at_ms} targets={} sent={sent}",
                    stable_targets.len()
                ),
            )
            .await;
        debug!(
            "Fresh-mapping punch generation {punch_generation} sent {sent} probes to peer {peer_id} from {local_endpoint}"
        );

        // The durable handoff is NOT performed here: the caller advertises
        // the fresh prediction window and only then calls `finalize`, which
        // waits for the watcher's explicit acknowledgement and detaches the
        // superseded predecessor.  Until then the peer can still be rolled
        // back to its previous path on cancellation.
        FreshMappingOutcome::Accepted(
            Box::new(FreshMappingResult {
                punch_generation,
                network_generation,
                socket_local_endpoint: local_endpoint,
                socket_index,
                model,
                predicted_ports,
                public_ip,
                first_punch_sent_at_ms,
                last_punch_sent_at_ms,
            }),
            Box::new(provisional_guard),
        )
    }

    /// Probe the peer's candidates from the dedicated punch socket only.
    ///
    /// Used by the synchronized punch flow after a fresh-mapping generation,
    /// so the predictable mapping socket carries the whole candidate sweep
    /// while the other pool sockets stay untouched.
    pub(crate) async fn punch_candidates_from_dynamic_socket(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        // The leased resolve re-validates peer ownership, Committed phase and
        // the network generation under the socket-state lock and keeps the
        // entry's reader alive until this whole sweep ends: a detach racing
        // the resolve can neither hand out a socket the peer must not use nor
        // kill the reader before the sweep's ACKs can arrive.
        let Some((index, socket, _lease)) = self
            .resolve_dynamic_socket_for_send(peer_id)
            .await
        else {
            return Ok(PunchSendReport::default());
        };
        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        let mut packets_sent = 0u32;
        let mut sent_endpoints = HashSet::new();
        for round in schedule {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }
            for candidate in round.endpoints {
                match self
                    .send_probe_on_socket(
                        index,
                        socket.clone(),
                        Some(peer_id),
                        candidate,
                        false,
                        PendingProbePurpose::ConnectivityCheck,
                    )
                    .await
                {
                    Ok(_) => {
                        packets_sent = packets_sent.saturating_add(1);
                        sent_endpoints.insert(candidate);
                        self.peers.record_direct_probe_sent(peer_id, candidate).await;
                        if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                            sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                        }
                    }
                    Err(error) => {
                        debug!(
                            "Dynamic-socket punch to peer {peer_id} candidate {candidate} failed: {error}"
                        );
                    }
                }
            }
        }
        Ok(PunchSendReport {
            packets_sent,
            unique_target_endpoints: u32::try_from(sent_endpoints.len()).unwrap_or(u32::MAX),
        })
    }
}

fn model_deltas(batch: &MappingBatch) -> Vec<i16> {
    let ports = batch.ordered_ports();
    ports
        .windows(2)
        .map(|pair| p2pnet_nat::modular_difference(pair[0], pair[1]))
        .collect()
}

/// Whether a target endpoint may receive a fresh-mapping punch.
///
/// Production filters to real public probe endpoints; unit tests simulate the
/// peer's public side on the loopback NAT address.
fn fresh_mapping_target_eligible(endpoint: SocketAddr) -> bool {
    if is_public_probe_endpoint(endpoint) {
        return true;
    }
    #[cfg(test)]
    {
        endpoint.ip().is_loopback()
    }
    #[cfg(not(test))]
    {
        let _ = endpoint;
        false
    }
}

fn monotonic_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Outcome of one atomic commit-and-pin phase transition.
#[derive(Debug, Clone, Copy)]
struct CommitOutcome {
    /// Whether the socket transitioned from Provisional to
    /// CommittedPendingHandoff and was pinned as the peer's traffic socket.
    committed: bool,
    /// The affinity pin the commit replaced, captured under the same
    /// socket-state lock.  A cancelled generation must restore it so the
    /// peer keeps its previous working path — but only while the affinity
    /// still equals THIS commit's pin (a newer commit owns the affinity
    /// after that and a blind restore would downgrade it).
    predecessor: Option<PeerSocketPin>,
    /// The pin this commit installed.  Post-commit rollback compares the
    /// live affinity against this pin before touching anything.
    installed: Option<PeerSocketPin>,
}

/// How long `finalize` waits for the watcher's explicit acknowledgement
/// before treating the handoff as durable (the watcher may be gone, in which
/// case nothing can roll the socket back anymore).
const FINALIZE_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Read the latest commit outcome from the watcher's watch channel without
/// holding any lock: `borrow_and_update` marks the value as seen so the next
/// `changed()` parks until a NEW publish, while `borrow` re-reads the same
/// value — the watcher re-verifies plain values on every wake to stay immune
/// to lost notifications.
fn watched_commit_outcome(
    commit_rx: &mut tokio::sync::watch::Receiver<Option<CommitOutcome>>,
) -> Option<CommitOutcome> {
    (*commit_rx.borrow_and_update()).as_ref().map(|outcome| *outcome)
}

/// Cancellation-safe ownership for a provisional fresh-mapping punch socket.
///
/// The generation's future can be dropped at any await point when the owning
/// punch session is preempted (the session `select` aborts the work future),
/// so the explicit error paths never run.  This guard watches the session's
/// cancellation and the guard's own drop from an independent task and detaches
/// the socket unless the generation committed and then finalized the durable
/// handoff.
///
/// The guard is created by `attach_dynamic_punch_socket` BEFORE the map
/// insert, so there is never an await between the insert and the guard
/// existing: every drop of the generation future is covered.
///
/// Lifecycle state machine:
///
/// - `Provisional`: the socket is owned by its in-flight generation; the
///   watcher detaches it on cancellation / dropped future.
/// - `CommittedPendingHandoff`: `commit_and_pin` re-validated ownership (peer
///   id, socket index, network generation, per-peer committed-generation
///   high-water) and the session's cancellation, flipped the phase and pinned
///   the affinity in one socket-state lock transaction.  The watcher stays
///   armed: a cancellation or dropped future rolls the peer back to the
///   predecessor pin and detaches the socket — conditionally, only while the
///   affinity still equals the pin THIS commit installed.
/// - `Finalized`: `finalize` flipped the phase under the lock, published the
///   durable handoff and WAITED for the watcher's explicit acknowledgement —
///   no racing stop signal can win after that.  Only peer-level cleanup
///   (PeerLeft, public-key change, a newer commit's predecessor detach) may
///   remove the socket.
pub(crate) struct ProvisionalSocketGuard {
    transport: UdpTransport,
    socket_index: usize,
    peer_id: String,
    cancellation: Arc<crate::PunchSessionCancellation>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    commit_tx: tokio::sync::watch::Sender<Option<CommitOutcome>>,
    finalize_tx: tokio::sync::watch::Sender<bool>,
    /// The watcher's finalize acknowledgement, taken by `finalize` and awaited
    /// with a bounded timeout.
    finalize_ack: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    /// The outcome of the commit that succeeded for this guard, captured under
    /// the socket-state lock; `finalize` uses it for the predecessor detach.
    outcome: std::sync::Mutex<Option<CommitOutcome>>,
    #[allow(dead_code)]
    watcher: tokio::task::JoinHandle<()>,
}

impl ProvisionalSocketGuard {
    fn spawn(
        transport: UdpTransport,
        socket_index: usize,
        peer_id: String,
        cancellation: Arc<crate::PunchSessionCancellation>,
    ) -> Self {
        let watcher_transport = transport.clone();
        let watcher_cancellation = cancellation.clone();
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let (commit_tx, mut commit_rx) =
            tokio::sync::watch::channel::<Option<CommitOutcome>>(None);
        let (finalize_tx, mut finalize_rx) = tokio::sync::watch::channel(false);
        let (finalize_ack_tx, finalize_ack) = oneshot::channel();
        let watcher = tokio::spawn(async move {
            // Wake-verification loop.  watch `changed()` has subtle initial-
            // value semantics (a fresh receiver's first poll may resolve
            // immediately, and a notification can be lost between polls), so
            // every wake is re-verified against the plain values and the
            // loop re-checks everything periodically.  The watcher can never
            // miss a state change: a cancellation, a guard drop, a commit
            // publish or a finalize is observed at the latest 50 ms after it
            // happened.
            //
            // The FINALIZE check is ordered BEFORE the stop/cancellation
            // check on every wake: `finalize` flips the entry phase to
            // Finalized under the socket-state lock before publishing, so a
            // stop signal that races the durable handoff can never win.
            let mut committed: Option<CommitOutcome> = None;
            loop {
                // Re-verify the plain values first: deterministic, immune to
                // lost wake-ups.
                if let Some(outcome) = watched_commit_outcome(&mut commit_rx) {
                    if outcome.committed {
                        committed = Some(outcome);
                    }
                }
                if *finalize_rx.borrow() {
                    // Durable handoff: the peer's long-term ownership owns
                    // this socket now; the watcher's job is done.  Ack so the
                    // guard's `finalize` never times out on a healthy
                    // watcher.
                    let _ = finalize_ack_tx.send(());
                    return;
                }
                if watcher_cancellation.is_cancelled() || *stop_rx.borrow() {
                    break;
                }
                // Park until a wake or the re-verify deadline.
                tokio::select! {
                    _ = watcher_cancellation.cancelled() => {}
                    _ = stop_rx.changed() => {}
                    _ = commit_rx.changed() => {}
                    _ = finalize_rx.changed() => {}
                    _ = sleep(Duration::from_millis(50)) => {}
                }
            }
            // One final re-verification after the wake: a commit or finalize
            // published while the select was parked must win over the stop
            // signal that woke us.
            if let Some(outcome) = watched_commit_outcome(&mut commit_rx) {
                if outcome.committed {
                    committed = Some(outcome);
                }
            }
            if *finalize_rx.borrow() {
                let _ = finalize_ack_tx.send(());
                return;
            }
            // The rollback decision runs under ONE socket-state lock
            // acquisition: `rollback_committed_entry` never re-acquires the
            // lock, so the watcher can never self-deadlock.
            let detached: Option<DynamicPunchSocket> = {
                let mut state = watcher_transport.socket_state.lock().await;
                // The durable handoff may have flipped the phase while the
                // watcher waited for the lock: a Finalized entry is never
                // rolled back.
                let Some(entry) = state.dynamic.get(&socket_index) else {
                    // Never attached (pre-insert drop) or already detached by
                    // an explicit path; the reader exits via the shutdown
                    // channel closure.  Ack if the finalize raced us anyway.
                    if *finalize_rx.borrow() {
                        drop(state);
                        let _ = finalize_ack_tx.send(());
                    }
                    return;
                };
                if *finalize_rx.borrow() || entry.phase == DynamicSocketPhase::Finalized {
                    drop(state);
                    let _ = finalize_ack_tx.send(());
                    return;
                }
                match committed {
                    None => {
                        if entry.phase == DynamicSocketPhase::Provisional {
                            // Pre-commit abandonment: detach the provisional
                            // socket.
                            let entry = state
                                .dynamic
                                .remove(&socket_index)
                                .expect("provisional socket verified above");
                            if state
                                .affinity
                                .get(&entry.peer_id)
                                .is_some_and(|pin| pin.socket_index == socket_index)
                            {
                                state.affinity.remove(&entry.peer_id);
                            }
                            Some(entry)
                        } else {
                            // A commit slipped in before this wake-up won the
                            // lock.  The outcome is published under the same
                            // lock before the phase flip, so it is visible
                            // now; without it the commit is still in flight
                            // and the generation owns the socket.
                            match watched_commit_outcome(&mut commit_rx) {
                                Some(outcome) if outcome.committed => {
                                    watcher_transport.rollback_committed_entry(
                                        &mut state,
                                        &socket_index,
                                        &outcome,
                                    )
                                }
                                _ => None,
                            }
                        }
                    }
                    Some(outcome) => watcher_transport.rollback_committed_entry(
                        &mut state,
                        &socket_index,
                        &outcome,
                    ),
                }
            };
            if let Some(entry) = detached {
                watcher_transport
                    .detach_dynamic_entry(entry, "generation_cancelled")
                    .await;
            }
        });
        Self {
            transport,
            socket_index,
            peer_id,
            cancellation,
            stop_tx,
            commit_tx,
            finalize_tx,
            finalize_ack: std::sync::Mutex::new(Some(finalize_ack)),
            outcome: std::sync::Mutex::new(None),
            watcher,
        }
    }

    /// Atomically transition the provisional socket to
    /// `CommittedPendingHandoff` and pin it as the peer's traffic socket,
    /// after re-validating ownership in the same lock transaction.
    ///
    /// The commit re-checks, under the socket-state lock:
    /// - the entry still exists, still belongs to `peer_id` and is still
    ///   `Provisional` at `socket_index`;
    /// - the entry's network generation still equals the current network
    ///   generation (read from the lock-free mirror inside the lock, so a
    ///   generation advance can never slip between the read and the check);
    /// - the session is not cancelled;
    /// - no NEWER generation already committed for this peer (the per-peer
    ///   committed-generation high-water), so an older generation can never
    ///   pin over a newer commit no matter how the awaits interleaved.
    ///
    /// The outcome (predecessor + installed pin) is published to the watcher
    /// inside the same critical section, so the watcher's post-commit
    /// rollback always knows exactly which pin this commit installed.
    ///
    /// Returns `committed == false` when any check fails; the provisional
    /// socket is then left for the watcher (which may already be waking on
    /// the cancellation).
    async fn commit_and_pin(
        &self,
        transport: &UdpTransport,
        peer_id: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
    ) -> CommitOutcome {
        let refused = CommitOutcome {
            committed: false,
            predecessor: None,
            installed: None,
        };
        let mut state = transport.socket_state.lock().await;
        let Some(entry) = state.dynamic.get(&socket_index) else {
            return refused;
        };
        // The network generation is re-read UNDER the lock (lock-free mirror)
        // and must match both the entry's stamped generation and the value
        // the generation measured with: a stale generation can never commit a
        // mapping that belongs to an old network.
        let current_network_generation = transport.peers.current_network_generation_sync();
        if entry.phase != DynamicSocketPhase::Provisional
            || entry.peer_id != peer_id
            || entry.network_generation != network_generation
            || entry.network_generation != current_network_generation
            || entry.punch_generation != punch_generation
        {
            return refused;
        }
        if self.cancellation.is_cancelled() {
            // Cancelled before the commit took the lock: leave the
            // provisional socket for the watcher (already woken) and abort.
            return refused;
        }
        // A newer generation that already committed for this peer must never
        // be pinned over by this older commit.
        if state
            .committed_punch_generations
            .get(peer_id)
            .is_some_and(|committed| *committed > punch_generation)
        {
            debug!(
                "stale commit refused for socket index={socket_index} peer={peer_id}: generation {punch_generation} is older than the committed generation {}",
                state
                    .committed_punch_generations
                    .get(peer_id)
                    .copied()
                    .unwrap_or(0)
            );
            return refused;
        }
        let predecessor = state.affinity.get(peer_id).copied();
        let epoch = state.next_epoch();
        let installed = PeerSocketPin {
            socket_index,
            epoch,
        };
        state.affinity.insert(peer_id.to_string(), installed);
        state
            .committed_punch_generations
            .entry(peer_id.to_string())
            .and_modify(|committed| *committed = (*committed).max(punch_generation))
            .or_insert(punch_generation);
        let outcome = CommitOutcome {
            committed: true,
            predecessor,
            installed: Some(installed),
        };
        *self.outcome.lock().expect("guard outcome mutex") = Some(outcome);
        // Publish under the same lock the entry was flipped under: the
        // watcher can never observe a CommittedPendingHandoff entry without
        // the outcome.
        let _ = self.commit_tx.send(Some(outcome));
        // Flip the phase last, still inside the lock: a concurrent watcher
        // that wins the lock between the publish and the phase flip sees the
        // outcome and the Provisional entry, and its rollback only runs for
        // committed entries, so the ordering cannot mislead it.
        state
            .dynamic
            .get_mut(&socket_index)
            .expect("committed entry verified above")
            .phase = DynamicSocketPhase::CommittedPendingHandoff;
        outcome
    }

    /// Hand the committed socket to the peer's long-term ownership.
    ///
    /// Called only after the generation's durable handoff (the fresh mapping
    /// was recorded AND the prediction was advertised to the peer).  The
    /// entry phase is flipped to `Finalized` under the socket-state lock —
    /// from that point the watcher can never roll the socket back — then the
    /// finalize value is published and the watcher's EXPLICIT acknowledgement
    /// is awaited, so a racing stop signal can never be processed before the
    /// finalize.  Only then is the superseded predecessor detached (unless it
    /// was re-pinned by authenticated traffic).
    ///
    /// Returns `false` when the socket was already rolled back (entry gone)
    /// or never committed: the durable handoff did not happen and the caller
    /// must not treat the socket as the peer's long-term path.
    pub(crate) async fn finalize(&self) -> bool {
        // Phase flip under the lock: after this, the watcher can never roll
        // the socket back.
        let flipped = {
            let mut state = self.transport.socket_state.lock().await;
            let Some(entry) = state.dynamic.get_mut(&self.socket_index) else {
                // Rolled back (or evicted) before the durable handoff: the
                // watcher already restored the predecessor.
                return false;
            };
            if entry.phase == DynamicSocketPhase::Provisional {
                // Never committed; the generation's own cleanup owns it.
                return false;
            }
            if entry.phase != DynamicSocketPhase::Finalized {
                entry.phase = DynamicSocketPhase::Finalized;
            }
            true
        };
        if !flipped {
            return false;
        }
        // Publish the durable handoff and WAIT for the watcher's explicit
        // acknowledgement (bounded: a dead watcher cannot roll back anyway).
        let _ = self.finalize_tx.send(true);
        let ack = self.finalize_ack.lock().expect("finalize ack mutex").take();
        if let Some(ack) = ack {
            let _ = tokio::time::timeout(FINALIZE_ACK_TIMEOUT, ack).await;
        }
        // The predecessor detach runs only now, after the durable handoff: a
        // cancellation between the commit and this point must still be able
        // to roll the peer back to the predecessor.
        let predecessor = self
            .outcome
            .lock()
            .expect("guard outcome mutex")
            .and_then(|outcome| outcome.predecessor);
        if let Some(predecessor) = predecessor.filter(|pin| {
            pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE
                && pin.socket_index != self.socket_index
        }) {
            self.transport
                .detach_predecessor_unless_repinned(
                    &self.peer_id,
                    predecessor,
                    self.socket_index,
                    "superseded_by_new_generation",
                )
                .await;
        }
        true
    }
}

impl UdpTransport {
    /// Post-commit rollback decision for one socket, executed under a SINGLE
    /// socket-state lock acquisition (the guard watcher holds the lock while
    /// calling this, so it must never re-acquire it).
    ///
    /// Returns the entry to detach, or `None` when nothing must be detached:
    /// - the entry is already `Finalized` or gone;
    /// - the affinity still equals THIS commit's installed pin → full
    ///   rollback: restore the predecessor pin (or clear the affinity) and
    ///   detach this generation's socket;
    /// - the affinity was re-pinned to THIS socket by fresh evidence → the
    ///   socket demonstrably carries the peer's traffic: promote it to
    ///   `Finalized` and keep it;
    /// - a newer commit or evidence owns the affinity → detach this socket
    ///   WITHOUT restoring the predecessor (a restore would downgrade the
    ///   current owner — the "G2 rollback overwrites G3 commit" race).
    fn rollback_committed_entry(
        &self,
        state: &mut SocketState,
        socket_index: &usize,
        outcome: &CommitOutcome,
    ) -> Option<DynamicPunchSocket> {
        let installed = outcome.installed?;
        {
            let entry = state.dynamic.get(socket_index)?;
            if entry.phase == DynamicSocketPhase::Finalized {
                return None;
            }
        }
        let peer_id = state.dynamic.get(socket_index)?.peer_id.clone();
        let affinity = state.affinity.get(&peer_id).copied();
        if affinity == Some(installed) {
            // Full rollback: restore the predecessor pin and detach this
            // generation's socket.
            let entry = state
                .dynamic
                .remove(socket_index)
                .expect("committed socket verified above");
            let predecessor = outcome.predecessor;
            let valid = predecessor.is_some_and(|pin| {
                pin.socket_index < self.socket_count()
                    || (pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE
                        && state.dynamic.contains_key(&pin.socket_index))
            });
            if valid {
                let epoch = state.next_epoch();
                if let Some(predecessor) = predecessor {
                    state.affinity.insert(
                        peer_id,
                        PeerSocketPin {
                            socket_index: predecessor.socket_index,
                            epoch,
                        },
                    );
                }
            } else {
                state.affinity.remove(&peer_id);
            }
            Some(entry)
        } else if affinity.is_some_and(|pin| pin.socket_index == *socket_index) {
            // The socket was re-pinned by fresh inbound evidence since the
            // commit: it demonstrably carries the peer's traffic and must not
            // be deleted.  Promote it to the durable phase; the predecessor
            // is NOT restored (this socket owns the affinity now).
            state
                .dynamic
                .get_mut(socket_index)
                .expect("committed socket verified above")
                .phase = DynamicSocketPhase::Finalized;
            debug!(
                "rollback promoted socket index={socket_index} peer={peer_id} to Finalized: the socket was re-pinned by fresh evidence and stays as the working data path"
            );
            None
        } else {
            // A newer commit or fresh evidence owns the affinity: this socket
            // is superseded.  Detach it WITHOUT restoring the predecessor.
            debug!(
                "rollback detached socket index={socket_index} peer={peer_id} without restoring the predecessor (a newer owner holds the affinity)"
            );
            let entry = state
                .dynamic
                .remove(socket_index)
                .expect("committed socket verified above");
            Some(entry)
        }
    }
}

impl Drop for ProvisionalSocketGuard {
    fn drop(&mut self) {
        self.stop_tx.send_replace(true);
    }
}
