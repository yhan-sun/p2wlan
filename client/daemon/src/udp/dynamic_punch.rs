use p2pnet_nat::adaptive::{DirectionPattern, ReverseDetector, StepLearner};
use p2pnet_nat::mapping::{
    build_model_for_batch, infer_allocation_model, predict_ports_with_learning, MappingBatch,
    MappingObservation, ModelRejection, PortModel, PortModelKind,
};

const MEASUREMENT_SOFTWARE_TAG: &str = "P2WLAN/0.2";
/// A spawned dynamic reader should reach its first socket receive poll
/// immediately.  Bound the handshake so a broken runtime/task cannot leave a
/// fresh-mapping generation waiting forever before its first STUN request.
const DYNAMIC_READER_READY_TIMEOUT: Duration = Duration::from_secs(1);
const HARD_HARD_BIRTHDAY_WAVE_INTERVAL: Duration = Duration::from_millis(20);
const HARD_HARD_BIRTHDAY_WAVES: usize = 2;

/// Adaptive-prediction learner state for one network generation, scoped by
/// destination so a stride learned toward STUN observers is not blindly applied
/// to a real peer (audit P1-B: complex CGNAT may bucket allocation by target;
/// Mini-Air observed the peer-facing mapping diverge from the STUN direction).
#[derive(Debug)]
struct LearningCache {
    /// The network generation this cache was last synced to; any other value
    /// forces a full reset (a new allocator invalidates every learned stride
    /// and direction).
    network_generation: u64,
    /// (destination scope) -> (cross-batch step learner, direction detector).
    /// The scope separates STUN-observer allocation from per-peer allocation so
    /// a peer whose real direction differs from the STUN direction is not
    /// dragged toward the STUN-learned stride.
    entries: HashMap<DestinationScope, (StepLearner, ReverseDetector)>,
}

/// The destination an allocation-sequence measurement was taken toward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DestinationScope {
    /// The measurement was a batch of STUN-observer requests on a fresh socket.
    /// This is the shared prior used when no peer-scope evidence exists.
    Stun,
    /// The measurement/observation was toward one specific peer (its actual
    /// mapping port observed on the wire).  Peer-scope evidence, when present,
    /// is authoritative for that peer over the STUN prior.
    Peer(String),
}

impl LearningCache {
    /// An empty cache that resets on first use (its generation starts out of
    /// sync with any real one).
    fn new() -> Self {
        Self {
            network_generation: u64::MAX,
            entries: HashMap::new(),
        }
    }

    /// Drop all learned state when the network generation moved on.
    fn reset_if_generation_changed(&mut self, generation: u64) {
        if generation != self.network_generation {
            self.entries.clear();
            self.network_generation = generation;
        }
    }

    fn entry(&mut self, scope: DestinationScope) -> &mut (StepLearner, ReverseDetector) {
        self.entries
            .entry(scope)
            .or_insert_with(|| (StepLearner::new(), ReverseDetector::new()))
    }

    /// The peer-scope learner for `peer_id`, or `None` when no peer-scope
    /// evidence was ever observed for it.
    fn peer_scope(&self, peer_id: &str) -> Option<&(StepLearner, ReverseDetector)> {
        self.entries
            .get(&DestinationScope::Peer(peer_id.to_string()))
    }
}

/// A point-in-time read of the adaptive learner for one public IP, used both as
/// the predictor input and as the fields logged/recorded for diagnostics.
#[derive(Debug, Clone, Copy)]
struct LearningSnapshot {
    /// Cross-batch EWMA stride estimate (signed — a reverse allocator learns a
    /// negative stride) when the learner has a valid reading, else `None`.  A
    /// `Some(0)` reading is a no-consensus placeholder the predictor treats as
    /// "no useful stride".
    step_estimate: Option<i16>,
    /// How many times the estimate changed (learning trajectory).
    revision_count: u32,
    /// Detected allocation direction of the peer's fresh mappings.
    direction: DirectionPattern,
}

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
        let socket = p2pnet_netbind::bind_udp(bind_addr, self.outbound_interface.as_deref())
            .await
            .map_err(|error| {
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
    ///
    /// The insert runs under the shared network-epoch gate: a generation
    /// advance can never land between the entry's generation stamp and the
    /// map insert, so an old-generation socket can never be registered after
    /// the generation moved on.
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
        let (reader_ready_tx, reader_ready_rx) = oneshot::channel();
        let reader_handle = {
            let transport = self.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                transport
                    .run_dynamic_inbound_socket(socket_index, socket, shutdown_rx, reader_ready_tx)
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
        let mut superseded = false;
        let capacity_ok = {
            let _epoch_gate = self.network_epoch_gate.lock().await;
            // The caller captured `network_generation` before binding this
            // socket.  Recheck it only after acquiring the epoch gate and
            // before even inspecting an eviction target: a delayed old task
            // must not evict a current-generation socket and then discover its
            // staleness during measurement/commit. Cancellation is the same
            // ownership loss and is rejected at this boundary too.
            if self.peers.current_network_generation_sync() != network_generation
                || cancellation.is_some_and(|cancellation| cancellation.is_cancelled())
            {
                superseded = true;
                false
            } else {
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
                        // commits. Direct peers are never evicted either.
                        // Re-verify against the synchronous mirror under this
                        // lock so a peer which became Direct after the pre-lock
                        // snapshot cannot lose its dedicated socket.
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
                                hard_hard_session_token: None,
                                created_at: Instant::now(),
                                authenticated_evidence: 0,
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
                            hard_hard_session_token: None,
                            created_at: Instant::now(),
                            authenticated_evidence: 0,
                            phase: DynamicSocketPhase::Provisional,
                            shutdown_tx,
                            reader: reader_handle.take().expect("reader handle owned"),
                            send_leases: Arc::new(DynamicSocketLeaseState::default()),
                        },
                    );
                    true
                }
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
            return Err(if superseded {
                DynamicSocketAttachError::Superseded
            } else {
                DynamicSocketAttachError::CapacityRejected
            });
        }
        for entry in evicted {
            self.detach_dynamic_entry(entry, "dynamic_socket_cap_reached")
                .await;
        }
        // Do not let the caller issue the first STUN request until the spawned
        // reader has actually polled `recv_from` once.  Spawning alone is not a
        // scheduling barrier: on a busy runtime the request and response can
        // otherwise complete while the reader has never registered socket
        // readiness, making the sole STUN waiter time out.  The sender fires
        // from the same poll that registers readiness (see
        // `recv_from_with_reader_ready`).
        let reader_ready = matches!(
            timeout(DYNAMIC_READER_READY_TIMEOUT, reader_ready_rx).await,
            Ok(Ok(true))
        );
        if !reader_ready {
            self.detach_dynamic_socket_by_index(socket_index, "dynamic_reader_start_failed")
                .await;
            drop(provisional_guard);
            return Err(DynamicSocketAttachError::ReaderStartupFailed);
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
    /// The entry is removed from the map by the caller before this runs.
    ///
    /// The shutdown ORDER is deliberate: the reader MUST keep receiving while
    /// the outstanding send leases drain and the socket's pending probes wait
    /// for their ACKs — the ACK of a probe that raced the detach only arrives
    /// at a live reader.  The stop signal is therefore sent AFTER the bounded
    /// drain (and after the socket's pending probes were dropped on drain
    /// timeout), so the reader exits only once nothing can arrive for it
    /// anymore; the abort is a belt-and-braces for a reader stuck in
    /// `recv_from`.
    async fn detach_dynamic_entry(&self, entry: DynamicPunchSocket, reason: &str) {
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
            self.drop_pending_probes_for_socket(entry.socket_index)
                .await;
        }
        // Only now stop the reader: every ACK that could still arrive was
        // given its chance during the drain.
        entry.shutdown_tx.send_replace(true);
        entry.reader.abort();
        self.dynamic_socket_diagnostics
            .lock()
            .await
            .remove(&entry.socket_index);
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
    pub(crate) async fn detach_dynamic_socket_by_index(&self, socket_index: usize, reason: &str) {
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

    /// Detach only when the live entry is still the exact socket identity that
    /// belonged to a Hard↔Hard session.  Dynamic indices are monotonic, but
    /// checking every stamped field makes cleanup fail closed even if a future
    /// allocator ever reuses an index.
    pub(crate) async fn detach_hard_hard_socket_if_identity(
        &self,
        identity: &crate::peer::HardHardFreshSocketIdentity,
        reason: &str,
    ) {
        let matches = {
            let state = self.socket_state.lock().await;
            state
                .dynamic
                .get(&identity.socket_index)
                .is_some_and(|entry| {
                    entry.peer_id == identity.peer_id
                        && entry.network_generation == identity.network_generation
                        && entry.punch_generation == identity.punch_generation
                        && entry.phase.is_usable()
                        && entry.socket.local_addr().ok() == Some(identity.socket_local_endpoint)
                })
        };
        if matches {
            self.detach_dynamic_socket_by_index(identity.socket_index, reason)
                .await;
        }
    }

    /// Bind a local-only token to every speculative socket in a bounded
    /// rendezvous. The token is checked only after the authenticated Probe v2
    /// identity has been verified; it is never trusted as wire authentication.
    pub(crate) async fn tag_hard_hard_socket(
        &self,
        peer_id: &str,
        socket_index: usize,
        token: &str,
    ) -> bool {
        let mut state = self.socket_state.lock().await;
        let Some(entry) = state.dynamic.get_mut(&socket_index) else {
            return false;
        };
        if entry.peer_id != peer_id || !entry.phase.is_usable() || token.is_empty() {
            return false;
        }
        entry.hard_hard_session_token = Some(token.to_string());
        true
    }

    /// Return the local-only Hard↔Hard token attached to one receiving socket.
    pub(crate) async fn hard_hard_socket_token(&self, socket_index: usize) -> Option<String> {
        self.socket_state
            .lock()
            .await
            .dynamic
            .get(&socket_index)
            .and_then(|entry| entry.hard_hard_session_token.clone())
    }

    pub(crate) async fn hard_hard_socket_indices_for_token(
        &self,
        peer_id: &str,
        token: &str,
    ) -> Vec<usize> {
        self.socket_state
            .lock()
            .await
            .dynamic
            .iter()
            .filter(|(_, entry)| {
                entry.peer_id == peer_id
                    && entry.hard_hard_session_token.as_deref() == Some(token)
                    && entry.phase.is_usable()
            })
            .map(|(index, _)| *index)
            .collect()
    }

    pub(crate) async fn detach_hard_hard_sockets_for_token(
        &self,
        peer_id: &str,
        token: &str,
        preserve_socket_index: Option<usize>,
        reason: &str,
    ) {
        let entries = {
            let mut state = self.socket_state.lock().await;
            let indices = state
                .dynamic
                .iter()
                .filter(|(index, entry)| {
                    Some(**index) != preserve_socket_index
                        && entry.peer_id == peer_id
                        && entry.hard_hard_session_token.as_deref() == Some(token)
                })
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let mut entries = Vec::with_capacity(indices.len());
            for index in indices {
                if let Some(entry) = state.dynamic.remove(&index) {
                    if state
                        .affinity
                        .get(peer_id)
                        .is_some_and(|pin| pin.socket_index == index)
                    {
                        state.affinity.remove(peer_id);
                    }
                    entries.push(entry);
                }
            }
            entries
        };
        for entry in entries {
            self.detach_dynamic_entry(entry, reason).await;
        }
    }

    /// Select and durably protect the first authenticated peer-reflexive
    /// socket. The caller already holds the network-epoch gate, so all socket
    /// checks and the affinity switch happen in this generation transaction.
    pub(crate) async fn promote_hard_hard_winner_in_epoch(
        &self,
        _epoch_guard: &tokio::sync::MutexGuard<'_, ()>,
        peer_id: &str,
        token: &str,
        socket_index: usize,
        network_generation: u64,
    ) -> bool {
        let (punch_generation, local_endpoint) = {
            let state = self.socket_state.lock().await;
            let Some(entry) = state.dynamic.get(&socket_index) else {
                return false;
            };
            if entry.peer_id != peer_id
                || entry.network_generation != network_generation
                || !entry.phase.is_usable()
                || entry.hard_hard_session_token.as_deref() != Some(token)
            {
                return false;
            }
            let Some(local_endpoint) = entry.socket.local_addr().ok() else {
                return false;
            };
            (entry.punch_generation, local_endpoint)
        };
        let Some(identity) = self
            .peers
            .hard_hard_select_winner(
                peer_id,
                token,
                socket_index,
                network_generation,
                punch_generation,
                local_endpoint,
            )
            .await
        else {
            return false;
        };
        self.peers
            .record_direct_event_for_generation_with_socket(
                peer_id,
                network_generation,
                "hard_hard_peer_reflexive_learned",
                None,
                Some(identity.socket_index),
                None,
                None,
                format!(
                    "authenticated peer-reflexive evidence socket_index={} punch_generation={} local_endpoint={}",
                    identity.socket_index, identity.punch_generation, identity.socket_local_endpoint
                ),
            )
            .await;
        let losers = {
            let mut state = self.socket_state.lock().await;
            let Some(entry) = state.dynamic.get(&socket_index) else {
                return false;
            };
            if entry.peer_id != peer_id
                || entry.network_generation != network_generation
                || entry.punch_generation != punch_generation
                || entry.hard_hard_session_token.as_deref() != Some(token)
            {
                return false;
            }
            let epoch = state.next_epoch();
            state.affinity.insert(
                peer_id.to_string(),
                PeerSocketPin {
                    socket_index,
                    epoch,
                },
            );
            state
                .dynamic
                .get_mut(&socket_index)
                .expect("winner entry verified above")
                .phase = DynamicSocketPhase::Finalized;
            let loser_indices = state
                .dynamic
                .iter()
                .filter(|(index, entry)| {
                    **index != socket_index
                        && entry.peer_id == peer_id
                        && entry.network_generation == network_generation
                        && entry.hard_hard_session_token.as_deref() == Some(token)
                })
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            loser_indices
                .into_iter()
                .filter_map(|index| state.dynamic.remove(&index))
                .collect::<Vec<_>>()
        };
        for entry in losers {
            self.detach_dynamic_entry(entry, "hard_hard_loser_socket").await;
        }
        self.peers
            .record_direct_event_for_generation_with_socket(
                peer_id,
                network_generation,
                "hard_hard_winner_selected",
                None,
                Some(identity.socket_index),
                None,
                None,
                format!(
                    "authenticated peer-reflexive socket selected; socket_index={} punch_generation={} local_endpoint={}",
                    identity.socket_index, identity.punch_generation, identity.socket_local_endpoint
                ),
            )
            .await;
        true
    }

    pub(crate) async fn hard_hard_socket_identity_is_current(
        &self,
        identity: &crate::peer::HardHardFreshSocketIdentity,
    ) -> bool {
        let state = self.socket_state.lock().await;
        state
            .dynamic
            .get(&identity.socket_index)
            .is_some_and(|entry| {
                entry.peer_id == identity.peer_id
                    && entry.network_generation == identity.network_generation
                    && entry.punch_generation == identity.punch_generation
                    && entry.phase.is_usable()
                    && entry.socket.local_addr().ok() == Some(identity.socket_local_endpoint)
                    && state
                        .affinity
                        .get(&identity.peer_id)
                        .is_some_and(|pin| pin.socket_index == identity.socket_index)
                    && self.peers.current_network_generation_sync() == identity.network_generation
            })
    }

    /// Exact-socket ownership plus authenticated evidence observed on that
    /// same dynamic entry.  A commit-time affinity pin alone is not enough for
    /// Hard↔Hard success: it is installed before the first peer-directed
    /// authenticated ACK, so the final proof must also see the entry's own
    /// evidence counter advance.
    pub(crate) async fn hard_hard_socket_identity_has_authenticated_evidence(
        &self,
        identity: &crate::peer::HardHardFreshSocketIdentity,
    ) -> bool {
        let state = self.socket_state.lock().await;
        state
            .dynamic
            .get(&identity.socket_index)
            .is_some_and(|entry| {
                entry.peer_id == identity.peer_id
                    && entry.network_generation == identity.network_generation
                    && entry.punch_generation == identity.punch_generation
                    && entry.phase.is_usable()
                    && entry.socket.local_addr().ok() == Some(identity.socket_local_endpoint)
                    && entry.authenticated_evidence > 0
                    && state
                        .affinity
                        .get(&identity.peer_id)
                        .is_some_and(|pin| pin.socket_index == identity.socket_index)
                    && self.peers.current_network_generation_sync() == identity.network_generation
            })
    }

    /// Return the authenticated-evidence counter for one dynamic socket.
    /// This is test-only observability for the exact-socket acceptance
    /// harness; production callers use the identity-fenced proof above.
    #[cfg(test)]
    pub(crate) async fn authenticated_evidence_for_socket(&self, socket_index: usize) -> u64 {
        self.socket_state
            .lock()
            .await
            .dynamic
            .get(&socket_index)
            .map(|entry| entry.authenticated_evidence)
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) async fn dynamic_socket_phase_for_test(
        &self,
        socket_index: usize,
    ) -> Option<DynamicSocketPhase> {
        self.socket_state
            .lock()
            .await
            .dynamic
            .get(&socket_index)
            .map(|entry| entry.phase)
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
    ///
    /// Production cleanups go through `cleanup_peer_lifecycle` (which runs
    /// the same removal inside the peer's adoption-lock transaction); this
    /// standalone form is used by tests and by teardown paths that never
    /// race ACK adoption.
    #[cfg(test)]
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
            let entries = state
                .dynamic
                .drain()
                .map(|(_, entry)| entry)
                .collect::<Vec<_>>();
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
    ///
    /// `keep_measuring` is re-evaluated before EVERY sample send and before
    /// every waiter wait: a Direct promotion, a session cancellation or a
    /// network-generation advance must stop the measurement immediately
    /// instead of completing the remaining STUN samples (which would only
    /// allocate more NAT mappings for a path that no longer needs them).
    async fn measure_fresh_mapping_batch(
        &self,
        socket: &Arc<UdpSocket>,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        keep_measuring: impl Fn() -> bool,
    ) -> Vec<MappingObservation> {
        let started_ms = monotonic_millis();
        let mut observations = Vec::with_capacity(observers.len());
        for (sequence, observer) in observers.iter().enumerate() {
            if !keep_measuring() {
                debug!(
                    "Fresh-mapping STUN measurement aborted before sample {sequence}: Direct was confirmed, the session was cancelled or the network generation changed"
                );
                break;
            }
            let budget_elapsed_ms = monotonic_millis().saturating_sub(started_ms) as u128;
            let remaining_budget_ms = FRESH_MAPPING_MEASURE_BUDGET
                .as_millis()
                .saturating_sub(budget_elapsed_ms);
            let remaining_samples = observers.len().saturating_sub(sequence).max(1) as u128;
            let per_sample_timeout =
                stun_timeout
                    .min(FRESH_MAPPING_STUN_TIMEOUT)
                    .min(Duration::from_millis(
                        remaining_budget_ms
                            .saturating_div(remaining_samples)
                            .min(u64::MAX as u128) as u64,
                    ));

            let mut request = StunMessage::binding_request();
            request.add_attribute(StunAttribute::Software(
                MEASUREMENT_SOFTWARE_TAG.to_string(),
            ));
            let transaction_id = request.transaction_id;
            let encoded = request.encode();
            let (response_tx, response_rx) = oneshot::channel();
            self.stun_waiters
                .lock()
                .await
                .insert(transaction_id, response_tx);
            let sent_at_ms = monotonic_millis();
            if let Err(error) = socket.send_to(&encoded, observer).await {
                self.stun_waiters.lock().await.remove(&transaction_id);
                debug!("Fresh-mapping STUN send {sequence} to {observer} failed: {error}");
                continue;
            }
            if !keep_measuring() {
                self.stun_waiters.lock().await.remove(&transaction_id);
                debug!(
                    "Fresh-mapping STUN measurement aborted while waiting for sample {sequence}: Direct was confirmed, the session was cancelled or the network generation changed"
                );
                break;
            }
            let result = tokio::time::timeout(per_sample_timeout, response_rx).await;
            if result.is_err() {
                // The waiter timed out without a response: remove its entry so
                // a cancelled or stalled measurement never leaks waiters that
                // can only be matched by the same (never-reused) transaction.
                self.stun_waiters.lock().await.remove(&transaction_id);
            }
            let responded_at_ms = monotonic_millis();
            let parsed = match result {
                Ok(Ok(StunResponse { data, source })) if source == *observer => {
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
                    local_endpoint: socket
                        .local_addr()
                        .ok()
                        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
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

    /// Fold one fresh-mapping batch into the shared adaptive learner for its
    /// egress public IP and return a point-in-time snapshot to feed the
    /// predictor.
    ///
    /// The observed ports are streamed into the direction detector and the
    /// model's positive deltas into the step learner (negative deltas carry no
    /// forward-stride information; the detector already captures the direction
    /// from the ports themselves).  A network-generation change clears every
    /// learned stride and direction first, so a stale reading is never applied
    /// to a new allocator.
    /// Fold a STUN measurement batch into the adaptive learner and return a
    /// point-in-time snapshot to feed the predictor.
    ///
    /// The observed ports are streamed into the direction detector and the
    /// model's deltas into the step learner.  This is the STUN-observer scope:
    /// it is the shared prior.  A peer whose real allocation direction was
    /// observed on the wire (see [`Self::observe_peer_scope`]) gets its own
    /// peer scope and the predictor prefers that evidence (audit P1-B).
    /// A network-generation change clears every learned state first, so a
    /// stale reading is never applied to a new allocator.
    async fn observe_learning(
        &self,
        ports: &[u16],
        model: &PortModel,
        network_generation: u64,
    ) -> LearningSnapshot {
        let mut cache = self.learning_cache.lock().await;
        cache.reset_if_generation_changed(network_generation);
        let (step_learner, detector) = cache.entry(DestinationScope::Stun);
        for port in ports {
            detector.observe_port(*port);
        }
        for delta in &model.deltas {
            step_learner.observe_diff(*delta);
        }
        let step_estimate = step_learner.estimate();
        let direction = detector.pattern();
        LearningSnapshot {
            step_estimate,
            revision_count: step_learner.revision_count(),
            direction,
        }
    }

    /// Fold one real peer-scope allocation observation (the peer's actual
    /// public mapping port, learned from the wire) into a per-peer direction
    /// detector.
    ///
    /// The peer scope is authoritative for that peer over the STUN prior: a
    /// complex CGNAT can allocate toward STUN observers differently than toward
    /// the real peer, so once a peer's true direction is observed it must not
    /// be dragged back toward the STUN-learned stride (audit P1-B).
    async fn observe_peer_scope(&self, peer_id: &str, observed_port: u16, network_generation: u64) {
        let mut cache = self.learning_cache.lock().await;
        cache.reset_if_generation_changed(network_generation);
        let (_, detector) = cache.entry(DestinationScope::Peer(peer_id.to_string()));
        // The peer's observed ports, in observation order, feed the direction
        // detector.  The stride learner is deliberately not fed here: a single
        // wire observation cannot pin a stride, and the predictor already
        // guards the direction conflict at P0-1 (current batch wins).  The
        // peer-scope *direction* is the new, authoritative signal.
        detector.observe_port(observed_port);
    }

    /// Read the peer-scope learning snapshot for `peer_id`, or fall back to the
    /// STUN prior when no peer-scope evidence exists.
    async fn peer_learning_snapshot(
        &self,
        peer_id: &str,
        network_generation: u64,
    ) -> Option<LearningSnapshot> {
        let cache = self.learning_cache.lock().await;
        if cache.network_generation != network_generation {
            return None;
        }
        let (_, detector) = cache.peer_scope(peer_id)?;
        Some(LearningSnapshot {
            step_estimate: None,
            revision_count: 0,
            direction: detector.pattern(),
        })
    }

    /// Test-only presence check for the STUN-scope adaptive learner, syncing
    /// the cache to `network_generation` first (the same lazy reset the
    /// production path performs).  Returns `false` when the STUN scope has no
    /// learned state for the requested generation — i.e. the cache was reset or
    /// never fed.
    #[cfg(test)]
    pub(crate) async fn has_learning_for(&self, ip: IpAddr, network_generation: u64) -> bool {
        let _ = ip;
        let mut cache = self.learning_cache.lock().await;
        cache.reset_if_generation_changed(network_generation);
        cache.entries.contains_key(&DestinationScope::Stun)
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
        self.run_fresh_mapping_generation_internal(
            peer_id,
            observers,
            stun_timeout,
            stable_targets,
            probe_interval,
            attempts,
            cancellation,
            false,
        )
        .await
    }

    /// Measure and commit a fresh mapping without sending a peer-directed
    /// probe before the synchronized rendezvous.  The returned dynamic socket
    /// is the exact socket that produced the STUN sequence; the Hard↔Hard
    /// coordinator later sweeps that same index and fails closed if it is gone.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_hard_hard_fresh_mapping_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> FreshMappingOutcome {
        self.run_fresh_mapping_generation_internal(
            peer_id,
            observers,
            stun_timeout,
            &[],
            Duration::ZERO,
            0,
            cancellation,
            true,
        )
        .await
    }

    /// Run the bounded high-entropy Hard↔Hard lane. Each level owns a small
    /// set of fresh sockets, measures several observers on the first socket,
    /// and derives a token-scoped destination guess set. The sockets remain
    /// attached and authenticated until the first peer-reflexive packet
    /// promotes one of them; all losers are then detached immediately.
    pub(crate) async fn run_hard_hard_birthday_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        level: usize,
        session_token: &str,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> std::result::Result<HardHardBirthdayResult, FreshMappingRejection> {
        if !self.peers.local_nat_requires_fresh_mapping_punch().await {
            return Err(FreshMappingRejection::StableLocalNat);
        }
        if cancellation.is_some_and(|cancellation| cancellation.is_cancelled())
            || self.peers.is_direct(peer_id).await
        {
            return Err(FreshMappingRejection::Superseded);
        }
        if self.local_node_id.is_none() || self.peers.probe_key_for_peer(peer_id).await.is_none() {
            return Err(FreshMappingRejection::MissingProbeKey);
        }
        let observers = observers
            .iter()
            .copied()
            .filter(|observer| observer.is_ipv4())
            .collect::<Vec<_>>();
        if observers.len() < 3 {
            return Err(FreshMappingRejection::InsufficientSamples);
        }
        let requested_level = match level {
            0..=64 => 64,
            65..=128 => 128,
            _ => 256,
        };
        let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
        let mut level = requested_level;
        let network_generation = self.peers.current_network_generation_sync();
        let mut attached: Vec<(
            usize,
            std::sync::Arc<UdpSocket>,
            ProvisionalSocketGuard,
            u64,
            SocketAddr,
        )> = Vec::with_capacity(requested_socket_count);
        let mut capacity_rejected = false;
        for _ in 0..requested_socket_count {
            let punch_generation = self.peers.next_punch_generation(peer_id).await;
            let (socket_index, socket) = match self.bind_fresh_punch_socket().await {
                Ok(bound) => bound,
                Err(_) => {
                    for attached_socket in &attached {
                        self.detach_dynamic_socket_by_index(
                            attached_socket.0,
                            "hard_hard_birthday_bind_failed",
                        )
                        .await;
                    }
                    return Err(FreshMappingRejection::BindFailed);
                }
            };
            let local_endpoint = socket.local_addr().ok();
            let Some(local_endpoint) = local_endpoint else {
                self.detach_dynamic_socket_by_index(socket_index, "hard_hard_birthday_no_local_endpoint")
                    .await;
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_no_local_endpoint",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::BindFailed);
            };
            let guard = match self
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
                Err(DynamicSocketAttachError::CapacityRejected) => {
                    capacity_rejected = true;
                    break;
                }
                Err(error) => {
                    for attached_socket in &attached {
                        self.detach_dynamic_socket_by_index(
                            attached_socket.0,
                            "hard_hard_birthday_attach_failed",
                        )
                        .await;
                    }
                    return Err(match error {
                        DynamicSocketAttachError::Superseded => FreshMappingRejection::Superseded,
                        DynamicSocketAttachError::CapacityRejected => {
                            FreshMappingRejection::CapacityRejected
                        }
                        DynamicSocketAttachError::NoInboundChannel
                        | DynamicSocketAttachError::ReaderStartupFailed => {
                            FreshMappingRejection::BindFailed
                        }
                    });
                }
            };
            attached.push((socket_index, socket, guard, punch_generation, local_endpoint));
        }

        if capacity_rejected {
            let Some((actual_level, actual_socket_count)) =
                hard_hard_birthday_capacity_plan(requested_level, attached.len())
            else {
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_capacity_rejected",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::CapacityRejected);
            };
            level = actual_level;
            while attached.len() > actual_socket_count {
                if let Some((socket_index, _, _, _, _)) = attached.pop() {
                    self.detach_dynamic_socket_by_index(
                        socket_index,
                        "hard_hard_birthday_capacity_downgrade",
                    )
                    .await;
                }
            }
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_birthday_degraded",
                    None,
                    Some(level),
                    None,
                    format!(
                        "requested_level={} actual_level={} requested_socket_count={} actual_socket_count={} reason=socket_cap",
                        requested_level,
                        level,
                        requested_socket_count,
                        attached.len(),
                    ),
                )
                .await;
        }

        let mut measurements = JoinSet::new();
        for (position, (_, socket, _, _, _)) in attached.iter().enumerate() {
            let transport = self.clone();
            let socket = socket.clone();
            let peer_id = peer_id.to_string();
            let cancellation = cancellation.cloned();
            let selected_observers = if position == 0 {
                observers.iter().copied().take(4).collect::<Vec<_>>()
            } else {
                vec![observers[position % observers.len()]]
            };
            measurements.spawn(async move {
                let observations = transport
                    .measure_fresh_mapping_batch(&socket, &selected_observers, stun_timeout, || {
                        !cancellation
                            .as_ref()
                            .is_some_and(|cancellation| cancellation.is_cancelled())
                            && !transport.peers.is_direct_sync(&peer_id)
                            && transport.peers.current_network_generation_sync()
                                == network_generation
                    })
                    .await;
                (position, observations)
            });
        }
        let mut observations_by_socket = vec![Vec::new(); attached.len()];
        while let Some(joined) = measurements.join_next().await {
            if let Ok((position, observations)) = joined {
                observations_by_socket[position] = observations;
            }
        }
        if cancellation.is_some_and(|cancellation| cancellation.is_cancelled())
            || self.peers.current_network_generation_sync() != network_generation
            || self.peers.is_direct(peer_id).await
        {
            for attached_socket in &attached {
                self.detach_dynamic_socket_by_index(attached_socket.0, "hard_hard_birthday_superseded")
                    .await;
            }
            return Err(FreshMappingRejection::Superseded);
        }
        let all_observations = observations_by_socket
            .iter()
            .flat_map(|observations| observations.iter().cloned())
            .collect::<Vec<_>>();
        let mut public_ip = None;
        let mut observed_ports = Vec::new();
        for observation in &all_observations {
            if public_ip.is_some_and(|ip| ip != observation.observed.ip()) {
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_public_ip_changed",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::PublicIpChanged);
            }
            public_ip = Some(observation.observed.ip());
            observed_ports.push(observation.observed.port());
        }
        let Some(public_ip) = public_ip else {
            for attached_socket in &attached {
                self.detach_dynamic_socket_by_index(
                    attached_socket.0,
                    "hard_hard_birthday_no_observation",
                )
                .await;
            }
            return Err(FreshMappingRejection::InsufficientSamples);
        };
        observed_ports.sort_unstable();
        observed_ports.dedup();
        let local_model = infer_allocation_model(&observations_by_socket[0]);
        let model_label = local_model.kind.label().to_string();
        let candidate_endpoints = hard_hard_birthday_candidates(
            public_ip,
            &observed_ports,
                    level,
                    session_token,
        );
        if candidate_endpoints.len() != level {
            for attached_socket in &attached {
                self.detach_dynamic_socket_by_index(
                    attached_socket.0,
                    "hard_hard_birthday_candidate_generation_failed",
                )
                .await;
            }
            return Err(FreshMappingRejection::UnpredictableSequence);
        }
        // A birthday window has one affinity owner but several authenticated
        // speculative receivers.  Pin only the first socket; committing each
        // guard with commit_and_pin would overwrite the previous pin and make
        // every earlier guard fail its finalize revalidation.  The remaining
        // guards use the no-affinity speculative commit below and are still
        // protected by the same generation/cancellation fences.
        for (position, (socket_index, _, guard, punch_generation, _)) in
            attached.iter().enumerate()
        {
            let committed = if position == 0 {
                guard
                    .commit_and_pin(
                        self,
                        peer_id,
                        *socket_index,
                        network_generation,
                        *punch_generation,
                    )
                    .await
                    .committed
            } else {
                guard
                    .commit_speculative(
                        self,
                        peer_id,
                        *socket_index,
                        network_generation,
                        *punch_generation,
                    )
                    .await
                    .committed
            };
            if !committed || !self.tag_hard_hard_socket(peer_id, *socket_index, session_token).await {
                for attached_socket in &attached {
                    self.detach_dynamic_socket_by_index(
                        attached_socket.0,
                        "hard_hard_birthday_commit_failed",
                    )
                    .await;
                }
                return Err(FreshMappingRejection::Superseded);
            }
        }
        self.peers
            .record_direct_event(
                peer_id,
                "hard_hard_fresh_mapping_observed",
                candidate_endpoints.first().copied(),
                Some(candidate_endpoints.len()),
                None,
                format!(
                    "model={} strategy=bounded_birthday confidence={} socket_count={} observation_count={} public_ip={} level={} requested_level={} requested_socket_count={} public_port_samples={}",
                    model_label,
                    local_model.confidence,
                    attached.len(),
                    all_observations.len(),
                    public_ip,
                    level,
                    requested_level,
                    requested_socket_count,
                    observed_ports.len(),
                ),
            )
            .await;
        let sockets = attached
            .into_iter()
            .map(|(socket_index, _, guard, punch_generation, socket_local_endpoint)| {
                HardHardBirthdaySocket {
                    punch_generation,
                    socket_index,
                    socket_local_endpoint,
                    guard,
                }
        })
        .collect();
        Ok(HardHardBirthdayResult {
            requested_level,
            requested_socket_count,
            level,
            public_ip,
            public_port_samples: observed_ports,
            observation_count: all_observations.len(),
            candidate_endpoints,
            sockets,
            model_label,
            model_confidence: local_model.confidence,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_fresh_mapping_generation_internal(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        stable_targets: &[SocketAddr],
        probe_interval: Duration,
        attempts: u32,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
        measure_only: bool,
    ) -> FreshMappingOutcome {
        if !self.peers.local_nat_requires_fresh_mapping_punch().await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat);
        }
        if cancellation.is_some_and(|c| c.is_cancelled()) {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        let allow_loopback = self.peers.fresh_mapping_harness_loopback_enabled().await;
        let stable_targets = stable_targets
            .iter()
            .copied()
            .filter(|endpoint| fresh_mapping_target_eligible(*endpoint, allow_loopback))
            .collect::<Vec<_>>();
        if !measure_only && stable_targets.is_empty() {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::NoStablePeerEndpoint);
        }
        if self.local_node_id.is_none() || self.peers.probe_key_for_peer(peer_id).await.is_none() {
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
                    DynamicSocketAttachError::Superseded => FreshMappingRejection::Superseded,
                    DynamicSocketAttachError::CapacityRejected => {
                        FreshMappingRejection::CapacityRejected
                    }
                    DynamicSocketAttachError::NoInboundChannel
                    | DynamicSocketAttachError::ReaderStartupFailed => {
                        FreshMappingRejection::BindFailed
                    }
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
            self.detach_dynamic_socket_by_index(socket_index, "insufficient_observers")
                .await;
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
        let measurement_peer_id = peer_id.to_string();
        let observations = self
            .measure_fresh_mapping_batch(&socket, &observers, stun_timeout, || {
                !cancellation.is_some_and(|c| c.is_cancelled())
                    && !self.peers.is_direct_sync(&measurement_peer_id)
                    && self.peers.current_network_generation_sync() == network_generation
            })
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
            debug!(
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
            // Direct confirmation, session cancellation and generation
            // advances take precedence over the sample-count rejection: an
            // aborted measurement (the peer went Direct mid-batch) must
            // report the real reason instead of masking it as an insufficient
            // sample count.
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
            self.detach_dynamic_socket_by_index(socket_index, "insufficient_samples")
                .await;
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
            self.detach_dynamic_socket_by_index(socket_index, "public_ip_changed")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
        }

        let now_ms = monotonic_millis();
        let model = match build_model_for_batch(&batch, FRESH_MAPPING_MODEL_MAX_AGE, now_ms) {
            Ok(model) => model,
            Err(ModelRejection::BatchStale) => {
                self.detach_dynamic_socket_by_index(socket_index, "batch_stale")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
            }
            Err(ModelRejection::InconsistentBatch) => {
                self.detach_dynamic_socket_by_index(socket_index, "inconsistent_batch")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InconsistentBatch);
            }
            Err(ModelRejection::InsufficientSamples) => {
                self.detach_dynamic_socket_by_index(socket_index, "insufficient_samples")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
            }
            Err(ModelRejection::PublicIpChanged) => {
                self.detach_dynamic_socket_by_index(socket_index, "public_ip_changed")
                    .await;
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
                self.detach_dynamic_socket_by_index(socket_index, "unpredictable_sequence")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::UnpredictableSequence);
            }
        };

        let step = match &model.kind {
            PortModelKind::FixedStep { step }
            | PortModelKind::Linear { step }
            | PortModelKind::NoisyLinear { step } => Some(*step),
            PortModelKind::MonotonicWindow { direction } => Some(i16::from(*direction)),
            _ => None,
        };
        if step
            .is_some_and(|step| u32::from(step.unsigned_abs()) > FRESH_MAPPING_MAX_ABS_STEP as u32)
        {
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
            self.detach_dynamic_socket_by_index(socket_index, "unpredictable_sequence")
                .await;
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
        let public_ip = batch.public_ip();
        // Fold this batch into the adaptive learner (scoped by destination:
        // STUN prior + per-peer direction) and read back its stride estimate +
        // allocation direction.  The detector is fed the raw observed ports; the
        // step learner is fed the model's deltas.  A network-generation change
        // resets both first, so a reading from a superseded allocator is never
        // applied here.
        let _learner_ip =
            public_ip.expect("a valid batch was checked for a single public IP above");
        let learning = self
            .observe_learning(&ports, &model, network_generation)
            .await;
        let learner_used = learning.step_estimate.is_some_and(|estimate| {
            u32::from(estimate.unsigned_abs()) <= FRESH_MAPPING_MAX_ABS_STEP as u32
        });
        let effective_step = if learner_used {
            learning.step_estimate
        } else {
            None
        };
        // Prefer the peer-scope allocation direction over the STUN prior: once
        // this peer's real mapping direction was observed on the wire, a
        // complex CGNAT that allocates toward STUN differently than toward the
        // peer must not drag this peer's window back toward the STUN direction
        // (audit P1-B).  With no peer-scope evidence the STUN direction is the
        // prior.
        let peer_direction = self
            .peer_learning_snapshot(peer_id, network_generation)
            .await
            .map(|snapshot| snapshot.direction);
        let direction = peer_direction.unwrap_or(learning.direction);
        let predicted = predict_ports_with_learning(
            &model,
            last,
            measurement_span_ms,
            probe_gap_ms,
            effective_step,
            direction == DirectionPattern::Reverse,
        );
        let predicted_ports = predicted
            .iter()
            .map(|candidate| candidate.port)
            .collect::<Vec<_>>();

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
            step_estimate = ?learning.step_estimate,
            learner_revision_count = learning.revision_count,
            direction_pattern = learning.direction.as_str(),
            learner_used = learner_used,
            predicted = ?predicted_ports,
            "fresh_mapping_model peer_id={} punch_generation={} model={:?} confidence={} sequence={} deltas={} step_estimate={:?} learner_revision_count={} direction_pattern={} learner_used={} predicted={:?}",
            peer_id,
            punch_generation,
            model.kind,
            model.confidence,
            sequence_label,
            deltas_label,
            learning.step_estimate,
            learning.revision_count,
            learning.direction.as_str(),
            learner_used,
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
        // In measure-only mode there is deliberately no peer-directed send at
        // this point.  Keep the result timestamps meaningful by anchoring the
        // handoff to the final STUN request rather than inventing a punch.
        let first_punch_sent_at_ms = if measure_only {
            first_sent_at_ms
        } else {
            monotonic_millis()
        };
        let mut sent = 0u32;
        if !measure_only {
            for round in 0..attempts {
                if cancellation.is_some_and(|c| c.is_cancelled()) {
                    debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; session superseded"
                );
                    break;
                }
                if self.peers.is_direct(peer_id).await {
                    // Direct was confirmed while this generation was measuring or
                    // punching: stop emitting peer-facing probes from the
                    // generation's socket immediately.
                    debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; Direct was confirmed"
                );
                    break;
                }
                if self.peers.current_network_generation_sync() != network_generation {
                    debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; the network generation changed"
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
        }
        let last_punch_sent_at_ms = monotonic_millis();

        // No peer-facing probe ever entered the kernel queue: the generation
        // must not claim success.  The provisional socket is detached while
        // the previous generation's socket (the peer's working path) stays.
        if !measure_only && sent == 0 {
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
            state
                .dynamic
                .get(&socket_index)
                .is_some_and(|entry| entry.phase.is_usable() && entry.peer_id == peer_id)
                && state
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
            .record_direct_event(
                peer_id,
                "fresh_mapping_model",
                stable_targets.first().copied(),
                Some(predicted_ports.len()),
                None,
                format!(
                    "punch_generation={punch_generation} model={:?} confidence={} sequence={} deltas={} step_estimate={:?} learner_revision_count={} direction_pattern={} learner_used={} predicted={:?}",
                    model.kind,
                    model.confidence,
                    sequence_label,
                    deltas_label,
                    learning.step_estimate,
                    learning.revision_count,
                    learning.direction.as_str(),
                    learner_used,
                    predicted_ports
                ),
            )
            .await;
        self.peers
            .record_fresh_mapping_with_socket(
                peer_id,
                p2pnet_nat::mapping::PortModel::clone(&model),
                predicted_ports.clone(),
                local_endpoint,
                socket_index,
                public_ip,
                punch_generation,
                network_generation,
            )
            .await;

        self.peers
            .record_direct_event(
                peer_id,
                if measure_only {
                    "fresh_mapping_measurement_ready"
                } else {
                    "fresh_mapping_punch_sent"
                },
                stable_targets.first().copied(),
                Some(stable_targets.len()),
                Some(sent),
                format!(
                    "punch_generation={punch_generation} socket_local={local_endpoint} socket_index={socket_index} first_sent_ms={first_punch_sent_at_ms} last_sent_ms={last_punch_sent_at_ms} targets={} sent={sent} measure_only={measure_only}",
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
    #[allow(dead_code)]
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
        let Some((index, socket, _lease)) = self.resolve_dynamic_socket_for_send(peer_id).await
        else {
            return Ok(PunchSendReport::default());
        };
        self.punch_candidates_from_dynamic_socket_resolved(
            peer_id,
            index,
            socket,
            candidates,
            probe_interval,
            attempts,
            None,
            None,
        )
        .await
    }

    /// Sweep an explicitly named committed dynamic socket.  This is the
    /// fail-closed variant used by Hard↔Hard sessions: if the measured socket
    /// is no longer available, the caller receives an empty report instead of
    /// silently sending the prediction from a different socket.
    pub(crate) async fn punch_candidates_from_dynamic_socket_index(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        self.punch_candidates_from_dynamic_socket_index_with_profile_fence(
            peer_id,
            socket_index,
            candidates,
            probe_interval,
            attempts,
            None,
        )
        .await
    }

    /// Fan a bounded Hard↔Hard birthday window across the committed candidate
    /// sockets in up to two deterministic waves. Each wave sends every target
    /// from exactly one socket; the second wave rotates the socket assignment
    /// so a target is retried from a different source port without creating a
    /// socket-count Cartesian product.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn punch_hard_hard_birthday_candidates(
        &self,
        peer_id: &str,
        socket_indices: Vec<usize>,
        targets: Vec<SocketAddr>,
        requested_level: usize,
        peer_session_generation: crate::peer::PeerSessionGeneration,
        profile_fence: (u64, u64),
        session_token: &str,
    ) -> Result<PunchSendReport> {
        let mut effective_targets = Vec::with_capacity(targets.len().min(crate::MAX_SIGNAL_CANDIDATES));
        for target in targets {
            if target.port() == 0 || effective_targets.contains(&target) {
                continue;
            }
            effective_targets.push(target);
            if effective_targets.len() == crate::MAX_SIGNAL_CANDIDATES {
                break;
            }
        }
        let mut effective_socket_indices = Vec::with_capacity(socket_indices.len());
        for socket_index in socket_indices {
            if !effective_socket_indices.contains(&socket_index) {
                effective_socket_indices.push(socket_index);
            }
        }

        let waves_planned = hard_hard_birthday_wave_count(effective_socket_indices.len());
        let mut birthday = BirthdaySweepReport {
            requested_level,
            effective_target_count: effective_targets.len(),
            waves_planned,
            packets_planned: hard_hard_birthday_packets_planned(
                effective_socket_indices.len(),
                effective_targets.len(),
            ),
            ..BirthdaySweepReport::default()
        };
        let mut aggregate = PunchSendReport::default();
        if effective_targets.is_empty() {
            birthday.stop_reason = Some("empty_targets".to_string());
            aggregate.birthday = Some(birthday);
            return Ok(aggregate);
        }
        if effective_socket_indices.is_empty() {
            birthday.stop_reason = Some("socket_unavailable".to_string());
            aggregate.birthday = Some(birthday);
            return Ok(aggregate);
        }

        // Keep the first-wave launch timing identical to the existing
        // one-shot path. Each worker still resolves its exact socket
        // fail-closed immediately before it can send; a fully detached set is
        // reported as `socket_unavailable` after that wave.
        birthday.socket_count = effective_socket_indices.len();
        if birthday.socket_count == 1 {
            birthday.degraded_reason = Some("single_socket".to_string());
        }
        birthday.waves_planned = hard_hard_birthday_wave_count(effective_socket_indices.len());
        birthday.packets_planned = hard_hard_birthday_packets_planned(
            birthday.socket_count,
            birthday.effective_target_count,
        );

        let network_generation_at_start = self.peers.current_network_generation_sync();
        let remote_candidate_epoch_at_start = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or_default();
        let direct_commit_seq_at_start = self.peers.direct_commit_seq_sync(peer_id);
        for wave in 0..birthday.waves_planned {
            if wave > 0 {
                sleep(HARD_HARD_BIRTHDAY_WAVE_INTERVAL).await;
            }
            if wave > 0 {
                if let Some(reason) = self
                    .hard_hard_birthday_stop_reason(
                        peer_id,
                        session_token,
                        profile_fence,
                        peer_session_generation,
                        network_generation_at_start,
                        remote_candidate_epoch_at_start,
                        direct_commit_seq_at_start,
                    )
                    .await
                {
                    birthday.stop_reason = Some(reason.to_string());
                    break;
                }
            }

            birthday.waves_started = birthday.waves_started.saturating_add(1);
            let mut assignments = hard_hard_birthday_wave_assignments(
                effective_socket_indices.len(),
                effective_targets.clone(),
                wave,
            );
            let mut workers = JoinSet::new();
            for (socket_position, socket_index) in
                effective_socket_indices.iter().copied().enumerate()
            {
                let assigned = std::mem::take(&mut assignments[socket_position]);
                if assigned.is_empty() {
                    continue;
                }
                let transport = self.clone();
                let peer_id = peer_id.to_string();
                let session_token = session_token.to_string();
                workers.spawn(async move {
                    transport
                        .punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
                            &peer_id,
                            socket_index,
                            assigned,
                            HARD_HARD_BIRTHDAY_WAVE_INTERVAL,
                            1,
                            Some(profile_fence),
                            Some(&session_token),
                        )
                        .await
                });
            }

            let mut wave_report = PunchSendReport::default();
            let mut worker_failed = false;
            while let Some(joined) = workers.join_next().await {
                let Ok(result) = joined else {
                    worker_failed = true;
                    continue;
                };
                let report = result?;
                merge_punch_send_reports(&mut wave_report, report);
            }
            if worker_failed {
                birthday.stop_reason = Some("send_error".to_string());
                break;
            }
            birthday.waves_completed = birthday.waves_completed.saturating_add(1);
            merge_punch_send_reports(&mut aggregate, wave_report.clone());
            if let Some(reason) = self
                .hard_hard_birthday_stop_reason(
                    peer_id,
                    session_token,
                    profile_fence,
                    peer_session_generation,
                    network_generation_at_start,
                    remote_candidate_epoch_at_start,
                    direct_commit_seq_at_start,
                )
                .await
            {
                birthday.stop_reason = Some(reason.to_string());
                break;
            }
            if wave_report.epoch_budget_exhausted {
                birthday.stop_reason = Some("epoch_budget_exhausted".to_string());
                break;
            }
            if wave_report.candidate_iteration_capped {
                birthday.stop_reason = Some("candidate_iteration_capped".to_string());
                break;
            }
            if wave_report.packets_sent == 0 && wave_report.budget_skipped > 0 {
                birthday.stop_reason = Some("budget_exhausted".to_string());
                break;
            }
            if wave_report.packets_sent == 0 && wave_report.budget_skipped == 0 {
                birthday.stop_reason = Some("socket_unavailable".to_string());
                break;
            }
        }

        if birthday.stop_reason.is_none() {
            birthday.stop_reason = Some("completed".to_string());
        }
        aggregate.unique_target_endpoints =
            u32::try_from(aggregate.sent_target_endpoints.len()).unwrap_or(u32::MAX);
        aggregate.birthday = Some(birthday);
        Ok(aggregate)
    }

    #[allow(clippy::too_many_arguments)]
    async fn hard_hard_birthday_stop_reason(
        &self,
        peer_id: &str,
        session_token: &str,
        profile_fence: (u64, u64),
        peer_session_generation: crate::peer::PeerSessionGeneration,
        network_generation: u64,
        remote_candidate_epoch: u64,
        direct_commit_seq: Option<u64>,
    ) -> Option<&'static str> {
        if self
            .peers
            .hard_hard_winner_for_token(peer_id, session_token)
            .await
            .is_some()
        {
            return Some("winner_selected");
        }
        if self.peers.is_direct_sync(peer_id) {
            return Some("direct_confirmed");
        }
        if self.peers.current_network_generation_sync() != network_generation {
            return Some("network_generation_changed");
        }
        if !self
            .peers
            .peer_session_is_current_sync(peer_id, peer_session_generation)
        {
            return Some("peer_session_changed");
        }
        if self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or_default()
            != remote_candidate_epoch
        {
            return Some("candidate_epoch_changed");
        }
        let profile_current = self
            .peers
            .hard_hard_plan_for_peer(peer_id)
            .await
            .is_some_and(|plan| {
                plan.local_profile_generation == profile_fence.0
                    && plan.remote_profile_generation == profile_fence.1
            });
        if !profile_current {
            return Some("profile_generation_changed");
        }
        if !self
            .peers
            .hard_hard_session_token_is_current(peer_id, session_token)
            .await
        {
            return Some("session_retired");
        }
        if self.peers.direct_commit_seq_sync(peer_id) != direct_commit_seq {
            return Some("direct_commit_seq_changed");
        }
        None
    }

    /// Exact-index sweep with an optional Hard↔Hard profile-generation fence.
    /// The ordinary dynamic helper leaves the fence unset; the synchronized
    /// path supplies both profile generations so a remote profile refresh
    /// cancels the old session before another datagram is emitted.
    pub(crate) async fn punch_candidates_from_dynamic_socket_index_with_profile_fence(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
    ) -> Result<PunchSendReport> {
        self.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
            peer_id,
            socket_index,
            candidates,
            probe_interval,
            attempts,
            profile_fence,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
        &self,
        peer_id: &str,
        socket_index: usize,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
        hard_hard_session_token: Option<&str>,
    ) -> Result<PunchSendReport> {
        let Some((index, socket, _lease)) = self
            .resolve_dynamic_socket_index_for_send(peer_id, socket_index)
            .await
        else {
            return Ok(PunchSendReport::default());
        };
        self.punch_candidates_from_dynamic_socket_resolved(
            peer_id,
            index,
            socket,
            candidates,
            probe_interval,
            attempts,
            profile_fence,
            hard_hard_session_token,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn punch_candidates_from_dynamic_socket_resolved(
        &self,
        peer_id: &str,
        index: usize,
        socket: Arc<UdpSocket>,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
        profile_fence: Option<(u64, u64)>,
        hard_hard_session_token: Option<&str>,
    ) -> Result<PunchSendReport> {
        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        let mut packets_sent = 0u32;
        let mut budget_skipped = 0u32;
        let mut last_budget_reason = None;
        let mut sent_endpoints = HashSet::new();
        let mut first_send_at_ms = None;
        let mut last_send_at_ms: Option<u64> = None;
        let mut per_socket_sent = 0u32;
        let commit_seq_at_start = self.peers.direct_commit_seq_sync(peer_id);
        let network_generation_at_start = self.peers.current_network_generation_sync();
        let remote_candidate_epoch_at_start = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or_default();
        'schedule: for round in schedule {
            if self.peers.current_network_generation_sync() != network_generation_at_start {
                trace!(
                    "Aborting dynamic-socket punch for peer {peer_id}: network generation changed mid-session"
                );
                break;
            }
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }
            for candidate in round.endpoints {
                if let Some(token) = hard_hard_session_token {
                    if self
                        .peers
                        .hard_hard_winner_for_token(peer_id, token)
                        .await
                        .is_some()
                    {
                        trace!(
                            "Aborting dynamic-socket Hard↔Hard scatter for peer {peer_id}: winner already selected"
                        );
                        break 'schedule;
                    }
                }
                if self.peers.current_network_generation_sync() != network_generation_at_start {
                    trace!(
                        "Aborting dynamic-socket punch for peer {peer_id}: network generation changed before candidate send"
                    );
                    break;
                }
                if self
                    .peers
                    .current_remote_candidate_epoch(peer_id)
                    .await
                    .unwrap_or_default()
                    != remote_candidate_epoch_at_start
                {
                    trace!(
                        "Aborting dynamic-socket punch for peer {peer_id}: remote candidate epoch changed before candidate send"
                    );
                    break;
                }
                if let Some((local_profile_generation, remote_profile_generation)) = profile_fence {
                    let profile_current = self
                        .peers
                        .hard_hard_plan_for_peer(peer_id)
                        .await
                        .is_some_and(|plan| {
                            plan.local_profile_generation == local_profile_generation
                                && plan.remote_profile_generation == remote_profile_generation
                        });
                    if !profile_current {
                        trace!(
                            "Aborting dynamic-socket punch for peer {peer_id}: Hard↔Hard profile generation changed before candidate send"
                        );
                        break;
                    }
                }
                if let Some(token) = hard_hard_session_token {
                    if !self
                        .peers
                        .hard_hard_session_token_is_current(peer_id, token)
                        .await
                    {
                        trace!(
                            "Aborting dynamic-socket Hard↔Hard punch for peer {peer_id}: session token was retired"
                        );
                        break;
                    }
                }
                if self.peers.is_direct_sync(peer_id) {
                    // Direct was confirmed while this dedicated-socket sweep
                    // was in flight: stop emitting peer-directed probes.
                    trace!(
                        "Aborting dynamic-socket UDP punch for peer {peer_id}: Direct was confirmed mid-session"
                    );
                    break;
                }
                if self.peers.direct_commit_seq_sync(peer_id) != commit_seq_at_start {
                    trace!(
                        "Aborting dynamic-socket UDP punch for peer {peer_id}: direct_commit_seq advanced past {commit_seq_at_start:?} mid-session"
                    );
                    break;
                }
                if self
                    .peers
                    .direct_probe_endpoint_quarantined(
                        peer_id,
                        candidate,
                        self.peers.current_network_generation_sync(),
                    )
                    .await
                {
                    budget_skipped = budget_skipped.saturating_add(1);
                    last_budget_reason = Some("direct_slow_relay_retained");
                    trace!(
                        "Skipped dynamic-socket punch for peer {peer_id} candidate {candidate}: recent slow ACK quarantine"
                    );
                    continue;
                }
                match self
                    .admit_outbound_connectivity_probe(peer_id, candidate, index)
                    .await
                {
                    OutboundProbeAdmission::Accepted => {}
                    limited => {
                        // The dedicated-socket sweep now shares the same
                        // admission as the pool sweeps: per-second windows,
                        // the persistent budgets AND the recovery-epoch probe
                        // credit all apply to fresh-mapping punches.
                        budget_skipped = budget_skipped.saturating_add(1);
                        last_budget_reason = Some(outbound_probe_admission_reason(limited));
                        continue;
                    }
                }
                match self
                    .send_probe_on_socket_result_with_hard_hard_token(
                        index,
                        socket.clone(),
                        Some(peer_id),
                        candidate,
                        false,
                        PendingProbePurpose::ConnectivityCheck,
                        hard_hard_session_token,
                    )
                    .await
                {
                    Ok(sent) => {
                        packets_sent = packets_sent.saturating_add(1);
                        if let Some(sent_at_ms) = sent.first_send_at_ms {
                            first_send_at_ms.get_or_insert(sent_at_ms);
                            last_send_at_ms = Some(
                                last_send_at_ms
                                    .map_or(sent_at_ms, |last| last.max(sent_at_ms)),
                            );
                        }
                        per_socket_sent =
                            per_socket_sent.saturating_add(u32::from(sent.datagrams_sent));
                        sent_endpoints.insert(candidate);
                        self.peers
                            .record_direct_probe_sent(peer_id, candidate)
                            .await;
                        trace!(
                            "Sent dynamic-socket punch probe to peer {peer_id} candidate {} commit_seq={commit_seq_at_start:?}",
                            candidate
                        );
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
        if budget_skipped > 0 {
            let reason = last_budget_reason.unwrap_or("probe_budget_limited");
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_probe_budget_limited",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "skipped {budget_skipped} dedicated-socket punch probes due to outbound {reason}; sent {packets_sent}"
                    ),
                )
                .await;
        }
        Ok(PunchSendReport {
            packets_sent,
            unique_target_endpoints: u32::try_from(sent_endpoints.len()).unwrap_or(u32::MAX),
            first_send_at_ms,
            per_socket_sent: (per_socket_sent > 0)
                .then_some(vec![(index, per_socket_sent)])
                .unwrap_or_default(),
            budget_skipped,
            epoch_budget_exhausted: false,
            candidate_iteration_capped: false,
            sent_target_endpoints: sent_endpoints.into_iter().collect(),
            last_send_at_ms,
            ..PunchSendReport::default()
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
/// peer's public side on the loopback NAT address, and the NAT-sim harness
/// (`config.network.fresh_mapping_harness_loopback`) deliberately allows
/// loopback endpoints so the deterministic dual-NAT simulation exercises the
/// production fresh path.
fn fresh_mapping_target_eligible(endpoint: SocketAddr, allow_loopback: bool) -> bool {
    if is_public_probe_endpoint(endpoint) {
        return true;
    }
    if allow_loopback && endpoint.ip().is_loopback() {
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

/// Generate a bounded, token-scoped birthday window. It deliberately uses a
/// permutation stride over the UDP port ring and stops at the negotiated
/// level; it never enumerates the full 65,535-port space.
fn hard_hard_birthday_candidates(
    public_ip: IpAddr,
    observed_ports: &[u16],
    level: usize,
    session_token: &str,
) -> Vec<SocketAddr> {
    let mut seed = 0xcbf29ce484222325u64;
    for byte in public_ip.to_string().bytes().chain(session_token.bytes()) {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    // Walk the non-zero UDP port ring with an odd stride.  Keep the stride
    // below 65535: a stride equal to the modulus would repeat one port and
    // could make a bounded level appear shorter than requested.
    let modulus = u64::from(u16::MAX);
    let stride = (seed % (modulus - 1)) | 1;
    let mut candidates = Vec::with_capacity(level);
    let mut seen = HashSet::new();
    for port in observed_ports {
        if *port != 0 && seen.insert(*port) {
            candidates.push(SocketAddr::new(public_ip, *port));
            if candidates.len() == level {
                return candidates;
            }
        }
    }
    let origin = seed % modulus;
    for index in 0..level.saturating_mul(4) {
        let port = ((origin + (index as u64).saturating_mul(stride)) % modulus + 1) as u16;
        if seen.insert(port) {
            candidates.push(SocketAddr::new(public_ip, port));
            if candidates.len() == level {
                break;
            }
        }
    }
    candidates
}

fn hard_hard_birthday_socket_count(level: usize) -> usize {
    match level {
        0..=64 => 2,
        65..=128 => 4,
        _ => 8,
    }
}

fn hard_hard_birthday_capacity_plan(
    requested_level: usize,
    attached_socket_count: usize,
) -> Option<(usize, usize)> {
    let requested_level = match requested_level {
        0..=64 => 64,
        65..=128 => 128,
        _ => 256,
    };
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let available_socket_count = if attached_socket_count >= 8 {
        8
    } else if attached_socket_count >= 4 {
        4
    } else if attached_socket_count >= 2 {
        2
    } else {
        return None;
    };
    let actual_socket_count = available_socket_count.min(requested_socket_count);
    let actual_level = match actual_socket_count {
        2 => 64,
        4 => 128,
        8 => 256,
        _ => return None,
    };
    Some((actual_level, actual_socket_count))
}

fn merge_punch_send_reports(destination: &mut PunchSendReport, source: PunchSendReport) {
    destination.packets_sent = destination.packets_sent.saturating_add(source.packets_sent);
    destination.budget_skipped = destination.budget_skipped.saturating_add(source.budget_skipped);
    destination.epoch_budget_exhausted |= source.epoch_budget_exhausted;
    destination.candidate_iteration_capped |= source.candidate_iteration_capped;
    destination.first_send_at_ms = match (destination.first_send_at_ms, source.first_send_at_ms) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, right) => right,
        (left, None) => left,
    };
    destination.last_send_at_ms = match (destination.last_send_at_ms, source.last_send_at_ms) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, right) => right,
        (left, None) => left,
    };
    for endpoint in source.sent_target_endpoints {
        if !destination.sent_target_endpoints.contains(&endpoint) {
            destination.sent_target_endpoints.push(endpoint);
        }
    }
    for (socket_index, sent) in source.per_socket_sent {
        if let Some((_, existing)) = destination
            .per_socket_sent
            .iter_mut()
            .find(|(index, _)| *index == socket_index)
        {
            *existing = existing.saturating_add(sent);
        } else {
            destination.per_socket_sent.push((socket_index, sent));
        }
    }
}

fn hard_hard_birthday_wave_count(socket_count: usize) -> usize {
    match socket_count {
        0 => 0,
        1 => 1,
        _ => HARD_HARD_BIRTHDAY_WAVES,
    }
}

fn hard_hard_birthday_packets_planned(socket_count: usize, target_count: usize) -> usize {
    target_count.saturating_mul(hard_hard_birthday_wave_count(socket_count))
}

fn hard_hard_birthday_wave_assignments(
    socket_count: usize,
    targets: Vec<SocketAddr>,
    wave: usize,
) -> Vec<Vec<SocketAddr>> {
    if socket_count == 0 {
        return Vec::new();
    }
    let mut assignments = vec![Vec::new(); socket_count];
    let socket_offset = wave % socket_count;
    for (index, target) in targets.into_iter().enumerate() {
        assignments[(index + socket_offset) % socket_count].push(target);
    }
    assignments
}

/// Outcome of one atomic commit phase transition.
#[derive(Debug, Clone, Copy)]
struct CommitOutcome {
    /// Whether the socket transitioned from Provisional to
    /// CommittedPendingHandoff. A birthday speculative commit deliberately
    /// leaves `installed` empty so it can remain a receiver without replacing
    /// the window's single affinity pin.
    committed: bool,
    /// The affinity pin the commit replaced, captured under the same
    /// socket-state lock.  A cancelled generation must restore it so the
    /// peer keeps its previous working path — but only while the affinity
    /// still equals THIS commit's pin (a newer commit owns the affinity
    /// after that and a blind restore would downgrade it).
    predecessor: Option<PeerSocketPin>,
    /// The pin this commit installed. Post-commit rollback compares the live
    /// affinity against this pin before touching anything. `None` identifies
    /// a birthday speculative receiver, whose rollback never changes peer
    /// affinity.
    installed: Option<PeerSocketPin>,
    /// The committed-generation high-water value that fences this guard's
    /// handoff. Birthday speculative receivers share the first socket's
    /// value; a later generation therefore invalidates every old guard.
    generation_fence: u64,
    /// The entry's authenticated-evidence counter at commit time, snapshotted
    /// under the same lock.  The watcher's rollback promotes the socket to
    /// Finalized when the counter moved afterwards: fresh authenticated
    /// evidence observed AFTER the commit proves the mapping carries the
    /// peer's traffic and the socket must never be rolled back and deleted.
    evidence_at_commit: u64,
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
    (*commit_rx.borrow_and_update())
        .as_ref()
        .map(|outcome| *outcome)
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
        let (commit_tx, mut commit_rx) = tokio::sync::watch::channel::<Option<CommitOutcome>>(None);
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
                                Some(outcome) if outcome.committed => watcher_transport
                                    .rollback_committed_entry(&mut state, &socket_index, &outcome),
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
    /// The whole transition runs under the shared network-epoch gate: a
    /// generation advance can never bump the mirror between the in-lock
    /// generation read and the phase flip + pin insert, so a stale generation
    /// can never commit once the generation has moved on.
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
            evidence_at_commit: 0,
            generation_fence: 0,
        };
        let _epoch_gate = transport.network_epoch_gate.lock().await;
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
        // Snapshot the entry's authenticated evidence at commit time: the
        // watcher compares this against the live counter on rollback, so
        // evidence observed AFTER this commit keeps the socket.
        let evidence_at_commit = state
            .dynamic
            .get(&socket_index)
            .map(|entry| entry.authenticated_evidence)
            .unwrap_or(0);
        let outcome = CommitOutcome {
            committed: true,
            predecessor,
            installed: Some(installed),
            evidence_at_commit,
            generation_fence: punch_generation,
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

    /// Commit a birthday receiver without changing peer affinity.
    ///
    /// The first socket in a birthday window owns the affinity pin. Every
    /// other socket still needs the committed phase (so its reader can admit
    /// authenticated Probe v2 traffic and its watcher can survive the
    /// rendezvous), but must not overwrite that pin. `installed = None` in
    /// the outcome gives rollback/finalize the corresponding no-affinity
    /// semantics.
    async fn commit_speculative(
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
            evidence_at_commit: 0,
            generation_fence: 0,
        };
        let _epoch_gate = transport.network_epoch_gate.lock().await;
        let mut state = transport.socket_state.lock().await;
        let Some(entry) = state.dynamic.get(&socket_index) else {
            return refused;
        };
        let current_network_generation = transport.peers.current_network_generation_sync();
        if entry.phase != DynamicSocketPhase::Provisional
            || entry.peer_id != peer_id
            || entry.network_generation != network_generation
            || entry.network_generation != current_network_generation
            || entry.punch_generation != punch_generation
            || self.cancellation.is_cancelled()
        {
            return refused;
        }
        if state
            .committed_punch_generations
            .get(peer_id)
            .is_some_and(|committed| *committed > punch_generation)
        {
            return refused;
        }
        let Some(generation_fence) = state.committed_punch_generations.get(peer_id).copied()
        else {
            return refused;
        };
        let evidence_at_commit = state
            .dynamic
            .get(&socket_index)
            .map(|entry| entry.authenticated_evidence)
            .unwrap_or(0);
        let outcome = CommitOutcome {
            committed: true,
            predecessor: None,
            installed: None,
            evidence_at_commit,
            generation_fence,
        };
        *self.outcome.lock().expect("guard outcome mutex") = Some(outcome);
        let _ = self.commit_tx.send(Some(outcome));
        state
            .dynamic
            .get_mut(&socket_index)
            .expect("speculative entry verified above")
            .phase = DynamicSocketPhase::CommittedPendingHandoff;
        outcome
    }

    #[cfg(test)]
    pub(crate) async fn commit_and_pin_for_test(
        &self,
        transport: &UdpTransport,
        peer_id: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
    ) -> bool {
        self.commit_and_pin(
            transport,
            peer_id,
            socket_index,
            network_generation,
            punch_generation,
        )
        .await
        .committed
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
    /// The flip re-verifies under the lock (and under the shared network-epoch
    /// gate) that the entry still belongs to this guard's peer, still matches
    /// the punch generation this guard committed, is still pinned as THIS
    /// commit installed it, still matches the current network generation, and
    /// the session was not cancelled meanwhile: a stale or superseded entry is
    /// never finalized.
    ///
    /// Returns `false` when the socket was already rolled back (entry gone)
    /// or never committed: the durable handoff did not happen and the caller
    /// must not treat the socket as the peer's long-term path.
    pub(crate) async fn finalize(&self) -> bool {
        // Phase flip under the gate and the lock: after this, the watcher can
        // never roll the socket back.
        let flipped = {
            let _epoch_gate = self.transport.network_epoch_gate.lock().await;
            let mut state = self.transport.socket_state.lock().await;
            let (phase, peer_id, punch_generation, network_generation) =
                match state.dynamic.get(&self.socket_index) {
                    Some(entry) => (
                        entry.phase,
                        entry.peer_id.clone(),
                        entry.punch_generation,
                        entry.network_generation,
                    ),
                    // Rolled back (or evicted) before the durable handoff: the
                    // watcher already restored the predecessor.
                    None => return false,
                };
            if phase == DynamicSocketPhase::Provisional {
                // Never committed; the generation's own cleanup owns it.
                return false;
            }
            if phase != DynamicSocketPhase::Finalized {
                let (committed_punch_generation, current_network_generation, outcome) = {
                    let outcome = self.outcome.lock().expect("guard outcome mutex");
                    (
                        state
                            .committed_punch_generations
                            .get(&self.peer_id)
                            .copied()
                            .unwrap_or(0),
                        self.transport.peers.current_network_generation_sync(),
                        *outcome,
                    )
                };
                let revalidated = outcome.is_some_and(|outcome| {
                    if !outcome.committed
                        || peer_id != self.peer_id
                        || network_generation != current_network_generation
                        || committed_punch_generation != outcome.generation_fence
                        || self.cancellation.is_cancelled()
                    {
                        return false;
                    }
                    match outcome.installed {
                        Some(installed) => {
                            punch_generation == committed_punch_generation
                                && state.affinity.get(&self.peer_id).copied() == Some(installed)
                        }
                        None => {
                            // Birthday speculative receivers share the first
                            // socket's generation fence but intentionally do
                            // not own the peer affinity pin.
                            punch_generation != 0
                                && state
                                    .dynamic
                                    .get(&self.socket_index)
                                    .is_some_and(|entry| {
                                        entry.phase == DynamicSocketPhase::CommittedPendingHandoff
                                    })
                        }
                    }
                });
                if !revalidated {
                    debug!(
                        "finalize refused for socket index={} peer={}: ownership, punch generation, network generation, affinity or cancellation changed since the commit",
                        self.socket_index,
                        self.peer_id
                    );
                    return false;
                }
                state
                    .dynamic
                    .get_mut(&self.socket_index)
                    .expect("finalize entry verified above")
                    .phase = DynamicSocketPhase::Finalized;
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
            pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE && pin.socket_index != self.socket_index
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
    /// - authenticated evidence was observed on the entry AFTER the commit
    ///   (matched ACK, accepted authenticated punch, or decrypted WireGuard
    ///   data received on this socket): the socket demonstrably carries the
    ///   peer's traffic, so it is promoted to `Finalized` and kept — the
    ///   evidence counter is the socket's own record and can never be faked
    ///   by a stale pin or an old network epoch;
    /// - the affinity still equals THIS commit's installed pin (and no
    ///   post-commit evidence exists) → full rollback: restore the
    ///   predecessor pin (or clear the affinity) and detach this
    ///   generation's socket;
    /// - a newer commit or evidence owns the affinity → detach this socket
    ///   WITHOUT restoring the predecessor (a restore would downgrade the
    ///   current owner — the "G2 rollback overwrites G3 commit" race).
    fn rollback_committed_entry(
        &self,
        state: &mut SocketState,
        socket_index: &usize,
        outcome: &CommitOutcome,
    ) -> Option<DynamicPunchSocket> {
        if outcome.installed.is_none() {
            let entry = state.dynamic.get(socket_index)?;
            if entry.phase == DynamicSocketPhase::Finalized {
                return None;
            }
            let has_post_commit_evidence = entry.authenticated_evidence
                > outcome.evidence_at_commit;
            if has_post_commit_evidence {
                state
                    .dynamic
                    .get_mut(socket_index)
                    .expect("speculative socket verified above")
                    .phase = DynamicSocketPhase::Finalized;
                return None;
            }
            let entry = state
                .dynamic
                .remove(socket_index)
                .expect("speculative socket verified above");
            if state
                .affinity
                .get(&entry.peer_id)
                .is_some_and(|pin| pin.socket_index == *socket_index)
            {
                state.affinity.remove(&entry.peer_id);
            }
            return Some(entry);
        }
        let installed = outcome.installed?;
        {
            let entry = state.dynamic.get(socket_index)?;
            if entry.phase == DynamicSocketPhase::Finalized {
                return None;
            }
        }
        let peer_id = state.dynamic.get(socket_index)?.peer_id.clone();
        // Post-commit authenticated evidence is the socket's OWN record:
        // whenever the counter moved past the commit snapshot the mapping
        // demonstrably carried the peer's traffic, so the socket is promoted
        // to the durable phase instead of being rolled back — even when the
        // affinity still equals the installed pin (the evidence re-verified
        // the very socket the commit pinned).
        let has_post_commit_evidence = state
            .dynamic
            .get(socket_index)
            .is_some_and(|entry| entry.authenticated_evidence > outcome.evidence_at_commit);
        if has_post_commit_evidence {
            state
                .dynamic
                .get_mut(socket_index)
                .expect("committed socket verified above")
                .phase = DynamicSocketPhase::Finalized;
            debug!(
                "rollback promoted socket index={socket_index} peer={peer_id} to Finalized: authenticated evidence arrived after the commit (counter {} -> {})",
                outcome.evidence_at_commit,
                state
                    .dynamic
                    .get(socket_index)
                    .map(|entry| entry.authenticated_evidence)
                    .unwrap_or(0)
            );
            return None;
        }
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
            // commit (its evidence counter would normally have moved too; the
            // epoch-only match is the belt-and-braces path for pool pins).
            // It demonstrably carries the peer's traffic and must not be
            // deleted.  Promote it to the durable phase; the predecessor is
            // NOT restored (this socket owns the affinity now).
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

#[cfg(test)]
mod birthday_tests {
    use super::{
        hard_hard_birthday_candidates, hard_hard_birthday_capacity_plan,
        hard_hard_birthday_packets_planned, hard_hard_birthday_wave_assignments,
        hard_hard_birthday_wave_count,
    };
    use p2pnet_nat::mapping::AllocationModelKind;
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn birthday_levels_are_exact_and_never_scan_the_full_port_ring() {
        let public_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        for (level, token) in [(64, "android"), (128, "android-2"), (256, "desktop")] {
            let candidates = hard_hard_birthday_candidates(
                public_ip,
                &[40_000, 40_001, 40_002, 40_003],
                level,
                token,
            );
            assert_eq!(candidates.len(), level);
            assert!(candidates.iter().all(|candidate| {
                candidate.ip() == public_ip && candidate.port() != 0
            }));
            let unique = candidates.iter().map(SocketAddr::port).collect::<HashSet<_>>();
            assert_eq!(unique.len(), level);
            assert!(level < usize::from(u16::MAX));
        }
    }

    #[test]
    fn birthday_diagnostics_keep_unknown_distinct_from_high_entropy() {
        assert_eq!(AllocationModelKind::Unknown.label(), "unknown");
        assert_eq!(AllocationModelKind::HighEntropy.label(), "high_entropy");
        assert_ne!(
            AllocationModelKind::Unknown.label(),
            AllocationModelKind::HighEntropy.label()
        );
    }

    #[test]
    fn birthday_two_waves_rotate_targets_without_socket_cartesian_product() {
        for (socket_count, level) in [(2, 64), (4, 128), (8, 256)] {
            let targets = (1..=level)
                .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16))
                .collect::<Vec<_>>();
            assert_eq!(hard_hard_birthday_wave_count(socket_count), 2);
            let first = hard_hard_birthday_wave_assignments(socket_count, targets.clone(), 0);
            let second = hard_hard_birthday_wave_assignments(socket_count, targets.clone(), 1);
            assert_eq!(first.len(), socket_count);
            assert_eq!(second.len(), socket_count);
            for assignments in [&first, &second] {
                let flattened = assignments.iter().flatten().copied().collect::<Vec<_>>();
                assert_eq!(flattened.len(), level);
                assert_eq!(flattened.iter().collect::<HashSet<_>>().len(), level);
                assert!(flattened.iter().all(|target| targets.contains(target)));
            }
            let first_socket = first
                .iter()
                .enumerate()
                .flat_map(|(socket, assigned)| assigned.iter().map(move |target| (*target, socket)))
                .collect::<HashMap<_, _>>();
            let second_socket = second
                .iter()
                .enumerate()
                .flat_map(|(socket, assigned)| assigned.iter().map(move |target| (*target, socket)))
                .collect::<HashMap<_, _>>();
            assert!(targets
                .iter()
                .all(|target| first_socket[target] != second_socket[target]));
        }
        assert_eq!(hard_hard_birthday_wave_count(1), 1);
        assert_eq!(hard_hard_birthday_wave_count(0), 0);
        assert_eq!(hard_hard_birthday_packets_planned(2, 64), 128);
        assert_eq!(hard_hard_birthday_packets_planned(4, 96), 192);
        assert_eq!(hard_hard_birthday_packets_planned(1, 96), 96);
    }

    #[test]
    fn birthday_capacity_plan_preserves_cap_and_exposes_downgrade() {
        assert_eq!(hard_hard_birthday_capacity_plan(64, 2), Some((64, 2)));
        assert_eq!(hard_hard_birthday_capacity_plan(128, 3), Some((64, 2)));
        assert_eq!(hard_hard_birthday_capacity_plan(256, 7), Some((128, 4)));
        assert_eq!(hard_hard_birthday_capacity_plan(256, 8), Some((256, 8)));
        assert_eq!(hard_hard_birthday_capacity_plan(256, 1), None);
    }
}
