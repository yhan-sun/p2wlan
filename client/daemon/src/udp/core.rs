/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    /// The primary socket is used for STUN and remains the single-socket
    /// fallback. Additional sockets, when explicitly enabled, are only used
    /// for bounded symmetric-NAT traversal experiments.
    socket: Arc<UdpSocket>,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    stun_waiters: StunWaiters,
    /// Merged socket ownership state: dynamic punch sockets, per-peer
    /// affinity pins and the affinity epoch counter live under one mutex so
    /// every ownership transition is atomic and no lock ordering exists.
    socket_state: Arc<Mutex<SocketState>>,
    /// Per-peer adoption locks serializing every pending-probe ACK adoption
    /// against `clear_pending_probes_for_peer`.
    ///
    /// An ACK handler matches the pending entry, removes it and then performs
    /// a sequence of awaits (WireGuard promotion, endpoint learning, socket
    /// pin, Direct promotion).  Without a fence, a PeerLeft / offline /
    /// public-key cleanup can interleave between those awaits and the ACK
    /// would recreate affinity, candidate or endpoint state for a peer that
    /// was cleaned.  The per-peer adoption lock makes each ACK's
    /// match+adoption one atomic section: the cleanup either runs before the
    /// ACK (the cleanup-epoch fence then refuses the adoption) or after it
    /// (the cleanup removes whatever the ACK created).  Lock order everywhere
    /// is: adoption lock -> socket_state -> pending probes.
    peer_adoption_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    socket_pool_active: Arc<AtomicBool>,
    socket_pool_diagnostics: Arc<Mutex<Vec<UdpSocketPoolMemberDiagnostics>>>,
    dynamic_socket_counter: Arc<AtomicUsize>,
    dynamic_socket_diagnostics: Arc<Mutex<HashMap<usize, UdpSocketPoolMemberDiagnostics>>>,
    inbound_tx: Option<mpsc::Sender<ReceivedEncryptedPacket>>,
    peer_reflexive_tx: Option<mpsc::Sender<PeerReflexiveObservation>>,
    peer_reflexive_notifications: PeerReflexiveNotificationState,
    triggered_checks: TriggeredCheckState,
    nat_maintainers: NatMaintainerState,
    authenticated_punch_replay: AuthPunchReplayState,
    authenticated_punch_rate: AuthPunchRateState,
    outbound_probe_budget: OutboundProbeBudgetState,
    global_outbound_probe_budget: Option<Arc<GlobalOutboundProbeBudget>>,
    local_node_id: Option<String>,
    wireguard_transport: Option<WireGuardTransport>,
}

impl UdpTransport {
    /// Bind a UDP socket for direct peer traffic.
    pub async fn bind(bind_addr: SocketAddr, peers: Arc<PeerManager>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DaemonError::Network(format!("failed to bind UDP socket at {bind_addr}: {e}"))
        })?;

        Ok(Self {
            socket: Arc::new(socket),
            sockets: Arc::new(Vec::new()),
            peers,
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
            stun_waiters: Arc::new(Mutex::new(HashMap::new())),
            socket_state: Arc::new(Mutex::new(SocketState {
                dynamic: HashMap::new(),
                affinity: HashMap::new(),
                affinity_epoch: 0,
                probe_cleanup_epochs: HashMap::new(),
                committed_punch_generations: HashMap::new(),
            })),
            peer_adoption_locks: Arc::new(Mutex::new(HashMap::new())),
            socket_pool_active: Arc::new(AtomicBool::new(false)),
            socket_pool_diagnostics: Arc::new(Mutex::new(vec![UdpSocketPoolMemberDiagnostics {
                socket_index: 0,
                ..Default::default()
            }])),
            dynamic_socket_counter: Arc::new(AtomicUsize::new(0)),
            dynamic_socket_diagnostics: Arc::new(Mutex::new(HashMap::new())),
            inbound_tx: None,
            peer_reflexive_tx: None,
            peer_reflexive_notifications: Arc::new(Mutex::new(HashMap::new())),
            triggered_checks: Arc::new(Mutex::new(HashMap::new())),
            nat_maintainers: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_replay: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_rate: Arc::new(Mutex::new(HashMap::new())),
            outbound_probe_budget: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_probe_budget: default_global_outbound_probe_budget(),
            local_node_id: None,
            wireguard_transport: None,
        })
    }

    #[cfg(test)]
    fn with_global_probe_budget(mut self, budget: Arc<GlobalOutboundProbeBudget>) -> Self {
        self.global_outbound_probe_budget = Some(budget);
        self
    }

    /// Add up to `count - 1` ephemeral sockets for an explicitly enabled
    /// traversal experiment. The primary socket is always slot zero.
    pub async fn with_socket_pool(mut self, count: usize) -> Result<Self> {
        const MAX_SOCKET_POOL_SIZE: usize = 4;
        let requested = count.clamp(1, MAX_SOCKET_POOL_SIZE);
        let bind_addr = self.local_addr()?;
        let pool_bind_addr = SocketAddr::new(bind_addr.ip(), 0);
        let mut sockets = vec![self.socket.clone()];

        for _ in 1..requested {
            let socket = UdpSocket::bind(pool_bind_addr).await.map_err(|e| {
                DaemonError::Network(format!(
                    "failed to bind UDP socket pool member at {pool_bind_addr}: {e}"
                ))
            })?;
            sockets.push(Arc::new(socket));
        }

        self.sockets = Arc::new(sockets);
        *self.socket_pool_diagnostics.lock().await = (0..requested)
            .map(|socket_index| UdpSocketPoolMemberDiagnostics {
                socket_index,
                ..Default::default()
            })
            .collect();
        Ok(self)
    }

    fn active_sockets(&self) -> &[Arc<UdpSocket>] {
        if self.sockets.is_empty() {
            std::slice::from_ref(&self.socket)
        } else {
            self.sockets.as_slice()
        }
    }

    /// Number of live UDP sockets, including the primary data socket.
    pub fn socket_count(&self) -> usize {
        self.active_sockets().len()
    }

    /// Enable additional socket probing after the NAT profile has qualified
    /// this network for the experiment. Receive ownership remains active for
    /// every socket regardless, so an already-open mapping is never missed.
    pub fn set_socket_pool_active(&self, active: bool) {
        self.socket_pool_active.store(active, Ordering::Relaxed);
    }

    pub fn socket_pool_active(&self) -> bool {
        self.socket_pool_active.load(Ordering::Relaxed) && self.socket_count() > 1
    }

    /// A stable, endpoint-free view of the bounded socket pool activity.
    pub async fn socket_pool_diagnostics(&self) -> Vec<UdpSocketPoolMemberDiagnostics> {
        self.socket_pool_diagnostics.lock().await.clone()
    }

    /// Aggregate receive-side probe counters across every bound UDP socket.
    ///
    /// The direct probe loops use this around a punch burst to distinguish
    /// "ACK was not matched" from the more useful runtime signal
    /// "no authenticated probe/ACK datagram reached this daemon at all".
    pub async fn probe_rx_snapshot(&self) -> UdpProbeRxSnapshot {
        let pool = self.socket_pool_diagnostics.lock().await.clone();
        let dynamic = self.dynamic_socket_diagnostics.lock().await.clone();
        pool.into_iter()
            .chain(dynamic.into_values())
            .fold(UdpProbeRxSnapshot::default(), |mut snapshot, member| {
                snapshot.known_peer_ip_datagrams_received = snapshot
                    .known_peer_ip_datagrams_received
                    .saturating_add(member.known_peer_ip_datagrams_received);
                snapshot.authenticated_probe_packets_received = snapshot
                    .authenticated_probe_packets_received
                    .saturating_add(member.authenticated_probe_packets_received);
                snapshot.authenticated_probe_acks_observed = snapshot
                    .authenticated_probe_acks_observed
                    .saturating_add(member.authenticated_probe_acks_observed);
                snapshot.authenticated_probe_acks_unmatched = snapshot
                    .authenticated_probe_acks_unmatched
                    .saturating_add(member.authenticated_probe_acks_unmatched);
                snapshot.legacy_probe_acks_observed = snapshot
                    .legacy_probe_acks_observed
                    .saturating_add(member.legacy_probe_acks_observed);
                snapshot.legacy_probe_acks_unmatched = snapshot
                    .legacy_probe_acks_unmatched
                    .saturating_add(member.legacy_probe_acks_unmatched);
                snapshot.probe_acks_received = snapshot
                    .probe_acks_received
                    .saturating_add(member.probe_acks_received);
                snapshot
            },
        )
    }

    async fn update_socket_diagnostics(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            if let Some(metrics) = self
                .dynamic_socket_diagnostics
                .lock()
                .await
                .get_mut(&socket_index)
            {
                update(metrics);
            }
            return;
        }
        if let Some(diagnostics) = self
            .socket_pool_diagnostics
            .lock()
            .await
            .get_mut(socket_index)
        {
            update(diagnostics);
        }
    }

    fn punch_socket_count(&self) -> usize {
        if self.socket_pool_active() {
            self.socket_count()
        } else {
            1
        }
    }

    async fn socket_index_for_peer(&self, peer_id: Option<&str>) -> usize {
        let socket_count = self.socket_count();
        let Some(peer_id) = peer_id else {
            return 0;
        };
        let state = self.socket_state.lock().await;
        let Some(pin) = state.affinity.get(peer_id).copied() else {
            return 0;
        };
        if pin.socket_index < socket_count {
            return pin.socket_index;
        }
        if pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            // The pin may only resolve to a dynamic socket that still belongs
            // to this peer and is Committed: a Provisional socket is owned by
            // its in-flight generation, and an entry re-purposed or evicted
            // must fall back to the pool instead of resolving to a dead
            // index.
            if state
                .dynamic
                .get(&pin.socket_index)
                .is_some_and(|entry| {
                    entry.peer_id == peer_id && entry.phase.is_usable()
                })
            {
                return pin.socket_index;
            }
            drop(state);
            self.socket_state.lock().await.affinity.remove(peer_id);
            return 0;
        }
        0
    }

    /// Resolve the UDP socket that should carry traffic for `peer_id` together
    /// with its ACTUAL index.
    ///
    /// A per-peer fresh-mapping punch socket takes precedence (it owns the
    /// peer-facing NAT mapping); otherwise the pool socket pinned by affinity.
    /// A dynamic socket whose network generation is stale is detached and the
    /// peer falls back to the pool, so a handover never keeps sending from a
    /// dead mapping.
    ///
    /// The index and the socket are resolved atomically under one lock
    /// acquisition: callers must record the returned index (not a separately
    /// resolved one) in their pending-probe bookkeeping, because the dynamic
    /// socket can be detached between two separate calls and the ACK would
    /// then never match the actual sending socket.
    pub async fn socket_for_peer(&self, peer_id: Option<&str>) -> Option<(usize, Arc<UdpSocket>)> {
        if let Some(peer_id) = peer_id {
            if let Some(index) = self.dynamic_socket_index_for_peer(peer_id).await {
                if let Some(socket) = self
                    .socket_state
                    .lock()
                    .await
                    .dynamic
                    .get(&index)
                    .map(|dynamic| dynamic.socket.clone())
                {
                    return Some((index, socket));
                }
            }
        }
        let index = self.socket_index_for_peer(peer_id).await;
        if index >= DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        self.active_sockets()
            .get(index)
            .cloned()
            .map(|socket| (index, socket))
    }

    /// Dynamic punch socket index pinned for a peer, if any.
    ///
    /// A socket that no longer matches the current network generation is
    /// detached immediately: its NAT mapping belongs to an old network and
    /// must not keep receiving probes or data.  The network generation is
    /// read before locking, and the detachment re-verifies ownership under
    /// the lock, so no async work ever runs while the socket state is held.
    /// The entry must also belong to the peer and be Committed: a pin to a
    /// Provisional socket or to another peer's entry is stale and falls back
    /// to the pool.
    pub async fn dynamic_socket_index_for_peer(&self, peer_id: &str) -> Option<usize> {
        let mut state = self.socket_state.lock().await;
        let pin = state.affinity.get(peer_id).copied()?;
        if pin.socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let Some(dynamic) = state.dynamic.get(&pin.socket_index) else {
            // Evicted or detached: clear the stale affinity so later
            // lookups fall back to the pool instead of returning None.
            state.affinity.remove(peer_id);
            return None;
        };
        if dynamic.peer_id != peer_id || !dynamic.phase.is_usable() {
            state.affinity.remove(peer_id);
            return None;
        }
        // The generation is read under the socket-state lock (lock-free
        // mirror), so a network-generation change can never slip between the
        // read and the ownership check.
        if dynamic.network_generation != self.peers.current_network_generation_sync() {
            let detached = state
                .dynamic
                .remove(&pin.socket_index)
                .expect("dynamic socket verified above");
            state.affinity.remove(peer_id);
            drop(state);
            self.detach_dynamic_entry(detached, "network_generation_changed")
                .await;
            return None;
        }
        Some(pin.socket_index)
    }

    /// Resolve the peer's dynamic punch socket for a probe send and hold a
    /// send lease on it.
    ///
    /// The resolve re-validates peer ownership, a usable phase and the
    /// current network generation under the socket-state lock, and the lease
    /// is registered in the SAME critical section (the detach path waits for
    /// leases to drain before aborting the reader, so a resolve that won the
    /// lock can never race a detach's drain).  The lease keeps the entry's
    /// reader alive until the send completes; `send_probe_on_socket` then
    /// re-binds the lease to the pending probe so it survives until the ACK.
    pub(crate) async fn resolve_dynamic_socket_for_send(
        &self,
        peer_id: &str,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        let state = self.socket_state.lock().await;
        let pin = state.affinity.get(peer_id).copied()?;
        if pin.socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let dynamic = state.dynamic.get(&pin.socket_index)?;
        if dynamic.peer_id != peer_id
            || !dynamic.phase.is_usable()
            || dynamic.network_generation != self.peers.current_network_generation_sync()
        {
            return None;
        }
        let leases = dynamic.send_leases.clone();
        let socket = dynamic.socket.clone();
        let index = pin.socket_index;
        // Register the lease while the socket-state lock is still held: a
        // concurrent detach can only drain AFTER removing the entry under
        // this same lock, so it always observes this lease.
        leases.acquire();
        drop(state);
        Some((
            index,
            socket,
            DynamicSocketSendLease {
                state: leases,
                socket_index: index,
            },
        ))
    }

    /// Whether a dynamic punch socket is currently attached for this peer.
    pub async fn has_dynamic_socket_for_peer(&self, peer_id: &str) -> bool {
        self.dynamic_socket_index_for_peer(peer_id).await.is_some()
    }

    /// Adopt `socket_index` as the peer's traffic socket, backed by evidence
    /// whose epoch decides whether it may supersede the current pin.
    ///
    /// Affinity selection is based on evidence newness, never on socket type:
    /// a matched current-generation ACK from a pool socket is valid evidence
    /// and may restore the working pool path after a failed fresh generation,
    /// while older stamped evidence can never downgrade a newer commit.
    ///
    /// A dynamic socket is only valid evidence for the peer it belongs to,
    /// only once it is Committed (a provisional socket is still owned by its
    /// in-flight generation), and only while it matches the current network
    /// generation: an old generation's socket must never be adopted by stale
    /// inbound evidence.
    pub(crate) async fn remember_peer_socket(
        &self,
        peer_id: &str,
        socket_index: usize,
        evidence: SocketEvidence,
    ) {
        let mut state = self.socket_state.lock().await;
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            let Some(entry) = state.dynamic.get(&socket_index) else {
                return;
            };
            // The network generation is read under the socket-state lock
            // (lock-free mirror): a generation advance can never slip between
            // the read and this ownership check.
            if entry.peer_id != peer_id
                || !entry.phase.is_usable()
                || entry.network_generation != self.peers.current_network_generation_sync()
            {
                return;
            }
        } else if socket_index >= self.socket_count() {
            return;
        }
        let current = state.affinity.get(peer_id).copied();
        match evidence {
            SocketEvidence::Stamped(epoch) => {
                if current.is_some_and(|pin| epoch < pin.epoch) {
                    // Older evidence than the committed path: refuse.
                    return;
                }
            }
            SocketEvidence::Fresh => {
                if current.is_some_and(|pin| pin.socket_index == socket_index) {
                    // Already pinned on this socket; keep the epoch stable so
                    // repeated inbound evidence never races newer stamps away.
                    return;
                }
            }
        }
        let epoch = state.next_epoch();
        state.affinity.insert(
            peer_id.to_string(),
            PeerSocketPin {
                socket_index,
                epoch,
            },
        );
    }

    /// The per-peer adoption lock serializing ACK adoption against peer
    /// cleanup.  Callers must hold the returned guard across the whole
    /// match/verify/adopt sequence (or, for cleanup, across the epoch bump
    /// and pending drop).  Entries are never removed so a stale lock can
    /// never be re-created for the same peer while a task still holds the
    /// old one.
    async fn adoption_lock_for(&self, peer_id: &str) -> Arc<Mutex<()>> {
        self.peer_adoption_locks
            .lock()
            .await
            .entry(peer_id.to_string())
            .or_default()
            .clone()
    }

    /// The peer's current affinity pin, for tests in other modules.
    #[cfg(test)]
    pub(crate) async fn affinity_pin_for_test(&self, peer_id: &str) -> Option<PeerSocketPin> {
        self.socket_state.lock().await.affinity.get(peer_id).copied()
    }

    /// Attach the encrypted-packet inbound channel used by socket readers.
    ///
    /// Called once by the UDP direct task before `run_inbound`, so dynamically
    /// attached punch sockets can start their own readers with the same
    /// receive destination.
    pub fn with_inbound_channel(mut self, tx: mpsc::Sender<ReceivedEncryptedPacket>) -> Self {
        self.inbound_tx = Some(tx);
        self
    }

    fn inbound_channel(&self) -> Option<mpsc::Sender<ReceivedEncryptedPacket>> {
        self.inbound_tx.clone()
    }

    /// Allocate a fresh dynamic socket index that never collides with the pool.
    pub(crate) fn next_dynamic_index(&self) -> usize {
        DYNAMIC_SOCKET_INDEX_BASE
            + self
                .dynamic_socket_counter
                .fetch_add(1, Ordering::Relaxed)
                % (usize::MAX - DYNAMIC_SOCKET_INDEX_BASE)
    }

    /// Drop every pending probe nonce owned by a peer and bump the peer's
    /// pending-probe cleanup epoch.
    ///
    /// Used when the peer leaves, goes offline, or its endpoint/public key
    /// changes: ACKs from the old endpoint/identity must not be matched and
    /// adopted afterwards, and an ACK handler racing the cleanup must not be
    /// able to re-insert an old pending entry (it stamps the cleanup epoch and
    /// re-insertion is refused once the epoch moved on).
    ///
    /// The whole transaction runs under the peer's adoption lock, the
    /// socket-state lock and the pending lock (in that order everywhere): no
    /// ACK handler can match, adopt or re-insert while the cleanup runs, and
    /// an ACK that already matched under the lock is followed by the cleanup
    /// removing every adoption it created.
    pub(crate) async fn clear_pending_probes_for_peer(&self, peer_id: &str) {
        let adoption = self.adoption_lock_for(peer_id).await;
        let _adoption_guard = adoption.lock().await;
        let mut state = self.socket_state.lock().await;
        let cleanup_epoch = state
            .probe_cleanup_epochs
            .entry(peer_id.to_string())
            .or_insert(0);
        *cleanup_epoch = cleanup_epoch.saturating_add(1);
        let cleanup_epoch = *cleanup_epoch;
        // The drop runs while the epoch guard is still held: no concurrent
        // send can insert a fresh entry stamped with the pre-cleanup epoch
        // after this transaction completes.
        self.pending_probes
            .lock()
            .await
            .retain(|_, pending| pending.peer_id.as_deref() != Some(peer_id));
        drop(state);
        debug!(
            "Cleared pending probes for peer {peer_id} (cleanup_epoch={cleanup_epoch})"
        );
    }

    /// The peer's current pending-probe cleanup epoch (0 when never cleaned).
    ///
    /// A pending probe is only eligible for re-insertion by an ACK handler
    /// when this value still equals the probe's stamped epoch.
    async fn peer_probe_cleanup_epoch(&self, peer_id: &str) -> u64 {
        self.socket_state
            .lock()
            .await
            .probe_cleanup_epochs
            .get(peer_id)
            .copied()
            .unwrap_or(0)
    }

    /// Drop every pending probe that was sent from `socket_index` and release
    /// its send lease.
    ///
    /// Called by the detach path AFTER the lease-drain grace expired: the
    /// reader is about to be aborted, so those probes can never be matched
    /// anymore; removing them releases their leases so the detach never
    /// blocks on a probe that will never be ACKed.
    async fn drop_pending_probes_for_socket(&self, socket_index: usize) {
        self.pending_probes
            .lock()
            .await
            .retain(|_, pending| pending.socket_index != socket_index);
    }

    /// Number of live dedicated fresh-mapping punch sockets.
    pub async fn dynamic_socket_count(&self) -> usize {
        self.socket_state.lock().await.dynamic.len()
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
    }

    /// Attach the WireGuard session registry so an authenticated pending
    /// Probe-v2 packet confirms the matching responder session first.
    pub fn with_wireguard_transport(mut self, transport: WireGuardTransport) -> Self {
        self.wireguard_transport = Some(transport);
        self
    }

    /// Attach a best-effort channel for relay-assisted peer-reflexive observations.
    pub fn with_peer_reflexive_observer(
        mut self,
        tx: mpsc::Sender<PeerReflexiveObservation>,
    ) -> Self {
        self.peer_reflexive_tx = Some(tx);
        self
    }
}
