use super::*;

impl UdpTransport {
    pub(crate) async fn socket_index_for_peer(&self, peer_id: Option<&str>) -> usize {
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
                .is_some_and(|entry| entry.peer_id == peer_id && entry.phase.is_usable())
            {
                return pin.socket_index;
            }
            drop(state);
            self.socket_state.lock().await.affinity.remove(peer_id);
            return 0;
        }
        0
    }

    pub(crate) async fn is_authenticated_direct_endpoint(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> bool {
        self.peers
            .is_authenticated_direct_endpoint(peer_id, endpoint, generation)
            .await
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

    /// Resolve the UDP socket for a peer when the remote endpoint may be IPv6.
    pub async fn socket_for_peer_endpoint(
        &self,
        peer_id: Option<&str>,
        endpoint: Option<SocketAddr>,
    ) -> Option<(usize, Arc<UdpSocket>)> {
        if endpoint.is_some_and(|ep| ep.is_ipv6()) {
            return self.ipv6_socket.clone().map(|s| (IPV6_SOCKET_INDEX, s));
        }
        self.socket_for_peer(peer_id).await
    }

    /// Resolve the exact socket that received an authenticated direct packet.
    ///
    /// A response to a hole-punch validation request must leave through the
    /// same local mapping that received the request.  Resolving by peer
    /// affinity here is incorrect: a concurrent candidate observation may
    /// have pinned another pool/dynamic socket between ingress and the ACK,
    /// causing the NAT to see the ACK from a different source port.  The
    /// caller has already verified that `socket_index` belongs to the live
    /// UDP publication; this method additionally checks dynamic ownership and
    /// network generation so a stale index cannot be reused for another peer.
    pub(crate) async fn socket_for_inbound_peer_index(
        &self,
        peer_id: &str,
        socket_index: usize,
    ) -> Option<Arc<UdpSocket>> {
        if socket_index == IPV6_SOCKET_INDEX {
            return self.ipv6_socket.clone();
        }
        if socket_index < self.socket_count() {
            return self.active_sockets().get(socket_index).cloned();
        }
        if socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let state = self.socket_state.lock().await;
        let dynamic = state.dynamic.get(&socket_index)?;
        if dynamic.peer_id != peer_id
            || dynamic.network_generation != self.peers.current_network_generation_sync()
        {
            return None;
        }
        Some(dynamic.socket.clone())
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

    /// Return every committed/finalized speculative socket for a peer. The
    /// deterministic loopback NAT harness uses this to route one packet that
    /// arrived at a shared fake public endpoint to a deterministic live
    /// receiver; production sends still use the exact-index path and never
    /// multiply their target count.
    #[cfg(test)]
    pub(crate) async fn dynamic_sockets_for_peer_for_test(
        &self,
        peer_id: &str,
    ) -> Vec<(usize, Arc<UdpSocket>)> {
        let state = self.socket_state.lock().await;
        state
            .dynamic
            .iter()
            .filter(|(_, entry)| {
                entry.peer_id == peer_id
                    && entry.phase.is_usable()
                    && entry.network_generation == self.peers.current_network_generation_sync()
            })
            .map(|(index, entry)| (*index, entry.socket.clone()))
            .collect()
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
    ///
    /// Every authenticated evidence observation (matched ACK, accepted
    /// authenticated punch, decrypted WireGuard data) is ALSO recorded on the
    /// dynamic socket entry itself: the watcher's post-commit rollback relies
    /// on the entry's own evidence counter, never on the indirect affinity
    /// epoch, so a socket that demonstrably carries the peer's traffic after
    /// its commit can never be rolled back and deleted by a cancellation
    /// that raced the commit.
    ///
    /// The whole adoption runs under the network-epoch gate: an advance can
    /// never bump the generation between the ownership check and the affinity
    /// insert, so an old generation's evidence can never become affinity.
    pub(crate) async fn remember_peer_socket(
        &self,
        peer_id: &str,
        socket_index: usize,
        evidence: SocketEvidence,
    ) {
        let epoch_guard = self.network_epoch_gate.lock().await;
        let generation = self.peers.current_network_generation_sync();
        let _ = self
            .remember_peer_socket_for_generation_in_epoch(
                &epoch_guard,
                peer_id,
                socket_index,
                generation,
                evidence,
            )
            .await;
    }

    /// Adopt a socket as affinity evidence while the caller owns the shared
    /// network-epoch gate and has already validated `generation`.
    ///
    /// Direct-validation ACK handling uses this together with expectation
    /// consumption and Direct promotion so a generation advance cannot land
    /// between a valid ACK and its affinity write.  The explicit generation
    /// fence also makes a pool-socket affinity impossible for a stale ACK
    /// (pool sockets do not themselves carry a generation field).
    pub(crate) async fn remember_peer_socket_for_generation_in_epoch(
        &self,
        _epoch_guard: &tokio::sync::MutexGuard<'_, ()>,
        peer_id: &str,
        socket_index: usize,
        generation: u64,
        evidence: SocketEvidence,
    ) -> bool {
        if generation != self.peers.current_network_generation_sync() {
            return false;
        }
        let mut state = self.socket_state.lock().await;
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            let Some(entry) = state.dynamic.get_mut(&socket_index) else {
                return false;
            };
            // The network generation is read under the socket-state lock
            // (lock-free mirror): a generation advance can never slip between
            // the read and this ownership check.
            if entry.peer_id != peer_id
                || !entry.phase.is_usable()
                || entry.network_generation != generation
            {
                return false;
            }
            // The evidence belongs to THIS entry: peer identity, network
            // generation and phase all matched.  Old sockets, old generations
            // and old network epochs can never bump a new owner's counter
            // because the entry itself is the evidence record.
            entry.authenticated_evidence = entry.authenticated_evidence.saturating_add(1);
        } else if socket_index >= self.socket_count() {
            return false;
        }
        let current = state.affinity.get(peer_id).copied();
        match evidence {
            SocketEvidence::Stamped(epoch) => {
                if current.is_some_and(|pin| epoch < pin.epoch) {
                    // Older evidence than the committed path: refuse.
                    return false;
                }
            }
            SocketEvidence::Fresh => {
                if current.is_some_and(|pin| pin.socket_index == socket_index) {
                    // Already pinned on this socket: the authenticated
                    // evidence was recorded on the entry above, so the
                    // watcher can still see it and keep the socket instead of
                    // restoring a predecessor.  The pin epoch stays stable so
                    // repeated inbound evidence never races newer stamps
                    // away.
                    return true;
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
        true
    }

    /// The per-peer adoption lock serializing ACK adoption against peer
    /// cleanup.  Callers must hold the returned guard across the whole
    /// match/verify/adopt sequence (or, for cleanup, across the epoch bump
    /// and pending drop).  Entries are never removed so a stale lock can
    /// never be re-created for the same peer while a task still holds the
    /// old one.
    pub(super) async fn adoption_lock_for(&self, peer_id: &str) -> Arc<Mutex<()>> {
        self.peer_adoption_locks
            .lock()
            .await
            .entry(peer_id.to_string())
            .or_default()
            .clone()
    }

    /// Acquire the same per-peer lifecycle fence used by authenticated punch
    /// ACKs and `PeerLeft` cleanup.  Encrypted direct-validation packets use
    /// this before entering the network-epoch transaction, preserving the
    /// global lock order `adoption -> epoch -> socket_state` and preventing a
    /// late validation ACK from promoting a peer incarnation that was removed
    /// and rejoined under the same node ID.
    pub(crate) async fn lock_peer_adoption_for_direct_validation(
        &self,
        peer_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.adoption_lock_for(peer_id).await.lock_owned().await
    }

    /// The peer's current affinity pin, for tests in other modules.
    #[cfg(test)]
    pub(crate) async fn affinity_pin_for_test(&self, peer_id: &str) -> Option<PeerSocketPin> {
        self.socket_state
            .lock()
            .await
            .affinity
            .get(peer_id)
            .copied()
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

    pub(super) fn inbound_channel(&self) -> Option<mpsc::Sender<ReceivedEncryptedPacket>> {
        self.inbound_tx.clone()
    }

    /// Stamp this transport with the owner of the daemon publication that is
    /// currently allowed to use it for Direct-path evidence. Owner zero is
    /// deliberately reserved for unpublished transports.
    pub(crate) fn set_inbound_publication_owner(&self, owner: u64) {
        debug_assert_ne!(owner, 0, "UDP publication owner zero is reserved");
        self.dplpmtud.with_business_publication_gate(|| {
            self.inbound_publication_owner
                .store(owner, Ordering::Release);
        });
        self.peers.notify_direct_business_budget_changed();
    }

    /// Revoke an owner only when this transport still carries that exact
    /// publication. A late cleanup from a retired worker must never clear a
    /// transport which has already been republished under a newer owner.
    pub(crate) fn clear_inbound_publication_owner_if_matches(&self, owner: u64) -> bool {
        let cleared = self.dplpmtud.with_business_publication_gate(|| {
            self.inbound_publication_owner
                .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        });
        if cleared {
            // Closing publishes an explicit Some -> None revision for every
            // managed peer before this retired transport can disappear.
            self.dplpmtud
                .close("udp_transport_unpublished", tokio::time::Instant::now());
            self.peers.notify_direct_business_budget_changed();
        }
        cleared
    }

    /// The owner token socket readers put on encrypted UDP envelopes. Zero
    /// means the reader belongs to no live daemon publication.
    pub(crate) fn inbound_publication_owner(&self) -> u64 {
        self.inbound_publication_owner.load(Ordering::Acquire)
    }

    /// Allocate a fresh dynamic socket index that never collides with the pool.
    pub(crate) fn next_dynamic_index(&self) -> usize {
        DYNAMIC_SOCKET_INDEX_BASE
            + self.dynamic_socket_counter.fetch_add(1, Ordering::Relaxed)
                % (usize::MAX - DYNAMIC_SOCKET_INDEX_BASE)
    }

    pub(crate) async fn resolve_send_socket_with_lease_for_endpoint(
        &self,
        peer_id: &str,
        endpoint: Option<SocketAddr>,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        if endpoint.is_some_and(|ep| ep.is_ipv6()) {
            return self.ipv6_socket.clone().map(|socket| {
                (
                    IPV6_SOCKET_INDEX,
                    socket,
                    DynamicSocketSendLease::noop(IPV6_SOCKET_INDEX),
                )
            });
        }
        self.resolve_send_socket_with_lease(peer_id).await
    }

    /// Resolve the socket for a direct-validation send under ONE
    /// socket-state critical section: a per-peer dynamic socket (with a real
    /// send lease) or the affinity-pinned pool socket (noop lease).  The
    /// peer falls back to pool index 0 when the pin is stale or detached.
    pub(super) async fn resolve_send_socket_with_lease(
        &self,
        peer_id: &str,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        let mut state = self.socket_state.lock().await;
        let socket_count = self.socket_count();
        let pin = state.affinity.get(peer_id).copied();
        if let Some(pin) = pin {
            if pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
                if let Some(dynamic) = state.dynamic.get(&pin.socket_index) {
                    if dynamic.peer_id == peer_id
                        && dynamic.phase.is_usable()
                        && dynamic.network_generation
                            == self.peers.current_network_generation_sync()
                    {
                        let leases = dynamic.send_leases.clone();
                        let socket = dynamic.socket.clone();
                        let index = pin.socket_index;
                        leases.acquire();
                        drop(state);
                        return Some((
                            index,
                            socket,
                            DynamicSocketSendLease {
                                state: leases,
                                socket_index: index,
                            },
                        ));
                    }
                }
                state.affinity.remove(peer_id);
            } else if pin.socket_index < socket_count {
                let index = pin.socket_index;
                let socket = self.active_sockets().get(index).cloned();
                drop(state);
                return socket.map(|socket| (index, socket, DynamicSocketSendLease::noop(index)));
            }
        }
        let index = 0usize;
        let socket = self.active_sockets().get(index).cloned();
        drop(state);
        socket.map(|socket| (index, socket, DynamicSocketSendLease::noop(index)))
    }
}
