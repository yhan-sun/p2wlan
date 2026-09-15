use super::{
    debug, format_optional_endpoint, oneshot, sleep, timeout, watch, Arc, DaemonError, Duration,
    DynamicPunchSocket, DynamicSocketAttachError, DynamicSocketLeaseState, DynamicSocketPhase,
    HardHardSocketSnapshot, HashSet, Instant, IpAddr, Ipv4Addr, PeerSocketPin,
    ProvisionalSocketGuard, Result, SocketAddr, UdpSocket, UdpSocketPoolMemberDiagnostics,
    UdpTransport, DYNAMIC_READER_READY_TIMEOUT, DYNAMIC_SOCKET_INDEX_BASE,
    DYNAMIC_SOCKET_LEASE_DRAIN_TIMEOUT, MAX_DYNAMIC_PUNCH_SOCKETS,
};

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
    pub(super) async fn detach_dynamic_entry(&self, entry: DynamicPunchSocket, reason: &str) {
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
    pub(super) async fn wait_for_detach_drain(
        &self,
        socket_index: usize,
        leases: &DynamicSocketLeaseState,
    ) {
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
                        && entry
                            .hard_hard_session_token
                            .as_deref()
                            .is_none_or(|token| token == identity.session_token)
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

    #[allow(dead_code)]
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

    /// Snapshot the exact sockets requested by one Hard↔Hard session without
    /// following affinity or falling back to the ordinary pool.  The caller
    /// owns the requested index list from the session ledger; a missing entry
    /// is represented explicitly as detached/unusable so diagnostics can
    /// distinguish it from a smaller request.
    pub(crate) async fn hard_hard_socket_snapshot_for_token(
        &self,
        peer_id: &str,
        token: &str,
        requested_socket_indices: &[usize],
    ) -> Vec<HardHardSocketSnapshot> {
        let state = self.socket_state.lock().await;
        let mut seen = HashSet::with_capacity(requested_socket_indices.len());
        requested_socket_indices
            .iter()
            .copied()
            .filter(|socket_index| seen.insert(*socket_index))
            .map(|socket_index| {
                let entry = state.dynamic.get(&socket_index);
                let attached = entry.is_some_and(|entry| {
                    entry.peer_id == peer_id
                        && entry.hard_hard_session_token.as_deref() == Some(token)
                });
                let usable = attached
                    && entry.is_some_and(|entry| {
                        entry.phase.is_usable()
                            && entry.network_generation
                                == self.peers.current_network_generation_sync()
                    });
                HardHardSocketSnapshot {
                    socket_index,
                    attached,
                    usable,
                }
            })
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
        let (identity, losers) = {
            // Keep the exact socket entry locked across manager selection.
            // `hard_hard_select_winner` commits its session record and sticky
            // winner without any later await; once it returns, this same poll
            // writes authenticated evidence, affinity and Finalized phase.
            // Cancellation therefore observes either no winner transaction or
            // the complete manager + UDP transaction, never a preservable
            // manager-only half state.
            let mut state = self.socket_state.lock().await;
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
            let punch_generation = entry.punch_generation;
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
            let epoch = state.next_epoch();
            state.affinity.insert(
                peer_id.to_string(),
                PeerSocketPin {
                    socket_index,
                    epoch,
                },
            );
            let winner = state
                .dynamic
                .get_mut(&socket_index)
                .expect("winner entry verified above");
            winner.authenticated_evidence = winner.authenticated_evidence.saturating_add(1);
            winner.phase = DynamicSocketPhase::Finalized;
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
            let losers = loser_indices
                .into_iter()
                .filter_map(|index| state.dynamic.remove(&index))
                .collect::<Vec<_>>();
            (identity, losers)
        };
        // The authenticated packet, affinity pin and Finalized phase are one
        // socket-state commit.  In particular, no durable diagnostics await
        // may sit between manager winner selection and this local evidence:
        // timeout cleanup is allowed to inspect the winner concurrently and
        // must never retire the exact socket merely because the event ring is
        // contended.
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
        for entry in losers {
            self.detach_dynamic_entry(entry, "hard_hard_loser_socket")
                .await;
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

    #[cfg(test)]
    pub(crate) async fn promote_hard_hard_winner_for_test(
        &self,
        peer_id: &str,
        token: &str,
        socket_index: usize,
        network_generation: u64,
    ) -> bool {
        let epoch_guard = self.network_epoch_gate.lock().await;
        self.promote_hard_hard_winner_in_epoch(
            &epoch_guard,
            peer_id,
            token,
            socket_index,
            network_generation,
        )
        .await
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
    pub(crate) async fn clear_authenticated_evidence_for_test(&self, socket_index: usize) {
        if let Some(entry) = self
            .socket_state
            .lock()
            .await
            .dynamic
            .get_mut(&socket_index)
        {
            entry.authenticated_evidence = 0;
        }
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

    #[cfg(test)]
    pub(crate) fn hard_hard_socket_state_is_locked_for_test(&self) -> bool {
        self.socket_state.try_lock().is_err()
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
    pub(super) async fn detach_predecessor_unless_repinned(
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
    pub(super) async fn abort_generation_if_cancelled(
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
}
