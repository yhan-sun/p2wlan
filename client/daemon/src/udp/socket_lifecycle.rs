use super::*;

/// A spawned dynamic reader should reach its first socket receive poll
/// immediately.  Bound the handshake so a broken runtime/task cannot leave a
/// fresh-mapping generation waiting forever before its first STUN request.
pub(super) const DYNAMIC_READER_READY_TIMEOUT: Duration = Duration::from_secs(1);

/// Outcome of one atomic commit phase transition.
#[derive(Debug, Clone, Copy)]
pub(super) struct CommitOutcome {
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
pub(super) const FINALIZE_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Read the latest commit outcome from the watcher's watch channel without
/// holding any lock: `borrow_and_update` marks the value as seen so the next
/// `changed()` parks until a NEW publish, while `borrow` re-reads the same
/// value — the watcher re-verifies plain values on every wake to stay immune
/// to lost notifications.
pub(super) fn watched_commit_outcome(
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
    pub(super) fn spawn(
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
    pub(super) async fn commit_and_pin(
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
    pub(super) async fn commit_speculative(
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
        let Some(generation_fence) = state.committed_punch_generations.get(peer_id).copied() else {
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
                                && state.dynamic.get(&self.socket_index).is_some_and(|entry| {
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

impl Drop for ProvisionalSocketGuard {
    fn drop(&mut self) {
        self.stop_tx.send_replace(true);
    }
}

impl std::fmt::Debug for ProvisionalSocketGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The guard contains live channels and a task handle; only its
        // identity is stable for debugging.
        f.debug_struct("ProvisionalSocketGuard")
            .field("socket_index", &self.socket_index)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}

impl UdpTransport {
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
    pub(super) fn rollback_committed_entry(
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
            let has_post_commit_evidence =
                entry.authenticated_evidence > outcome.evidence_at_commit;
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

impl CommitOutcome {
    pub(super) fn committed(&self) -> bool {
        self.committed
    }
    #[cfg(test)]
    pub(super) fn predecessor(&self) -> Option<PeerSocketPin> {
        self.predecessor
    }
    #[cfg(test)]
    pub(super) fn installed(&self) -> Option<PeerSocketPin> {
        self.installed
    }
}
