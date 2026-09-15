use super::*;

impl UdpTransport {
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
    #[allow(dead_code)]
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
        self.prune_hard_hard_probe_bindings().await;
        drop(state);
        debug!("Cleared pending probes for peer {peer_id} (cleanup_epoch={cleanup_epoch})");
    }

    /// One atomic per-peer lifecycle cleanup: PeerLeft / offline /
    /// public-key-change removal is linearized against every ACK
    /// match -> verify -> endpoint learn -> socket adopt -> Direct promotion
    /// transaction for the same peer.
    ///
    /// The ENTIRE cleanup runs under the peer's adoption lock — the same lock
    /// every ACK handler holds for its whole adoption sequence — so the two
    /// can never interleave: either the ACK completes first and the cleanup
    /// then removes everything it created (connection, affinity, dynamic
    /// sockets, pending probes, endpoints, candidates), or the cleanup
    /// completes first and the cleanup-epoch fence refuses every late ACK.
    /// After this returns, no old ACK can leave pool affinity, an endpoint or
    /// a candidate behind, and nothing can pollute a new identity that joins
    /// under the same node ID.
    ///
    /// `remove_connection` controls whether the peer's connection entry is
    /// deleted (PeerLeft) or kept (offline / public-key change, where
    /// `add_peer` already reset the new identity's state).
    ///
    /// Lock order: adoption lock -> network-epoch gate -> socket_state ->
    /// pending probes; the connection removal runs under the adoption lock
    /// but never nests the other locks (no path takes adoption while holding
    /// connections).
    pub(crate) async fn cleanup_peer_lifecycle(
        &self,
        peer_id: &str,
        reason: &str,
        remove_connection: bool,
    ) {
        let adoption = self.adoption_lock_for(peer_id).await;
        let _adoption_guard = adoption.lock().await;
        self.cleanup_peer_lifecycle_under_adoption(peer_id, reason, remove_connection)
            .await;
    }

    /// Atomically erase the old UDP lifecycle and publish a claimed remote
    /// incarnation while owning the same adoption fence used by authenticated
    /// Probe handlers.
    ///
    /// WireGuard session removal happens before this call (`emit`), then this
    /// method owns `adoption` while cleanup and `finish` acquire `epoch`,
    /// preserving the canonical cross-layer order `emit -> adoption -> epoch`.
    pub(crate) async fn cleanup_peer_lifecycle_and_finish_remote_incarnation_reset(
        &self,
        peer_id: &str,
        reason: &str,
        old_incarnation: u64,
        claimed_incarnation: u64,
    ) -> bool {
        let adoption = self.adoption_lock_for(peer_id).await;
        let _adoption_guard = adoption.lock().await;
        self.cleanup_peer_lifecycle_under_adoption(peer_id, reason, false)
            .await;
        #[cfg(test)]
        self.pause_after_remote_incarnation_cleanup_for_test(peer_id)
            .await;
        self.peers
            .finish_claimed_remote_incarnation_reset(
                peer_id,
                old_incarnation,
                claimed_incarnation,
                reason,
            )
            .await
    }

    #[cfg(test)]
    pub(crate) fn install_remote_incarnation_cleanup_gate_for_test(
        &self,
        peer_id: &str,
        gate: Arc<RemoteIncarnationCleanupGate>,
    ) {
        *self
            .remote_incarnation_cleanup_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((peer_id.to_string(), gate));
    }

    #[cfg(test)]
    pub(super) async fn pause_after_remote_incarnation_cleanup_for_test(&self, peer_id: &str) {
        let gate = {
            let mut installed = self
                .remote_incarnation_cleanup_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if installed
                .as_ref()
                .is_some_and(|(expected, _)| expected == peer_id)
            {
                installed.take().map(|(_, gate)| gate)
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.wait().await;
        }
    }

    /// Cleanup body for callers that already own this peer's adoption lock.
    pub(super) async fn cleanup_peer_lifecycle_under_adoption(
        &self,
        peer_id: &str,
        reason: &str,
        remove_connection: bool,
    ) {
        self.dplpmtud_ack_reverse_routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(peer_id);
        // Revoke the validation owner before removing peer/socket state.  A
        // worker that was waiting for a handshake or ACK immediately observes
        // cancellation, and its owner-conditional cleanup cannot erase a
        // future session if this node ID later rejoins.
        self.peers
            .cancel_active_direct_validation_for_peer(peer_id)
            .await;
        self.peers
            .cancel_active_dplpmtud_for_peer(peer_id, reason)
            .await;
        if remove_connection {
            // The connection removal runs INSIDE the adoption-lock
            // transaction: an ACK that already passed its peer-existence
            // fence either completed before this removal (and the rest of
            // this cleanup removes what it created) or is refused by the
            // epoch fence below.
            self.peers.remove_peer(peer_id).await;
            // A rebind could have installed a new active registry between the
            // first cancellation and this removal. Revoke that current owner
            // as well; `begin_or_merge` also refuses the now-absent peer.
            self.peers
                .cancel_active_direct_validation_for_peer(peer_id)
                .await;
            self.peers
                .cancel_active_dplpmtud_for_peer(peer_id, reason)
                .await;
        }
        // Bump the cleanup epoch and drop the peer's pending probes under the
        // adoption lock: a late ACK can neither match nor re-insert.
        {
            let mut state = self.socket_state.lock().await;
            let cleanup_epoch = state
                .probe_cleanup_epochs
                .entry(peer_id.to_string())
                .or_insert(0);
            *cleanup_epoch = cleanup_epoch.saturating_add(1);
            let cleanup_epoch = *cleanup_epoch;
            self.pending_probes
                .lock()
                .await
                .retain(|_, pending| pending.peer_id.as_deref() != Some(peer_id));
            // Remove every dynamic socket owned by the peer and clear the
            // affinity inside the same transaction: an ACK adoption that
            // raced the cleanup can never leave a stale pool pin or a dead
            // dynamic entry behind.
            let entries = {
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
            drop(state);
            for entry in entries {
                self.detach_dynamic_entry(entry, reason).await;
            }
            debug!(
                "Cleaned up peer {peer_id} lifecycle (reason={reason}, remove_connection={remove_connection}, cleanup_epoch={cleanup_epoch})"
            );
        }
    }

    /// The peer's current pending-probe cleanup epoch (0 when never cleaned).
    ///
    /// A pending probe is only eligible for re-insertion by an ACK handler
    /// when this value still equals the probe's stamped epoch.
    pub(super) async fn peer_probe_cleanup_epoch(&self, peer_id: &str) -> u64 {
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
    pub(super) async fn drop_pending_probes_for_socket(&self, socket_index: usize) {
        self.pending_probes
            .lock()
            .await
            .retain(|_, pending| pending.socket_index != socket_index);
        self.prune_hard_hard_probe_bindings().await;
    }

    pub(crate) async fn clear_hard_hard_pending_probe_token(&self, nonce: ProbeNonce) {
        self.hard_hard_probe_bindings.lock().await.remove(&nonce);
    }

    /// Remove pending probes owned by one exact Hard↔Hard token.  The token
    /// binding is local-only, so this remains session-scoped even when the
    /// dynamic socket entry was already removed or its token tag was lost.
    /// Pending probes on an explicitly retained Direct socket are left in the
    /// ordinary pending table but lose their Hard↔Hard ownership binding.
    pub(crate) async fn clear_hard_hard_pending_probes_for_token(
        &self,
        peer_id: &str,
        token: &str,
        preserve_socket_index: Option<usize>,
    ) {
        let token_nonces = self
            .hard_hard_probe_bindings
            .lock()
            .await
            .iter()
            .filter(|(_, bound_token)| bound_token.as_str() == token)
            .map(|(nonce, _)| *nonce)
            .collect::<HashSet<_>>();
        if token_nonces.is_empty() {
            return;
        }
        self.pending_probes.lock().await.retain(|nonce, pending| {
            pending.peer_id.as_deref() != Some(peer_id)
                || !token_nonces.contains(nonce)
                || preserve_socket_index == Some(pending.socket_index)
        });
        self.hard_hard_probe_bindings
            .lock()
            .await
            .retain(|nonce, bound_token| {
                bound_token.as_str() != token || !token_nonces.contains(nonce)
            });
    }

    pub(super) async fn prune_hard_hard_probe_bindings(&self) {
        let pending = self.pending_probes.lock().await;
        let mut bindings = self.hard_hard_probe_bindings.lock().await;
        bindings.retain(|nonce, _| pending.contains_key(nonce));
    }

    /// Number of live dedicated fresh-mapping punch sockets.
    pub async fn dynamic_socket_count(&self) -> usize {
        self.socket_state.lock().await.dynamic.len()
    }
}
