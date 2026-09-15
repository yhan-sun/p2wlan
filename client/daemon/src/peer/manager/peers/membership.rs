impl PeerManager {
    /// Update a peer's connection state.
    pub async fn update_state(&self, node_id: &str, state: ConnectionState) {
        let updated = {
            let mut conns = self.connections.write().await;
            if let Some(conn) = conns.get_mut(node_id) {
                conn.transition(state);
                true
            } else {
                false
            }
        };
        if updated
            && !matches!(
                state,
                ConnectionState::Relay | ConnectionState::FallbackToRelay
            )
        {
            self.cancel_relay_backoff_heartbeat(node_id);
        }
    }

    /// Transition connection state only for the exact online peer lifecycle
    /// that admitted delayed handshake work. The epoch gate makes the
    /// generation check and connection mutation one commit, so a same-node
    /// leave/rejoin cannot receive the old task's state transition.
    pub(crate) async fn update_state_if_peer_session_current(
        &self,
        node_id: &str,
        expected: PeerSessionGeneration,
        state: ConnectionState,
    ) -> bool {
        let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
        if !self.peer_session_is_current_sync(node_id, expected) {
            return false;
        }
        let updated = {
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if !conn.online || conn.state == ConnectionState::Closed {
                return false;
            }
            conn.transition(state);
            true
        };
        drop(conns);
        drop(_epoch_guard);
        if updated
            && !matches!(
                state,
                ConnectionState::Relay | ConnectionState::FallbackToRelay
            )
        {
            self.cancel_relay_backoff_heartbeat(node_id);
        }
        updated
    }

    /// Atomically re-check the state observed before an asynchronous punch
    /// setup and, if it is still current, enter HolePunching.  The caller
    /// must not make this decision from a cloned `PeerConnection`: Direct
    /// promotion may have committed while candidate refresh or HTTP work was
    /// in flight.
    pub(crate) async fn begin_hole_punch_if_current(
        &self,
        node_id: &str,
        observed_generation: u64,
        observed_commit_seq: Option<u64>,
    ) -> bool {
        let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
        self.begin_hole_punch_if_current_locked(
            node_id,
            observed_generation,
            observed_commit_seq,
            &mut conns,
        ) == HolePunchStartOutcome::Started
    }

    /// Try to commit punch preparation without entering either fair lock
    /// queue. Cooperative candidate work must not leave a granted-but-unpolled
    /// connection waiter ahead of an inline PeerUpdated commit.
    pub(crate) fn try_begin_hole_punch_if_current(
        &self,
        node_id: &str,
        observed_generation: u64,
        observed_commit_seq: Option<u64>,
    ) -> HolePunchStartOutcome {
        let epoch_guard = match self.network_epoch_gate.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                #[cfg(test)]
                self.notify_candidate_postprocess_lock_wait_for_test();
                return HolePunchStartOutcome::ContendedEpoch;
            }
        };
        let mut conns = match self.connections.try_write() {
            Ok(guard) => guard,
            Err(_) => {
                drop(epoch_guard);
                #[cfg(test)]
                self.notify_candidate_postprocess_lock_wait_for_test();
                return HolePunchStartOutcome::ContendedConnections;
            }
        };
        self.begin_hole_punch_if_current_locked(
            node_id,
            observed_generation,
            observed_commit_seq,
            &mut conns,
        )
    }

    fn begin_hole_punch_if_current_locked(
        &self,
        node_id: &str,
        observed_generation: u64,
        observed_commit_seq: Option<u64>,
        conns: &mut HashMap<String, PeerConnection>,
    ) -> HolePunchStartOutcome {
        if self.current_network_generation_sync() != observed_generation
            || self.direct_commit_seq_sync(node_id) != observed_commit_seq
        {
            return HolePunchStartOutcome::Stale;
        }
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return HolePunchStartOutcome::PeerMissing;
        };
        let Some(conn) = conns.get_mut(node_id) else {
            return HolePunchStartOutcome::PeerMissing;
        };
        if conn.state == ConnectionState::Direct && conn.direct_is_healthy_confirmed() {
            return HolePunchStartOutcome::HealthyDirect;
        }
        let epoch = PathEpoch::new(
            observed_generation,
            peer_session_generation,
            conn.remote_candidate_epoch(),
        );
        let attempt = DirectAttemptNumber(observed_commit_seq.unwrap_or_default());
        let event = if attempt.0 == 0 {
            PathEvent::DirectProbeStarted { epoch, attempt }
        } else {
            PathEvent::DirectRetryScheduled { epoch, attempt }
        };
        if conn.commit_path_transition(event, |_| {}).accepted() {
            HolePunchStartOutcome::Started
        } else {
            HolePunchStartOutcome::Stale
        }
    }
}
