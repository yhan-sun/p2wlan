impl PeerManager {
    /// Observe whether a queued business packet may attempt preparation in
    /// the current generation. Actual counter allocation and handoff revalidate
    /// their original epoch, path, session, and room fences. A probe-only
    /// Direct ACK remains subject to relay-first startup admission. A current
    /// encrypted-confirmed Selected Direct pair is authoritative and is
    /// admitted immediately; Relay remains available as its warm standby.
    /// The predicate is intentionally evaluated from one connection snapshot
    /// so queue admission cannot observe Direct and relay confirmation from
    /// different generations.
    pub async fn is_data_path_admitted_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        relay_available: bool,
    ) -> bool {
        self.queued_data_path_admitted(node_id, generation, relay_available, false)
            .await
    }

    pub(crate) async fn queued_data_path_admitted(
        &self,
        node_id: &str,
        generation: u64,
        relay_available: bool,
        live_writer: bool,
    ) -> bool {
        // A stable RelayOnly queue check changes no connection state. Read
        // that exact canonical connection without competing with original
        // packet observation for the epoch mutex. This result is only a
        // scheduling hint; encryption and physical/final commits still take
        // their original authoritative fences after every async boundary.
        if relay_available
            && self.config.relay.effective_path_policy(true) == crate::config::PathPolicy::RelayOnly
        {
            let conns = self.connections.read().await;
            if generation == self.current_network_generation_sync()
                && conns.get(node_id).is_some_and(|conn| {
                    conn.online
                        && conn.state != ConnectionState::Closed
                        && conn.relay_first.gate_generation == Some(generation)
                        && !conn.path_state_machine.direct_first_configured()
                        && conn.relay_confirmed_at.is_some()
                        && conn.relay_confirmed_generation == Some(generation)
                        && conn
                            .relay_confirmed_endpoint
                            .as_deref()
                            .is_some_and(|endpoint| !endpoint.is_empty())
                })
            {
                return true;
            }
        }
        // A settled Direct scheduling check also has no state to commit.
        // Read the canonical connection, without joining the epoch writer
        // queue. This grants neither a counter nor a physical/native permit;
        // the actual preparation and final transaction revalidate all fences.
        {
            let conns = self.connections.read().await;
            if generation == self.current_network_generation_sync()
                && conns.get(node_id).is_some_and(|conn| {
                    conn.online
                        && conn.state != ConnectionState::Closed
                        && (!(relay_available || self.relay_first_required())
                            || conn.relay_first.gate_generation == Some(generation))
                        && !conn.direct_first_pending()
                        && conn.path_state_machine.direct_first_deadline().is_none()
                        && (conn.has_current_authoritative_direct(generation)
                            || conn.is_on_link_direct_for_generation(generation))
                })
            {
                return true;
            }
        }
        // Release the reader before the unchanged epoch -> writer fallback.
        let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
        if generation != self.current_network_generation_sync() {
            return false;
        }
        self.is_data_path_admitted_for_generation_with_conns(
            &mut conns,
            node_id,
            generation,
            relay_available,
            live_writer,
        )
    }

    fn is_data_path_admitted_for_generation_with_conns(
        &self,
        conns: &mut HashMap<String, PeerConnection>,
        node_id: &str,
        generation: u64,
        relay_available: bool,
        live_writer: bool,
    ) -> bool {
        conns
            .get_mut(node_id)
            .map(|conn| {
                if (relay_available || self.relay_first_required())
                    && conn.relay_first.gate_generation != Some(generation)
                {
                    conn.relay_first.gate_generation = Some(generation);
                    conn.relay_first.gate_started_at = Some(Instant::now());
                }
                if !conn.online || conn.state == ConnectionState::Closed {
                    return false;
                }
                conn.advance_direct_first_deadline(generation);
                if conn.has_current_authoritative_direct(generation) {
                    return true;
                }
                if conn.is_on_link_direct_for_generation(generation) {
                    return true;
                }
                let relay_confirmed =
                    relay_available && conn.relay_peer_confirmed_for_generation(generation);
                if conn.direct_first_pending() {
                    if live_writer
                        && relay_confirmed
                        && self.config.relay.effective_path_policy(true)
                            == crate::config::PathPolicy::Adaptive
                    {
                        if let Some(epoch) = conn.path_state_machine.current_epoch() {
                            let last_direct_progress = conn
                                .candidate_pairs
                                .iter()
                                .filter(|pair| {
                                    pair.local_generation == generation
                                        && pair.remote_candidate_epoch
                                            == epoch.remote_candidate_epoch
                                })
                                .filter_map(|pair| pair.last_success_at)
                                .max();
                            let now = Instant::now();
                            let grace = path_state_machine::ADAPTIVE_DIRECT_GRACE;
                            let ready =
                                conn.path_state_machine.direct_first_deadline().is_some_and(
                                    |end| {
                                        now.saturating_duration_since(end - DIRECT_FIRST_WINDOW)
                                            >= grace
                                    },
                                ) && last_direct_progress
                                    .is_none_or(|at| now.saturating_duration_since(at) >= grace);
                            if ready {
                                conn.commit_path_transition(
                                    PathEvent::QueuedRelayRequested {
                                        epoch,
                                        now,
                                        last_direct_progress,
                                    },
                                    |_| {},
                                );
                            }
                        }
                    }
                    if conn.direct_first_pending() {
                        return false;
                    }
                }
                if relay_confirmed {
                    return true;
                }
                if conn.relay_first_confirmation_pending(generation, relay_available) {
                    return false;
                }
                conn.state == ConnectionState::Direct && conn.direct_generation == generation
            })
            .unwrap_or(false)
    }
}
