use std::collections::VecDeque as InitiatorQueue;

/// Initiator publication retries are latency-critical evidence producers. Keep
/// them in a separate bounded cooperative lane so a roster burst of unrelated
/// STUN/HTTP work cannot occupy every general slow-work slot until the retry
/// ledger expires. This is still the existing control-event loop and the
/// existing per-peer reservation/ledger; it is only a fairness boundary.
const MAX_INITIATOR_RETRY_WORK: usize = 16;
/// A roster burst may contain more peers than the cooperative slow-work lane
/// can admit at once.  Do not silently lose the initiator handshake for the
/// peers after that boundary: retain one newest-wins entry per peer and drain
/// it whenever a slow-work slot is released.  The bound is deliberately
/// finite so a corrupt control roster cannot grow daemon memory without
/// limit; overflow is an explicit diagnostic event, never an implicit drop.
const MAX_DEFERRED_INITIATOR_HANDSHAKES: usize = 256;

fn enqueue_deferred_initiator_handshake(
    queue: &mut InitiatorQueue<control::PeerInfo>,
    peer_info: control::PeerInfo,
) -> bool {
    if let Some(existing) = queue
        .iter_mut()
        .find(|existing| existing.node_id == peer_info.node_id)
    {
        *existing = peer_info;
        return true;
    }
    if queue.len() >= MAX_DEFERRED_INITIATOR_HANDSHAKES {
        return false;
    }
    queue.push_back(peer_info);
    true
}

fn remove_deferred_initiator_handshake(
    queue: &mut InitiatorQueue<control::PeerInfo>,
    peer_id: &str,
) {
    queue.retain(|peer_info| peer_info.node_id != peer_id);
}

impl Daemon {
    /// Admit queued event-triggered initiator work after a cooperative
    /// slow-work slot becomes available.
    ///
    /// A roster burst must not silently lose the initiator handshake for peers
    /// after the global slow-work cap. This drain is newest-wins per peer,
    /// checks the current online state before starting, and leaves the
    /// per-peer reservation as the single-flight boundary for duplicates.
    fn drain_deferred_initiator_handshakes<'a>(
        &'a self,
        slow_work: &mut FuturesUnordered<ControlEventWork<'a>>,
        deferred: &mut InitiatorQueue<control::PeerInfo>,
    ) {
        // A reservation can be temporarily unavailable because this peer's
        // current handshake owner is still running.  Scan each queued peer at
        // most once per drain pass: keep blocked entries newest-wins while
        // still admitting unrelated peers behind them.  A later completion
        // pass will retry the preserved entry after the owner releases it.
        let initial_queue_len = deferred.len();
        let mut scanned = 0usize;
        while slow_work.len() < MAX_CONTROL_EVENT_SLOW_WORK && scanned < initial_queue_len {
            let Some(peer_info) = deferred.pop_front() else {
                break;
            };
            scanned = scanned.saturating_add(1);
            let peer_id = peer_info.node_id.clone();
            let current_online = self.peers.peer_session_generation_sync(&peer_id).is_some();
            if !current_online {
                self.timeline.emit(
                    "initiator_handshake_deferred_dropped",
                    None,
                    Some("peer_offline_or_removed"),
                    Some(format!("peer={peer_id}")),
                );
                continue;
            }

            if !self.should_start_initiator_handshake(&peer_info) {
                continue;
            }

            let Some(reservation) = self
                .reserve_event_initiator_handshake(&peer_id)
                .into_reservation()
            else {
                // An existing pending handshake or starting worker owns this
                // peer. Keep the newest roster update for the next completion
                // pass; dropping it here would make endpoint/incarnation
                // changes wait for an unrelated future control poll.
                let _ = enqueue_deferred_initiator_handshake(deferred, peer_info);
                continue;
            };
            self.timeline.emit(
                "initiator_handshake_deferred_admitted",
                None,
                None,
                Some(format!("peer={peer_id} queue_remaining={}", deferred.len())),
            );
            let daemon = self;
            slow_work.push(Box::pin(async move {
                daemon
                    .run_event_initiator_handshake(peer_info, reservation)
                    .await;
            }));
        }
    }

    /// Validate one already-claimed retry inside the bounded slow-work lane.
    /// In particular, the control roster snapshot may wait on its own actor;
    /// it must never stall the serial control receiver which owns ledger
    /// admission and wake processing.
    async fn run_claimed_initiator_retry(
        &self,
        identity: HandshakeRetryIdentity,
        mut reservation: HandshakeStartReservation,
    ) {
        let lifecycle_current = self.peers.current_network_generation_sync()
            == identity.network_generation
            && self
                .peers
                .peer_session_is_current_sync(&identity.peer_id, identity.peer_session_generation);
        if !lifecycle_current {
            self.pending_handshakes
                .lock()
                .cancel_reservation_if_current(&identity.peer_id, identity.reservation_owner);
            self.timeline.emit(
                "initiator_handshake_retry_cancelled",
                None,
                Some("stale_lifecycle"),
                Some(format!(
                    "peer={} owner={} generation={} peer_session_generation={} phase={} attempt={} cancellation_generation={}",
                    identity.peer_id,
                    identity.reservation_owner,
                    identity.network_generation,
                    identity.peer_session_generation.value(),
                    identity.phase.as_str(),
                    identity.attempt,
                    identity.cancellation_generation,
                )),
            );
            return;
        }

        let peer_info = self.control.peers().await.get(&identity.peer_id).cloned();
        let Some(peer_info) = peer_info else {
            if !self.schedule_initiator_retry(
                &identity.peer_id,
                &mut reservation,
                identity.phase,
                "control_snapshot_unavailable",
            ) {
                self.pending_handshakes
                    .lock()
                    .cancel_reservation_if_current(&identity.peer_id, identity.reservation_owner);
            }
            return;
        };
        if !peer_info.online || !self.should_start_initiator_handshake(&peer_info) {
            self.pending_handshakes
                .lock()
                .cancel_reservation_if_current(&identity.peer_id, identity.reservation_owner);
            return;
        }

        self.timeline.emit(
            "initiator_handshake_retry_admitted",
            None,
            None,
            Some(format!(
                "peer={} owner={} generation={} peer_session_generation={} phase={} attempt={} cancellation_generation={}",
                identity.peer_id,
                identity.reservation_owner,
                identity.network_generation,
                identity.peer_session_generation.value(),
                identity.phase.as_str(),
                identity.attempt,
                identity.cancellation_generation,
            )),
        );
        self.run_event_initiator_handshake(peer_info, reservation)
            .await;
    }

    /// Drain exact preparation/publication retries from the authoritative
    /// per-peer ledger. Records are removed only when this supervised owner
    /// claims them; a repeated watch kick merely causes another bounded scan.
    /// This coordinator performs no await: all roster/session/control work is
    /// polled as part of the existing bounded slow-work lane.
    fn drain_initiator_retry_ledger<'a>(
        &'a self,
        retry_work: &mut FuturesUnordered<ControlEventWork<'a>>,
    ) {
        self.pending_handshakes
            .lock()
            .expire_initiator_retries(Instant::now());
        while retry_work.len() < MAX_INITIATOR_RETRY_WORK {
            let claimed = self
                .pending_handshakes
                .lock()
                .claim_ready_initiator_retry(Instant::now());
            let Some((identity, reservation)) = claimed else {
                break;
            };
            self.timeline.emit(
                "initiator_handshake_retry_claimed",
                None,
                None,
                Some(format!(
                    "peer={} owner={} generation={} peer_session_generation={} phase={} attempt={} cancellation_generation={}",
                    identity.peer_id,
                    identity.reservation_owner,
                    identity.network_generation,
                    identity.peer_session_generation.value(),
                    identity.phase.as_str(),
                    identity.attempt,
                    identity.cancellation_generation,
                )),
            );
            let daemon = self;
            retry_work.push(Box::pin(async move {
                daemon
                    .run_claimed_initiator_retry(identity, reservation)
                    .await;
            }));
        }
    }
}
