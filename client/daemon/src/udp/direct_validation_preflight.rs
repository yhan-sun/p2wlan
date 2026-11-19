//! One authenticated, non-nominating probe for an already owned ordinary
//! validation request. The request expectation remains the sole owner; the
//! pending probe holds only its fenced receipt and uses the existing budget.

use super::*;

#[cfg(test)]
#[path = "tests/direct_validation_preflight.rs"]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectValidationPreflightOutcome {
    Observed,
    TimedOut,
    Skipped { reason: &'static str },
}

#[derive(Debug)]
pub(super) struct PreflightReceipt {
    validation: DirectValidationIdentity,
    socket_index: usize,
    socket: std::sync::Weak<UdpSocket>,
    completion: StdMutex<Option<oneshot::Sender<()>>>,
}

fn owns_request(
    target: DirectValidationTarget,
    expectation: &DirectValidationExpectation,
    validation: DirectValidationIdentity,
    socket_index: usize,
) -> bool {
    !target.cancelled
        && validation.owner_token == Some(target.owner_token)
        && validation.epoch.network_generation == target.generation
        && validation.epoch.peer_session_generation == target.peer_session_generation
        && validation.epoch.remote_candidate_epoch == target.remote_candidate_epoch
        && validation.owner_token == Some(expectation.owner_token)
        && validation.request_id == Some(expectation.request_id)
        && validation.epoch.network_generation == expectation.generation
        && validation.epoch.peer_session_generation == expectation.peer_session_generation
        && validation.epoch.remote_candidate_epoch == expectation.remote_candidate_epoch
        && validation.request_endpoint() == expectation.endpoint
        && expectation.endpoint.is_some()
        && expectation.socket_index == Some(socket_index)
        && expectation.hard_hard_pair.is_none()
        && expectation.lease.is_some()
        && expectation.expires_at > Instant::now()
}

impl UdpTransport {
    /// Probe the ORIGINAL request destination from its exact leased socket.
    /// An APDM NAT can then return an independently authenticated ACK from a
    /// different source port without us chasing that port into a new mapping.
    /// All waits share the caller's attempt deadline and a 150 ms local cap.
    pub(crate) async fn send_direct_validation_preflight(
        &self,
        peer_id: &str,
        validation: DirectValidationIdentity,
        prepared: &PreparedDirectValidationSend,
        deadline: tokio::time::Instant,
    ) -> DirectValidationPreflightOutcome {
        let deadline = deadline.min(tokio::time::Instant::now() + Duration::from_millis(150));
        let send_deadline = deadline.min(tokio::time::Instant::now() + Duration::from_millis(100));
        let receiver = match tokio::time::timeout_at(
            send_deadline,
            self.send_validation_preflight(peer_id, validation, prepared, send_deadline, deadline),
        )
        .await
        {
            Ok(Ok(receiver)) => receiver,
            Ok(Err(reason)) => return DirectValidationPreflightOutcome::Skipped { reason },
            Err(_) => return DirectValidationPreflightOutcome::TimedOut,
        };
        match tokio::time::timeout_at(deadline, receiver).await {
            Ok(Ok(())) => DirectValidationPreflightOutcome::Observed,
            Ok(Err(_)) => DirectValidationPreflightOutcome::Skipped {
                reason: "preflight_owner_or_probe_retired",
            },
            Err(_) => DirectValidationPreflightOutcome::TimedOut,
        }
    }

    async fn send_validation_preflight(
        &self,
        peer_id: &str,
        validation: DirectValidationIdentity,
        prepared: &PreparedDirectValidationSend,
        send_deadline: tokio::time::Instant,
        receipt_deadline: tokio::time::Instant,
    ) -> std::result::Result<oneshot::Receiver<()>, &'static str> {
        let endpoint = validation
            .request_endpoint()
            .ok_or("preflight_identity_missing")?;
        let local_node_id = self
            .local_node_id
            .as_deref()
            .ok_or("preflight_v2_unavailable")?;
        if peer_id.len() > u8::MAX as usize || local_node_id.len() > u8::MAX as usize {
            return Err("preflight_v2_unavailable");
        }
        if self.peers.peer_requires_legacy_probe(peer_id).await {
            return Err("preflight_v2_unavailable");
        }
        if self
            .peers
            .probe_key_and_session_for_peer(peer_id)
            .await
            .is_none()
        {
            return Err("preflight_v2_unavailable");
        }
        let generation = validation.epoch.network_generation;
        if self.peers.current_network_generation_sync() != generation
            || self.peers.peer_session_generation_sync(peer_id)
                != Some(validation.epoch.peer_session_generation)
        {
            return Err("preflight_owner_revoked");
        }
        self.reserve_validation_preflight(peer_id, validation, prepared)
            .await?;
        let admission = self
            .admit_outbound_connectivity_probe(peer_id, endpoint, prepared.socket_index)
            .await;
        if admission != OutboundProbeAdmission::Accepted {
            return Err(outbound_probe_admission_reason(admission));
        }
        prepared
            .socket
            .writable()
            .await
            .map_err(|_| "preflight_socket_unavailable")?;

        // Lock order agrees with cancellation/ACK: epoch -> sessions ->
        // expectations -> socket state -> pending. The outer 100 ms bound
        // covers acquisition; after the final guard no await precedes handoff.
        let _epoch = self.network_epoch_gate.lock().await;
        if self.peers.current_network_generation_sync() != generation
            || self.peers.peer_session_generation_sync(peer_id)
                != Some(validation.epoch.peer_session_generation)
            || self.peers.current_remote_candidate_epoch(peer_id).await
                != Some(validation.epoch.remote_candidate_epoch)
        {
            return Err("preflight_owner_revoked");
        }
        let send_fence = self
            .peers
            .try_snapshot_probe_send_fence(peer_id, true)
            .ok_or("preflight_opaque_session_unavailable")?;
        let (key, probe_session_id) = self
            .peers
            .probe_key_and_session_for_peer(peer_id)
            .await
            .ok_or("preflight_v2_unavailable")?;
        let opaque_mode = send_fence.opaque;
        let (bytes, nonce) = if opaque_mode {
            build_opaque_punch_packet_with_nomination(
                local_node_id,
                peer_id,
                generation,
                false,
                &key,
                &key,
            )
        } else {
            build_authenticated_punch_packet_with_nomination(
                local_node_id,
                peer_id,
                generation,
                false,
                &key,
            )
        };
        let sessions = self.direct_validation.sessions.lock().await;
        let target = sessions
            .get(peer_id)
            .map(|session| *session.target_tx.borrow())
            .ok_or("preflight_owner_revoked")?;
        let expectations = self.direct_validation.expectations.lock().await;
        let expectation = expectations.get(peer_id).ok_or("preflight_owner_revoked")?;
        if !owns_request(target, expectation, validation, prepared.socket_index) {
            return Err("preflight_owner_revoked");
        }
        let state = self.socket_state.lock().await;
        if !self.preflight_socket_is_current(&state, peer_id, generation, prepared) {
            return Err("preflight_socket_revoked");
        }
        let mut pending = self.pending_probes.lock().await;
        if self.peers.current_network_generation_sync() != generation
            || self.peers.peer_session_generation_sync(peer_id)
                != Some(validation.epoch.peer_session_generation)
            || expectation.expires_at <= Instant::now()
        {
            return Err("preflight_owner_revoked");
        }
        let now = Instant::now();
        pending.retain(|_, probe| {
            probe.sent_at.elapsed() < Duration::from_secs(60) && probe.generation == generation
        });
        if pending.contains_key(&nonce) {
            return Err("preflight_nonce_collision");
        }
        let (completion, receiver) = oneshot::channel();
        let receipt = Arc::new(PreflightReceipt {
            validation,
            socket_index: prepared.socket_index,
            socket: Arc::downgrade(&prepared.socket),
            completion: StdMutex::new(Some(completion)),
        });
        pending.insert(
            nonce,
            PendingProbe {
                validation_preflight: Some(receipt),
                sent_at: now,
                expires_at: now
                    + receipt_deadline.saturating_duration_since(tokio::time::Instant::now()),
                endpoint,
                local_endpoint: prepared.socket.local_addr().ok(),
                socket_index: prepared.socket_index,
                generation,
                remote_candidate_epoch: validation.epoch.remote_candidate_epoch,
                probe_session_id,
                peer_id: Some(peer_id.to_string()),
                purpose: PendingProbePurpose::ConnectivityCheck,
                accepts_authenticated_ack: true,
                accepts_legacy_ack: false,
                socket_epoch: state
                    .affinity
                    .get(peer_id)
                    .map(|pin| pin.epoch)
                    .unwrap_or(0),
                cleanup_epoch: state
                    .probe_cleanup_epochs
                    .get(peer_id)
                    .copied()
                    .unwrap_or(0),
                direct_commit_seq: self.peers.direct_commit_seq_sync(peer_id).unwrap_or(0),
            },
        );
        if tokio::time::Instant::now() >= send_deadline {
            pending.remove(&nonce);
            return Err("preflight_handoff_deadline_expired");
        }
        match self.peers.with_probe_send_fence(&send_fence, &bytes, || {
            prepared.socket.try_send_to(&bytes, endpoint)
        }) {
            Ok(Ok(sent)) if sent == bytes.len() => {
                self.update_socket_diagnostics_try(prepared.socket_index, |metrics| {
                    metrics.probes_sent = metrics.probes_sent.saturating_add(1);
                });
                Ok(receiver)
            }
            _ => {
                pending.remove(&nonce);
                Err("preflight_physical_send_failed")
            }
        }
    }

    // Reserve the one-shot flag before admission. Repeated/stale calls cannot
    // repeatedly debit the existing budget, including after a local failure.
    async fn reserve_validation_preflight(
        &self,
        peer_id: &str,
        validation: DirectValidationIdentity,
        prepared: &PreparedDirectValidationSend,
    ) -> std::result::Result<(), &'static str> {
        let _epoch = self.network_epoch_gate.lock().await;
        let sessions = self.direct_validation.sessions.lock().await;
        let target = sessions
            .get(peer_id)
            .map(|session| *session.target_tx.borrow())
            .ok_or("preflight_owner_revoked")?;
        let mut expectations = self.direct_validation.expectations.lock().await;
        let expectation = expectations
            .get_mut(peer_id)
            .ok_or("preflight_owner_revoked")?;
        if !owns_request(target, expectation, validation, prepared.socket_index) {
            return Err("preflight_owner_revoked");
        }
        if expectation.preflight_attempted {
            return Err("preflight_already_attempted");
        }
        let state = self.socket_state.lock().await;
        if !self.preflight_socket_is_current(
            &state,
            peer_id,
            validation.epoch.network_generation,
            prepared,
        ) {
            return Err("preflight_socket_revoked");
        }
        expectation.preflight_attempted = true;
        Ok(())
    }

    fn preflight_socket_is_current(
        &self,
        state: &SocketState,
        peer_id: &str,
        generation: u64,
        prepared: &PreparedDirectValidationSend,
    ) -> bool {
        let index = prepared.socket_index;
        if state.hard_hard_pair_modes.contains_key(&index) {
            return false;
        }
        if index == IPV6_SOCKET_INDEX {
            return self
                .ipv6_socket
                .as_ref()
                .is_some_and(|socket| Arc::ptr_eq(socket, &prepared.socket));
        }
        if index < DYNAMIC_SOCKET_INDEX_BASE {
            return self
                .active_sockets()
                .get(index)
                .is_some_and(|socket| Arc::ptr_eq(socket, &prepared.socket));
        }
        state.dynamic.get(&index).is_some_and(|entry| {
            entry.peer_id == peer_id
                && entry.network_generation == generation
                && entry.phase.is_usable()
                && entry.permits_ordinary_traffic()
                && Arc::ptr_eq(&entry.socket, &prepared.socket)
        })
    }

    /// Called only after a MAC/nonce/socket/epoch matched ACK learned its
    /// endpoint while inbound still holds the network epoch transaction.
    pub(super) async fn complete_validation_preflight_in_epoch(
        &self,
        peer_id: &str,
        pending: &PendingProbe,
    ) {
        let Some(receipt) = pending.validation_preflight.as_ref() else {
            return;
        };
        if pending.is_expired(Instant::now()) {
            return;
        }
        let complete = async {
            let identity = receipt.validation;
            if self.peers.current_network_generation_sync() != identity.epoch.network_generation
                || self.peers.peer_session_generation_sync(peer_id)
                    != Some(identity.epoch.peer_session_generation)
                || self.peers.current_remote_candidate_epoch(peer_id).await
                    != Some(identity.epoch.remote_candidate_epoch)
            {
                return;
            }
            let sessions = self.direct_validation.sessions.lock().await;
            let Some(session) = sessions.get(peer_id) else {
                return;
            };
            let target = *session.target_tx.borrow();
            let expectations = self.direct_validation.expectations.lock().await;
            let Some(expectation) = expectations.get(peer_id) else {
                return;
            };
            if !owns_request(target, expectation, identity, receipt.socket_index) {
                return;
            }
            let Some(socket) = receipt.socket.upgrade() else {
                return;
            };
            let state = self.socket_state.lock().await;
            if !self.preflight_socket_is_current(
                &state,
                peer_id,
                identity.epoch.network_generation,
                &PreparedDirectValidationSend {
                    socket_index: receipt.socket_index,
                    socket,
                },
            ) {
                return;
            }
            if pending.is_expired(Instant::now()) {
                return;
            }
            if let Some(sender) = receipt
                .completion
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
            {
                let _ = sender.send(());
            }
        };
        let _ = timeout(Duration::from_millis(100), complete).await;
    }
}
