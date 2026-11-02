//! Legacy ACK matching and adoption share the original peer/epoch transaction.
//! This owner never supplies authenticated identity or encrypted validation.
use super::*;

impl UdpTransport {
    pub(super) async fn handle_legacy_probe_ack(
        &self,
        socket_index: usize,
        source: SocketAddr,
        nonce: ProbeNonce,
    ) {
        #[cfg(test)]
        self.trace_consent(nonce, ConsentStage::AckHandlerEntered);
        self.update_socket_diagnostics(socket_index, |metrics| {
            metrics.legacy_probe_acks_observed =
                metrics.legacy_probe_acks_observed.saturating_add(1)
        })
        .await;
        // Legacy ACKs have no authenticated sender identity.
        // Enter the transaction only through the peer ID stamped
        // on this exact pending nonce; an unmatched source must
        // never be allowed to learn or mutate a peer.
        let pending_peer_id = self
            .pending_probes
            .lock()
            .await
            .get(&nonce)
            .and_then(|pending| pending.peer_id.clone());
        #[cfg(test)]
        self.trace_consent(nonce, ConsentStage::PendingLookup);
        let Some(transaction_peer_id) = pending_peer_id else {
            #[cfg(test)]
            self.trace_consent(nonce, ConsentStage::NoPeerOwnedPending);
            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.legacy_probe_acks_unmatched =
                    metrics.legacy_probe_acks_unmatched.saturating_add(1)
            })
            .await;
            trace!("Ignored legacy UDP punch ACK from {source}: no peer-owned pending nonce");
            return;
        };

        // Match and every resulting mutation are one peer and
        // generation transaction. Lifecycle cleanup takes the
        // adoption lock; local generation and remote-candidate
        // writers take the epoch gate.
        let adoption = self.adoption_lock_for(&transaction_peer_id).await;
        let _adoption_guard = adoption.lock().await;
        #[cfg(test)]
        self.trace_consent(nonce, ConsentStage::AdoptionAcquired);
        let epoch_guard = self.network_epoch_gate.lock().await;
        #[cfg(test)]
        self.trace_consent(nonce, ConsentStage::EpochAcquired);
        let generation = self.peers.current_network_generation_sync();
        let remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(&transaction_peer_id)
            .await
            .unwrap_or(0);
        let cleanup_epoch = self.peer_probe_cleanup_epoch(&transaction_peer_id).await;
        let direct_commit_seq = self
            .peers
            .direct_commit_seq_sync(&transaction_peer_id)
            .unwrap_or(0);
        let (ack_match, expired_pending) = {
            let mut pending_probes = self.pending_probes.lock().await;
            let now = Instant::now();
            let pending = pending_probes.get(&nonce).cloned();
            let expired = pending
                .as_ref()
                .filter(|pending| {
                    pending.peer_id.as_deref() == Some(transaction_peer_id.as_str())
                        && legacy_ack_matches_pending(
                            pending,
                            source,
                            generation,
                            remote_candidate_epoch,
                            socket_index,
                            cleanup_epoch,
                            direct_commit_seq,
                        )
                        && pending.is_expired(now)
                })
                .cloned();
            let matched = pending
                .filter(|pending| {
                    pending.peer_id.as_deref() == Some(transaction_peer_id.as_str())
                        && legacy_ack_matches_pending(
                            pending,
                            source,
                            generation,
                            remote_candidate_epoch,
                            socket_index,
                            cleanup_epoch,
                            direct_commit_seq,
                        )
                        && !pending.is_expired(now)
                })
                .map(|pending| {
                    (
                        pending.sent_at.elapsed(),
                        pending.generation,
                        pending.peer_id.clone(),
                        pending.probe_session_id.clone(),
                        pending.local_endpoint,
                        pending.purpose,
                        pending.socket_epoch,
                        pending.cleanup_epoch,
                        pending.direct_commit_seq,
                    )
                });
            if matched.is_some() || expired.is_some() {
                pending_probes.remove(&nonce);
            }
            (matched, expired)
        };
        if let Some(expired) = expired_pending {
            #[cfg(test)]
            self.trace_consent(nonce, ConsentStage::Expired);
            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.legacy_probe_acks_unmatched =
                    metrics.legacy_probe_acks_unmatched.saturating_add(1)
            })
            .await;
            if let Some(peer_id) = expired.peer_id.as_deref() {
                self.peers
                    .record_direct_event_for_generation_with_socket(
                        peer_id,
                        expired.generation,
                        "direct_probe_ack_expired",
                        Some(source),
                        Some(socket_index),
                        Some(1),
                        None,
                        format!(
                            "ignored legacy UDP probe ACK after its terminal deadline: endpoint={} age_ms={} deadline_ms={}",
                            expired.endpoint,
                            expired.sent_at.elapsed().as_millis(),
                            expired
                                .expires_at
                                .saturating_duration_since(expired.sent_at)
                                .as_millis(),
                        ),
                    )
                    .await;
            }
            return;
        }
        // The peer identity comes from the matched pending
        // probe (never from the source address alone, which
        // would let a spoofed ACK drive endpoint learning).
        let peer_id = Some(transaction_peer_id.clone());
        if let Some(peer_id) = peer_id {
            // The whole fence -> learn -> adopt sequence runs
            // under the peer's adoption lock, and the cleanup
            // fence runs BEFORE any endpoint learning: a
            // legacy ACK must never learn an endpoint, pin a
            // socket or promote Direct after the peer was
            // cleaned (offline, PeerLeft, endpoint/public-key
            // change).
            let pending_cleanup_epoch = ack_match
                .as_ref()
                .map(|(_, _, _, _, _, _, _, epoch, _)| *epoch);
            let still_clean = match pending_cleanup_epoch {
                Some(stamped) => self.peer_probe_cleanup_epoch(&peer_id).await == stamped,
                None => true,
            };
            if !still_clean {
                #[cfg(test)]
                self.trace_consent(nonce, ConsentStage::CleanupChanged);
                debug!(
                    "Ignoring legacy ACK from {source} for peer {peer_id}: the peer was cleaned after the probe was sent"
                );
                return;
            }
            if let Some((
                latency,
                generation,
                _,
                probe_session_id,
                local_endpoint,
                purpose,
                socket_epoch,
                _,
                direct_commit_seq_at_send,
            )) = ack_match
            {
                #[cfg(test)]
                self.trace_consent(nonce, ConsentStage::Matched);
                self.update_socket_diagnostics(socket_index, |metrics| {
                    metrics.probe_acks_received += 1
                })
                .await;
                self.update_peer_probe_rx_diagnostics(
                    &peer_id,
                    generation,
                    probe_session_id.as_deref(),
                    |snapshot| {
                        snapshot.legacy_probe_acks_observed =
                            snapshot.legacy_probe_acks_observed.saturating_add(1);
                        snapshot.probe_acks_received =
                            snapshot.probe_acks_received.saturating_add(1);
                    },
                )
                .await;
                // Recheck every stamped authority immediately
                // before the first mutation.  Adoption + epoch
                // keep these values stable through the success
                // commit, closing both local-generation and
                // remote-candidate ABA races.
                let stamps_current = self.peers.current_network_generation_sync() == generation
                    && self
                        .peers
                        .current_remote_candidate_epoch(&peer_id)
                        .await
                        .unwrap_or(0)
                        == remote_candidate_epoch
                    && self.peer_probe_cleanup_epoch(&peer_id).await
                        == pending_cleanup_epoch.unwrap_or(u64::MAX)
                    && self.peers.direct_commit_seq_sync(&peer_id).unwrap_or(0)
                        == direct_commit_seq_at_send;
                if !stamps_current {
                    #[cfg(test)]
                    self.trace_consent(nonce, ConsentStage::StampsChanged);
                    trace!(
                        "Ignored legacy UDP punch ACK from {source} for peer {peer_id}: lifecycle or generation changed before adoption"
                    );
                    return;
                }
                if !self
                    .peers
                    .learn_correlated_probe_endpoint(&peer_id, source)
                    .await
                {
                    #[cfg(test)]
                    self.trace_consent(nonce, ConsentStage::EndpointRejected);
                    return;
                }
                let _affinity_adopted = self
                    .remember_peer_socket_for_generation_in_epoch(
                        &epoch_guard,
                        &peer_id,
                        socket_index,
                        generation,
                        SocketEvidence::Stamped(socket_epoch),
                    )
                    .await;
                let accepted = self
                    .peers
                    .record_direct_probe_success_with_latency_for_generation_and_local_endpoint_for_remote_epoch(
                        &peer_id,
                        source,
                        Some(latency),
                        generation,
                        local_endpoint,
                        Some(remote_candidate_epoch),
                        purpose == PendingProbePurpose::ConsentCheck,
                    )
                    .await;
                #[cfg(test)]
                self.trace_consent(
                    nonce,
                    if accepted {
                        ConsentStage::HealthCommitted
                    } else {
                        ConsentStage::HealthRejected
                    },
                );
                if accepted {
                    self.notify_peer_reflexive_observation(&peer_id, source)
                        .await;
                    // Legacy peers still need the same
                    // per-pending-probe attribution. The ACK
                    // remains only an ingress signal for the
                    // encrypted validation worker.
                    let admission = self.trigger_encrypted_validation(&peer_id, source).await;
                    self.peers
                        .count_hot_path(matched_ack_validation_observation(admission));
                    if matches!(
                        admission,
                        DirectValidationAdmission::Queued | DirectValidationAdmission::Coalesced
                    ) {
                        self.peers
                            .record_direct_event_for_generation_with_socket(
                            &peer_id,
                            generation,
                            "direct_validation_ingress_requested",
                            Some(source),
                            Some(socket_index),
                            None,
                            None,
                            format!(
                                "matched legacy probe ACK; probe_session_id={} socket_index={} local_endpoint={} rtt_ms={}; requesting bounded encrypted validation ingress",
                                probe_session_id.as_deref().unwrap_or("legacy"),
                                socket_index,
                                format_optional_endpoint(local_endpoint),
                                latency.as_millis(),
                            ),
                            )
                            .await;
                    }
                    debug!(
                        "Received UDP punch ACK from peer {peer_id} at {source} (rtt={latency:?} direct_commit_seq_at_send={direct_commit_seq_at_send})"
                    );
                } else {
                    trace!("Ignored stale UDP punch ACK from peer {peer_id} at {source}");
                }
            } else {
                self.update_socket_diagnostics(socket_index, |metrics| {
                    metrics.legacy_probe_acks_unmatched =
                        metrics.legacy_probe_acks_unmatched.saturating_add(1)
                })
                .await;
                #[cfg(test)]
                self.trace_consent(nonce, ConsentStage::Mismatch);
                trace!("Ignored stale or unmatched UDP punch ACK from {source}");
            }
        } else {
            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.legacy_probe_acks_unmatched =
                    metrics.legacy_probe_acks_unmatched.saturating_add(1)
            })
            .await;
            trace!("Received UDP punch ACK from unknown candidate {source}");
        }
    }
}
