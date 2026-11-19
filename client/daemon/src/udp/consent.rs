impl UdpTransport {
    /// Periodically refresh direct UDP NAT mappings.
    pub async fn run_keepalives(self, keepalive_interval: Duration) {
        if keepalive_interval.is_zero() {
            return;
        }

        let mut ticker = interval(keepalive_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;

            self.run_keepalive_round(DIRECT_KEEPALIVE_ACK_TIMEOUT).await;
        }
    }

    async fn run_keepalive_round(&self, ack_timeout: Duration) {
        let targets = self.peers.direct_consent_targets().await;
        let mut recheck = Vec::new();
        self.probe_consent_targets(targets, ack_timeout, Some(&mut recheck))
            .await;
        if !recheck.is_empty() {
            self.probe_consent_targets(recheck, ack_timeout, None).await;
        }
    }

    async fn probe_consent_targets(
        &self,
        targets: Vec<(String, crate::peer::DirectConsentPath)>,
        ack_timeout: Duration,
        mut recheck: Option<&mut Vec<(String, crate::peer::DirectConsentPath)>>,
    ) {
        let mut sent = Vec::new();
        for (peer_id, target) in targets {
            if recheck.is_none() && !self.peers.consent_recheck_due(&peer_id, target).await {
                continue;
            }
            let endpoint = target.path.endpoint;
            // Consent belongs to the selected pair, even if received traffic has
            // since moved the peer's probe affinity to another local socket.
            let probe = if let Some(local) = target.local_endpoint {
                let Some((index, socket, _lease)) = self
                    .resolve_committed_direct_socket_with_lease(
                        &peer_id,
                        local,
                        target.path.generation,
                    )
                    .await
                else {
                    continue;
                };
                self.send_probe_on_socket_result(
                    index,
                    socket,
                    Some(&peer_id),
                    endpoint,
                    false,
                    PendingProbePurpose::ConsentCheck,
                )
                .await
                .map(|result| result.nonce)
            } else {
                let index = self.socket_index_for_peer(Some(&peer_id)).await;
                self.send_probe_from_socket_with_nomination(
                    index,
                    Some(&peer_id),
                    endpoint,
                    false,
                    PendingProbePurpose::ConsentCheck,
                )
                .await
            };
            match probe {
                Ok(nonce) => {
                    #[cfg(test)]
                    self.trace_consent(nonce, ConsentStage::SendReturned);
                    let local_endpoint = self
                        .pending_probes
                        .lock()
                        .await
                        .get(&nonce)
                        .and_then(|pending| pending.local_endpoint);
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "consent_check_sent",
                            Some(endpoint),
                            Some(1),
                            Some(1),
                            format!(
                                "sent direct UDP consent check to {endpoint} local_endpoint={}",
                                format_optional_endpoint(local_endpoint)
                            ),
                        )
                        .await;
                    trace!("Sent direct UDP keepalive to peer {peer_id} at {endpoint}");
                    sent.push((peer_id, target, nonce));
                }
                Err(err) => {
                    self.peers
                        .record_direct_failure_for_active_path_snapshot(
                            &peer_id,
                            target.path,
                            REASON_DIRECT_SEND_FAILED,
                            format!("direct keepalive to {endpoint} failed: {err}"),
                            None,
                        )
                        .await;
                    debug!(
                        "Failed to send direct UDP keepalive to peer {peer_id} at {endpoint}: {err}"
                    );
                }
            }
        }

        if sent.is_empty() {
            return;
        }

        sleep(ack_timeout).await;
        for (peer_id, target, nonce) in sent {
            let endpoint = target.path.endpoint;
            let unanswered = self.pending_probes.lock().await.remove(&nonce);
            #[cfg(test)]
            self.trace_consent(
                nonce,
                if unanswered.is_some() {
                    ConsentStage::RoundRemovedPending
                } else {
                    ConsentStage::RoundPendingAbsent
                },
            );
            let Some(pending) = unanswered else {
                continue;
            };
            if pending.peer_id.as_deref() != Some(peer_id.as_str())
                || pending.endpoint != endpoint
                || pending.generation != target.path.generation
                || pending.remote_candidate_epoch != target.remote_candidate_epoch
                || pending.direct_commit_seq != target.path.direct_commit_seq
            {
                continue;
            }
            if pending.purpose == PendingProbePurpose::ConsentCheck {
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "consent_timeout",
                        Some(endpoint),
                        Some(1),
                        None,
                        format!(
                            "direct UDP consent ACK timed out for {endpoint} local_endpoint={}",
                            format_optional_endpoint(pending.local_endpoint)
                        ),
                    )
                    .await;
            }

            if self
                .peers
                .record_direct_consent_timeout(&peer_id, target, pending.local_endpoint)
                .await
            {
                debug!("Direct UDP keepalive ACK timed out for peer {peer_id} at {endpoint}");
                if let Some(pending) = recheck.as_mut() {
                    if self.peers.consent_recheck_due(&peer_id, target).await {
                        pending.push((peer_id, target));
                    }
                }
            }
        }
    }
}
