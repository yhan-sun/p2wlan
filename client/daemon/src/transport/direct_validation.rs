use super::*;

/// Bridges the transport-instance fence with the existing authoritative
/// Direct transaction. It adds no path state: committed only survives a
/// timeout in post-commit bookkeeping so the caller can finish its owner.
struct DirectValidationAckCommitHooks<'a> {
    pair: Option<&'a mut (dyn crate::peer::DirectCommitHooks + Send)>,
    session_guard: &'a mut Option<OwnedEmitGuard>,
    committed: &'a mut bool,
}

impl crate::peer::DirectCommitHooks for DirectValidationAckCommitHooks<'_> {
    fn is_current(&self) -> bool {
        self.pair.as_ref().is_none_or(|pair| pair.is_current())
    }

    fn committed(&mut self) {
        if let Some(pair) = self.pair.as_mut() {
            pair.committed();
        }
        *self.committed = true;
    }

    fn finish(&mut self) {
        if let Some(pair) = self.pair.as_mut() {
            pair.finish();
        }
        // Every Direct/business mirror is now published. Rekey may proceed
        // before the reducer's asynchronous cleanup and observations.
        self.session_guard.take();
    }
}

impl WireGuardTransport {
    #[allow(clippy::too_many_arguments)]
    /// Handle one daemon-internal direct-validation packet after successful
    /// WireGuard decryption.
    ///
    /// Request (responder role): the initiator's encrypted request reached us
    /// through the direct UDP path.  It is validation ingress evidence only:
    /// record it, enqueue the local worker and return an idempotent ACK.  The
    /// request itself never promotes Direct or adopts socket affinity.
    ///
    /// ACK (initiator role): the peer answers our outstanding validation
    /// request.  The ACK is only trusted when its token matches the
    /// expectation the validation task registered (request id AND network
    /// generation): a stale request can never confirm a new session.  On a
    /// match the initiator promotes to Direct and consumes the expectation, so
    /// duplicate or late ACKs are no-ops.
    pub(in crate::transport) async fn handle_direct_validation_packet(
        &self,
        peers: &Arc<PeerManager>,
        udp: Option<&crate::udp::UdpTransport>,
        peer_id: &str,
        packet: &[u8],
        source: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        direct_socket: Option<Arc<tokio::net::UdpSocket>>,
        peer_session_generation: PeerSessionGeneration,
        mut session_guard: Option<OwnedEmitGuard>,
        token: crate::transport::DirectValidationToken,
    ) {
        if token.kind == DirectValidationKind::Request {
            // Requests only enqueue validation and reply. Encryption takes
            // emit again, so release the inbound fence before that path.
            drop(session_guard.take());
        }
        if let Some(udp) = udp.filter(|_| token.kind == DirectValidationKind::Request) {
            if let (Some(index), Some(source)) = (socket_index, source) {
                if !udp
                    .hh2_validation_pair_matches(peer_id, index, source)
                    .await
                {
                    return;
                }
            }
        }
        match token.kind {
            crate::transport::DirectValidationKind::Request => {
                let Some(source) = source else {
                    let generation = peers.current_network_generation().await;
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            generation,
                            crate::peer::DirectValidationEventMetadata {
                                remote_validation_owner: Some(token.owner_token),
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_request_dropped",
                            None,
                            socket_index,
                            None,
                            Some(0),
                            format!(
                                "reason_code=direct_validation_request_missing_source remote_generation={} local_generation={} request_id={} seq={}",
                                token.generation, generation, token.request_id, token.sequence
                            ),
                        )
                        .await;
                    return;
                };
                let Some(udp) = udp else {
                    // A direct-validation request without the owning UDP
                    // transport cannot be serialized with peer lifecycle
                    // cleanup or safely answered on the receiving socket.
                    let generation = peers.current_network_generation().await;
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            generation,
                            crate::peer::DirectValidationEventMetadata {
                                remote_validation_owner: Some(token.owner_token),
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_request_dropped",
                            Some(source),
                            socket_index,
                            None,
                            Some(0),
                            format!(
                                "reason_code=direct_validation_udp_transport_unavailable remote_generation={} local_generation={} request_id={} seq={}",
                                token.generation, generation, token.request_id, token.sequence
                            ),
                        )
                        .await;
                    return;
                };
                // No REMOTE network-generation comparison here: network
                // generations are PER-SIDE
                // counters (each daemon advances its own on candidate
                // refreshes), so the initiator's generation can never be
                // compared with the responder's.  The request is already
                // authenticated — it decrypted under the peer's current
                // WireGuard session — and the ACK's token is strictly
                // verified against the initiator's own expectation, which is
                // the real security boundary.  A stale request can only
                // trigger a benign idempotent ACK.

                // The request is authenticated (decrypted under the peer's
                // WireGuard session) and arrived over the direct path. Make
                // its validation ingress one transaction with PeerLeft/key
                // cleanup: adoption -> network epoch -> lifecycle re-check ->
                // generation snapshot -> scheduler enqueue.
                // The token generation is remote-local and therefore cannot
                // be compared with `local_generation`; it is echoed only for
                // the initiator's owned ACK expectation.
                // Revalidate the local peer lifecycle at the same
                // adoption -> network-epoch boundary used by lifecycle
                // cleanup.  The outer transport-session check deliberately
                // released its emit guard so this request can later acquire
                // that guard to encrypt its ACK without self-deadlocking.
                let adoption_guard = udp.lock_peer_adoption_for_direct_validation(peer_id).await;
                let epoch_gate = peers.network_epoch_gate();
                let epoch_guard = epoch_gate.lock().await;
                if !peers.peer_session_is_current_sync(peer_id, peer_session_generation) {
                    drop(epoch_guard);
                    drop(adoption_guard);
                    peers.emit_timeline(
                        "stale_session_evidence",
                        Some("direct"),
                        Some("peer_lifecycle_replaced_or_removed"),
                        Some(format!(
                            "peer={peer_id} direct_validation={:?} request_id={}",
                            token.kind, token.request_id,
                        )),
                    );
                    return;
                }

                // An authenticated request is evidence for the local
                // validation worker, not proof of the local path. Enqueue it
                // newest-wins and let the worker send our own request. This
                // keeps an inbound request from cancelling the local
                // request/ACK transaction in the R7/R8 cross-over race.
                let local_generation = peers.current_network_generation_sync();

                let _ = udp.remember_dplpmtud_ack_reverse_route(
                    peer_id,
                    local_generation,
                    peer_session_generation,
                    source,
                    local_endpoint,
                    socket_index,
                );

                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        local_generation,
                        crate::peer::DirectValidationEventMetadata {
                            remote_validation_owner: Some(token.owner_token),
                            request_id: Some(token.request_id),
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_request_received",
                        Some(source),
                        socket_index,
                        None,
                        Some(0),
                        format!(
                            "received authenticated encrypted validation request remote_generation={} local_generation={} request_id={} seq={}",
                            token.generation,
                            local_generation,
                            token.request_id,
                            token.sequence,
                        ),
                    )
                    .await;
                udp.enqueue_direct_validation_observation(crate::udp::PeerReflexiveObservation {
                    peer_id: peer_id.to_string(),
                    observed_endpoint: source,
                });
                // ACK encryption takes the per-peer WireGuard emit guard.
                // Release the UDP lifecycle transaction first to preserve the
                // canonical emit -> adoption -> epoch order used by teardown
                // and ACK evidence commits.
                drop(epoch_guard);
                drop(adoption_guard);
                info!(
                    event = "direct_validation_request_received",
                    peer_id = %peer_id,
                    remote_endpoint = %source,
                    request_id = token.request_id,
                    "received authenticated encrypted validation request request_id={}",
                    token.request_id
                );
                // Answer idempotently — also when already Direct — so the
                // initiator always gets the confirmation it needs.  The ACK
                // uses the request's own IP header with source/destination
                // swapped: no virtual IP state required.
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            local_generation,
                            crate::peer::DirectValidationEventMetadata {
                                remote_validation_owner: Some(token.owner_token),
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_send_failed",
                            Some(source),
                            socket_index,
                            None,
                            Some(0),
                            format!(
                                "reason_code=direct_validation_request_invalid_ipv4 request_id={} seq={}",
                                token.request_id, token.sequence
                            ),
                        )
                        .await;
                    return;
                };
                let ack_payload = crate::transport::build_direct_validation_payload(
                    crate::transport::DirectValidationKind::Ack,
                    token.generation,
                    token.request_id,
                    token.sequence,
                    token.owner_token,
                );
                let ack_packet = Ipv4Packet::build_icmp_echo_request(
                    ip.dst_addr(),
                    ip.src_addr(),
                    token.request_id,
                    u16::from(token.sequence),
                    &ack_payload,
                );
                let send_udp = udp.clone();
                let peer_id_owned = peer_id.to_string();
                let receive_socket_index = socket_index;
                let receive_socket = direct_socket;
                match self
                    .encrypt_and_emit_outbound_with_lock_timeout(
                        OutboundPacket {
                            room_authorization: None,
                            peer_id: peer_id_owned.clone(),
                            dst_ip: ip.src_addr().to_string(),
                            packet: ack_packet,
                            trace: None,
                        },
                        DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT,
                        move |encrypted| async move {
                            let Some(receive_socket_index) = receive_socket_index else {
                                return Err(crate::error::DaemonError::Network(
                                    "direct validation request had no receiving UDP socket index"
                                        .to_string(),
                                ));
                            };
                            if let Some(receive_socket) = receive_socket {
                                send_udp
                                    .send_direct_validation_packet_on_socket(
                                        &receive_socket,
                                        receive_socket_index,
                                        &encrypted,
                                        source,
                                    )
                                    .await
                                    .map(|_| ())
                            } else {
                                send_udp
                                    .send_packet_on_socket_index(
                                        &encrypted,
                                        receive_socket_index,
                                        source,
                                    )
                                    .await
                                    .map(|_| ())
                            }
                        },
                    )
                    .await
                {
                    Ok(BoundedEmitOutcome::Sent) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_sent",
                                Some(source),
                                socket_index,
                                None,
                                Some(1),
                                format!(
                                    "sent encrypted validation ACK request_id={} seq={}",
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        info!(
                            event = "direct_validation_ack_sent",
                            peer_id = %peer_id,
                            remote_endpoint = %source,
                            request_id = token.request_id,
                            "sent encrypted validation ACK request_id={} seq={}",
                            token.request_id,
                            token.sequence
                        );
                        debug!(
                            "Answered direct-validation request from peer {peer_id_owned} at {source} with an ACK"
                        );
                    }
                    Ok(BoundedEmitOutcome::LockTimeout) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_send_failed",
                                Some(source),
                                socket_index,
                                None,
                                Some(0),
                                format!(
                                    "reason_code=direct_validation_ack_emit_lock_timeout lock_timeout_ms={} request_id={} seq={}; ACK was not encrypted or sent",
                                    DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis(),
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        debug!(
                            "Could not answer direct-validation request from {peer_id_owned}: outbound emit lock timed out after {}ms",
                            DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis()
                        );
                    }
                    Ok(BoundedEmitOutcome::SessionUnavailable) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_send_failed",
                                Some(source),
                                socket_index,
                                None,
                                Some(0),
                                format!(
                                    "reason_code=direct_validation_ack_session_unavailable request_id={} seq={}",
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        debug!(
                            "Could not answer direct-validation request from {peer_id_owned}: WireGuard session is no longer ready"
                        );
                    }
                    Err(err) => {
                        peers
                            .record_direct_validation_event_with_metadata(
                                peer_id,
                                local_generation,
                                crate::peer::DirectValidationEventMetadata {
                                    remote_validation_owner: Some(token.owner_token),
                                    request_id: Some(token.request_id),
                                    ..crate::peer::DirectValidationEventMetadata::default()
                                },
                                "direct_validation_ack_send_failed",
                                Some(source),
                                socket_index,
                                None,
                                Some(0),
                                format!(
                                    "failed to send ACK for request_id={} seq={}: {err}",
                                    token.request_id, token.sequence
                                ),
                            )
                            .await;
                        debug!(
                            "Failed to answer direct-validation request from {peer_id_owned} at {source}: {err}"
                        );
                    }
                }
            }
            crate::transport::DirectValidationKind::Ack => {
                if session_guard.is_none() {
                    peers.emit_timeline(
                        "stale_session_evidence",
                        Some("direct"),
                        Some("direct_validation_ack_missing_instance_fence"),
                        None,
                    );
                    return;
                }
                let Some(udp) = udp else {
                    drop(session_guard.take());
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            peers.current_network_generation().await,
                            crate::peer::DirectValidationEventMetadata {
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_unmatched",
                            source,
                            socket_index,
                            None,
                            None,
                            format!(
                                "reason_code=direct_validation_ack_udp_transport_unavailable request_id={} token_generation={}",
                                token.request_id, token.generation
                            ),
                        )
                        .await;
                    return;
                };
                let Some(source) = source else {
                    drop(session_guard.take());
                    // An ACK without a direct UDP source cannot establish a
                    // path.  Keep the owned expectation alive for a real ACK
                    // rather than consuming it merely because the packet
                    // decrypted through a non-UDP transport.
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            peers.current_network_generation().await,
                            crate::peer::DirectValidationEventMetadata {
                                request_id: Some(token.request_id),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_unmatched",
                            None,
                            socket_index,
                            None,
                            None,
                            format!(
                                "reason_code=direct_validation_ack_missing_source request_id={} token_generation={}",
                                token.request_id, token.generation
                            ),
                        )
                        .await;
                    return;
                };
                // Only the critical ACK transaction holds the exact current
                // transport-instance fence. Canonical order: emit -> adoption
                // -> epoch -> socket/HH -> connection. All waits share 100ms;
                // no IO or diagnostic awaits precede the synchronous commit.
                let mut expectation = None;
                let mut rejection = None;
                let mut endpoint_authenticated = false;
                let mut validation_latency = None;
                let mut promoted = false;
                let mut affinity_adopted = false;
                let mut slow_relay_retained = false;
                let transaction = async {
                    let _adoption = udp.lock_peer_adoption_for_direct_validation(peer_id).await;
                    let epoch_gate = peers.network_epoch_gate();
                    let epoch = epoch_gate.lock().await;
                    let generation = peers.current_network_generation_sync();
                    if !peers.peer_session_is_current_sync(peer_id, peer_session_generation) {
                        return;
                    }
                    endpoint_authenticated = udp
                        .is_authenticated_direct_endpoint(peer_id, source, generation)
                        .await;
                    match udp
                        .consume_direct_validation_ack(
                            peer_id,
                            token.request_id,
                            token.generation,
                            token.owner_token,
                            generation,
                            source,
                            socket_index,
                            endpoint_authenticated,
                        )
                        .await
                    {
                        Ok(value) => expectation = Some(value),
                        Err(reason) => {
                            rejection = Some(reason);
                            return;
                        }
                    }
                    let proof = expectation
                        .as_ref()
                        .expect("ACK proof stored in this transaction");
                    validation_latency = proof.sent_at.map(|sent_at| sent_at.elapsed());
                    let latency = validation_latency;
                    let Ok(mut hh2_commit) = udp
                        .prepare_hh2_direct_commit(&epoch, peer_id, proof.hard_hard_pair.as_ref())
                        .await
                    else {
                        return;
                    };
                    let deadline = hh2_commit.as_ref().map(|commit| commit.deadline);
                    // End the borrowed hook scope before inspecting or dropping
                    // the actual HH commit guard and transport session guard.
                    let accepted = {
                        let mut hooks = DirectValidationAckCommitHooks {
                            pair: hh2_commit.as_mut().map(|commit| {
                                commit as &mut (dyn crate::peer::DirectCommitHooks + Send)
                            }),
                            session_guard: &mut session_guard,
                            committed: &mut promoted,
                        };
                        let commit = peers.record_direct_success_with_commit_hooks(
                            &epoch,
                            peer_id,
                            Some(source),
                            proof.generation,
                            local_endpoint,
                            latency,
                            Some(proof.remote_candidate_epoch),
                            Some(
                                crate::peer::DirectValidationIdentity::authenticated_ack(
                                    crate::peer::PathEpoch::new(
                                        proof.generation,
                                        proof.peer_session_generation,
                                        proof.remote_candidate_epoch,
                                    ),
                                    proof.owner_token,
                                    proof.request_id,
                                    proof.endpoint,
                                    source,
                                )
                                .with_verified_return(
                                    endpoint_authenticated && proof.endpoint != Some(source),
                                ),
                            ),
                            Some(&mut hooks),
                        );
                        if let Some(deadline) = deadline {
                            tokio::time::timeout_at(deadline, commit)
                                .await
                                .unwrap_or(false)
                        } else {
                            commit.await
                        }
                    };
                    // Legacy/already-committed exact pairs may receive an
                    // accepted no-op. A new HH pair still requires its actual
                    // synchronous hook before any socket adoption is allowed.
                    promoted |= accepted && hh2_commit.is_none();
                    drop(hh2_commit);
                    drop(session_guard.take());
                    // finish() has released emit after the authoritative
                    // mirrors. Cancellation during reducer housekeeping must
                    // neither erase that commit nor strand the validation owner.
                    if promoted {
                        if let Some(index) = socket_index {
                            affinity_adopted = udp
                                .remember_peer_socket_for_generation_in_epoch(
                                    &epoch,
                                    peer_id,
                                    index,
                                    proof.generation,
                                    crate::udp::SocketEvidence::Fresh,
                                )
                                .await;
                        }
                    }
                    slow_relay_retained = !promoted
                        && latency.is_some_and(|latency| {
                            latency.as_millis() as u64
                                >= crate::peer::SLOW_DIRECT_RELAY_VALIDATION_RTT_MS
                        })
                        && peers
                            .is_relay_peer_confirmed_for_generation(peer_id, proof.generation)
                            .await
                        && !peers
                            .is_direct_for_generation(peer_id, proof.generation)
                            .await;
                    if slow_relay_retained {
                        udp.suppress_direct_validation_for_slow_relay(peer_id, proof.generation)
                            .await;
                    }
                };
                let completed =
                    tokio::time::timeout(DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT, transaction)
                        .await
                        .is_ok();
                drop(session_guard.take());
                // This is owner-conditional and runs after every consumed ACK,
                // including timeout/prepare failure and already-committed
                // transactions. Never roll back a synchronous Direct commit.
                if let Some(proof) = expectation.as_ref() {
                    let _ = udp
                        .finish_direct_validation_session(peer_id, proof.owner_token)
                        .await;
                }
                if !completed {
                    peers.emit_timeline(
                        "session_evidence_contended",
                        Some("direct"),
                        Some("direct_validation_ack_commit_timeout"),
                        Some(format!(
                            "peer={peer_id} request_id={} committed={promoted}",
                            token.request_id
                        )),
                    );
                }
                let Some(expectation) = expectation else {
                    let reason = rejection
                        .map_or("direct_validation_ack_commit_unavailable", |reason| {
                            reason.reason_code()
                        });
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            peers.current_network_generation_sync(),
                            crate::peer::DirectValidationEventMetadata {
                                request_id: Some(token.request_id),
                                observed_ack_endpoint: Some(source),
                                ack_endpoint_authenticated: Some(endpoint_authenticated),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_unmatched",
                            Some(source),
                            socket_index,
                            None,
                            None,
                            format!(
                                "reason_code={reason} request_id={} token_generation={}",
                                token.request_id, token.generation
                            ),
                        )
                        .await;
                    return;
                };
                let validation_rtt_ms =
                    validation_latency.map(|latency| latency.as_millis() as u64);

                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        expectation.generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(expectation.owner_token),
                            request_id: Some(token.request_id),
                            expected_endpoint: expectation.endpoint,
                            observed_ack_endpoint: Some(source),
                            ack_endpoint_authenticated: Some(endpoint_authenticated),
                            validation_rtt_ms,
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_ack_received",
                        Some(source),
                        socket_index,
                        None,
                        Some(1),
                        format!(
                            "consumed encrypted validation ACK request_id={} generation={} socket_index={} expected_endpoint={} observed_endpoint={} authenticated_endpoint_drift={}",
                            token.request_id,
                            expectation.generation,
                            socket_index
                                .map_or_else(|| "none".to_string(), |index| index.to_string()),
                            expectation
                                .endpoint
                                .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            source,
                            expectation.endpoint != Some(source),
                        ),
                    )
                    .await;
                info!(
                    event = "direct_validation_ack_received",
                    peer_id = %peer_id,
                    remote_endpoint = %source,
                    request_id = token.request_id,
                    generation = expectation.generation,
                    validation_rtt_ms = ?validation_rtt_ms,
                    "consumed encrypted validation ACK request_id={}",
                    token.request_id
                );

                // A slow encrypted ACK is still useful evidence that the
                // candidate can reach the peer, but it is not a reason to
                // keep starting new validation owners while the confirmed
                // relay is healthy. The candidate-level quarantine in the
                // peer manager cannot cover peer-reflexive endpoint churn, so
                // retain a peer/generation cooldown in the shared UDP
                // validation registry before the current owner is finished.
                if slow_relay_retained {
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            expectation.generation,
                            crate::peer::DirectValidationEventMetadata {
                                local_validation_session_id: Some(expectation.owner_token),
                                request_id: Some(token.request_id),
                                expected_endpoint: expectation.endpoint,
                                observed_ack_endpoint: Some(source),
                                ack_endpoint_authenticated: Some(endpoint_authenticated),
                                validation_rtt_ms,
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_suppressed",
                            Some(source),
                            socket_index,
                            None,
                            Some(1),
                            format!(
                                "reason_code=direct_validation_slow_relay_cooldown generation={} validation_rtt_ms={} relay_retained=true",
                                expectation.generation,
                                validation_rtt_ms.unwrap_or_default()
                            ),
                        )
                        .await;
                }

                if !promoted {
                    peers
                        .record_direct_validation_event_with_metadata(
                            peer_id,
                            expectation.generation,
                            crate::peer::DirectValidationEventMetadata {
                                local_validation_session_id: Some(expectation.owner_token),
                                request_id: Some(token.request_id),
                                expected_endpoint: expectation.endpoint,
                                observed_ack_endpoint: Some(source),
                                ack_endpoint_authenticated: Some(endpoint_authenticated),
                                validation_rtt_ms,
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_not_promoted",
                            Some(source),
                            socket_index,
                            None,
                            Some(1),
                            format!(
                                "reason_code=direct_validation_promotion_rejected request_id={} generation={} expected_endpoint={} observed_endpoint={} endpoint_authenticated={endpoint_authenticated}",
                                token.request_id,
                                expectation.generation,
                                expectation
                                    .endpoint
                                    .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                                source,
                            ),
                        )
                        .await;
                    debug!(
                        "Ignored direct-validation ACK from {peer_id}: owned expectation could not promote generation {}",
                        expectation.generation
                    );
                    return;
                }

                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        expectation.generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(expectation.owner_token),
                            request_id: Some(token.request_id),
                            expected_endpoint: expectation.endpoint,
                            observed_ack_endpoint: Some(source),
                            selected_endpoint: Some(source),
                            ack_endpoint_authenticated: Some(endpoint_authenticated),
                            validation_rtt_ms,
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_promoted",
                        Some(source),
                        socket_index,
                        None,
                        Some(1),
                        format!(
                            "promoted after owned request/ACK request_id={} generation={} socket_index={} expected_endpoint={} observed_endpoint={} local_endpoint={} authenticated_endpoint_drift={} affinity_adopted={affinity_adopted}",
                            token.request_id,
                            expectation.generation,
                            socket_index.map_or_else(|| "none".to_string(), |index| index.to_string()),
                            expectation
                                .endpoint
                                .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            source,
                            local_endpoint.map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            expectation.endpoint != Some(source),
                        ),
                    )
                    .await;
                info!(
                    event = "direct_validation_promoted",
                    peer_id = %peer_id,
                    remote_endpoint = %source,
                    request_id = token.request_id,
                    generation = expectation.generation,
                    "promoted after owned request/ACK request_id={}",
                    token.request_id
                );
                peers.emit_timeline(
                    "direct_promoted",
                    Some("direct"),
                    None,
                    Some(format!(
                        "peer={peer_id} endpoint={source} generation={} request_id={:?}",
                        expectation.generation, token.request_id
                    )),
                );
                peers
                    .record_direct_validation_event_with_metadata(
                        peer_id,
                        expectation.generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(expectation.owner_token),
                            request_id: Some(token.request_id),
                            expected_endpoint: expectation.endpoint,
                            observed_ack_endpoint: Some(source),
                            selected_endpoint: Some(source),
                            ack_endpoint_authenticated: Some(endpoint_authenticated),
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_path_promoted",
                        Some(source),
                        socket_index,
                        None,
                        Some(1),
                        format!(
                            "selected endpoint after owned validation ACK request_id={} expected_endpoint={} observed_ack_endpoint={} selected_endpoint={} affinity_adopted={affinity_adopted}",
                            token.request_id,
                            expectation
                                .endpoint
                                .map_or_else(|| "none".to_string(), |endpoint| endpoint.to_string()),
                            source,
                            source,
                        ),
                    )
                    .await;
                debug!(
                    "Direct UDP path confirmed for peer {peer_id} at {source} by validation ACK"
                );
            }
        }
    }
}
