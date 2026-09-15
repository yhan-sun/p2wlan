use super::{
    debug, info, Arc, Instant, Ipv4Packet, OutboundPacket, PathCommitIngress, PeerManager,
    RelayProbeIngress, RelayTransport, RwLock, WireGuardTransport,
};

impl WireGuardTransport {
    pub(super) fn handle_relay_probe_ack(
        &self,
        peers: &Arc<PeerManager>,
        probe: RelayProbeIngress<'_>,
    ) {
        let confirmed = peers.consume_relay_probe_ack_with_transport_for_session(
            probe.peer_id,
            probe.token,
            probe.relay_endpoint,
            probe.relay_connection_id,
            probe.wireguard_session_instance.unwrap_or(0),
        );
        if !confirmed {
            debug!(
                peer_id = %probe.peer_id,
                "relay probe ACK from {} did not match a fresh outstanding expectation, or arrived over a different relay (or was already consumed)",
                probe.peer_id,
            );
        }
    }

    pub(super) fn handle_path_commit_ack(
        &self,
        peers: &Arc<PeerManager>,
        probe: PathCommitIngress<'_>,
    ) {
        let outcome = peers.try_consume_path_commit_ack_with_transport(
            probe.peer_id,
            probe.token,
            probe.relay_endpoint,
            probe.relay_connection_id,
        );
        if matches!(
            outcome,
            crate::peer::PathCommitCommitOutcome::ContendedEpoch
                | crate::peer::PathCommitCommitOutcome::ContendedConnections
        ) {
            peers.emit_timeline_first(
                probe.peer_id,
                probe.token.generation,
                "path_commit_ack_contended",
                Some("relay"),
                Some(match outcome {
                    crate::peer::PathCommitCommitOutcome::ContendedEpoch => "network_epoch_busy",
                    crate::peer::PathCommitCommitOutcome::ContendedConnections => {
                        "fair_rwlock_writer_unavailable"
                    }
                    _ => unreachable!(),
                }),
                Some(format!(
                    "peer={} generation={} relay_endpoint={} relay_connection_id={:?} queued_writer=false expectation_retained=true",
                    probe.peer_id,
                    probe.token.generation,
                    probe.relay_endpoint,
                    probe.relay_connection_id,
                )),
            );
        } else if matches!(
            outcome,
            crate::peer::PathCommitCommitOutcome::RejectedLifecycle
        ) {
            debug!(
                peer_id = %probe.peer_id,
                "path-commit ACK from {} did not match a fresh outstanding expectation, or arrived over a different relay (or was already consumed)",
                probe.peer_id,
            );
        }
    }

    /// Handle one forced-relay path-probe / path-ack packet after successful
    /// WireGuard decryption and a confirmed relay ingress (`relay_endpoint` is
    /// `Some` at the call site).
    ///
    /// Request (responder role): the initiator's encrypted probe reached us
    /// through the relay.  Answer idempotently over the SAME relay transport
    /// (never the path selector) with the mirrored token, so the initiator can
    /// confirm the relay path.  The request itself never changes local path
    /// state.
    ///
    /// ACK (initiator role): the peer answers our outstanding forced-relay
    /// probe.  The ACK is trusted only when its token mirrors the expectation
    /// the probe loop registered (request id AND network generation AND owner
    /// token) AND the ACK arrived over the relay.  On a match the peer manager
    /// sets RelayPeerConfirmed and consumes the expectation, so duplicate or
    /// late ACKs are no-ops.
    pub(super) async fn handle_relay_probe_packet(
        &self,
        peers: &Arc<PeerManager>,
        relay_transport: Option<&Arc<RwLock<Option<RelayTransport>>>>,
        probe: RelayProbeIngress<'_>,
    ) {
        let RelayProbeIngress {
            peer_id,
            packet,
            relay_endpoint,
            relay_connection_id,
            wireguard_session_instance,
            token,
        } = probe;
        if peers.peer_session_generation_sync(peer_id).is_none() {
            debug!(
                peer_id = %peer_id,
                "ignored relay probe for offline or closed peer {peer_id}"
            );
            return;
        }
        match token.kind {
            crate::relay_probe::RelayProbeKind::Request => {
                // ACK packets were already bound to the current Relay slot at
                // the decrypt boundary and retain the session evidence guard;
                // only the request branch may await this shared slot read.
                if let Some(relay_transport) = relay_transport {
                    let current_connection_id = relay_transport
                        .read()
                        .await
                        .as_ref()
                        .map(RelayTransport::connection_id);
                    if relay_connection_id != current_connection_id {
                        peers.emit_timeline(
                            "relay_probe_packet_stale",
                            Some("relay"),
                            Some("relay_transport_replaced"),
                            Some(format!(
                                "peer={peer_id} relay_endpoint={relay_endpoint} packet_connection_id={relay_connection_id:?} current_connection_id={current_connection_id:?}"
                            )),
                        );
                        return;
                    }
                }
                let ack_started = Instant::now();
                peers.emit_timeline_first(
                    peer_id,
                    token.generation,
                    "relay_probe_ack_encrypt_started",
                    Some("relay"),
                    None,
                    Some(format!(
                        "peer={peer_id} generation={} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?}",
                        token.generation
                    )),
                );
                // Without a live relay transport there is nothing to answer
                // over; drop silently (the initiator retries its probe).
                let Some(relay_transport) = relay_transport else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored relay probe request from {peer_id}: no relay transport to answer on"
                    );
                    return;
                };
                let Some(relay) = relay_transport.read().await.clone() else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored relay probe request from {peer_id}: relay slot is empty"
                    );
                    return;
                };
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    return;
                };
                // Answer with the request's own IP header, source/destination
                // swapped; the token mirrors the request exactly.  Sending the
                // ACK over the relay (forced, not the path selector) is what
                // lets the initiator confirm the real relay ingress.
                let ack_payload = crate::relay_probe::build_relay_probe_payload(
                    crate::relay_probe::RelayProbeKind::Ack,
                    token.generation,
                    token.request_id,
                    token.owner_token,
                );
                let ack_packet = Ipv4Packet::build_icmp_echo_request(
                    ip.dst_addr(),
                    ip.src_addr(),
                    token.request_id,
                    1,
                    &ack_payload,
                );
                let relay_send = relay.clone();
                match self
                    .encrypt_and_emit_outbound(
                        OutboundPacket {
                            room_authorization: None,
                            peer_id: peer_id.to_string(),
                            dst_ip: ip.src_addr().to_string(),
                            packet: ack_packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            relay_send.send_packet(&encrypted).await.map(|_| ())
                        },
                    )
                    .await
                {
                    Ok(true) => {
                        debug!(
                            event = "relay_probe_ack_sent",
                            peer_id = %peer_id,
                            relay_endpoint = %relay_endpoint,
                            request_id = token.request_id,
                            "relay_probe_ack_sent peer_id={peer_id} relay_endpoint={relay_endpoint} request_id={}",
                            token.request_id,
                        );
                        peers.emit_timeline_first(
                            peer_id,
                            token.generation,
                            "relay_probe_ack_sent",
                            Some("relay"),
                            None,
                            Some(format!(
                                "peer={peer_id} generation={} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} encrypt_and_send_us={}",
                                token.generation,
                                ack_started.elapsed().as_micros()
                            )),
                        );
                    }
                    Ok(false) => {
                        debug!(
                            "Could not answer relay probe from {peer_id}: WireGuard session is no longer ready"
                        );
                        peers.emit_timeline_first(
                            peer_id,
                            token.generation,
                            "relay_probe_ack_send_deferred",
                            Some("relay"),
                            Some("session_or_emit_unavailable"),
                            Some(format!(
                                "peer={peer_id} generation={} relay_connection_id={relay_connection_id:?} elapsed_us={}",
                                token.generation,
                                ack_started.elapsed().as_micros()
                            )),
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to answer relay probe from {peer_id} over {relay_endpoint}: {err}"
                        );
                        peers.emit_timeline_first(
                            peer_id,
                            token.generation,
                            "relay_probe_ack_send_failed",
                            Some("relay"),
                            Some("relay_send_error"),
                            Some(format!(
                                "peer={peer_id} generation={} relay_connection_id={relay_connection_id:?} elapsed_us={}",
                                token.generation,
                                ack_started.elapsed().as_micros()
                            )),
                        );
                    }
                }
            }
            crate::relay_probe::RelayProbeKind::Ack => {
                self.handle_relay_probe_ack(
                    peers,
                    RelayProbeIngress {
                        peer_id,
                        packet,
                        relay_endpoint,
                        relay_connection_id,
                        wireguard_session_instance,
                        token,
                    },
                );
            }
        }
    }

    /// Handle one inbound synthetic path-commit packet (request or ack).
    ///
    /// Mirrors [`Self::handle_relay_probe_packet`]: a request is answered
    /// idempotently over the same relay, and an ack is verified against the
    /// outstanding expectation before it commits relay-first business evidence
    /// for one-directional traffic.  A relay renewal rejects this reader the
    /// same way, so a stale transport can neither answer nor consume.
    pub(super) async fn handle_path_commit_packet(
        &self,
        peers: &Arc<PeerManager>,
        relay_transport: Option<&Arc<RwLock<Option<RelayTransport>>>>,
        probe: PathCommitIngress<'_>,
    ) {
        let PathCommitIngress {
            peer_id,
            packet,
            relay_endpoint,
            relay_connection_id,
            token,
        } = probe;
        if peers.peer_session_generation_sync(peer_id).is_none() {
            debug!(
                peer_id = %peer_id,
                "ignored path-commit packet for offline or closed peer {peer_id}"
            );
            return;
        }
        match token.kind {
            crate::path_commit::PathCommitKind::Request => {
                if let Some(relay_transport) = relay_transport {
                    let current_connection_id = relay_transport
                        .read()
                        .await
                        .as_ref()
                        .map(RelayTransport::connection_id);
                    if relay_connection_id != current_connection_id {
                        peers.emit_timeline(
                            "path_commit_packet_stale",
                            Some("relay"),
                            Some("relay_transport_replaced"),
                            Some(format!(
                                "peer={peer_id} relay_endpoint={relay_endpoint} packet_connection_id={relay_connection_id:?} current_connection_id={current_connection_id:?}"
                            )),
                        );
                        return;
                    }
                }
                let Some(relay_transport) = relay_transport else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored path-commit request from {peer_id}: no relay transport to answer on"
                    );
                    return;
                };
                let Some(relay) = relay_transport.read().await.clone() else {
                    debug!(
                        peer_id = %peer_id,
                        "ignored path-commit request from {peer_id}: relay slot is empty"
                    );
                    return;
                };
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    return;
                };
                let ack_payload = crate::path_commit::build_path_commit_payload(
                    crate::path_commit::PathCommitKind::Ack,
                    token.generation,
                    token.request_id,
                    token.owner_token,
                );
                let ack_packet = Ipv4Packet::build_icmp_echo_request(
                    ip.dst_addr(),
                    ip.src_addr(),
                    token.request_id,
                    1,
                    &ack_payload,
                );
                let relay_send = relay.clone();
                match self
                    .encrypt_and_emit_outbound(
                        OutboundPacket {
                            room_authorization: None,
                            peer_id: peer_id.to_string(),
                            dst_ip: ip.src_addr().to_string(),
                            packet: ack_packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            relay_send.send_packet(&encrypted).await.map(|_| ())
                        },
                    )
                    .await
                {
                    Ok(true) => {
                        info!(
                            event = "path_commit_ack_sent",
                            peer_id = %peer_id,
                            relay_endpoint = %relay_endpoint,
                            request_id = token.request_id,
                            "path_commit_ack_sent peer_id={peer_id} relay_endpoint={relay_endpoint} request_id={}",
                            token.request_id,
                        );
                    }
                    Ok(false) => {
                        debug!(
                            "Could not answer path-commit from {peer_id}: WireGuard session is no longer ready"
                        );
                    }
                    Err(err) => {
                        debug!(
                            "Failed to answer path-commit from {peer_id} over {relay_endpoint}: {err}"
                        );
                    }
                }
            }
            crate::path_commit::PathCommitKind::Ack => {
                self.handle_path_commit_ack(
                    peers,
                    PathCommitIngress {
                        peer_id,
                        packet,
                        relay_endpoint,
                        relay_connection_id,
                        token,
                    },
                );
            }
        }
    }
}
