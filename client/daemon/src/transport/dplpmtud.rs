use super::{
    debug, dplpmtud_ack_destination, Arc, BoundedEmitOutcome, DaemonError, Ipv4Packet,
    OutboundPacket, PeerManager, PeerSessionGeneration, SocketAddr, WireGuardTransport,
    DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT,
};

impl WireGuardTransport {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_dplpmtud_packet(
        &self,
        peers: &Arc<PeerManager>,
        udp: &crate::udp::UdpTransport,
        peer_id: &str,
        packet: &[u8],
        received_udp_datagram_size: usize,
        source: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
        socket_index: Option<usize>,
        direct_socket: Option<Arc<tokio::net::UdpSocket>>,
        peer_session_generation: PeerSessionGeneration,
        control: crate::dplpmtud::DplpmtudControlPacket,
    ) {
        let token = control.token;
        match control.kind {
            crate::dplpmtud::DplpmtudControlKind::Probe => {
                let (Some(source), Some(local_endpoint), Some(socket_index)) =
                    (source, local_endpoint, socket_index)
                else {
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("probe_ingress_identity_incomplete"),
                        Some(format!("peer={peer_id}")),
                    );
                    return;
                };
                if received_udp_datagram_size != token.candidate_udp_datagram_size.0 as usize
                    || crate::dplpmtud::OuterIpFamily::from_ip(source.ip()) != token.outer_ip_family
                {
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("probe_size_or_family_mismatch"),
                        Some(format!(
                            "peer={peer_id} received_udp_datagram_size={received_udp_datagram_size} claimed_udp_datagram_size={} source={source}",
                            token.candidate_udp_datagram_size.0,
                        )),
                    );
                    return;
                }
                if !udp
                    .dplpmtud_runtime()
                    .admit_probe_response(peer_id, tokio::time::Instant::now())
                {
                    peers.emit_timeline(
                        "dplpmtud_probe_send_failed",
                        Some("direct"),
                        Some("probe_response_rate_limited"),
                        Some(format!(
                            "peer={peer_id} sequence={} candidate_udp_datagram_size={}",
                            token.sequence, token.candidate_udp_datagram_size.0,
                        )),
                    );
                    return;
                }
                let Ok(ip) = Ipv4Packet::new(packet) else {
                    return;
                };
                let ack_packet =
                    crate::dplpmtud::build_ack_inner_packet(ip.dst_addr(), ip.src_addr(), token);
                let current_response_path = udp
                    .dplpmtud_runtime()
                    .path_identity(peer_id)
                    .filter(|identity| peers.dplpmtud_path_is_current_sync(identity));
                let authenticated_reverse_endpoint = udp.dplpmtud_ack_reverse_endpoint(
                    peer_id,
                    peer_session_generation,
                    local_endpoint,
                    socket_index,
                );
                let ack_destination = dplpmtud_ack_destination(
                    current_response_path.as_ref(),
                    authenticated_reverse_endpoint,
                    udp.transport_instance_id(),
                    source,
                    local_endpoint,
                    socket_index,
                );
                let publication_owner = udp.inbound_publication_owner();
                let send_udp = udp.clone();
                let send_peers = peers.clone();
                let peer_id_owned = peer_id.to_string();
                let receive_socket = direct_socket;
                let result = self
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
                            if encrypted.wire_bytes.len() > received_udp_datagram_size {
                                return Err(DaemonError::Network(format!(
                                    "DPLPMTUD ACK amplification refused: ack={} probe={received_udp_datagram_size}",
                                    encrypted.wire_bytes.len(),
                                )));
                            }
                            if publication_owner == 0
                                || send_udp.inbound_publication_owner() != publication_owner
                                || !send_peers.peer_session_is_current_sync(
                                    &peer_id_owned,
                                    peer_session_generation,
                                )
                            {
                                return Err(DaemonError::Network(
                                    "DPLPMTUD Probe lifecycle changed before ACK send"
                                        .to_string(),
                                ));
                            }
                            if let Some(receive_socket) = receive_socket {
                                if receive_socket.local_addr().ok() != Some(local_endpoint) {
                                    return Err(DaemonError::Network(
                                        "DPLPMTUD receiving socket endpoint changed"
                                            .to_string(),
                                    ));
                                }
                                send_udp
                                    .send_encrypted_packet_on_socket(
                                        &receive_socket,
                                        socket_index,
                                        &encrypted,
                                        ack_destination,
                                    )
                                    .await
                                    .map(|_| ())
                            } else {
                                send_udp
                                    .send_packet_on_socket_index(
                                        &encrypted,
                                        socket_index,
                                        ack_destination,
                                    )
                                    .await
                                    .map(|_| ())
                            }
                        },
                    )
                    .await;
                match result {
                    Ok(BoundedEmitOutcome::Sent) => {
                        debug!(
                            event = "dplpmtud_ack_sent",
                            peer_id = %peer_id,
                            probe_source = %source,
                            remote_endpoint = %ack_destination,
                            local_endpoint = %local_endpoint,
                            socket_index,
                            sequence = token.sequence,
                            candidate_udp_datagram_size = token.candidate_udp_datagram_size.0,
                            "sent authenticated DPLPMTUD ACK on the receiving Direct socket"
                        );
                    }
                    Ok(
                        BoundedEmitOutcome::LockTimeout | BoundedEmitOutcome::SessionUnavailable,
                    )
                    | Err(_) => {
                        peers.emit_timeline(
                            "dplpmtud_probe_send_failed",
                            Some("direct"),
                            Some("ack_send_failed"),
                            Some(format!(
                                "peer={peer_id} sequence={} probe_source={source} remote_endpoint={ack_destination} local_endpoint={local_endpoint} socket_index={socket_index}",
                                token.sequence,
                            )),
                        );
                    }
                }
            }
            crate::dplpmtud::DplpmtudControlKind::Ack => {
                let (Some(source), Some(local_endpoint), Some(socket_index)) =
                    (source, local_endpoint, socket_index)
                else {
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("ack_ingress_identity_incomplete"),
                        Some(format!("peer={peer_id} sequence={}", token.sequence)),
                    );
                    return;
                };
                if crate::dplpmtud::OuterIpFamily::from_ip(source.ip()) != token.outer_ip_family {
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("ack_outer_ip_family_mismatch"),
                        Some(format!(
                            "peer={peer_id} sequence={} source={source}",
                            token.sequence,
                        )),
                    );
                    return;
                }

                // Canonical order: the transport inbound path retained the
                // per-peer emit guard for an ACK; below it we take adoption,
                // then the global network epoch, then the non-awaiting runtime
                // try-lock.  No socket I/O occurs in this transaction.
                let adoption_guard = udp.lock_peer_adoption_for_direct_validation(peer_id).await;
                let epoch_gate = peers.network_epoch_gate();
                let epoch_guard = epoch_gate.lock().await;
                if !peers.peer_session_is_current_sync(peer_id, peer_session_generation) {
                    drop(epoch_guard);
                    drop(adoption_guard);
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("peer_lifecycle_changed"),
                        Some(format!("peer={peer_id} sequence={}", token.sequence)),
                    );
                    return;
                }
                let runtime = udp.dplpmtud_runtime();
                let Some(current_path) = runtime.path_identity(peer_id) else {
                    drop(epoch_guard);
                    drop(adoption_guard);
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("no_current_probe_path"),
                        Some(format!("peer={peer_id} sequence={}", token.sequence)),
                    );
                    return;
                };
                if !peers.dplpmtud_path_is_current_sync(&current_path) {
                    drop(epoch_guard);
                    drop(adoption_guard);
                    peers.emit_timeline(
                        "dplpmtud_stale_ack_rejected",
                        Some("direct"),
                        Some("path_identity_changed"),
                        Some(format!("peer={peer_id} sequence={}", token.sequence)),
                    );
                    return;
                }
                let decision = runtime.try_accept_ack(
                    peer_id,
                    &current_path,
                    token,
                    crate::dplpmtud::DplpmtudAckIngress {
                        remote_endpoint: source,
                        local_endpoint,
                        socket: crate::dplpmtud::DplpmtudSocketIdentity {
                            transport_instance_id: udp.transport_instance_id(),
                            socket_index,
                        },
                    },
                    tokio::time::Instant::now(),
                );
                drop(epoch_guard);
                drop(adoption_guard);

                let snapshot = runtime.snapshot_for_path(&current_path);
                match decision {
                    crate::dplpmtud::DplpmtudTransitionDecision::Applied => {
                        peers.emit_timeline(
                            "dplpmtud_probe_acked",
                            Some("direct"),
                            None,
                            Some(format!(
                                "peer={peer_id} sequence={} candidate_udp_datagram_size={} confirmed_udp_datagram_size={} search_upper_udp_datagram_size={}",
                                token.sequence,
                                token.candidate_udp_datagram_size.0,
                                snapshot
                                    .as_ref()
                                    .and_then(|value| value.confirmed_udp_datagram_size)
                                    .unwrap_or(0),
                                snapshot.as_ref().map_or(0, |value| value.search_upper_udp_datagram_size),
                            )),
                        );
                        peers.emit_timeline(
                            "dplpmtud_search_bounds_updated",
                            Some("direct"),
                            None,
                            Some(format!(
                                "peer={peer_id} confirmed_udp_datagram_size={} search_upper_udp_datagram_size={}",
                                snapshot
                                    .as_ref()
                                    .and_then(|value| value.confirmed_udp_datagram_size)
                                    .unwrap_or(0),
                                snapshot.as_ref().map_or(0, |value| value.search_upper_udp_datagram_size),
                            )),
                        );
                        if snapshot.as_ref().is_some_and(|value| {
                            value.state == crate::dplpmtud::DplpmtudState::SearchComplete
                        }) {
                            peers.emit_timeline(
                                "dplpmtud_search_complete",
                                Some("direct"),
                                None,
                                Some(format!(
                                    "peer={peer_id} confirmed_udp_datagram_size={}",
                                    snapshot
                                        .as_ref()
                                        .and_then(|value| value.confirmed_udp_datagram_size)
                                        .unwrap_or(0),
                                )),
                            );
                        }
                    }
                    crate::dplpmtud::DplpmtudTransitionDecision::Duplicate => {
                        peers.emit_timeline(
                            "dplpmtud_duplicate_ack",
                            Some("direct"),
                            Some("duplicate_ack"),
                            Some(format!("peer={peer_id} sequence={}", token.sequence)),
                        );
                    }
                    crate::dplpmtud::DplpmtudTransitionDecision::Stale
                    | crate::dplpmtud::DplpmtudTransitionDecision::Busy
                    | crate::dplpmtud::DplpmtudTransitionDecision::Noop
                    | crate::dplpmtud::DplpmtudTransitionDecision::Rejected => {
                        peers.emit_timeline(
                            "dplpmtud_stale_ack_rejected",
                            Some("direct"),
                            Some("identity_or_expectation_mismatch"),
                            Some(format!(
                                "peer={peer_id} sequence={} decision={decision:?}",
                                token.sequence,
                            )),
                        );
                    }
                }
            }
        }
    }
}
