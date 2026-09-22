use super::*;

pub(super) async fn direct_business_budget_ready_for_active_path(
    peers: &PeerManager,
    peer_id: &str,
    udp_transport: &RwLock<Option<UdpTransport>>,
    generation: u64,
    relay_available: bool,
) -> bool {
    let Some(committed) = peers.committed_business_path_snapshot_sync(peer_id) else {
        return true;
    };
    match committed.active {
        // Relay is fully isolated: do not even inspect a Direct publication.
        ActiveBusinessPath::Relay(_) | ActiveBusinessPath::Unavailable => true,
        ActiveBusinessPath::Direct(_) => {
            let budget_ready = udp_transport
                .read()
                .await
                .as_ref()
                .is_some_and(|udp| udp.direct_business_budget_ready_for_peer(peer_id));
            if budget_ready {
                return true;
            }
            // Make-before-break: while the committed Direct path is still
            // waiting for its authoritative business proof, a confirmed
            // Relay keeps carrying business. The queue stays flushable so
            // the first budget-confirmed packet switches it to Direct.
            relay_available
                && peers
                    .is_relay_business_admitted_for_generation(peer_id, generation)
                    .await
        }
    }
}

/// Decide (and record) whether this plaintext may ride the confirmed Relay
/// while the committed Direct path is not business-ready yet. Returns false
/// when no confirmed Relay exists, leaving the bounded Pending semantics in
/// place instead of silently dropping the make-before-break guarantee.
pub(super) async fn relay_make_before_break_fallback(
    epoch_guard: &tokio::sync::MutexGuard<'_, ()>,
    peers: &PeerManager,
    peer_id: &str,
    generation: u64,
    relay_available: bool,
    reason: &str,
) -> bool {
    let usable = relay_available
        && peers
            .is_relay_business_admitted_in_epoch(epoch_guard, peer_id, generation)
            .await;
    if usable {
        peers.emit_timeline(
            "direct_business_budget_relay_fallback",
            Some("direct"),
            Some(REASON_DIRECT_BUDGET_PENDING),
            Some(format!(
                "peer={peer_id} generation={generation} reason={reason} fallback=relay make_before_break=true"
            )),
        );
    }
    usable
}

pub(super) async fn send_direct_if_selected(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    udp: Option<UdpTransport>,
    selection: &PathSelection,
    udp_local_endpoint: Option<SocketAddr>,
    sampled: Option<bool>,
) -> DirectSendOutcome {
    // A candidate probe or nomination is not an encrypted data-plane proof.
    // Business packets must never use a Direct trial: sending the same
    // ciphertext as a relay hedge can create duplicate/reordered delivery,
    // while sending it only over UDP makes the WireGuard counter's delivery
    // status unknowable.  The direct-validation worker owns trial probes;
    // this function accepts only the committed Direct state.
    if selection.path != Some(NetworkPath::Direct) || !selection.direct_confirmed {
        return DirectSendOutcome::NotHanded {
            err: "Direct path is not encrypted-confirmed".to_string(),
        };
    }

    match (udp, selection.direct_endpoint) {
        (Some(udp), Some(endpoint)) => {
            debug!(
                event = "direct_data_send_started",
                peer_id = %packet.peer_id,
                remote_endpoint = %endpoint,
                local_endpoint = ?udp_local_endpoint,
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                is_business = packet.is_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                "encrypted packet handed to the Direct UDP socket"
            );
            let udp_send_started = Instant::now();
            let send_result = udp.send_packet_to(packet, endpoint).await;
            if let Some(sampled) = sampled {
                global_dataplane_profiler().record(
                    sampled,
                    "udp_send_path_lookup_and_call_us",
                    udp_send_started.elapsed(),
                );
            }
            match send_result {
                Ok(_) => {
                    debug!(
                        event = "direct_data_handoff_accepted",
                        peer_id = %packet.peer_id,
                        remote_endpoint = %endpoint,
                        local_endpoint = ?udp_local_endpoint,
                        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                        bytes = packet.wire_bytes.len(),
                        is_business = packet.is_business,
                        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                        "Direct UDP send_to accepted the datagram locally; peer delivery remains unconfirmed"
                    );
                    DirectSendOutcome::HandoffAccepted
                }
                Err(err @ crate::error::DaemonError::UdpPacketTooLarge { .. }) => {
                    warn!(
                        event = "direct_data_packet_too_large",
                        peer_id = %packet.peer_id,
                        remote_endpoint = %endpoint,
                        local_endpoint = ?udp_local_endpoint,
                        bytes = packet.wire_bytes.len(),
                        error = %err,
                        "Direct UDP send was synchronously rejected with EMSGSIZE; path health and Relay selection are unchanged"
                    );
                    DirectSendOutcome::PacketTooLarge {
                        err: err.to_string(),
                    }
                }
                Err(err) => {
                    warn!(
                        event = "direct_data_send_failed",
                        peer_id = %packet.peer_id,
                        remote_endpoint = %endpoint,
                        local_endpoint = ?udp_local_endpoint,
                        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                        bytes = packet.wire_bytes.len(),
                        is_business = packet.is_business,
                        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                        error = %err,
                        "Direct UDP send failed; delivery is uncertain and the ciphertext will not be replayed"
                    );
                    peers
                        .record_direct_failure_with_code_and_local_endpoint(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            err.to_string(),
                            udp_local_endpoint,
                        )
                        .await;
                    DirectSendOutcome::DeliveryUncertain {
                        err: format!("Direct UDP send result uncertain: {err}"),
                    }
                }
            }
        }
        (None, _) => {
            peers
                .record_direct_failure_with_code_and_local_endpoint(
                    &packet.peer_id,
                    REASON_DIRECT_SEND_FAILED,
                    "UDP transport unavailable for encrypted packet",
                    udp_local_endpoint,
                )
                .await;
            DirectSendOutcome::NotHanded {
                err: "UDP transport unavailable for encrypted packet".to_string(),
            }
        }
        (_, None) => {
            peers
                .record_direct_failure_with_code_and_local_endpoint(
                    &packet.peer_id,
                    REASON_DIRECT_SEND_FAILED,
                    "path selector chose direct without an endpoint",
                    udp_local_endpoint,
                )
                .await;
            DirectSendOutcome::NotHanded {
                err: "path selector chose direct without an endpoint".to_string(),
            }
        }
    }
}
