use super::*;

pub(super) fn relay_send_failure(err: &crate::error::DaemonError) -> SendOutcome {
    // These typed relay outcomes prove the frame was rejected before the
    // writer owned it, so plaintext may be re-encrypted. A writer completion
    // loss or an interrupted write is deliberately not in this set. Do not
    // classify by formatted text: that would turn a future wording change
    // into a possible replay of an old WireGuard counter.
    if let crate::error::DaemonError::RelaySend { error, .. } = err {
        if matches!(
            error,
            p2pnet_relay::RelayError::CommandQueueFull
                | p2pnet_relay::RelayError::WriterStoppedBeforeAccept
                | p2pnet_relay::RelayError::WriteBoundaryRejected
        ) {
            return SendOutcome::Retryable(RetryableSendFailure::RelaySendNotHanded {
                err: err.to_string(),
            });
        }
    }
    SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
        reason: REASON_RELAY_DELIVERY_UNCERTAIN,
        err: err.to_string(),
    })
}

/// Send one already-encrypted packet through the confirmed relay and expose
/// the exact local boundaries around it.  A successful return is still only
/// the relay client's writer completion; peer delivery is proven later by the
/// encrypted relay probe ACK or real relay-ingress business packet.
pub(super) async fn send_via_relay(
    relay: &RelayTransport,
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    generation: u64,
    relay_send_started: &AtomicBool,
    sampled: Option<bool>,
) -> SendOutcome {
    relay_send_started.store(true, Ordering::Release);
    debug!(
        event = "relay_data_send_started",
        peer_id = %packet.peer_id,
        generation,
        relay_connection_id = relay.connection_id(),
        relay_region = %relay.region(),
        relay_endpoint = %relay.endpoint(),
        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
        bytes = packet.wire_bytes.len(),
        is_business = packet.is_business,
        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
        "encrypted packet handed to the relay client command boundary"
    );
    let relay_send_call_started = Instant::now();
    let send_result = relay.send_packet(packet).await;
    let relay_send_call_us = relay_send_call_started.elapsed();
    if let Some(sampled) = sampled {
        global_dataplane_profiler().record(sampled, "relay_send_call_us", relay_send_call_us);
    }
    match send_result {
        Ok(()) => {
            let first_business = packet.is_business
                && peers
                    .mark_relay_first_business_sent_for_generation_with_transport(
                        &packet.peer_id,
                        generation,
                        relay.endpoint(),
                        Some(relay.connection_id()),
                    )
                    .await;
            debug!(
                event = "relay_data_write_completed",
                peer_id = %packet.peer_id,
                generation,
                relay_connection_id = relay.connection_id(),
                relay_region = %relay.region(),
                relay_endpoint = %relay.endpoint(),
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                is_business = packet.is_business,
                first_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                "relay client write completed; this is not peer delivery"
            );
            if first_business {
                peers.emit_timeline(
                    "relay_first_business_write_completed",
                    Some("relay"),
                    Some("writer_completed_not_peer_delivery"),
                    Some(format!(
                        "peer={} generation={} relay_id={} relay_connection_id={} counter={} bytes={} wire_fp={:016x}",
                        packet.peer_id,
                        generation,
                        relay.endpoint(),
                        relay.connection_id(),
                        crate::transport::wire_counter(&packet.wire_bytes)
                            .map_or_else(|| "none".to_string(), |counter| counter.to_string()),
                        packet.wire_bytes.len(),
                        crate::transport::wire_fingerprint(&packet.wire_bytes),
                    )),
                );
            }
            SendOutcome::Sent
        }
        Err(err) => {
            debug!(
                event = "relay_data_send_failed",
                peer_id = %packet.peer_id,
                generation,
                relay_connection_id = relay.connection_id(),
                relay_region = %relay.region(),
                relay_endpoint = %relay.endpoint(),
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                is_business = packet.is_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                error = %err,
                "relay client rejected or failed an encrypted packet"
            );
            relay_send_failure(&err)
        }
    }
}
