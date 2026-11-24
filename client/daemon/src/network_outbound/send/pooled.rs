//! Healthy Direct datagrams keep their TUN allocation through the UDP write.
use super::*;
use p2pnet_crypto::packet_buf::PacketBuf;

pub(super) enum Attempt {
    Sent,
    RetryUnsent,
    Terminal(&'static str, String),
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn try_send(
    packet: &RawRequestDelivery,
    buffer: &mut PacketBuf,
    transport: &WireGuardTransport,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_slot: &RwLock<Option<UdpTransport>>,
    relay_slot: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
    window: SendAdmissionWindow<'_>,
) -> Attempt {
    if !prefer_direct || transport.resource_capture().is_some() {
        return Attempt::RetryUnsent;
    }
    let bounded = async {
        let peer_id = &packet.peer_id;
        let generation = window.expected_generation;
        let Some(status) = transport.try_session_status(peer_id) else {
            return Attempt::RetryUnsent;
        };
        let Some(instance) = status.active_session_instance else {
            return Attempt::RetryUnsent;
        };
        let key = SessionKey {
            generation,
            instance,
        };
        if peers
            .tuning()
            .needs_tuning(peer_id, key, buffer.len(), peers.transport_config())
        {
            return Attempt::RetryUnsent;
        }
        let Some(_emit) = transport.try_acquire_outbound_emit_guard(peer_id) else {
            return Attempt::RetryUnsent;
        };
        let gate = peers.network_epoch_gate();
        let Ok(epoch) = gate.try_lock() else {
            return Attempt::RetryUnsent;
        };
        let Ok(slot) = udp_slot.try_read() else {
            return Attempt::RetryUnsent;
        };
        let Some(udp) = slot.as_ref() else {
            return Attempt::RetryUnsent;
        };
        if peers.current_network_generation_sync() != generation
            || !udp.peer_requires_direct_business_budget(peer_id)
        {
            return Attempt::RetryUnsent;
        }
        let relay_available = relay_slot
            .try_read()
            .ok()
            .is_some_and(|slot| slot.is_some());
        let selection = peers
            .select_path_for_data_with_local_endpoint_in_epoch(
                peer_id,
                prefer_direct,
                relay_available || relay_expected,
                udp.local_addr().ok(),
                generation,
                false,
            )
            .await;
        let Some(endpoint) = selection
            .direct_endpoint
            .filter(|_| selection.direct_confirmed && selection.path == Some(NetworkPath::Direct))
        else {
            return Attempt::RetryUnsent;
        };
        let mut socket = udp.try_prepare_direct_business_socket_resource(peer_id);
        let DirectBusinessBudgetGate::Ready(prepared) = udp
            .prepare_direct_business_send_with_resource(peer_id, endpoint, &mut socket)
            .await
        else {
            return Attempt::RetryUnsent;
        };
        let budget = prepared.token.max_overlay_payload_size.0 as usize;
        if complete_inner_ip_packet_len(buffer.bytes()) != Some(buffer.len())
            || buffer.len() > budget
            || (buffer.bytes().first().is_some_and(|first| first >> 4 == 6)
                && budget < crate::business_mtu::IPV6_MINIMUM_MTU as usize)
            || window.rejection_reason().is_some()
            || !peers.dplpmtud_path_is_current_sync(&prepared.token.path_identity)
        {
            return Attempt::RetryUnsent;
        }
        peers
            .satisfy_direct_first_in_epoch(&epoch, peer_id, generation, endpoint)
            .await;
        if window.rejection_reason().is_some() {
            return Attempt::RetryUnsent;
        }
        let result = transport.try_send_pooled(peer_id, instance, buffer, |wire| {
            udp.try_send_direct_business_wire(
                &prepared,
                packet.room_authorization.as_ref(),
                wire,
                None,
            )
        });
        match result {
            Ok(Some(Ok(_))) => {
                peers
                    .tuning()
                    .pooled_tx_packets
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(counter) = crate::transport::wire_counter(buffer.bytes()) {
                    let path = peers
                        .committed_business_path_snapshot_sync(peer_id)
                        .map(|path| path.active);
                    peers.tuning().sent_unmodified(peer_id, key, path, counter);
                }
                Attempt::Sent
            }
            Ok(
                None
                | Some(Err(
                    DirectBusinessUdpSendError::StaleToken
                    | DirectBusinessUdpSendError::WouldBlock
                    | DirectBusinessUdpSendError::LocalPacketTooLarge
                    | DirectBusinessUdpSendError::CiphertextTooLarge,
                )),
            ) => Attempt::RetryUnsent,
            Ok(Some(Err(error))) => {
                Attempt::Terminal(REASON_DIRECT_DELIVERY_UNCERTAIN, error.to_string())
            }
            Err(error) => Attempt::Terminal(REASON_OUTBOUND_ENCRYPT_FAILED, error.to_string()),
        }
    };
    let limit = window.deadline.map_or(OUTBOUND_SEND_TIMEOUT, |deadline| {
        deadline
            .saturating_duration_since(Instant::now())
            .min(OUTBOUND_SEND_TIMEOUT)
    });
    timeout(limit, bounded)
        .await
        .unwrap_or(Attempt::RetryUnsent)
}
