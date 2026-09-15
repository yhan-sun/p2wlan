use super::{
    debug, global_dataplane_profiler, overlay_packet_identity, timeout, DataplaneTailMetrics,
    DirectFastPathEntry, Duration, FastPathAttempt, FastPathEligibilityToken, HashMap, Instant,
    OutboundPacket, PeerManager, RwLock, SessionBoundEncryption, UdpTransport, WireGuardTransport,
    OUTBOUND_SEND_TIMEOUT, REASON_DIRECT_DELIVERY_UNCERTAIN, REASON_DIRECT_SEND_FAILED,
    REASON_OUTBOUND_ENCRYPT_FAILED,
};

/// Try the specialized LAN Direct sender. The caller has already established
/// that this peer has no older pending FIFO or in-flight flush task, so a
/// successful fast send cannot overtake an earlier plaintext packet.
#[allow(clippy::too_many_arguments)]
pub(super) async fn try_lan_direct_fast_path(
    packet: OutboundPacket,
    transport: &WireGuardTransport,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    fast_paths: &mut HashMap<String, DirectFastPathEntry>,
    ineligible: &mut HashMap<String, FastPathEligibilityToken>,
) -> FastPathAttempt {
    let peer_id = packet.peer_id.as_str();
    let profiler = global_dataplane_profiler();
    // The legacy LAN specialization predates business-budget tokens. A
    // capability-managed peer must use the tokenized slow path until the fast
    // cache itself carries the complete DPLPMTUD identity and revision.
    if udp_transport
        .read()
        .await
        .as_ref()
        .is_some_and(|udp| udp.peer_requires_direct_business_budget(peer_id))
    {
        fast_paths.remove(peer_id);
        ineligible.remove(peer_id);
        return FastPathAttempt::Fallback(packet);
    }
    let fast_path_lookup_started = Instant::now();
    let mut udp_socket_lookup_us = 0u64;
    let mut entry = fast_paths.get(peer_id).cloned();

    if let Some(cached) = entry.as_ref() {
        if !peers.active_direct_path_snapshot_is_current_sync(peer_id, cached.path) {
            fast_paths.remove(peer_id);
            profiler.record_fast_path_invalidation();
            entry = None;
        }
    }

    if entry.is_none() {
        profiler.record_fast_path_miss();
        if ineligible
            .get(peer_id)
            .is_some_and(|token| token.is_current(peers, peer_id))
        {
            return FastPathAttempt::Fallback(packet);
        }
        ineligible.remove(peer_id);

        let generation = peers.current_network_generation_sync();
        let Some(path) = peers
            .active_direct_path_snapshot(peer_id, generation, prefer_direct)
            .await
        else {
            if let (Some(direct_commit_seq), Some(peer_session_generation)) = (
                peers.direct_commit_seq_sync(peer_id),
                peers.peer_session_generation_sync(peer_id),
            ) {
                ineligible.insert(
                    peer_id.to_owned(),
                    FastPathEligibilityToken {
                        generation,
                        direct_commit_seq,
                        peer_session_generation,
                    },
                );
            }
            return FastPathAttempt::Fallback(packet);
        };
        let session_status_started = Instant::now();
        let session_instance = transport
            .session_status(peer_id)
            .await
            .active_session_instance;
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_fast_path_session_status_us",
                session_status_started.elapsed(),
            );
        }
        let Some(session_instance) = session_instance else {
            return FastPathAttempt::Fallback(packet);
        };
        let udp_read_started = Instant::now();
        let udp_guard = udp_transport.read().await;
        let udp_read_acquired = Instant::now();
        let udp = udp_guard.clone();
        let udp_read_hold = udp_read_acquired.elapsed();
        drop(udp_guard);
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_udp_transport_rwlock_wait_us",
                udp_read_acquired.duration_since(udp_read_started),
            );
            profiler.record(
                trace.sampled,
                "tx_udp_transport_rwlock_hold_us",
                udp_read_hold,
            );
        }
        let Some(udp) = udp else {
            return FastPathAttempt::Fallback(packet);
        };
        let socket_lookup_started = Instant::now();
        let socket = udp
            .socket_for_peer_endpoint(Some(peer_id), Some(path.endpoint))
            .await;
        let socket_lookup_completed = Instant::now();
        let cache_socket_lookup_us = socket_lookup_completed
            .duration_since(socket_lookup_started)
            .as_micros() as u64;
        udp_socket_lookup_us = udp_socket_lookup_us.saturating_add(cache_socket_lookup_us);
        if let Some(trace) = packet.trace.as_ref() {
            profiler.record(
                trace.sampled,
                "udp_socket_lookup_us",
                Duration::from_micros(cache_socket_lookup_us),
            );
        }
        let Some((socket_index, _)) = socket else {
            return FastPathAttempt::Fallback(packet);
        };
        entry = Some(DirectFastPathEntry {
            path,
            session_instance,
            udp_transport_instance_id: udp.transport_instance_id(),
            publication_owner: udp.inbound_publication_owner(),
            socket_index,
        });
        fast_paths.insert(
            peer_id.to_string(),
            entry
                .as_ref()
                .expect("fast-path entry was just built")
                .clone(),
        );
        ineligible.remove(peer_id);
    }

    let Some(entry) = entry else {
        return FastPathAttempt::Fallback(packet);
    };
    if let Some(trace) = packet.trace.as_ref() {
        profiler.record(
            trace.sampled,
            "tx_fast_path_lookup_us",
            fast_path_lookup_started.elapsed(),
        );
    }
    let packet_bytes = packet.packet.len();
    let sampled_trace = packet.trace.clone();
    let overlay_identity = overlay_packet_identity(&packet.packet);
    let encrypt_started = Instant::now();
    let mut epoch_gate_wait_us = 0u64;
    let mut epoch_gate_hold_us = 0u64;
    let emit_guard_wait_started = Instant::now();
    let emit_guard = transport.acquire_outbound_emit_guard(peer_id).await;
    let emit_guard_acquired = Instant::now();
    if let Some(trace) = sampled_trace.as_ref() {
        profiler.record(
            trace.sampled,
            "tx_emit_guard_wait_us",
            emit_guard_acquired.duration_since(emit_guard_wait_started),
        );
    }

    // Keep the lock order identical to the existing business path:
    // per-peer emit -> network epoch -> socket state/session. The UDP write is
    // intentionally outside the epoch gate.
    let (udp, socket, encrypted, session_lock_wait_us, crypto_us) = {
        let epoch_gate = peers.network_epoch_gate();
        let epoch_gate_wait_started = Instant::now();
        let _epoch_guard = epoch_gate.lock().await;
        let epoch_gate_acquired = Instant::now();
        if let Some(trace) = sampled_trace.as_ref() {
            epoch_gate_wait_us = epoch_gate_acquired
                .duration_since(epoch_gate_wait_started)
                .as_micros() as u64;
            profiler.record(
                trace.sampled,
                "tx_epoch_gate_wait_us",
                Duration::from_micros(epoch_gate_wait_us),
            );
        }
        if !peers.active_direct_path_snapshot_is_current_sync(peer_id, entry.path) {
            drop(emit_guard);
            profiler.record_fast_path_invalidation();
            fast_paths.remove(peer_id);
            return FastPathAttempt::Fallback(packet);
        }

        let udp_read_started = Instant::now();
        let udp_guard = udp_transport.read().await;
        let udp_read_acquired = Instant::now();
        let udp = udp_guard.clone();
        let udp_read_hold = udp_read_acquired.elapsed();
        drop(udp_guard);
        if let Some(trace) = sampled_trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_udp_transport_rwlock_wait_us",
                udp_read_acquired.duration_since(udp_read_started),
            );
            profiler.record(
                trace.sampled,
                "tx_udp_transport_rwlock_hold_us",
                udp_read_hold,
            );
        }
        let Some(udp) = udp else {
            drop(emit_guard);
            profiler.record_fast_path_invalidation();
            fast_paths.remove(peer_id);
            return FastPathAttempt::Fallback(packet);
        };
        if udp.transport_instance_id() != entry.udp_transport_instance_id
            || udp.inbound_publication_owner() != entry.publication_owner
        {
            drop(emit_guard);
            profiler.record_fast_path_invalidation();
            fast_paths.remove(peer_id);
            return FastPathAttempt::Fallback(packet);
        }
        let socket_lookup_started = Instant::now();
        let socket = udp
            .socket_for_inbound_peer_index(peer_id, entry.socket_index)
            .await;
        let socket_lookup_completed = Instant::now();
        let socket_lookup_us = socket_lookup_completed
            .duration_since(socket_lookup_started)
            .as_micros() as u64;
        udp_socket_lookup_us = udp_socket_lookup_us.saturating_add(socket_lookup_us);
        if let Some(trace) = sampled_trace.as_ref() {
            profiler.record(
                trace.sampled,
                "udp_socket_lookup_us",
                Duration::from_micros(socket_lookup_us),
            );
        }
        let Some(socket) = socket else {
            drop(emit_guard);
            profiler.record_fast_path_invalidation();
            fast_paths.remove(peer_id);
            return FastPathAttempt::Fallback(packet);
        };

        let (encrypted, session_lock_wait_us, crypto_us) = match transport
            .encrypt_outbound_with_emit_guard_for_session(packet, entry.session_instance)
            .await
        {
            SessionBoundEncryption::Encrypted {
                packet: encrypted,
                session_lock_wait_us,
                crypto_us,
            } => (encrypted, session_lock_wait_us, crypto_us),
            SessionBoundEncryption::Unavailable { packet, reason } => {
                debug!(
                    event = "wireguard_session_unavailable",
                    peer_id = %packet.peer_id,
                    reason = reason.as_str(),
                    expected_session_instance = entry.session_instance,
                    "LAN Direct FastPath cache could not bind the packet to its expected session"
                );
                drop(emit_guard);
                profiler.record_fast_path_invalidation();
                fast_paths.remove(packet.peer_id.as_str());
                return FastPathAttempt::Fallback(packet);
            }
            SessionBoundEncryption::Failed { packet, error } => {
                drop(emit_guard);
                fast_paths.remove(packet.peer_id.as_str());
                return FastPathAttempt::Terminal {
                    packet,
                    generation: entry.path.generation,
                    reason_code: REASON_OUTBOUND_ENCRYPT_FAILED,
                    reason: error.to_string(),
                };
            }
        };
        if let Some(trace) = sampled_trace.as_ref() {
            epoch_gate_hold_us = epoch_gate_acquired.elapsed().as_micros() as u64;
            profiler.record(
                trace.sampled,
                "tx_epoch_gate_hold_us",
                Duration::from_micros(epoch_gate_hold_us),
            );
        }
        (udp, socket, encrypted, session_lock_wait_us, crypto_us)
    };

    let peer_id = encrypted.peer_id.as_str();
    let encrypt_completed = Instant::now();
    if let Some(trace) = sampled_trace.as_ref() {
        profiler.record(
            trace.sampled,
            "tun_read_to_encrypt_us",
            encrypt_started.duration_since(trace.tun_read_completed),
        );
        if let Some(route_ready) = trace.route_ready {
            profiler.record(
                trace.sampled,
                "route_to_encrypt_us",
                encrypt_started.duration_since(route_ready),
            );
        }
        profiler.record(
            trace.sampled,
            "encrypt_us",
            encrypt_completed.duration_since(encrypt_started),
        );
        profiler.record(
            trace.sampled,
            "tx_fast_path_encrypt_us",
            encrypt_completed.duration_since(encrypt_started),
        );
    }

    let transport_handoff_started = Instant::now();
    let local_endpoint = udp.local_addr().ok();
    debug!(
        event = "lan_direct_fast_path_send_started",
        peer_id = %peer_id,
        generation = entry.path.generation,
        remote_endpoint = %entry.path.endpoint,
        local_endpoint = ?local_endpoint,
        socket_index = entry.socket_index,
        udp_transport_instance_id = entry.udp_transport_instance_id,
        session_instance = entry.session_instance,
        counter = ?crate::transport::wire_counter(&encrypted.wire_bytes),
        "encrypted packet entered the LAN Direct fast path"
    );
    let send_result = timeout(
        OUTBOUND_SEND_TIMEOUT,
        udp.send_encrypted_packet_on_socket(
            &socket,
            entry.socket_index,
            &encrypted,
            entry.path.endpoint,
        ),
    )
    .await;
    let transport_handoff_completed = Instant::now();
    let udp_send_call_us = transport_handoff_completed
        .duration_since(transport_handoff_started)
        .as_micros() as u64;
    let emit_guard_hold_us = transport_handoff_completed
        .duration_since(emit_guard_acquired)
        .as_micros() as u64;
    if let Some(trace) = sampled_trace.as_ref() {
        profiler.record(
            trace.sampled,
            "udp_send_call_us",
            Duration::from_micros(udp_send_call_us),
        );
        profiler.record(
            trace.sampled,
            "tx_emit_guard_hold_us",
            Duration::from_micros(emit_guard_hold_us),
        );
    }
    if let Some(trace) = sampled_trace.as_ref() {
        let total_userspace_tx =
            transport_handoff_completed.duration_since(trace.tun_read_completed);
        profiler.record(
            trace.sampled,
            "encrypt_to_send_us",
            transport_handoff_started.duration_since(encrypt_completed),
        );
        profiler.record(trace.sampled, "total_userspace_tx_us", total_userspace_tx);
        profiler.record(
            trace.sampled,
            "tx_fast_path_total_userspace_us",
            total_userspace_tx,
        );
        let queue_wait_us = trace
            .dataplane_queue_send_started
            .zip(trace.transport_queue_dequeued)
            .map(|(start, end)| end.duration_since(start).as_micros() as u64)
            .unwrap_or_default()
            .saturating_add(
                trace
                    .transport_queue_send_started
                    .zip(trace.network_queue_dequeued)
                    .map(|(start, end)| end.duration_since(start).as_micros() as u64)
                    .unwrap_or_default(),
            );
        profiler.record_tail_event(
            "tx",
            peer_id,
            "lan_direct",
            total_userspace_tx,
            DataplaneTailMetrics {
                queue_wait_us,
                emit_guard_wait_us: emit_guard_acquired
                    .duration_since(emit_guard_wait_started)
                    .as_micros() as u64,
                emit_guard_hold_us,
                epoch_gate_wait_us,
                epoch_gate_hold_us,
                session_lock_wait_us,
                crypto_us,
                udp_socket_lookup_us,
                udp_send_call_us,
                ..DataplaneTailMetrics::default()
            },
            profiler.candidate_gather_active(),
            entry.path.generation,
        );
        if total_userspace_tx >= crate::dataplane::DATAPLANE_STALL_THRESHOLD {
            debug!(
                event = "dataplane_stall",
                peer_id = %peer_id,
                active_path = "direct",
                tun_to_send_us = total_userspace_tx.as_micros() as u64,
                receive_to_tun_us = 0u64,
                candidate_gather_active = profiler.candidate_gather_active(),
                network_generation = entry.path.generation,
                "LAN Direct fast-path packet exceeded the diagnostic stall threshold"
            );
        }
    }

    let outcome = match send_result {
        Ok(Ok(_)) => {
            profiler.record_fast_path_hit();
            FastPathAttempt::Sent
        }
        Ok(Err(error)) => {
            let reason = format!("LAN Direct UDP send result uncertain: {error}");
            peers
                .record_direct_failure_with_code_and_local_endpoint(
                    peer_id,
                    REASON_DIRECT_SEND_FAILED,
                    reason.clone(),
                    local_endpoint,
                )
                .await;
            fast_paths.remove(peer_id);
            FastPathAttempt::TerminalBytes {
                peer_id: encrypted.peer_id.clone(),
                generation: entry.path.generation,
                bytes: packet_bytes,
                reason_code: REASON_DIRECT_DELIVERY_UNCERTAIN,
                reason,
            }
        }
        Err(_) => {
            fast_paths.remove(peer_id);
            FastPathAttempt::TerminalBytes {
                peer_id: encrypted.peer_id.clone(),
                generation: entry.path.generation,
                bytes: packet_bytes,
                reason_code: REASON_DIRECT_DELIVERY_UNCERTAIN,
                reason: "LAN Direct UDP send timed out; delivery is uncertain".to_string(),
            }
        }
    };
    if let Some((nonce, sequence, direction)) = overlay_identity {
        let outcome_label = match &outcome {
            FastPathAttempt::Sent => "sent",
            FastPathAttempt::Fallback(_) => "fallback",
            FastPathAttempt::Terminal { .. } | FastPathAttempt::TerminalBytes { .. } => "terminal",
        };
        debug!(
            event = "outbound_overlay_transport_result",
            peer_id = %peer_id,
            nonce = format_args!("{nonce:#x}"),
            sequence,
            direction,
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&encrypted.wire_bytes)),
            counter = ?crate::transport::wire_counter(&encrypted.wire_bytes),
            outcome = outcome_label,
            "encrypted overlay packet reached the LAN Direct fast-path outcome"
        );
    }
    drop(emit_guard);
    outcome
}
