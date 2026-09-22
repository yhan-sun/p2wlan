use super::*;

/// Encrypt a RAW packet (holding the peer's emit lock) and send it while the
/// guard is still held.
#[allow(clippy::too_many_arguments)]
pub(super) async fn encrypt_then_send(
    packet: OutboundPacket,
    transport: &WireGuardTransport,
    peers: &PeerManager,
    expected_generation: u64,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
) -> EncryptSendOutcome {
    let retry_packet = packet.clone();
    let profiler = global_dataplane_profiler();
    let sampled_trace = retry_packet.trace.clone();
    let encrypt_started = Instant::now();
    // Acquire the per-peer counter-ordering guard BEFORE the global epoch
    // gate.  Inbound relay ACK/business evidence uses the same order
    // (`emit -> epoch`); taking these in the opposite order here would let an
    // outbound encryptor and an inbound evidence commit wait on each other.
    // Generation advance and counter allocation are still one short
    // transaction. Relay and legacy Direct writes happen after that epoch
    // gate is released. Managed Direct later takes a fresh epoch guard only
    // across its exact nonblocking UDP syscall, which is the revocation/path
    // replacement linearization point.
    let emit_lock_started = Instant::now();
    let emit_guard = Arc::new(transport.acquire_outbound_emit_guard(&packet.peer_id).await);
    let emit_guard_acquired = Instant::now();
    let emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64;
    if let Some(trace) = sampled_trace.as_ref() {
        profiler.record(
            trace.sampled,
            "tx_emit_guard_wait_us",
            emit_guard_acquired.duration_since(emit_lock_started),
        );
    }
    debug!(
        event = "outbound_business_emit_lock_acquired",
        peer_id = %packet.peer_id,
        generation = expected_generation,
        lock_wait_ms = emit_lock_wait_ms,
        "business packet acquired its per-peer WireGuard counter-ordering lock"
    );
    let (encrypted, direct_business_plan, force_relay) = {
        let epoch_gate = peers.network_epoch_gate();
        let epoch_gate_wait_started = Instant::now();
        let _epoch_guard = epoch_gate.lock().await;
        let epoch_gate_acquired = Instant::now();
        if let Some(trace) = sampled_trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_epoch_gate_wait_us",
                epoch_gate_acquired.duration_since(epoch_gate_wait_started),
            );
        }
        let current_generation = peers.current_network_generation_sync();
        if current_generation != expected_generation {
            debug!(
                event = "outbound_counter_allocation_rejected",
                peer_id = %retry_packet.peer_id,
                expected_generation,
                current_generation,
                reason_code = REASON_OUTBOUND_GENERATION_CHANGED,
                "business packet was not encrypted because its network generation is stale"
            );
            return EncryptSendOutcome::Retryable {
                packet: retry_packet,
                reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
                reason: format!(
                    "network generation advanced before counter allocation: expected={expected_generation} current={current_generation}"
                ),
            };
        }
        let relay_available = relay_transport.read().await.is_some();
        let udp = udp_transport.read().await.clone();
        let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
        let selection = peers
            .select_path_for_data_with_local_endpoint_in_epoch(
                &retry_packet.peer_id,
                prefer_direct,
                relay_available || relay_expected,
                udp_local_endpoint,
                current_generation,
                false,
            )
            .await;
        let mut force_relay = false;
        let direct_business_plan = if selection.path == Some(NetworkPath::Direct)
            && selection.direct_confirmed
        {
            match (udp, selection.direct_endpoint) {
                (Some(udp), Some(endpoint)) => {
                    match udp
                        .prepare_direct_business_send(&retry_packet.peer_id, endpoint)
                        .await
                    {
                        DirectBusinessBudgetGate::Unmanaged => None,
                        DirectBusinessBudgetGate::ManagedPending { reason } => {
                            // Make-before-break: the encrypted Direct commit
                            // exists, but its authoritative business proof
                            // (confirmed budget) does not. A confirmed Relay
                            // must keep carrying business instead of parking
                            // the queue behind a budget only the Direct
                            // commit can publish.
                            if !relay_make_before_break_fallback(
                                &_epoch_guard,
                                peers,
                                &retry_packet.peer_id,
                                current_generation,
                                relay_available,
                                reason,
                            )
                            .await
                            {
                                return EncryptSendOutcome::BudgetPending {
                                    packet: retry_packet,
                                    reason: format!(
                                        "Direct DPLPMTUD budget pending before encryption: {reason}"
                                    ),
                                };
                            }
                            force_relay = true;
                            None
                        }
                        DirectBusinessBudgetGate::Ready(prepared) => {
                            let Some(inner_len) =
                                complete_inner_ip_packet_len(&retry_packet.packet)
                            else {
                                return EncryptSendOutcome::Terminal {
                                    packet: retry_packet,
                                    reason_code: REASON_DIRECT_BUSINESS_MALFORMED,
                                    reason: "managed Direct packet is not one complete IP packet"
                                        .to_string(),
                                };
                            };
                            let overlay_budget = prepared.token.max_overlay_payload_size.0 as usize;
                            if retry_packet.packet[0] >> 4 == 6
                                && overlay_budget < crate::business_mtu::IPV6_MINIMUM_MTU as usize
                            {
                                return EncryptSendOutcome::Terminal {
                                    packet: retry_packet,
                                    reason_code: REASON_IPV6_BUDGET_BELOW_MINIMUM_MTU,
                                    reason: format!(
                                        "inner IPv6 business traffic requires an advertised MTU of at least {}; confirmed inner budget is {overlay_budget}; no UDP handoff or invalid Packet Too Big was produced",
                                        crate::business_mtu::IPV6_MINIMUM_MTU,
                                    ),
                                };
                            }
                            if inner_len > overlay_budget {
                                let feedback = peers.emit_local_mtu_feedback(
                                    &retry_packet.peer_id,
                                    &retry_packet.packet,
                                    crate::business_mtu::LocalMtuFeedbackKind::PacketTooBig {
                                        inner_ip_mtu: prepared.token.max_overlay_payload_size.0,
                                    },
                                );
                                return EncryptSendOutcome::Terminal {
                                    packet: retry_packet,
                                    reason_code: REASON_DIRECT_BUDGET_OVERSIZE,
                                    reason: format!(
                                        "inner IP packet {inner_len} exceeds confirmed overlay budget {overlay_budget}; feedback={feedback:?}"
                                    ),
                                };
                            }
                            Some(DirectBusinessSendPlan {
                                udp,
                                prepared: *prepared,
                            })
                        }
                    }
                }
                _ => {
                    if !relay_make_before_break_fallback(
                        &_epoch_guard,
                        peers,
                        &retry_packet.peer_id,
                        current_generation,
                        relay_available,
                        "Direct selected without a published UDP endpoint/socket",
                    )
                    .await
                    {
                        return EncryptSendOutcome::BudgetPending {
                            packet: retry_packet,
                            reason: "Direct selected without a published UDP endpoint/socket"
                                .to_string(),
                        };
                    }
                    force_relay = true;
                    None
                }
            }
        } else {
            None
        };
        let result = match transport.encrypt_outbound_with_emit_guard(packet).await {
            Ok(Some(value)) => value,
            Ok(None) => {
                debug!(
                    event = "outbound_session_unavailable",
                    peer_id = %retry_packet.peer_id,
                    generation = expected_generation,
                    bytes = retry_packet.packet.len(),
                    reason_code = REASON_OUTBOUND_SESSION_NOT_READY,
                    "business packet remained plaintext because no usable WireGuard session exists"
                );
                return EncryptSendOutcome::Retryable {
                    packet: retry_packet,
                    reason_code: REASON_OUTBOUND_SESSION_NOT_READY,
                    reason: "WireGuard session is not ready".to_string(),
                };
            }
            Err(err) => {
                warn!(
                    event = "outbound_encrypt_failed",
                    peer_id = %retry_packet.peer_id,
                    generation = expected_generation,
                    bytes = retry_packet.packet.len(),
                    reason_code = REASON_OUTBOUND_ENCRYPT_FAILED,
                    error = %err,
                    "business packet encryption failed before a transport handoff"
                );
                return EncryptSendOutcome::Terminal {
                    packet: retry_packet,
                    reason_code: REASON_OUTBOUND_ENCRYPT_FAILED,
                    reason: err.to_string(),
                };
            }
        };
        if let Some(trace) = sampled_trace.as_ref() {
            profiler.record(
                trace.sampled,
                "tx_epoch_gate_hold_us",
                epoch_gate_acquired.elapsed(),
            );
        }
        if selection.path == Some(NetworkPath::Direct) && selection.direct_confirmed && !force_relay
        {
            if let Some(endpoint) = selection.direct_endpoint {
                peers
                    .satisfy_direct_first_in_epoch(
                        &_epoch_guard,
                        &retry_packet.peer_id,
                        current_generation,
                        endpoint,
                    )
                    .await;
            }
        }
        (result, direct_business_plan, force_relay)
    };
    let encrypt_completed = Instant::now();
    if let Some(plan) = direct_business_plan.as_ref() {
        if encrypted.wire_bytes.len() > plan.prepared.token.max_udp_datagram_size.0 as usize {
            let invalidated = plan
                .udp
                .invalidate_direct_business_budget(&plan.prepared.token);
            let feedback = peers.emit_local_mtu_feedback(
                &retry_packet.peer_id,
                &retry_packet.packet,
                crate::business_mtu::LocalMtuFeedbackKind::PacketTooBig {
                    inner_ip_mtu: plan.prepared.token.max_overlay_payload_size.0,
                },
            );
            drop(emit_guard);
            return EncryptSendOutcome::Terminal {
                packet: retry_packet,
                reason_code: REASON_DIRECT_CIPHERTEXT_OVERSIZE,
                reason: format!(
                    "actual ciphertext {} exceeds confirmed UDP budget {}; budget_invalidated={invalidated} feedback={feedback:?}",
                    encrypted.wire_bytes.len(),
                    plan.prepared.token.max_udp_datagram_size.0,
                ),
            };
        }
    }
    #[cfg(test)]
    if let Some(plan) = direct_business_plan.as_ref() {
        plan.udp.wait_at_direct_business_send_gate_for_test().await;
    }
    if let Some(trace) = retry_packet.trace.as_ref() {
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
            "tx_slow_path_encrypt_us",
            encrypt_completed.duration_since(encrypt_started),
        );
    }
    let transport_handoff_started = Instant::now();
    let outcome = send_encrypted_packet_bounded(
        &encrypted,
        peers,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        sampled_trace.as_ref().map(|trace| trace.sampled),
        direct_business_plan.as_ref(),
        complete_inner_ip_packet_len(&retry_packet.packet).unwrap_or(retry_packet.packet.len()),
        force_relay,
    )
    .await;
    let transport_handoff_completed = Instant::now();
    if let Some(trace) = retry_packet.trace.as_ref() {
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
            "tx_slow_path_total_userspace_us",
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
            &retry_packet.peer_id,
            "slow_path",
            total_userspace_tx,
            DataplaneTailMetrics {
                queue_wait_us,
                emit_guard_wait_us: emit_guard_acquired
                    .duration_since(emit_lock_started)
                    .as_micros() as u64,
                emit_guard_hold_us: transport_handoff_completed
                    .duration_since(emit_guard_acquired)
                    .as_micros() as u64,
                ..DataplaneTailMetrics::default()
            },
            profiler.candidate_gather_active(),
            expected_generation,
        );
        if total_userspace_tx >= crate::dataplane::DATAPLANE_STALL_THRESHOLD {
            debug!(
                event = "dataplane_stall",
                peer_id = %retry_packet.peer_id,
                active_path = if peers.is_direct_sync(&retry_packet.peer_id) { "direct" } else { "relay_or_unknown" },
                tun_to_send_us = total_userspace_tx.as_micros() as u64,
                receive_to_tun_us = 0u64,
                candidate_gather_active = profiler.candidate_gather_active(),
                network_generation = expected_generation,
                "outbound encrypted dataplane packet exceeded the diagnostic stall threshold"
            );
        }
    }
    if let Some((nonce, sequence, direction)) = overlay_packet_identity(&retry_packet.packet) {
        let outcome_label = match &outcome {
            SendOutcome::Sent => "sent",
            SendOutcome::Retryable(_) => "retryable",
            SendOutcome::RetryableLocalBackpressure { .. } => "local_backpressure",
            SendOutcome::Terminal(_) | SendOutcome::LocalMtuFailure { .. } => "terminal",
            SendOutcome::DirectBudgetStale { .. } => "stale_budget",
        };
        debug!(
            event = "outbound_overlay_transport_result",
            peer_id = %retry_packet.peer_id,
            nonce = format_args!("{nonce:#x}"),
            sequence,
            direction,
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&encrypted.wire_bytes)),
            counter = ?crate::transport::wire_counter(&encrypted.wire_bytes),
            outcome = outcome_label,
            "encrypted overlay packet reached a classified transport outcome"
        );
    }
    // The guard is deliberately released before any asynchronous retry is
    // queued. A retry is always the original plaintext and receives a fresh
    // WireGuard counter.
    drop(emit_guard);
    match outcome {
        SendOutcome::Sent => EncryptSendOutcome::Sent,
        SendOutcome::Retryable(failure) => EncryptSendOutcome::Retryable {
            packet: retry_packet,
            reason_code: failure.reason_code(),
            reason: failure.reason(),
        },
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain { reason, err }) => {
            EncryptSendOutcome::Terminal {
                packet: retry_packet,
                reason_code: reason,
                reason: err,
            }
        }
        SendOutcome::DirectBudgetStale { reason } => EncryptSendOutcome::Retryable {
            packet: retry_packet,
            reason_code: REASON_DIRECT_BUDGET_STALE,
            reason,
        },
        SendOutcome::RetryableLocalBackpressure { reason } => {
            EncryptSendOutcome::RetryableLocalBackpressure {
                packet: retry_packet,
                reason,
            }
        }
        SendOutcome::LocalMtuFailure {
            reason_code,
            reason,
            inner_ip_mtu,
        } => {
            let feedback = peers.emit_local_mtu_feedback(
                &retry_packet.peer_id,
                &retry_packet.packet,
                crate::business_mtu::LocalMtuFeedbackKind::PacketTooBig { inner_ip_mtu },
            );
            EncryptSendOutcome::Terminal {
                packet: retry_packet,
                reason_code,
                reason: format!("{reason}; feedback={feedback:?}"),
            }
        }
    }
}

/// Send one encrypted packet with a hard time bound so a stalled relay cannot
/// block the shared outbound worker. The caller owns the per-peer emit guard
/// and releases it immediately after this classification returns.
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_encrypted_packet_bounded(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
    sampled: Option<bool>,
    direct_business_plan: Option<&DirectBusinessSendPlan>,
    inner_ip_packet_len: usize,
    force_relay: bool,
) -> SendOutcome {
    // Capture the exact shared connection before entering the bounded send.
    // The same snapshot is passed into the send operation, so a supervisor
    // replacement cannot make the timeout abort one relay while the packet is
    // actually blocked on another. The replacement remains available for the
    // next plaintext retry.
    let profiler = global_dataplane_profiler();
    let relay_read_started = Instant::now();
    let relay_guard = relay_transport.read().await;
    let relay_read_acquired = Instant::now();
    let relay_for_send = relay_guard.clone();
    let relay_read_hold = relay_read_acquired.elapsed();
    drop(relay_guard);
    if let Some(sampled) = sampled {
        profiler.record(
            sampled,
            "tx_relay_transport_rwlock_wait_us",
            relay_read_acquired.duration_since(relay_read_started),
        );
        profiler.record(
            sampled,
            "tx_relay_transport_rwlock_hold_us",
            relay_read_hold,
        );
    }
    let relay_at_start = relay_for_send.clone();
    let relay_send_started = AtomicBool::new(false);
    match timeout(
        OUTBOUND_SEND_TIMEOUT,
        send_encrypted_packet_once(
            packet,
            peers,
            prefer_direct,
            udp_transport,
            relay_for_send,
            &relay_send_started,
            relay_expected,
            sampled,
            direct_business_plan,
            inner_ip_packet_len,
            force_relay,
        ),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            if relay_send_started.load(Ordering::Acquire) {
                if let Some(relay) = relay_at_start {
                    relay.abort_writer();
                }
            }
            // UDP `send_to` normally completes immediately, but classify the
            // timeout from the committed state as well: a Direct timeout is
            // not a relay writer timeout, and the loss counters must preserve
            // that distinction for incident diagnosis.
            let reason = if relay_send_started.load(Ordering::Acquire) {
                REASON_RELAY_DELIVERY_UNCERTAIN
            } else if peers.is_direct_sync(&packet.peer_id) && prefer_direct {
                REASON_DIRECT_DELIVERY_UNCERTAIN
            } else {
                REASON_PATH_UNAVAILABLE
            };
            warn!(
                event = "outbound_send_timeout",
                peer_id = %packet.peer_id,
                reason_code = reason,
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                bytes = packet.wire_bytes.len(),
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                relay_send_started = relay_send_started.load(Ordering::Acquire),
                "encrypted packet exceeded the bounded transport send deadline and is terminal"
            );
            outbound_send_timeout_failure_for_path(reason)
        }
    }
}

pub(super) fn outbound_send_timeout_failure_for_path(reason: &'static str) -> SendOutcome {
    // A timeout does not tell us whether the relay accepted the ciphertext.
    // The caller therefore terminally consumes this counter and records the
    // original plaintext as a loss; it must never re-encrypt/retry this packet.
    SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
        reason,
        err: "outbound send timed out".to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_encrypted_packet_once(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay: Option<RelayTransport>,
    relay_send_started: &AtomicBool,
    relay_expected: bool,
    sampled: Option<bool>,
    direct_business_plan: Option<&DirectBusinessSendPlan>,
    inner_ip_packet_len: usize,
    force_relay: bool,
) -> SendOutcome {
    let profiler = global_dataplane_profiler();
    // Take one path/generation snapshot atomically. Managed Direct keeps this
    // gate through its synchronous UDP handoff; legacy Direct and Relay keep
    // the historical async behavior after releasing it.
    let (generation, relay_peer_confirmed, udp, udp_local_endpoint, selection) = {
        let epoch_gate = peers.network_epoch_gate();
        let epoch_gate_wait_started = Instant::now();
        let _epoch_guard = epoch_gate.lock().await;
        let epoch_gate_acquired = Instant::now();
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_epoch_gate_wait_us",
                epoch_gate_acquired.duration_since(epoch_gate_wait_started),
            );
        }
        let generation = peers.current_network_generation_sync();
        let relay_peer_confirmed = peers
            .is_relay_business_admitted_in_epoch(&_epoch_guard, &packet.peer_id, generation)
            .await;
        let relay_available = relay.is_some();
        let udp_read_started = Instant::now();
        let udp_guard = udp_transport.read().await;
        let udp_read_acquired = Instant::now();
        let udp = udp_guard.clone();
        let udp_read_hold = udp_read_acquired.elapsed();
        drop(udp_guard);
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_udp_transport_rwlock_wait_us",
                udp_read_acquired.duration_since(udp_read_started),
            );
            profiler.record(sampled, "tx_udp_transport_rwlock_hold_us", udp_read_hold);
        }
        let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
        let selection = select_outbound_path(
            packet,
            peers,
            prefer_direct,
            relay_available,
            relay_expected,
            udp_local_endpoint,
            force_relay,
        )
        .await;
        debug!(
            event = "outbound_transport_handoff_started",
            peer_id = %packet.peer_id,
            generation,
            counter = ?crate::transport::wire_counter(&packet.wire_bytes),
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
            selected_path = ?selection.path,
            direct_confirmed = selection.direct_confirmed,
            relay_peer_confirmed,
            relay_connection_id = relay.as_ref().map(RelayTransport::connection_id),
            relay_endpoint = relay.as_ref().map(RelayTransport::endpoint),
            "encrypted packet is entering the selected transport handoff"
        );
        if let Some(plan) = direct_business_plan {
            let token = &plan.prepared.token;
            let current_udp_matches = udp.as_ref().is_some_and(|current| {
                current.transport_instance_id() == token.path_identity.socket.transport_instance_id
                    && current.inbound_publication_owner() == token.udp_publication_owner
            });
            let exact_selection = selection.path == Some(NetworkPath::Direct)
                && selection.direct_confirmed
                && selection.direct_endpoint
                    == Some(token.path_identity.authenticated_remote_endpoint);
            if !current_udp_matches
                || !exact_selection
                || !peers.dplpmtud_path_is_current_sync(&token.path_identity)
            {
                if let Some(sampled) = sampled {
                    profiler.record(
                        sampled,
                        "tx_epoch_gate_hold_us",
                        epoch_gate_acquired.elapsed(),
                    );
                }
                return SendOutcome::DirectBudgetStale {
                    reason: format!(
                        "Direct identity changed after encryption: current_udp_matches={current_udp_matches} exact_selection={exact_selection}"
                    ),
                };
            }
            let send_started = Instant::now();
            // Linearization point: the network-epoch guard above prevents an
            // active-path replacement, while the runtime's independent
            // publication gate orders revision/owner revocation against this
            // one nonblocking `try_send_to` syscall.
            let send_result = plan
                .udp
                .try_send_direct_business_packet(&plan.prepared, packet);
            if let Some(sampled) = sampled {
                profiler.record(sampled, "udp_send_call_us", send_started.elapsed());
                profiler.record(
                    sampled,
                    "tx_epoch_gate_hold_us",
                    epoch_gate_acquired.elapsed(),
                );
            }
            return match send_result {
                Ok(_) => SendOutcome::Sent,
                Err(DirectBusinessUdpSendError::StaleToken) => SendOutcome::DirectBudgetStale {
                    reason: "Direct budget/path/publication changed at UDP linearization"
                        .to_string(),
                },
                Err(DirectBusinessUdpSendError::WouldBlock) => {
                    SendOutcome::RetryableLocalBackpressure {
                        reason: "exact UDP socket would block before handoff".to_string(),
                    }
                }
                Err(DirectBusinessUdpSendError::LocalPacketTooLarge) => {
                    let invalidated = plan.udp.invalidate_direct_business_budget(token);
                    SendOutcome::LocalMtuFailure {
                        reason_code: REASON_DIRECT_BUSINESS_EMSGSIZE,
                        reason: format!(
                            "kernel returned EMSGSIZE; exact budget invalidated={invalidated}"
                        ),
                        inner_ip_mtu: token.max_overlay_payload_size.0,
                    }
                }
                Err(DirectBusinessUdpSendError::CiphertextTooLarge) => {
                    let invalidated = plan.udp.invalidate_direct_business_budget(token);
                    SendOutcome::LocalMtuFailure {
                        reason_code: REASON_DIRECT_CIPHERTEXT_OVERSIZE,
                        reason: format!(
                            "actual ciphertext exceeded confirmed UDP budget at final boundary; exact budget invalidated={invalidated}"
                        ),
                        inner_ip_mtu: token.max_overlay_payload_size.0,
                    }
                }
                Err(
                    error @ (DirectBusinessUdpSendError::Io(_)
                    | DirectBusinessUdpSendError::Short { .. }),
                ) => {
                    // Preserve the historical Direct health behavior for
                    // genuine I/O/short-send failures. The typed EMSGSIZE,
                    // stale-token and local size fences above deliberately do
                    // not enter this branch. Release the epoch guard before
                    // the path-state reducer acquires it again.
                    drop(_epoch_guard);
                    peers
                        .record_direct_failure_with_code_and_local_endpoint(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            error.to_string(),
                            udp_local_endpoint,
                        )
                        .await;
                    SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                        reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
                        err: error.to_string(),
                    })
                }
            };
        }
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_epoch_gate_hold_us",
                epoch_gate_acquired.elapsed(),
            );
        }
        (
            generation,
            relay_peer_confirmed,
            udp,
            udp_local_endpoint,
            selection,
        )
    };

    if selection.direct_confirmed {
        if udp
            .as_ref()
            .is_some_and(|udp| udp.peer_requires_direct_business_budget(&packet.peer_id))
        {
            return SendOutcome::DirectBudgetStale {
                reason: "managed Direct became selected without a pre-encryption token".to_string(),
            };
        }
        match send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint, sampled)
            .await
        {
            DirectSendOutcome::HandoffAccepted => return SendOutcome::Sent,
            DirectSendOutcome::DeliveryUncertain { err } => {
                // The Direct counter may have reached the kernel. Never send
                // this ciphertext over Relay; terminally account this packet
                // and let later plaintext entries receive fresh counters.
                return SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                    reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
                    err,
                });
            }
            DirectSendOutcome::NotHanded { err } => {
                // No Direct handoff occurred, so a confirmed Relay may safely
                // carry this same ciphertext without replaying its counter.
                if relay_peer_confirmed {
                    if let Some(relay) = relay {
                        return send_via_relay(
                            &relay,
                            packet,
                            peers,
                            generation,
                            relay_send_started,
                            sampled,
                        )
                        .await;
                    }
                }
                return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
                    reason: format!("confirmed Direct was not handed off: {err}"),
                    reason_code: REASON_PATH_UNAVAILABLE,
                });
            }
            DirectSendOutcome::PacketTooLarge { err } => {
                let conservative_inner_mtu = inner_ip_packet_len
                    .saturating_sub(1)
                    .min(
                        crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE as usize
                            - crate::dplpmtud::WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize,
                    )
                    .max(68) as u32;
                return SendOutcome::LocalMtuFailure {
                    reason_code: REASON_DIRECT_BUSINESS_EMSGSIZE,
                    reason: format!(
                        "legacy/unmanaged Direct UDP send returned typed EMSGSIZE: {err}"
                    ),
                    inner_ip_mtu: conservative_inner_mtu,
                };
            }
        }
    }

    // Until Direct is confirmed by decrypted traffic, Relay is the only
    // business data-plane.  It must also be peer-confirmed: a relay client
    // connection or writer completion is not enough to admit a counter.
    if relay_peer_confirmed {
        if let Some(relay) = relay {
            return send_via_relay(
                &relay,
                packet,
                peers,
                generation,
                relay_send_started,
                sampled,
            )
            .await;
        }
        return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
            reason: "relay peer was confirmed but relay transport is unavailable".to_string(),
            reason_code: REASON_PATH_UNAVAILABLE,
        });
    }
    // A candidate RTT / Direct trial is not a data-plane admission proof.
    // Keep the raw packet queued until Relay or a real Direct ACK exists.
    SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
        reason: selection.reason,
        reason_code: selection.reason_code,
    })
}

pub(super) async fn select_outbound_path(
    packet: &EncryptedPeerPacket,
    peers: &PeerManager,
    prefer_direct: bool,
    relay_available: bool,
    relay_expected: bool,
    udp_local_endpoint: Option<SocketAddr>,
    force_relay: bool,
) -> PathSelection {
    // Queue admission already treats a configured relay as an active
    // relay-first gate before the transport object is published.  The
    // send-time selector must see the same fact; otherwise a confirmed
    // Direct can consume a WireGuard counter while the relay is still
    // connecting.  The actual `relay` Option remains separate in the caller,
    // so this flag can never make us call send_packet on a non-existent
    // transport.
    let relay_for_selection = relay_available || relay_expected;
    let selection = peers
        .select_path_for_data_with_local_endpoint_in_epoch(
            &packet.peer_id,
            prefer_direct,
            relay_for_selection,
            udp_local_endpoint,
            peers.current_network_generation_sync(),
            force_relay,
        )
        .await;
    debug!(
        event = "outbound_path_decision",
        peer_id = %packet.peer_id,
        generation = peers.current_network_generation_sync(),
        relay_available,
        relay_expected,
        path = ?selection.path,
        direct_confirmed = selection.direct_confirmed,
        relay_hedged = selection.relay_hedged,
        reason_code = selection.reason_code,
        counter = ?crate::transport::wire_counter(&packet.wire_bytes),
        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
        "outbound path decision: path={:?} relay_hedged={} reason_code={} reason={}",
        selection.path,
        selection.relay_hedged,
        selection.reason_code,
        selection.reason
    );
    selection
}

#[cfg(test)]
#[path = "tests/send.rs"]
mod tests;
