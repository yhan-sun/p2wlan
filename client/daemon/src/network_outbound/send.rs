use super::*;
use crate::dataplane::{DeferredOutboundPreparationProfile, OutboundPreparationStage};

/// Compatibility entry for unit tests of one isolated send. The worker
/// supplies the FIFO's original deadline through the bounded entry below.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn encrypt_then_send(
    packet: impl Into<RawRequestDelivery> + Send,
    transport: &WireGuardTransport,
    peers: &PeerManager,
    expected_generation: u64,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
) -> EncryptSendOutcome {
    encrypt_then_send_with_deadline(
        packet,
        transport,
        peers,
        expected_generation,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        None,
        None,
    )
    .await
}

/// Encrypt a RAW packet (holding the peer's emit lock) and send it while the
/// guard is still held.
#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt_then_send_with_deadline<'a>(
    packet: impl Into<RawRequestDelivery> + Send + 'a,
    transport: &'a WireGuardTransport,
    peers: &'a PeerManager,
    expected_generation: u64,
    prefer_direct: bool,
    udp_transport: &'a RwLock<Option<UdpTransport>>,
    relay_transport: &'a RwLock<Option<RelayTransport>>,
    relay_expected: bool,
    admission_deadline: Option<Instant>,
    stopping: Option<&'a AtomicBool>,
) -> impl std::future::Future<Output = EncryptSendOutcome> + Send + 'a {
    // Return a small heap-owned frame to callers that nest several sends.
    // Boxing acquires no guards; original clocks still start on first poll.
    Box::pin(encrypt_then_send_bounded(
        packet,
        transport,
        peers,
        expected_generation,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        admission_deadline,
        stopping,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn encrypt_then_send_bounded(
    packet: impl Into<RawRequestDelivery> + Send,
    transport: &WireGuardTransport,
    peers: &PeerManager,
    expected_generation: u64,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
    admission_deadline: Option<Instant>,
    stopping: Option<&AtomicBool>,
) -> EncryptSendOutcome {
    // This outer owner outlives preparation (including its cancellation) and
    // the physical attempt. A selector log never calls subscribers while this
    // operation still owns its original epoch, connection or emit guard.
    let mut path_log = crate::peer::DeferredPathSelectionLog::default();
    let mut packet = packet.into();
    packet.observe_resources(
        transport.resource_capture(),
        crate::dataplane_resources::ResidencyStage::DetachedRaw,
    );
    let original_buffer_lease = crate::dataplane_resources::OwnedBufferLease::observe(
        transport.resource_capture(),
        crate::dataplane_resources::BufferStage::ActiveOriginal,
        &packet.packet,
    );
    let mut retry_packet = packet.clone();
    retry_packet.relocate_resources(crate::dataplane_resources::ResidencyStage::RetryPlaintext);
    let _retry_buffer_lease = crate::dataplane_resources::OwnedBufferLease::observe(
        transport.resource_capture(),
        crate::dataplane_resources::BufferStage::RetryPlaintext,
        &retry_packet.packet,
    );
    if let Some(capture) = transport.resource_capture() {
        let _ = capture.observe_vec(
            crate::dataplane_resources::VecSite::TxRetryCopy,
            crate::dataplane_resources::VecOperation::DeepClone,
            Some(retry_packet.packet.len()),
            &retry_packet.packet,
        );
    }
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
    let mut preparation_retry = retry_packet.clone();
    preparation_retry
        .relocate_resources(crate::dataplane_resources::ResidencyStage::PreparationPlaintext);
    let preparation_buffer_lease = crate::dataplane_resources::OwnedBufferLease::observe(
        transport.resource_capture(),
        crate::dataplane_resources::BufferStage::PreparationPlaintext,
        &preparation_retry.packet,
    );
    if let Some(capture) = transport.resource_capture() {
        let _ = capture.observe_vec(
            crate::dataplane_resources::VecSite::TxPreparationCopy,
            crate::dataplane_resources::VecOperation::DeepClone,
            Some(preparation_retry.packet.len()),
            &preparation_retry.packet,
        );
    }
    let preparation_bound = admission_deadline.map_or(OUTBOUND_SEND_TIMEOUT, |deadline| {
        deadline
            .saturating_duration_since(Instant::now())
            .min(OUTBOUND_SEND_TIMEOUT)
    });
    if preparation_bound.is_zero() {
        return EncryptSendOutcome::Terminal {
            packet: retry_packet,
            reason_code: REASON_OUTBOUND_DELIVERY_DEADLINE,
            reason: "original FIFO deadline expired before encryption/handoff".into(),
        };
    }
    // These scalar diagnostics outlive the cancellable preparation and actual
    // physical owner. Original observation sites retain values and clocks;
    // histogram/logger callbacks run after this attempt releases its guards.
    let mut preparation_profile = DeferredOutboundPreparationProfile::new(profiler);
    let mut crypto_profile = crate::dataplane::DeferredCryptoProfile::new(profiler);
    let mut epoch_profile = crate::dataplane::DeferredEpochProfile::new(
        profiler,
        sampled_trace.as_ref().is_some_and(|trace| trace.sampled),
    );
    let mut preparation_log = super::preparation_log::DeferredPreparationLog::new(
        packet.peer_id.clone(),
        expected_generation,
    );
    let mut encryption_log = crate::transport::DeferredEncryptionLog::new(packet.peer_id.clone());
    // This future contains no UDP syscall or Relay writer admission. A
    // cancellation may abandon an allocated counter, but its ciphertext has
    // never been handed off, so only the original plaintext can be retried.
    let prepare = async {
        // These move-only leases are owned by the same preparation future as
        // the corresponding buffers, including cancellation before encryption.
        let original_buffer_lease = original_buffer_lease;
        let _preparation_buffer_lease = preparation_buffer_lease;
        // These are resource snapshots, never a path or generation fence.
        // A slot replacement must not make original read observation wait
        // behind an epoch guard held by this pre-encryption preparation.
        // The unchanged epoch transaction below validates generation/path;
        // actual budget, socket and native handoff fences remain authoritative.
        let relay_available = relay_transport.read().await.is_some();
        let udp = udp_transport.read().await.clone();
        // Resolve only the resource named by the current committed tuple
        // before entering the original epoch transaction. Its canonical
        // generation/path/budget checks still run below. Exact socket and
        // lease-owner identity are rechecked before consuming this hint;
        // any mismatch or busy registry retains the original resolver.
        // At most one extra lease lives within the original preparation
        // timeout, including cancellation and the unchanged fallback.
        let mut committed_socket_resource = if prefer_direct
            && peers.current_network_generation_sync() == expected_generation
            && !preparation_retry
                .original_echo()
                .is_some_and(|echo| echo.source().original_relay_read().is_some())
        {
            if let Some(udp) = udp.as_ref() {
                udp.try_prepare_direct_business_socket_resource(&preparation_retry.peer_id)
            } else {
                None
            }
        } else {
            None
        };
        let prepared_read_view = peers.prepare_original_kernel_read_view(
            &preparation_retry.peer_id,
            &preparation_retry.dst_ip,
        );
        let emit_lock_started = Instant::now();
        let emit_guard = Arc::new(transport.acquire_outbound_emit_guard(&packet.peer_id).await);
        let emit_guard_acquired = Instant::now();
        let emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64;
        if let Some(trace) = sampled_trace.as_ref() {
            preparation_profile.record(
                trace.sampled,
                OutboundPreparationStage::EmitWait,
                emit_guard_acquired.duration_since(emit_lock_started),
            );
        }
        preparation_log.acquired(emit_lock_wait_ms);
        // Resolve this owned primary socket before the epoch transaction.
        // The original generation/path/budget and final owner fences remain.
        let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
        // Materialize real wire storage after the original emit turn and endpoint
        // query. Emit wait retains only its original plaintext buffer budget;
        // the same outer timeout/cancellation owner covers this allocation.
        let prepared_wire = match crate::transport::PreparedEncryptionBuffer::new(
            packet.packet.len(),
            transport.resource_capture(),
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(EncryptSendOutcome::Terminal {
                    packet: preparation_retry,
                    reason_code: REASON_OUTBOUND_ENCRYPT_FAILED,
                    reason: error.to_string(),
                })
            }
        };
        let (
            encrypted,
            direct_business_plan,
            force_relay,
            physical_preparation,
            serialized_buffer_lease,
        ) = {
            let epoch_gate_wait_started = Instant::now();
            let (_epoch_guard, path_connections) = peers.lock_epoch_and_connections_write().await;
            let epoch_gate_acquired = Instant::now();
            if sampled_trace.is_some() {
                epoch_profile.waited(epoch_gate_acquired.duration_since(epoch_gate_wait_started));
            }
            _epoch_guard.note_outbound_phase(crate::peer::OutboundEpochPhase::Generation);
            let current_generation = peers.current_network_generation_sync();
            if current_generation != expected_generation {
                drop(path_connections);
                preparation_log.generation_rejected(current_generation);
                return Err(EncryptSendOutcome::Retryable {
                packet: preparation_retry,
                reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
                reason: format!(
                    "network generation advanced before counter allocation: expected={expected_generation} current={current_generation}"
                ),
            });
            }
            let Some((mut _epoch_guard, selection)) = peers
                .select_path_with_original_identity_epoch(
                    _epoch_guard,
                    path_connections,
                    prepared_read_view,
                    &preparation_retry.peer_id,
                    prefer_direct,
                    relay_available || relay_expected,
                    udp_local_endpoint,
                    current_generation,
                    false,
                    Some(&mut path_log),
                )
            else {
                return Err(EncryptSendOutcome::Terminal {
                    packet: preparation_retry,
                    reason_code: "outbound_preparation_owner_changed",
                    reason: "original preparation grants have a different owner".into(),
                });
            };
            _epoch_guard.note_outbound_phase(crate::peer::OutboundEpochPhase::DirectBudget);
            let mut force_relay = false;
            // A sealed Relay REQUEST echo must use its original Relay writer.
            // Direct may have won since ingress, but cannot validate a Relay
            // read as an original UDP read at its final write boundary.
            let original_relay_echo = preparation_retry
                .original_echo()
                .is_some_and(|echo| echo.source().original_relay_read().is_some());
            let direct_business_plan = if !original_relay_echo
                && selection.path == Some(NetworkPath::Direct)
                && selection.direct_confirmed
            {
                match (udp, selection.direct_endpoint) {
                    (Some(udp), Some(endpoint)) => {
                        match udp
                            .prepare_direct_business_send_with_resource(
                                &preparation_retry.peer_id,
                                endpoint,
                                &mut committed_socket_resource,
                            )
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
                                    &preparation_retry.peer_id,
                                    current_generation,
                                    relay_available,
                                    reason,
                                )
                                .await
                                {
                                    return Err(EncryptSendOutcome::BudgetPending {
                                        packet: preparation_retry,
                                        reason: format!(
                                        "Direct DPLPMTUD budget pending before encryption: {reason}"
                                    ),
                                    });
                                }
                                force_relay = true;
                                None
                            }
                            DirectBusinessBudgetGate::Ready(prepared) => {
                                let Some(inner_len) =
                                    complete_inner_ip_packet_len(&preparation_retry.packet)
                                else {
                                    return Err(EncryptSendOutcome::Terminal {
                                        packet: preparation_retry,
                                        reason_code: REASON_DIRECT_BUSINESS_MALFORMED,
                                        reason:
                                            "managed Direct packet is not one complete IP packet"
                                                .to_string(),
                                    });
                                };
                                let overlay_budget =
                                    prepared.token.max_overlay_payload_size.0 as usize;
                                if preparation_retry.packet[0] >> 4 == 6
                                    && overlay_budget
                                        < crate::business_mtu::IPV6_MINIMUM_MTU as usize
                                {
                                    return Err(EncryptSendOutcome::Terminal {
                                    packet: preparation_retry,
                                    reason_code: REASON_IPV6_BUDGET_BELOW_MINIMUM_MTU,
                                    reason: format!(
                                        "inner IPv6 business traffic requires an advertised MTU of at least {}; confirmed inner budget is {overlay_budget}; no UDP handoff or invalid Packet Too Big was produced",
                                        crate::business_mtu::IPV6_MINIMUM_MTU,
                                    ),
                                });
                                }
                                if inner_len > overlay_budget {
                                    let feedback = peers.emit_local_mtu_feedback(
                                        &preparation_retry.peer_id,
                                        &preparation_retry.packet,
                                        crate::business_mtu::LocalMtuFeedbackKind::PacketTooBig {
                                            inner_ip_mtu: prepared.token.max_overlay_payload_size.0,
                                        },
                                    );
                                    return Err(EncryptSendOutcome::Terminal {
                                    packet: preparation_retry,
                                    reason_code: REASON_DIRECT_BUDGET_OVERSIZE,
                                    reason: format!(
                                        "inner IP packet {inner_len} exceeds confirmed overlay budget {overlay_budget}; feedback={feedback:?}"
                                    ),
                                });
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
                            &preparation_retry.peer_id,
                            current_generation,
                            relay_available,
                            "Direct selected without a published UDP endpoint/socket",
                        )
                        .await
                        {
                            return Err(EncryptSendOutcome::BudgetPending {
                                packet: preparation_retry,
                                reason: "Direct selected without a published UDP endpoint/socket"
                                    .to_string(),
                            });
                        }
                        force_relay = true;
                        None
                    }
                }
            } else {
                None
            };
            _epoch_guard.note_outbound_phase(crate::peer::OutboundEpochPhase::OriginalEcho);
            if let Some(echo) = packet.original_echo() {
                if packet.binding().is_none_or(|binding| {
                    binding.state() != crate::request_carriage::RequestBindingState::RoutedExact
                }) || !echo.exact_route_for_owner(peers, &packet, Instant::now())
                {
                    return Err(EncryptSendOutcome::Terminal {
                        packet: preparation_retry,
                        reason_code: "original_echo_input_changed",
                        reason: "sealed original echo bytes or route changed before encryption"
                            .into(),
                    });
                }
                if let Err(reason) = peers.try_qualify_original_echo_input_in_epoch(transport, echo)
                {
                    if let crate::overlay_requests::OverlayCreditOutcome::Contended(site) = reason {
                        // No encryption, counter allocation or handoff has
                        // happened. Return the same sealed plaintext to its
                        // existing FIFO, whose retry pacing and original
                        // deadline remain authoritative. The next attempt
                        // must qualify the original source again.
                        return Err(EncryptSendOutcome::Retryable {
                            packet: preparation_retry,
                            reason_code: REASON_ORIGINAL_ECHO_SOURCE_CONTENDED,
                            reason: format!(
                                "original REQUEST source contended before encryption: {site:?}"
                            ),
                        });
                    }
                    return Err(EncryptSendOutcome::Terminal {
                        packet: preparation_retry,
                        reason_code: "original_echo_source_rejected",
                        reason: format!(
                            "original REQUEST source rejected before encryption: {reason:?}"
                        ),
                    });
                }
            }
            _epoch_guard.note_outbound_phase(crate::peer::OutboundEpochPhase::Encryption);
            _epoch_guard.begin_encryption();
            let mut result = match transport
                .encrypt_request_with_prepared_buffer_diagnostics(
                    packet,
                    prepared_wire,
                    Some(&mut crypto_profile),
                    Some(&mut encryption_log),
                )
                .await
            {
                Ok(Some(value)) => value,
                Ok(None) => {
                    preparation_log.missing_session(preparation_retry.packet.len());
                    return Err(EncryptSendOutcome::Retryable {
                        packet: preparation_retry,
                        reason_code: REASON_OUTBOUND_SESSION_NOT_READY,
                        reason: "WireGuard session is not ready".to_string(),
                    });
                }
                Err(err) => {
                    let reason = err.to_string();
                    preparation_log
                        .encryption_failed(preparation_retry.packet.len(), reason.clone());
                    return Err(EncryptSendOutcome::Terminal {
                        packet: preparation_retry,
                        reason_code: REASON_OUTBOUND_ENCRYPT_FAILED,
                        reason,
                    });
                }
            };
            let _epoch_guard = _epoch_guard.finish();
            _epoch_guard.note_outbound_phase(crate::peer::OutboundEpochPhase::PhysicalMetadata);
            // The original plaintext has been consumed by the crypto call.
            // Bind the returned wire owner before any further awaited work.
            drop(original_buffer_lease);
            let serialized_buffer_lease = crate::dataplane_resources::OwnedBufferLease::observe(
                transport.resource_capture(),
                crate::dataplane_resources::BufferStage::SerializedWire,
                &result.wire_bytes,
            );
            result.bind_original_echo_emit(&emit_guard);
            let physical_preparation =
                result.prepare_physical_publication(peers, transport, current_generation);
            if sampled_trace.is_some() {
                epoch_profile.held(epoch_gate_acquired.elapsed());
            }
            if selection.path == Some(NetworkPath::Direct)
                && selection.direct_confirmed
                && !force_relay
            {
                _epoch_guard.note_outbound_phase(crate::peer::OutboundEpochPhase::DirectFirst);
                if let Some(endpoint) = selection.direct_endpoint {
                    peers
                        .satisfy_direct_first_in_epoch(
                            &_epoch_guard,
                            &preparation_retry.peer_id,
                            current_generation,
                            endpoint,
                        )
                        .await;
                }
            }
            (
                result,
                direct_business_plan,
                force_relay,
                physical_preparation,
                serialized_buffer_lease,
            )
        };
        Ok((
            emit_guard,
            encrypted,
            direct_business_plan,
            force_relay,
            emit_lock_started,
            emit_guard_acquired,
            physical_preparation,
            serialized_buffer_lease,
        ))
    };
    let (emit_guard, encrypted, direct_business_plan, force_relay, emit_lock_started, emit_guard_acquired, physical_preparation, _serialized_buffer_lease) =
        match timeout(preparation_bound, prepare).await {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(outcome)) => return outcome,
            Err(_) => return EncryptSendOutcome::Retryable {
                packet: retry_packet,
                reason_code: REASON_OUTBOUND_ADMISSION_TIMEOUT,
                reason: "bounded pre-handoff emit/epoch/slot/session admission timed out; no transport owned ciphertext".into(),
            },
        };
    let mut physical_attempt = PhysicalAttempt::new(emit_guard, physical_preparation);
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
            physical_attempt.finish(true);
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
        preparation_profile.record(
            trace.sampled,
            OutboundPreparationStage::TunToEncrypt,
            encrypt_started.duration_since(trace.tun_read_completed),
        );
        if let Some(route_ready) = trace.route_ready {
            preparation_profile.record(
                trace.sampled,
                OutboundPreparationStage::RouteToEncrypt,
                encrypt_started.duration_since(route_ready),
            );
        }
        preparation_profile.record(
            trace.sampled,
            OutboundPreparationStage::Encrypt,
            encrypt_completed.duration_since(encrypt_started),
        );
        preparation_profile.record(
            trace.sampled,
            OutboundPreparationStage::SlowEncrypt,
            encrypt_completed.duration_since(encrypt_started),
        );
    }
    let window = SendAdmissionWindow {
        deadline: admission_deadline,
        stopping,
        expected_generation,
    };
    if let Some(reason_code) = window.rejection_reason() {
        return EncryptSendOutcome::Terminal {
            packet: retry_packet,
            reason_code,
            reason: "FIFO lifecycle ended after preparation and before transport handoff".into(),
        };
    }
    let transport_handoff_started = Instant::now();
    #[cfg(test)]
    transport.observe_request_handoff_for_test(
        &encrypted,
        crate::request_carriage::test_probe::HandoffArgumentPoint::SlowBoundedEntry,
    );
    #[cfg(test)]
    prepare_relay_capture_for_test(&encrypted, &mut physical_attempt);
    #[cfg(test)]
    transport
        .pause_worker_loss_for_test(
            crate::transport::WorkerLossPoint::BeforePhysicalHandoff,
            admission_deadline,
        )
        .await;
    let outcome = send_encrypted_packet_bounded_with_origin(
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
        window,
        Some(&mut physical_attempt),
    )
    .await;
    let transport_handoff_completed = Instant::now();
    // The inner send future has ended. Seal any remaining original result;
    // Relay already sealed before its post-send policy waits. Finish is idempotent.
    // Retain the original completion timestamp for every duration below.
    physical_attempt.finish(matches!(
        &outcome,
        SendOutcome::DirectBudgetStale { .. }
            | SendOutcome::RetryableLocalBackpressure { .. }
            | SendOutcome::LocalMtuFailure { .. }
    ));
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
        SendOutcome::RetryableLocalBackpressure { reason, socket } => {
            EncryptSendOutcome::RetryableLocalBackpressure {
                packet: retry_packet,
                reason,
                socket,
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

#[derive(Clone, Copy)]
struct SendAdmissionWindow<'a> {
    deadline: Option<Instant>,
    stopping: Option<&'a AtomicBool>,
    expected_generation: u64,
}

impl SendAdmissionWindow<'_> {
    fn rejection_reason(self) -> Option<&'static str> {
        if self
            .stopping
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Some(REASON_OUTBOUND_WORKER_STOPPED)
        } else if self.deadline.is_some_and(|at| at <= Instant::now()) {
            Some(REASON_OUTBOUND_DELIVERY_DEADLINE)
        } else {
            None
        }
    }

    fn rejected(self) -> Option<SendOutcome> {
        self.rejection_reason().map(|reason_code| {
            SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
                reason_code,
                reason: "original FIFO lifecycle ended before physical handoff".into(),
            })
        })
    }
}

/// Send one encrypted packet with a hard time bound so a stalled relay cannot
/// block the shared outbound worker. The caller owns the per-peer emit guard
/// and releases it immediately after this classification returns.
#[allow(dead_code)] // Retain the original None compatibility signature.
#[allow(clippy::too_many_arguments)]
async fn send_encrypted_packet_bounded(
    packet: &EncryptedRequestDelivery,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
    sampled: Option<bool>,
    direct_business_plan: Option<&DirectBusinessSendPlan>,
    inner_ip_packet_len: usize,
    force_relay: bool,
    window: SendAdmissionWindow<'_>,
) -> SendOutcome {
    send_encrypted_packet_bounded_with_origin(
        packet,
        peers,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        sampled,
        direct_business_plan,
        inner_ip_packet_len,
        force_relay,
        window,
        None,
    )
    .await
}

#[allow(dead_code)] // Retain the original None compatibility signature.
#[allow(clippy::too_many_arguments)]
async fn send_encrypted_packet_once(
    packet: &EncryptedRequestDelivery,
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
    window: SendAdmissionWindow<'_>,
) -> SendOutcome {
    send_encrypted_packet_once_with_origin(
        packet,
        peers,
        prefer_direct,
        udp_transport,
        relay,
        relay_send_started,
        relay_expected,
        sampled,
        direct_business_plan,
        inner_ip_packet_len,
        force_relay,
        window,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_encrypted_packet_bounded_with_origin(
    packet: &EncryptedRequestDelivery,
    peers: &PeerManager,
    prefer_direct: bool,
    udp_transport: &RwLock<Option<UdpTransport>>,
    relay_transport: &RwLock<Option<RelayTransport>>,
    relay_expected: bool,
    sampled: Option<bool>,
    direct_business_plan: Option<&DirectBusinessSendPlan>,
    inner_ip_packet_len: usize,
    force_relay: bool,
    window: SendAdmissionWindow<'_>,
    origin: Option<&mut super::physical_attempt::OutboundPhysicalAttempt>,
) -> SendOutcome {
    // Capture the exact shared connection before entering the bounded send.
    // The same snapshot is passed into the send operation, so a supervisor
    // replacement cannot make the timeout abort one relay while the packet is
    // actually blocked on another. The replacement remains available for the
    // next plaintext retry.
    let profiler = global_dataplane_profiler();
    let bounded_send_started = Instant::now();
    let relay_read_started = Instant::now();
    // No transport owns this ciphertext while only the slot snapshot waits.
    // Bound this phase separately from the terminal-aware physical send;
    // both phases share the original two-second transport-operation budget.
    if let Some(rejected) = window.rejected() {
        return rejected;
    }
    let slot_bound = window.deadline.map_or(OUTBOUND_SEND_TIMEOUT, |deadline| {
        deadline
            .saturating_duration_since(Instant::now())
            .min(OUTBOUND_SEND_TIMEOUT)
    });
    let relay_guard = match timeout(slot_bound, relay_transport.read()).await {
        Ok(guard) => guard,
        Err(_) => {
            return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
                reason_code: REASON_OUTBOUND_ADMISSION_TIMEOUT,
                reason: "Relay slot snapshot timed out before any physical handoff".into(),
            })
        }
    };
    let relay_read_acquired = Instant::now();
    let relay_for_send = relay_guard.clone();
    let relay_read_hold = relay_read_acquired.elapsed();
    drop(relay_guard);
    if let Some(rejected) = window.rejected() {
        return rejected;
    }
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
    let remaining = OUTBOUND_SEND_TIMEOUT.saturating_sub(bounded_send_started.elapsed());
    if remaining.is_zero() {
        return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
            reason_code: REASON_OUTBOUND_ADMISSION_TIMEOUT,
            reason: "send budget expired before entering the transport".into(),
        });
    }
    match timeout(
        remaining,
        send_encrypted_packet_once_with_origin(
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
            window,
            origin,
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
async fn send_encrypted_packet_once_with_origin(
    packet: &EncryptedRequestDelivery,
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
    window: SendAdmissionWindow<'_>,
    mut origin: Option<&mut super::physical_attempt::OutboundPhysicalAttempt>,
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
        if generation != window.expected_generation && direct_business_plan.is_none() {
            return SendOutcome::Retryable(RetryableSendFailure::NoSelectedPath {
                reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
                reason: "network generation changed after counter allocation, before handoff"
                    .into(),
            });
        }
        let relay_peer_confirmed = peers
            .is_relay_business_admitted_in_epoch(&_epoch_guard, &packet.peer_id, generation)
            .await;
        let relay_available = relay.is_some();
        let udp_read_started = Instant::now();
        let udp_guard = udp_transport.read().await;
        let udp_read_acquired = Instant::now();
        let udp = udp_guard.clone();
        let udp_read_hold = udp_read_acquired.elapsed();
        // Sourced Direct echoes retain the actual slot through the syscall.
        if !packet.has_original_echo() {
            drop(udp_guard);
        }
        if let Some(sampled) = sampled {
            profiler.record(
                sampled,
                "tx_udp_transport_rwlock_wait_us",
                udp_read_acquired.duration_since(udp_read_started),
            );
            profiler.record(sampled, "tx_udp_transport_rwlock_hold_us", udp_read_hold);
        }
        let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
        let original_relay_echo = packet
            .binding()
            .and_then(|binding| binding.token().echo())
            .is_some_and(|echo| echo.source().original_relay_read().is_some());
        let selection = if original_relay_echo {
            // Packet-specific return routing does not change the peer's
            // committed Direct owner. Relay admission and the original
            // reader/client/session prewrite fences still apply below.
            PathSelection::relay(
                "original_relay_echo_return",
                "sealed Relay REQUEST echo retains its original return writer",
            )
        } else {
            select_outbound_path(
                packet,
                peers,
                prefer_direct,
                relay_available,
                relay_expected,
                udp_local_endpoint,
                force_relay,
            )
            .await
        };
        // These authority/slot awaits still precede every syscall or writer
        // admission. After the check below, the physical operation owns its
        // existing terminal-aware timeout and is never externally replayed.
        if let Some(rejected) = window.rejected() {
            return rejected;
        }
        debug!(
            event = "outbound_transport_handoff_started",
            peer_id = %packet.peer_id,
            generation,
            counter = ?crate::transport::wire_counter(&packet.wire_bytes),
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
            selected_path = ?selection.path,
            reason_code = selection.reason_code,
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
            let send_result = if packet.has_original_echo() {
                packet
                    .original_echo_prewrite()
                    .ok_or(DirectBusinessUdpSendError::StaleToken)
                    .and_then(|prewrite| {
                        prewrite.try_send_direct_in_epoch(
                            &plan.udp,
                            Some(&plan.prepared),
                            packet,
                            plan.prepared.endpoint,
                        )
                    })
            } else {
                match origin.as_deref_mut().and_then(|owner| owner.capture()) {
                    Some(origin) => plan.udp.try_send_direct_business_packet_with_origin(
                        &plan.prepared,
                        packet,
                        Some(origin),
                    ),
                    None => plan
                        .udp
                        .try_send_direct_business_packet(&plan.prepared, packet),
                }
            };
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
                        socket: Some(plan.prepared.socket.clone()),
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
        if packet.has_original_echo() && selection.path == Some(NetworkPath::Direct) {
            let result = match (
                udp.as_ref(),
                selection.direct_endpoint,
                packet.original_echo_prewrite(),
            ) {
                (Some(udp), Some(endpoint), Some(prewrite)) if selection.direct_confirmed => {
                    prewrite.try_send_direct_in_epoch(udp, None, packet, endpoint)
                }
                _ => Err(DirectBusinessUdpSendError::StaleToken),
            };
            return match result {
                Ok(_) => SendOutcome::Sent,
                Err(DirectBusinessUdpSendError::WouldBlock) => {
                    SendOutcome::RetryableLocalBackpressure {
                        reason: "original echo receive/send publication contended".into(),
                        socket: None,
                    }
                }
                Err(DirectBusinessUdpSendError::StaleToken) => SendOutcome::DirectBudgetStale {
                    reason: "original REQUEST source is stale at Direct echo syscall".into(),
                },
                Err(error) => SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
                    reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
                    err: error.to_string(),
                }),
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
        let direct_result = match origin.as_deref_mut().and_then(|owner| owner.capture()) {
            Some(origin) => {
                send_direct_if_selected_with_origin(
                    packet,
                    peers,
                    udp,
                    &selection,
                    udp_local_endpoint,
                    sampled,
                    Some(origin),
                )
                .await
            }
            None => {
                send_direct_if_selected(packet, peers, udp, &selection, udp_local_endpoint, sampled)
                    .await
            }
        };
        match direct_result {
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
                        return send_original_relay_with_capture(
                            &relay,
                            packet,
                            peers,
                            generation,
                            relay_send_started,
                            sampled,
                            origin.as_deref_mut(),
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
            return send_original_relay_with_capture(
                &relay,
                packet,
                peers,
                generation,
                relay_send_started,
                sampled,
                origin,
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

#[cfg(test)]
#[path = "tests/resource_capture_send.rs"]
mod resource_capture_tests;

#[cfg(test)]
#[path = "tests/resource_capture_active_buffers.rs"]
mod resource_capture_active_buffers_tests;

#[cfg(test)]
#[path = "tests/prepared_crypto_send.rs"]
mod prepared_crypto_tests;

#[cfg(test)]
#[path = "tests/request_carriage_send.rs"]
mod request_carriage_tests;

#[cfg(test)]
#[path = "tests/physical_publication.rs"]
mod physical_publication_tests;

#[cfg(test)]
#[path = "tests/relay_publication.rs"]
mod relay_publication_tests;

async fn send_original_relay_with_capture(
    relay: &RelayTransport,
    packet: &EncryptedRequestDelivery,
    peers: &PeerManager,
    generation: u64,
    relay_send_started: &AtomicBool,
    sampled: Option<bool>,
    origin: Option<&mut super::physical_attempt::OutboundPhysicalAttempt>,
) -> SendOutcome {
    if packet.has_original_echo() {
        let Some(prewrite) = packet.original_echo_prewrite() else {
            return SendOutcome::DirectBudgetStale {
                reason: "original echo encryption/emit source unavailable".into(),
            };
        };
        return match origin {
            Some(owner) => {
                super::relay::send_via_relay_with_attempt(
                    relay,
                    packet,
                    peers,
                    generation,
                    relay_send_started,
                    sampled,
                    None,
                    Some(prewrite),
                    owner,
                )
                .await
            }
            None => {
                super::relay::send_via_relay_with_echo(
                    relay,
                    packet,
                    peers,
                    generation,
                    relay_send_started,
                    sampled,
                    prewrite,
                )
                .await
            }
        };
    }
    match origin {
        Some(owner) => {
            let capture = owner
                .slow_capture()
                .and_then(|storage| storage.relay(packet));
            super::relay::send_via_relay_with_attempt(
                relay,
                packet,
                peers,
                generation,
                relay_send_started,
                sampled,
                capture,
                None,
                owner,
            )
            .await
        }
        None => {
            send_via_relay(
                relay,
                packet,
                peers,
                generation,
                relay_send_started,
                sampled,
            )
            .await
        }
    }
}

// This original-caller setup seam exists only in test builds. The registry key
// is the address of a live original A, never an Arc keeper; callbacks are removed
// synchronously before the actual bounded future borrows its owner's storage.
#[cfg(test)]
type RelayCaptureSetupForTest = Box<
    dyn FnOnce(
            &mut super::physical_attempt::PhysicalSendCapture,
            &crate::transport::EncryptedPeerPacket,
        ) + Send
        + 'static,
>;
#[cfg(test)]
fn relay_capture_setups_for_test(
) -> &'static std::sync::Mutex<HashMap<usize, RelayCaptureSetupForTest>> {
    static SETUPS: std::sync::OnceLock<std::sync::Mutex<HashMap<usize, RelayCaptureSetupForTest>>> =
        std::sync::OnceLock::new();
    SETUPS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}
#[cfg(test)]
struct RelayCaptureSetupGuardForTest(usize);
#[cfg(test)]
impl Drop for RelayCaptureSetupGuardForTest {
    fn drop(&mut self) {
        relay_capture_setups_for_test()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.0);
    }
}
#[cfg(test)]
fn install_relay_capture_setup_for_test(
    request: &Arc<crate::overlay_requests::CanonicalOverlayRequest>,
    hook: impl FnOnce(
            &mut super::physical_attempt::PhysicalSendCapture,
            &crate::transport::EncryptedPeerPacket,
        ) + Send
        + 'static,
) -> RelayCaptureSetupGuardForTest {
    let key = Arc::as_ptr(request) as usize;
    assert!(relay_capture_setups_for_test()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(key, Box::new(hook))
        .is_none());
    RelayCaptureSetupGuardForTest(key)
}
#[cfg(test)]
fn prepare_relay_capture_for_test<G>(
    packet: &EncryptedRequestDelivery,
    owner: &mut PhysicalAttempt<G>,
) {
    let Some(request) = packet
        .binding()
        .and_then(|binding| binding.token().request())
    else {
        return;
    };
    let key = Arc::as_ptr(&request) as usize;
    drop(request);
    let hook = relay_capture_setups_for_test()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&key);
    if let (Some(hook), Some(capture)) = (hook, owner.slow_capture()) {
        hook(capture, packet);
    }
}

#[cfg(test)]
#[path = "tests/relay_actor_publication.rs"]
mod relay_actor_publication_tests;

#[cfg(test)]
#[path = "tests/relay_actor_legacy_full.rs"]
mod relay_actor_legacy_full_tests;

#[cfg(test)]
#[path = "tests/relay_actor_drain.rs"]
mod relay_actor_drain_tests;

#[cfg(test)]
#[path = "tests/relay_actor_loss.rs"]
mod relay_actor_loss_tests;
