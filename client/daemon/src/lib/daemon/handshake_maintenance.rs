struct HandshakeMaintenanceContext {
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    pending: Arc<PendingHandshakeStore>,
    handshake_arbiter: HandshakeArbiter,
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    local_network_identity: Arc<RwLock<Vec<String>>>,
    candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
    candidate_refresh_lock: Arc<Mutex<()>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    runtime_stun_servers: Arc<RwLock<Vec<SocketAddr>>>,
    runtime_stun_timeout: Arc<RwLock<Duration>>,
    udp_advertise: Option<String>,
    node_private_key: String,
    /// A first business packet or relay replacement wakes maintenance
    /// immediately. The ten-second tick remains the recovery backstop, but it
    /// must not be the first chance to recreate a missing encrypted session.
    kick_rx: tokio::sync::watch::Receiver<u64>,
    handshake_retry_kick_tx: tokio::sync::watch::Sender<u64>,
}

enum MaintenanceInitiatorReservationOutcome {
    Reserved {
        reservation: HandshakeStartReservation,
        stale_session_id: Option<String>,
        retry_budget_reset: bool,
    },
    Busy,
    Contended,
}

/// Claim the maintenance producer's long-lived reservation in one short,
/// zero-wait mutation turn. All actor/control/candidate snapshots happen
/// before this function and every slow continuation happens after it.
fn try_reserve_maintenance_initiator(
    pending: &PendingHandshakeStore,
    handshake_arbiter: &HandshakeArbiter,
    peer_id: &str,
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
) -> MaintenanceInitiatorReservationOutcome {
    let identity = HandshakeLeaseIdentity::new(
        peer_id,
        HandshakeOwnerKind::MaintenanceInitiator,
        None,
        network_generation,
        Some(peer_session_generation),
        "reserve",
    );
    let Ok(handshake_guard) = handshake_arbiter.try_acquire(identity) else {
        return MaintenanceInitiatorReservationOutcome::Contended;
    };
    let transaction = pending.try_with(|state| {
        let stale_session_id = state.remove_stale_pending_for_generation(
            peer_id,
            network_generation,
            peer_session_generation,
        );
        let reservation = state.reserve_start_with_owner_at_generation_and_kind(
            peer_id,
            network_generation,
            peer_session_generation,
            HandshakeOwnerKind::MaintenanceInitiator,
        );
        let retry_budget_reset = reservation.is_some()
            && state.attempts.get(peer_id).copied().unwrap_or(0) >= MAX_HANDSHAKE_ATTEMPTS;
        if retry_budget_reset {
            state.attempts.remove(peer_id);
        }
        (stale_session_id, reservation, retry_budget_reset)
    });
    drop(handshake_guard);
    let Some((stale_session_id, reservation, retry_budget_reset)) = transaction else {
        return MaintenanceInitiatorReservationOutcome::Contended;
    };
    match reservation {
        Some(reservation) => MaintenanceInitiatorReservationOutcome::Reserved {
            reservation,
            stale_session_id,
            retry_budget_reset,
        },
        None => MaintenanceInitiatorReservationOutcome::Busy,
    }
}

async fn run_handshake_maintenance(ctx: HandshakeMaintenanceContext) {
    let HandshakeMaintenanceContext {
        peers,
        transport,
        pending,
        handshake_arbiter,
        control,
        local_candidates,
        local_candidate_sources,
        local_network_identity,
        candidate_snapshot,
        candidate_refresh_lock,
        nat_profile,
        udp_transport,
        runtime_stun_servers,
        runtime_stun_timeout,
        udp_advertise,
        node_private_key,
        mut kick_rx,
        handshake_retry_kick_tx,
    } = ctx;

    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            changed = kick_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                kick_rx.borrow_and_update();
            }
        }
        // The exact retry record is committed before its wake.  Republishing
        // the current revision from the supervised maintenance owner makes a
        // receiver replacement or coalesced watch notification harmless: the
        // control coordinator always scans the authoritative ledger.
        let retry_revision = {
            let state = pending.lock();
            state
                .has_initiator_retries()
                .then(|| state.retry_revision())
        };
        if let Some(retry_revision) = retry_revision {
            handshake_retry_kick_tx.send_replace(retry_revision);
        }
        let conns = peers.all_connections().await;
        for conn in conns {
            if !conn.online {
                continue;
            }
            // The maintenance tick is another initiator producer.  Do not
            // let it briefly claim the per-peer handshake arbiter on a node
            // whose static identity makes it the responder; an inbound offer
            // is the latency-critical transaction in that case.
            if matches!(
                should_start_initiator_for_encoded_keys(&node_private_key, &conn.public_key),
                Some(false)
            ) {
                debug!(
                    "Skipping maintenance initiator for {}: deterministic responder role",
                    conn.node_id
                );
                continue;
            }
            let Some(peer_session_generation) = peers.peer_session_generation_sync(&conn.node_id)
            else {
                continue;
            };
            // Maintenance is a low-priority producer.  Snapshot every actor or
            // control-plane dependency before attempting the zero-wait mutation
            // turn; an Event/Responder owner must never queue behind this scan.
            let status = transport.session_status(&conn.node_id).await;
            if status.has_pending_responder {
                debug!(
                    "Responder rekey for {} is awaiting authenticated confirmation; suppressing a crossing initiator offer",
                    conn.node_id
                );
                continue;
            }
            if status.has_active && !status.needs_rekey && !status.expired {
                continue;
            }
            let is_rekey = status.has_active;
            if !status.has_active {
                debug!(
                    "No WireGuard session for {}; retrying handshake",
                    conn.node_id
                );
            } else if status.expired {
                info!(
                    "Session for peer {} expired; rekeying before dropping old session",
                    conn.node_id
                );
            } else {
                info!(
                    "Session for peer {} needs rekey (message/time threshold)",
                    conn.node_id
                );
            }
            let handshake_generation = peers.current_network_generation_sync();
            let control_peers = control.peers().await;
            let Some(peer_info) = control_peers.get(&conn.node_id) else {
                debug!("No control peer info for handshake with {}", conn.node_id);
                continue;
            };
            let Ok(private_key) = decode_x25519_key(&node_private_key, "node private key") else {
                continue;
            };
            let Ok(peer_public) = decode_x25519_key(&peer_info.public_key, "peer public key")
            else {
                continue;
            };
            let identity = NodeIdentity::from_private_key(private_key);
            if !local_is_designated_handshake_initiator(&identity.public_key(), &peer_public) {
                continue;
            }
            let mut initiator = HandshakeInitiator::new(identity, peer_public, None);
            let Ok(initiation) = initiator.create_initiation() else {
                continue;
            };
            let initiation_bytes = initiation.to_bytes();

            let (mut reservation, stale_session_id, retry_budget_reset) =
                match try_reserve_maintenance_initiator(
                    &pending,
                    &handshake_arbiter,
                    &conn.node_id,
                    handshake_generation,
                    peer_session_generation,
                ) {
                    MaintenanceInitiatorReservationOutcome::Reserved {
                        reservation,
                        stale_session_id,
                        retry_budget_reset,
                    } => (reservation, stale_session_id, retry_budget_reset),
                    MaintenanceInitiatorReservationOutcome::Busy
                    | MaintenanceInitiatorReservationOutcome::Contended => {
                        // A high-priority Event/Responder turn owns the peer, or
                        // the short state store is momentarily busy. Never join
                        // either wait queue; a kick/tick reevaluates lifecycle.
                        continue;
                    }
                };
            if retry_budget_reset {
                warn!(
                    "Handshake for {} reached max attempts; resetting retry budget",
                    conn.node_id
                );
            }
            if let Some(session_id) = stale_session_id {
                peers
                    .discard_pending_probe_session_binding(&conn.node_id, &session_id)
                    .await;
            }
            // Rekey defaults to the cached candidate snapshot: a live STUN
            // gather is only run when no snapshot exists yet (first boot), so
            // a healthy Direct peer's rekey never re-triggers traversal churn.
            let refreshed = {
                let _lease_guard = candidate_refresh_lock.lock().await;
                let snapshot_state = candidate_snapshot.read().await.clone();
                let leased = snapshot_state.as_ref().and_then(|snapshot| {
                    (snapshot.initial_gather_complete && !snapshot.candidates.is_empty()).then(
                        || {
                            (
                                snapshot.candidates.clone(),
                                snapshot.candidate_sources.clone(),
                            )
                        },
                    )
                });
                let startup_snapshot_is_provisional = snapshot_state
                    .as_ref()
                    .is_some_and(|snapshot| !snapshot.initial_gather_complete);
                drop(_lease_guard);
                if let Some(leased) = leased {
                    debug!(
                        "Handshake maintenance reuses the cached candidate snapshot; no live STUN gather"
                    );
                    Some(leased)
                } else if startup_snapshot_is_provisional {
                    debug!(
                        "Handshake maintenance waits for the full startup candidate snapshot before retrying the initiator"
                    );
                    Some(wait_for_initial_candidate_set_from_store(&candidate_snapshot).await)
                } else {
                    refresh_candidate_cache_for_maintenance_signal(
                        &peers,
                        &control,
                        &udp_transport,
                        &runtime_stun_servers,
                        &runtime_stun_timeout,
                        udp_advertise.as_deref(),
                        &local_candidates,
                        &local_candidate_sources,
                        &local_network_identity,
                        &candidate_snapshot,
                        &candidate_refresh_lock,
                        &nat_profile,
                        "handshake maintenance",
                    )
                    .await
                }
            };
            let (candidates, candidate_sources) = if let Some(refreshed) = refreshed {
                refreshed
            } else {
                let _refresh_guard = candidate_refresh_lock.lock().await;
                (
                    local_candidates.read().await.clone(),
                    local_candidate_sources.read().await.clone(),
                )
            };

            // An inbound offer may have established a responder session while
            // candidates were being read. For normal retries, any session is
            // enough to cancel. For rekeys, keep the old session alive and only
            // cancel once it has been replaced by a session that no longer needs
            // rekey. This avoids a brief no-session window that pushes traffic
            // through relay during otherwise healthy Direct paths.
            let current_status = transport.session_status(&conn.node_id).await;
            if *reservation.cancellation.borrow()
                || !peers.peer_session_is_current_sync(
                    &conn.node_id,
                    reservation.peer_session_generation,
                )
                || should_cancel_maintenance_offer(
                    is_rekey,
                    current_status.has_active,
                    current_status.needs_rekey,
                    current_status.expired,
                    current_status.has_pending_responder,
                )
            {
                pending
                    .lock()
                    .cancel_reservation_if_current(&conn.node_id, reservation.owner);
                continue;
            }

            let session_id = new_probe_session_id();
            let (probe_ephemeral, probe_ephemeral_public_key) = new_probe_ephemeral_keypair();
            let publish_identity = HandshakeLeaseIdentity::new(
                &conn.node_id,
                HandshakeOwnerKind::MaintenanceInitiator,
                Some(reservation.owner),
                handshake_generation,
                Some(reservation.peer_session_generation),
                "publish",
            );
            let Ok(publish_guard) = handshake_arbiter.try_acquire(publish_identity) else {
                pending
                    .lock()
                    .cancel_reservation_if_current(&conn.node_id, reservation.owner);
                continue;
            };
            let Some((attempt_no, pending_id)) = ({
                let epoch_gate = peers.network_epoch_gate();
                let Ok(_epoch_guard) = epoch_gate.try_lock() else {
                    drop(publish_guard);
                    pending
                        .lock()
                        .cancel_reservation_if_current(&conn.node_id, reservation.owner);
                    continue;
                };
                if *reservation.cancellation.borrow()
                    || peers.current_network_generation_sync() != handshake_generation
                    || !peers.peer_session_is_current_sync(
                        &conn.node_id,
                        reservation.peer_session_generation,
                    )
                {
                    drop(_epoch_guard);
                    drop(publish_guard);
                    pending
                        .lock()
                        .cancel_reservation_if_current(&conn.node_id, reservation.owner);
                    continue;
                }
                let inserted = pending.try_with(|state| {
                    state
                        .insert_reserved_if_current_with_generation(
                            conn.node_id.clone(),
                            reservation.owner,
                            initiator,
                            Some(session_id.clone()),
                            Some(probe_ephemeral),
                            handshake_generation,
                            reservation.peer_session_generation,
                        )
                        .map(|pending_id| {
                            let attempts = state.attempts.entry(conn.node_id.clone()).or_insert(0);
                            *attempts = attempts.saturating_add(1);
                            (*attempts, pending_id)
                        })
                });
                drop(_epoch_guard);
                drop(publish_guard);
                inserted.flatten()
            }) else {
                pending
                    .lock()
                    .cancel_reservation_if_current(&conn.node_id, reservation.owner);
                continue;
            };
            // An inbound responder rekey can be staged after the candidate
            // refresh check above but before this initiator's Probe binding is
            // staged. Re-check at the mutation boundary so the crossing
            // initiator never overwrites the responder's pending binding.
            let pre_probe_status = transport.session_status(&conn.node_id).await;
            if *reservation.cancellation.borrow()
                || peers.current_network_generation_sync() != handshake_generation
                || !peers.peer_session_is_current_sync(
                    &conn.node_id,
                    reservation.peer_session_generation,
                )
                || should_cancel_maintenance_offer(
                    is_rekey,
                    pre_probe_status.has_active,
                    pre_probe_status.needs_rekey,
                    pre_probe_status.expired,
                    pre_probe_status.has_pending_responder,
                )
            {
                pending.lock().remove_if_current(&conn.node_id, pending_id);
                continue;
            }
            // Stage the Probe binding in the same generation transaction and
            // never queue a connection writer. Maintenance is the low-priority
            // producer: contention cancels this exact pending owner and the
            // next kick/tick takes a fresh snapshot.
            let binding_stage = {
                let epoch_gate = peers.network_epoch_gate();
                let Ok(_epoch_guard) = epoch_gate.try_lock() else {
                    pending.lock().remove_if_current(&conn.node_id, pending_id);
                    continue;
                };
                if *reservation.cancellation.borrow()
                    || peers.current_network_generation_sync() != handshake_generation
                    || !peers.peer_session_is_current_sync(
                        &conn.node_id,
                        reservation.peer_session_generation,
                    )
                {
                    None
                } else {
                    peers.try_stage_probe_session_binding(
                        &conn.node_id,
                        session_id.clone(),
                        Some(session_id.clone()),
                        None,
                        false,
                    )
                }
            };
            if binding_stage != Some(ProbeBindingStage::Staged) {
                pending.lock().remove_if_current(&conn.node_id, pending_id);
                peers
                    .discard_pending_probe_session_binding(&conn.node_id, &session_id)
                    .await;
                warn!(
                    "Failed to stage Probe v2 binding for handshake with {}",
                    conn.node_id
                );
                continue;
            }

            let punch_at_ms = Some(relay_assisted_punch_at_ms());
            let Some(offer_result) = await_initiator_offer_or_cancellation(
                control.send_peer_offer_with_sources_punch_and_session(
                    &conn.node_id,
                    &candidates,
                    &candidate_sources,
                    &initiation_bytes,
                    punch_at_ms,
                    Some(session_id.clone()),
                    Some(probe_ephemeral_public_key.clone()),
                ),
                &mut reservation.cancellation,
            )
            .await
            else {
                peers
                    .discard_pending_probe_session_binding(&conn.node_id, &session_id)
                    .await;
                continue;
            };
            if offer_result.is_ok() {
                if is_rekey {
                    info!(
                        "Rekey: sent handshake initiation to {} ({} bytes, attempt {})",
                        conn.node_id,
                        initiation_bytes.len(),
                        attempt_no
                    );
                } else {
                    info!(
                        "Retry: sent handshake initiation to {} ({} bytes, attempt {})",
                        conn.node_id,
                        initiation_bytes.len(),
                        attempt_no
                    );
                }
            } else {
                warn!(
                    "Handshake offer delivery to {} is ambiguous; retaining pending handshake until timeout",
                    conn.node_id
                );
            }

            // Timeout cleanup runs for both successful and delivery-ambiguous
            // control requests. The short rekey timeout permits retries well
            // before the old WireGuard session reaches hard reject.
            let pending2 = pending.clone();
            let timeout_peer = conn.node_id.clone();
            let transport2 = transport.clone();
            let peers2 = peers.clone();
            let timeout_session_id = session_id;
            let timeout_secs = if is_rekey {
                REKEY_HANDSHAKE_TIMEOUT_SECS
            } else {
                HANDSHAKE_TIMEOUT_SECS
            };
            let generation = handshake_generation;
            let timeout_peer_session_generation = reservation.peer_session_generation;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
                // The pending owner is the timeout's first authority. Remove
                // only that exact transaction before publishing any failure;
                // an answer/retry/rejoin that replaced it makes this task a
                // no-op. The stored lifecycle stamp closes the same-node ABA.
                let removed = {
                    let mut state = pending2.lock();
                    if state.is_current(&timeout_peer, pending_id)
                        && state.peer_session_generation(&timeout_peer)
                            == Some(timeout_peer_session_generation)
                    {
                        state.remove(&timeout_peer);
                        if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                            state.attempts.remove(&timeout_peer);
                        }
                        true
                    } else {
                        false
                    }
                };
                if !removed {
                    return;
                }

                if peers2
                    .peer_session_is_current_sync(&timeout_peer, timeout_peer_session_generation)
                {
                    let status = transport2.session_status(&timeout_peer).await;
                    if !is_rekey
                        && !status.has_active
                        && peers2.peer_session_is_current_sync(
                            &timeout_peer,
                            timeout_peer_session_generation,
                        )
                    {
                        warn!("Handshake timeout for peer {timeout_peer}");
                        let failed = peers2
                            .record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
                                &timeout_peer,
                                generation,
                                timeout_peer_session_generation,
                                REASON_HANDSHAKE_TIMEOUT,
                                "handshake timed out",
                                None,
                            )
                            .await;
                        if failed {
                            peers2
                                .mark_recovery_relay_backoff_for_peer_session(
                                    &timeout_peer,
                                    timeout_peer_session_generation,
                                    "handshake timed out",
                                )
                                .await;
                        }
                    }
                }
                peers2
                    .discard_pending_probe_session_binding(&timeout_peer, &timeout_session_id)
                    .await;
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn refresh_candidate_cache_for_maintenance_signal(
    peers: &Arc<PeerManager>,
    control: &ControlClient,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    runtime_stun_servers: &Arc<RwLock<Vec<SocketAddr>>>,
    runtime_stun_timeout: &Arc<RwLock<Duration>>,
    udp_advertise: Option<&str>,
    local_candidates: &Arc<RwLock<Vec<String>>>,
    local_candidate_sources: &Arc<RwLock<HashMap<String, String>>>,
    local_network_identity: &Arc<RwLock<Vec<String>>>,
    candidate_snapshot: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    candidate_refresh_lock: &Arc<Mutex<()>>,
    nat_profile: &Arc<RwLock<Option<NatProfile>>>,
    reason: &str,
) -> Option<(Vec<String>, HashMap<String, String>)> {
    let refresh_guard = candidate_refresh_lock.lock().await;
    let udp = udp_transport.read().await.clone()?;
    let stun_servers = runtime_stun_servers.read().await.clone();
    if stun_servers.is_empty() {
        return None;
    }
    let stun_timeout = *runtime_stun_timeout.read().await;
    let report = match udp
        .gather_candidate_report_live_parallel(stun_servers, stun_timeout)
        .await
    {
        Ok(report) => report,
        Err(err) => {
            warn!("Pre-signal UDP candidate refresh failed for {reason}: {err}");
            return None;
        }
    };

    peers.update_nat_profile(report.nat_profile.clone()).await;
    *nat_profile.write().await = Some(report.nat_profile.clone());

    let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
    let include_host_candidate = peers.gather_host_candidates().await;
    if let Some(endpoint) = udp.local_addr().ok().and_then(|local_addr| {
        advertised_udp_endpoint(
            local_addr,
            udp_advertise,
            &candidates,
            &candidate_sources,
            include_host_candidate,
        )
    }) {
        if !candidates.contains(&endpoint) {
            candidates.insert(0, endpoint.clone());
        }
        candidate_sources
            .entry(endpoint.clone())
            .or_insert_with(|| {
                if udp_advertise.is_some_and(|configured| {
                    !configured.trim().is_empty() && configured.trim() == endpoint
                }) {
                    "manual".to_string()
                } else {
                    "host".to_string()
                }
            });
    }

    let previous_snapshot = candidate_snapshot.read().await.clone();
    let previous_candidates = previous_snapshot
        .as_ref()
        .map(|snapshot| snapshot.candidates.clone())
        .unwrap_or_default();
    let previous_candidate_sources = previous_snapshot
        .as_ref()
        .map(|snapshot| snapshot.candidate_sources.clone())
        .unwrap_or_default();
    let next_network_identity = prepare_signal_candidates_and_network_identity(
        &previous_candidates,
        &previous_candidate_sources,
        &mut candidates,
        &mut candidate_sources,
    );
    let previous_network_identity = previous_snapshot
        .as_ref()
        .map(|snapshot| snapshot.network_identity.clone())
        .unwrap_or_default();
    let should_advance_generation =
        network_identity_changed(&previous_network_identity, &next_network_identity);
    let changed = previous_candidates != candidates
        || previous_candidate_sources != candidate_sources
        || previous_network_identity != next_network_identity;

    if changed {
        publish_candidate_snapshot_to_store(
            candidate_snapshot,
            candidates.clone(),
            candidate_sources.clone(),
            next_network_identity.clone(),
        )
        .await;
        *local_candidates.write().await = candidates.clone();
        *local_candidate_sources.write().await = candidate_sources.clone();
        *local_network_identity.write().await = next_network_identity;
        if should_advance_generation {
            peers
                // Identity replacement means the socket/NAT path changed;
                // ordinary refresh retention would incorrectly preserve the
                // old Direct pair and suppress the required re-punch.
                .advance_network_generation("pre-signal UDP network identity changed")
                .await;
        }
        info!(
            "Pre-signal UDP candidates refreshed for {reason}; {} candidates (mapping={:?}, public={:?})",
            candidates.len(),
            report.nat_profile.mapping_behavior,
            report.nat_profile.public_endpoint
        );
    }

    if let Some(endpoint) = control_udp_endpoint_from_candidates(&candidates, &candidate_sources) {
        drop(refresh_guard);
        let nat_type = report
            .nat_profile
            .control_label_with_generation(peers.current_local_profile_generation_sync());
        if let Err(err) = control.update_endpoint(&endpoint, &nat_type).await {
            warn!("Failed to publish pre-signal UDP endpoint '{endpoint}': {err}");
        }
    } else {
        drop(refresh_guard);
    }

    Some((candidates, candidate_sources))
}
