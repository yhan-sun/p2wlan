struct HandshakeMaintenanceContext {
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    pending: Arc<tokio::sync::Mutex<PendingHandshakeState>>,
    handshake_arbiter: HandshakeArbiter,
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    local_network_identity: Arc<RwLock<Vec<String>>>,
    candidate_refresh_lock: Arc<Mutex<()>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    runtime_stun_servers: Arc<RwLock<Vec<SocketAddr>>>,
    runtime_stun_timeout: Arc<RwLock<Duration>>,
    udp_advertise: Option<String>,
    node_private_key: String,
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
        candidate_refresh_lock,
        nat_profile,
        udp_transport,
        runtime_stun_servers,
        runtime_stun_timeout,
        udp_advertise,
        node_private_key,
    } = ctx;

    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let conns = peers.all_connections().await;
        for conn in conns {
            if !conn.online {
                continue;
            }
            let handshake_guard = handshake_arbiter.acquire(&conn.node_id).await;
            // Establish missing sessions and refresh sessions that need rekey.
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

            // Reserve before any further awaits.  The peer-join path can run at
            // the same time as this maintenance loop; without this reservation,
            // both paths could create an initiator and the later one would
            // overwrite the former pending handshake.
            let reserved = {
                let mut state = pending.lock().await;
                if !state.reserve_start(&conn.node_id) {
                    false
                } else {
                    if state.attempts.get(&conn.node_id).copied().unwrap_or(0)
                        >= MAX_HANDSHAKE_ATTEMPTS
                    {
                        warn!(
                            "Handshake for {} reached max attempts; resetting retry budget",
                            conn.node_id
                        );
                        state.attempts.remove(&conn.node_id);
                    }
                    true
                }
            };
            if !reserved {
                continue;
            }

            // PeerConnection doesn't store public key; look up from control.
            // Best-effort: if control has the peer, use it.
            // (control.peers is async)
            // We intentionally skip initiation if we can't get the key —
            // the peer may also rekey from its side.
            let control_peers = control.peers().await;
            let Some(peer_info) = control_peers.get(&conn.node_id) else {
                pending.lock().await.cancel_reservation(&conn.node_id);
                debug!("No control peer info for handshake with {}", conn.node_id);
                continue;
            };
            let Ok(private_key) =
                decode_x25519_key(&node_private_key, "node private key")
            else {
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            };
            let Ok(peer_public) =
                decode_x25519_key(&peer_info.public_key, "peer public key")
            else {
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            };
            let identity = NodeIdentity::from_private_key(private_key);
            if !local_is_designated_handshake_initiator(
                &identity.public_key(),
                &peer_public,
            ) {
                // Let the deterministically selected peer initiate.
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            }
            let mut initiator =
                HandshakeInitiator::new(identity, peer_public, None);
            let Ok(initiation) = initiator.create_initiation() else {
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            };
            let initiation_bytes = initiation.to_bytes();
            // The per-peer handshake reservation above is the actual
            // mutual-exclusion primitive.  The arbiter guard must NOT be held
            // across the slow steps below (STUN candidate refresh, control
            // plane offer POST): a crossing inbound offer/answer handler
            // waits on the same arbiter, and holding it through a multi-second
            // refresh or POST stalls (or effectively deadlocks) the responder
            // path — the peer never answers, the session never forms, and
            // direct validation can never promote.
            drop(handshake_guard);
            // Rekey defaults to the cached candidate snapshot: a live STUN
            // gather is only run when no snapshot exists yet (first boot), so
            // a healthy Direct peer's rekey never re-triggers traversal churn.
            let refreshed = {
                let _lease_guard = candidate_refresh_lock.lock().await;
                let leased = {
                    let candidates = local_candidates.read().await.clone();
                    let sources = local_candidate_sources.read().await.clone();
                    if !candidates.is_empty() {
                        Some((candidates, sources))
                    } else {
                        None
                    }
                };
                drop(_lease_guard);
                if let Some(leased) = leased {
                    debug!(
                        "Handshake maintenance reuses the cached candidate snapshot; no live STUN gather"
                    );
                    Some(leased)
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
            if should_cancel_maintenance_offer(
                is_rekey,
                current_status.has_active,
                current_status.needs_rekey,
                current_status.expired,
                current_status.has_pending_responder,
            ) {
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            }

            let session_id = new_probe_session_id();
            let (probe_ephemeral, probe_ephemeral_public_key) =
                new_probe_ephemeral_keypair();
            let Some((attempt_no, pending_id)) = ({
                let mut state = pending.lock().await;
                state
                    .insert_reserved(
                        conn.node_id.clone(),
                        initiator,
                        Some(session_id.clone()),
                        Some(probe_ephemeral),
                    )
                    .map(|pending_id| {
                        let attempts =
                            state.attempts.entry(conn.node_id.clone()).or_insert(0);
                        *attempts = attempts.saturating_add(1);
                        (*attempts, pending_id)
                    })
            }) else {
                continue;
            };
            // An inbound responder rekey can be staged after the candidate
            // refresh check above but before this initiator's Probe binding is
            // staged. Re-check at the mutation boundary so the crossing
            // initiator never overwrites the responder's pending binding.
            let pre_probe_status = transport.session_status(&conn.node_id).await;
            if should_cancel_maintenance_offer(
                is_rekey,
                pre_probe_status.has_active,
                pre_probe_status.needs_rekey,
                pre_probe_status.expired,
                pre_probe_status.has_pending_responder,
            ) {
                pending.lock().await.remove(&conn.node_id);
                continue;
            }
            if peers
                .stage_probe_session_binding(
                    &conn.node_id,
                    session_id.clone(),
                    Some(session_id.clone()),
                    None,
                    false,
                )
                .await
                != ProbeBindingStage::Staged
            {
                pending.lock().await.remove(&conn.node_id);
                warn!(
                    "Failed to stage Probe v2 binding for handshake with {}",
                    conn.node_id
                );
                continue;
            }

            let punch_at_ms = Some(relay_assisted_punch_at_ms());
            let offer_result = control
                .send_peer_offer_with_sources_punch_and_session(
                    &conn.node_id,
                    &candidates,
                    &candidate_sources,
                    &initiation_bytes,
                    punch_at_ms,
                    Some(session_id.clone()),
                    Some(probe_ephemeral_public_key.clone()),
                )
                .await;
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
            let generation = peers.current_network_generation().await;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(timeout_secs)).await;
                let status = transport2.session_status(&timeout_peer).await;
                if !is_rekey && !status.has_active {
                    warn!("Handshake timeout for peer {timeout_peer}");
                    peers2
                        .record_direct_failure_for_generation(
                            &timeout_peer,
                            generation,
                            REASON_HANDSHAKE_TIMEOUT,
                            "handshake timed out",
                        )
                        .await;
                    peers2
                        .mark_recovery_relay_backoff(&timeout_peer, "handshake timed out")
                        .await;
                }
                let removed = {
                    let mut state = pending2.lock().await;
                    if state.is_current(&timeout_peer, pending_id) {
                        state.remove(&timeout_peer);
                        if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                            state.attempts.remove(&timeout_peer);
                        }
                        true
                    } else {
                        false
                    }
                };
                if removed {
                    peers2
                        .discard_pending_probe_session_binding(
                            &timeout_peer,
                            &timeout_session_id,
                        )
                        .await;
                }
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
        .gather_candidate_report_live(stun_servers, stun_timeout)
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
            include_host_candidate,
        )
    }) {
        if !candidates.contains(&endpoint) {
            candidates.insert(0, endpoint.clone());
        }
        candidate_sources.entry(endpoint.clone()).or_insert_with(|| {
            if udp_advertise.is_some_and(|configured| {
                !configured.trim().is_empty() && configured.trim() == endpoint
            }) {
                "manual".to_string()
            } else {
                "host".to_string()
            }
        });
    }

    let previous_candidates = local_candidates.read().await.clone();
    let previous_candidate_sources = local_candidate_sources.read().await.clone();
    let next_network_identity = prepare_signal_candidates_and_network_identity(
        &previous_candidates,
        &previous_candidate_sources,
        &mut candidates,
        &mut candidate_sources,
    );
    let previous_network_identity = local_network_identity.read().await.clone();
    let should_advance_generation =
        !previous_network_identity.is_empty() && previous_network_identity != next_network_identity;
    let changed = previous_candidates != candidates
        || previous_candidate_sources != candidate_sources
        || previous_network_identity != next_network_identity;

    if changed {
        *local_candidates.write().await = candidates.clone();
        *local_candidate_sources.write().await = candidate_sources.clone();
        *local_network_identity.write().await = next_network_identity;
        if should_advance_generation {
            peers
                .advance_candidate_refresh_generation("pre-signal UDP candidate refresh")
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
        if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
            warn!("Failed to publish pre-signal UDP endpoint '{endpoint}': {err}");
        }
    } else {
        drop(refresh_guard);
    }

    Some((candidates, candidate_sources))
}
