struct HandshakeMaintenanceContext {
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    pending: Arc<tokio::sync::Mutex<PendingHandshakeState>>,
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    node_private_key: String,
    node_public_key: String,
}

async fn run_handshake_maintenance(ctx: HandshakeMaintenanceContext) {
    let HandshakeMaintenanceContext {
        peers,
        transport,
        pending,
        control,
        local_candidates,
        local_candidate_sources,
        node_private_key,
        node_public_key,
    } = ctx;

    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let conns = peers.all_connections().await;
        for conn in conns {
            if !conn.online {
                continue;
            }
            // Establish missing sessions and refresh sessions that need rekey.
            let has_session = transport.has_session(&conn.node_id).await;
            let needs = transport.session_needs_rekey(&conn.node_id).await;
            let expired = transport.session_is_expired(&conn.node_id).await;
            if has_session && !needs && !expired {
                continue;
            }
            let is_rekey = has_session;
            if !has_session {
                debug!(
                    "No WireGuard session for {}; retrying handshake",
                    conn.node_id
                );
            } else if expired {
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
            if node_public_key >= peer_info.public_key {
                // Let the other side initiate.
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            }

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
            let mut initiator =
                HandshakeInitiator::new(identity, peer_public, None);
            let Ok(initiation) = initiator.create_initiation() else {
                pending.lock().await.cancel_reservation(&conn.node_id);
                continue;
            };
            let initiation_bytes = initiation.to_bytes();
            let candidates = local_candidates.read().await.clone();
            let candidate_sources = local_candidate_sources.read().await.clone();

            // An inbound offer may have established a responder session while
            // candidates were being read. For normal retries, any session is
            // enough to cancel. For rekeys, keep the old session alive and only
            // cancel once it has been replaced by a session that no longer needs
            // rekey. This avoids a brief no-session window that pushes traffic
            // through relay during otherwise healthy Direct paths.
            let current_has_session = transport.has_session(&conn.node_id).await;
            let current_needs = if is_rekey && current_has_session {
                transport.session_needs_rekey(&conn.node_id).await
            } else {
                false
            };
            let current_expired = if is_rekey && current_has_session {
                transport.session_is_expired(&conn.node_id).await
            } else {
                false
            };
            if should_cancel_maintenance_offer(
                is_rekey,
                current_has_session,
                current_needs,
                current_expired,
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
            peers
                .set_probe_session_id(&conn.node_id, Some(session_id.clone()))
                .await;

            let punch_at_ms = Some(relay_assisted_punch_at_ms());
            if let Err(err) = control
                .send_peer_offer_with_sources_punch_and_session(
                    &conn.node_id,
                    &candidates,
                    &candidate_sources,
                    &initiation_bytes,
                    punch_at_ms,
                    Some(session_id.clone()),
                    Some(probe_ephemeral_public_key.clone()),
                )
                .await
            {
                warn!("Handshake offer to {} failed: {err}", conn.node_id);
                let mut state = pending.lock().await;
                if state.is_current(&conn.node_id, pending_id) {
                    state.remove(&conn.node_id);
                    peers.set_probe_session_id(&conn.node_id, None).await;
                }
            } else {
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
                // Timeout cleanup
                let pending2 = pending.clone();
                let timeout_peer = conn.node_id.clone();
                let transport2 = transport.clone();
                let peers2 = peers.clone();
                let generation = peers.current_network_generation().await;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS))
                        .await;
                    if !transport2.has_session(&timeout_peer).await {
                        warn!("Handshake timeout for peer {timeout_peer}");
                        peers2
                            .record_direct_failure_for_generation(
                                &timeout_peer,
                                generation,
                                REASON_HANDSHAKE_TIMEOUT,
                                "handshake timed out",
                            )
                            .await;
                    }
                    let mut state = pending2.lock().await;
                    if state.is_current(&timeout_peer, pending_id) {
                        state.remove(&timeout_peer);
                        if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                            state.attempts.remove(&timeout_peer);
                        }
                    }
                });
            }
        }
    }

}
