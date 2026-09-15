#[cfg(test)]
use super::build_relay_validation_payload;
#[cfg(test)]
use super::Result;
use super::{
    debug, interval, join_all, unix_time_millis, warn, watch, Arc, DaemonError, HashMap, Instant,
    Ipv4Addr, Ipv4Packet, OutboundPacket, PeerManager, RelayTransport, RelayWriteBoundaryPermit,
    RwLock, WireGuardTransport, RELAY_CONTROL_SEND_TIMEOUT, RELAY_PEER_VALIDATION_INTERVAL,
    RELAY_PEER_VALIDATION_MAX_AGE, RELAY_PEER_VALIDATION_READY_POLL_INTERVAL,
    RELAY_PROBE_POLL_INTERVAL, RELAY_PROBE_RETRY_INTERVAL,
};

pub(crate) async fn run_relay_peer_validation_loop(
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    local_virtual_ip: String,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!("Skipping relay peer validation; local virtual IP '{local_virtual_ip}' is not IPv4");
        return;
    };
    let mut ticker = interval(RELAY_PEER_VALIDATION_READY_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_validation_at: Option<Instant> = None;
    let mut last_relay_endpoint: Option<String> = None;

    loop {
        ticker.tick().await;
        let Some(relay) = relay_transport.read().await.clone() else {
            last_relay_endpoint = None;
            continue;
        };
        let relay_endpoint = relay.endpoint().to_string();
        let relay_changed = last_relay_endpoint.as_deref() != Some(relay_endpoint.as_str());
        if !relay_changed
            && last_validation_at.is_some_and(|at| at.elapsed() < RELAY_PEER_VALIDATION_INTERVAL)
        {
            continue;
        }

        let targets = peers
            .relay_validation_targets(RELAY_PEER_VALIDATION_MAX_AGE)
            .await;
        if targets.is_empty() {
            last_relay_endpoint = Some(relay_endpoint);
            continue;
        }
        last_relay_endpoint = Some(relay_endpoint.clone());

        let generation = peers.current_network_generation().await;
        let validation_id = unix_time_millis() as u16;
        let validation_owner = unix_time_millis();
        let mut sends = Vec::new();
        for (sequence, (peer_id, peer_virtual_ip)) in targets.into_iter().enumerate() {
            let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                debug!(
                    "Skipping relay peer validation for {peer_id}; peer virtual IP '{peer_virtual_ip}' is not IPv4"
                );
                continue;
            };
            let send_transport = transport.clone();
            let send_relay = relay.clone();
            let send_peer_id = peer_id;
            let send_peer_virtual_ip = peer_virtual_ip;
            let send_sequence = sequence as u16;
            let request_id = validation_id.wrapping_add(send_sequence);
            let owner_token = validation_owner.wrapping_add(sequence as u64);
            let send_generation = generation;
            let send_relay_endpoint = relay_endpoint.clone();
            let send_connection_id = relay.connection_id();
            let send_peers = Arc::clone(&peers);
            let expectation_peer_id = send_peer_id.clone();
            let expectation_endpoint = send_relay_endpoint.clone();
            sends.push(async move {
                let deadline_permit = RelayWriteBoundaryPermit::new();
                let boundary_permit = deadline_permit.clone();
                // Periodic health uses the same authenticated request/ACK
                // protocol as forced confirmation.  Its wire token is only an
                // identity; RTT is measured with the local Instant installed
                // at the relay writer boundary below, never at local enqueue
                // time and never with the wall-clock payload.
                let payload = crate::relay_probe::build_relay_probe_payload(
                    crate::relay_probe::RelayProbeKind::Request,
                    send_generation,
                    request_id,
                    owner_token,
                );
                let packet = Ipv4Packet::build_icmp_echo_request(
                    local_ip,
                    peer_ip,
                    request_id,
                    send_sequence,
                    &payload,
                );
                let result = tokio::time::timeout(
                    RELAY_CONTROL_SEND_TIMEOUT,
                    send_transport.encrypt_and_emit_outbound(
                        OutboundPacket {
                            room_authorization: None,
                            peer_id: send_peer_id.clone(),
                            dst_ip: send_peer_virtual_ip,
                            packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            let Some(peer_session_generation) = send_peers
                                .relay_validation_write_permit_for_transport(
                                    &expectation_peer_id,
                                    send_generation,
                                    &expectation_endpoint,
                                    send_connection_id,
                                )
                                .await
                            else {
                                return Err(DaemonError::Peer(format!(
                                    "peer {} is no longer confirmed on relay connection {}",
                                    expectation_peer_id, send_connection_id
                                )));
                            };
                            send_relay
                                .send_packet_with_write_boundary(&encrypted, move |sent_at| {
                                    boundary_permit.commit(|| {
                                        send_peers.register_relay_validation_expectation_at_write_boundary(
                                            &expectation_peer_id,
                                            send_generation,
                                            request_id,
                                            owner_token,
                                            &expectation_endpoint,
                                            send_connection_id,
                                            peer_session_generation,
                                            sent_at,
                                        )
                                    })
                                })
                                .await
                        },
                    ),
                )
                .await;
                (
                    send_peer_id,
                    send_generation,
                    request_id,
                    owner_token,
                    send_connection_id,
                    deadline_permit,
                    result,
                )
            });
        }

        let mut sent_count = 0usize;
        let mut transport_failed = false;
        for (
            peer_id,
            generation,
            request_id,
            owner_token,
            connection_id,
            deadline_permit,
            result,
        ) in join_all(sends).await
        {
            match result {
                Ok(Ok(true)) => sent_count = sent_count.saturating_add(1),
                Ok(Ok(false)) => {
                    deadline_permit.revoke();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    debug!(
                        "Relay peer validation skipped for {peer_id}: WireGuard session is not ready"
                    );
                }
                Ok(Err(err)) => {
                    deadline_permit.revoke();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    debug!("Relay peer validation skipped for {peer_id}: {err}");
                }
                Err(_) => {
                    deadline_permit.revoke();
                    relay.abort_writer();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    transport_failed = true;
                    warn!(
                        event = "relay_validation_send_timeout",
                        peer_id = %peer_id,
                        relay_endpoint = %relay_endpoint,
                        timeout_ms = RELAY_CONTROL_SEND_TIMEOUT.as_millis(),
                        "relay validation writer completion timed out; relay transport invalidated"
                    );
                }
            }
        }
        if sent_count > 0 && !transport_failed {
            last_validation_at = Some(Instant::now());
        }
    }
}

#[cfg(test)]
pub(crate) struct RelayValidationPacket<'a> {
    pub(crate) peer_id: &'a str,
    pub(crate) peer_virtual_ip: &'a str,
    pub(crate) local_ip: Ipv4Addr,
    pub(crate) peer_ip: Ipv4Addr,
    pub(crate) validation_id: u16,
    pub(crate) sequence: u16,
}

/// Drive forced-relay path-probes to every peer that has an encrypting
/// WireGuard session, relay connected, Direct unconfirmed and RelayPeerConfirmed
/// not yet set.  Each probe registers a newest-wins expectation on the peer
/// manager; only the matching ACK whose real ingress is relay sets
/// `RelayPeerConfirmed` (never a local connect or a queued registration).
///
/// The loop ticks at [`RELAY_PROBE_POLL_INTERVAL`] and is also kicked
/// immediately (`kick_rx`) by the outbound actor when a first business packet
/// starts waiting, so a peer that becomes relay-ready does not wait for the
/// next tick.
pub(crate) async fn run_relay_peer_probe_loop(
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    local_virtual_ip: String,
    timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
    mut kick_rx: watch::Receiver<u64>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!("Skipping relay peer probe; local virtual IP '{local_virtual_ip}' is not IPv4");
        return;
    };
    let mut ticker = interval(RELAY_PROBE_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Per-peer probe token: (owner token, request id). It remains stable while
    // a probe is in flight so a late ACK — relay latency up to the expectation
    // TTL — can still confirm the path. When the expectation disappears
    // without confirmation (the relay's `peer_not_found` path, a stale ACK,
    // or a transport/generation invalidation), the token is rotated before a
    // retry. This prevents an ACK for a rejected old probe from confirming a
    // later registration attempt.
    let mut probe_tokens: HashMap<String, (u64, u16)> = HashMap::new();
    // Per-peer last-send time, to pace re-sends (bounded cadence) without
    // changing the token.
    let mut last_sent: HashMap<String, Instant> = HashMap::new();
    // Per-peer + generation probe attempt counts, so the timeline can report a
    // bounded summary instead of one `relay_probe_sent` event per re-send
    // (which would crowd out the startup/roster/session/confirmed milestones
    // in the 64-event ring).
    let mut attempt_counts: HashMap<String, (u64, u64)> = HashMap::new();
    let mut next_request_id: u16 = 0;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = kick_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                kick_rx.borrow_and_update();
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow_and_update() {
                    return;
                }
            }
        }
        let Some(relay) = relay_transport.read().await.clone() else {
            continue;
        };
        let relay_endpoint = relay.endpoint().to_string();
        let targets = peers.relay_probe_targets().await;
        if targets.is_empty() {
            probe_tokens.clear();
            last_sent.clear();
            // Report attempt summaries for peers that stopped needing probes.
            emit_probe_attempt_summaries(&timeline, &attempt_counts);
            attempt_counts.clear();
            continue;
        }
        let now = Instant::now();
        let mut sends = Vec::new();
        for (peer_id, peer_virtual_ip, target_generation) in &targets {
            let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                debug!("Skipping relay probe for {peer_id}; peer virtual IP '{peer_virtual_ip}' is not IPv4");
                continue;
            };
            let session_status = transport.session_status(peer_id).await;
            if !session_status.has_active {
                // The relay probe is encrypted with the WireGuard session, so
                // it cannot be sent before that session exists. Do not turn
                // this necessary ordering into a silent wait: a missed/late
                // PeerJoined event otherwise looks like a relay failure until
                // the business queue deadline expires.
                let scope = format!("peer:{peer_id}:{target_generation}");
                timeline.emit_first_scoped(
                    &scope,
                    "relay_probe_waiting_for_session",
                    Some("relay"),
                    Some("wireguard_session_unavailable"),
                    Some(format!(
                        "peer={peer_id} generation={target_generation} relay_endpoint={relay_endpoint} relay_connection_id={} has_pending_responder={} needs_rekey={} expired={}",
                        relay.connection_id(),
                        session_status.has_pending_responder,
                        session_status.needs_rekey,
                        session_status.expired,
                    )),
                );
                continue;
            }
            // The relay is genuinely usable for this peer: record the
            // per-peer RelayTransportConnected milestone.
            peers
                .mark_relay_transport_ready_with_transport(
                    peer_id,
                    &relay_endpoint,
                    *target_generation,
                    Some(relay.connection_id()),
                )
                .await;
            let Some(send_peer_session_generation) = peers.peer_session_generation_sync(peer_id)
            else {
                continue;
            };
            // Stable per-peer token: chosen once, reused for every re-send
            // until the manager reports that the outstanding expectation was
            // consumed/invalidated. In that case rotate before installing the
            // next expectation, so old-generation/old-registration ACKs cannot
            // confirm the retry.
            if last_sent.contains_key(peer_id) && !peers.relay_probe_expectation_present(peer_id) {
                next_request_id = next_request_id.wrapping_add(1);
                probe_tokens.insert(peer_id.clone(), (unix_time_millis(), next_request_id));
            }
            let (owner_token, request_id) = match probe_tokens.get(peer_id) {
                Some(&token) => token,
                None => {
                    next_request_id = next_request_id.wrapping_add(1);
                    let token = (unix_time_millis(), next_request_id);
                    probe_tokens.insert(peer_id.clone(), token);
                    token
                }
            };
            // Pace re-sends before registering any timing expectation.  The
            // expectation is installed only after encryption, after the relay
            // client's command-queue wait, and immediately before write_all,
            // so local queue/emit-lock delay is not misreported as network RTT.
            if last_sent
                .get(peer_id)
                .is_some_and(|at| now.saturating_duration_since(*at) < RELAY_PROBE_RETRY_INTERVAL)
            {
                continue;
            }
            let payload = crate::relay_probe::build_relay_probe_payload(
                crate::relay_probe::RelayProbeKind::Request,
                *target_generation,
                request_id,
                owner_token,
            );
            let packet =
                Ipv4Packet::build_icmp_echo_request(local_ip, peer_ip, request_id, 1, &payload);
            let send_transport = transport.clone();
            let send_relay = relay.clone();
            let send_peer_id = peer_id.clone();
            let send_peer_virtual_ip = peer_virtual_ip.clone();
            let send_relay_endpoint = relay_endpoint.clone();
            let send_generation = *target_generation;
            let send_owner_token = owner_token;
            let send_relay_connection_id = relay.connection_id();
            let send_peers = Arc::clone(&peers);
            let expectation_peer_id = send_peer_id.clone();
            let expectation_endpoint = send_relay_endpoint.clone();
            sends.push(async move {
                let deadline_permit = RelayWriteBoundaryPermit::new();
                let boundary_permit = deadline_permit.clone();
                let result = tokio::time::timeout(
                    RELAY_CONTROL_SEND_TIMEOUT,
                    send_transport.encrypt_and_emit_outbound(
                        OutboundPacket {
                            room_authorization: None,
                            peer_id: send_peer_id.clone(),
                            dst_ip: send_peer_virtual_ip,
                            packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            send_relay
                                .send_packet_with_write_boundary(&encrypted, move |sent_at| {
                                    boundary_permit.commit(|| {
                                        send_peers
                                            .register_relay_probe_expectation_at_write_boundary(
                                                &expectation_peer_id,
                                                send_generation,
                                                request_id,
                                                send_owner_token,
                                                &expectation_endpoint,
                                                send_relay_connection_id,
                                                send_peer_session_generation,
                                                sent_at,
                                            )
                                    })
                                })
                                .await
                        },
                    ),
                )
                .await;
                (
                    send_peer_id,
                    send_generation,
                    request_id,
                    send_owner_token,
                    send_relay_endpoint,
                    send_relay_connection_id,
                    deadline_permit,
                    result,
                )
            });
        }

        // Do not serialize probe delivery across peers.  A blocked writer is a
        // relay-connection failure, but it must not make peer B wait behind
        // peer A's 500ms boundary before B can even allocate/send its probe.
        for (
            peer_id,
            generation,
            request_id,
            owner_token,
            endpoint,
            connection_id,
            deadline_permit,
            result,
        ) in join_all(sends).await
        {
            match result {
                Ok(Ok(true)) => {
                    last_sent.insert(peer_id.clone(), now);
                    let count = attempt_counts
                        .entry(peer_id.clone())
                        .or_insert((0, generation));
                    count.0 = count.0.saturating_add(1);
                    count.1 = generation;
                    debug!(
                        event = "relay_probe_sent",
                        peer_id = %peer_id,
                        relay_endpoint = %endpoint,
                        generation = generation,
                        request_id = request_id,
                        "relay probe sent peer_id={peer_id} request_id={request_id}",
                    );
                    // Only the FIRST probe per peer + generation lands in the
                    // bounded timeline; re-sends are counted in the summary
                    // event emitted when the peer leaves the probe set, so the
                    // 64-event ring cannot be flooded by retries.
                    let scope = format!("peer:{peer_id}:{generation}");
                    timeline.emit_first_scoped(
                        &scope,
                        "relay_probe_sent",
                        Some("relay"),
                        None,
                        Some(format!(
                            "peer={peer_id} relay_endpoint={endpoint} generation={generation} request_id={request_id}"
                        )),
                    );
                }
                Ok(Ok(false)) => {
                    deadline_permit.revoke();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    probe_tokens.remove(&peer_id);
                    last_sent.remove(&peer_id);
                    timeline.emit(
                        "relay_probe_send_skipped",
                        Some("relay"),
                        Some("wireguard_session_unavailable"),
                        Some(format!(
                            "peer={peer_id} generation={generation} relay_endpoint={endpoint} request_id={request_id}"
                        )),
                    );
                    debug!("Relay probe skipped for {peer_id}: WireGuard session is not ready");
                }
                Ok(Err(err)) => {
                    deadline_permit.revoke();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    probe_tokens.remove(&peer_id);
                    last_sent.remove(&peer_id);
                    timeline.emit(
                        "relay_probe_send_failed",
                        Some("relay"),
                        Some("relay_send_failed"),
                        Some(format!(
                            "peer={peer_id} generation={generation} relay_endpoint={endpoint} request_id={request_id} error={err}"
                        )),
                    );
                    debug!("Relay probe send failed for {peer_id} via {endpoint}: {err}");
                }
                Err(_) => {
                    deadline_permit.revoke();
                    relay.abort_writer();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    probe_tokens.remove(&peer_id);
                    last_sent.remove(&peer_id);
                    // The probe already consumed its counter when encryption
                    // succeeded.  Never retry that ciphertext.  Invalidating
                    // the writer also wakes any other completion waiters and
                    // lets the supervisor establish a replacement transport.
                    timeline.emit(
                        "relay_probe_send_timeout",
                        Some("relay"),
                        Some("relay_writer_timeout"),
                        Some(format!(
                            "peer={peer_id} generation={generation} relay_endpoint={endpoint} request_id={request_id} timeout_ms={}",
                            RELAY_CONTROL_SEND_TIMEOUT.as_millis()
                        )),
                    );
                    warn!(
                        event = "relay_probe_send_timeout",
                        peer_id = %peer_id,
                        relay_endpoint = %endpoint,
                        generation = generation,
                        request_id = request_id,
                        "relay probe writer completion timed out; relay transport invalidated"
                    );
                }
            }
        }
        // Drop token/last-sent state for peers that no longer need a probe
        // (now confirmed, Direct, offline), so the maps stay bounded, and
        // report each such peer's total probe-attempt count as a summary
        // milestone (one event per peer + generation, never per re-send).
        let departed: Vec<(String, u64, u64)> = attempt_counts
            .iter()
            .filter(|(peer_id, _)| {
                !targets
                    .iter()
                    .any(|(target_id, _, _)| target_id == *peer_id)
            })
            .map(|(peer_id, (count, generation))| (peer_id.clone(), *count, *generation))
            .collect();
        for (peer_id, count, generation) in departed {
            let scope = format!("peer:{peer_id}:{generation}");
            timeline.emit_first_scoped(
                &scope,
                "relay_probe_attempts",
                Some("relay"),
                None,
                Some(format!(
                    "peer={peer_id} generation={generation} attempts={count}"
                )),
            );
        }
        probe_tokens
            .retain(|peer_id, _| targets.iter().any(|(target_id, _, _)| target_id == peer_id));
        last_sent.retain(|peer_id, _| targets.iter().any(|(target_id, _, _)| target_id == peer_id));
        attempt_counts
            .retain(|peer_id, _| targets.iter().any(|(target_id, _, _)| target_id == peer_id));

        // Synthetic path-commit probes: peers stuck on the relay-first business
        // gate (relay confirmed + Direct confirmed + no natural two-way
        // business) get a bounded path-commit request.  Its ack proves the
        // bidirectional relay-data invariant and releases the gate for
        // one-directional traffic (audit P0-4).  A fresh token is used per
        // request and the expectation is registered at the real relay writer
        // boundary, so queue delay cannot expire it and a late ack can only
        // match the outstanding request.
        let path_targets = peers.path_commit_targets().await;
        if !path_targets.is_empty() {
            let mut path_sends = Vec::new();
            for (peer_id, peer_virtual_ip, target_generation) in &path_targets {
                let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                    continue;
                };
                let session_status = transport.session_status(peer_id).await;
                if !session_status.has_active {
                    continue;
                }
                if peers.path_commit_expectation_present(peer_id) {
                    // An outstanding request is still in flight (within TTL);
                    // do not pile up duplicate probes.
                    continue;
                }
                let Some(send_peer_session_generation) =
                    peers.peer_session_generation_sync(peer_id)
                else {
                    continue;
                };
                next_request_id = next_request_id.wrapping_add(1);
                let request_id = next_request_id;
                let owner_token = unix_time_millis();
                let payload = crate::path_commit::build_path_commit_payload(
                    crate::path_commit::PathCommitKind::Request,
                    *target_generation,
                    request_id,
                    owner_token,
                );
                let packet =
                    Ipv4Packet::build_icmp_echo_request(local_ip, peer_ip, request_id, 1, &payload);
                let send_transport = transport.clone();
                let send_relay = relay.clone();
                let send_peer_id = peer_id.clone();
                let send_peer_virtual_ip = peer_virtual_ip.clone();
                let send_generation = *target_generation;
                let send_owner_token = owner_token;
                let send_connection_id = relay.connection_id();
                let send_peers = Arc::clone(&peers);
                let expectation_peer_id = send_peer_id.clone();
                let expectation_endpoint = relay_endpoint.clone();
                path_sends.push(async move {
                    let deadline_permit = RelayWriteBoundaryPermit::new();
                    let boundary_permit = deadline_permit.clone();
                    let result = tokio::time::timeout(
                        RELAY_CONTROL_SEND_TIMEOUT,
                        send_transport.encrypt_and_emit_outbound(
                            OutboundPacket {
                                room_authorization: None,
                                peer_id: send_peer_id.clone(),
                                dst_ip: send_peer_virtual_ip,
                                packet,
                                trace: None,
                            },
                            move |encrypted| async move {
                                send_relay
                                    .send_packet_with_write_boundary(&encrypted, move |sent_at| {
                                        boundary_permit.commit(|| {
                                            send_peers
                                                .register_path_commit_expectation_at_write_boundary(
                                                    &expectation_peer_id,
                                                    send_generation,
                                                    request_id,
                                                    send_owner_token,
                                                    &expectation_endpoint,
                                                    send_connection_id,
                                                    send_peer_session_generation,
                                                    sent_at,
                                                )
                                        })
                                    })
                                    .await
                            },
                        ),
                    )
                    .await;
                    (
                        send_peer_id,
                        send_generation,
                        request_id,
                        send_owner_token,
                        send_connection_id,
                        deadline_permit,
                        result,
                    )
                });
            }
            for (
                peer_id,
                generation,
                request_id,
                owner_token,
                connection_id,
                deadline_permit,
                result,
            ) in join_all(path_sends).await
            {
                match result {
                    Ok(Ok(true)) => debug!(
                        event = "path_commit_sent",
                        peer_id = %peer_id,
                        relay_endpoint = %relay_endpoint,
                        request_id = request_id,
                        "path_commit_sent peer_id={peer_id} relay_endpoint={relay_endpoint} request_id={request_id}"
                    ),
                    Ok(_) => {
                        deadline_permit.revoke();
                        peers.cancel_path_commit_expectation_if_matches(
                            &peer_id,
                            generation,
                            request_id,
                            owner_token,
                            connection_id,
                        );
                        debug!(
                            "path-commit request to {peer_id} was not sent (WireGuard session not ready)"
                        );
                    }
                    Err(err) => {
                        deadline_permit.revoke();
                        relay.abort_writer();
                        peers.cancel_path_commit_expectation_if_matches(
                            &peer_id,
                            generation,
                            request_id,
                            owner_token,
                            connection_id,
                        );
                        debug!(
                            "path-commit request to {peer_id} over {relay_endpoint} failed: {err}"
                        );
                    }
                }
            }
        }
    }
}

/// Emit bounded `relay_probe_attempts` summary milestones for every tracked
/// peer + generation (used when the target set empties as a whole).
pub(super) fn emit_probe_attempt_summaries(
    timeline: &crate::connection_timeline::ConnectionTimeline,
    attempt_counts: &HashMap<String, (u64, u64)>,
) {
    for (peer_id, (count, generation)) in attempt_counts {
        let scope = format!("peer:{peer_id}:{generation}");
        timeline.emit_first_scoped(
            &scope,
            "relay_probe_attempts",
            Some("relay"),
            None,
            Some(format!(
                "peer={peer_id} generation={generation} attempts={count}"
            )),
        );
    }
}

#[cfg(test)]
pub(crate) async fn send_relay_validation_packet(
    validation: RelayValidationPacket<'_>,
    transport: &WireGuardTransport,
    relay: &RelayTransport,
) -> Result<()> {
    let payload = build_relay_validation_payload(unix_time_millis());
    let packet = Ipv4Packet::build_icmp_echo_request(
        validation.local_ip,
        validation.peer_ip,
        validation.validation_id,
        validation.sequence,
        &payload,
    );
    let sent = transport
        .encrypt_and_emit_outbound(
            OutboundPacket {
                room_authorization: None,
                peer_id: validation.peer_id.to_string(),
                dst_ip: validation.peer_virtual_ip.to_string(),
                packet,
                trace: None,
            },
            |encrypted| async move { relay.send_packet(&encrypted).await },
        )
        .await?;
    if !sent {
        return Err(DaemonError::Peer(format!(
            "WireGuard session for peer {} is not ready",
            validation.peer_id
        )));
    }
    Ok(())
}
