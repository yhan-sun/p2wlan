// Native ACK consumption: parse before qualification, diagnostics only after
// the sole PeerManager synchronous current-owner/once transaction returns.
pub(crate) struct SourcedOverlayOwners {
    pub(crate) wireguard: crate::transport::WireGuardTransport,
    pub(crate) relay: Arc<RwLock<Option<crate::relay::RelayTransport>>>,
    pub(crate) room: Arc<crate::rooms::RoomAuthorization>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OriginalRequestEchoOutcome {
    Injected,
    Queued,
    DuplicateRequest,
    InjectionFailed,
    Rejected(crate::overlay_requests::OverlayCreditOutcome),
}

#[allow(clippy::too_many_arguments)]
async fn handle_native_overlay_request(
    event: OverlayIngressEvent,
    source: Option<crate::transport::OriginalOverlayIngressSource>,
    owners: &SourcedOverlayOwners,
    udp: &Arc<RwLock<Option<UdpTransport>>>,
    peers: &Arc<PeerManager>,
    controller: &MockTunController,
    local_vip: &str,
    overlay_any_path: bool,
    start_gate_released: bool,
    seen: &mut VecDeque<(u64, u32)>,
    stats: &mut OverlayStats,
    pending_echoes: &mut VecDeque<PendingOverlayEcho>,
) -> OriginalRequestEchoOutcome {
    use crate::overlay_requests::{
        OriginalOverlayAck, OverlayCreditOutcome as Credit, OverlayCreditStale as Stale,
        OverlayCreditUnknown as Unknown,
    };
    use OriginalRequestEchoOutcome::*;
    if owners.room.enabled() {
        return Rejected(Credit::Unknown(Unknown::RoomAuthority));
    }
    let Some(request) = OriginalOverlayAck::parse_request(&event.packet, &event.peer_id) else {
        return Rejected(Credit::Stale(Stale::Identity));
    };
    if request.local_vip != local_vip {
        return Rejected(Credit::Stale(Stale::Identity));
    }
    let Some(source) = source else {
        return Rejected(Credit::Unknown(Unknown::OriginalSource));
    };
    if source.network_generation() != Some(event.connection_generation) {
        return Rejected(Credit::Stale(Stale::Generation));
    }
    if source.session().original_role() != crate::transport::OriginalSessionRole::Active
        || !source.session().belongs_to(&owners.wireguard)
    {
        return Rejected(Credit::Stale(Stale::Session));
    }
    if seen.contains(&(request.nonce, request.seq)) {
        return DuplicateRequest;
    }
    let nonce = request.nonce;
    let seq = request.seq;
    let peer = request.peer_id.clone();
    let Some(mut echo) = build_pending_overlay_echo(
        local_vip,
        peer.clone(),
        request.source_vip.clone(),
        event.connection_generation,
        nonce,
        seq,
    ) else {
        return Rejected(Credit::Stale(Stale::Identity));
    };
    let Some(input) = crate::overlay_requests::OriginalEchoInput::capture(
        peers,
        &owners.wireguard,
        udp,
        &owners.relay,
        request,
        source,
        &echo.packet,
    ) else {
        return Rejected(Credit::Unknown(Unknown::OriginalSource));
    };
    loop {
        if !crate::request_carriage::in_original_window(input.read_at(), Instant::now()) {
            return Rejected(Credit::Stale(Stale::OriginalWindow));
        }
        match input.qualify_before_injection(&owners.wireguard) {
            Ok(()) => break,
            Err(Credit::Contended(_)) => {
                // Keep this original input before TUN injection. Qualification
                // releases every guard; each paced attempt rechecks current
                // owners and the unmodified original read deadline.
                let wake = (input.read_at() + OVERLAY_NONCE_TTL)
                    .min(Instant::now() + Duration::from_millis(20));
                tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
            }
            Err(reason) => return Rejected(reason),
        }
    }
    // The original read time is also the queue deadline. Readiness waits and
    // actor transfers cannot renew this immutable source's lifetime.
    echo.queued_at = input.read_at();
    echo.original_echo = Some(crate::overlay_requests::RequestSendToken::original_echo(
        input,
    ));
    let direct = committed_direct_ready_for_echo(peers, &peer, event.connection_generation);
    let ready = direct && overlay_direct_business_budget_ready(Some(udp), &peer).await;
    let outcome = if start_gate_released && (overlay_any_path || ready) {
        if inject_pending_overlay_echo(controller, echo).await {
            Injected
        } else {
            InjectionFailed
        }
    } else {
        if pending_echoes.len() >= OVERLAY_PENDING_ECHO_CAP {
            pending_echoes.pop_front();
        }
        pending_echoes.push_back(echo);
        Queued
    };
    if matches!(outcome, Injected | Queued) {
        seen.push_back((nonce, seq));
        while seen.len() > OVERLAY_SEEN_CAP {
            seen.pop_front();
        }
        stats.received_valid = stats.received_valid.saturating_add(1);
    }
    // REQUEST never consumes a local canonical once or verified roundtrip.
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn handle_native_overlay_ack(
    event: OverlayIngressEvent,
    source: Option<crate::transport::OriginalOverlayIngressSource>,
    owners: &SourcedOverlayOwners,
    udp: &Arc<RwLock<Option<UdpTransport>>>,
    peers: &Arc<PeerManager>,
    timeline: &Arc<ConnectionTimeline>,
    seen: &mut VecDeque<(u64, u32)>,
    stats: &mut OverlayStats,
    sent_nonces: &HashMap<u64, SentOverlayNonce>,
    bursts: &mut HashMap<String, OverlayBurst>,
) {
    use crate::overlay_requests::{OriginalOverlayAck, OverlayCreditOutcome};
    let Some(ack) = OriginalOverlayAck::parse(&event.packet, &event.peer_id) else {
        return;
    };
    let request = sent_nonces
        .get(&ack.nonce)
        .filter(|request| request.peer_id == ack.peer_id && request.seq == ack.seq)
        .cloned()
        .or_else(|| {
            bursts
                .get(&ack.peer_id)
                .filter(|burst| burst.fired_at.is_some())
                .and_then(|burst| {
                    burst.nonces.iter().find(|request| {
                        request.nonce == ack.nonce
                            && request.seq == ack.seq
                            && request.peer_id == ack.peer_id
                    })
                })
                .cloned()
        });
    let Some(request) = request else {
        return;
    };
    let borrowed = crate::peer::OriginalOverlayCurrentOwners {
        wireguard: &owners.wireguard,
        udp,
        relay: &owners.relay,
        room: &owners.room,
    };
    let outcome = loop {
        let outcome =
            peers.try_commit_original_overlay_ack(&borrowed, &request, &ack, source.as_ref());
        if !matches!(outcome, OverlayCreditOutcome::Contended(_))
            || !crate::request_carriage::in_original_window(request.sent_at, Instant::now())
        {
            break outcome;
        }
        // The synchronous transaction released every owner guard. Retain only
        // this received ACK and canonical request while waiting; the next
        // attempt requalifies all current owners before consuming once. No
        // packet is resent and no source or deadline is replaced.
        let wake =
            (request.sent_at + OVERLAY_NONCE_TTL).min(Instant::now() + Duration::from_millis(20));
        tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
    };
    let OverlayCreditOutcome::Fresh(receipt) = outcome else {
        debug!(event = "overlay_native_ack_rejected", outcome = ?outcome,
            "original ACK did not commit native credit");
        return;
    };
    // No authority is granted after this point. All owner guards are gone;
    // statistics and timeline consume only the immutable committed receipt.
    seen.push_back((ack.nonce, ack.seq));
    while seen.len() > OVERLAY_SEEN_CAP {
        seen.pop_front();
    }
    stats.received_valid = stats.received_valid.saturating_add(1);
    stats.verified_round_trips = stats.verified_round_trips.saturating_add(1);
    let path = match receipt.path {
        crate::peer::NetworkPath::Direct => "direct",
        crate::peer::NetworkPath::Relay => "relay",
    };
    let ingress = match receipt.path {
        crate::peer::NetworkPath::Direct => "direct".to_string(),
        crate::peer::NetworkPath::Relay => format!(
            "relay:{}",
            source
                .as_ref()
                .and_then(|source| source.relay_endpoint())
                .unwrap_or_default()
        ),
    };
    // Compatibility evidence is emitted only after the original owner has
    // committed this exact ACK. A REQUEST/rejection/duplicate never logs it.
    info!(
        native_original_ack = true,
        "{OVERLAY_EVIDENCE_PREFIX}_verified peer={} src_ip={} seq={} nonce={:#x} len={} ingress={} verified_round_trips={}",
        ack.peer_id, ack.source_vip, ack.seq, ack.nonce,
        event.packet.len(), ingress, stats.verified_round_trips,
    );
    let scope = format!("peer:{}:{}", ack.peer_id, receipt.generation);
    let newly_confirmed = timeline.emit_first_scoped(
        &scope,
        "first_usable_bidirectional_overlay_ms",
        Some(path),
        receipt.fallback_reason,
        Some(format!(
            "peer={} seq={} generation={} native_original_ack=true attempt={} first_usable_new={}",
            ack.peer_id, ack.seq, receipt.generation, receipt.attempt_id, receipt.first_usable_new
        )),
    );
    if newly_confirmed {
        info!(event = "first_usable_confirmed", peer_id = %ack.peer_id, path,
            generation = receipt.generation, native_original_ack = true,
            "first_usable_confirmed from the original current-owner ACK transaction");
        bursts
            .entry(ack.peer_id.clone())
            .or_insert_with(|| OverlayBurst {
                armed: true,
                nonces: Vec::new(),
                sent: 0,
                received: 0,
                fired_at: None,
            })
            .armed = true;
    }
    let mut complete = None;
    if let Some(burst) = bursts.get_mut(&ack.peer_id) {
        if let Some(index) = burst
            .nonces
            .iter()
            .position(|entry| Arc::ptr_eq(entry, &request))
        {
            burst.nonces.swap_remove(index);
            burst.received = burst.received.saturating_add(1);
            if burst.received >= burst.sent {
                complete = Some((burst.sent, burst.received));
            }
        }
    }
    if let Some((sent, received)) = complete {
        bursts.remove(&ack.peer_id);
        info!(event = "overlay_burst_complete", peer = %ack.peer_id, sent, received,
            "overlay_burst_complete from canonical original ACK receipts");
        timeline.emit(
            "overlay_burst_complete",
            None,
            None,
            Some(format!(
                "peer={} sent={sent} received={received}",
                ack.peer_id
            )),
        );
    }
}
