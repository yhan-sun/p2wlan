/// Advertise the fresh-mapping prediction window to the peer.
///
/// The predicted ports are signaled in priority order (top-1 first, then the
/// successor window) as real `predicted` candidates carrying the distinct
/// fresh-prediction label with the sender's incarnation+generation.  No
/// reserved metadata keys are embedded in `candidate_sources`: the control
/// plane requires every key to be a real candidate, values to stay under 64
/// bytes, and the map size to stay within the candidate count, so model
/// details travel only in structured logs and diagnostics.  Older clients
/// simply probe the ordered candidates, so the signal degrades gracefully to
/// today's strategy.
///
/// Ownership checks run before building the payload, again before the
/// command is queued, and inside the HTTP worker before and during the request.
/// A newer delivered signal supersedes an older one through the receiver's
/// per-peer fresh-generation high-water. If an in-flight cancellation has
/// ambiguous delivery and no successor reached the server, the retired local
/// socket is still never finalized. Cancellation is reported distinctly from
/// a send failure.
///
/// Returns `true` only when the prediction was really accepted by the control
/// server while the session's ownership was still valid: the caller then
/// finalizes the generation's durable handoff.  A cancellation or a send
/// failure leaves the generation's socket rollable, so the caller must drop
/// the guard instead of finalizing.
async fn advertise_fresh_mapping_prediction(
    signal: &HolePunchSignalContext,
    peers: &Arc<PeerManager>,
    peer_id: &str,
    result: &FreshMappingResult,
    cancellation: &Arc<crate::PunchSessionCancellation>,
) -> bool {
    if cancellation.is_cancelled() {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                None,
                None,
                "fresh-mapping prediction ownership was revoked before the payload was built",
            )
            .await;
        return false;
    }
    let snapshot = signal.candidate_snapshot.read().await.clone();
    let (local_candidates, local_candidate_sources) = snapshot
        .map(|snapshot| (snapshot.candidates, snapshot.candidate_sources))
        .unwrap_or_default();
    let (candidates, candidate_sources) = build_fresh_mapping_signal_payload(
        result,
        signal.boot_epoch_ms,
        &local_candidates,
        &local_candidate_sources,
    );

    let punch_at_ms = Some(relay_assisted_punch_at_ms());
    if cancellation.is_cancelled() {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction ownership was revoked before the signal was queued",
            )
            .await;
        return false;
    }
    // Direct may have been confirmed while the generation measured: a
    // post-convergence prediction advertisement would be pure HTTP noise and
    // must not reach the wire.
    if peers.is_direct(peer_id).await {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction was not advertised because Direct was confirmed before the HTTP request",
            )
            .await;
        return false;
    }
    // The command worker re-checks ownership inside the queue, immediately
    // before HTTP, and while the request is in flight. `Cancelled` therefore
    // means delivery is not authoritative: the server may already have
    // accepted a request whose local response future was dropped, so the
    // caller must roll back instead of finalizing the socket.
    match signal
        .control
        .send_fresh_peer_offer_with_sources_and_punch_at(
            peer_id,
            &candidates,
            &candidate_sources,
            &[],
            punch_at_ms,
            cancellation.clone(),
        )
        .await
    {
        Ok(()) => {}
        Err(PeerOfferSendFailure::Cancelled) => {
            peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    None,
                    Some(candidates.len()),
                    None,
                    "fresh-mapping prediction ownership was revoked while queued or in flight; delivery is ambiguous and the socket must not be finalized",
                )
                .await;
            debug!(
                "Fresh-mapping prediction to peer {peer_id} was cancelled while queued or in flight; delivery is ambiguous and the socket will not be finalized"
            );
            return false;
        }
        Err(PeerOfferSendFailure::SendFailed | PeerOfferSendFailure::ChannelClosed) => {
            warn!("Failed to advertise fresh-mapping prediction window to peer {peer_id}");
            return false;
        }
    }
    // The HTTP request completed and the server accepted the signal, but the
    // ownership may have been revoked while the request was in flight: only a
    // still-valid ownership lets the caller finalize the socket, otherwise
    // the watcher restores the predecessor.
    if cancellation.is_cancelled() {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction was sent but its punch session was superseded before the durable handoff; the socket rolls back",
            )
            .await;
        return false;
    }
    // Direct may have been confirmed while the advertisement HTTP request was
    // in flight: the request was already on the wire (pre-Direct), but the
    // socket must roll back and no post-convergence signal may be recorded.
    if peers.is_direct(peer_id).await {
        peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_skipped",
                None,
                Some(candidates.len()),
                None,
                "fresh-mapping prediction was sent pre-Direct but Direct was confirmed while the advertisement was in flight; the socket rolls back",
            )
            .await;
        return false;
    }
    info!(
        event = "fresh_mapping_prediction_signaled",
        peer_id = %peer_id,
        punch_generation = result.punch_generation,
        network_generation = result.network_generation,
        socket_local_endpoint = %result.socket_local_endpoint,
        first_punch_sent_at_ms = result.first_punch_sent_at_ms,
        last_punch_sent_at_ms = result.last_punch_sent_at_ms,
        socket_index = result.socket_index,
        predicted = ?result.predicted_ports,
        model = ?result.model.kind,
        confidence = result.model.confidence,
        candidate_count = candidates.len(),
        punch_at_ms = ?punch_at_ms,
        "fresh_mapping_prediction_signaled peer_id={} punch_generation={} network_generation={} socket_local={} first_sent_ms={} last_sent_ms={} socket_index={} predicted={:?} model={:?} confidence={} candidates={}",
        peer_id,
        result.punch_generation,
        result.network_generation,
        result.socket_local_endpoint,
        result.first_punch_sent_at_ms,
        result.last_punch_sent_at_ms,
        result.socket_index,
        result.predicted_ports,
        result.model.kind,
        result.model.confidence,
        candidates.len()
    );
    peers
        .record_direct_event(
            peer_id,
            "fresh_mapping_prediction_signaled",
            None,
            Some(candidates.len()),
            None,
            format!(
                "signaled predicted window punch_generation={} network_generation={} socket_local={} first_sent_ms={} last_sent_ms={} predicted={:?} model={:?} confidence={} candidates={}",
                result.punch_generation,
                result.network_generation,
                result.socket_local_endpoint,
                result.first_punch_sent_at_ms,
                result.last_punch_sent_at_ms,
                result.predicted_ports,
                result.model.kind.clone().label(),
                result.model.confidence,
                candidates.len()
            ),
        )
        .await;
    true
}

/// Build the signal payload carrying the fresh-mapping prediction window.
///
/// The payload must satisfy the control-plane validation rules applied by the
/// Go signaling service: every `candidate_sources` key must be a real
/// candidate, values must stay under 64 bytes, and the map size must not
/// exceed the candidate count.  The predicted ports are ordered top-1 first so
/// the stable side probes the model prediction before the successor window.
fn build_fresh_mapping_signal_payload(
    result: &FreshMappingResult,
    boot_epoch_ms: u64,
    current_candidates: &[String],
    current_sources: &HashMap<String, String>,
) -> (Vec<String>, HashMap<String, String>) {
    let mut candidates = Vec::new();
    let mut candidate_sources = HashMap::new();
    // Distinct label carrying the sender's incarnation epoch and per-peer
    // punch generation: ordinary ICE `predicted` candidates must not be
    // mistaken for a fresh prediction, and the embedded identity orders
    // predictions by measurement generation instead of HTTP send time.
    let fresh_id = FreshPredictionId {
        boot_epoch: boot_epoch_ms,
        generation: result.punch_generation,
    };
    let fresh_label = fresh_prediction_source_label(fresh_id);
    for port in &result.predicted_ports {
        let endpoint = SocketAddr::new(
            result
                .public_ip
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            *port,
        )
        .to_string();
        if !candidates.contains(&endpoint) {
            candidates.push(endpoint.clone());
            candidate_sources.insert(endpoint, fresh_label.clone());
        }
    }
    for endpoint in current_candidates {
        if !candidates.contains(endpoint) {
            candidates.push(endpoint.clone());
        }
        if let Some(source) = current_sources.get(endpoint) {
            // Never overwrite the fresh-prediction label of an overlapping
            // predicted port with the ordinary ICE label.
            candidate_sources
                .entry(endpoint.clone())
                .or_insert_with(|| source.clone());
        }
    }
    let _network_identity = prepare_signal_candidates_and_network_identity(
        &[],
        &HashMap::new(),
        &mut candidates,
        &mut candidate_sources,
    );
    (candidates, candidate_sources)
}
