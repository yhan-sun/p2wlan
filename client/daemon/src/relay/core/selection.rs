fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// Connect to all valid relay candidates concurrently and select the best one.
/// Preferred regions win first; connection latency and config order break ties.
///
/// A2 parameters (ticket, TLS config) are passed through to the relay client.
#[allow(clippy::too_many_arguments)]
pub async fn select_relay(
    specs: &[RelayCandidateConfig],
    preferred_regions: &[String],
    selection_timeout: Duration,
    node_id: &str,
    peers: Arc<PeerManager>,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
) -> RelaySelectionOutcome {
    let cooldowns = HashMap::new();
    select_relay_with_cooldowns(
        specs,
        preferred_regions,
        selection_timeout,
        node_id,
        peers,
        ticket_cache,
        static_relay_ticket,
        allow_insecure_plaintext,
        ca_cert_path,
        &cooldowns,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn select_relay_with_cooldowns(
    specs: &[RelayCandidateConfig],
    preferred_regions: &[String],
    selection_timeout: Duration,
    node_id: &str,
    peers: Arc<PeerManager>,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
    cooldowns: &HashMap<String, Instant>,
) -> RelaySelectionOutcome {
    let mut diagnostics = RelaySelectionDiagnostics::default();
    let mut candidates = Vec::new();
    let mut seen_endpoints = HashSet::new();
    let now = Instant::now();

    for (index, spec) in specs.iter().enumerate() {
        match parse_candidate(index, spec, preferred_regions) {
            Ok(candidate) => {
                if let Some(remaining) = cooldowns
                    .get(&candidate.endpoint)
                    .and_then(|until| until.checked_duration_since(now))
                {
                    let remaining_ms = duration_millis(remaining);
                    diagnostics.candidates.push(RelayCandidateDiagnostics {
                        region: candidate.region,
                        endpoint: candidate.endpoint,
                        connect_latency_ms: None,
                        cooldown_remaining_ms: Some(remaining_ms),
                        error: Some(format!(
                            "relay candidate cooling down for {remaining_ms} ms"
                        )),
                        error_code: Some("cooling_down".to_string()),
                    });
                    continue;
                }

                if seen_endpoints.insert(candidate.endpoint.clone()) {
                    diagnostics.candidates.push(RelayCandidateDiagnostics {
                        region: candidate.region.clone(),
                        endpoint: candidate.endpoint.clone(),
                        connect_latency_ms: None,
                        cooldown_remaining_ms: None,
                        error: None,
                        error_code: None,
                    });
                    candidates.push(candidate);
                } else {
                    diagnostics.candidates.push(RelayCandidateDiagnostics {
                        region: candidate.region,
                        endpoint: candidate.endpoint,
                        connect_latency_ms: None,
                        cooldown_remaining_ms: None,
                        error: Some("duplicate relay endpoint".to_string()),
                        error_code: Some("duplicate_endpoint".to_string()),
                    });
                }
            }
            Err(error) => diagnostics.candidates.push(RelayCandidateDiagnostics {
                region: "unknown".to_string(),
                endpoint: spec.endpoint.trim().to_string(),
                connect_latency_ms: None,
                cooldown_remaining_ms: None,
                error: Some(error),
                error_code: Some("invalid_spec".to_string()),
            }),
        }
    }

    let mut tasks = JoinSet::new();
    for candidate in candidates {
        let node_id = node_id.to_string();
        let peers = peers.clone();
        let ticket_cache = ticket_cache.clone();
        let static_ticket = static_relay_ticket.clone();
        let ca_path = ca_cert_path.clone();
        tasks.spawn(async move {
            let started = Instant::now();
            let result = timeout(selection_timeout, async {
                let ticket: Option<(String, i64)> =
                    relay_ticket_for_candidate(&candidate, ticket_cache, static_ticket)
                        .await?;
                let (transport, relay_rx) = RelayTransport::connect_in_region(
                    &candidate.endpoint,
                    &candidate.region,
                    &node_id,
                    peers,
                    ticket.as_ref().map(|(ticket, _)| ticket.clone()),
                    allow_insecure_plaintext,
                    ca_path,
                )
                .await
                .map_err(RelayAttemptError::Relay)?;
                // Attach the ticket deadline so the supervisor can renew
                // BEFORE the server closes the connection at expiry.  The
                // audience is the ticket's audience.
                let transport = match (ticket, candidate.audience.clone()) {
                    (Some((_, expires_at_unix)), Some(audience)) if expires_at_unix > 0 => {
                        transport.with_ticket_metadata(&audience, &candidate.region, expires_at_unix)
                    }
                    _ => transport,
                };
                Ok::<_, RelayAttemptError>((transport, relay_rx))
            })
            .await;
            let latency_ms = duration_millis(started.elapsed());
            (candidate, latency_ms, result)
        });
    }

    let mut connected = Vec::new();
    while let Some(task_result) = tasks.join_next().await {
        let Ok((candidate, latency_ms, result)) = task_result else {
            continue;
        };
        let candidate_diagnostics = &mut diagnostics.candidates[candidate.index];
        candidate_diagnostics.connect_latency_ms = Some(latency_ms);

        match result {
            Ok(Ok((transport, relay_rx))) => connected.push(ConnectedCandidate {
                candidate,
                transport,
                relay_rx,
            }),
            Ok(Err(error)) => {
                candidate_diagnostics.error = Some(error.to_string());
                candidate_diagnostics.error_code = Some(error.error_code());
            }
            Err(_) => {
                candidate_diagnostics.error = Some(format!(
                    "relay selection timed out after {} ms",
                    duration_millis(selection_timeout)
                ));
                candidate_diagnostics.error_code = Some("timeout".to_string());
            }
        }
    }

    connected.sort_by_key(|connected| {
        (
            connected.candidate.preference_rank,
            connected.transport.connect_latency_ms,
            connected.candidate.index,
        )
    });

    if let Some(selected) = connected.into_iter().next() {
        diagnostics.selected_region = Some(selected.candidate.region.clone());
        diagnostics.selected_endpoint = Some(selected.candidate.endpoint.clone());
        diagnostics.selected_connect_latency_ms = Some(selected.transport.connect_latency_ms);
        RelaySelectionOutcome {
            transport: Some(selected.transport),
            relay_rx: Some(selected.relay_rx),
            diagnostics,
        }
    } else {
        diagnostics.last_error = Some(if specs.is_empty() {
            "no relay candidates configured".to_string()
        } else {
            "all relay candidates failed".to_string()
        });
        if let Some(first_failed) = diagnostics.candidates.iter().find(|c| c.error.is_some()) {
            diagnostics.last_error_code = first_failed.error_code.clone();
        } else {
            diagnostics.last_error_code = Some("no_candidates".to_string());
        }
        RelaySelectionOutcome {
            transport: None,
            relay_rx: None,
            diagnostics,
        }
    }
}

/// Fetch the ticket for a candidate together with its server-side expiry
/// (unix seconds), so the connected transport can schedule the proactive
/// renewal before the server closes the connection at expiry.
async fn relay_ticket_for_candidate(
    candidate: &RelayCandidate,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
) -> std::result::Result<Option<(String, i64)>, RelayAttemptError> {
    if let (Some(cache), Some((audience, region))) =
        (ticket_cache, relay_ticket_lookup_key(candidate))
    {
        let expiry = cache.ticket_expiry_for(audience, region).await;
        let ticket = cache.ticket_for(audience, region).await.map_err(RelayAttemptError::Daemon)?;
        // ticket_for may have refreshed the cache: read the authoritative
        // expiry after the fetch.
        let expiry = cache
            .ticket_expiry_for(audience, region)
            .await
            .or(expiry)
            .unwrap_or(0);
        return Ok(Some((ticket, expiry)));
    }

    Ok(static_relay_ticket.map(|ticket| (ticket, 0)))
}

fn relay_ticket_lookup_key(candidate: &RelayCandidate) -> Option<(&str, &str)> {
    candidate
        .audience
        .as_deref()
        .map(|audience| (audience, candidate.region.as_str()))
}
