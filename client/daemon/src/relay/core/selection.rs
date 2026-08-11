fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// How long after the FIRST relay connect success the selection keeps waiting
/// for a better-ranked (preferred-region) candidate before publishing.  This
/// is the explicit preference window: it must be very short so a black-hole
/// candidate never stretches the total selection time, while still letting a
/// preferred candidate that is already mid-connect win.
const RELAY_SELECTION_PREFERENCE_WINDOW: Duration = Duration::from_millis(25);

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
                        outcome: None,
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
                        outcome: None,
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
                        outcome: None,
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
                outcome: None,
            }),
        }
    }

    let mut tasks = JoinSet::new();
    for candidate in &candidates {
        let candidate = candidate.clone();
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

    // First-success publish with a very short explicit preference window.
    //
    // Every candidate connect runs concurrently and is internally bounded by
    // `selection_timeout`.  The moment ANY candidate succeeds:
    //   - if the success is the best-ranked (preferred-region) candidate, the
    //     selection publishes immediately;
    //   - otherwise it waits at most RELAY_SELECTION_PREFERENCE_WINDOW for a
    //     better-ranked candidate that is already mid-connect, then publishes
    //     the best success so far and ABORTS every still-running task.
    // A black-hole candidate can therefore never stretch the total selection
    // past (first success + the 25ms preference window).
    let mut connected = Vec::new();
    let mut first_success_at: Option<Instant> = None;
    let mut preference_deadline: Option<Instant> = None;

    loop {
        // Best-ranked preference rank among ALL connectable candidates.
        let best_rank = candidates
            .iter()
            .map(|candidate| candidate.preference_rank)
            .min();
        // Once we have a success, stop early if the best-ranked candidate has
        // succeeded (publish immediately) or the preference window elapsed.
        if first_success_at.is_some() {
            if connected
                .iter()
                .any(|c: &ConnectedCandidate| Some(c.candidate.preference_rank) == best_rank)
            {
                break;
            }
            if preference_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
            {
                break;
            }
        }
        let wait_budget = match (first_success_at, preference_deadline) {
            (Some(_), Some(deadline)) => deadline.saturating_duration_since(Instant::now()),
            _ => {
                // No success yet: keep joining until some task resolves.  Every
                // in-flight task is internally bounded by selection_timeout, so
                // this cannot wait forever; a black hole resolves with a
                // timeout result.
                Duration::from_secs(3600)
            }
        };
        if wait_budget.is_zero() {
            break;
        }

        let joined = tokio::time::timeout(wait_budget, tasks.join_next()).await;
        match joined {
            Ok(Some(Ok((candidate, latency_ms, result)))) => {
                let candidate_diagnostics = &mut diagnostics.candidates[candidate.index];
                candidate_diagnostics.connect_latency_ms = Some(latency_ms);

                match result {
                    Ok(Ok((transport, relay_rx))) => {
                        candidate_diagnostics.outcome = Some("success".to_string());
                        connected.push(ConnectedCandidate {
                            candidate,
                            transport,
                            relay_rx,
                        });
                        connected.sort_by_key(|connected| {
                            (
                                connected.candidate.preference_rank,
                                connected.transport.connect_latency_ms,
                                connected.candidate.index,
                            )
                        });
                        if first_success_at.is_none() {
                            first_success_at = Some(Instant::now());
                            preference_deadline =
                                Some(Instant::now() + RELAY_SELECTION_PREFERENCE_WINDOW);
                        }
                    }
                    Ok(Err(error)) => {
                        candidate_diagnostics.error = Some(error.to_string());
                        candidate_diagnostics.error_code = Some(error.error_code());
                        candidate_diagnostics.outcome = Some("failed".to_string());
                    }
                    Err(_) => {
                        candidate_diagnostics.error = Some(format!(
                            "relay selection timed out after {} ms",
                            duration_millis(selection_timeout)
                        ));
                        candidate_diagnostics.error_code = Some("timeout".to_string());
                        candidate_diagnostics.outcome = Some("timeout".to_string());
                    }
                }
            }
            Ok(Some(Err(_))) => {
                // Task panicked: cannot attribute a candidate; treat as failed.
            }
            Ok(None) => break, // every task resolved
            Err(_) => break,   // preference window elapsed after a first success
        }
    }

    // The publish decision is final: abort every still-running candidate so a
    // black hole (or any slower candidate) can never keep the supervisor busy
    // or leak a connection.  Candidates that never resolved are recorded as
    // cancelled so diagnostics distinguish success / failed / cancelled /
    // timeout for failover analysis.
    tasks.abort_all();
    for candidate in &candidates {
        let candidate_diagnostics = &mut diagnostics.candidates[candidate.index];
        if candidate_diagnostics.outcome.is_none() {
            candidate_diagnostics.outcome = Some("cancelled".to_string());
            if candidate_diagnostics.error.is_none() {
                candidate_diagnostics.error = Some(
                    "relay connect superseded by an earlier success; task cancelled".to_string(),
                );
                candidate_diagnostics.error_code = Some("cancelled".to_string());
            }
        }
    }

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
