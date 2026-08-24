#[allow(clippy::too_many_arguments)]
pub(super) async fn send_signal(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    from_node_id: &str,
    to_node_id: &str,
    signal_type: &str,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    handshake: &[u8],
    punch_at_ms: Option<u64>,
    punch_at_server_ms: Option<u64>,
    session_id: Option<&str>,
    probe_ephemeral_public_key: Option<&str>,
    signing_identity: Option<&SignalSigningIdentity>,
) -> Result<()> {
    let payload = prepare_signal_payload(
        from_node_id,
        to_node_id,
        signal_type,
        candidates,
        candidate_sources,
        handshake,
        punch_at_ms,
        punch_at_server_ms,
        session_id,
        probe_ephemeral_public_key,
        signing_identity,
    )?;
    send_prepared_signal(http, base_url, token, &payload).await
}

/// Build one immutable signal body.
///
/// Critical handshake delivery retries this exact value. In particular, the
/// candidate generation, expiry, Probe signature, session id, and WireGuard
/// bytes must not change between delivery-ambiguous attempts.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_signal_payload(
    from_node_id: &str,
    to_node_id: &str,
    signal_type: &str,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    handshake: &[u8],
    punch_at_ms: Option<u64>,
    punch_at_server_ms: Option<u64>,
    session_id: Option<&str>,
    probe_ephemeral_public_key: Option<&str>,
    signing_identity: Option<&SignalSigningIdentity>,
) -> Result<serde_json::Value> {
    // `candidate_generation` is the signal/candidate freshness revision, not
    // a declaration that this process rebound its UDP transport. A fresh
    // offer/answer (including a routine WireGuard rekey) deliberately gets a
    // new revision even when `candidates` is identical; receivers compare the
    // candidate set and encrypted-confirmed endpoint before declaring a remote
    // transport handover. Keep the revision and expiry derived from one
    // instant so the set has a coherent lifetime even if the wall clock moves.
    // A refused generation (incarnation or per-boot counter exhausted) fails
    // the whole signal instead of sending a wrapped value receivers judge
    // stale.
    let candidate_generation = next_candidate_generation().map_err(|error| {
        warn!("{error}; dropping this candidate signal");
        DaemonError::ControlPlane(error.to_string())
    })?;
    let client_time_ms = unix_time_millis();
    let candidates_expires_at_ms = client_time_ms.saturating_add(45_000);
    let probe_ephemeral_signature = sign_probe_ephemeral_transcript(
        signing_identity,
        signal_type,
        from_node_id,
        to_node_id,
        session_id,
        probe_ephemeral_public_key,
        candidate_generation,
        candidates_expires_at_ms,
    );
    Ok(serde_json::json!({
        "from_node_id": from_node_id,
        "to_node_id": to_node_id,
        "type": signal_type,
        "protocol_version": SIGNAL_REST_PROTOCOL_VERSION,
        "candidates": candidates,
        "candidate_sources": candidate_sources,
        "candidate_generation": candidate_generation,
        "candidates_expires_at_ms": candidates_expires_at_ms,
        "session_id": session_id,
        "probe_ephemeral_public_key": probe_ephemeral_public_key,
        "probe_ephemeral_signature": probe_ephemeral_signature,
        "handshake": hex::encode(handshake),
        "punch_at_ms": punch_at_ms,
        "punch_at_server_ms": punch_at_server_ms,
        "client_time_ms": client_time_ms,
    }))
}

/// Send a signal body that was prepared once by its owning handshake.
pub(super) async fn send_prepared_signal(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    payload: &serde_json::Value,
) -> Result<()> {
    let res = http
        .post(format!("{base_url}/api/v1/signals"))
        .timeout(SIGNAL_SEND_TIMEOUT)
        .bearer_auth(token)
        .json(payload)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("send signal request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "send signal returned HTTP {}",
            res.status()
        )));
    }

    let body: SignalCreateResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("send signal decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "send signal failed".to_string()),
        ));
    }
    if let Some(protocol_version) = body.protocol_version {
        if protocol_version != SIGNAL_REST_PROTOCOL_VERSION {
            warn!(
                "Control server returned unsupported signal protocol_version={} (client supports {})",
                protocol_version, SIGNAL_REST_PROTOCOL_VERSION
            );
        }
    }

    // This is a server-side queue receipt, not a peer-delivery proof.  Keep it
    // in the log so a later receiver-side `signal_delivery_enqueued` event can
    // be correlated without logging handshake bytes, credentials, or tickets.
    if let Some(receipt) = body.signal.as_ref() {
        let expected_to = payload
            .get("to_node_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<missing>");
        let received_to = receipt.to_node_id.as_deref().unwrap_or("<missing>");
        if receipt.to_node_id.as_deref().is_some_and(|to| to != expected_to) {
            return Err(DaemonError::ControlPlane(format!(
                "control signal receipt target mismatch: expected {expected_to}, got {received_to}"
            )));
        }
        debug!(
            "Control signal queued receipt id={:?} from={:?} to={:?} type={:?} signal_seq={:?}",
            receipt.id,
            receipt.from_node_id,
            receipt.to_node_id,
            receipt.signal_type,
            receipt.signal_seq,
        );
    }

    Ok(())
}

pub(super) async fn poll_signals(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    wait_ms: u64,
    delivery_tracker: &Arc<tokio::sync::Mutex<SignalDeliveryTracker>>,
) -> Result<()> {
    // ACK mode (`ack=1`): the server hands out delivery LEASES instead of
    // deleting rows at GET time, so a connection that breaks mid-body or a
    // client that dies mid-processing can never lose a signal — the lease
    // expires and the batch is redelivered.  An old server ignores the query
    // parameter and keeps its delete-on-GET contract, which is exactly what
    // an old client expects (no infinite redelivery either way).
    let res = http
        .get(format!(
            "{base_url}/api/v1/signals?node_id={self_node_id}&wait_ms={wait_ms}&ack=1"
        ))
        .timeout(signal_poll_timeout(wait_ms))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list signals request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "list signals returned HTTP {}",
            res.status()
        )));
    }

    let body: ListSignalsResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list signals decode failed: {e}")))?;
    let received_at_ms = unix_time_millis();
    let server_time_ms = body.server_time_ms;
    if let Some(protocol_version) = body.protocol_version {
        if protocol_version != SIGNAL_REST_PROTOCOL_VERSION {
            warn!(
                "Control server list response used signal protocol_version={} (client supports {})",
                protocol_version, SIGNAL_REST_PROTOCOL_VERSION
            );
        }
    }
    let ack_mode = body.delivery.is_some();
    if let Some(delivery) = body.delivery.as_ref() {
        debug!(
            "Control server granted an ACK-mode delivery lease (batch_token={} lease_expires_at_ms={:?}); acknowledging each row only after state-machine application",
            delivery.batch_token, delivery.lease_expires_at_ms
        );
    }

    // ACK-mode rows are handed to detached, per-sender ordered application
    // lanes below. Keeping those lanes outside the HTTP/control heartbeat loop
    // prevents a slow responder handshake from starving the device lease
    // heartbeat, while one blocked peer cannot stall an independent sender.
    let mut leased_deliveries: HashMap<String, Vec<LeasedSignalDelivery>> = HashMap::new();
    let mut blocked_senders = HashSet::new();
    for signal in body.signals {
        let sender_key = signal.from_node_id.clone();
        if blocked_senders.contains(&sender_key) {
            continue;
        }
        let delivery_ack = match (signal.id.as_deref(), signal.delivery_token.as_deref()) {
            (Some(signal_id), Some(delivery_token)) => Some(SignalAckRequest {
                id: signal_id.to_string(),
                delivery_token: delivery_token.to_string(),
            }),
            _ => None,
        };

        if ack_mode && delivery_ack.is_none() {
            warn!(
                "Rejecting ACK-mode signal batch at id={:?}: missing id or delivery_token; leaving this row and every later row from the same sender unacknowledged",
                signal.id
            );
            blocked_senders.insert(sender_key);
            continue;
        }

        debug!(
            "Control signal delivery received id={:?} from={} to={:?} type={} signal_seq={:?}",
            signal.id,
            signal.from_node_id,
            signal.to_node_id,
            signal.signal_type,
            signal.signal_seq,
        );

        if signal
            .to_node_id
            .as_deref()
            .is_some_and(|to_node_id| to_node_id != self_node_id)
        {
            warn!(
                "Rejecting control signal delivery id={:?}: target mismatch expected={} got={:?} reason_code=signal_wrong_target",
                signal.id, self_node_id, signal.to_node_id
            );
            // Do not ACK a row that the server claims belongs to another
            // device.  Its lease will expire and preserve evidence of the
            // routing defect for the control-plane operator.
            blocked_senders.insert(sender_key);
            continue;
        }
        if signal.protocol_version != SIGNAL_REST_PROTOCOL_VERSION {
            warn!(
                "Skipping unsupported signal protocol_version={} from {} type={}",
                signal.protocol_version, signal.from_node_id, signal.signal_type
            );
            if let (Some(signal_id), Some(ack)) = (signal.id.clone(), delivery_ack) {
                leased_deliveries
                    .entry(sender_key)
                    .or_default()
                    .push(LeasedSignalDelivery {
                        signal_id,
                        signal_seq: signal.signal_seq,
                        from_node_id: signal.from_node_id,
                        ack,
                        prepared: PreparedSignalDelivery::TerminalRejected,
                    });
            }
            continue;
        }
        let punch_at_ms =
            normalize_signal_punch_at(signal.punch_at_ms, server_time_ms, received_at_ms);
        let punch_at_server_ms = signal.punch_at_ms.filter(|_| server_time_ms.is_some());
        let candidates_expires_at_ms = normalize_signal_candidate_expiry(
            signal.candidates_expires_at_ms,
            server_time_ms,
            received_at_ms,
        );
        // One malformed signal must never abort the batch: the server already
        // leased every delivered row, so aborting here would drop the healthy
        // signals of the same poll together with the bad one (their leases
        // would expire and redeliver, so nothing is lost).
        let handshake = if signal.handshake.trim().is_empty() {
            Some(Vec::new())
        } else if signal.handshake.trim().len() % 2 != 0 {
            warn!(
                "Skipping signal from {} type={}: handshake hex has an odd length",
                signal.from_node_id, signal.signal_type
            );
            None
        } else {
            match hex::decode(signal.handshake.trim()) {
                Ok(decoded) => Some(decoded),
                Err(error) => {
                    warn!(
                        "Skipping signal from {} type={}: handshake hex decode failed: {error}",
                        signal.from_node_id, signal.signal_type
                    );
                    None
                }
            }
        };

        let signal_id = signal.id.clone();
        let from_node_id = signal.from_node_id.clone();
        let signal_seq = signal.signal_seq;
        let signal_type = signal.signal_type.clone();
        let prepared = match (signal.signal_type.as_str(), handshake) {
            // `peer_offer_fresh` is the independent queue key for fresh-mapping
            // prediction advertisements: it is delivered in send order and an
            // ordinary `peer_offer` can never overwrite it server-side.  The
            // event handler re-verifies the fresh label and the per-peer
            // high-water before applying anything.
            ("peer_offer" | "peer_offer_fresh", Some(handshake)) => {
                PreparedSignalDelivery::Apply(Box::new(ControlEvent::PeerOffer {
                    from_node_id: signal.from_node_id,
                    candidates: signal.candidates,
                    session_id: signal.session_id,
                    probe_ephemeral_public_key: signal.probe_ephemeral_public_key,
                    candidate_sources: signal.candidate_sources,
                    candidate_generation: signal.candidate_generation,
                    candidates_expires_at_ms,
                    handshake_init: handshake,
                    punch_at_ms,
                    punch_at_server_ms,
                    sender_public_key: signal.sender_public_key,
                }))
            }
            ("peer_answer", Some(handshake)) => {
                PreparedSignalDelivery::Apply(Box::new(ControlEvent::PeerAnswer {
                    from_node_id: signal.from_node_id,
                    candidates: signal.candidates,
                    session_id: signal.session_id,
                    probe_ephemeral_public_key: signal.probe_ephemeral_public_key,
                    candidate_sources: signal.candidate_sources,
                    candidate_generation: signal.candidate_generation,
                    candidates_expires_at_ms,
                    handshake_response: handshake,
                    punch_at_ms,
                    punch_at_server_ms,
                    sender_public_key: signal.sender_public_key,
                }))
            }
            ("peer_reflexive", Some(_)) => {
                if let Some(observed_endpoint) = peer_reflexive_endpoint_from_signal(&signal) {
                    PreparedSignalDelivery::Apply(Box::new(ControlEvent::PeerReflexive {
                        from_node_id: signal.from_node_id,
                        observed_endpoint,
                        punch_at_ms,
                    }))
                } else {
                    warn!(
                        "Ignoring peer_reflexive signal from {}; missing observed endpoint",
                        signal.from_node_id
                    );
                    PreparedSignalDelivery::TerminalRejected
                }
            }
            (_, None) => PreparedSignalDelivery::TerminalRejected,
            (other, Some(_)) => {
                warn!("Ignoring unsupported signal type from control plane: {other}");
                PreparedSignalDelivery::TerminalRejected
            }
        };

        if let (Some(signal_id), Some(ack)) = (signal_id, delivery_ack) {
            debug!(
                "Control signal delivery staged id={} from={} to={} type={} signal_seq={:?}",
                signal_id,
                from_node_id,
                self_node_id,
                signal_type,
                signal_seq,
            );
            leased_deliveries
                .entry(sender_key)
                .or_default()
                .push(LeasedSignalDelivery {
                    signal_id,
                    signal_seq,
                    from_node_id,
                    ack,
                    prepared,
                });
            continue;
        }

        // Legacy delete-on-GET servers provide no durable lease. Preserve
        // compatibility by dispatching immediately; an ACK-mode response with
        // incomplete per-row metadata was rejected above and must never fall
        // through to this crash-unsafe compatibility path.
        if !ack_mode {
            if let PreparedSignalDelivery::Apply(event) = prepared {
                event_tx.send(*event).map_err(|_| {
                    DaemonError::ControlPlane(
                        "control signal event channel closed before dispatch".to_string(),
                    )
                })?;
            }
        }
    }

    for deliveries in leased_deliveries.into_values() {
        spawn_signal_application_lane(
            http.clone(),
            base_url.to_string(),
            token.to_string(),
            self_node_id.to_string(),
            event_tx.clone(),
            delivery_tracker.clone(),
            deliveries,
        );
    }

    Ok(())
}

/// How many recent signal IDs the receive-side dedup cache retains.  The
/// per-sender applied sequence high-water below remains authoritative after an
/// ID ages out, so this deque only needs to absorb legacy rows without a
/// sequence and ordinary lost-ACK redelivery.
const MAX_RECENT_SIGNAL_IDS: usize = 2_048;

#[derive(Debug, Default)]
pub(super) struct SignalDeliveryTracker {
    applied_ids: VecDeque<String>,
    applied_seq_by_sender: HashMap<String, u64>,
    in_flight: HashMap<String, SignalDeliveryWaiter>,
}

impl SignalDeliveryTracker {
    fn already_applied(&self, signal_id: &str, from_node_id: &str, signal_seq: Option<u64>) -> bool {
        self.applied_ids.iter().any(|seen| seen == signal_id)
            || signal_seq.is_some_and(|seq| {
                self.applied_seq_by_sender
                    .get(from_node_id)
                    .is_some_and(|high_water| seq <= *high_water)
            })
    }

    fn mark_applied(&mut self, signal_id: String, from_node_id: &str, signal_seq: Option<u64>) {
        if !self.applied_ids.iter().any(|seen| seen == &signal_id) {
            self.applied_ids.push_back(signal_id);
            while self.applied_ids.len() > MAX_RECENT_SIGNAL_IDS {
                self.applied_ids.pop_front();
            }
        }
        if let Some(seq) = signal_seq {
            self.applied_seq_by_sender
                .entry(from_node_id.to_string())
                .and_modify(|high_water| *high_water = (*high_water).max(seq))
                .or_insert(seq);
        }
    }

    fn begin_application(
        &mut self,
        signal_id: &str,
        from_node_id: &str,
        signal_seq: Option<u64>,
    ) -> TrackedSignalApplication {
        if self.already_applied(signal_id, from_node_id, signal_seq) {
            return TrackedSignalApplication::AlreadyApplied;
        }
        if let Some(waiter) = self.in_flight.get(signal_id) {
            return TrackedSignalApplication::Join(waiter.clone());
        }
        let receipt = SignalDeliveryReceipt::pending();
        let waiter = receipt.waiter();
        self.in_flight
            .insert(signal_id.to_string(), waiter.clone());
        TrackedSignalApplication::Start { receipt, waiter }
    }

    fn finish_application(
        &mut self,
        signal_id: String,
        from_node_id: &str,
        signal_seq: Option<u64>,
        waiter: Option<&SignalDeliveryWaiter>,
        outcome: SignalApplyOutcome,
    ) {
        if let Some(waiter) = waiter {
            let remove = self
                .in_flight
                .get(&signal_id)
                .is_some_and(|current| current.same_delivery(waiter));
            if remove {
                self.in_flight.remove(&signal_id);
            }
        }
        if matches!(
            outcome,
            SignalApplyOutcome::Applied | SignalApplyOutcome::TerminalRejected
        ) {
            self.mark_applied(signal_id, from_node_id, signal_seq);
        }
    }
}

enum TrackedSignalApplication {
    AlreadyApplied,
    Join(SignalDeliveryWaiter),
    Start {
        receipt: SignalDeliveryReceipt,
        waiter: SignalDeliveryWaiter,
    },
}

#[derive(Debug)]
enum PreparedSignalDelivery {
    Apply(Box<ControlEvent>),
    TerminalRejected,
}

#[derive(Debug)]
struct LeasedSignalDelivery {
    signal_id: String,
    signal_seq: Option<u64>,
    from_node_id: String,
    ack: SignalAckRequest,
    prepared: PreparedSignalDelivery,
}

/// Apply one leased server batch in response order without blocking the
/// heartbeat/roster polling loop.  ACKs are deliberately emitted one row at a
/// time: if an ACK is ambiguous, later rows stay unacknowledged and the
/// server's per-pair head-of-line lease will replay from the first uncertain
/// commit instead of allowing a newer handshake to overtake it.
fn spawn_signal_application_lane(
    http: reqwest::Client,
    base_url: String,
    token: String,
    self_node_id: String,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    delivery_tracker: Arc<tokio::sync::Mutex<SignalDeliveryTracker>>,
    deliveries: Vec<LeasedSignalDelivery>,
) {
    tokio::spawn(async move {
        for delivery in deliveries {
            let mut application_waiter = None;
            let mut already_applied = false;
            let outcome = match delivery.prepared {
                PreparedSignalDelivery::TerminalRejected => {
                    already_applied = delivery_tracker.lock().await.already_applied(
                        &delivery.signal_id,
                        &delivery.from_node_id,
                        delivery.signal_seq,
                    );
                    if already_applied {
                        SignalApplyOutcome::Applied
                    } else {
                        SignalApplyOutcome::TerminalRejected
                    }
                }
                PreparedSignalDelivery::Apply(event) => {
                    let tracked = delivery_tracker.lock().await.begin_application(
                        &delivery.signal_id,
                        &delivery.from_node_id,
                        delivery.signal_seq,
                    );
                    match tracked {
                        TrackedSignalApplication::AlreadyApplied => {
                            already_applied = true;
                            SignalApplyOutcome::Applied
                        }
                        TrackedSignalApplication::Join(waiter) => {
                            debug!(
                                "Joining in-flight redelivery {} from {} at seq {:?}",
                                delivery.signal_id, delivery.from_node_id, delivery.signal_seq
                            );
                            application_waiter = Some(waiter.clone());
                            waiter.wait().await
                        }
                        TrackedSignalApplication::Start { receipt, waiter } => {
                            application_waiter = Some(waiter.clone());
                            let delivered = ControlEvent::DeliveredSignal {
                                signal_id: delivery.signal_id.clone(),
                                signal_seq: delivery.signal_seq,
                                event,
                                receipt,
                            };
                            if event_tx.send(delivered).is_err() {
                                warn!(
                                    "Control signal {} could not enter the daemon state machine; leaving its server lease unacknowledged",
                                    delivery.signal_id
                                );
                                delivery_tracker.lock().await.finish_application(
                                    delivery.signal_id.clone(),
                                    &delivery.from_node_id,
                                    delivery.signal_seq,
                                    application_waiter.as_ref(),
                                    SignalApplyOutcome::Retry,
                                );
                                break;
                            }
                            waiter.wait().await
                        }
                    }
                }
            };

            if already_applied {
                debug!(
                    "Skipping redelivered signal {} from {} at seq {:?}; state-machine application already committed",
                    delivery.signal_id, delivery.from_node_id, delivery.signal_seq
                );
            } else {
                delivery_tracker.lock().await.finish_application(
                    delivery.signal_id.clone(),
                    &delivery.from_node_id,
                    delivery.signal_seq,
                    application_waiter.as_ref(),
                    outcome,
                );
            }

            if !matches!(
                outcome,
                SignalApplyOutcome::Applied | SignalApplyOutcome::TerminalRejected
            ) {
                warn!(
                    "Control signal {} application ended as {:?}; leaving it and all later rows unacknowledged for ordered redelivery",
                    delivery.signal_id, outcome
                );
                break;
            }

            if let Err(error) = ack_signals(
                &http,
                &base_url,
                &token,
                &self_node_id,
                std::slice::from_ref(&delivery.ack),
            )
            .await
            {
                warn!(
                    "Signal {} applied but ACK failed; later rows remain unprocessed until ordered redelivery: {error}",
                    delivery.signal_id
                );
                break;
            }
        }
    });
}

/// One per-row delivery acknowledgement.
#[derive(Debug, Clone, serde::Serialize)]
struct SignalAckRequest {
    id: String,
    delivery_token: String,
}

/// Acknowledge a delivered signal batch (idempotent server-side).
async fn ack_signals(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    acks: &[SignalAckRequest],
) -> Result<()> {
    let res = http
        .post(format!("{base_url}/api/v1/signals/ack?node_id={self_node_id}"))
        .timeout(SIGNAL_SEND_TIMEOUT)
        .bearer_auth(token)
        .json(&serde_json::json!({ "signals": acks }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("signal ack request failed: {e}")))?;
    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "signal ack returned HTTP {}",
            res.status()
        )));
    }
    Ok(())
}

pub(super) fn normalize_signal_punch_at(
    punch_at_ms: Option<u64>,
    server_time_ms: Option<u64>,
    received_at_ms: u64,
) -> Option<u64> {
    let punch_at_ms = punch_at_ms?;
    let Some(server_time_ms) = server_time_ms else {
        return Some(punch_at_ms);
    };
    if punch_at_ms <= server_time_ms {
        return Some(received_at_ms);
    }
    Some(received_at_ms.saturating_add(punch_at_ms - server_time_ms))
}

/// Convert a server-clock candidate deadline into the local receiver clock.
/// This avoids discarding a fresh candidate set merely because two devices
/// have different wall-clock settings.
pub(super) fn normalize_signal_candidate_expiry(
    candidates_expires_at_ms: Option<u64>,
    server_time_ms: Option<u64>,
    received_at_ms: u64,
) -> Option<u64> {
    let expires_at_ms = candidates_expires_at_ms?;
    let Some(server_time_ms) = server_time_ms else {
        return Some(expires_at_ms);
    };
    Some(if expires_at_ms <= server_time_ms {
        received_at_ms
    } else {
        received_at_ms.saturating_add(expires_at_ms - server_time_ms)
    })
}

/// Marker bit that separates incarnation-encoded candidate generations (this
/// release and later) from the legacy wall-clock generations older releases
/// sent.  All incarnation-encoded values live above 2^62 while every legacy
/// wall-clock value fits far below it, so after an upgrade the first
/// incarnation-encoded generation always supersedes the highest legacy value a
/// receiver has seen, and a rolled-back clock can never reintroduce an older
/// number.  The value stays below i64::MAX so JSON/Go int64 handling is safe.
pub(super) const CANDIDATE_GENERATION_INCARNATION_FLAG: u64 = 0x4000_0000_0000_0000;
/// Incarnation occupies the 41 bits below the flag, the per-boot counter the
/// low 21 bits.  The incarnation field must be wide enough to hold the
/// persisted incarnation without truncation: the old 31-bit field wrapped
/// every 2^31 ms (~24.86 days), so a restart shortly after a wrap produced an
/// encoded incarnation that receivers judged stale (a receiver compares the
/// full value, so a truncated high half silently reorders boots).  41 bits
/// holds the wall-clock-seeded counter until year ~2039; beyond that the
/// generation is refused instead of wrapping (see
/// [`next_candidate_generation_value`]).
pub(super) const CANDIDATE_GENERATION_INCARNATION_BITS: u64 = 41;
/// Counter field width in bits: 2^21 generations per boot before the limit is
/// reached and further generations are refused.
pub(super) const CANDIDATE_GENERATION_COUNTER_BITS: u64 = 63 - 1 - CANDIDATE_GENERATION_INCARNATION_BITS;
pub(super) const CANDIDATE_GENERATION_COUNTER_MASK: u64 = (1u64 << CANDIDATE_GENERATION_COUNTER_BITS) - 1;

/// Return the daemon-incarnation component of an encoded candidate
/// generation. Legacy generations have no restart identity and must not be
/// used to infer a restart from ordinary endpoint churn.
pub(crate) fn candidate_generation_incarnation(generation: u64) -> Option<u64> {
    if generation & CANDIDATE_GENERATION_INCARNATION_FLAG == 0 {
        return None;
    }
    let incarnation =
        (generation & (CANDIDATE_GENERATION_INCARNATION_FLAG - 1)) >> CANDIDATE_GENERATION_COUNTER_BITS;
    (incarnation != 0).then_some(incarnation)
}

/// Return the strict ordering floor immediately before one valid
/// incarnation-encoded generation.
///
/// Production counters start at one. Persisting this predecessor while a
/// newer remote incarnation is being reset lets the triggering generation
/// itself apply exactly once, while lower counters from that incarnation are
/// already fenced across a concurrent PeerLeft/rejoin. Counter zero is not a
/// valid wire generation and therefore has no predecessor floor.
pub(crate) fn candidate_generation_predecessor_floor(generation: u64) -> Option<u64> {
    candidate_generation_incarnation(generation)?;
    let counter = generation & CANDIDATE_GENERATION_COUNTER_MASK;
    (counter > 0).then_some(generation - 1)
}

/// Whether a value occupies the incarnation-encoded wire namespace but does
/// not contain both a non-zero incarnation and a non-zero counter. Such a
/// value cannot be a legacy wall-clock generation because every legacy value
/// is below the marker bit, so receivers must fail closed instead of silently
/// treating it as legacy.
pub(crate) fn candidate_generation_is_malformed_encoded(generation: u64) -> bool {
    generation & CANDIDATE_GENERATION_INCARNATION_FLAG != 0
        && candidate_generation_predecessor_floor(generation).is_none()
}

/// Why no candidate generation could be produced for this signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateGenerationError {
    /// The persisted incarnation no longer fits the encoding field.  Kept for
    /// documentation and API stability: signaling now degrades such boots to
    /// the legacy generation 0 instead of failing (see
    /// [`next_candidate_generation_for_incarnation`]).
    #[allow(dead_code)]
    IncarnationExhausted(u64),
    /// The per-boot generation counter reached its field limit: refusing to
    /// wrap keeps every generation strictly newer than its predecessors.
    CounterExhausted(u64),
}

impl std::fmt::Display for CandidateGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncarnationExhausted(incarnation) => write!(
                f,
                "candidate generation exhausted: the daemon incarnation {incarnation} no longer fits the {CANDIDATE_GENERATION_INCARNATION_BITS}-bit encoding field (refusing to mask and wrap)"
            ),
            Self::CounterExhausted(counter) => write!(
                f,
                "candidate generation exhausted: the per-boot generation counter reached {counter} and cannot advance without wrapping"
            ),
        }
    }
}

pub(super) fn next_candidate_generation() -> std::result::Result<u64, CandidateGenerationError> {
    loop {
        let previous = LAST_CANDIDATE_GENERATION.load(Ordering::Relaxed);
        let next = next_candidate_generation_value(previous)?;
        if LAST_CANDIDATE_GENERATION
            .compare_exchange_weak(previous, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(next);
        }
    }
}

/// Pure next-generation rule: the persistent incarnation dominates the high
/// bits, the low bits keep a strictly increasing per-boot counter, and the
/// wall clock only seeds the first value of a boot (clock rollback is already
/// absorbed by `max(previous + 1, ...)`).
///
/// Both fields refuse to wrap instead of masking: an encoded generation that
/// wraps the incarnation would let an old boot outrank a newer one at the
/// receiver, and a wrapped counter would collide with an older generation of
/// the same boot.
pub(super) fn next_candidate_generation_value(
    previous: u64,
) -> std::result::Result<u64, CandidateGenerationError> {
    next_candidate_generation_for_incarnation(crate::incarnation::local_incarnation(), previous)
}

/// Pure rule with an explicit incarnation, so tests never depend on the
/// process-global incarnation.
pub(super) fn next_candidate_generation_for_incarnation(
    incarnation: u64,
    previous: u64,
) -> std::result::Result<u64, CandidateGenerationError> {
    let incarnation_max = (1u64 << CANDIDATE_GENERATION_INCARNATION_BITS) - 1;
    if incarnation == 0 || incarnation > incarnation_max {
        // No encodable trustworthy incarnation exists for this boot (missing
        // config path, corrupt/unreadable state, version mismatch, counter
        // exhausted, or the persisted incarnation outgrew the 41-bit field).
        // The generation MUST NOT silently encode incarnation=0 under the
        // flag: a flagged value with a zero incarnation field is lower than
        // every real incarnation-encoded value, so a receiver whose
        // high-water already saw one would judge this boot's ordinary
        // candidates stale forever.  Instead the ordinary candidates carry
        // generation 0 — the legacy "no ordering metadata" value that the
        // receiver's stale check never rejects (`candidate_generation != 0`
        // gates the comparison).  Ordinary offer/answer signaling therefore
        // keeps working; only fresh prediction is disabled for such a boot
        // (the ordering the generation would provide is not needed, and the
        // fresh label check in `hole_punch_signal_context` disables the
        // fresh path when the incarnation cannot be encoded).
        return Ok(0);
    }
    let previous_counter = previous & CANDIDATE_GENERATION_COUNTER_MASK;
    if previous_counter >= CANDIDATE_GENERATION_COUNTER_MASK {
        return Err(CandidateGenerationError::CounterExhausted(previous_counter));
    }
    // The per-boot counter starts at 1 and strictly increments: it never
    // borrows the wall clock's low bits, so the boot time can never decide
    // how much capacity this boot has left.
    let counter = previous_counter.saturating_add(1).min(CANDIDATE_GENERATION_COUNTER_MASK);
    Ok(CANDIDATE_GENERATION_INCARNATION_FLAG
        | (incarnation << CANDIDATE_GENERATION_COUNTER_BITS)
        | counter)
}

/// Whether a daemon incarnation fits the candidate-generation encoding field.
///
/// `boot_epoch_ms == 0` (no trustworthy persistent incarnation) AND an
/// incarnation that outgrew the 41-bit field both disable fresh prediction:
/// the fresh label embeds the incarnation and must never wrap.
pub(crate) fn incarnation_fits_candidate_generation_encoding(incarnation: u64) -> bool {
    incarnation != 0 && incarnation < (1u64 << CANDIDATE_GENERATION_INCARNATION_BITS)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX)
}

#[derive(Clone)]
pub(crate) struct SignalSigningIdentity {
    keypair: Ed25519KeyPair,
}

impl SignalSigningIdentity {
    pub(super) fn from_config(config: &Config) -> Option<Self> {
        let private_key = hex::decode(config.node.ed25519_private_key.trim()).ok()?;
        let private_key: [u8; 32] = private_key.as_slice().try_into().ok()?;
        Some(Self {
            keypair: Ed25519KeyPair::from_private_key(&private_key),
        })
    }
}

fn probe_ephemeral_transcript(
    signal_type: &str,
    from_node_id: &str,
    to_node_id: &str,
    session_id: &str,
    probe_ephemeral_public_key: &str,
    candidate_generation: u64,
    candidates_expires_at_ms: u64,
) -> Vec<u8> {
    format!(
        "p2wlan signal probe ephemeral v1\n\
type={signal_type}\n\
from={from_node_id}\n\
to={to_node_id}\n\
session_id={session_id}\n\
probe_ephemeral_public_key={}\n\
candidate_generation={candidate_generation}\n\
candidates_expires_at_ms={candidates_expires_at_ms}\n",
        probe_ephemeral_public_key.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

#[allow(clippy::too_many_arguments)]
fn sign_probe_ephemeral_transcript(
    signing_identity: Option<&SignalSigningIdentity>,
    signal_type: &str,
    from_node_id: &str,
    to_node_id: &str,
    session_id: Option<&str>,
    probe_ephemeral_public_key: Option<&str>,
    candidate_generation: u64,
    candidates_expires_at_ms: u64,
) -> Option<String> {
    let signing_identity = signing_identity?;
    let session_id = session_id?.trim();
    let probe_ephemeral_public_key = probe_ephemeral_public_key?.trim();
    if session_id.is_empty() || probe_ephemeral_public_key.is_empty() {
        return None;
    }
    let transcript = probe_ephemeral_transcript(
        signal_type,
        from_node_id,
        to_node_id,
        session_id,
        probe_ephemeral_public_key,
        candidate_generation,
        candidates_expires_at_ms,
    );
    Some(hex::encode(signing_identity.keypair.sign(&transcript)))
}

pub(super) fn peer_reflexive_endpoint_from_signal(signal: &SignalResponse) -> Option<String> {
    signal
        .candidates
        .iter()
        .find(|candidate| {
            signal
                .candidate_sources
                .get(candidate.as_str())
                .is_some_and(|source| source == "peer_reflexive")
        })
        .or_else(|| signal.candidates.first())
        .cloned()
}
