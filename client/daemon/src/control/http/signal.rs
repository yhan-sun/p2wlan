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
    // Keep the revision and expiry derived from one instant: a candidate set
    // must have a coherent lifetime even if the wall clock is adjusted while
    // this request is being assembled.  A refused generation (incarnation or
    // per-boot counter exhausted) fails the whole signal instead of sending a
    // wrapped value receivers would judge stale.
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
    let res = http
        .post(format!("{base_url}/api/v1/signals"))
        .timeout(SIGNAL_SEND_TIMEOUT)
        .bearer_auth(token)
        .json(&serde_json::json!({
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

    Ok(())
}

pub(super) async fn poll_signals(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    self_node_id: &str,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
    wait_ms: u64,
) -> Result<()> {
    let res = http
        .get(format!(
            "{base_url}/api/v1/signals?node_id={self_node_id}&wait_ms={wait_ms}"
        ))
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

    for signal in body.signals {
        if signal.protocol_version != SIGNAL_REST_PROTOCOL_VERSION {
            warn!(
                "Skipping unsupported signal protocol_version={} from {} type={}",
                signal.protocol_version, signal.from_node_id, signal.signal_type
            );
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
        // deleted every delivered row from its queue, so aborting here would
        // drop the healthy signals of the same poll together with the bad one.
        let handshake = if signal.handshake.trim().is_empty() {
            Vec::new()
        } else if signal.handshake.trim().len() % 2 != 0 {
            warn!(
                "Skipping signal from {} type={}: handshake hex has an odd length",
                signal.from_node_id, signal.signal_type
            );
            continue;
        } else {
            match hex::decode(signal.handshake.trim()) {
                Ok(decoded) => decoded,
                Err(error) => {
                    warn!(
                        "Skipping signal from {} type={}: handshake hex decode failed: {error}",
                        signal.from_node_id, signal.signal_type
                    );
                    continue;
                }
            }
        };

        match signal.signal_type.as_str() {
            // `peer_offer_fresh` is the independent queue key for fresh-mapping
            // prediction advertisements: it is delivered in send order and an
            // ordinary `peer_offer` can never overwrite it server-side.  The
            // event handler re-verifies the fresh label and the per-peer
            // high-water before applying anything.
            "peer_offer" | "peer_offer_fresh" => {
                let _ = event_tx.send(ControlEvent::PeerOffer {
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
                });
            }
            "peer_answer" => {
                let _ = event_tx.send(ControlEvent::PeerAnswer {
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
                });
            }
            "peer_reflexive" => {
                if let Some(observed_endpoint) = peer_reflexive_endpoint_from_signal(&signal) {
                    let _ = event_tx.send(ControlEvent::PeerReflexive {
                        from_node_id: signal.from_node_id,
                        observed_endpoint,
                        punch_at_ms,
                    });
                } else {
                    warn!(
                        "Ignoring peer_reflexive signal from {}; missing observed endpoint",
                        signal.from_node_id
                    );
                }
            }
            other => {
                warn!("Ignoring unsupported signal type from control plane: {other}");
            }
        }
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

/// Why no candidate generation could be produced for this signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidateGenerationError {
    /// The persisted incarnation no longer fits the encoding field: refusing
    /// to mask it would let a wrapped incarnation reorder boots at the
    /// receiver.
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
    if incarnation == 0 {
        // No trustworthy persistent incarnation exists for this boot (missing
        // config path, corrupt/unreadable state, version mismatch, or the
        // counter exhausted).  The generation MUST NOT silently encode
        // incarnation=0 under the flag: a flagged value with a zero
        // incarnation field is lower than every real incarnation-encoded
        // value, so a receiver whose high-water already saw one would judge
        // this boot's ordinary candidates stale forever.  Instead the
        // ordinary candidates carry generation 0 — the legacy "no ordering
        // metadata" value that the receiver's stale check never rejects
        // (`candidate_generation != 0` gates the comparison).  Fresh
        // prediction is disabled for such a boot anyway, so the ordering the
        // generation would provide is not needed.
        return Ok(0);
    }
    let incarnation_max = (1u64 << CANDIDATE_GENERATION_INCARNATION_BITS) - 1;
    if incarnation > incarnation_max {
        return Err(CandidateGenerationError::IncarnationExhausted(incarnation));
    }
    let previous_counter = previous & CANDIDATE_GENERATION_COUNTER_MASK;
    if previous_counter >= CANDIDATE_GENERATION_COUNTER_MASK {
        return Err(CandidateGenerationError::CounterExhausted(previous_counter));
    }
    let counter = (unix_time_millis() & CANDIDATE_GENERATION_COUNTER_MASK)
        .max(previous_counter.saturating_add(1))
        .min(CANDIDATE_GENERATION_COUNTER_MASK);
    Ok(CANDIDATE_GENERATION_INCARNATION_FLAG
        | (incarnation << CANDIDATE_GENERATION_COUNTER_BITS)
        | counter)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(u64::MAX)
}

#[derive(Clone)]
pub(super) struct SignalSigningIdentity {
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
