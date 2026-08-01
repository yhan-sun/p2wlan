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
    // this request is being assembled.
    let candidate_generation = next_candidate_generation();
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
        let handshake = if signal.handshake.trim().is_empty() {
            Vec::new()
        } else {
            hex::decode(signal.handshake.trim()).map_err(|e| {
                DaemonError::ControlPlane(format!("signal handshake hex decode failed: {e}"))
            })?
        };

        match signal.signal_type.as_str() {
            "peer_offer" => {
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

pub(super) fn next_candidate_generation() -> u64 {
    loop {
        let previous = LAST_CANDIDATE_GENERATION.load(Ordering::Relaxed);
        let next = unix_time_millis().max(previous.saturating_add(1));
        if LAST_CANDIDATE_GENERATION
            .compare_exchange_weak(previous, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return next;
        }
    }
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
