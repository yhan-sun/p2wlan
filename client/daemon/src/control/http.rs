//! REST/HTTP client functions for the control plane.
//!
//! Device registration, challenge-response credential issuance, relay ticket
//! fetch, endpoint lease refresh, signal send/poll, peer polling and tunnel
//! creation. Split out of `control.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use p2pnet_crypto::Ed25519KeyPair;
use serde::Deserialize;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::config::Config;
use crate::error::{DaemonError, Result};

use super::{
    ClientState, ControlErrorResponse, ControlEvent, CreateTunnelResponse, EndpointUpdateResponse,
    FetchRelayTicketResponse, ListNodesResponse, ListSignalsResponse, PeerInfo,
    RegisterDeviceResponse, RelayCatalogEntry, SignalCreateResponse, SignalResponse,
};

/// Candidate-set revisions must be strictly increasing within a daemon.  Wall
/// clock milliseconds alone collide when an offer and a candidate refresh are
/// emitted in the same tick.
static LAST_CANDIDATE_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(super) const SIGNAL_REST_PROTOCOL_VERSION: u8 = 1;

pub(super) async fn obtain_device_credential(
    http: &reqwest::Client,
    base_url: &str,
    user_token: &str,
    device_id: &str,
    ed25519_private_key_hex: &str,
    ed25519_public_key_hex: &str,
) -> Result<String> {
    // Step 1: Request a challenge
    let challenge_resp = http
        .post(format!("{base_url}/api/v1/challenges"))
        .bearer_auth(user_token)
        .json(&serde_json::json!({
            "device_id": device_id,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("challenge request failed: {e}")))?;

    if !challenge_resp.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "challenge request returned HTTP {}",
            challenge_resp.status()
        )));
    }

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct ChallengeResponse {
        challenge_id: String,
        challenge: String,
        expires_at: i64,
    }

    let challenge_body: ChallengeResponse = challenge_resp
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("challenge decode failed: {e}")))?;

    let challenge_bytes = hex::decode(&challenge_body.challenge)
        .map_err(|e| DaemonError::ControlPlane(format!("challenge hex decode failed: {e}")))?;

    // Step 2: Sign the challenge with Ed25519
    let ed25519_private_key = hex::decode(ed25519_private_key_hex).map_err(|e| {
        DaemonError::ControlPlane(format!("ed25519 private key hex decode failed: {e}"))
    })?;

    if ed25519_private_key.len() != 32 {
        return Err(DaemonError::ControlPlane(
            "invalid ed25519 private key length".into(),
        ));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&ed25519_private_key);
    let keypair = p2pnet_crypto::Ed25519KeyPair::from_private_key(&key_bytes);
    let signature = keypair.sign(&challenge_bytes);
    let signature_hex = hex::encode(signature);

    // Step 3: Submit the signed challenge to get a device credential
    let cred_resp = http
        .post(format!("{base_url}/api/v1/devices/credential"))
        .bearer_auth(user_token)
        .json(&serde_json::json!({
            "device_id": device_id,
            "ed25519_public_key": ed25519_public_key_hex,
            "challenge_id": challenge_body.challenge_id,
            "challenge_signature": signature_hex,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("credential request failed: {e}")))?;

    if !cred_resp.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "credential request returned HTTP {}",
            cred_resp.status()
        )));
    }

    #[derive(Deserialize)]
    struct CredentialResponse {
        success: bool,
        device_credential: Option<String>,
        error: Option<String>,
    }

    let cred_body: CredentialResponse = cred_resp.json().await.map_err(|e| {
        DaemonError::ControlPlane(format!("credential response decode failed: {e}"))
    })?;

    if !cred_body.success {
        return Err(DaemonError::ControlPlane(
            cred_body
                .error
                .unwrap_or_else(|| "credential request failed".to_string()),
        ));
    }

    cred_body.device_credential.ok_or_else(|| {
        DaemonError::ControlPlane("credential response missing device_credential".into())
    })
}

#[derive(Debug, Deserialize)]
struct RelayTicketResponse {
    ticket: Option<String>,
    expires_at: Option<i64>,
    error: Option<String>,
}

pub(super) async fn fetch_relay_ticket_http(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    audience: &str,
    region: &str,
) -> Result<FetchRelayTicketResponse> {
    let resp = http
        .post(format!("{base_url}/api/v1/relay/tickets"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "audience": audience,
            "region": region,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("relay ticket request failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body: RelayTicketResponse = resp.json().await.unwrap_or(RelayTicketResponse {
            ticket: None,
            expires_at: None,
            error: Some(format!("HTTP {status}")),
        });
        let msg = body.error.unwrap_or_else(|| format!("HTTP {status}"));
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(DaemonError::ControlPlane(format!("permanent auth: {msg}")));
        }
        return Err(DaemonError::ControlPlane(format!(
            "relay ticket request: {msg}"
        )));
    }

    let body: RelayTicketResponse = resp
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("relay ticket decode: {e}")))?;

    let ticket = body
        .ticket
        .ok_or_else(|| DaemonError::ControlPlane("relay ticket response missing ticket".into()))?;
    let expires_at = body.expires_at.unwrap_or(0);

    Ok(FetchRelayTicketResponse { ticket, expires_at })
}

pub(super) fn normalize_http_base_url(server_url: &str) -> String {
    let trimmed = server_url.trim().trim_end_matches('/');
    if trimmed.starts_with("ws://") {
        format!("http://{}", trimmed.trim_start_matches("ws://"))
    } else if trimmed.starts_with("wss://") {
        format!("https://{}", trimmed.trim_start_matches("wss://"))
    } else {
        trimmed.to_string()
    }
}

pub(super) async fn register_device(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
) -> Result<(String, String, String, Vec<String>, Vec<RelayCatalogEntry>)> {
    let res = http
        .post(format!("{base_url}/api/v1/devices"))
        .bearer_auth(token)
        .json(&register_device_payload(config))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("register request failed: {e}")))?;

    if !res.status().is_success() {
        let status = res.status();
        let detail = control_error_detail(res).await;
        return Err(DaemonError::ControlPlane(format!(
            "register request returned HTTP {status}: {detail}"
        )));
    }

    let body: RegisterDeviceResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("register response decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "device registration failed".to_string()),
        ));
    }

    let node_id = body
        .node_id
        .ok_or_else(|| DaemonError::ControlPlane("register response missing node_id".into()))?;
    let virtual_ip = body
        .virtual_ip
        .ok_or_else(|| DaemonError::ControlPlane("register response missing virtual_ip".into()))?;
    let cidr = body.cidr.unwrap_or_else(|| "10.20.0.0/16".to_string());

    Ok((
        node_id,
        virtual_ip,
        cidr,
        body.relay_servers,
        body.relay_catalog,
    ))
}

pub(super) fn register_device_payload(config: &Config) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "public_key": config.node.public_key,
        "ed25519_public_key": config.node.ed25519_public_key,
        "device_name": config.node.device_name,
        "platform": config.node.platform,
        "app_version": env!("CARGO_PKG_VERSION"),
        "network_id": config.network.network_id,
    });

    if config.network.manual {
        let virtual_ip = config.network.virtual_ip.trim();
        if !virtual_ip.is_empty() {
            payload["virtual_ip"] = serde_json::Value::String(virtual_ip.to_string());
        }
    }

    payload
}

async fn control_error_detail(res: reqwest::Response) -> String {
    let status = res.status();
    let text = res.text().await.unwrap_or_default();
    if text.trim().is_empty() {
        return status.to_string();
    }
    match serde_json::from_str::<ControlErrorResponse>(&text) {
        Ok(body) => body.error.unwrap_or(text),
        Err(_) => text,
    }
}

pub(super) async fn update_endpoint(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    endpoint: &str,
    nat_type: &str,
    relay_rtt_ms: Option<u64>,
) -> Result<()> {
    let res = http
        .patch(format!("{base_url}/api/v1/devices/{device_id}/endpoint"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "endpoint": endpoint,
            "nat_type": nat_type,
            "relay_rtt_ms": relay_rtt_ms,
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("endpoint update request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "endpoint update returned HTTP {}",
            res.status()
        )));
    }

    let body: EndpointUpdateResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("endpoint update decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "endpoint update failed".to_string()),
        ));
    }

    Ok(())
}

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

pub(super) async fn poll_peers(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    config: &Config,
    self_node_id: &str,
    state: &Arc<RwLock<ClientState>>,
    event_tx: &mpsc::UnboundedSender<ControlEvent>,
) -> Result<()> {
    let res = http
        .get(format!(
            "{base_url}/api/v1/nodes?network_id={}",
            config.network.network_id
        ))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list nodes request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "list nodes request returned HTTP {}",
            res.status()
        )));
    }

    let body: ListNodesResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("list nodes decode failed: {e}")))?;

    info!(
        "poll_peers: received {} nodes from control plane (self_node_id={})",
        body.nodes.len(),
        self_node_id
    );

    let mut seen = HashMap::new();
    let mut joined = Vec::new();
    let mut updated = Vec::new();

    {
        let mut state = state.write().await;

        for node in body.nodes {
            if node.id == self_node_id || node.public_key == config.node.public_key {
                continue;
            }

            let peer = PeerInfo {
                node_id: node.id.clone(),
                device_name: node.device_name,
                app_version: node.app_version,
                public_key: node.public_key,
                endpoint: node.endpoint,
                nat_type: node.nat_type,
                virtual_ip: node.virtual_ip,
                online: node.online,
                last_seen: node.last_seen,
                relay_rtt_ms: node.relay_rtt_ms,
            };

            seen.insert(peer.node_id.clone(), peer.clone());
            match state.peers.get(&peer.node_id) {
                Some(known) if peer_metadata_changed(known, &peer) => updated.push(peer.clone()),
                None => joined.push(peer.clone()),
                _ => {}
            }
            state.peers.insert(peer.node_id.clone(), peer);
        }

        let departed: Vec<String> = state
            .peers
            .keys()
            .filter(|node_id| !seen.contains_key(*node_id))
            .cloned()
            .collect();

        for node_id in departed {
            state.peers.remove(&node_id);
            let _ = event_tx.send(ControlEvent::PeerLeft(node_id));
        }
    }

    info!(
        "poll_peers: {} joined, {} updated, {} total known peers",
        joined.len(),
        updated.len(),
        seen.len()
    );

    for peer in joined {
        let _ = event_tx.send(ControlEvent::PeerJoined(peer));
    }
    for peer in updated {
        let _ = event_tx.send(ControlEvent::PeerUpdated(peer));
    }

    Ok(())
}

pub(super) fn peer_metadata_changed(known: &PeerInfo, peer: &PeerInfo) -> bool {
    known.device_name != peer.device_name
        || known.app_version != peer.app_version
        || known.public_key != peer.public_key
        || known.endpoint != peer.endpoint
        || known.nat_type != peer.nat_type
        || known.virtual_ip != peer.virtual_ip
        || known.online != peer.online
        || known.relay_rtt_ms != peer.relay_rtt_ms
}

pub(super) async fn create_tunnel(
    http: &reqwest::Client,
    base_url: &str,
    token: &str,
    device_id: &str,
    protocol: &str,
    local_port: u16,
    remote_port: u16,
) -> Result<(String, String)> {
    let res = http
        .post(format!("{base_url}/api/v1/tunnels"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "device_id": device_id,
            "protocol": protocol,
            "local_port": local_port,
            "remote_port": remote_port,
            "local_address": "127.0.0.1",
        }))
        .send()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("create tunnel request failed: {e}")))?;

    if !res.status().is_success() {
        return Err(DaemonError::ControlPlane(format!(
            "create tunnel request returned HTTP {}",
            res.status()
        )));
    }

    let body: CreateTunnelResponse = res
        .json()
        .await
        .map_err(|e| DaemonError::ControlPlane(format!("create tunnel decode failed: {e}")))?;

    if !body.success {
        return Err(DaemonError::ControlPlane(
            body.error
                .unwrap_or_else(|| "create tunnel failed".to_string()),
        ));
    }

    Ok((
        body.tunnel_id
            .ok_or_else(|| DaemonError::ControlPlane("create tunnel response missing id".into()))?,
        body.public_endpoint.ok_or_else(|| {
            DaemonError::ControlPlane("create tunnel response missing public endpoint".into())
        })?,
    ))
}
