// ============================================================
// Peer Manager
// ============================================================

/// Manages all peer connections.
pub struct PeerManager {
    /// Active peer connections, indexed by node ID.
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// Virtual IP → node ID mapping for routing.
    ip_to_node: Arc<RwLock<HashMap<String, String>>>,
    /// Monotonic local network generation. Incremented when local UDP candidates change.
    network_generation: Arc<RwLock<u64>>,
    /// Latest local NAT profile used to decide whether bounded birthday probing is suitable.
    local_nat_profile: Arc<RwLock<Option<NatProfile>>>,
    /// Anonymous local traversal outcome history.
    traversal_history: Arc<RwLock<TraversalHistory>>,
    /// Optional persistent history path.
    traversal_history_path: Option<PathBuf>,
    /// Per-peer punch generation counters for fresh-mapping batches.
    punch_generations: Arc<RwLock<HashMap<String, u64>>>,
    /// Per-peer fresh-mapping state produced by measure-then-punch generations.
    local_fresh_mappings: Arc<RwLock<HashMap<String, LocalFreshMapping>>>,
    /// Time-limited prediction-error fingerprint per peer.
    fresh_mapping_history: Arc<std::sync::Mutex<HashMap<String, VecDeque<FreshMappingPredictionResult>>>>,
    /// Configuration.
    config: Config,
}

/// Metadata changes observed while applying one control-plane peer snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerUpdate {
    pub is_new: bool,
    pub virtual_ip_changed: bool,
    pub endpoint_changed: bool,
    pub public_key_changed: bool,
}

fn derive_probe_mac_key(config: &Config, peer_public_key: &str) -> Option<ProbeMacKey> {
    let local_private = decode_x25519_key_bytes(&config.node.private_key).ok()?;
    let peer_public = decode_x25519_key_bytes(peer_public_key).ok()?;
    let identity = NodeIdentity::from_private_key(local_private);
    let shared = identity.diffie_hellman(&peer_public).ok()?;
    Some(hmac(&shared, PROBE_MAC_KEY_DOMAIN))
}

fn derive_session_probe_mac_key(base_key: &ProbeMacKey, session_id: &str) -> ProbeMacKey {
    let mut input = Vec::with_capacity(PROBE_MAC_SESSION_KEY_DOMAIN.len() + session_id.len());
    input.extend_from_slice(PROBE_MAC_SESSION_KEY_DOMAIN);
    input.extend_from_slice(session_id.as_bytes());
    hmac(base_key, &input)
}

fn derive_ephemeral_session_probe_mac_key(
    base_key: &ProbeMacKey,
    session_id: &str,
    ephemeral_shared: &[u8; 32],
) -> ProbeMacKey {
    let mut input = Vec::with_capacity(
        PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN.len() + session_id.len() + ephemeral_shared.len(),
    );
    input.extend_from_slice(PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN);
    input.extend_from_slice(session_id.as_bytes());
    input.extend_from_slice(ephemeral_shared);
    hmac(base_key, &input)
}

fn probe_mac_key_for_binding(
    base_key: ProbeMacKey,
    binding: &ProbeSessionBinding,
) -> ProbeMacKey {
    match binding.session_id.as_deref() {
        Some(session_id) if !session_id.is_empty() => match binding.ephemeral_shared.as_ref() {
            Some(shared) => derive_ephemeral_session_probe_mac_key(&base_key, session_id, shared),
            None => derive_session_probe_mac_key(&base_key, session_id),
        },
        _ => base_key,
    }
}

fn active_probe_binding(conn: &PeerConnection) -> ProbeSessionBinding {
    ProbeSessionBinding {
        token: conn.probe_binding_token.clone(),
        session_id: conn.probe_session_id.clone(),
        ephemeral_shared: conn.probe_ephemeral_shared,
    }
}

fn effective_probe_mac_key(conn: &PeerConnection) -> Option<ProbeMacKey> {
    let base_key = conn.probe_mac_key?;
    Some(probe_mac_key_for_binding(base_key, &active_probe_binding(conn)))
}

fn probe_key_type(conn: &PeerConnection) -> &'static str {
    if conn.probe_mac_key.is_none() {
        "none"
    } else if conn.probe_session_id.is_none() {
        "static"
    } else if conn.probe_ephemeral_shared.is_some() {
        "ephemeral_session"
    } else {
        "session"
    }
}

fn decode_x25519_key_bytes(hex_value: &str) -> std::result::Result<[u8; 32], ()> {
    let bytes = hex::decode(hex_value.trim()).map_err(|_| ())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ())
}
