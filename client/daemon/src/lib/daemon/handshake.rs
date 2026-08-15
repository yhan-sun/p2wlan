#[derive(Clone, Default)]
struct HandshakeArbiter {
    peer_locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
}

impl HandshakeArbiter {
    async fn acquire(&self, peer_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let peer_lock = {
            let mut peer_locks = self.peer_locks.lock().await;
            if let Some(peer_lock) = peer_locks.get(peer_id).and_then(Weak::upgrade) {
                peer_lock
            } else {
                peer_locks.retain(|_, peer_lock| peer_lock.strong_count() > 0);
                let peer_lock = Arc::new(Mutex::new(()));
                peer_locks.insert(peer_id.to_string(), Arc::downgrade(&peer_lock));
                peer_lock
            }
        };
        peer_lock.lock_owned().await
    }

    /// Acquire a peer's handshake turn without allowing a stale lifecycle
    /// worker to hold the responder lane forever.  Callers that need
    /// cancellation should race this future with their cancellation watch;
    /// this method supplies the independent hard upper bound.
    async fn acquire_with_timeout(
        &self,
        peer_id: &str,
        timeout: Duration,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        tokio::time::timeout(timeout, self.acquire(peer_id))
            .await
            .ok()
    }
}

/// A responder offer must never wait indefinitely behind an initiator or
/// lifecycle cleanup worker.  This is deliberately a lock-wait bound, not a
/// network/handshake timeout: the responder worker retries the same idempotent
/// offer when this bound is hit.
const RESPONDER_HANDSHAKE_ARBITER_TIMEOUT: Duration = Duration::from_millis(750);
const REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT: &str =
    "responder_handshake_arbiter_timeout";

/// Correlate one control-plane session without writing the raw session token
/// to logs. This uses the existing local diagnostic fingerprint only; it is
/// not an authentication or identity value.
fn handshake_token_fingerprint(token: Option<&str>) -> String {
    token
        .map(|token| format!("{:016x}", crate::transport::wire_fingerprint(token.as_bytes())))
        .unwrap_or_else(|| "legacy".to_string())
}

fn local_is_designated_handshake_initiator(
    local_public_key: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> bool {
    local_public_key < peer_public_key
}

/// Return whether an already decoded, distinct peer identity should cause
/// this daemon to start an initiator transaction.  Equal keys are invalid
/// configuration and intentionally return true so the normal handshake path
/// emits its explicit identity error instead of silently suppressing it.
fn should_start_initiator_for_keys(local_public_key: &[u8; 32], peer_public_key: &[u8; 32]) -> bool {
    local_public_key == peer_public_key
        || local_is_designated_handshake_initiator(local_public_key, peer_public_key)
}

fn should_start_initiator_for_encoded_keys(
    local_private_key: &str,
    peer_public_key: &str,
) -> Option<bool> {
    let local_private_key = decode_x25519_key(local_private_key, "node private key").ok()?;
    let peer_public_key = decode_x25519_key(peer_public_key, "peer public key").ok()?;
    let local_public_key = NodeIdentity::from_private_key(local_private_key).public_key();
    Some(should_start_initiator_for_keys(
        &local_public_key,
        &peer_public_key,
    ))
}

fn handshake_public_key_fingerprint(key: &[u8; 32]) -> String {
    format!("{:016x}", crate::transport::wire_fingerprint(key))
}

impl Daemon {
    /// Avoid creating a competing initiator worker when the static identity
    /// ordering already says this daemon is the responder.  Unknown or
    /// malformed identity material is allowed through so the normal handshake
    /// path can report the precise configuration error instead of silently
    /// suppressing it.
    fn should_start_initiator_handshake(&self, peer_info: &control::PeerInfo) -> bool {
        let local_public_fingerprint = decode_x25519_key(
            &self.config.node.private_key,
            "node private key",
        )
        .ok()
        .map(|private_key| {
            let identity = NodeIdentity::from_private_key(private_key);
            handshake_public_key_fingerprint(&identity.public_key())
        })
        .unwrap_or_else(|| "invalid".to_string());
        let peer_public_fingerprint = decode_x25519_key(&peer_info.public_key, "peer public key")
            .ok()
            .map(|public_key| handshake_public_key_fingerprint(&public_key))
            .unwrap_or_else(|| "invalid".to_string());
        let Some(should_start) = should_start_initiator_for_encoded_keys(
            &self.config.node.private_key,
            &peer_info.public_key,
        ) else {
            self.timeline.emit(
                "initiator_handshake_role",
                None,
                Some("invalid_identity_material"),
                Some(format!(
                    "peer={} role=unknown local_public_fp={} peer_public_fp={}",
                    peer_info.node_id, local_public_fingerprint, peer_public_fingerprint
                )),
            );
            return true;
        };
        self.timeline.emit(
            "initiator_handshake_role",
            None,
            None,
            Some(format!(
                "peer={} role={} local_public_fp={} peer_public_fp={}",
                peer_info.node_id,
                if should_start { "initiator" } else { "responder" },
                local_public_fingerprint,
                peer_public_fingerprint,
            )),
        );
        if !should_start {
            self.timeline.emit(
                "initiator_handshake_suppressed",
                None,
                Some("deterministic_responder_role"),
                Some(format!(
                    "peer={} local_role=responder",
                    peer_info.node_id
                )),
            );
        }
        should_start
    }
}

fn should_mark_connecting_after_session_install(
    replaced_existing_session: bool,
    current_state: Option<ConnectionState>,
) -> bool {
    !replaced_existing_session
        && matches!(
            current_state,
            Some(ConnectionState::Idle | ConnectionState::Failed | ConnectionState::Closed)
        )
}

include!("handshake/init.rs");
include!("handshake/initiate.rs");
include!("handshake/candidates.rs");
include!("handshake/offer.rs");
include!("handshake/answer.rs");
include!("handshake/identity.rs");
