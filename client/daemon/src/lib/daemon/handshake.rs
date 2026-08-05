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
}

fn local_is_designated_handshake_initiator(
    local_public_key: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> bool {
    local_public_key < peer_public_key
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
