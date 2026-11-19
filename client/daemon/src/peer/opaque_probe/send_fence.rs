//! Original probe intent, checked against the real connection and auth owners
//! through each synchronous UDP syscall. It grants no receive/adoption credit.
use super::*;

#[derive(Clone)]
pub(crate) struct ProbeSendFence {
    peer: String,
    generation: Option<PeerSessionGeneration>,
    registration: u64,
    session: Option<String>,
    token: Option<String>,
    key_fingerprint: Option<[u8; 32]>,
    local_registration: Option<(Option<u64>, bool)>,
    pub(crate) opaque: bool,
    unknown: bool,
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeSendFenceError {
    Busy,
    Revoked,
}

impl PeerManager {
    fn probe_send_fence_from_connection(
        &self,
        conn: &PeerConnection,
        sending: bool,
    ) -> Option<ProbeSendFence> {
        let opaque = self.opaque_probe_mode_for_connection(conn, sending)?;
        let local_registration = match self.opaque_probe_registration.get() {
            Some(control) => Some(control.probe_registration_snapshot()?),
            None => None,
        };
        if opaque && !local_registration.is_some_and(|(seq, accepted)| seq.is_some() && accepted) {
            return None;
        }
        Some(ProbeSendFence {
            peer: conn.node_id.clone(),
            generation: Some(self.peer_session_generation_sync(&conn.node_id)?),
            registration: conn.registration_seq,
            session: conn.probe_session_id.clone(),
            token: conn.probe_binding_token.clone(),
            key_fingerprint: effective_probe_mac_key(conn).map(|key| p2pnet_crypto::hash(&key)),
            local_registration,
            opaque,
            unknown: false,
        })
    }

    pub(crate) async fn snapshot_probe_send_fence(
        &self,
        peer: &str,
        sending: bool,
    ) -> Option<ProbeSendFence> {
        let connections = self.connections.read().await;
        match connections.get(peer) {
            Some(conn) => self.probe_send_fence_from_connection(conn, sending),
            None => self.unknown_probe_send_fence(peer),
        }
    }

    pub(crate) fn try_snapshot_probe_send_fence(
        &self,
        peer: &str,
        sending: bool,
    ) -> Option<ProbeSendFence> {
        let connections = self.connections.try_read().ok()?;
        match connections.get(peer) {
            Some(conn) => self.probe_send_fence_from_connection(conn, sending),
            None => self.unknown_probe_send_fence(peer),
        }
    }

    fn unknown_probe_send_fence(&self, peer: &str) -> Option<ProbeSendFence> {
        self.check_initial_probe_peer(peer).ok()?;
        let local_registration = match self.opaque_probe_registration.get() {
            Some(control) => Some(control.probe_registration_snapshot()?),
            None => None,
        };
        Some(ProbeSendFence {
            peer: peer.into(),
            generation: None,
            registration: 0,
            session: None,
            token: None,
            key_fingerprint: None,
            local_registration,
            opaque: false,
            unknown: true,
        })
    }

    // Both callers hold the connection reader. PeerLeft records the exact
    // identity in this existing bounded ledger before removing membership.
    fn check_initial_probe_peer(&self, peer: &str) -> std::result::Result<(), ProbeSendFenceError> {
        if self.peer_session_generation_any_sync(peer).is_some() {
            return Err(ProbeSendFenceError::Revoked);
        }
        let identities = self
            .remote_identity_ledger
            .try_lock()
            .map_err(|_| ProbeSendFenceError::Busy)?;
        if identities.get(peer).is_some() {
            return Err(ProbeSendFenceError::Revoked);
        }
        Ok(())
    }

    pub(crate) fn with_probe_send_fence<T>(
        &self,
        expected: &ProbeSendFence,
        bytes: &[u8],
        write: impl FnOnce() -> T,
    ) -> std::result::Result<T, ProbeSendFenceError> {
        let connections = self
            .connections
            .try_read()
            .map_err(|_| ProbeSendFenceError::Busy)?;
        if expected.unknown {
            if connections.contains_key(&expected.peer)
                || bytes.len() != 14
                || bytes.get(..5) != Some(b"PNCH\x01")
            {
                return Err(ProbeSendFenceError::Revoked);
            }
            self.check_initial_probe_peer(&expected.peer)?;
            return self.with_probe_local_registration(expected, write);
        }
        let conn = connections
            .get(&expected.peer)
            .ok_or(ProbeSendFenceError::Revoked)?;
        // The connection read guard pins lifecycle, capabilities and the exact
        // active binding through write. No auth borrow is held while looking up
        // connection state, avoiding a second state owner or reversed lock order.
        if !conn.online
            || conn.registration_seq != expected.registration
            || self.peer_session_generation_sync(&expected.peer) != expected.generation
            || conn.probe_session_id != expected.session
            || conn.probe_binding_token != expected.token
            || effective_probe_mac_key(conn).map(|key| p2pnet_crypto::hash(&key))
                != expected.key_fingerprint
            || self.opaque_probe_mode_for_connection(conn, false) != Some(expected.opaque)
            || bytes.get(4).is_none_or(|version| {
                (*version == p2pnet_nat::OPAQUE_PUNCH_VERSION) != expected.opaque
            })
        {
            return Err(ProbeSendFenceError::Revoked);
        }
        self.with_probe_local_registration(expected, write)
    }

    fn with_probe_local_registration<T>(
        &self,
        expected: &ProbeSendFence,
        write: impl FnOnce() -> T,
    ) -> std::result::Result<T, ProbeSendFenceError> {
        match (
            self.opaque_probe_registration.get(),
            expected.local_registration,
        ) {
            (Some(control), Some(registration)) => control
                .with_probe_registration(Some(registration), |_| write())
                .ok_or(ProbeSendFenceError::Revoked),
            (None, None) => Ok(write()),
            _ => Err(ProbeSendFenceError::Revoked),
        }
    }
}
