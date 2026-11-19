//! Bounded, non-authoritative routing hints for session-opaque PNCH identities.
//! A hit only selects a peer. The current connection still owns keys, roles,
//! expiry, registration and lifecycle fencing for authentication and adoption.

use super::*;
mod send_fence;
pub(crate) use send_fence::{ProbeSendFence, ProbeSendFenceError};

const MAX_OPAQUE_PROBE_ROUTES: usize = 8192;
const OPAQUE_PROBE_ROUTE_TTL: Duration = Duration::from_secs(180);

#[derive(Clone)]
struct RouteHint {
    peer: String,
    generation: PeerSessionGeneration,
    expires: Instant,
}

#[derive(Default)]
pub(crate) struct OpaqueProbeRouteHints {
    entries: HashMap<String, RouteHint>,
}

impl OpaqueProbeRouteHints {
    fn publish(
        &mut self,
        mut labels: Vec<String>,
        peer: &str,
        generation: PeerSessionGeneration,
        now: Instant,
    ) -> bool {
        labels.sort();
        labels.dedup();
        if labels.iter().any(|label| {
            self.entries
                .get(label)
                .is_some_and(|hint| hint.expires > now && hint.peer != peer)
        }) {
            return false;
        }
        let additional = labels
            .iter()
            .filter(|label| !self.entries.contains_key(*label))
            .count();
        if self.entries.len().saturating_add(additional) > MAX_OPAQUE_PROBE_ROUTES {
            // Reclaim expired hints only under capacity pressure, never for
            // the normal exact-label refresh on a healthy consent hot path.
            self.entries.retain(|_, hint| hint.expires > now);
            let additional = labels
                .iter()
                .filter(|label| !self.entries.contains_key(*label))
                .count();
            if self.entries.len().saturating_add(additional) > MAX_OPAQUE_PROBE_ROUTES {
                return false;
            }
        }
        for label in labels {
            self.entries.insert(
                label,
                RouteHint {
                    peer: peer.to_string(),
                    generation,
                    expires: now + OPAQUE_PROBE_ROUTE_TTL,
                },
            );
        }
        true
    }
}

impl PeerManager {
    pub(crate) fn bind_opaque_probe_registration(
        &self,
        control: crate::control::ControlClient,
    ) -> bool {
        self.opaque_probe_registration.set(control).is_ok()
    }

    /// Receive eligibility admits a pending first handshake. Its exact key,
    /// role and session are authenticated by the existing adoption transaction.
    pub(crate) async fn opaque_probe_mode_for_peer(&self, peer: &str) -> Option<bool> {
        let connections = self.connections.read().await;
        self.opaque_probe_mode_for_connection(connections.get(peer)?, false)
    }

    /// Sending requires the installed active session; absence never grants
    /// permission to fall back to a stable node ID or unauthenticated probe.
    #[cfg(test)]
    pub(crate) async fn opaque_probe_send_mode_for_peer(&self, peer: &str) -> Option<bool> {
        let connections = self.connections.read().await;
        self.opaque_probe_mode_for_connection(connections.get(peer)?, true)
    }

    fn opaque_probe_mode_for_connection(
        &self,
        conn: &PeerConnection,
        sending: bool,
    ) -> Option<bool> {
        if !conn.online
            || self.peer_session_generation_sync(&conn.node_id).is_none()
            || (conn.opaque_probe_required && !conn.capabilities.probe_opaque_ids_v1)
        {
            return None;
        }
        if conn.capabilities.probe_opaque_ids_v1 {
            if self
                .opaque_probe_registration
                .get()?
                .local_opaque_probe_registration_seq()
                .is_none()
                || conn.registration_seq == 0
                || (sending
                    && (conn.probe_session_id.is_none() || conn.probe_ephemeral_shared.is_none()))
            {
                return None;
            }
            Some(true)
        } else {
            Some(false)
        }
    }

    /// Best-effort exact active refresh cannot change availability of the
    /// original active key. A full pending publication or contended hint lock
    /// therefore cannot stop an already healthy connection's consent sends.
    pub(super) fn refresh_active_opaque_probe_route(&self, conn: &PeerConnection) {
        if !conn.capabilities.probe_opaque_ids_v1
            || conn.probe_session_id.is_none()
            || conn.probe_ephemeral_shared.is_none()
        {
            return;
        }
        let Some(generation) = self.peer_session_generation_sync(&conn.node_id) else {
            return;
        };
        let Some(key) = effective_probe_mac_key(conn) else {
            return;
        };
        let label = p2pnet_nat::opaque_probe_identity(&key, &conn.node_id);
        let Ok(mut hints) = self.opaque_probe_routes.try_lock() else {
            return;
        };
        if let Some(hint) = hints
            .entries
            .get_mut(&label)
            .filter(|hint| hint.peer == conn.node_id && hint.generation == generation)
        {
            hint.expires = Instant::now() + OPAQUE_PROBE_ROUTE_TTL;
            return;
        }
        let _ = hints.publish(vec![label], &conn.node_id, generation, Instant::now());
    }

    pub(super) fn refresh_opaque_probe_routes(&self, conn: &PeerConnection) {
        if !self.publish_opaque_probe_routes(conn) {
            warn!(
                reason_code = "opaque_probe_route_capacity_or_contention",
                "Opaque probe route hint unavailable; plaintext identity fallback is disabled"
            );
        }
    }

    /// Called with the authoritative connection guard for these bindings.
    /// A full/contended hint table fails publication without evicting live peers.
    pub(super) fn publish_opaque_probe_routes(&self, conn: &PeerConnection) -> bool {
        if !conn.capabilities.probe_opaque_ids_v1 {
            return true;
        }
        let Some(generation) = self.peer_session_generation_sync(&conn.node_id) else {
            return false;
        };
        let Some(base_key) = conn.probe_mac_key else {
            return false;
        };
        let active = active_probe_binding(conn);
        let now = Instant::now();
        let bindings = std::iter::once(&active)
            .chain(
                conn.pending_probe_bindings
                    .values()
                    .filter(|pending| pending.expires_at > now)
                    .map(|pending| &pending.binding),
            )
            .chain(
                conn.previous_probe_binding
                    .iter()
                    .filter(|previous| previous.expires_at > now)
                    .map(|previous| &previous.binding),
            );
        let labels = bindings
            .filter(|binding| binding.session_id.is_some() && binding.ephemeral_shared.is_some())
            .map(|binding| {
                p2pnet_nat::opaque_probe_identity(
                    &probe_mac_key_for_binding(base_key, binding),
                    &conn.node_id,
                )
            })
            .collect();
        self.opaque_probe_routes
            .try_lock()
            .ok()
            .is_some_and(|mut hints| hints.publish(labels, &conn.node_id, generation, now))
    }

    pub(crate) fn resolve_opaque_probe_peer(&self, label: &str) -> Option<String> {
        let hint = self
            .opaque_probe_routes
            .try_lock()
            .ok()?
            .entries
            .get(label)?
            .clone();
        (hint.expires > Instant::now()
            && self.peer_session_generation_sync(&hint.peer) == Some(hint.generation))
        .then_some(hint.peer)
    }
}

#[cfg(test)]
mod tests;
