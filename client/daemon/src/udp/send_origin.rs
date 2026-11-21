// Opaque full-length UDP syscall fact. Only UDP descendants may mint it.
use super::{SocketState, UdpTransport};
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpSendFence {
    LegacyUnknown,
    LanPublication,
    ManagedPublication,
}
pub(crate) struct UdpFullSendFact {
    socket: Weak<UdpSocket>,
    registry: Weak<Mutex<SocketState>>,
    transport_instance: u64,
    socket_index: usize,
    local_endpoint: Option<SocketAddr>,
    endpoint: SocketAddr,
    sent: usize,
    syscall_started: Instant,
    syscall_completed: Instant,
    publication_owner: Option<u64>,
    fence: UdpSendFence,
    original_direct_commit: Option<u64>,
    // Only managed captured sends pay this allocation; do not enlarge every
    // canonical request's inline physical-publication cell by a full token.
    managed_token: Option<Box<crate::dplpmtud::DirectBusinessSendToken>>,
    wire: (usize, Option<u64>, u64),
}
#[allow(dead_code)] // Immutable evidence access, not final ownership/ACK authority.
impl UdpFullSendFact {
    pub(crate) fn original_managed_token(
        &self,
    ) -> Option<&crate::dplpmtud::DirectBusinessSendToken> {
        self.managed_token.as_deref()
    }
    pub(super) fn belongs_to_registry(&self, transport: &UdpTransport) -> bool {
        Weak::ptr_eq(&self.registry, &Arc::downgrade(&transport.socket_state))
    }
    pub(crate) fn matches_wire(&self, wire: (usize, Option<u64>, u64)) -> bool {
        self.wire == wire
    }
    pub(crate) fn source_is_live(&self) -> bool {
        self.socket.upgrade().is_some() && self.registry.upgrade().is_some()
    }
    pub(crate) fn belongs_to_socket(&self, socket: &Arc<UdpSocket>) -> bool {
        Weak::ptr_eq(&self.socket, &Arc::downgrade(socket))
    }
    pub(crate) fn transport_instance(&self) -> u64 {
        self.transport_instance
    }
    pub(crate) fn socket_index(&self) -> usize {
        self.socket_index
    }
    pub(crate) fn local_endpoint(&self) -> Option<SocketAddr> {
        self.local_endpoint
    }
    pub(crate) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
    pub(crate) fn sent(&self) -> usize {
        self.sent
    }
    pub(crate) fn syscall_started(&self) -> Instant {
        self.syscall_started
    }
    pub(crate) fn syscall_completed(&self) -> Instant {
        self.syscall_completed
    }
    pub(crate) fn publication_owner(&self) -> Option<u64> {
        self.publication_owner
    }
    pub(crate) fn fence(&self) -> UdpSendFence {
        self.fence
    }
    pub(crate) fn original_direct_commit(&self) -> Option<u64> {
        self.original_direct_commit
    }
}
// Attempt-local storage borrowed by the cancellable inner future. No Arc,
// queue, callback, task, duplicate mutable truth, or strong source keeper.
pub(crate) struct UdpSendCapture {
    fact: Option<UdpFullSendFact>,
}
impl UdpSendCapture {
    pub(crate) fn new() -> Self {
        Self { fact: None }
    }
    pub(crate) fn take(&mut self) -> Option<UdpFullSendFact> {
        self.fact.take()
    }
    // Only callers in the UDP parent/descendants can supply actual syscall Ok.
    // No public/crate-wide Some factory, Default, Clone or time setter.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_full_success(
        &mut self,
        transport: &UdpTransport,
        socket: &Arc<UdpSocket>,
        socket_index: usize,
        endpoint: SocketAddr,
        sent: usize,
        packet: &crate::transport::EncryptedPeerPacket,
        syscall_started: Instant,
        publication_owner: Option<u64>,
        fence: UdpSendFence,
        managed_token: Option<&crate::dplpmtud::DirectBusinessSendToken>,
    ) {
        if sent != packet.wire_bytes.len()
            || self.fact.is_some()
            || (fence == UdpSendFence::ManagedPublication) != managed_token.is_some()
        {
            return;
        }
        let syscall_completed = Instant::now();
        self.fact = Some(UdpFullSendFact {
            socket: Arc::downgrade(socket),
            registry: Arc::downgrade(&transport.socket_state),
            transport_instance: transport.transport_instance_id(),
            socket_index,
            local_endpoint: socket.local_addr().ok(),
            endpoint,
            sent,
            syscall_started,
            syscall_completed,
            publication_owner,
            fence,
            original_direct_commit: if fence == UdpSendFence::LegacyUnknown {
                None
            } else {
                transport.peers.try_original_direct_send_commit(
                    &packet.peer_id,
                    transport.peers.current_network_generation_sync(),
                    endpoint,
                )
            },
            managed_token: managed_token.map(|token| Box::new(token.clone())),
            wire: (
                packet.wire_bytes.len(),
                crate::transport::wire_counter(&packet.wire_bytes),
                crate::transport::wire_fingerprint(&packet.wire_bytes),
            ),
        });
    }
}

#[cfg(test)]
#[path = "send_origin/tests.rs"]
mod tests;
