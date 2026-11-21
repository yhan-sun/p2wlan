//! Exact immutable UDP reader provenance and a borrowed original publication fence.
//! These primitives do not own network/session state or grant final ACK credit.
use super::{
    SocketState, UdpFullSendFact, UdpSendFence, UdpTransport, DYNAMIC_SOCKET_INDEX_BASE,
    IPV6_SOCKET_INDEX,
};
use std::sync::{Arc, Weak};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, MutexGuard};

#[derive(Clone, Debug)]
pub(crate) struct OriginalUdpIngressSource {
    socket: Weak<UdpSocket>,
    registry: Weak<Mutex<SocketState>>,
    transport_instance: u64,
    socket_index: usize,
    publication_owner: u64,
    network_generation: u64,
    received_at: Instant,
    queue_send_started: Instant,
}

#[allow(dead_code)] // Immutable observation accessors may be diagnostic-only.
impl OriginalUdpIngressSource {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture(
        transport: &UdpTransport,
        socket: &Arc<UdpSocket>,
        socket_index: usize,
        publication_owner: u64,
        network_generation: u64,
        received_at: Instant,
        queue_send_started: Instant,
    ) -> Self {
        Self {
            socket: Arc::downgrade(socket),
            registry: Arc::downgrade(&transport.socket_state),
            transport_instance: transport.transport_instance_id(),
            socket_index,
            publication_owner,
            network_generation,
            received_at,
            queue_send_started,
        }
    }
    pub(crate) fn belongs_to_socket(&self, socket: &Arc<UdpSocket>) -> bool {
        Weak::ptr_eq(&self.socket, &Arc::downgrade(socket))
    }
    pub(crate) fn belongs_to_transport(&self, transport: &UdpTransport) -> bool {
        self.transport_instance == transport.transport_instance_id()
            && Weak::ptr_eq(&self.registry, &Arc::downgrade(&transport.socket_state))
    }
    pub(crate) fn received_at(&self) -> Instant {
        self.received_at
    }
    pub(crate) fn queue_send_started(&self) -> Instant {
        self.queue_send_started
    }
    pub(crate) fn socket_index(&self) -> usize {
        self.socket_index
    }
    pub(crate) fn publication_owner(&self) -> u64 {
        self.publication_owner
    }
    pub(crate) fn network_generation(&self) -> u64 {
        self.network_generation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectOriginFailure {
    Unknown,
    Stale,
    ContendedMembership,
    ContendedSocket,
    ContendedPublication,
}

/// Keeps only the original socket registry/publication fences. The caller must
/// additionally hold the current daemon slot, epoch, session and peer guards
/// before any credit transaction. Emit also freezes the same-peer production
/// capability publisher. Holding this alone is not final authority.
#[must_use]
pub(crate) struct DirectOriginPublicationGuard<'a> {
    _sockets: Option<MutexGuard<'a, SocketState>>,
    _publication: crate::dplpmtud::DirectBusinessPublicationGuard<'a>,
}

// Final ACK authority remains in the original peer-owner transaction.
impl UdpTransport {
    /// Sourced echo uses the original receiving socket and one publication
    /// guard for both RX validation and TX. Caller holds emit, epoch and slot.
    #[allow(clippy::too_many_arguments)] // Retain original fences plus one copied local qualifier.
    pub(crate) fn try_send_original_echo_on_receive_socket(
        &self,
        read: &OriginalUdpIngressSource,
        generation: u64,
        prepared: Option<&super::PreparedDirectBusinessSend>,
        packet: &crate::transport::EncryptedPeerPacket,
        endpoint: std::net::SocketAddr,
        verified_local: Option<std::net::SocketAddr>,
        session: &crate::transport::OriginalEchoSessionGuard<'_>,
    ) -> Result<usize, super::DirectBusinessUdpSendError> {
        use super::DirectBusinessUdpSendError as Error;
        let capability = self.peers.try_peer_dplpmtud_capability(&packet.peer_id);
        if capability == crate::peer::PeerDplpmtudCapability::Contended {
            return Err(Error::WouldBlock);
        }
        let guard = self
            .try_original_direct_publication_guard_with_prepared(
                &packet.peer_id,
                generation,
                Some(read),
                None,
                prepared,
            )
            .map_err(|failure| match failure {
                DirectOriginFailure::ContendedMembership
                | DirectOriginFailure::ContendedSocket
                | DirectOriginFailure::ContendedPublication => Error::WouldBlock,
                _ => Error::StaleToken,
            })?;
        let received_socket = if read.socket_index >= DYNAMIC_SOCKET_INDEX_BASE
            && read.socket_index != IPV6_SOCKET_INDEX
        {
            &guard
                ._sockets
                .as_ref()
                .ok_or(Error::StaleToken)?
                .dynamic
                .get(&read.socket_index)
                .ok_or(Error::StaleToken)?
                .socket
        } else if read.socket_index == IPV6_SOCKET_INDEX {
            self.ipv6_socket.as_ref().ok_or(Error::StaleToken)?
        } else {
            self.active_sockets()
                .get(read.socket_index)
                .ok_or(Error::StaleToken)?
        };
        // RX remains independently qualified by the original reader guard.
        // An authenticated asymmetric return follows its verified Direct
        // pair, whose current socket and budget are fenced by that same guard.
        let socket = match (verified_local, prepared) {
            (Some(_), Some(prepared)) => &prepared.socket,
            _ => received_socket,
        };
        if verified_local.is_some_and(|local| socket.local_addr().ok() != Some(local)) {
            return Err(Error::StaleToken);
        }
        match prepared {
            Some(prepared) => {
                if !Arc::ptr_eq(socket, &prepared.socket)
                    || prepared.endpoint != endpoint
                    || prepared.token.path_identity.peer_id != packet.peer_id
                    || prepared.token.path_identity.epoch.network_generation != generation
                    || prepared.token.udp_publication_owner != read.publication_owner
                    || !guard._publication.matches_original_token(&prepared.token)
                {
                    return Err(Error::StaleToken);
                }
                if packet.wire_bytes.len() > prepared.token.max_udp_datagram_size.0 as usize {
                    return Err(Error::CiphertextTooLarge);
                }
            }
            None => match capability {
                crate::peer::PeerDplpmtudCapability::Unsupported => {}
                crate::peer::PeerDplpmtudCapability::Supported
                    if self
                        .dplpmtud
                        .direct_business_budget_entry(&packet.peer_id)
                        .is_some_and(|entry| !entry.enforced) => {}
                _ => return Err(Error::StaleToken),
            },
        }
        if packet
            .room_authorization
            .as_ref()
            .is_some_and(|permit| !permit.is_valid())
        {
            return Err(Error::StaleToken);
        }
        if !session.is_current() {
            return Err(Error::StaleToken);
        }
        let sent = socket
            .try_send_to(&packet.wire_bytes, endpoint)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    Error::WouldBlock
                } else if super::is_local_packet_too_large(&error) {
                    Error::LocalPacketTooLarge
                } else {
                    Error::Io(error.to_string())
                }
            })?;
        if sent != packet.wire_bytes.len() {
            return Err(Error::Short {
                sent,
                expected: packet.wire_bytes.len(),
            });
        }
        Ok(sent)
    }

    pub(crate) fn try_original_direct_publication_guard(
        &self,
        peer: &str,
        generation: u64,
        received: Option<&OriginalUdpIngressSource>,
        sent: Option<&UdpFullSendFact>,
    ) -> Result<DirectOriginPublicationGuard<'_>, DirectOriginFailure> {
        self.try_original_direct_publication_guard_with_prepared(
            peer, generation, received, sent, None,
        )
    }

    fn try_original_direct_publication_guard_with_prepared(
        &self,
        peer: &str,
        generation: u64,
        received: Option<&OriginalUdpIngressSource>,
        sent: Option<&UdpFullSendFact>,
        prepared: Option<&super::PreparedDirectBusinessSend>,
    ) -> Result<DirectOriginPublicationGuard<'_>, DirectOriginFailure> {
        if (received.is_none() && sent.is_none())
            || sent.is_some_and(|fact| fact.fence() == UdpSendFence::LegacyUnknown)
        {
            return Err(DirectOriginFailure::Unknown);
        }
        // Do not call the legacy blocking membership predicate under our UDP
        // locks. Unknown membership can never be an unsupported/legacy bypass.
        let lan_capable = if sent.is_some_and(|fact| fact.fence() == UdpSendFence::LanPublication) {
            match self.peers.try_peer_dplpmtud_capability(peer) {
                crate::peer::PeerDplpmtudCapability::Contended => {
                    return Err(DirectOriginFailure::ContendedMembership)
                }
                crate::peer::PeerDplpmtudCapability::Unknown => {
                    return Err(DirectOriginFailure::Unknown)
                }
                crate::peer::PeerDplpmtudCapability::Supported => true,
                crate::peer::PeerDplpmtudCapability::Unsupported => false,
            }
        } else {
            false
        };
        let dynamic = |index| index >= DYNAMIC_SOCKET_INDEX_BASE && index != IPV6_SOCKET_INDEX;
        let sockets = if received.is_some_and(|fact| dynamic(fact.socket_index))
            || sent.is_some_and(|fact| dynamic(fact.socket_index()))
            || prepared.is_some_and(|prepared| dynamic(prepared.socket_index))
        {
            Some(
                self.socket_state
                    .try_lock()
                    .map_err(|_| DirectOriginFailure::ContendedSocket)?,
            )
        } else {
            None
        };
        let publication = self
            .dplpmtud
            .try_original_business_publication_guard()
            .ok_or(DirectOriginFailure::ContendedPublication)?;
        let owner = self.inbound_publication_owner();
        if owner == 0 || generation != self.peers.current_network_generation_sync() {
            return Err(DirectOriginFailure::Stale);
        }
        let current_socket = |index| {
            if dynamic(index) {
                sockets
                    .as_ref()?
                    .dynamic
                    .get(&index)
                    .filter(|entry| {
                        entry.peer_id == peer
                            && entry.network_generation == generation
                            && entry.phase.is_usable()
                            && entry.permits_ordinary_traffic()
                    })
                    .map(|entry| &entry.socket)
            } else if index == IPV6_SOCKET_INDEX {
                self.ipv6_socket.as_ref()
            } else {
                self.active_sockets().get(index)
            }
        };
        if let Some(fact) = received {
            if !fact.belongs_to_transport(self)
                || fact.publication_owner != owner
                || fact.network_generation != generation
                || current_socket(fact.socket_index)
                    .is_none_or(|socket| !fact.belongs_to_socket(socket))
            {
                return Err(DirectOriginFailure::Stale);
            }
        }
        if let Some(prepared) = prepared {
            let token = &prepared.token;
            if token.path_identity.peer_id != peer
                || token.path_identity.epoch.network_generation != generation
                || token.path_identity.socket.transport_instance_id != self.transport_instance_id()
                || token.path_identity.socket.socket_index != prepared.socket_index
                || token.path_identity.authenticated_remote_endpoint != prepared.endpoint
                || prepared.socket.local_addr().ok() != Some(token.path_identity.local_endpoint)
                || current_socket(prepared.socket_index)
                    .is_none_or(|socket| !Arc::ptr_eq(socket, &prepared.socket))
            {
                return Err(DirectOriginFailure::Stale);
            }
        }
        if let Some(fact) = sent {
            if !fact.belongs_to_registry(self)
                || fact.transport_instance() != self.transport_instance_id()
                || fact.publication_owner() != Some(owner)
                || current_socket(fact.socket_index())
                    .is_none_or(|socket| !fact.belongs_to_socket(socket))
            {
                return Err(DirectOriginFailure::Stale);
            }
            match fact.fence() {
                UdpSendFence::LegacyUnknown => return Err(DirectOriginFailure::Unknown),
                UdpSendFence::LanPublication
                    if lan_capable
                        && self
                            .dplpmtud
                            .direct_business_budget_entry(peer)
                            .is_none_or(|entry| entry.enforced) =>
                {
                    return Err(DirectOriginFailure::Stale);
                }
                UdpSendFence::ManagedPublication => {
                    let token = fact
                        .original_managed_token()
                        .ok_or(DirectOriginFailure::Unknown)?;
                    if token.path_identity.peer_id != peer
                        || token.udp_publication_owner != owner
                        || token.path_identity.epoch.network_generation != generation
                        || token.path_identity.socket.transport_instance_id
                            != fact.transport_instance()
                        || token.path_identity.socket.socket_index != fact.socket_index()
                        || Some(token.path_identity.local_endpoint) != fact.local_endpoint()
                        || token.path_identity.authenticated_remote_endpoint != fact.endpoint()
                        || !publication.matches_original_token(token)
                    {
                        return Err(DirectOriginFailure::Stale);
                    }
                }
                UdpSendFence::LanPublication => {}
            }
        }
        Ok(DirectOriginPublicationGuard {
            _sockets: sockets,
            _publication: publication,
        })
    }
}
