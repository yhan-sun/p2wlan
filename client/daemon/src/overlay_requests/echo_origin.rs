//! Original REQUEST provenance through the existing echo/TUN/carriage queues.
//! Metadata holds only Weak owners; qualification is repeated at actual send.
use super::{OriginalOverlayAck, OverlayCreditOutcome};
use crate::peer::PeerManager;
use crate::transport::{
    OriginalEncryptionSource, OriginalOverlayIngressSource, OriginalSessionRole, WireGuardTransport,
};
use std::sync::{Arc, Weak};
use std::time::Instant;
use tokio::sync::{OwnedMutexGuard, RwLock};

pub(crate) struct OriginalEchoInput {
    source: OriginalOverlayIngressSource,
    owner: Weak<PeerManager>,
    udp: Weak<RwLock<Option<crate::udp::UdpTransport>>>,
    relay: Weak<RwLock<Option<crate::relay::RelayTransport>>>,
    peer_id: String,
    target_vip: String,
    generation: u64,
    read_at: Instant,
    packet: Box<[u8]>,
}

impl OriginalEchoInput {
    pub(crate) fn source(&self) -> &OriginalOverlayIngressSource {
        &self.source
    }
    pub(crate) fn owner(&self) -> &Weak<PeerManager> {
        &self.owner
    }
    pub(crate) fn udp(&self) -> &Weak<RwLock<Option<crate::udp::UdpTransport>>> {
        &self.udp
    }
    pub(crate) fn relay(&self) -> &Weak<RwLock<Option<crate::relay::RelayTransport>>> {
        &self.relay
    }
    pub(crate) fn peer_id(&self) -> &str {
        &self.peer_id
    }
    pub(crate) fn target_vip(&self) -> &str {
        &self.target_vip
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn read_at(&self) -> Instant {
        self.read_at
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        peers: &Arc<PeerManager>,
        wireguard: &WireGuardTransport,
        udp: &Arc<RwLock<Option<crate::udp::UdpTransport>>>,
        relay: &Arc<RwLock<Option<crate::relay::RelayTransport>>>,
        request: OriginalOverlayAck,
        source: OriginalOverlayIngressSource,
        echo: &[u8],
    ) -> Option<Self> {
        if request.is_echo()
            || !source.session().belongs_to(wireguard)
            || source.session().original_role() != OriginalSessionRole::Active
            || source.session().peer_id() != request.peer_id
            || (source.original_relay_read().is_some()
                && source.relay_peer_id() != Some(request.peer_id.as_str()))
        {
            return None;
        }
        let generation = source.network_generation()?;
        let read_at = match (source.original_udp_read(), source.original_relay_read()) {
            (Some(read), None) => read.received_at(),
            (None, Some(read)) => read.completed_at(),
            _ => return None,
        };
        if read_at > source.session().authenticated_at() {
            return None;
        }
        Some(Self {
            source,
            owner: Arc::downgrade(peers),
            udp: Arc::downgrade(udp),
            relay: Arc::downgrade(relay),
            peer_id: request.peer_id,
            target_vip: request.source_vip,
            generation,
            read_at,
            packet: echo.into(),
        })
    }

    pub(crate) fn exact_input(
        &self,
        peers: &Arc<PeerManager>,
        packet: &[u8],
        now: Instant,
    ) -> bool {
        self.owner.ptr_eq(&Arc::downgrade(peers))
            && self.packet.as_ref() == packet
            && crate::request_carriage::in_original_window(self.read_at, now)
    }

    pub(crate) fn exact_route(
        &self,
        peers: &Arc<PeerManager>,
        packet: &crate::dataplane::OutboundPacket,
        now: Instant,
    ) -> bool {
        self.exact_input(peers, &packet.packet, now)
            && packet.peer_id == self.peer_id
            && packet.dst_ip == self.target_vip
    }

    pub(crate) fn exact_route_for_owner(
        &self,
        peers: &PeerManager,
        packet: &crate::dataplane::OutboundPacket,
        now: Instant,
    ) -> bool {
        std::ptr::eq(self.owner.as_ptr(), peers)
            && self.packet.as_ref() == packet.packet
            && packet.peer_id == self.peer_id
            && packet.dst_ip == self.target_vip
            && crate::request_carriage::in_original_window(self.read_at, now)
    }

    pub(crate) fn qualify_before_injection(
        &self,
        wireguard: &WireGuardTransport,
    ) -> Result<(), OverlayCreditOutcome> {
        let peers = self.owner.upgrade().ok_or(OverlayCreditOutcome::Stale(
            crate::overlay_requests::OverlayCreditStale::Lifecycle,
        ))?;
        peers.try_qualify_original_echo_input(wireguard, self)
    }

    pub(crate) fn prewrite(
        self: &Arc<Self>,
        tx: &OriginalEncryptionSource,
        emit: Weak<OwnedMutexGuard<()>>,
        packet: &crate::transport::EncryptedPeerPacket,
    ) -> Option<Arc<OriginalEchoPrewrite>> {
        if packet.peer_id != self.peer_id || tx.peer_id() != self.peer_id {
            return None;
        }
        Some(Arc::new(OriginalEchoPrewrite {
            input: self.clone(),
            tx: tx.try_copy_for_publication().ok()?,
            emit,
            wire: (
                packet.wire_bytes.len(),
                crate::transport::wire_counter(&packet.wire_bytes),
                crate::transport::wire_fingerprint(&packet.wire_bytes),
            ),
        }))
    }
}

pub(crate) struct OriginalEchoPrewrite {
    input: Arc<OriginalEchoInput>,
    tx: OriginalEncryptionSource,
    emit: Weak<OwnedMutexGuard<()>>,
    wire: (usize, Option<u64>, u64),
}

impl OriginalEchoPrewrite {
    pub(crate) fn matches_packet(&self, packet: &crate::transport::EncryptedPeerPacket) -> bool {
        packet.peer_id == self.input.peer_id
            && self.wire
                == (
                    packet.wire_bytes.len(),
                    crate::transport::wire_counter(&packet.wire_bytes),
                    crate::transport::wire_fingerprint(&packet.wire_bytes),
                )
    }
    /// The original caller owns epoch and current UDP slot through this syscall.
    pub(crate) fn try_send_direct_in_epoch(
        &self,
        udp: &crate::udp::UdpTransport,
        prepared: Option<&crate::udp::PreparedDirectBusinessSend>,
        packet: &crate::transport::EncryptedPeerPacket,
        endpoint: std::net::SocketAddr,
    ) -> Result<usize, crate::udp::DirectBusinessUdpSendError> {
        use crate::udp::DirectBusinessUdpSendError as Error;
        if !self.matches_packet(packet) {
            return Err(Error::StaleToken);
        }
        let _emit = self.emit.upgrade().ok_or(Error::StaleToken)?;
        let peers = self.input.owner.upgrade().ok_or(Error::StaleToken)?;
        let peer = peers
            .try_original_echo_peer_in_epoch(&self.input, &self.tx)
            .map_err(|_| Error::StaleToken)?;
        let read = self
            .input
            .source
            .original_udp_read()
            .ok_or(Error::StaleToken)?;
        let source = self.input.source.source().ok_or(Error::StaleToken)?;
        let verified_local = peer.verified_direct_return_local(&self.input, endpoint);
        // A current owned return can differ in local socket even when its
        // remote endpoint equals the observed REQUEST source. Legacy
        // equal-source compatibility still uses only the original RX socket.
        if source != endpoint && verified_local.is_none() {
            return Err(Error::StaleToken);
        }
        udp.try_send_original_echo_on_receive_socket(
            read,
            self.input.generation,
            prepared,
            packet,
            endpoint,
            verified_local,
            &peer.session,
        )
    }
    pub(crate) fn peer_guard(
        &self,
    ) -> Result<crate::peer::OriginalEchoPeerWriteGuard<'_>, OverlayCreditOutcome> {
        let peers = self
            .input
            .owner
            .upgrade()
            .ok_or(OverlayCreditOutcome::Stale(
                crate::overlay_requests::OverlayCreditStale::Lifecycle,
            ))?;
        peers.try_original_echo_peer_write_guard(&self.input, &self.tx, &self.emit)
    }

    /// Original Relay writer calls this after dequeue/encoding, under its
    /// existing outer-live guard and immediately before starting write_all.
    /// It never grants a lease through the later asynchronous Full completion.
    pub(crate) fn relay_prewrite_is_current(
        &self,
        actual_client: &Arc<p2pnet_relay::RelayClient>,
        id: u64,
        actual_live: &Arc<std::sync::Mutex<bool>>,
    ) -> bool {
        let Ok(peer) = self.peer_guard() else {
            return false;
        };
        let Some(slot) = self.input.relay.upgrade() else {
            return false;
        };
        let Ok(slot) = slot.try_read() else {
            return false;
        };
        let Some(relay) = slot.as_ref() else {
            return false;
        };
        let (Some(read), Some(original_id), Some(endpoint)) = (
            self.input.source.original_relay_read(),
            self.input.source.relay_connection_id(),
            self.input.source.relay_reader_endpoint(),
        ) else {
            return false;
        };
        let Ok(member) = relay.try_original_echo_reader_member_guard_under_live(
            read,
            endpoint,
            original_id,
            actual_client,
            id,
            actual_live,
        ) else {
            return false;
        };
        let Ok(_open) = member.try_open_guard() else {
            return false;
        };
        peer.current.session.is_current()
    }
}
