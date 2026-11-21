//! Immutable encrypted-ingress provenance carried to the overlay validator.
//! This module owns no session, publication or credit state.

use std::net::SocketAddr;
use std::time::Instant;

use crate::transport::{OriginalSessionSource, OverlayIngressEvent, ReceivedEncryptedPacket};

pub(crate) struct OverlayIngressDelivery {
    event: OverlayIngressEvent,
    original_source: Option<OriginalOverlayIngressSource>,
}

impl OverlayIngressDelivery {
    // Only the actual inbound parent can supply a successful decrypt source.
    pub(super) fn authenticated(
        event: OverlayIngressEvent,
        original_source: OriginalOverlayIngressSource,
    ) -> Self {
        Self {
            event,
            original_source: Some(original_source),
        }
    }

    pub(crate) fn into_parts(self) -> (OverlayIngressEvent, Option<OriginalOverlayIngressSource>) {
        (self.event, self.original_source)
    }
}

impl From<OverlayIngressEvent> for OverlayIngressDelivery {
    fn from(event: OverlayIngressEvent) -> Self {
        Self {
            event,
            original_source: None,
        }
    }
}

#[cfg_attr(test, derive(Clone))]
pub(super) struct EncryptedOverlayOrigin {
    network_generation: Option<u64>,
    relay_endpoint: Option<String>,
    relay_connection_id: Option<u64>,
    relay_peer_id: Option<String>,
    udp_transport_owner: Option<u64>,
    source: Option<SocketAddr>,
    local_endpoint: Option<SocketAddr>,
    socket_index: Option<usize>,
    received_at: Option<Instant>,
    queue_send_started: Option<Instant>,
    original_relay_read: Option<p2pnet_relay::OriginalRelayFrameRead>,
    original_udp_read: Option<crate::udp::OriginalUdpIngressSource>,
}

impl EncryptedOverlayOrigin {
    pub(super) fn capture(packet: &ReceivedEncryptedPacket) -> Self {
        Self {
            network_generation: packet.network_generation,
            relay_endpoint: packet.relay_endpoint.clone(),
            relay_connection_id: packet.relay_connection_id,
            relay_peer_id: packet.relay_peer_id.clone(),
            udp_transport_owner: packet.udp_transport_owner,
            source: packet.source,
            local_endpoint: packet.local_endpoint,
            socket_index: packet.socket_index,
            received_at: packet.udp_received,
            queue_send_started: packet.transport_queue_send_started,
            original_relay_read: packet.original_relay_read.clone(),
            original_udp_read: packet.original_udp_read.clone(),
        }
    }

    pub(super) fn authenticated(
        self,
        session: OriginalSessionSource,
    ) -> OriginalOverlayIngressSource {
        OriginalOverlayIngressSource {
            session,
            envelope: self,
        }
    }
}

/// Original observations only; no current-owner or once-credit qualification.
// Tests retain the same immutable original observation across rejected/fresh
// final calls. Clone preserves roles/times/Weak identities and mints no fact.
#[cfg_attr(test, derive(Clone))]
pub(crate) struct OriginalOverlayIngressSource {
    session: OriginalSessionSource,
    envelope: EncryptedOverlayOrigin,
}

// Immutable metadata is qualified separately by the original final owner.
#[allow(dead_code)]
impl OriginalOverlayIngressSource {
    pub(crate) fn session(&self) -> &OriginalSessionSource {
        &self.session
    }

    pub(crate) fn network_generation(&self) -> Option<u64> {
        self.envelope.network_generation
    }

    /// The original outer selected transport endpoint, not an auxiliary reader.
    pub(crate) fn relay_endpoint(&self) -> Option<&str> {
        self.envelope.relay_endpoint.as_deref()
    }

    /// The original native reader's requested endpoint. No current route,
    /// outer slot or replacement client can supply this historical metadata.
    pub(crate) fn relay_reader_endpoint(&self) -> Option<&str> {
        self.envelope
            .original_relay_read
            .as_ref()
            .map(|read| read.requested_endpoint())
    }

    pub(crate) fn relay_connection_id(&self) -> Option<u64> {
        self.envelope.relay_connection_id
    }

    pub(crate) fn relay_peer_id(&self) -> Option<&str> {
        self.envelope.relay_peer_id.as_deref()
    }

    pub(crate) fn udp_transport_owner(&self) -> Option<u64> {
        self.envelope.udp_transport_owner
    }

    pub(crate) fn source(&self) -> Option<SocketAddr> {
        self.envelope.source
    }

    pub(crate) fn local_endpoint(&self) -> Option<SocketAddr> {
        self.envelope.local_endpoint
    }

    pub(crate) fn socket_index(&self) -> Option<usize> {
        self.envelope.socket_index
    }

    pub(crate) fn received_at(&self) -> Option<Instant> {
        self.envelope.received_at
    }

    pub(crate) fn queue_send_started(&self) -> Option<Instant> {
        self.envelope.queue_send_started
    }

    pub(crate) fn original_udp_read(&self) -> Option<&crate::udp::OriginalUdpIngressSource> {
        self.envelope.original_udp_read.as_ref()
    }

    pub(crate) fn original_relay_read(&self) -> Option<&p2pnet_relay::OriginalRelayFrameRead> {
        self.envelope.original_relay_read.as_ref()
    }
}
