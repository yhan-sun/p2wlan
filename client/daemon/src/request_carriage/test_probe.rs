//! One bounded test-only historical argument observation. Never a receipt.

use std::time::Instant;

use super::EncryptedRequestDelivery;
use crate::overlay_requests::RequestSendToken;
use crate::peer::PeerSessionGeneration;
use crate::transport::WireGuardTransport;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandoffArgumentPoint {
    SlowBoundedEntry,
    FastUdpCall,
}

pub(crate) struct HandoffEncryptionFacts {
    pub(crate) peer_id: String,
    pub(crate) session_instance: u64,
    pub(crate) authorized_peer_lifecycle: Option<PeerSessionGeneration>,
    pub(crate) encrypted_at: Instant,
    pub(crate) belongs_to_transport: bool,
}

pub(crate) struct RequestHandoffArguments {
    pub(crate) point: HandoffArgumentPoint,
    pub(crate) token: Option<RequestSendToken>,
    pub(crate) source: Option<HandoffEncryptionFacts>,
    pub(crate) wire: (usize, Option<u64>, u64),
}

pub(crate) struct RequestHandoffArgumentProbe {
    pub(crate) recorded: std::sync::Mutex<Option<RequestHandoffArguments>>,
}

impl RequestHandoffArgumentProbe {
    pub(crate) fn new() -> Self {
        Self {
            recorded: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn observe(
        &self,
        packet: &EncryptedRequestDelivery,
        transport: &WireGuardTransport,
        point: HandoffArgumentPoint,
    ) {
        // A busy/saturated test cell never waits under real authority guards.
        // No callback/IO/await, strong request owner, or production allocation.
        let Ok(mut recorded) = self.recorded.try_lock() else {
            return;
        };
        if recorded.is_some() {
            return;
        }
        *recorded = Some(RequestHandoffArguments {
            point,
            wire: (
                packet.wire_bytes.len(),
                crate::transport::wire_counter(&packet.wire_bytes),
                crate::transport::wire_fingerprint(&packet.wire_bytes),
            ),
            token: packet.binding().map(|binding| binding.token().clone()),
            source: packet.source().map(|source| HandoffEncryptionFacts {
                peer_id: source.peer_id().to_string(),
                session_instance: source.session_instance(),
                authorized_peer_lifecycle: source.authorized_peer_lifecycle(),
                encrypted_at: source.encrypted_at(),
                belongs_to_transport: source.belongs_to(transport),
            }),
        });
    }
}
