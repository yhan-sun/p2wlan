//! First input/route refusal. The original predicates and their order remain;
//! these reasons neither recover a binding nor grant physical-send authority.
use super::*;

impl KernelReadBinding {
    pub(crate) fn input_rejection(
        &self,
        peers: &Arc<PeerManager>,
        packet: &[u8],
        observed_at: Instant,
    ) -> Option<FullRetentionLossReason> {
        use FullRetentionLossReason as Reason;
        if let Some(reason) = self.read_retention_input_rejection(observed_at) {
            return Some(reason);
        }
        let Some(scope) = self.scope.upgrade() else {
            return Some(Reason::InputScopeUnavailable);
        };
        if !Weak::ptr_eq(&scope.peers, &Arc::downgrade(peers)) {
            return Some(Reason::InputOwnerMismatch);
        }
        if let Some(reason) = self.original_peer_identity_rejection(&scope, observed_at) {
            return Some(reason);
        }
        if !scope.is_live(observed_at) {
            return Some(Reason::InputScopeNotLive);
        }
        if !self.read.is_current() {
            return Some(Reason::InputDeviceRetired);
        }
        if self.read.at() > observed_at {
            return Some(Reason::InputClockBeforeRead);
        }
        if self.packet_len != packet.len() {
            return Some(Reason::InputPacketLengthMismatch);
        }
        if self.packet_sha256 != <[u8; 32]>::from(Sha256::digest(packet)) {
            return Some(Reason::InputPacketDigestMismatch);
        }
        if self.slots.is_empty() || self.slots.len() > MAX_BINDINGS_PER_PACKET {
            return Some(Reason::InputFrameBindingsInvalid);
        }
        None
    }

    pub(crate) fn route_rejection(
        &self,
        peers: &Arc<PeerManager>,
        packet: &OutboundPacket,
        observed_at: Instant,
    ) -> Option<FullRetentionLossReason> {
        use FullRetentionLossReason as Reason;
        if let Some(reason) = self.input_rejection(peers, &packet.packet, observed_at) {
            return Some(reason);
        }
        if packet.peer_id != self.plan.peer {
            return Some(Reason::RoutedPeerMismatch);
        }
        if packet.dst_ip != self.plan.flow.dst_v4.to_string() {
            return Some(Reason::RoutedDestinationMismatch);
        }
        if !self.original_room_matches_permit(packet.room_authorization.as_ref()) {
            return Some(Reason::RoutedRoomPermitRejected);
        }
        None
    }
}
