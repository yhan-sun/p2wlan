//! Pure ACK identity and the canonical request's sole native-credit once.
use super::CanonicalOverlayRequest;
use crate::peer::NetworkPath;
use std::sync::atomic::Ordering;
use std::time::Instant;

/// Constructed only by validating the actual decrypted ACK bytes.
pub(crate) struct OriginalOverlayAck {
    pub(crate) peer_id: String,
    pub(crate) source_vip: String,
    pub(crate) local_vip: String,
    pub(crate) nonce: u64,
    pub(crate) seq: u32,
    direction: u8,
}

impl OriginalOverlayAck {
    pub(crate) fn is_echo(&self) -> bool {
        self.direction == crate::OVERLAY_DIRECTION_ECHO
    }
    pub(crate) fn parse(packet: &[u8], authenticated_peer: &str) -> Option<Self> {
        Self::parse_direction(packet, authenticated_peer, crate::OVERLAY_DIRECTION_ECHO)
    }

    pub(crate) fn parse_request(packet: &[u8], authenticated_peer: &str) -> Option<Self> {
        Self::parse_direction(packet, authenticated_peer, crate::OVERLAY_DIRECTION_REQUEST)
    }

    fn parse_direction(packet: &[u8], authenticated_peer: &str, direction: u8) -> Option<Self> {
        if packet.first()? >> 4 != 4 || packet.len() < 20 {
            return None;
        }
        let ip = p2pnet_tun::Ipv4Packet::new(packet).ok()?;
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        // Reject truncation, concatenation and every fragmented UDP envelope.
        if ip.protocol() != p2pnet_tun::Protocol::Udp
            || header_len < 20
            || total_len != packet.len()
            || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
        {
            return None;
        }
        let udp = packet.get(header_len..)?;
        if udp.len() < 8 || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len() {
            return None;
        }
        let expected_ports = if direction == crate::OVERLAY_DIRECTION_REQUEST {
            (39286, 39287)
        } else {
            (39287, 39286)
        };
        if (
            u16::from_be_bytes([udp[0], udp[1]]),
            u16::from_be_bytes([udp[2], udp[3]]),
        ) != expected_ports
        {
            return None;
        }
        let payload = &udp[8..];
        if payload.len() != crate::OVERLAY_CHECKSUM_OFFSET + 4 + crate::OVERLAY_FILLER_BYTES
            || payload.get(..crate::OVERLAY_MAGIC.len())? != crate::OVERLAY_MAGIC
            || payload[crate::OVERLAY_MAGIC.len()] != direction
        {
            return None;
        }
        let checksum = u32::from_be_bytes(
            payload[crate::OVERLAY_CHECKSUM_OFFSET..crate::OVERLAY_CHECKSUM_OFFSET + 4]
                .try_into()
                .ok()?,
        );
        if checksum != crate::crc32_business_payload(&payload[..crate::OVERLAY_CHECKSUM_SPAN]) {
            return None;
        }
        Some(Self {
            peer_id: authenticated_peer.to_string(),
            source_vip: ip.src_addr().to_string(),
            local_vip: ip.dst_addr().to_string(),
            nonce: u64::from_be_bytes(payload[7..15].try_into().ok()?),
            seq: u32::from_be_bytes(payload[15..19].try_into().ok()?),
            direction,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverlayCreditUnknown {
    OriginalSource,
    OriginalPublication,
    OriginalAuthorization,
    MixedPath,
    RoomAuthority,
    CrossRelayClient,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverlayCreditStale {
    Identity,
    Generation,
    Lifecycle,
    Session,
    PeerState,
    Quarantine,
    Policy,
    DirectPublication,
    RelayPublication,
    OriginalWindow,
    ReadBeforePublication,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverlayCreditLockSite {
    Emit,
    Epoch,
    Sessions,
    Connections,
    Membership,
    Quarantine,
    UdpSlot,
    DirectPolicy,
    DirectSocket,
    DirectPublication,
    RelaySlot,
    RelayRoutes,
    RelayLive,
    RelayClose,
}

/// Only fixed-size committed observations; no owner or transferable permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OverlayCreditReceipt {
    pub(crate) generation: u64,
    pub(crate) path: NetworkPath,
    pub(crate) attempt_id: u64,
    pub(crate) committed_at: Instant,
    pub(crate) first_usable_new: bool,
    pub(crate) fallback_reason: Option<&'static str>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OverlayCreditOutcome {
    Fresh(OverlayCreditReceipt),
    AlreadyCommitted,
    Unknown(OverlayCreditUnknown),
    Stale(OverlayCreditStale),
    Contended(OverlayCreditLockSite),
}

impl CanonicalOverlayRequest {
    /// The permit has a private constructor in the sole PeerManager final
    /// transaction. Neither retained views nor public events can mint one.
    pub(crate) fn consume_native_ack_once(
        &self,
        _permit: crate::peer::OriginalOverlayAckCommitPermit,
    ) -> bool {
        self.native_ack_credited
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[cfg(test)]
    pub(crate) fn native_ack_credited_for_test(&self) -> bool {
        self.native_ack_credited.load(Ordering::Acquire)
    }
}
