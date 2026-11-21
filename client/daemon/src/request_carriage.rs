//! Weak original-request identity carried by the existing packet owners.
//!
//! Binding is historical input recognition. It never changes business routing,
//! establishes physical completion, or authorizes ACK credit.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Instant;

use p2pnet_tun::{IpPacket, PacketReadContext, Protocol};

use crate::dataplane::OutboundPacket;
use crate::overlay_requests::RequestSendToken;
use crate::peer::PeerManager;
use crate::transport::{EncryptedPeerPacket, OriginalEncryptionSource};

mod channel;
mod crypto;
mod physical;
pub(crate) use channel::{RawOutboundReceiver, RawOutboundSink};
pub(crate) use crypto::RequestEncryptionAttempt;
#[cfg(test)]
pub(crate) mod test_probe;
#[cfg(test)]
pub(crate) mod test_support;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestBindingFailure {
    Retired,
    OriginalBytes,
    OriginalIdentity,
    ForeignOwner,
    RouteIdentity,
    RouteBytes,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestBindingState {
    ReadExact,
    RoutedExact,
    Invalid(RequestBindingFailure),
}

#[allow(dead_code)] // Staged input qualifier; final receipt/credit is separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestInputEligibility {
    PendingInjection,
    AcceptedInput,
    Invalid(RequestBindingFailure),
    Retired,
    Expired,
}

/// This sealed identity survives every invalid/pending state until the original
/// packet is actually dropped. Acceptance is read from its one canonical owner.
#[derive(Clone)]
pub(crate) struct RequestBinding {
    token: RequestSendToken,
    state: RequestBindingState,
}

impl RequestBinding {
    pub(crate) fn from_read_context(
        context: Option<PacketReadContext>,
        packet: &[u8],
        peers: &Arc<PeerManager>,
        observed_at: Instant,
    ) -> Option<Self> {
        let token = RequestSendToken::from_read_context(context?)?;
        if let Some(echo) = token.echo() {
            let state = if echo.exact_input(peers, packet, observed_at) {
                RequestBindingState::ReadExact
            } else {
                RequestBindingState::Invalid(RequestBindingFailure::OriginalBytes)
            };
            return Some(Self { token, state });
        }
        // The temporary Arc is dropped synchronously before any route await.
        let state = match token.request() {
            None => RequestBindingState::Invalid(RequestBindingFailure::Retired),
            Some(request) => {
                let failure = if !request.belongs_to(peers) {
                    Some(RequestBindingFailure::ForeignOwner)
                } else if request.original_packet() != packet {
                    Some(RequestBindingFailure::OriginalBytes)
                } else if !original_identity_matches(&request, packet) {
                    Some(RequestBindingFailure::OriginalIdentity)
                } else if !in_original_window(request.sent_at, observed_at) {
                    Some(RequestBindingFailure::Expired)
                } else {
                    None
                };
                failure.map_or(RequestBindingState::ReadExact, RequestBindingState::Invalid)
            }
        };
        Some(Self { token, state })
    }

    pub(crate) fn recheck_routed(
        &mut self,
        packet: &OutboundPacket,
        peers: &Arc<PeerManager>,
        observed_at: Instant,
    ) {
        if self.state != RequestBindingState::ReadExact {
            return;
        }
        if let Some(echo) = self.token.echo() {
            self.state = if echo.exact_route(peers, packet, observed_at) {
                RequestBindingState::RoutedExact
            } else {
                RequestBindingState::Invalid(RequestBindingFailure::RouteIdentity)
            };
            return;
        }
        let failure = match self.token.request() {
            None => Some(RequestBindingFailure::Retired),
            Some(request) => {
                if !request.belongs_to(peers) {
                    Some(RequestBindingFailure::ForeignOwner)
                } else if request.peer_id != packet.peer_id || request.target_vip() != packet.dst_ip
                {
                    Some(RequestBindingFailure::RouteIdentity)
                } else if request.original_packet() != packet.packet {
                    Some(RequestBindingFailure::RouteBytes)
                } else if !in_original_window(request.sent_at, observed_at) {
                    Some(RequestBindingFailure::Expired)
                } else {
                    None
                }
            }
        };
        self.state = failure.map_or(
            RequestBindingState::RoutedExact,
            RequestBindingState::Invalid,
        );
    }

    #[allow(dead_code)] // Immutable source accessor; no current-owner verdict.
    pub(crate) fn token(&self) -> &RequestSendToken {
        &self.token
    }

    pub(crate) fn state(&self) -> RequestBindingState {
        self.state
    }

    /// The final receipt/credit transaction must still check current owners,
    /// original A, actual B, ingress, physical completion and once state.
    #[allow(dead_code)] // Future transaction rechecks the same canonical owner.
    pub(crate) fn eligibility_at(&self, observed_at: Instant) -> RequestInputEligibility {
        if let RequestBindingState::Invalid(reason) = self.state {
            return RequestInputEligibility::Invalid(reason);
        }
        let Some(request) = self.token.request() else {
            return RequestInputEligibility::Retired;
        };
        if !in_original_window(request.sent_at, observed_at) {
            RequestInputEligibility::Expired
        } else if !request.injection_accepted() {
            RequestInputEligibility::PendingInjection
        } else if self.state != RequestBindingState::RoutedExact {
            RequestInputEligibility::Invalid(RequestBindingFailure::RouteIdentity)
        } else {
            RequestInputEligibility::AcceptedInput
        }
    }
}

pub(crate) fn in_original_window(created_at: Instant, observed_at: Instant) -> bool {
    observed_at
        .checked_duration_since(created_at)
        .is_some_and(|age| age <= crate::OVERLAY_NONCE_TTL)
}

fn original_identity_matches(
    request: &crate::overlay_requests::CanonicalOverlayRequest,
    packet: &[u8],
) -> bool {
    let Ok(ip) = IpPacket::new(packet) else {
        return false;
    };
    if packet.first().is_none_or(|first| first >> 4 != 4)
        || ip.protocol() != Protocol::Udp
        || ip.total_len() != packet.len()
        || ip.src_addr_string() != request.local_vip()
        || ip.dst_addr_string() != request.target_vip()
    {
        return false;
    }
    let udp_start = usize::from(packet[0] & 0x0f) * 4;
    let Some(udp) = packet.get(udp_start..) else {
        return false;
    };
    if udp.len() < 8 || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len() {
        return false;
    }
    let payload = &udp[8..];
    payload.len() >= 23
        && &payload[..6] == crate::OVERLAY_PAYLOAD_MAGIC
        && payload[6] == crate::OVERLAY_DIRECTION_REQUEST
        && payload[7..15] == request.nonce.to_be_bytes()
        && payload[15..19] == request.seq.to_be_bytes()
        && payload[19..23] == crate::crc32_business_payload(&payload[..19]).to_be_bytes()
}

/// Shared-core envelope layout exists for legacy packets too. Only a genuine
/// sealed input carries a Weak binding; no strong request owner is retained.
#[derive(Clone)]
pub(crate) struct RawRequestDelivery {
    raw: OutboundPacket,
    binding: Option<RequestBinding>,
}

impl std::fmt::Debug for RawRequestDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawRequestDelivery")
            .field("raw", &self.raw)
            .field("binding", &self.binding.as_ref().map(RequestBinding::state))
            .finish()
    }
}

impl From<OutboundPacket> for RawRequestDelivery {
    fn from(raw: OutboundPacket) -> Self {
        Self { raw, binding: None }
    }
}

impl RawRequestDelivery {
    pub(crate) fn routed(raw: OutboundPacket, binding: Option<RequestBinding>) -> Self {
        Self { raw, binding }
    }

    #[allow(dead_code)] // Historical carriage accessor, no send/credit authority.
    pub(crate) fn binding(&self) -> Option<&RequestBinding> {
        self.binding.as_ref()
    }

    pub(crate) fn original_echo(&self) -> Option<&Arc<crate::overlay_requests::OriginalEchoInput>> {
        self.binding
            .as_ref()
            .and_then(|binding| binding.token.echo())
    }
}

impl Deref for RawRequestDelivery {
    type Target = OutboundPacket;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl DerefMut for RawRequestDelivery {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.raw
    }
}

/// Lexical ciphertext owner with the same A and actual successful-encryption B.
/// Dropping/retrying it drops B; no method strips a tracked ciphertext into a
/// legacy packet. Source B never supplies network-G or physical success.
pub(crate) struct EncryptedRequestDelivery {
    packet: EncryptedPeerPacket,
    binding: Option<RequestBinding>,
    source: Option<OriginalEncryptionSource>,
    echo_emit: Option<std::sync::Weak<tokio::sync::OwnedMutexGuard<()>>>,
}

impl EncryptedRequestDelivery {
    pub(crate) fn bind_original_echo_emit(
        &mut self,
        guard: &Arc<tokio::sync::OwnedMutexGuard<()>>,
    ) {
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| binding.token.echo().is_some())
        {
            self.echo_emit = Some(Arc::downgrade(guard));
        }
    }

    pub(crate) fn original_echo_prewrite(
        &self,
    ) -> Option<Arc<crate::overlay_requests::OriginalEchoPrewrite>> {
        let echo = self.binding.as_ref()?.token.echo()?;
        echo.prewrite(
            self.source.as_ref()?,
            self.echo_emit.as_ref()?.clone(),
            &self.packet,
        )
    }

    pub(crate) fn has_original_echo(&self) -> bool {
        self.binding
            .as_ref()
            .is_some_and(|binding| binding.token.echo().is_some())
    }
    #[allow(dead_code)] // Historical carriage accessor, no send/credit authority.
    pub(crate) fn binding(&self) -> Option<&RequestBinding> {
        self.binding.as_ref()
    }

    #[allow(dead_code)] // Actual B is immutable; final current ownership is separate.
    pub(crate) fn source(&self) -> Option<&OriginalEncryptionSource> {
        self.source.as_ref()
    }
}

impl Deref for EncryptedRequestDelivery {
    type Target = EncryptedPeerPacket;
    fn deref(&self) -> &Self::Target {
        &self.packet
    }
}
