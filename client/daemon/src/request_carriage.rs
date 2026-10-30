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
mod queue_observation;
mod residency_metadata;
#[cfg(test)]
mod residency_overhead_tests;
use crate::dataplane_resources::{ResidencyStage, ResourceCapture};
pub(crate) use channel::{RawOutboundReceiver, RawOutboundSink};
pub(crate) use crypto::RequestEncryptionAttempt;
use residency_metadata::DeliveryMetadata;
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
    OriginalKernelSource,
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
    /// A real registered system read only; never native ACK/send authority.
    KernelReadOnly,
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
    // Immutable first refusal only. Clones carry the same negative metadata;
    // route/encryption never rerun a failed check to refill this diagnostic.
    kernel_input_rejection: Option<crate::os_request_capture::FullRetentionLossReason>,
}

impl RequestBinding {
    pub(crate) fn from_read_context(
        context: Option<PacketReadContext>,
        packet: &[u8],
        peers: &Arc<PeerManager>,
        observed_at: Instant,
    ) -> Option<Self> {
        let token = RequestSendToken::from_read_context(context?)?;
        if let Some(kernel) = token.kernel() {
            let rejected = kernel.input_rejection(peers, packet, observed_at);
            let state = if rejected.is_none() {
                RequestBindingState::ReadExact
            } else {
                RequestBindingState::Invalid(RequestBindingFailure::OriginalKernelSource)
            };
            return Some(Self {
                token,
                state,
                kernel_input_rejection: rejected,
            });
        }
        if let Some(echo) = token.echo() {
            let state = if echo.exact_input(peers, packet, observed_at) {
                RequestBindingState::ReadExact
            } else {
                RequestBindingState::Invalid(RequestBindingFailure::OriginalBytes)
            };
            return Some(Self {
                token,
                state,
                kernel_input_rejection: None,
            });
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
        Some(Self {
            token,
            state,
            kernel_input_rejection: None,
        })
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
        if let Some(kernel) = self.token.kernel() {
            let rejected = kernel.route_rejection(peers, packet, observed_at);
            self.state = if rejected.is_none() {
                RequestBindingState::RoutedExact
            } else {
                RequestBindingState::Invalid(RequestBindingFailure::OriginalKernelSource)
            };
            self.kernel_input_rejection = rejected;
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

    pub(crate) fn original_kernel_rejection(
        &self,
    ) -> Option<crate::os_request_capture::FullRetentionLossReason> {
        self.kernel_input_rejection
    }

    /// The final receipt/credit transaction must still check current owners,
    /// original A, actual B, ingress, physical completion and once state.
    #[allow(dead_code)] // Future transaction rechecks the same canonical owner.
    pub(crate) fn eligibility_at(&self, observed_at: Instant) -> RequestInputEligibility {
        if let RequestBindingState::Invalid(reason) = self.state {
            return RequestInputEligibility::Invalid(reason);
        }
        if let Some(kernel) = self.token.kernel() {
            return if kernel.is_current_at(observed_at) {
                RequestInputEligibility::KernelReadOnly
            } else {
                RequestInputEligibility::Retired
            };
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
pub(crate) struct RawRequestDelivery {
    raw: OutboundPacket,
    metadata: DeliveryMetadata,
}

impl Clone for RawRequestDelivery {
    fn clone(&self) -> Self {
        let raw = self.raw.clone();
        let metadata = self.metadata.clone_for(&raw.packet);
        Self { raw, metadata }
    }
}

impl std::fmt::Debug for RawRequestDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawRequestDelivery")
            .field("raw", &self.raw)
            .field("binding", &self.binding().map(RequestBinding::state))
            .finish()
    }
}

impl From<OutboundPacket> for RawRequestDelivery {
    fn from(raw: OutboundPacket) -> Self {
        Self {
            raw,
            metadata: DeliveryMetadata::Empty,
        }
    }
}

impl RawRequestDelivery {
    pub(crate) fn routed(raw: OutboundPacket, binding: Option<RequestBinding>) -> Self {
        Self {
            raw,
            metadata: DeliveryMetadata::from_parts(binding, None),
        }
    }

    #[allow(dead_code)] // Historical carriage accessor, no send/credit authority.
    pub(crate) fn binding(&self) -> Option<&RequestBinding> {
        self.metadata.binding()
    }

    pub(crate) fn original_echo(&self) -> Option<&Arc<crate::overlay_requests::OriginalEchoInput>> {
        self.binding().and_then(|binding| binding.token.echo())
    }

    pub(crate) fn observe_resources(
        &mut self,
        capture: Option<&Arc<ResourceCapture>>,
        stage: ResidencyStage,
    ) {
        if let Some(capture) = capture {
            self.metadata.observe(capture, stage, &self.raw.packet);
        } else {
            self.metadata.relocate(stage, &self.raw.packet);
        }
    }

    pub(crate) fn relocate_resources(&mut self, stage: ResidencyStage) {
        self.metadata.relocate(stage, &self.raw.packet);
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
    metadata: DeliveryMetadata,
    source: Option<OriginalEncryptionSource>,
    echo_emit: Option<std::sync::Weak<crate::transport::OwnedEmitGuard>>,
}

impl EncryptedRequestDelivery {
    pub(crate) fn bind_original_echo_emit(
        &mut self,
        guard: &Arc<crate::transport::OwnedEmitGuard>,
    ) {
        if self
            .binding()
            .is_some_and(|binding| binding.token.echo().is_some())
        {
            self.echo_emit = Some(Arc::downgrade(guard));
        }
    }

    pub(crate) fn original_echo_prewrite(
        &self,
    ) -> Option<Arc<crate::overlay_requests::OriginalEchoPrewrite>> {
        let echo = self.binding()?.token.echo()?;
        echo.prewrite(
            self.source.as_ref()?,
            self.echo_emit.as_ref()?.clone(),
            &self.packet,
        )
    }

    pub(crate) fn has_original_echo(&self) -> bool {
        self.binding()
            .is_some_and(|binding| binding.token.echo().is_some())
    }
    #[allow(dead_code)] // Historical carriage accessor, no send/credit authority.
    pub(crate) fn binding(&self) -> Option<&RequestBinding> {
        self.metadata.binding()
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
