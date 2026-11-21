use super::*;
use std::sync::Arc;

#[cfg(test)]
mod tests;

impl CaptureOwner {
    /// Called with the very decrypt result before later lifecycle awaits.
    /// A recorder contention cannot strip a successfully constructed carrier.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture_authenticated(
        &self,
        raw_ip: &[u8],
        authenticated_peer: &str,
        physical: Option<&PhysicalIngressContext>,
        wg_owner: WgEvidenceOwnerId,
        session_instance: Option<u64>,
        auth_prev_session: bool,
        wire: Option<WireTuple>,
        authenticated_at: Instant,
    ) -> Option<Arc<AuthenticatedIngressContext>> {
        // A contended/expired lookup cannot establish this capture's scope.
        // Delivery still proceeds; the lookup records its typed coverage gap.
        let registered = self.lookup_registered(raw_ip, authenticated_peer).ok()?;
        let (Some(physical), Some(session_instance), Some(wire)) =
            (physical, session_instance.and_then(NonZeroU64::new), wire)
        else {
            self.note_gap(EvidenceGap::IdentityMissing);
            return None;
        };
        let Some(context) = AuthenticatedIngressContext::new(
            registered,
            *physical,
            wg_owner,
            session_instance,
            auth_prev_session,
            wire,
            authenticated_at,
        ) else {
            self.note_gap(EvidenceGap::IdentityMissing);
            return None;
        };
        // This result is observation coverage only, never a delivery gate.
        self.try_record(StageReceipt::AuthenticatedReceive(context));
        Some(Arc::new(context))
    }

    /// Receives the exact normalized bytes passed to the completed write,
    /// rather than trusting a caller-supplied flow/length description.
    pub(crate) fn capture_tun_full(
        &self,
        authenticated: &AuthenticatedIngressContext,
        target: TunEvidenceIdentity,
        normalized_packet: &[u8],
        written: usize,
        allowed_normalized_source: Option<Ipv4Addr>,
        completed_at: Instant,
    ) -> RecordDisposition {
        let parsed = match parse_os_udp(normalized_packet) {
            Ok(parsed) => parsed,
            Err(_) => return self.note_gap(EvidenceGap::Malformed),
        };
        let registration = authenticated.registered().registration();
        let source_matches = parsed.flow.src_v4 == registration.flow.src_v4
            || allowed_normalized_source == Some(parsed.flow.src_v4);
        if parsed.key != registration.key
            || parsed.payload_bytes != registration.expected_payload_bytes
            || parsed.flow.src_port != registration.flow.src_port
            || parsed.flow.dst_port != registration.flow.dst_port
            || parsed.flow.dst_v4 != registration.flow.dst_v4
            || !source_matches
        {
            return self.note_gap(EvidenceGap::FlowMismatch);
        }
        let (Ok(normalized_len), Ok(written)) = (
            u32::try_from(normalized_packet.len()),
            u32::try_from(written),
        ) else {
            return self.note_gap(EvidenceGap::IdentityMissing);
        };
        let Some(receipt) = TunFullReceipt::new(
            *authenticated,
            parsed.flow,
            normalized_len,
            written,
            target,
            completed_at,
            // No combined nonblocking current-path/session transaction was
            // taken here. Historical full-write remains true independently.
            CurrentFence::Unknown,
        ) else {
            return self.note_gap(EvidenceGap::IdentityMissing);
        };
        self.try_record(StageReceipt::TunWriteFull(receipt))
    }
}
