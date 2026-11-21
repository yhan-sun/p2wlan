// Called only by the two production crypto-success arms while their original
// network epoch is still held. The passed G is actual, never expected/current
// refill. Crate visibility is trusted call-site confinement, not public mint.
use super::*;
use crate::overlay_requests::PreparedPhysicalPublication;
impl EncryptedRequestDelivery {
    pub(crate) fn prepare_physical_publication(
        &self,
        peers: &PeerManager,
        transport: &crate::transport::WireGuardTransport,
        actual_encryption_generation: u64,
    ) -> Option<PreparedPhysicalPublication> {
        PreparedPhysicalPublication::capture_encryption_epoch(
            self.binding.as_ref()?,
            self.source.as_ref()?,
            peers,
            transport,
            actual_encryption_generation,
            &self.packet,
        )
        .ok()
        .flatten()
    }
}
