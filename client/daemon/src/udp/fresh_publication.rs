use super::*;

impl UdpTransport {
    /// Wait for the metadata writer before taking the original authority
    /// gates. A retired publication cannot complete a delayed metadata write;
    /// no await separates the final identity check from the local commit.
    pub(super) async fn commit_fresh_mapping_for_publication(
        &self,
        peer_id: &str,
        mapping: crate::peer::LocalFreshMapping,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> bool {
        let Ok(writer) = timeout(
            Duration::from_millis(100),
            self.peers.lock_fresh_mapping_for_commit(),
        )
        .await
        else {
            return false;
        };
        let Ok(_epoch) = self.network_epoch_gate.try_lock() else {
            return false;
        };
        self.dplpmtud
            .try_with_business_publication_gate(|| {
                if cancellation.is_some_and(|owner| owner.is_cancelled())
                    || self.peers.current_network_generation_sync() != mapping.network_generation
                {
                    return false;
                }
                if let Some((owner, generation)) = self.probe_publication_identity() {
                    if owner == 0
                        || self.inbound_publication_owner() != owner
                        || generation != mapping.network_generation
                    {
                        return false;
                    }
                }
                writer.commit(peer_id, mapping)
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
#[path = "tests/fresh_publication.rs"]
mod tests;
