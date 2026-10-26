//! First-read peer expectations. Neither retries nor encryption can refill a
//! missing first capture. No connection state or final once authority lives here.
use super::*;
use crate::overlay_requests::{OverlayCreditOutcome, OverlayCreditUnknown};
use crate::peer::OriginalKernelReadPeer;
use crate::transport::OriginalEncryptionSource;

pub(super) struct FirstReadPeer {
    original: Result<OriginalKernelReadPeer, OverlayCreditOutcome>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct ReadPeerSnapshot {
    known: bool,
    network_generation: Option<u64>,
    peer_lifecycle: Option<u64>,
    #[serde(serialize_with = "super::snapshot_hex::serialize_optional_debug")]
    capture_failure: Option<OverlayCreditOutcome>,
}

impl FirstReadPeer {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn original(&self) -> Result<&OriginalKernelReadPeer, OverlayCreditOutcome> {
        self.original.as_ref().map_err(|reason| *reason)
    }

    pub(super) fn is_known(&self) -> bool {
        self.original.is_ok()
    }

    pub(super) fn matches_original_ingress(
        &self,
        source: &crate::transport::OriginalOverlayIngressSource,
        before: Instant,
    ) -> bool {
        self.original
            .as_ref()
            .is_ok_and(|peer| peer.matches_original_ingress(source, before))
    }
    fn capture(
        scope: &CaptureSession,
        plan: &RegisteredFlowPlan,
        #[cfg(any(target_os = "linux", all(unix, test)))] context: Option<
            crate::peer::EpochTryContext,
        >,
    ) -> Self {
        let original = scope
            .peers
            .upgrade()
            .ok_or(OverlayCreditOutcome::Unknown(
                OverlayCreditUnknown::OriginalAuthorization,
            ))
            .and_then(|peers| {
                peers.try_capture_original_kernel_read_peer(
                    &plan.peer,
                    plan.flow.dst_v4,
                    #[cfg(any(target_os = "linux", all(unix, test)))]
                    context,
                )
            });
        if original.is_err() {
            scope.gap();
        }
        Self { original }
    }

    #[cfg(any(test, not(target_os = "linux")))]
    fn current_rejection(
        &self,
        peers: &PeerManager,
        at: Instant,
    ) -> Option<FullRetentionLossReason> {
        self.original
            .as_ref()
            .map_err(|reason| *reason)
            .and_then(|original| original.try_identity_at(peers, at))
            .err()
            .map(FullRetentionLossReason::read_peer)
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    fn current_rejection_observed(
        &self,
        peers: &PeerManager,
        at: Instant,
        context: Option<crate::peer::EpochTryContext>,
    ) -> Option<FullRetentionLossReason> {
        self.original
            .as_ref()
            .map_err(|reason| *reason)
            .and_then(|original| {
                original.try_read_retention_identity_at_observed(peers, at, context)
            })
            .err()
            .map(FullRetentionLossReason::read_peer)
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> ReadPeerSnapshot {
        ReadPeerSnapshot {
            known: self.original.is_ok(),
            network_generation: self.original.as_ref().ok().map(|peer| peer.generation()),
            peer_lifecycle: self
                .original
                .as_ref()
                .ok()
                .map(|peer| peer.lifecycle().value()),
            // Diagnostic only. This text is never parsed to drive control flow.
            capture_failure: self.original.as_ref().err().copied(),
        }
    }
}

impl CaptureSession {
    pub(super) fn first_read_peers(
        &self,
        flow: &mut FlowState,
        slots: &[usize],
        #[cfg(any(target_os = "linux", all(unix, test)))] original: Option<&KernelRead>,
    ) -> Vec<Arc<FirstReadPeer>> {
        // Capture once for previously unobserved slots of this original read.
        // Cached positive and negative expectations never perform another try.
        let plan = flow.plan.clone();
        let mut observed = None;
        slots
            .iter()
            .map(|slot| {
                flow.requests[*slot]
                    .first_peer
                    .get_or_insert_with(|| {
                        observed
                            .get_or_insert_with(|| {
                                #[cfg(any(target_os = "linux", all(unix, test)))]
                                let context = original.and_then(|read| {
                                    self.read_peer_epoch_context(&plan, *slot, read.ordinal())
                                });
                                Arc::new(FirstReadPeer::capture(
                                    self,
                                    &plan,
                                    #[cfg(any(target_os = "linux", all(unix, test)))]
                                    context,
                                ))
                            })
                            .clone()
                    })
                    .clone()
            })
            .collect()
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    fn read_peer_epoch_context(
        &self,
        plan: &RegisteredFlowPlan,
        slot: usize,
        read_ordinal: u64,
    ) -> Option<crate::peer::EpochTryContext> {
        let key = plan.requests.get(slot)?;
        Some(crate::peer::EpochTryContext {
            capture_owner: self.owner,
            capture_id: self.capture_id,
            run: key.run,
            round: key.round,
            request_nonce: key.request_nonce,
            sequence: key.sequence,
            protocol: match plan.protocol {
                Protocol::Udp => "udp",
                Protocol::Tcp => "tcp",
            },
            kind: match key.kind {
                crate::business_evidence::RequestKind::Request => "request",
                crate::business_evidence::RequestKind::Response => "response",
            },
            first_read_ordinal: 0,
            read_peer_input_ordinal: Some(read_ordinal),
        })
    }
}

impl KernelReadBinding {
    pub(super) fn original_peer_identity_rejection(
        &self,
        scope: &CaptureSession,
        at: Instant,
    ) -> Option<FullRetentionLossReason> {
        let Some(peers) = scope.peers.upgrade() else {
            return Some(FullRetentionLossReason::ReadPeerOwnerUnavailable);
        };
        if self.original_peers.is_empty() || self.original_peers.len() != self.slots.len() {
            return Some(FullRetentionLossReason::ReadPeerBindingsInvalid);
        }
        self.original_peers
            .iter()
            .enumerate()
            .find_map(|(index, original)| {
                #[cfg(any(target_os = "linux", all(unix, test)))]
                {
                    original.current_rejection_observed(
                        &peers,
                        at,
                        self.peer_epoch_context(scope, index),
                    )
                }
                #[cfg(not(any(target_os = "linux", all(unix, test))))]
                {
                    let _ = index;
                    original.current_rejection(&peers, at)
                }
            })
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    fn peer_epoch_context(
        &self,
        scope: &CaptureSession,
        index: usize,
    ) -> Option<crate::peer::EpochTryContext> {
        if !std::ptr::eq(self.scope.as_ptr(), scope) {
            return None;
        }
        scope.read_peer_epoch_context(&self.plan, *self.slots.get(index)?, self.read.ordinal())
    }

    pub(crate) fn original_peer_matches_encryption(
        &self,
        owner: &Weak<PeerManager>,
        generation: u64,
        encryption: &OriginalEncryptionSource,
    ) -> bool {
        !self.original_peers.is_empty()
            && self.original_peers.len() == self.slots.len()
            && self.original_peers.iter().all(|original| {
                original.original.as_ref().is_ok_and(|peer| {
                    peer.matches_original_encryption(owner, generation, encryption)
                })
            })
    }
}

#[cfg(all(unix, test))]
mod tests;
