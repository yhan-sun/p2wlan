//! The two sealed input mints share the original physical-attempt producer.
//! This weak identity never substitutes registration labels for a system read.
use super::{CanonicalOverlayRequest, PhysicalSendPublication};
use crate::os_request_capture::{FullRetentionLossReason, KernelReadBinding};
use crate::peer::PeerManager;
use crate::request_carriage::{RequestBinding, RequestBindingState};
use std::sync::{Arc, Weak};
use std::time::Instant;

pub(super) enum OriginalPhysicalInput {
    Canonical(Weak<CanonicalOverlayRequest>),
    Kernel(Weak<KernelReadBinding>),
}

pub(super) enum OriginalPhysicalInputOwner {
    Canonical(Arc<CanonicalOverlayRequest>),
    Kernel(Arc<KernelReadBinding>),
}

impl OriginalPhysicalInput {
    pub(super) fn capture(
        binding: &RequestBinding,
        peers: &PeerManager,
        encrypted_at: Instant,
        peer_id: &str,
        rejected: &mut FullRetentionLossReason,
    ) -> Option<(Self, Weak<PeerManager>)> {
        if let Some(request) = binding.token().request() {
            let owner = request.original_peer_owner(peers)?;
            return Some((Self::Canonical(Arc::downgrade(&request)), owner));
        }
        let kernel = binding.token().kernel()?;
        let state = binding.state();
        if state != RequestBindingState::RoutedExact {
            *rejected = binding.original_kernel_rejection().unwrap_or(match state {
                RequestBindingState::ReadExact => FullRetentionLossReason::InputBindingNotRouted,
                _ => FullRetentionLossReason::InputRouteMismatch,
            });
            return None;
        }
        if let Some(reason) = kernel.read_retention_input_rejection(encrypted_at) {
            *rejected = reason;
            return None;
        }
        if kernel.peer_id() != peer_id {
            *rejected = FullRetentionLossReason::InputPeerMismatch;
            return None;
        }
        let Some(owner) = kernel.original_peer_owner(peers) else {
            *rejected = FullRetentionLossReason::InputPeerOwnerUnavailable;
            return None;
        };
        Some((Self::Kernel(Arc::downgrade(kernel)), owner))
    }

    pub(super) fn upgrade(&self) -> Option<OriginalPhysicalInputOwner> {
        match self {
            Self::Canonical(request) => {
                request.upgrade().map(OriginalPhysicalInputOwner::Canonical)
            }
            Self::Kernel(read) => read.upgrade().map(OriginalPhysicalInputOwner::Kernel),
        }
    }

    pub(super) fn matches_canonical(&self, request: &CanonicalOverlayRequest) -> bool {
        matches!(self, Self::Canonical(original) if std::ptr::eq(original.as_ptr(), request))
    }

    pub(super) fn matches_kernel(&self, read: &KernelReadBinding) -> bool {
        matches!(self, Self::Kernel(original) if std::ptr::eq(original.as_ptr(), read))
    }
}

impl OriginalPhysicalInputOwner {
    pub(super) fn before_recorded(&self) {
        if let Self::Kernel(read) = self {
            read.observe_original_publication_clock();
        }
    }
    pub(super) fn publication(&self) -> &PhysicalSendPublication {
        match self {
            Self::Canonical(request) => &request.physical_publication,
            Self::Kernel(read) => read.physical_publication(),
        }
    }

    pub(super) fn recorded(&self, attempt_id: u64) {
        match self {
            Self::Canonical(request) => {
                tracing::debug!(target: "p2pnet_daemon::overlay_native_credit",
                    event = "overlay_original_publication_observed",
                    peer = %request.peer_id, nonce = request.nonce, seq = request.seq,
                    attempt_id,
                    publication_age_us = ?request.physical_publication.recorded_observed_at()
                        .and_then(|observed| observed.checked_duration_since(request.sent_at))
                        .map(|age| age.as_micros()),
                    "original Full publication observed; no ACK credit granted");
            }
            Self::Kernel(read) => read.retain_original_full(),
        }
    }
}
