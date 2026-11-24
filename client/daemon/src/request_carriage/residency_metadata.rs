//! Optional observer storage shares the existing metadata enum. The default
//! envelope keeps its original inline binding and never allocates an observer.
use super::RequestBinding;
use crate::dataplane_resources::{ResidencyLease, ResidencyStage, ResourceCapture};
use std::sync::Arc;

pub(super) enum DeliveryMetadata {
    Empty,
    Tun,
    Pooled(p2pnet_crypto::packet_buf::PacketBuf),
    Tuning(tokio::time::Instant),
    Bound(RequestBinding),
    Observed(Box<ObservedDelivery>),
}

pub(super) struct ObservedDelivery {
    binding: Option<RequestBinding>,
    lease: ResidencyLease,
}

#[allow(clippy::ptr_arg)] // Observes actual Vec capacity, not only its slice.
impl DeliveryMetadata {
    pub(super) fn is_observed(&self) -> bool {
        matches!(self, Self::Observed(_))
    }

    pub(super) fn from_parts(
        binding: Option<RequestBinding>,
        lease: Option<ResidencyLease>,
    ) -> Self {
        match lease {
            Some(lease) => Self::Observed(Box::new(ObservedDelivery { binding, lease })),
            None => binding.map_or(Self::Empty, Self::Bound),
        }
    }

    pub(super) fn into_parts(self) -> (Option<RequestBinding>, Option<ResidencyLease>) {
        match self {
            Self::Empty | Self::Tun | Self::Pooled(_) | Self::Tuning(_) => (None, None),
            Self::Bound(binding) => (Some(binding), None),
            Self::Observed(observed) => {
                let ObservedDelivery { binding, lease } = *observed;
                (binding, Some(lease))
            }
        }
    }

    pub(super) fn binding(&self) -> Option<&RequestBinding> {
        match self {
            Self::Empty | Self::Tun | Self::Pooled(_) | Self::Tuning(_) => None,
            Self::Bound(binding) => Some(binding),
            Self::Observed(observed) => observed.binding.as_ref(),
        }
    }

    pub(super) fn clone_for(&self, bytes: &Vec<u8>) -> Self {
        match self {
            Self::Tun | Self::Pooled(_) => return Self::Tun,
            Self::Tuning(deadline) => return Self::Tuning(*deadline),
            _ => {}
        }
        let binding = self.binding().cloned();
        let lease = match self {
            Self::Observed(observed) => observed.lease.clone_for(bytes),
            _ => None,
        };
        Self::from_parts(binding, lease)
    }

    pub(super) fn observe(
        &mut self,
        capture: &Arc<ResourceCapture>,
        stage: ResidencyStage,
        bytes: &Vec<u8>,
    ) {
        if let Self::Observed(observed) = self {
            if Arc::ptr_eq(observed.lease.capture(), capture) {
                observed.lease.relocate(stage, bytes);
            } else {
                // Different capture scopes never silently join. Networking
                // still follows its existing owner and original packet.
                capture.unobserved_residency_exit();
                observed.lease.unobserved_exit();
            }
            return;
        }
        if !matches!(
            stage,
            ResidencyStage::ChannelReserve | ResidencyStage::RawChannel
        ) {
            capture.unobserved_residency_exit();
        }
        if let Some(lease) = ResidencyLease::observe(capture, stage, bytes) {
            let (binding, _) = std::mem::replace(self, Self::Empty).into_parts();
            *self = Self::from_parts(binding, Some(lease));
        }
    }

    pub(super) fn relocate(&mut self, stage: ResidencyStage, bytes: &Vec<u8>) {
        if let Self::Observed(observed) = self {
            observed.lease.relocate(stage, bytes);
        }
    }

    pub(super) fn observe_crypto_input(
        &mut self,
        capture: Option<&Arc<ResourceCapture>>,
        bytes: &Vec<u8>,
    ) {
        if let Self::Observed(observed) = self {
            // The input may still be a preparation or retry owner. Entering
            // crypto does not create another buffer or change that ownership.
            observed.lease.refresh(bytes);
            if capture.is_none_or(|capture| !Arc::ptr_eq(observed.lease.capture(), capture)) {
                observed.lease.unobserved_exit();
                if let Some(capture) = capture {
                    capture.unobserved_residency_exit();
                }
            }
        } else if let Some(capture) = capture {
            self.observe(capture, ResidencyStage::DetachedRaw, bytes);
        }
    }

    pub(super) fn unobserved_exit(&self) {
        if let Self::Observed(observed) = self {
            observed.lease.unobserved_exit();
        }
    }
}
