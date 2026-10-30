//! Immutable registration handles into the sole published source cells.
//! An input-registry version fences each frozen batch before any native try.
use super::*;
use crate::os_request_capture::registry::published::{First, Published};

pub(in crate::os_request_capture::registry) struct RequestSources {
    pub(super) credit: completion::NativeFrameSlot,
    pub(in crate::os_request_capture::registry) window: First<write_window::WriteWindow>,
    pub(super) peer: First<Arc<read_peer::FirstReadPeer>>,
    pub(super) response: First<Arc<ingress::ResponseCapture>>,
}
pub(in crate::os_request_capture::registry) struct FlowSources {
    pub(in crate::os_request_capture::registry) producer_scope: [u8; 16],
    pub(in crate::os_request_capture::registry) plan: Arc<RegisteredFlowPlan>,
    pub(in crate::os_request_capture::registry) invalid: Arc<AtomicBool>,
    pub(super) inbound_invalid: Arc<AtomicBool>,
    pub(in crate::os_request_capture::registry) requests: Vec<RequestSources>,
}
impl FlowSources {
    pub(in crate::os_request_capture::registry) fn capture(
        flow: &FlowState,
    ) -> Result<Arc<Self>, CaptureFailure> {
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(flow.requests.len())
            .map_err(|_| CaptureFailure::Capacity)?;
        requests.extend(flow.requests.iter().map(|row| RequestSources {
            credit: row.native_credit.shared(),
            window: row.original_write_window.clone(),
            peer: row.first_peer.clone(),
            response: row.first_response.clone(),
        }));
        Ok(Arc::new(Self {
            producer_scope: flow.producer_scope,
            plan: flow.plan.clone(),
            invalid: flow.invalid.clone(),
            inbound_invalid: flow.inbound.invalid.clone(),
            requests,
        }))
    }
}
pub(in crate::os_request_capture::registry) struct SourceIndex {
    pub(in crate::os_request_capture::registry) flows: Published<Arc<FlowSources>>,
    pub(in crate::os_request_capture::registry) reads: Published<Arc<KernelReadBinding>>,
    pub(super) writes: Published<Arc<KernelIngressBinding>>,
    pub(super) device: First<Weak<DeviceLease>>,
    pub(super) owners: First<Arc<owners::OriginalKernelOwners>>,
}
impl SourceIndex {
    pub(in crate::os_request_capture::registry) fn new(
        flows: Published<Arc<FlowSources>>,
        reads: Published<Arc<KernelReadBinding>>,
        writes: Published<Arc<KernelIngressBinding>>,
        device: First<Weak<DeviceLease>>,
        owners: First<Arc<owners::OriginalKernelOwners>>,
    ) -> Self {
        Self {
            flows,
            reads,
            writes,
            device,
            owners,
        }
    }
}
