//! Observe existing times on the packet owner, without creating send authority.
use super::*;

impl RawRequestDelivery {
    pub(crate) fn observe_initial_queue_intervals(&self) {
        if let Some(kernel) = self.binding().and_then(|binding| binding.token.kernel()) {
            kernel.observe_initial_queue_intervals(self.raw.trace.as_ref());
        }
    }
}
