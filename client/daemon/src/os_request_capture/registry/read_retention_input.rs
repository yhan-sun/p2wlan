//! Historical input retention reads the same canonical invalidation cell.
//! Its one original registry try remains observable; final eligibility and
//! native current-owner/once transactions keep their strict entry points.
use super::*;

#[cfg(any(target_os = "linux", all(unix, test)))]
struct PreparedInput(Arc<native::source_index::FlowSources>);

#[cfg(any(target_os = "linux", all(unix, test)))]
impl PreparedInput {
    fn capture(
        scope: &CaptureSession,
        flow: usize,
        plan: &Arc<RegisteredFlowPlan>,
    ) -> Option<Self> {
        let source = scope.sources.flows.get(flow)?;
        (Arc::ptr_eq(&source.plan, plan) && source.requests.len() == plan.requests.len())
            .then(|| Self(source.clone()))
    }

    fn scope_rejection(scope: &CaptureSession, at: Instant) -> Option<FullRetentionLossReason> {
        if !scope.is_live(at) {
            Some(FullRetentionLossReason::InputScopeNotLive)
        } else if !scope.read_complete.load(Ordering::Acquire) {
            Some(FullRetentionLossReason::InputReadObservationIncomplete)
        } else {
            None
        }
    }

    fn after_original(
        &self,
        original: Option<FullRetentionLossReason>,
    ) -> Option<FullRetentionLossReason> {
        if original == Some(FullRetentionLossReason::InputRegistryContended) {
            self.0
                .invalid
                .load(Ordering::Acquire)
                .then_some(FullRetentionLossReason::InputFlowInvalid)
        } else {
            original
        }
    }
}

impl KernelReadBinding {
    /// Only metadata for an already sealed real read. No read, Full, physical
    /// completion, current-owner lease or native credit can be minted here.
    pub(crate) fn read_retention_input_rejection(
        &self,
        at: Instant,
    ) -> Option<FullRetentionLossReason> {
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        {
            self.original_input_rejection(at)
        }
        #[cfg(any(target_os = "linux", all(unix, test)))]
        {
            // Freeze the exact existing registration handle BEFORE the one
            // original try, never acquire a replacement after a refusal.
            let prepared = self
                .scope
                .upgrade()
                .and_then(|scope| PreparedInput::capture(&scope, self.flow, &self.plan));
            let original = self.original_input_rejection(at);
            if original != Some(FullRetentionLossReason::InputRegistryContended) {
                return original;
            }
            let Some(prepared) = prepared else {
                return original;
            };
            let Some(scope) = self.scope.upgrade() else {
                return Some(FullRetentionLossReason::InputScopeUnavailable);
            };
            if let Some(reason) = PreparedInput::scope_rejection(&scope, at) {
                return Some(reason);
            }
            if !self.read.is_current() {
                return Some(FullRetentionLossReason::InputDeviceRetired);
            }
            if self.read.at() > at {
                return Some(FullRetentionLossReason::InputClockBeforeRead);
            }
            // This is the sole FlowState.invalid AtomicBool, not a cached
            // verdict. Invalidation observed during the actual try still wins.
            prepared.after_original(original)
        }
    }
}

#[cfg(all(unix, test))]
mod tests;
