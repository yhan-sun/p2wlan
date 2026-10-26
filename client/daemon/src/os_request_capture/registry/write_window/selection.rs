//! Recheck producer uniqueness, shape and the exact original registration Arc.
//! Expected metadata cannot authorize a window outside the real owner.
use super::*;

#[cfg(all(unix, test))]
pub(super) struct RegistrationPrefix {
    revision: u64,
    flows: usize,
}

#[cfg(all(unix, test))]
impl RegistrationPrefix {
    pub(super) fn capture(state: &RegistryState) -> Self {
        Self {
            revision: state.revision,
            flows: state.flows.len(),
        }
    }

    pub(super) fn current_index(
        &self,
        prepared: &OriginalWindowPlan,
        state: &RegistryState,
    ) -> Result<usize, CaptureFailure> {
        let (index, flow) = if self.revision == state.revision && self.flows == state.flows.len() {
            let flow = state
                .flows
                .get(prepared.flow)
                .ok_or(CaptureFailure::InvalidPlan)?;
            (prepared.flow, flow)
        } else {
            // Preserve the original unique-producer search after any append or
            // prefix mismatch. A revision is never used as native IO authority.
            let mut flows = state.flows.iter().enumerate().filter(|(_, flow)| {
                #[cfg(all(unix, test))]
                record_scan();
                flow.producer_scope == prepared.producer
            });
            let selected = flows.next().ok_or(CaptureFailure::InvalidPlan)?;
            if flows.next().is_some() {
                return Err(CaptureFailure::InvalidPlan);
            }
            selected
        };
        if flow.requests.len() != 8 || flow.plan.payload_bytes != 128 {
            return Err(CaptureFailure::InvalidPlan);
        }
        if !prepared.is_current(index, flow) {
            return Err(CaptureFailure::InvalidPlan);
        }
        Ok(index)
    }
}

// Expected published labels never authorize the selection. Recheck the whole
// original unique-producer condition under the actual registration owner.
#[cfg(all(unix, test))]
pub(super) fn current_original_index(
    prepared: &OriginalWindowPlan,
    state: &RegistryState,
) -> Result<usize, CaptureFailure> {
    let mut flows = state
        .flows
        .iter()
        .enumerate()
        .filter(|(_, flow)| flow.producer_scope == prepared.producer);
    let (index, flow) = flows.next().ok_or(CaptureFailure::InvalidPlan)?;
    if flows.next().is_some()
        || flow.requests.len() != 8
        || flow.plan.payload_bytes != 128
        || !prepared.is_current(index, flow)
    {
        return Err(CaptureFailure::InvalidPlan);
    }
    Ok(index)
}

#[cfg(all(unix, test))]
thread_local! {
    static SCANS: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(all(unix, test))]
fn record_scan() {
    SCANS.with(|scans| scans.set(scans.get().map(|n| n.saturating_add(1))));
}

#[cfg(all(unix, test))]
pub(super) fn begin_scans() {
    SCANS.with(|scans| assert!(scans.replace(Some(0)).is_none()));
}

#[cfg(all(unix, test))]
pub(super) fn finish_scans() -> usize {
    SCANS.with(|scans| scans.replace(None).unwrap())
}

// Registration appends and window installation share the window owner. The
// immutable cells and original plan Arc are the canonical published prefix;
// packet callbacks never acquire this metadata owner.
pub(super) fn current_published_source<'a>(
    prepared: &OriginalWindowPlan,
    sources: &'a native::source_index::SourceIndex,
) -> Result<&'a native::source_index::FlowSources, CaptureFailure> {
    let mut flows = sources
        .flows
        .iter()
        .enumerate()
        .filter(|(_, flow)| flow.producer_scope == prepared.producer);
    let (index, flow) = flows.next().ok_or(CaptureFailure::InvalidPlan)?;
    if flows.next().is_some()
        || index != prepared.flow
        || flow.requests.len() != 8
        || flow.plan.payload_bytes != 128
        || !Arc::ptr_eq(&prepared.plan, &flow.plan)
    {
        return Err(CaptureFailure::InvalidPlan);
    }
    Ok(flow.as_ref())
}
