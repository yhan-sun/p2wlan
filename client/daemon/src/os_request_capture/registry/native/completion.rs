//! One terminal metadata slot for each registered request. Reservation is
//! scheduling only: the unchanged PeerManager transaction alone consumes once.
use super::frozen_sources::{FrozenFlowSources, FrozenRequestSources};
use super::*;
use std::sync::atomic::AtomicU8;
use std::sync::OnceLock;

const OPEN: u8 = 0;
const CLAIMED: u8 = 1;
const CLAIMED_WITH_WAKE: u8 = 3;
const TERMINAL: u8 = 4;

struct SlotState {
    phase: AtomicU8,
    outcome: OnceLock<NativeFrameOutcome>,
}

pub(in crate::os_request_capture::registry) struct NativeFrameSlot(Arc<SlotState>);

impl NativeFrameSlot {
    pub(in crate::os_request_capture::registry) fn new() -> Self {
        Self(Arc::new(SlotState {
            phase: AtomicU8::new(OPEN),
            outcome: OnceLock::new(),
        }))
    }
    pub(in crate::os_request_capture::registry) fn as_ref(&self) -> Option<&NativeFrameOutcome> {
        self.0.outcome.get()
    }
    pub(in crate::os_request_capture::registry) fn is_some(&self) -> bool {
        self.as_ref().is_some()
    }
    #[cfg(all(unix, test))]
    pub(in crate::os_request_capture::registry) fn is_none(&self) -> bool {
        self.as_ref().is_none()
    }
    pub(in crate::os_request_capture::registry) fn shared(&self) -> Self {
        Self(self.0.clone())
    }

    fn claim(&self, scope: &Arc<CaptureSession>) -> Option<CompletionClaim> {
        match self
            .0
            .phase
            .compare_exchange(OPEN, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Some(CompletionClaim {
                state: self.0.clone(),
                scope: Arc::downgrade(scope),
                released: false,
            }),
            Err(CLAIMED) => {
                // If release won this race, request a wake after it. Otherwise
                // the sole in-flight owner observes the bit when it releases.
                if self.0.phase.compare_exchange(
                    CLAIMED,
                    CLAIMED_WITH_WAKE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) == Err(OPEN)
                {
                    scope.pending_full.request_window();
                }
                None
            }
            Err(_) => None,
        }
    }

    // Existing fixtures install negative metadata only, before any candidate.
    #[cfg(all(unix, test))]
    pub(in crate::os_request_capture::registry) fn get_or_insert_with(
        &mut self,
        make: impl FnOnce() -> NativeFrameOutcome,
    ) -> &NativeFrameOutcome {
        let result = self.0.outcome.get_or_init(make);
        self.0.phase.store(TERMINAL, Ordering::Release);
        result
    }
}

#[cfg(all(unix, test))]
impl From<Option<NativeFrameOutcome>> for NativeFrameSlot {
    fn from(value: Option<NativeFrameOutcome>) -> Self {
        let mut slot = Self::new();
        if let Some(value) = value {
            slot.get_or_insert_with(|| value);
        }
        slot
    }
}

struct CompletionClaim {
    state: Arc<SlotState>,
    scope: Weak<CaptureSession>,
    released: bool,
}

impl CompletionClaim {
    fn finish(mut self, result: NativeFrameOutcome) {
        // Only this reservation can reach the original native transaction.
        // Every refusal is terminal too; later metadata cannot enter it again.
        let duplicate = self.state.outcome.set(result).is_err();
        self.state.phase.store(TERMINAL, Ordering::Release);
        self.released = true;
        if let Some(scope) = self.scope.upgrade() {
            if duplicate {
                scope.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
            }
            scope.record_native_terminal_progress();
        }
    }
    fn wait_for_executor(mut self) {
        self.state.phase.store(OPEN, Ordering::Release);
        self.released = true;
        if let Some(scope) = self.scope.upgrade() {
            scope.pending_full.defer_window_until_unlock();
        }
    }
    fn not_ready(mut self) {
        let previous = self.state.phase.swap(OPEN, Ordering::AcqRel);
        self.released = true;
        if previous == CLAIMED_WITH_WAKE {
            if let Some(scope) = self.scope.upgrade() {
                scope.pending_full.request_window();
            }
        }
    }
}

impl Drop for CompletionClaim {
    fn drop(&mut self) {
        if !self.released {
            // Cancellation before a synchronous transaction enters may wake
            // the existing metadata actor. No terminal native check is retried.
            self.state.phase.store(OPEN, Ordering::Release);
            if let Some(scope) = self.scope.upgrade() {
                scope.pending_full.request_window();
            }
        }
    }
}

struct PreparedCompletion {
    source: FrozenRequestSources,
    claim: CompletionClaim,
}

#[must_use = "finish only after releasing the original input registry guard"]
pub(in crate::os_request_capture::registry) struct NativeCompletionBatch {
    flows: Vec<(usize, Arc<FrozenFlowSources>)>,
    requests: Vec<PreparedCompletion>,
    version: Option<(u64, u64, u64)>,
    unstable: bool,
}

impl NativeCompletionBatch {
    pub(in crate::os_request_capture::registry) fn new() -> Self {
        Self {
            flows: Vec::new(),
            requests: Vec::new(),
            version: None,
            unstable: false,
        }
    }
    fn prepare(&mut self, scope: &Arc<CaptureSession>, flow: usize, slot: usize) {
        if !self.begin(scope) {
            return;
        }
        let Some(original) = scope
            .sources
            .flows
            .get(flow)
            .and_then(|f| f.requests.get(slot))
        else {
            return;
        };
        let Some(claim) = original.credit.claim(scope) else {
            return;
        };
        let sources =
            if let Some((_, sources)) = self.flows.iter().find(|(index, _)| *index == flow) {
                sources.clone()
            } else {
                let Some(sources) = FrozenFlowSources::capture(&scope.sources, flow) else {
                    claim.finish(NativeFrameOutcome::failure(unknown()));
                    return;
                };
                if self.flows.try_reserve(1).is_err() {
                    claim.finish(NativeFrameOutcome::failure(unknown()));
                    return;
                }
                let sources = Arc::new(sources);
                self.flows.push((flow, sources.clone()));
                sources
            };
        if self.requests.try_reserve(1).is_err() {
            claim.finish(NativeFrameOutcome::failure(unknown()));
            return;
        }
        self.requests.push(PreparedCompletion {
            source: FrozenRequestSources::capture(original, flow, slot, sources),
            claim,
        });
    }
    pub(in crate::os_request_capture::registry) fn begin(
        &mut self,
        scope: &CaptureSession,
    ) -> bool {
        if self.unstable {
            return false;
        }
        match scope.try_source_metadata_versions() {
            Ok(version) if self.version.is_none_or(|old| old == version) => {
                self.version = Some(version);
                true
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                scope.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
                scope.pending_full.clear();
                self.unstable = true;
                false
            }
            _ => {
                self.unstable = true;
                false
            }
        }
    }
    pub(in crate::os_request_capture::registry) fn finish(mut self, scope: &Arc<CaptureSession>) {
        if !self.begin(scope) {
            for prepared in self.requests {
                prepared.claim.not_ready();
            }
            if matches!(
                scope.try_source_metadata_versions(),
                Err(std::sync::TryLockError::Poisoned(_))
            ) {
                scope.pending_full.clear();
                return;
            }
            scope.pending_full.defer_window_until_unlock();
            // Subscribe first, then check: an unlock that already happened
            // must not strand the one existing metadata actor's pending work.
            if scope.try_source_metadata_versions().is_ok() {
                scope.pending_full.request_window();
            }
            return;
        }
        if self.requests.is_empty() {
            return;
        }
        // Preserve the original serialization of native owner/once checks,
        // using a separate synchronous metadata gate after input unlock.
        let _guard = match scope.native_completion.try_enter(&scope.pending_full) {
            Ok(guard) => guard,
            Err(super::completion_gate::EnterError::Busy) => {
                for prepared in self.requests {
                    prepared.claim.wait_for_executor();
                }
                scope
                    .native_completion
                    .probe_released_after_defer(&scope.pending_full);
                return;
            }
            Err(super::completion_gate::EnterError::Poisoned) => {
                scope.original_full_retention_lost(FullRetentionLossReason::HistoryContended);
                for prepared in self.requests {
                    prepared
                        .claim
                        .finish(NativeFrameOutcome::failure(unknown()));
                }
                return;
            }
        };
        for prepared in self.requests {
            if let Some(result) = complete(scope, &prepared.source) {
                prepared.claim.finish(result);
            } else {
                prepared.claim.not_ready();
            }
        }
    }
}

impl CaptureSession {
    pub(in crate::os_request_capture::registry) fn prepare_original_frames(
        self: &Arc<Self>,
        flow: usize,
        slots: &[usize],
        batch: &mut NativeCompletionBatch,
    ) {
        for &slot in slots {
            batch.prepare(self, flow, slot);
        }
    }
}

fn complete(
    scope: &Arc<CaptureSession>,
    source: &FrozenRequestSources,
) -> Option<NativeFrameOutcome> {
    let candidate = match OriginalKernelExchange::capture(scope, source) {
        Ok(Some(candidate)) => candidate,
        Ok(None) => return None,
        Err(reason) => return Some(NativeFrameOutcome::failure(reason)),
    };
    let mut result = NativeFrameOutcome::failure(unknown());
    if result
        .read_ordinals
        .try_reserve(candidate.reads.len())
        .is_err()
        || result
            .write_ordinals
            .try_reserve(candidate.writes.len())
            .is_err()
        || result
            .skipped_read_attempts
            .try_reserve(candidate.skipped.len())
            .is_err()
    {
        return Some(result);
    }
    result
        .read_ordinals
        .extend(candidate.reads.iter().map(|read| read.read.ordinal()));
    result.skipped_read_attempts.extend(
        candidate
            .skipped
            .iter()
            .map(|(read, fence)| (read.read.ordinal(), fence.attempt_id())),
    );
    result.write_ordinals.extend(
        candidate
            .writes
            .iter()
            .filter_map(|source| source.original_write().map(|write| write.ordinal())),
    );
    if let (Some(peers), Some(owners)) = (
        scope.peers.upgrade(),
        source
            .flow
            .owners
            .as_ref()
            .and_then(|owners| owners.upgrade()),
    ) {
        let mut once = OriginalKernelOnce {
            committed: &mut result.committed,
            commit_ns: &mut result.commit_ns,
        };
        result.outcome = peers.try_commit_original_kernel_exchange(
            &owners,
            &candidate,
            &mut once,
            &mut result.owner_check,
        );
    }
    Some(result)
}
