// Canonical physical facts. This is not final ACK or current-owner credit.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Instant;

use super::CanonicalOverlayRequest;
use crate::peer::PeerManager;
use crate::relay::RelayFullSendFact;
use crate::request_carriage::{in_original_window, RequestBindingState};
use crate::transport::OriginalEncryptionSource;
use crate::udp::UdpFullSendFact;

const ID_MAX: u64 = (1u64 << 61) - 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub(crate) enum PhysicalPublicationState {
    Idle = 0,
    Open = 1,
    Publishing = 2,
    Recorded = 3,
    DefinitelyNotHanded = 4,
    CancelledOrUncertain = 5,
    MetadataFailed = 6,
    Exhausted = 7,
}
fn packed(id: u64, state: PhysicalPublicationState) -> u64 {
    (id << 3) | state as u64
}
fn state(word: u64) -> PhysicalPublicationState {
    match word & 7 {
        0 => PhysicalPublicationState::Idle,
        1 => PhysicalPublicationState::Open,
        2 => PhysicalPublicationState::Publishing,
        3 => PhysicalPublicationState::Recorded,
        4 => PhysicalPublicationState::DefinitelyNotHanded,
        5 => PhysicalPublicationState::CancelledOrUncertain,
        6 => PhysicalPublicationState::MetadataFailed,
        _ => PhysicalPublicationState::Exhausted,
    }
}

pub(crate) struct PhysicalSendPublication {
    phase: AtomicU64,
    record: OnceLock<PhysicalSendRecord>,
    recorded_observed_at: OnceLock<Instant>,
    #[cfg(test)]
    recorded_observation_hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}
impl PhysicalSendPublication {
    pub(super) fn new() -> Self {
        Self {
            phase: AtomicU64::new(0),
            record: OnceLock::new(),
            recorded_observed_at: OnceLock::new(),
            #[cfg(test)]
            recorded_observation_hook: std::sync::Mutex::new(None),
        }
    }
    /// Original producer observation only. Fixture callbacks must use a fixed
    /// bounded wait; they cannot set the phase, record, or monotonic timestamp.
    #[cfg(test)]
    pub(crate) fn set_recorded_observation_hook_for_test(
        &self,
        hook: impl FnOnce() + Send + 'static,
    ) {
        *self.recorded_observation_hook.lock().unwrap() = Some(Box::new(hook));
    }
    #[allow(dead_code)] // Historical publication phase; not a current-owner business verdict.
    pub(crate) fn state(&self) -> PhysicalPublicationState {
        let phase = state(self.phase.load(Ordering::Acquire));
        if phase == PhysicalPublicationState::Recorded && self.recorded_observed_at.get().is_none()
        {
            PhysicalPublicationState::Publishing
        } else {
            phase
        }
    }
    #[allow(dead_code)] // Acquire historical evidence; final owner separately qualifies current guards.
    pub(crate) fn record(&self) -> Option<&PhysicalSendRecord> {
        let word = self.phase.load(Ordering::Acquire);
        if state(word) != PhysicalPublicationState::Recorded
            || self.recorded_observed_at.get().is_none()
        {
            return None;
        }
        self.record
            .get()
            .filter(|record| record.attempt_id == word >> 3)
    }

    /// A conservative upper bound observed after Recorded was published.
    /// An original read before this observation cannot inherit a later Full.
    pub(crate) fn recorded_observed_at(&self) -> Option<Instant> {
        (self.state() == PhysicalPublicationState::Recorded)
            .then(|| self.recorded_observed_at.get().copied())
            .flatten()
    }
    fn open(&self) -> Result<u64, PublicationFailure> {
        let old = self.phase.load(Ordering::Acquire);
        if !matches!(
            state(old),
            PhysicalPublicationState::Idle | PhysicalPublicationState::DefinitelyNotHanded
        ) {
            return Err(PublicationFailure::Occupied);
        }
        let previous = old >> 3;
        if previous == ID_MAX {
            let _ = self.phase.compare_exchange(
                old,
                packed(previous, PhysicalPublicationState::Exhausted),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return Err(PublicationFailure::Exhausted);
        }
        let id = previous + 1;
        self.phase
            .compare_exchange(
                old,
                packed(id, PhysicalPublicationState::Open),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| id)
            .map_err(|_| PublicationFailure::Contended)
    }
    #[cfg(test)]
    pub(crate) fn original_reopen_is_occupied_for_test(&self) -> bool {
        // Calls the original owner/CAS, without a source or phase factory.
        matches!(self.open(), Err(PublicationFailure::Occupied))
    }
    fn terminal(&self, id: u64, terminal: PhysicalPublicationState) -> bool {
        self.phase
            .compare_exchange(
                packed(id, PhysicalPublicationState::Open),
                packed(id, terminal),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationFailure {
    Retired,
    Occupied,
    Contended,
    Exhausted,
    MetadataFailed,
}
#[allow(dead_code)] // Compatibility intrinsic result; final guards are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhysicalInputQualification {
    PendingInjection,
    AcceptedInput,
    Expired,
    OriginalMismatch,
    Retired,
    UnknownOriginalAuthorization,
    UnknownUdpPublication,
    UnknownRelayPublication,
}

// Prepared under the original encryption epoch, before any Open/Publishing CAS.
// Visibility trusts crate call sites; it is not an adversarial crate boundary.
pub(crate) struct PreparedPhysicalPublication {
    pub(super) request: Weak<CanonicalOverlayRequest>,
    pub(super) peer_owner: Weak<PeerManager>,
    pub(super) binding: RequestBindingState,
    pub(super) encryption: OriginalEncryptionSource,
    pub(super) encryption_generation: u64,
    wire: (usize, Option<u64>, u64),
}
impl PreparedPhysicalPublication {
    pub(crate) fn capture_encryption_epoch(
        binding: &crate::request_carriage::RequestBinding,
        source: &OriginalEncryptionSource,
        peers: &PeerManager,
        transport: &crate::transport::WireGuardTransport,
        actual_generation: u64,
        packet: &crate::transport::EncryptedPeerPacket,
    ) -> Result<Option<Self>, PublicationFailure> {
        let Some(request) = binding.token().request() else {
            return Ok(None);
        };
        let Some(peer_owner) = request.original_peer_owner(peers) else {
            return Ok(None);
        };
        if !source.belongs_to(transport) {
            return Ok(None);
        }
        // Copy may fail before Open. It cannot leave an orphan attempt.
        let encryption = source
            .try_copy_for_publication()
            .map_err(|_| PublicationFailure::MetadataFailed)?;
        Ok(Some(Self {
            request: std::sync::Arc::downgrade(&request),
            peer_owner,
            binding: binding.state(),
            encryption,
            encryption_generation: actual_generation,
            wire: (
                packet.wire_bytes.len(),
                crate::transport::wire_counter(&packet.wire_bytes),
                crate::transport::wire_fingerprint(&packet.wire_bytes),
            ),
        }))
    }
    pub(crate) fn open(self) -> Result<PhysicalRequestPublisher, PublicationFailure> {
        let request = self.request.upgrade().ok_or(PublicationFailure::Retired)?;
        let id = request.physical_publication.open()?;
        drop(request);
        Ok(PhysicalRequestPublisher {
            id,
            prepared: Some(self),
        })
    }
}

// The UDP variant is a fixed-size immutable fact. Keep it inline so sealing
// the original publication does not add a separate heap allocation.
#[allow(clippy::large_enum_variant)]
enum PhysicalTransportFact {
    Udp(UdpFullSendFact),
    Relay(Arc<RelayFullSendFact>),
}
impl PhysicalTransportFact {
    fn matches_wire(&self, wire: (usize, Option<u64>, u64), peer: &str) -> bool {
        match self {
            Self::Udp(fact) => fact.matches_wire(wire),
            Self::Relay(fact) => fact.matches_wire(wire, peer),
        }
    }
    fn source_is_live(&self) -> bool {
        match self {
            Self::Udp(fact) => fact.source_is_live(),
            Self::Relay(fact) => fact.source_is_live(),
        }
    }
}

pub(crate) struct PhysicalSendRecord {
    request: Weak<CanonicalOverlayRequest>,
    attempt_id: u64,
    peer_owner: Weak<PeerManager>,
    binding: RequestBindingState,
    encryption: OriginalEncryptionSource,
    encryption_generation: u64,
    transport: PhysicalTransportFact,
}
#[allow(dead_code)] // Read-only intrinsic evidence; current-owner guards are separate.
impl PhysicalSendRecord {
    pub(crate) fn attempt_id(&self) -> u64 {
        self.attempt_id
    }
    pub(crate) fn encryption(&self) -> &OriginalEncryptionSource {
        &self.encryption
    }
    pub(crate) fn encryption_generation(&self) -> u64 {
        self.encryption_generation
    }
    pub(crate) fn udp(&self) -> Option<&UdpFullSendFact> {
        match &self.transport {
            PhysicalTransportFact::Udp(fact) => Some(fact),
            PhysicalTransportFact::Relay(_) => None,
        }
    }
    pub(crate) fn relay(&self) -> Option<&RelayFullSendFact> {
        match &self.transport {
            PhysicalTransportFact::Relay(fact) => Some(fact),
            PhysicalTransportFact::Udp(_) => None,
        }
    }
    pub(crate) fn qualify(
        &self,
        request: &CanonicalOverlayRequest,
        now: Instant,
    ) -> PhysicalInputQualification {
        if !std::ptr::eq(self.request.as_ptr(), request) {
            return PhysicalInputQualification::OriginalMismatch;
        }
        if self.peer_owner.upgrade().is_none()
            || !self.encryption.owner_is_live()
            || !self.transport.source_is_live()
        {
            return PhysicalInputQualification::Retired;
        }
        if !in_original_window(request.sent_at, now) {
            return PhysicalInputQualification::Expired;
        }
        if self.binding != RequestBindingState::RoutedExact
            || request.generation != self.encryption_generation
            || request.peer_id != self.encryption.peer_id()
            || !in_original_window(request.sent_at, self.encryption.encrypted_at())
        {
            return PhysicalInputQualification::OriginalMismatch;
        }
        if !request.injection_accepted() {
            return PhysicalInputQualification::PendingInjection;
        }
        if self.encryption.authorized_peer_lifecycle().is_none()
            || request.expected_target_lifecycle().is_none()
        {
            return PhysicalInputQualification::UnknownOriginalAuthorization;
        }
        if request.expected_target_lifecycle() != self.encryption.authorized_peer_lifecycle() {
            return PhysicalInputQualification::OriginalMismatch;
        }
        match &self.transport {
            PhysicalTransportFact::Relay(_) => PhysicalInputQualification::UnknownRelayPublication,
            PhysicalTransportFact::Udp(fact) => {
                if fact.publication_owner().is_none_or(|owner| owner == 0) {
                    PhysicalInputQualification::UnknownUdpPublication
                } else {
                    PhysicalInputQualification::AcceptedInput
                }
            }
        }
    }

    /// Intrinsic original-input checks only. The final owner must additionally
    /// freeze current lifecycle, session and transport publications.
    pub(crate) fn matches_original_input(
        &self,
        request: &CanonicalOverlayRequest,
        now: Instant,
    ) -> bool {
        std::ptr::eq(self.request.as_ptr(), request)
            && self.peer_owner.ptr_eq(&request.target.owner)
            && self.binding == RequestBindingState::RoutedExact
            && request.injection_accepted()
            && request.generation == self.encryption_generation
            && request.peer_id == self.encryption.peer_id()
            && request.expected_target_lifecycle().is_some()
            && request.expected_target_lifecycle() == self.encryption.authorized_peer_lifecycle()
            && in_original_window(request.sent_at, now)
            && in_original_window(request.sent_at, self.encryption.encrypted_at())
            && match &self.transport {
                PhysicalTransportFact::Udp(fact) => {
                    self.encryption.encrypted_at() <= fact.syscall_started()
                        && fact.syscall_started() <= fact.syscall_completed()
                        && in_original_window(request.sent_at, fact.syscall_completed())
                }
                PhysicalTransportFact::Relay(fact) => fact.original().is_some_and(|write| {
                    self.encryption.encrypted_at() <= write.write_started_at()
                        && write.write_started_at() <= write.completed_at()
                        && in_original_window(request.sent_at, write.completed_at())
                }),
            }
    }
}

// Sole attempt producer. Drop only cancels matching Open; it cannot overwrite a
// winning captured success or a distinct external terminal. No strong keeper.
pub(crate) struct PhysicalRequestPublisher {
    id: u64,
    prepared: Option<PreparedPhysicalPublication>,
}
impl PhysicalRequestPublisher {
    pub(crate) fn publish(&mut self, udp: UdpFullSendFact) -> Result<(), PublicationFailure> {
        self.publish_transport(PhysicalTransportFact::Udp(udp))
    }
    pub(crate) fn publish_relay(
        &mut self,
        relay: Arc<RelayFullSendFact>,
    ) -> Result<(), PublicationFailure> {
        self.publish_transport(PhysicalTransportFact::Relay(relay))
    }
    fn publish_transport(
        &mut self,
        transport: PhysicalTransportFact,
    ) -> Result<(), PublicationFailure> {
        let Some(prepared) = self.prepared.take() else {
            return Err(PublicationFailure::Occupied);
        };
        let request = prepared
            .request
            .upgrade()
            .ok_or(PublicationFailure::Retired)?;
        let publication = &request.physical_publication;
        if !transport.matches_wire(prepared.wire, prepared.encryption.peer_id()) {
            publication.terminal(self.id, PhysicalPublicationState::MetadataFailed);
            return Err(PublicationFailure::MetadataFailed);
        }
        let record = PhysicalSendRecord {
            request: prepared.request,
            attempt_id: self.id,
            peer_owner: prepared.peer_owner,
            binding: prepared.binding,
            encryption: prepared.encryption,
            encryption_generation: prepared.encryption_generation,
            transport,
        };
        publication
            .phase
            .compare_exchange(
                packed(self.id, PhysicalPublicationState::Open),
                packed(self.id, PhysicalPublicationState::Publishing),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| PublicationFailure::Contended)?;
        if publication.record.set(record).is_err() {
            publication.phase.store(
                packed(self.id, PhysicalPublicationState::MetadataFailed),
                Ordering::Release,
            );
            return Err(PublicationFailure::MetadataFailed);
        }
        publication.phase.store(
            packed(self.id, PhysicalPublicationState::Recorded),
            Ordering::Release,
        );
        // PhysicalAttempt already destroyed the inner send future and released
        // emit. Fast caller also dropped epoch/slot; no current owner is leased.
        #[cfg(test)]
        {
            let hook = publication.recorded_observation_hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        let _ = publication.recorded_observed_at.set(Instant::now());
        Ok(())
    }
    pub(crate) fn fail_metadata(&mut self) {
        if let Some(prepared) = self.prepared.take() {
            if let Some(request) = prepared.request.upgrade() {
                request
                    .physical_publication
                    .terminal(self.id, PhysicalPublicationState::MetadataFailed);
            }
        }
    }
    pub(crate) fn finish(&mut self, definitely_not_handed: bool) {
        if let Some(prepared) = self.prepared.take() {
            if let Some(request) = prepared.request.upgrade() {
                request.physical_publication.terminal(
                    self.id,
                    if definitely_not_handed {
                        PhysicalPublicationState::DefinitelyNotHanded
                    } else {
                        PhysicalPublicationState::CancelledOrUncertain
                    },
                );
            }
        }
    }
}
impl Drop for PhysicalRequestPublisher {
    fn drop(&mut self) {
        self.finish(false);
    }
}

#[cfg(test)]
#[path = "send_publication/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "send_publication/relay_tests.rs"]
mod relay_tests;
