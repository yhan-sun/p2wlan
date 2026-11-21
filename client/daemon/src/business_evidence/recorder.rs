use super::*;
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArmError {
    Empty,
    Capacity,
    Ttl,
    Peer,
    Registration,
    DuplicateKey,
    IncompatiblePlan,
    Footprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotDisposition {
    Disabled,
    Expired,
    Contended,
    Unregistered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotSnapshot {
    pub(crate) registration: Registration,
    pub(crate) authenticated: Option<AuthenticatedIngressContext>,
    pub(crate) tun_full: Option<TunFullReceipt>,
    pub(crate) ambiguous: bool,
}

#[derive(Clone, Copy)]
struct Slot {
    snapshot: SlotSnapshot,
}

struct PeerBinding {
    bytes: [u8; MAX_PEER_ID_BYTES],
    len: u16,
}

impl PeerBinding {
    fn matches(&self, peer: &str) -> bool {
        peer.as_bytes() == &self.bytes[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoverageSnapshot {
    counts: [u64; RecordDisposition::COUNT],
    pub(crate) overflow: bool,
}

impl CoverageSnapshot {
    pub(crate) fn count(self, disposition: RecordDisposition) -> u64 {
        self.counts[disposition.index()]
    }
}

/// Fixed plan owner, not a packet queue or daemon-global capture registry.
pub(crate) struct CaptureOwner {
    scope: CaptureScope,
    deadline: Instant,
    // 0=open, 1=disarmed, 2=expired. There is no arm/retry deadline reset.
    state: AtomicU8,
    table: Mutex<Option<Box<[Slot]>>>,
    peers: Box<[PeerBinding]>,
    coverage: [AtomicU64; RecordDisposition::COUNT],
    coverage_overflow: AtomicBool,
}

impl CaptureOwner {
    /// Bounded control-path allocation. Never invoked by a packet hook.
    pub(crate) fn arm(
        scope: CaptureScope,
        peers: &[&str],
        registrations: &[Registration],
        ttl: Duration,
    ) -> Result<Arc<Self>, ArmError> {
        if registrations.is_empty() || peers.is_empty() {
            return Err(ArmError::Empty);
        }
        if registrations.len() > MAX_SLOTS || peers.len() > MAX_PEERS {
            return Err(ArmError::Capacity);
        }
        if ttl < Duration::from_secs(1) || ttl > Duration::from_secs(MAX_TTL_SECS) {
            return Err(ArmError::Ttl);
        }
        let table_bytes = registrations.len() * std::mem::size_of::<Slot>();
        let peer_bytes = peers.len() * std::mem::size_of::<PeerBinding>();
        if std::mem::size_of::<AuthenticatedIngressContext>() > MAX_CONTEXT_BYTES
            || std::mem::size_of::<Slot>() > MAX_SLOT_BYTES
            || table_bytes + peer_bytes + std::mem::size_of::<Self>() > MAX_CAPTURE_BYTES
        {
            return Err(ArmError::Footprint);
        }
        for (index, peer) in peers.iter().enumerate() {
            if peer.is_empty() || peer.len() > MAX_PEER_ID_BYTES || peers[..index].contains(peer) {
                return Err(ArmError::Peer);
            }
        }
        let first = registrations[0];
        let mut requests = 0;
        for (index, entry) in registrations.iter().enumerate() {
            if !entry.flow.valid()
                || usize::from(entry.peer_slot) >= peers.len()
                || usize::from(entry.expected_payload_bytes)
                    > MAX_OS_UDP_BYTES - OS_UDP_HEADER_BYTES
            {
                return Err(ArmError::Registration);
            }
            if entry.key.run != first.key.run || entry.key.round != first.key.round {
                return Err(ArmError::IncompatiblePlan);
            }
            if registrations[..index].iter().any(|prior| {
                prior.key.request_nonce == entry.key.request_nonce
                    && prior.key.sequence != entry.key.sequence
            }) {
                return Err(ArmError::IncompatiblePlan);
            }
            if registrations[..index]
                .iter()
                .any(|prior| prior.key == entry.key)
            {
                return Err(ArmError::DuplicateKey);
            }
            let prior_sequence = registrations[..index]
                .iter()
                .find(|prior| prior.key.sequence == entry.key.sequence);
            if let Some(prior) = prior_sequence {
                if prior.key == entry.key {
                    return Err(ArmError::DuplicateKey);
                }
                if prior.key.request_nonce != entry.key.request_nonce
                    || prior.flow.reverse() != entry.flow
                    || prior.peer_slot != entry.peer_slot
                    || prior.expected_payload_bytes != entry.expected_payload_bytes
                {
                    return Err(ArmError::IncompatiblePlan);
                }
            } else {
                requests += 1;
            }
        }
        if requests > MAX_REQUESTS {
            return Err(ArmError::Capacity);
        }
        // All input bounds are validated before any plan-sized allocation.
        let peers = peers
            .iter()
            .map(|peer| {
                let mut bytes = [0; MAX_PEER_ID_BYTES];
                bytes[..peer.len()].copy_from_slice(peer.as_bytes());
                PeerBinding {
                    bytes,
                    len: peer.len() as u16,
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut slots = registrations
            .iter()
            .map(|registration| Slot {
                snapshot: SlotSnapshot {
                    registration: *registration,
                    authenticated: None,
                    tun_full: None,
                    ambiguous: false,
                },
            })
            .collect::<Vec<_>>();
        slots.sort_unstable_by_key(|slot| slot.snapshot.registration.key);
        Ok(Arc::new(Self {
            scope,
            deadline: Instant::now() + ttl,
            state: AtomicU8::new(0),
            table: Mutex::new(Some(slots.into_boxed_slice())),
            peers,
            coverage: std::array::from_fn(|_| AtomicU64::new(0)),
            coverage_overflow: AtomicBool::new(false),
        }))
    }

    fn count(&self, disposition: RecordDisposition) -> RecordDisposition {
        if self.coverage[disposition.index()].fetch_add(1, Ordering::Relaxed) == u64::MAX {
            // Counts are no longer exact after wrap; expose Unknown coverage.
            self.coverage_overflow.store(true, Ordering::Relaxed);
        }
        disposition
    }

    pub(crate) fn coverage(&self) -> CoverageSnapshot {
        CoverageSnapshot {
            counts: std::array::from_fn(|i| self.coverage[i].load(Ordering::Relaxed)),
            overflow: self.coverage_overflow.load(Ordering::Relaxed),
        }
    }

    fn closed(&self) -> Option<RecordDisposition> {
        if Instant::now() >= self.deadline {
            let _ = self
                .state
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
        }
        match self.state.load(Ordering::Acquire) {
            1 => Some(RecordDisposition::Disabled),
            2 => Some(RecordDisposition::Expired),
            _ => None,
        }
    }

    pub(crate) fn accepts_observation(&self) -> bool {
        self.closed().is_none()
    }

    pub(crate) fn note_gap(&self, gap: EvidenceGap) -> RecordDisposition {
        self.count(self.closed().unwrap_or_else(|| gap.disposition()))
    }

    fn try_table(&self) -> Result<MutexGuard<'_, Option<Box<[Slot]>>>, RecordDisposition> {
        match self.table.try_lock() {
            Ok(guard) => Ok(guard),
            Err(TryLockError::Poisoned(poisoned)) => Ok(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => Err(RecordDisposition::Contended),
        }
    }

    pub(crate) fn lookup_registered(
        &self,
        raw_ip: &[u8],
        authenticated_peer: &str,
    ) -> Result<RegisteredObservation, RecordDisposition> {
        if let Some(reason) = self.closed() {
            return Err(self.count(reason));
        }
        let parsed = parse_os_udp(raw_ip).map_err(|_| self.count(RecordDisposition::Malformed))?;
        let table = self.try_table().map_err(|reason| self.count(reason))?;
        if let Some(reason) = self.closed() {
            return Err(self.count(reason));
        }
        let slots = table
            .as_ref()
            .ok_or_else(|| self.count(RecordDisposition::Disabled))?;
        let index = slots
            .binary_search_by_key(&parsed.key, |slot| slot.snapshot.registration.key)
            .map_err(|_| self.count(RecordDisposition::Unregistered))?;
        let registration = slots[index].snapshot.registration;
        if parsed.flow != registration.flow
            || parsed.payload_bytes != registration.expected_payload_bytes
        {
            return Err(self.count(RecordDisposition::FlowMismatch));
        }
        if !self.peers[usize::from(registration.peer_slot)].matches(authenticated_peer) {
            return Err(self.count(RecordDisposition::PeerMismatch));
        }
        Ok(RegisteredObservation {
            slot: SlotRef {
                scope: self.scope,
                index: index as u16,
            },
            registration,
        })
    }

    pub(crate) fn try_record(&self, receipt: StageReceipt) -> RecordDisposition {
        if let Some(reason) = self.closed() {
            return self.count(reason);
        }
        let mut table = match self.try_table() {
            Ok(guard) => guard,
            Err(reason) => return self.count(reason),
        };
        if let Some(reason) = self.closed() {
            return self.count(reason);
        }
        let context = match receipt {
            StageReceipt::AuthenticatedReceive(context) => context,
            StageReceipt::TunWriteFull(receipt) => receipt.authenticated,
        };
        let observed = context.registered;
        if observed.slot.scope != self.scope {
            return self.count(RecordDisposition::Unregistered);
        }
        let Some(slot) = table
            .as_mut()
            .and_then(|slots| slots.get_mut(usize::from(observed.slot.index)))
        else {
            return self.count(RecordDisposition::Unregistered);
        };
        if slot.snapshot.registration != observed.registration {
            return self.count(RecordDisposition::Unregistered);
        }
        let cross_stage_conflict = match receipt {
            StageReceipt::AuthenticatedReceive(context) => slot
                .snapshot
                .tun_full
                .is_some_and(|old| old.authenticated != context),
            StageReceipt::TunWriteFull(receipt) => slot
                .snapshot
                .authenticated
                .is_some_and(|old| old != receipt.authenticated),
        };
        let disposition = match receipt {
            StageReceipt::AuthenticatedReceive(context) => match slot.snapshot.authenticated {
                None => {
                    slot.snapshot.authenticated = Some(context);
                    RecordDisposition::Stored
                }
                Some(old) if old == context => RecordDisposition::DuplicateSameIdentity,
                Some(_) => RecordDisposition::Conflict,
            },
            StageReceipt::TunWriteFull(receipt) => match slot.snapshot.tun_full {
                None => {
                    slot.snapshot.tun_full = Some(receipt);
                    RecordDisposition::Stored
                }
                Some(old) if old.same_identity(receipt) => RecordDisposition::DuplicateSameIdentity,
                Some(_) => RecordDisposition::Conflict,
            },
        };
        let disposition = if cross_stage_conflict {
            RecordDisposition::Conflict
        } else {
            disposition
        };
        if disposition == RecordDisposition::Conflict {
            slot.snapshot.ambiguous = true;
        }
        self.count(disposition)
    }

    pub(crate) fn try_read_registered(
        &self,
        slot: SlotRef,
    ) -> Result<SlotSnapshot, SnapshotDisposition> {
        if let Some(reason) = self.closed() {
            return Err(match reason {
                RecordDisposition::Expired => SnapshotDisposition::Expired,
                _ => SnapshotDisposition::Disabled,
            });
        }
        if slot.scope != self.scope {
            return Err(SnapshotDisposition::Unregistered);
        }
        let table = self.try_table().map_err(|_| {
            self.count(RecordDisposition::Contended);
            SnapshotDisposition::Contended
        })?;
        if let Some(reason) = self.closed() {
            return Err(match reason {
                RecordDisposition::Expired => SnapshotDisposition::Expired,
                _ => SnapshotDisposition::Disabled,
            });
        }
        table
            .as_ref()
            .and_then(|slots| slots.get(usize::from(slot.index)))
            .map(|slot| slot.snapshot)
            .ok_or(SnapshotDisposition::Unregistered)
    }

    /// Immediate logical close. Reclamation is best-effort without waiting.
    /// A contended table is retained until owner drop; no idle task is added.
    pub(crate) fn disarm(&self) -> RecordDisposition {
        self.state.store(1, Ordering::Release);
        match self.try_table() {
            Ok(mut table) => {
                *table = None;
                self.count(RecordDisposition::Disabled)
            }
            Err(reason) => self.count(reason),
        }
    }

    pub(crate) fn seal_expired(&self) -> RecordDisposition {
        match self.closed() {
            Some(reason) => match self.try_table() {
                Ok(mut table) => {
                    *table = None;
                    self.count(reason)
                }
                Err(reason) => self.count(reason),
            },
            None => RecordDisposition::Stored,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure owner controls. This input does not claim real authenticated I/O.
    fn owner_and_context() -> (Arc<CaptureOwner>, AuthenticatedIngressContext) {
        let scope = CaptureScope {
            capture_id: [1; 16],
            producer_scope: [2; 16],
        };
        let registration = Registration {
            key: OsUdpReqKey {
                run: [3; 16],
                round: [4; 16],
                sequence: 1,
                request_nonce: [5; 16],
                kind: RequestKind::Request,
            },
            flow: RegisteredFlow {
                src_v4: Ipv4Addr::new(10, 20, 0, 1),
                dst_v4: Ipv4Addr::new(10, 20, 0, 2),
                src_port: 41000,
                dst_port: 42000,
            },
            expected_payload_bytes: 0,
            peer_slot: 0,
        };
        let owner =
            CaptureOwner::arm(scope, &["peer-a"], &[registration], Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        let context = AuthenticatedIngressContext::new(
            RegisteredObservation {
                slot: SlotRef { scope, index: 0 },
                registration,
            },
            PhysicalIngressContext::direct_udp(
                Some(0),
                NonZeroU64::new(1).unwrap(),
                0,
                SocketOwner::FixedPool { index: 0 },
                PublicationObservation::EnqueueObserved {
                    owner: NonZeroU64::new(2),
                },
                "127.0.0.1:41000".parse().unwrap(),
                "127.0.0.1:42000".parse().unwrap(),
                now,
                now,
            ),
            WgEvidenceOwnerId::allocate(),
            NonZeroU64::new(1).unwrap(),
            false,
            WireTuple {
                receiver_index: 1,
                counter: 1,
                wire_len: 128,
            },
            now,
        )
        .unwrap();
        (owner, context)
    }

    #[test]
    fn pure_actual_table_contention_returns_unknown_without_waiting() {
        let (owner, context) = owner_and_context();
        let guard = owner.table.lock().unwrap();
        assert_eq!(
            owner.try_record(StageReceipt::AuthenticatedReceive(context)),
            RecordDisposition::Contended
        );
        assert_eq!(
            owner.try_read_registered(context.registered().slot()),
            Err(SnapshotDisposition::Contended)
        );
        assert_eq!(owner.disarm(), RecordDisposition::Contended);
        drop(guard);
        assert_eq!(
            owner.try_record(StageReceipt::AuthenticatedReceive(context)),
            RecordDisposition::Disabled
        );
        assert_eq!(owner.coverage().count(RecordDisposition::Contended), 3);
        assert_eq!(owner.coverage().count(RecordDisposition::Stored), 0);
        // Close during contention rejects immediately; reclaim is owner drop.
        let weak = Arc::downgrade(&owner);
        drop(owner);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn pure_fixed_expired_owner_rejects_without_extending_deadline() {
        let (mut owner, context) = owner_and_context();
        // Private owner input only: no fake public clock or Tokio rebase.
        let deadline = Instant::now() - Duration::from_nanos(1);
        Arc::get_mut(&mut owner).unwrap().deadline = deadline;
        assert_eq!(
            owner.try_record(StageReceipt::AuthenticatedReceive(context)),
            RecordDisposition::Expired
        );
        assert_eq!(
            owner.try_read_registered(context.registered().slot()),
            Err(SnapshotDisposition::Expired)
        );
        assert_eq!(owner.deadline, deadline);
        assert_eq!(owner.seal_expired(), RecordDisposition::Expired);
        assert!(owner.table.lock().unwrap().is_none());
        assert_eq!(owner.deadline, deadline);
        assert_eq!(owner.coverage().count(RecordDisposition::Stored), 0);
    }

    #[test]
    fn pure_coverage_counter_exhaustion_is_explicitly_unknown() {
        let (owner, context) = owner_and_context();
        owner.coverage[RecordDisposition::Stored.index()].store(u64::MAX, Ordering::Relaxed);
        assert_eq!(
            owner.try_record(StageReceipt::AuthenticatedReceive(context)),
            RecordDisposition::Stored
        );
        assert!(owner.coverage().overflow);
        // No exact cumulative count is claimed after overflow.
        assert!(owner
            .try_read_registered(context.registered().slot())
            .unwrap()
            .authenticated
            .is_some());
    }
}
