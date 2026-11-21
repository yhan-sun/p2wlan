/// Read outcome from the original membership/capability owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerDplpmtudCapability {
    Unknown,
    Contended,
    Unsupported,
    Supported,
}

// One gate serializes updates of the original watch map across different peers.
// There is no second capability map; ordinary immutable readers retain the
// existing watch interface, while final qualification can refuse contention.
struct DplpmtudCapabilityPublication {
    gate: std::sync::Mutex<()>,
    sender: tokio::sync::watch::Sender<Arc<HashMap<String, PeerSessionGeneration>>>,
}

impl DplpmtudCapabilityPublication {
    fn new() -> Self {
        let (sender, _) = tokio::sync::watch::channel(Arc::new(HashMap::new()));
        Self {
            gate: std::sync::Mutex::new(()),
            sender,
        }
    }
}

impl PeerManager {
    /// Remember a negotiated capability at the WireGuard peer-session scope.
    /// The immutable watch value gives the business hot path a registry-free
    /// read and remains valid across a UDP socket publication replacement.
    pub(crate) fn mark_dplpmtud_capable_sync(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
    ) {
        let gate = self
            .dplpmtud_capability
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let membership = self
            .peer_membership
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if membership.active_generation(peer_id) != Some(peer_session_generation) {
            return;
        }
        let current = self.dplpmtud_capability.sender.borrow().clone();
        if current.get(peer_id) == Some(&peer_session_generation) {
            return;
        }
        let mut next = (*current).clone();
        next.retain(|candidate, generation| {
            membership.active_generation(candidate) == Some(*generation)
        });
        // This mirror is bounded by the authoritative live peer-session set,
        // not by the smaller DPLPMTUD worker/publication cap. Evicting a live
        // negotiated capability would incorrectly turn that modern peer into
        // a legacy bypass while its old runtime entry still existed.
        next.insert(peer_id.to_string(), peer_session_generation);
        self.dplpmtud_capability.sender.send_replace(Arc::new(next));
        drop(membership);
        drop(gate);
        self.notify_direct_business_budget_changed();
    }

    /// A staged policy snapshot, never a current-owner permission. The caller
    /// must hold the peer's original emit and network epoch through use: the
    /// production capability publisher owns emit; membership publishers own
    /// epoch. Read this before taking UDP registry/publication guards.
    /// The publication gate excludes every watch writer before borrowing its
    /// immutable value. Both acquisitions are try-only and precede UDP guards.
    pub(crate) fn try_peer_dplpmtud_capability(&self, peer_id: &str) -> PeerDplpmtudCapability {
        let membership = match self.peer_membership.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return PeerDplpmtudCapability::Contended,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        };
        let Some(generation) = membership.active_generation(peer_id) else {
            return PeerDplpmtudCapability::Unknown;
        };
        drop(membership);
        let _publication = match self.dplpmtud_capability.gate.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => return PeerDplpmtudCapability::Contended,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if self.peer_supports_dplpmtud_sync(peer_id, generation) {
            PeerDplpmtudCapability::Supported
        } else {
            PeerDplpmtudCapability::Unsupported
        }
    }

    #[cfg(test)]
    pub(crate) fn with_peer_membership_held_for_test<R>(&self, operation: impl FnOnce() -> R) -> R {
        let _guard = self.peer_membership.lock().unwrap();
        operation()
    }

    pub(crate) fn peer_supports_dplpmtud_sync(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
    ) -> bool {
        self.dplpmtud_capability
            .sender
            .borrow()
            .get(peer_id)
            .is_some_and(|generation| *generation == peer_session_generation)
    }
}
