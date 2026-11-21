// Qualification of original REQUEST sources at echo injection/send boundaries.
// These guards never grant canonical ACK credit or outlive a synchronous check.
use crate::overlay_requests::OriginalEchoInput;

pub(crate) struct OriginalEchoPeerReadGuard<'a> {
    _connections: tokio::sync::OwnedRwLockReadGuard<HashMap<String, PeerConnection>>,
    pub(crate) session: crate::transport::OriginalEchoSessionGuard<'a>,
}

impl OriginalEchoPeerReadGuard<'_> {
    /// The retained original connection/session guards fence this observation
    /// through the caller's syscall. It does not nominate the receive source.
    pub(crate) fn verified_direct_return_local(
        &self,
        input: &OriginalEchoInput,
        endpoint: SocketAddr,
    ) -> Option<SocketAddr> {
        let conn = self._connections.get(input.peer_id())?;
        let validation = conn.path_state_machine.active_direct_validation()?;
        let lifecycle = input.source().session().authorized_peer_lifecycle()?;
        if !conn.direct_is_healthy_confirmed()
            || conn.direct_generation != input.generation()
            || validation.epoch
                != PathEpoch::new(input.generation(), lifecycle, conn.remote_candidate_epoch())
            || validation.owner_token.is_none()
            || validation.request_id.is_none()
            || validation.commit_endpoint() != Some(endpoint)
            || conn.selected_direct_endpoint_for_consent(input.generation()) != Some(endpoint)
        {
            return None;
        }
        conn.candidate_pairs
            .iter()
            .find(|pair| {
                pair.local_generation == input.generation()
                    && pair.remote_candidate_epoch == validation.epoch.remote_candidate_epoch
                    && pair.remote_endpoint == endpoint
                    && pair.state == CandidatePairState::Selected
                    && pair.selected_at.is_some()
                    && !conn.is_overlay_candidate_pair(pair)
            })?
            .local_endpoint
    }
}

pub(crate) struct OriginalEchoPeerWriteGuard<'a> {
    pub(crate) current: OriginalEchoPeerReadGuard<'a>,
    _owner: Arc<PeerManager>,
    _emit: Arc<tokio::sync::OwnedMutexGuard<()>>,
    _epoch: tokio::sync::OwnedMutexGuard<()>,
}

impl PeerManager {
    fn original_echo_peer_checks(
        &self,
        input: &OriginalEchoInput,
        lifecycle: PeerSessionGeneration,
    ) -> std::result::Result<
        tokio::sync::OwnedRwLockReadGuard<HashMap<String, PeerConnection>>,
        OverlayCreditOutcome,
    > {
        use OverlayCreditOutcome::{Contended, Stale};
        if self.current_network_generation_sync() != input.generation()
            || input.source().network_generation() != Some(input.generation())
        {
            return Err(Stale(CreditStale::Generation));
        }
        // The native REQUEST entrance checks the destination against its
        // resolved runtime VIP before sealing this input. Manager Config is
        // the construction-time bootstrap, not a second current VIP owner.
        if !crate::request_carriage::in_original_window(input.read_at(), Instant::now()) {
            return Err(Stale(CreditStale::OriginalWindow));
        }
        let connections = self
            .connections
            .clone()
            .try_read_owned()
            .map_err(|_| Contended(CreditLock::Connections))?;
        let membership = match self.peer_membership.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(Contended(CreditLock::Membership))
            }
        };
        let current = membership.active_generation(input.peer_id());
        drop(membership);
        if current != Some(lifecycle) || lifecycle == PeerSessionGeneration::UNBOUND {
            return Err(Stale(CreditStale::Lifecycle));
        }
        let Some(conn) = connections.get(input.peer_id()) else {
            return Err(Stale(CreditStale::PeerState));
        };
        if !conn.online
            || conn.state == ConnectionState::Closed
            || conn.virtual_ip != input.target_vip()
        {
            return Err(Stale(CreditStale::PeerState));
        }
        let quarantine = match self.quarantine_deadline_mirror.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(Contended(CreditLock::Quarantine))
            }
        };
        if quarantine
            .get(input.peer_id())
            .is_some_and(|until| Instant::now() < *until)
        {
            return Err(Stale(CreditStale::Quarantine));
        }
        Ok(connections)
    }

    pub(crate) fn try_qualify_original_echo_input(
        &self,
        wireguard: &crate::transport::WireGuardTransport,
        input: &OriginalEchoInput,
    ) -> std::result::Result<(), OverlayCreditOutcome> {
        use OverlayCreditOutcome::{Contended, Stale};
        if !std::ptr::eq(input.owner().as_ptr(), self) {
            return Err(Stale(CreditStale::Identity));
        }
        let _emit = wireguard
            .try_acquire_outbound_emit_guard(input.peer_id())
            .ok_or(Contended(CreditLock::Emit))?;
        let _epoch = self
            .network_epoch_gate
            .try_lock()
            .map_err(|_| Contended(CreditLock::Epoch))?;
        self.try_qualify_original_echo_input_in_epoch(wireguard, input)
    }

    /// Original outbound caller already retains this peer's emit and epoch.
    pub(crate) fn try_qualify_original_echo_input_in_epoch(
        &self,
        wireguard: &crate::transport::WireGuardTransport,
        input: &OriginalEchoInput,
    ) -> std::result::Result<(), OverlayCreditOutcome> {
        use OverlayCreditOutcome::{Contended, Stale, Unknown};
        if !std::ptr::eq(input.owner().as_ptr(), self) {
            return Err(Stale(CreditStale::Identity));
        }
        let session = wireguard
            .try_original_overlay_ingress_session_guard(input.peer_id(), input.source().session())
            .map_err(|failure| match failure {
                crate::transport::OriginalOverlaySessionFailure::Contended => {
                    Contended(CreditLock::Sessions)
                }
                crate::transport::OriginalOverlaySessionFailure::UnknownAuthorization => {
                    Unknown(CreditUnknown::OriginalAuthorization)
                }
                crate::transport::OriginalOverlaySessionFailure::Stale => {
                    Stale(CreditStale::Session)
                }
            })?;
        let _connections = self.original_echo_peer_checks(input, session.lifecycle())?;
        if let Some(read) = input.source().original_udp_read() {
            let slot = input
                .udp()
                .upgrade()
                .ok_or(Stale(CreditStale::DirectPublication))?;
            let slot = slot
                .try_read()
                .map_err(|_| Contended(CreditLock::UdpSlot))?;
            let udp = slot.as_ref().ok_or(Stale(CreditStale::DirectPublication))?;
            let _publication = udp
                .try_original_direct_publication_guard(
                    input.peer_id(),
                    input.generation(),
                    Some(read),
                    None,
                )
                .map_err(|failure| match failure {
                    crate::udp::DirectOriginFailure::ContendedMembership => {
                        Contended(CreditLock::DirectPolicy)
                    }
                    crate::udp::DirectOriginFailure::ContendedSocket => {
                        Contended(CreditLock::DirectSocket)
                    }
                    crate::udp::DirectOriginFailure::ContendedPublication => {
                        Contended(CreditLock::DirectPublication)
                    }
                    crate::udp::DirectOriginFailure::Unknown => {
                        Unknown(CreditUnknown::OriginalPublication)
                    }
                    crate::udp::DirectOriginFailure::Stale => Stale(CreditStale::DirectPublication),
                })?;
            if !session.is_current() {
                return Err(Stale(CreditStale::Session));
            }
        } else if let (Some(read), Some(id), Some(endpoint)) = (
            input.source().original_relay_read(),
            input.source().relay_connection_id(),
            input.source().relay_reader_endpoint(),
        ) {
            let slot = input
                .relay()
                .upgrade()
                .ok_or(Stale(CreditStale::RelayPublication))?;
            let slot = slot
                .try_read()
                .map_err(|_| Contended(CreditLock::RelaySlot))?;
            let relay = slot.as_ref().ok_or(Stale(CreditStale::RelayPublication))?;
            let member = relay
                .try_original_reader_member_guard(read, endpoint, id)
                .map_err(|_| Stale(CreditStale::RelayPublication))?;
            let _open = member
                .try_open_guard()
                .map_err(|_| Stale(CreditStale::RelayPublication))?;
            if !session.is_current() {
                return Err(Stale(CreditStale::Session));
            }
        } else {
            return Err(Unknown(CreditUnknown::OriginalSource));
        }
        Ok(())
    }

    /// Final Direct echo caller owns emit -> epoch. Preserve original sessions
    /// and connections so every writer, including compatibility writers, fences.
    pub(crate) fn try_original_echo_peer_in_epoch<'a>(
        &self,
        input: &OriginalEchoInput,
        tx: &'a crate::transport::OriginalEncryptionSource,
    ) -> std::result::Result<OriginalEchoPeerReadGuard<'a>, OverlayCreditOutcome> {
        use OverlayCreditOutcome::Stale;
        if !std::ptr::eq(input.owner().as_ptr(), self) {
            return Err(Stale(CreditStale::Identity));
        }
        let session = tx
            .try_original_echo_receive_session_guard(input.source().session())
            .ok_or(Stale(CreditStale::Session))?;
        let connections = self.original_echo_peer_checks(
            input,
            tx.authorized_peer_lifecycle()
                .ok_or(Stale(CreditStale::Lifecycle))?,
        )?;
        Ok(OriginalEchoPeerReadGuard {
            _connections: connections,
            session,
        })
    }

    pub(crate) fn try_original_echo_peer_write_guard<'a>(
        self: &Arc<Self>,
        input: &OriginalEchoInput,
        tx: &'a crate::transport::OriginalEncryptionSource,
        emit: &std::sync::Weak<tokio::sync::OwnedMutexGuard<()>>,
    ) -> std::result::Result<OriginalEchoPeerWriteGuard<'a>, OverlayCreditOutcome> {
        use OverlayCreditOutcome::{Contended, Stale};
        if !input.owner().ptr_eq(&Arc::downgrade(self)) {
            return Err(Stale(CreditStale::Identity));
        }
        let emit = emit.upgrade().ok_or(Stale(CreditStale::Session))?;
        let epoch = self
            .network_epoch_gate
            .clone()
            .try_lock_owned()
            .map_err(|_| Contended(CreditLock::Epoch))?;
        let current = self.try_original_echo_peer_in_epoch(input, tx)?;
        Ok(OriginalEchoPeerWriteGuard {
            current,
            _owner: self.clone(),
            _emit: emit,
            _epoch: epoch,
        })
    }
}
