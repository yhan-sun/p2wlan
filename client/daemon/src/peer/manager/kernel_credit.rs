// The sole full128 kernel-frame current-owner/once transaction. The scope
// caller owns its original metadata mutex; every further acquisition is try-only.
use crate::os_request_capture::{
    OriginalKernelCurrentOwners, OriginalKernelExchange, OriginalKernelOnce,
};

pub(crate) struct OriginalKernelAckCommitPermit {
    _private: (),
}

impl PeerManager {
    pub(crate) fn try_commit_original_kernel_exchange(
        &self,
        owners: &OriginalKernelCurrentOwners,
        request: &OriginalKernelExchange,
        once: &mut OriginalKernelOnce<'_>,
        owner_check: &mut &'static str,
    ) -> OverlayCreditOutcome {
        use OverlayCreditOutcome::{Contended, Stale, Unknown};
        *owner_check = "original_peer";
        let expected = match request.original_peer() {
            Ok(peer) => peer,
            Err(reason) => return reason,
        };
        if !std::ptr::eq(expected.owner.as_ptr(), self)
            || expected.peer != request.peer()
            || expected.target.to_string() != request.target()
        {
            return Stale(CreditStale::Identity);
        }
        *owner_check = "original_sources";
        let mut records = Vec::new();
        let mut sources = Vec::new();
        if records.try_reserve(request.reads().len()).is_err()
            || sources.try_reserve(request.writes().len()).is_err()
        {
            return Unknown(CreditUnknown::OriginalPublication);
        }
        for read in request.reads() {
            let Some(record) = read.physical_publication().record() else {
                return Unknown(CreditUnknown::OriginalPublication);
            };
            records.push(record);
        }
        for write in request.writes() {
            sources.push(write.original_source());
        }
        let (Some(first_tx), Some(first_rx)) = (records.first(), sources.first()) else {
            return Unknown(CreditUnknown::OriginalSource);
        };
        *owner_check = "room";
        let room = match owners.room.try_original_send_guard(
            request.room(),
            request.peer(),
            request.target(),
            request.local(),
        ) {
            Ok(guard) => guard,
            Err(reason) => return reason.into(),
        };
        *owner_check = "emit_registry";
        let _emit = match owners
            .wireguard
            .try_emit_guard(request.peer(), request.emit_try_context())
        {
            Ok(guard) => guard,
            Err(crate::transport::OriginalKernelEmitFailure::Registry) => {
                return Contended(CreditLock::Emit)
            }
            Err(crate::transport::OriginalKernelEmitFailure::Emit) => {
                *owner_check = "emit";
                return Contended(CreditLock::Emit);
            }
        };
        *owner_check = "epoch";
        let Ok(_epoch) = self
            .network_epoch_gate
            .try_lock_original(request.epoch_try_context())
        else {
            return Contended(CreditLock::Epoch);
        };
        *owner_check = "session";
        let session = match owners.wireguard.try_session_guard(
            request.peer(),
            first_tx.encryption(),
            first_rx.session(),
        ) {
            Ok(guard) => guard,
            Err(crate::transport::OriginalOverlaySessionFailure::Contended) => {
                return Contended(CreditLock::Sessions)
            }
            Err(crate::transport::OriginalOverlaySessionFailure::UnknownAuthorization) => {
                return Unknown(CreditUnknown::OriginalAuthorization)
            }
            Err(crate::transport::OriginalOverlaySessionFailure::Stale) => {
                return Stale(CreditStale::Session)
            }
        };
        *owner_check = "connections";
        let Ok(mut connections) = self.connections.try_write() else {
            return Contended(CreditLock::Connections);
        };
        *owner_check = "membership";
        let membership = match self.peer_membership.try_read() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Contended(CreditLock::Membership),
        };
        *owner_check = "lifecycle";
        let lifecycle = membership.active_generation(request.peer());
        drop(membership);
        if lifecycle != Some(expected.lifecycle) || lifecycle != Some(session.lifecycle()) {
            return Stale(CreditStale::Lifecycle);
        }
        *owner_check = "quarantine";
        let quarantine = match self.quarantine_deadline_mirror.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Contended(CreditLock::Quarantine),
        };
        let quarantined = quarantine
            .get(request.peer())
            .is_some_and(|at| Instant::now() < *at);
        drop(quarantine);
        if quarantined {
            return Stale(CreditStale::Quarantine);
        }
        *owner_check = "generation";
        let generation = self.current_network_generation_sync();
        if generation != expected.generation
            || records
                .iter()
                .any(|record| record.encryption_generation() != generation)
            || sources
                .iter()
                .any(|source| source.network_generation() != Some(generation))
        {
            return Stale(CreditStale::Generation);
        }
        *owner_check = "session_identity";
        if records.iter().any(|record| {
            sources.iter().any(|source| {
                !session.matches_original_sources(record.encryption(), source.session())
            })
        }) {
            return Stale(CreditStale::Session);
        }
        *owner_check = "peer_state";
        let Some(conn) = connections.get_mut(request.peer()) else {
            return Stale(CreditStale::PeerState);
        };
        if conn.virtual_ip != request.target()
            || !conn.online
            || conn.state == ConnectionState::Closed
        {
            return Stale(CreditStale::PeerState);
        }
        if records.iter().all(|record| record.udp().is_some()) {
            let mut txs = Vec::new();
            let mut rxs = Vec::new();
            if txs.try_reserve(records.len()).is_err() || rxs.try_reserve(sources.len()).is_err() {
                return Unknown(CreditUnknown::OriginalPublication);
            }
            for record in &records {
                let Some(tx) = record.udp() else {
                    return Unknown(CreditUnknown::MixedPath);
                };
                if tx.original_direct_commit().is_none() {
                    return Unknown(CreditUnknown::OriginalPublication);
                }
                *owner_check = "direct_state_generation";
                if conn.state != ConnectionState::Direct || conn.direct_generation != generation {
                    return Stale(CreditStale::DirectPublication);
                }
                *owner_check = "direct_commit_sequence";
                if tx.original_direct_commit() != Some(conn.direct_commit_seq) {
                    return Stale(CreditStale::DirectPublication);
                }
                *owner_check = "direct_consent_endpoint";
                if conn.selected_direct_endpoint_for_consent(generation) != Some(tx.endpoint()) {
                    return Stale(CreditStale::DirectPublication);
                }
                txs.push(tx);
            }
            for source in &sources {
                if source.original_relay_read().is_some() || source.relay_endpoint().is_some() {
                    return Unknown(CreditUnknown::MixedPath);
                }
                let Some(rx) = source.original_udp_read() else {
                    return Unknown(CreditUnknown::OriginalSource);
                };
                rxs.push(rx);
            }
            *owner_check = "direct_slot";
            let Ok(slot) = owners.udp.try_read() else {
                return Contended(CreditLock::UdpSlot);
            };
            let Some(udp) = slot.as_ref() else {
                return Stale(CreditStale::DirectPublication);
            };
            let _publication = match udp.try_original_direct_publication_batch_guard_observed(
                request.peer(),
                generation,
                &rxs,
                &txs,
                owner_check,
            ) {
                Ok(guard) => guard,
                Err(crate::udp::DirectOriginFailure::ContendedMembership) => {
                    return Contended(CreditLock::DirectPolicy)
                }
                Err(crate::udp::DirectOriginFailure::ContendedSocket) => {
                    return Contended(CreditLock::DirectSocket)
                }
                Err(crate::udp::DirectOriginFailure::ContendedPublication) => {
                    return Contended(CreditLock::DirectPublication)
                }
                Err(crate::udp::DirectOriginFailure::Unknown) => {
                    return Unknown(CreditUnknown::OriginalPublication)
                }
                Err(crate::udp::DirectOriginFailure::Stale) => {
                    return Stale(CreditStale::DirectPublication)
                }
            };
            *owner_check = "final_transaction";
            Self::commit_original_kernel_locked(
                self,
                conn,
                request,
                once,
                &room,
                &session,
                None,
                NetworkPath::Direct,
                None,
                first_tx.attempt_id(),
            )
        } else if records.iter().all(|record| record.relay().is_some()) {
            let Some(tx) = first_tx.relay() else {
                return Unknown(CreditUnknown::OriginalPublication);
            };
            let (Some(rx), Some(id), Some(endpoint)) = (
                first_rx.original_relay_read(),
                first_rx.relay_connection_id(),
                first_rx.relay_endpoint(),
            ) else {
                return Unknown(CreditUnknown::OriginalSource);
            };
            if sources.iter().any(|source| {
                source.original_udp_read().is_some()
                    || source.relay_peer_id() != Some(request.peer())
            }) {
                return Unknown(CreditUnknown::MixedPath);
            }
            *owner_check = "relay_slot";
            let Ok(slot) = owners.relay.try_read() else {
                return Contended(CreditLock::RelaySlot);
            };
            let Some(relay) = slot.as_ref() else {
                return Stale(CreditStale::RelayPublication);
            };
            *owner_check = "relay_membership";
            let member = match relay.try_original_member_guard(tx, rx, id) {
                Ok(guard) => guard,
                Err(reason) => return Self::kernel_relay_failure(reason),
            };
            *owner_check = "relay_open";
            let _open = match member.try_open_guard() {
                Ok(guard) => guard,
                Err(reason) => return Self::kernel_relay_failure(reason),
            };
            for record in &records {
                let Some(tx) = record.relay() else {
                    return Unknown(CreditUnknown::MixedPath);
                };
                for source in &sources {
                    let (Some(rx), Some(other_id)) =
                        (source.original_relay_read(), source.relay_connection_id())
                    else {
                        return Unknown(CreditUnknown::OriginalSource);
                    };
                    if source.relay_endpoint() != Some(endpoint) {
                        return Unknown(CreditUnknown::MixedPath);
                    }
                    if let Err(reason) = member.matches_original_fragment(tx, rx, other_id) {
                        return Self::kernel_relay_failure(reason);
                    }
                }
            }
            *owner_check = "relay_current";
            if conn.relay_confirmed_connection_id != Some(id) || !member.is_current() {
                return Stale(CreditStale::RelayPublication);
            }
            *owner_check = "final_transaction";
            Self::commit_original_kernel_locked(
                self,
                conn,
                request,
                once,
                &room,
                &session,
                Some(&member),
                NetworkPath::Relay,
                Some(endpoint),
                first_tx.attempt_id(),
            )
        } else {
            Unknown(CreditUnknown::MixedPath)
        }
    }

    fn kernel_relay_failure(reason: crate::relay::RelayMemberFailure) -> OverlayCreditOutcome {
        use crate::relay::RelayMemberFailure as R;
        match reason {
            R::ContendedRoutes => OverlayCreditOutcome::Contended(CreditLock::RelayRoutes),
            R::ContendedLive => OverlayCreditOutcome::Contended(CreditLock::RelayLive),
            R::ContendedClose => OverlayCreditOutcome::Contended(CreditLock::RelayClose),
            R::UnknownReader => OverlayCreditOutcome::Unknown(CreditUnknown::CrossRelayClient),
            R::UnknownWrite => OverlayCreditOutcome::Unknown(CreditUnknown::OriginalPublication),
            _ => OverlayCreditOutcome::Stale(CreditStale::RelayPublication),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_original_kernel_locked(
        peers: &PeerManager,
        conn: &mut PeerConnection,
        request: &OriginalKernelExchange,
        once: &mut OriginalKernelOnce<'_>,
        room: &crate::rooms::OriginalRoomSendGuard<'_>,
        session: &crate::transport::OriginalOverlaySessionGuard<'_>,
        relay: Option<&crate::relay::RelayMemberGuard<'_>>,
        path: NetworkPath,
        endpoint: Option<&str>,
        attempt_id: u64,
    ) -> OverlayCreditOutcome {
        let generation = peers.current_network_generation_sync();
        let fallback_reason = match conn.verified_first_usable_policy(generation, path, endpoint) {
            Ok(reason) => reason,
            Err(_) => return OverlayCreditOutcome::Stale(CreditStale::Policy),
        };
        let Some(commit_ns) = crate::os_request_capture::original_kernel_monotonic_ns() else {
            return OverlayCreditOutcome::Unknown(CreditUnknown::OriginalSource);
        };
        let commit_at = Instant::now();
        if relay.is_some_and(|member| !member.is_current()) {
            return OverlayCreditOutcome::Stale(CreditStale::RelayPublication);
        }
        if !room.is_current_at(commit_at) {
            return OverlayCreditOutcome::Stale(CreditStale::RoomAuthority);
        }
        if !session.is_current() {
            return OverlayCreditOutcome::Stale(CreditStale::Session);
        }
        if !request.live_after_point(peers, commit_at, commit_ns) {
            return OverlayCreditOutcome::Stale(CreditStale::OriginalWindow);
        }
        if !once.consume(OriginalKernelAckCommitPermit { _private: () }, commit_ns) {
            return OverlayCreditOutcome::AlreadyCommitted;
        }
        let first_usable_new = conn.record_first_usable(path, generation);
        OverlayCreditOutcome::Fresh(OverlayCreditReceipt {
            generation,
            path,
            attempt_id,
            committed_at: commit_at,
            first_usable_new,
            fallback_reason,
        })
    }
}
