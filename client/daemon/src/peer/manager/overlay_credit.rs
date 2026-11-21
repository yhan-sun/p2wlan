// The sole current-owner/once transaction. Every acquisition is try-only;
// original guards are retained through the final window check and commit.
use crate::overlay_requests::{
    CanonicalOverlayRequest, OriginalOverlayAck, OverlayCreditLockSite as CreditLock,
    OverlayCreditOutcome, OverlayCreditReceipt, OverlayCreditStale as CreditStale,
    OverlayCreditUnknown as CreditUnknown,
};

/// Only this peer-owner module can mint the canonical once permission.
pub(crate) struct OriginalOverlayAckCommitPermit {
    _private: (),
}

/// Actual daemon owners, borrowed rather than captured as current snapshots.
pub(crate) struct OriginalOverlayCurrentOwners<'a> {
    pub(crate) wireguard: &'a crate::transport::WireGuardTransport,
    pub(crate) udp: &'a tokio::sync::RwLock<Option<crate::udp::UdpTransport>>,
    pub(crate) relay: &'a tokio::sync::RwLock<Option<crate::relay::RelayTransport>>,
    pub(crate) room: &'a crate::rooms::RoomAuthorization,
}

impl PeerConnection {
    /// Pure policy shared by the original first-usable callers and native ACK.
    fn verified_first_usable_policy(
        &self,
        generation: u64,
        path: NetworkPath,
        relay_endpoint: Option<&str>,
    ) -> std::result::Result<Option<&'static str>, &'static str> {
        if !self.online || self.state == ConnectionState::Closed {
            return Err("peer_offline_or_closed");
        }
        if path == NetworkPath::Relay
            && !(self.relay_confirmed_generation == Some(generation)
                && relay_endpoint.is_some()
                && self.relay_confirmed_endpoint.as_deref() == relay_endpoint)
        {
            return Err(REASON_FIRST_RELAY_BEFORE_CONFIRMATION);
        }
        if self.is_on_link_direct_for_generation(generation) {
            return Ok(None);
        }
        if path == NetworkPath::Direct && !self.has_current_authoritative_direct(generation) {
            if self.relay_confirmed_generation == Some(generation)
                && self.relay_confirmed_endpoint.is_some()
                && self.relay_first.business_gate_completed_generation != Some(generation)
                && self.relay_first.business_exchange_generation != Some(generation)
            {
                return Err(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS);
            }
            if (self.relay_ready_generation == Some(generation)
                || self.relay_first.gate_generation == Some(generation))
                && self.relay_confirmed_generation != Some(generation)
            {
                let expired = self
                    .relay_ready_at
                    .or(self.relay_first.gate_started_at)
                    .is_some_and(|at| at.elapsed() >= RELAY_FIRST_CONFIRMATION_GRACE);
                return if expired {
                    Ok(Some(REASON_FIRST_DIRECT_AFTER_RELAY_BUSINESS_DEADLINE))
                } else {
                    Err(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS)
                };
            }
        }
        Ok(None)
    }
}

impl PeerManager {
    #[cfg(test)]
    pub(crate) fn with_original_quarantine_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _guard = self.quarantine_deadline_mirror.lock().unwrap();
        operation()
    }

    #[cfg(test)]
    pub(crate) fn with_original_capability_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _guard = self.dplpmtud_capability.gate.lock().unwrap();
        operation()
    }

    /// Captured only by the original exact nonblocking UDP Full minter while
    /// its caller retains epoch. Unknown on contention; no mirror or keeper.
    pub(crate) fn try_original_direct_send_commit(
        &self,
        peer: &str,
        generation: u64,
        endpoint: SocketAddr,
    ) -> Option<u64> {
        let connections = self.connections.try_read().ok()?;
        let conn = connections.get(peer)?;
        (conn.online
            && conn.state == ConnectionState::Direct
            && conn.direct_generation == generation
            && conn.selected_direct_endpoint_for_consent(generation) == Some(endpoint))
        .then_some(conn.direct_commit_seq)
    }

    pub(crate) fn try_commit_original_overlay_ack(
        &self,
        owners: &OriginalOverlayCurrentOwners<'_>,
        request: &CanonicalOverlayRequest,
        ack: &OriginalOverlayAck,
        source: Option<&crate::transport::OriginalOverlayIngressSource>,
    ) -> OverlayCreditOutcome {
        use OverlayCreditOutcome::{Contended, Stale, Unknown};
        if owners.room.enabled() {
            return Unknown(CreditUnknown::RoomAuthority);
        }
        let Some(source) = source else {
            return Unknown(CreditUnknown::OriginalSource);
        };
        let Some(record) = request.physical_publication.record() else {
            return Unknown(CreditUnknown::OriginalPublication);
        };
        if !ack.is_echo()
            || request.original_peer_owner(self).is_none()
            || ack.peer_id != request.peer_id
            || source.session().peer_id() != request.peer_id
            || ack.source_vip != request.target_vip()
            || ack.local_vip != request.local_vip()
            || ack.nonce != request.nonce
            || ack.seq != request.seq
        {
            return Stale(CreditStale::Identity);
        }
        let Some(_emit) = owners
            .wireguard
            .try_acquire_outbound_emit_guard(&request.peer_id)
        else {
            return Contended(CreditLock::Emit);
        };
        let Ok(_epoch) = self.network_epoch_gate.try_lock() else {
            return Contended(CreditLock::Epoch);
        };
        let session = match owners.wireguard.try_original_overlay_session_guard(
            &request.peer_id,
            record.encryption(),
            source.session(),
        ) {
            Ok(guard) => guard,
            Err(crate::transport::OriginalOverlaySessionFailure::Contended) => {
                return Contended(CreditLock::Sessions);
            }
            Err(crate::transport::OriginalOverlaySessionFailure::UnknownAuthorization) => {
                return Unknown(CreditUnknown::OriginalAuthorization);
            }
            Err(crate::transport::OriginalOverlaySessionFailure::Stale) => {
                return Stale(CreditStale::Session);
            }
        };
        let Ok(mut connections) = self.connections.try_write() else {
            return Contended(CreditLock::Connections);
        };
        let membership = match self.peer_membership.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Contended(CreditLock::Membership),
        };
        let lifecycle = membership.active_generation(&request.peer_id);
        drop(membership);
        if lifecycle != Some(session.lifecycle())
            || request.expected_target_lifecycle() != lifecycle
        {
            return Stale(CreditStale::Lifecycle);
        }
        let quarantine = match self.quarantine_deadline_mirror.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Contended(CreditLock::Quarantine),
        };
        let quarantined = quarantine
            .get(&request.peer_id)
            .is_some_and(|at| Instant::now() < *at);
        drop(quarantine);
        if quarantined {
            return Stale(CreditStale::Quarantine);
        }
        let generation = self.current_network_generation_sync();
        if request.generation != generation
            || record.encryption_generation() != generation
            || source.network_generation() != Some(generation)
        {
            return Stale(CreditStale::Generation);
        }
        let Some(conn) = connections.get_mut(&request.peer_id) else {
            return Stale(CreditStale::PeerState);
        };
        if conn.virtual_ip != request.target_vip()
            || !conn.online
            || conn.state == ConnectionState::Closed
        {
            return Stale(CreditStale::PeerState);
        }
        if let Some(tx) = record.udp() {
            if tx.original_direct_commit().is_none() {
                return Unknown(CreditUnknown::OriginalPublication);
            }
            if conn.state != ConnectionState::Direct
                || conn.direct_generation != generation
                || tx.original_direct_commit() != Some(conn.direct_commit_seq)
                || conn.selected_direct_endpoint_for_consent(generation) != Some(tx.endpoint())
            {
                return Stale(CreditStale::DirectPublication);
            }
            if source.original_relay_read().is_some() || source.relay_endpoint().is_some() {
                return Unknown(CreditUnknown::MixedPath);
            }
            let Some(rx) = source.original_udp_read() else {
                return Unknown(CreditUnknown::OriginalSource);
            };
            let Ok(slot) = owners.udp.try_read() else {
                return Contended(CreditLock::UdpSlot);
            };
            let Some(udp) = slot.as_ref() else {
                return Stale(CreditStale::DirectPublication);
            };
            let _publication = match udp.try_original_direct_publication_guard(
                &request.peer_id,
                generation,
                Some(rx),
                Some(tx),
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
            Self::commit_original_overlay_ack_locked(
                conn,
                request,
                ack,
                source,
                record,
                &session,
                NetworkPath::Direct,
                None,
                rx.received_at(),
            )
        } else if let Some(tx) = record.relay() {
            if source.original_udp_read().is_some() {
                return Unknown(CreditUnknown::MixedPath);
            }
            let (Some(rx), Some(id), Some(endpoint)) = (
                source.original_relay_read(),
                source.relay_connection_id(),
                source.relay_endpoint(),
            ) else {
                return Unknown(CreditUnknown::OriginalSource);
            };
            if source.relay_peer_id() != Some(request.peer_id.as_str()) {
                return Stale(CreditStale::Identity);
            }
            let Ok(slot) = owners.relay.try_read() else {
                return Contended(CreditLock::RelaySlot);
            };
            let Some(relay) = slot.as_ref() else {
                return Stale(CreditStale::RelayPublication);
            };
            let member = match relay.try_original_member_guard(tx, rx, id) {
                Ok(guard) => guard,
                Err(crate::relay::RelayMemberFailure::ContendedRoutes) => {
                    return Contended(CreditLock::RelayRoutes)
                }
                Err(crate::relay::RelayMemberFailure::ContendedLive) => {
                    return Contended(CreditLock::RelayLive)
                }
                Err(crate::relay::RelayMemberFailure::UnknownReader) => {
                    return Unknown(CreditUnknown::CrossRelayClient)
                }
                Err(crate::relay::RelayMemberFailure::UnknownWrite) => {
                    return Unknown(CreditUnknown::OriginalPublication)
                }
                Err(_) => return Stale(CreditStale::RelayPublication),
            };
            let _open = match member.try_open_guard() {
                Ok(guard) => guard,
                Err(crate::relay::RelayMemberFailure::ContendedClose) => {
                    return Contended(CreditLock::RelayClose)
                }
                Err(_) => return Stale(CreditStale::RelayPublication),
            };
            if conn.relay_confirmed_connection_id != Some(id) {
                return Stale(CreditStale::Policy);
            }
            Self::commit_original_overlay_ack_locked(
                conn,
                request,
                ack,
                source,
                record,
                &session,
                NetworkPath::Relay,
                Some(endpoint),
                rx.completed_at(),
            )
        } else {
            Unknown(CreditUnknown::OriginalPublication)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_original_overlay_ack_locked(
        conn: &mut PeerConnection,
        request: &CanonicalOverlayRequest,
        _ack: &OriginalOverlayAck,
        source: &crate::transport::OriginalOverlayIngressSource,
        record: &crate::overlay_requests::PhysicalSendRecord,
        session: &crate::transport::OriginalOverlaySessionGuard<'_>,
        path: NetworkPath,
        endpoint: Option<&str>,
        read_at: Instant,
    ) -> OverlayCreditOutcome {
        use OverlayCreditOutcome::{Stale, Unknown};
        let now = Instant::now();
        if !session.is_current() {
            return Stale(CreditStale::Session);
        }
        if !record.matches_original_input(request, now)
            || !crate::request_carriage::in_original_window(request.sent_at, read_at)
            || !crate::request_carriage::in_original_window(
                request.sent_at,
                source.session().authenticated_at(),
            )
        {
            return Stale(CreditStale::OriginalWindow);
        }
        let Some(recorded_at) = request.physical_publication.recorded_observed_at() else {
            return Unknown(CreditUnknown::OriginalPublication);
        };
        if read_at < recorded_at || read_at > source.session().authenticated_at() {
            return Stale(CreditStale::ReadBeforePublication);
        }
        let fallback_reason =
            match conn.verified_first_usable_policy(request.generation, path, endpoint) {
                Ok(reason) => reason,
                Err(_) => return Stale(CreditStale::Policy),
            };
        // Policy evaluation precedes the last time-based checks. No earlier
        // timestamp can extend the original window while guards are acquired.
        let commit_at = Instant::now();
        if !session.is_current() {
            return Stale(CreditStale::Session);
        }
        if !crate::request_carriage::in_original_window(request.sent_at, commit_at) {
            return Stale(CreditStale::OriginalWindow);
        }
        if !request.consume_native_ack_once(OriginalOverlayAckCommitPermit { _private: () }) {
            return OverlayCreditOutcome::AlreadyCommitted;
        }
        // Everything after the once is infallible, synchronous and fixed-size.
        let first_usable_new = conn.record_first_usable(path, request.generation);
        OverlayCreditOutcome::Fresh(OverlayCreditReceipt {
            generation: request.generation,
            path,
            attempt_id: record.attempt_id(),
            committed_at: commit_at,
            first_usable_new,
            fallback_reason,
        })
    }
}
