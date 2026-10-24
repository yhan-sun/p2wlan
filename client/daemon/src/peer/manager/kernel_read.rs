// Immutable expectation captured by the original system-read observer.
// It retains no peer owner and grants no current-owner or once permission.
pub(crate) struct OriginalKernelReadPeer {
    owner: std::sync::Weak<PeerManager>,
    peer: String,
    target: std::net::Ipv4Addr,
    generation: u64,
    lifecycle: PeerSessionGeneration,
    observed_at: Instant,
}

// This marker satisfies only the peer expectation for retaining actual read
// bytes. It is never accepted by a native/current-owner/once transaction.
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) struct ReadRetentionIdentity {
    _private: (),
}

impl OriginalKernelReadPeer {
    #[cfg(unix)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(unix)]
    pub(crate) fn lifecycle(&self) -> PeerSessionGeneration {
        self.lifecycle
    }

    pub(crate) fn matches_original_encryption(
        &self,
        owner: &std::sync::Weak<PeerManager>,
        generation: u64,
        encryption: &crate::transport::OriginalEncryptionSource,
    ) -> bool {
        self.owner.ptr_eq(owner)
            && self.generation == generation
            && self.peer == encryption.peer_id()
            && Some(self.lifecycle) == encryption.authorized_peer_lifecycle()
            && self.observed_at <= encryption.encrypted_at()
    }

    pub(crate) fn matches_original_ingress(
        &self,
        source: &crate::transport::OriginalOverlayIngressSource,
        before: Instant,
    ) -> bool {
        Some(self.generation) == source.network_generation()
            && self.peer == source.session().peer_id()
            && Some(self.lifecycle) == source.session().authorized_peer_lifecycle()
            && source.session().original_role() == crate::transport::OriginalSessionRole::Active
            && source.session().authenticated_at() <= before
            && before <= self.observed_at
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn matches_original_response(
        &self,
        source: &crate::transport::OriginalOverlayIngressSource,
    ) -> bool {
        Some(self.generation) == source.network_generation()
            && self.peer == source.session().peer_id()
            && Some(self.lifecycle) == source.session().authorized_peer_lifecycle()
            && source.session().original_role() == crate::transport::OriginalSessionRole::Active
            && self.observed_at <= source.session().authenticated_at()
    }

    /// A synchronous identity observation only; callers must still perform the
    /// sole final transaction after every handoff before granting any credit.
    pub(crate) fn try_identity_at(
        &self,
        peers: &PeerManager,
        at: Instant,
    ) -> std::result::Result<(), OverlayCreditOutcome> {
        self.try_identity_at_inner(
            peers,
            at,
            #[cfg(any(target_os = "linux", all(unix, test)))]
            None,
        )
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn try_identity_at_observed(
        &self,
        peers: &PeerManager,
        at: Instant,
        context: Option<crate::peer::EpochTryContext>,
    ) -> std::result::Result<(), OverlayCreditOutcome> {
        if context.is_none() {
            return self.try_identity_at(peers, at);
        }
        self.try_identity_at_inner(peers, at, context)
    }

    /// Retention keeps the same one real identity try. A view observed before
    /// that try may cover only its metadata expectation while the same actual
    /// epoch guard is immutably borrowed for encryption. Final native identity
    /// and once admission continue to use the strict entry points above.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(crate) fn try_read_retention_identity_at_observed(
        &self,
        peers: &PeerManager,
        at: Instant,
        context: Option<crate::peer::EpochTryContext>,
    ) -> std::result::Result<ReadRetentionIdentity, OverlayCreditOutcome> {
        let preobserved = peers.kernel_read_views.observe(&self.peer, self.target);
        match self.try_identity_at_observed(peers, at, context) {
            Ok(()) => Ok(ReadRetentionIdentity { _private: () }),
            Err(error @ OverlayCreditOutcome::Contended(CreditLock::Epoch)) => {
                let compatible = preobserved.is_some_and(|(view, generation, lifecycle)| {
                    generation == self.generation
                        && lifecycle == self.lifecycle
                        && view.is_live(Instant::now())
                });
                if compatible {
                    Ok(ReadRetentionIdentity { _private: () })
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn try_identity_at_inner(
        &self,
        peers: &PeerManager,
        at: Instant,
        #[cfg(any(target_os = "linux", all(unix, test)))] context: Option<
            crate::peer::EpochTryContext,
        >,
    ) -> std::result::Result<(), OverlayCreditOutcome> {
        use OverlayCreditOutcome::Stale;
        if !std::ptr::eq(self.owner.as_ptr(), peers) || at < self.observed_at {
            return Err(Stale(CreditStale::Identity));
        }
        let (generation, lifecycle) = peers.try_kernel_read_peer_values(
            &self.peer,
            self.target,
            #[cfg(any(target_os = "linux", all(unix, test)))]
            context,
        )?;
        if generation != self.generation {
            return Err(Stale(CreditStale::Generation));
        }
        if lifecycle != self.lifecycle {
            return Err(Stale(CreditStale::Lifecycle));
        }
        Ok(())
    }
}

impl PeerManager {
    #[cfg(all(unix, test))]
    pub(crate) fn with_original_kernel_peer_connections_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _held = self.connections.try_write().unwrap();
        operation()
    }

    #[cfg(all(unix, test))]
    pub(crate) fn with_original_kernel_peer_membership_held_for_test<R>(
        &self,
        operation: impl FnOnce() -> R,
    ) -> R {
        let _held = self.peer_membership.try_lock().unwrap();
        operation()
    }

    pub(crate) fn try_capture_original_kernel_read_peer(
        self: &Arc<Self>,
        peer: &str,
        target: std::net::Ipv4Addr,
        #[cfg(any(target_os = "linux", all(unix, test)))] context: Option<
            crate::peer::EpochTryContext,
        >,
    ) -> std::result::Result<OriginalKernelReadPeer, OverlayCreditOutcome> {
        let preobserved = self.kernel_read_views.observe(peer, target);
        let original = self.try_kernel_read_peer_values(
            peer,
            target,
            #[cfg(any(target_os = "linux", all(unix, test)))]
            context,
        );
        let (generation, lifecycle, used_view) = match original {
            Ok((generation, lifecycle)) => (generation, lifecycle, false),
            Err(OverlayCreditOutcome::Contended(CreditLock::Epoch)) => {
                let Some((_, generation, lifecycle)) = preobserved.as_ref() else {
                    return Err(OverlayCreditOutcome::Contended(CreditLock::Epoch));
                };
                (*generation, *lifecycle, true)
            }
            Err(error) => return Err(error),
        };
        let captured = OriginalKernelReadPeer {
            owner: Arc::downgrade(self),
            peer: peer.to_owned(),
            target,
            generation,
            lifecycle,
            observed_at: Instant::now(),
        };
        if used_view
            && !preobserved
                .as_ref()
                .is_some_and(|(view, _, _)| view.is_live(captured.observed_at))
        {
            return Err(OverlayCreditOutcome::Contended(CreditLock::Epoch));
        }
        Ok(captured)
    }

    fn try_kernel_read_peer_values(
        &self,
        peer: &str,
        target: std::net::Ipv4Addr,
        #[cfg(any(target_os = "linux", all(unix, test)))] context: Option<
            crate::peer::EpochTryContext,
        >,
    ) -> std::result::Result<(u64, PeerSessionGeneration), OverlayCreditOutcome> {
        use OverlayCreditOutcome::Contended;
        #[cfg(any(target_os = "linux", all(unix, test)))]
        let _epoch = self
            .network_epoch_gate
            .try_lock_original(context)
            .map_err(|_| Contended(CreditLock::Epoch))?;
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        let _epoch = self
            .network_epoch_gate
            .try_lock()
            .map_err(|_| Contended(CreditLock::Epoch))?;
        self.try_kernel_read_peer_values_in_epoch(&_epoch, peer, target)
    }

    fn try_kernel_read_peer_values_in_epoch(
        &self,
        _epoch: &tokio::sync::MutexGuard<'_, ()>,
        peer: &str,
        target: std::net::Ipv4Addr,
    ) -> std::result::Result<(u64, PeerSessionGeneration), OverlayCreditOutcome> {
        use OverlayCreditOutcome::{Contended, Stale};
        let connections = self
            .connections
            .try_read()
            .map_err(|_| Contended(CreditLock::Connections))?;
        let membership = self
            .peer_membership
            .try_lock()
            .map_err(|_| Contended(CreditLock::Membership))?;
        let lifecycle = membership
            .active_generation(peer)
            .filter(|value| *value != PeerSessionGeneration::UNBOUND)
            .ok_or(Stale(CreditStale::Lifecycle))?;
        connections
            .get(peer)
            .filter(|connection| {
                connection.online
                    && connection.state != ConnectionState::Closed
                    && connection.virtual_ip.parse::<std::net::Ipv4Addr>() == Ok(target)
            })
            .ok_or(Stale(CreditStale::PeerState))?;
        Ok((self.current_network_generation_sync(), lifecycle))
    }
}
