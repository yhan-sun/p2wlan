//! Bind the same expectation at the original two-lock grant, before caller
//! profiling or generation checks. No identity mutation is admitted here.
use super::*;
use std::time::Instant;

pub(crate) struct IdentityPreparationGrant<'g> {
    // Release the writer before retiring the view and unlocking the epoch.
    connections: ConnectionsWriteGuard<'g>,
    scope: IdentityPreparationEpoch<'g>,
    acquired: Instant,
}

impl IdentityPreparationGrant<'_> {
    pub(crate) fn acquired_at(&self) -> Instant {
        self.acquired
    }
    pub(crate) fn current_generation(&self) -> u64 {
        self.scope.owner.current_network_generation_sync()
    }
}

impl<'g> IdentityPreparationGrant<'g> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn select(
        self,
        peer: &str,
        prefer_direct: bool,
        relay_available: bool,
        local_endpoint: Option<SocketAddr>,
        generation: u64,
        force_relay: bool,
        deferred_log: Option<&mut DeferredPathSelectionLog>,
    ) -> (IdentityPreparationEpoch<'g>, PathSelection) {
        let Self {
            mut connections,
            mut scope,
            ..
        } = self;
        if scope
            .prepared
            .as_ref()
            .is_some_and(|prepared| prepared.peer != peer)
        {
            drop(scope.view.take());
        }
        scope.note_outbound_phase(OutboundEpochPhase::Path);
        let selection = scope
            .owner
            .select_path_for_data_with_local_endpoint_in_epoch_with_conns(
                &mut connections,
                peer,
                prefer_direct,
                relay_available,
                local_endpoint,
                generation,
                force_relay,
                deferred_log,
            );
        drop(connections);
        (scope, selection)
    }
}

impl PeerManager {
    #[track_caller]
    pub(crate) fn lock_original_identity_preparation(
        &self,
        prepared: Option<Arc<PreparedReadView>>,
    ) -> impl std::future::Future<Output = IdentityPreparationGrant<'_>> + '_ {
        self.lock_epoch_and_connections_write_with(move |mut epoch, connections| {
            let acquired = Instant::now();
            let view = prepared.as_ref().and_then(|prepared| {
                if !self.capture_original_kernel_read_view_values(
                    &mut epoch,
                    &connections,
                    prepared,
                ) {
                    return None;
                }
                self.publish_original_kernel_read_value(&mut epoch, prepared)?;
                Some(ActiveView(prepared.clone()))
            });
            epoch.note_outbound_phase(OutboundEpochPhase::Generation);
            IdentityPreparationGrant {
                connections,
                scope: IdentityPreparationEpoch {
                    view,
                    epoch,
                    owner: self,
                    prepared,
                },
                acquired,
            }
        })
    }
}
