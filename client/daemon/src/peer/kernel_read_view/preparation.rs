//! Own the original epoch, with an immutable identity-only expectation.
//! Path selection may change paths, nominations and diagnostics, never the
//! generation, membership lifecycle, online status or VIP copied here.
use super::*;
use crate::peer::{DeferredPathSelectionLog, OutboundEpochPhase, PathSelection};
use std::net::SocketAddr;
use std::ops::Deref;

struct ActiveView(Arc<PreparedReadView>);
impl Drop for ActiveView {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
    }
}

pub(crate) struct IdentityPreparationEpoch<'g> {
    // Rust drops fields in declaration order: retire before real unlock,
    // including cancellation. No mutable epoch/connection borrow escapes.
    view: Option<ActiveView>,
    epoch: NetworkEpochGuard<'g>,
    owner: &'g PeerManager,
    prepared: Option<Arc<PreparedReadView>>,
}

impl<'g> Deref for IdentityPreparationEpoch<'g> {
    type Target = NetworkEpochGuard<'g>;
    fn deref(&self) -> &Self::Target {
        &self.epoch
    }
}

impl<'g> IdentityPreparationEpoch<'g> {
    pub(crate) fn begin_encryption(&mut self) {
        if self.view.is_none() {
            self.view = self.prepared.as_ref().and_then(|prepared| {
                self.owner
                    .publish_original_kernel_read_value(&mut self.epoch, prepared)?;
                Some(ActiveView(prepared.clone()))
            });
        }
    }

    pub(crate) fn finish(self) -> NetworkEpochGuard<'g> {
        let Self { view, epoch, .. } = self;
        drop(view);
        epoch
    }
}

impl PeerManager {
    /// Consume the same actual grants and run only the canonical selector.
    /// Its identity-preserving mutations are covered by the epoch owned by
    /// the returned scope; release the connection writer at its old boundary.
    #[cfg(all(unix, test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn select_path_with_original_identity_epoch<'g>(
        &'g self,
        mut epoch: NetworkEpochGuard<'g>,
        mut connections: ConnectionsWriteGuard<'_>,
        prepared: Option<Arc<PreparedReadView>>,
        peer: &str,
        prefer_direct: bool,
        relay_available: bool,
        local_endpoint: Option<SocketAddr>,
        generation: u64,
        force_relay: bool,
        deferred_log: Option<&mut DeferredPathSelectionLog>,
    ) -> Option<(IdentityPreparationEpoch<'g>, PathSelection)> {
        if !epoch.protects(&self.network_epoch_gate) || !connections.protects(&self.connections) {
            return None;
        }
        let view = prepared.as_ref().and_then(|prepared| {
            if prepared.peer != peer
                || !self.capture_original_kernel_read_view_values(
                    &mut epoch,
                    &connections,
                    prepared,
                )
            {
                return None;
            }
            self.publish_original_kernel_read_value(&mut epoch, prepared)?;
            Some(ActiveView(prepared.clone()))
        });
        epoch.note_outbound_phase(OutboundEpochPhase::Path);
        let selection = self.select_path_for_data_with_local_endpoint_in_epoch_with_conns(
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
        Some((
            IdentityPreparationEpoch {
                view,
                epoch,
                owner: self,
                prepared,
            },
            selection,
        ))
    }
}

mod grant;
