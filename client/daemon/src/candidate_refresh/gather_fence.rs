/// Identity of the committed candidate state from which one unlocked gather
/// started. A later gather or peer-reflexive publication must not be replaced
/// by this older result just because its gateway discovery completed last.
#[derive(Debug, Clone, Copy)]
pub(super) struct CandidateGatherFence {
    snapshot_version: Option<u64>,
    network_generation: u64,
    transport_instance: u64,
    publication_owner: u64,
    local_addr: Option<SocketAddr>,
}

impl CandidateGatherFence {
    pub(super) async fn capture(
        _refresh_guard: &tokio::sync::MutexGuard<'_, ()>,
        udp: &UdpTransport,
        peers: &PeerManager,
        snapshots: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    ) -> Self {
        let snapshot_version = snapshots
            .read()
            .await
            .as_ref()
            .map(|snapshot| snapshot.version);
        Self {
            snapshot_version,
            network_generation: peers.current_network_generation_sync(),
            transport_instance: udp.transport_instance_id(),
            publication_owner: udp.inbound_publication_owner(),
            local_addr: udp.local_addr().ok(),
        }
    }

    /// The caller keeps the existing refresh lock through the ensuing local
    /// profile/candidate commit, so a checked snapshot version cannot change
    /// between this comparison and that commit. Generation and publication
    /// checks also reject changes during discovery; they do not claim to make
    /// the existing later generation-advance/publication path one transaction.
    pub(super) async fn stale_reason(
        &self,
        _refresh_guard: &tokio::sync::MutexGuard<'_, ()>,
        udp: &UdpTransport,
        peers: &PeerManager,
        snapshots: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    ) -> Option<&'static str> {
        let snapshot_version = snapshots
            .read()
            .await
            .as_ref()
            .map(|snapshot| snapshot.version);
        self.stale_reason_for_commit(snapshot_version, udp, peers)
    }

    /// Synchronous recheck while the caller already holds the snapshot writer
    /// and authoritative publication/epoch guards for a local commit.
    pub(super) fn stale_reason_for_commit(
        &self,
        snapshot_version: Option<u64>,
        udp: &UdpTransport,
        peers: &PeerManager,
    ) -> Option<&'static str> {
        if self.publication_owner == 0 {
            return Some("udp_transport_unpublished");
        }
        if snapshot_version != self.snapshot_version {
            Some("candidate_snapshot_replaced")
        } else if peers.current_network_generation_sync() != self.network_generation {
            Some("network_generation_changed")
        } else if udp.transport_instance_id() != self.transport_instance
            || udp.inbound_publication_owner() != self.publication_owner
            || udp.local_addr().ok() != self.local_addr
        {
            Some("udp_transport_replaced")
        } else {
            None
        }
    }
}
