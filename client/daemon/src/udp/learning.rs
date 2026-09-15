use super::*;

/// Adaptive-prediction learner state for one network generation, scoped by
/// destination so a stride learned toward STUN observers is not blindly applied
/// to a real peer (audit P1-B: complex CGNAT may bucket allocation by target;
/// Mini-Air observed the peer-facing mapping diverge from the STUN direction).
#[derive(Debug)]
pub(super) struct LearningCache {
    /// The network generation this cache was last synced to; any other value
    /// forces a full reset (a new allocator invalidates every learned stride
    /// and direction).
    network_generation: u64,
    /// (destination scope) -> (cross-batch step learner, direction detector).
    /// The scope separates STUN-observer allocation from per-peer allocation so
    /// a peer whose real direction differs from the STUN direction is not
    /// dragged toward the STUN-learned stride.
    entries: HashMap<DestinationScope, (StepLearner, ReverseDetector)>,
}

/// The destination an allocation-sequence measurement was taken toward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum DestinationScope {
    /// The measurement was a batch of STUN-observer requests on a fresh socket.
    /// This is the shared prior used when no peer-scope evidence exists.
    Stun,
    /// The measurement/observation was toward one specific peer (its actual
    /// mapping port observed on the wire).  Peer-scope evidence, when present,
    /// is authoritative for that peer over the STUN prior.
    Peer(String),
}

impl LearningCache {
    /// An empty cache that resets on first use (its generation starts out of
    /// sync with any real one).
    pub(super) fn new() -> Self {
        Self {
            network_generation: u64::MAX,
            entries: HashMap::new(),
        }
    }

    /// Drop all learned state when the network generation moved on.
    pub(super) fn reset_if_generation_changed(&mut self, generation: u64) {
        if generation != self.network_generation {
            self.entries.clear();
            self.network_generation = generation;
        }
    }

    pub(super) fn entry(&mut self, scope: DestinationScope) -> &mut (StepLearner, ReverseDetector) {
        self.entries
            .entry(scope)
            .or_insert_with(|| (StepLearner::new(), ReverseDetector::new()))
    }

    /// The peer-scope learner for `peer_id`, or `None` when no peer-scope
    /// evidence was ever observed for it.
    pub(super) fn peer_scope(&self, peer_id: &str) -> Option<&(StepLearner, ReverseDetector)> {
        self.entries
            .get(&DestinationScope::Peer(peer_id.to_string()))
    }
}

/// A point-in-time read of the adaptive learner for one public IP, used both as
/// the predictor input and as the fields logged/recorded for diagnostics.
#[derive(Debug, Clone, Copy)]
pub(super) struct LearningSnapshot {
    /// Cross-batch EWMA stride estimate (signed — a reverse allocator learns a
    /// negative stride) when the learner has a valid reading, else `None`.  A
    /// `Some(0)` reading is a no-consensus placeholder the predictor treats as
    /// "no useful stride".
    pub(super) step_estimate: Option<i16>,
    /// How many times the estimate changed (learning trajectory).
    pub(super) revision_count: u32,
    /// Detected allocation direction of the peer's fresh mappings.
    pub(super) direction: DirectionPattern,
}

pub(super) fn model_deltas(batch: &MappingBatch) -> Vec<i16> {
    let ports = batch.ordered_ports();
    ports
        .windows(2)
        .map(|pair| p2pnet_nat::modular_difference(pair[0], pair[1]))
        .collect()
}

/// Whether a target endpoint may receive a fresh-mapping punch.
///
/// Production filters to real public probe endpoints; unit tests simulate the
/// peer's public side on the loopback NAT address, and the NAT-sim harness
/// (`config.network.fresh_mapping_harness_loopback`) deliberately allows
/// loopback endpoints so the deterministic dual-NAT simulation exercises the
/// production fresh path.
pub(super) fn fresh_mapping_target_eligible(endpoint: SocketAddr, allow_loopback: bool) -> bool {
    if is_public_probe_endpoint(endpoint) {
        return true;
    }
    if allow_loopback && endpoint.ip().is_loopback() {
        return true;
    }
    #[cfg(test)]
    {
        endpoint.ip().is_loopback()
    }
    #[cfg(not(test))]
    {
        let _ = endpoint;
        false
    }
}

impl UdpTransport {
    /// Fold one fresh-mapping batch into the shared adaptive learner for its
    /// egress public IP and return a point-in-time snapshot to feed the
    /// predictor.
    ///
    /// The observed ports are streamed into the direction detector and the
    /// model's positive deltas into the step learner (negative deltas carry no
    /// forward-stride information; the detector already captures the direction
    /// from the ports themselves).  A network-generation change clears every
    /// learned stride and direction first, so a stale reading is never applied
    /// to a new allocator.
    /// Fold a STUN measurement batch into the adaptive learner and return a
    /// point-in-time snapshot to feed the predictor.
    ///
    /// The observed ports are streamed into the direction detector and the
    /// model's deltas into the step learner.  This is the STUN-observer scope:
    /// it is the shared prior.  A peer whose real allocation direction was
    /// observed on the wire (see [`Self::observe_peer_scope`]) gets its own
    /// peer scope and the predictor prefers that evidence (audit P1-B).
    /// A network-generation change clears every learned state first, so a
    /// stale reading is never applied to a new allocator.
    pub(super) async fn observe_learning(
        &self,
        ports: &[u16],
        model: &PortModel,
        network_generation: u64,
    ) -> LearningSnapshot {
        let mut cache = self.learning_cache.lock().await;
        cache.reset_if_generation_changed(network_generation);
        let (step_learner, detector) = cache.entry(DestinationScope::Stun);
        for port in ports {
            detector.observe_port(*port);
        }
        for delta in &model.deltas {
            step_learner.observe_diff(*delta);
        }
        let step_estimate = step_learner.estimate();
        let direction = detector.pattern();
        LearningSnapshot {
            step_estimate,
            revision_count: step_learner.revision_count(),
            direction,
        }
    }

    /// Fold one real peer-scope allocation observation (the peer's actual
    /// public mapping port, learned from the wire) into a per-peer direction
    /// detector.
    ///
    /// The peer scope is authoritative for that peer over the STUN prior: a
    /// complex CGNAT can allocate toward STUN observers differently than toward
    /// the real peer, so once a peer's true direction is observed it must not
    /// be dragged back toward the STUN-learned stride (audit P1-B).
    pub(super) async fn observe_peer_scope(
        &self,
        peer_id: &str,
        observed_port: u16,
        network_generation: u64,
    ) {
        let mut cache = self.learning_cache.lock().await;
        cache.reset_if_generation_changed(network_generation);
        let (_, detector) = cache.entry(DestinationScope::Peer(peer_id.to_string()));
        // The peer's observed ports, in observation order, feed the direction
        // detector.  The stride learner is deliberately not fed here: a single
        // wire observation cannot pin a stride, and the predictor already
        // guards the direction conflict at P0-1 (current batch wins).  The
        // peer-scope *direction* is the new, authoritative signal.
        detector.observe_port(observed_port);
    }

    /// Read the peer-scope learning snapshot for `peer_id`, or fall back to the
    /// STUN prior when no peer-scope evidence exists.
    pub(super) async fn peer_learning_snapshot(
        &self,
        peer_id: &str,
        network_generation: u64,
    ) -> Option<LearningSnapshot> {
        let cache = self.learning_cache.lock().await;
        if cache.network_generation != network_generation {
            return None;
        }
        let (_, detector) = cache.peer_scope(peer_id)?;
        Some(LearningSnapshot {
            step_estimate: None,
            revision_count: 0,
            direction: detector.pattern(),
        })
    }

    /// Test-only presence check for the STUN-scope adaptive learner, syncing
    /// the cache to `network_generation` first (the same lazy reset the
    /// production path performs).  Returns `false` when the STUN scope has no
    /// learned state for the requested generation — i.e. the cache was reset or
    /// never fed.
    #[cfg(test)]
    pub(crate) async fn has_learning_for(&self, ip: IpAddr, network_generation: u64) -> bool {
        let _ = ip;
        let mut cache = self.learning_cache.lock().await;
        cache.reset_if_generation_changed(network_generation);
        cache.entries.contains_key(&DestinationScope::Stun)
    }
}
