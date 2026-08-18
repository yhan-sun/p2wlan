use p2pnet_nat::mapping::PortModel;

/// Local fresh-mapping state for one peer, produced by the most recent
/// measure-then-punch generation.
#[derive(Debug, Clone)]
pub(crate) struct LocalFreshMapping {
    /// Per-peer punch generation counter.
    pub punch_generation: u64,
    /// Local network generation the measurement ran in.
    pub network_generation: u64,
    /// Dedicated punch socket local endpoint.
    pub socket_local_endpoint: SocketAddr,
    /// Port-allocation model inferred from the send-ordered STUN sequence.
    pub model: PortModel,
    /// Rank-ordered predicted public ports (rank 0 = top-1).
    pub predicted_ports: Vec<u16>,
    /// Public IP the mapping belongs to.
    pub public_ip: Option<IpAddr>,
    /// Monotonic creation time for staleness checks.
    pub created_at: Instant,
}

/// Outcome of comparing an actually learned peer-reflexive port with the
/// model prediction.
#[derive(Debug, Clone)]
pub(crate) struct FreshMappingPredictionResult {
    pub punch_generation: u64,
    pub predicted_top_port: Option<u16>,
    pub actual_port: u16,
    /// Signed error = actual - predicted (wrap-aware).
    pub error: i32,
    pub model_label: String,
    pub confidence: u8,
    pub window_ports: Vec<u16>,
    pub hit_window: bool,
    /// 0-indexed position of the actually-learned port within the rank-ordered
    /// prediction window, or `None` when it fell outside the window.  This is
    /// the per-hit calibration signal: `hit_window` only says in/out, while the
    /// rank tells how well-ordered the window was (top-1 vs. deep-in-window).
    pub hit_rank: Option<u8>,
    /// Whether this observation landed in each calibration prefix.
    pub hit_top1: bool,
    pub hit_top6: bool,
    pub hit_top24: bool,
    pub hit_top96: bool,
}

const FRESH_MAPPING_STATE_MAX_AGE: Duration = Duration::from_secs(30);
const FRESH_MAPPING_RESULT_HISTORY_PER_PEER: usize = 8;

/// Whether a remote fresh-mapping prediction identity was admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteFreshAdmission {
    /// The (incarnation, generation) is newer than the high-water: its
    /// candidates may be applied, and the identity is committed only after
    /// the apply really succeeded (prepare/apply/commit transaction).
    Accepted,
    /// The identity is exactly the current high-water and the payload is
    /// byte-identical (candidates, sources, expiry) to the snapshot the
    /// identity was committed with: an idempotent retry of an already-applied
    /// prediction.  The fresh punch may start from the COMMITTED snapshot.
    AlreadyRecorded,
    /// The identity equals the high-water but the payload differs from the
    /// snapshot the identity was committed with.  A retry must never apply
    /// different candidates under the same identity: rejected.
    PayloadMismatch,
    /// The identity is older than the high-water (a superseded prediction
    /// sent late); its candidates must not be applied.
    Stale,
}

/// The immutable candidate snapshot one fresh-prediction identity was
/// committed with.  Bound to the identity at commit time: an idempotent
/// retry of the same identity can only ever punch toward this snapshot, and a
/// retry whose payload differs is rejected instead of applied.
#[derive(Debug, Clone)]
pub(crate) struct FreshPredictionSnapshot {
    /// The candidate payload the identity was committed with: an idempotent
    /// retry can only ever punch toward this snapshot.
    pub(crate) candidates: Vec<String>,
    /// Only candidates carrying this prediction identity are valid fresh
    /// punch targets. Ordinary candidates may remain in `candidates` for
    /// signaling compatibility, but must not expand the synchronized fresh
    /// window back into a full 96-entry sweep.
    pub(crate) fresh_candidates: Vec<String>,
    /// Fingerprint of the full payload (candidates + sources + expiry); the
    /// retry verification compares hashes, never re-applies the payload.
    pub(crate) payload_hash: [u8; 32],
    /// The expiry deadline (receiver-local clock) the identity was committed
    /// with, so an idempotent retry can never punch toward an expired
    /// prediction and a retry whose expiry differs is rejected.
    pub(crate) candidates_expires_at_ms: Option<u64>,
}

/// Deterministic, stable, collision-resistant payload fingerprint for one
/// fresh signal.
///
/// The fingerprint identifies the exact payload (candidates + sources +
/// expiry) a fresh identity was committed with, so a retry's payload can be
/// compared against the committed snapshot without shipping the whole
/// candidate set around.  The digest is a fixed-key BLAKE2b-256 over the
/// normalized (sorted) payload: it is byte-stable across processes and
/// machines, and 256 bits of keyed-away digest are immune to the
/// accidental-collision concerns of a 64-bit `DefaultHasher` (whose output
/// must never be the sole identity of a payload a receiver acts on).
pub(crate) fn fresh_payload_hash(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    candidates_expires_at_ms: Option<u64>,
) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(32).expect("blake2b-256 output size");
    let mut sorted = candidates.to_vec();
    sorted.sort();
    for candidate in &sorted {
        hasher.update(candidate.as_bytes());
        hasher.update(&[0xff]);
        if let Some(source) = candidate_sources.get(candidate) {
            hasher.update(source.as_bytes());
        }
        hasher.update(&[0xfe]);
    }
    match candidates_expires_at_ms {
        Some(expires_at) => hasher.update(&expires_at.to_be_bytes()),
        None => hasher.update(&[0x00]),
    }
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("blake2b-256 finalize");
    digest
}

/// Shared peer-connection state one fresh apply overwrote, captured at apply
/// time so a losing commit's rollback can restore or precisely remove exactly
/// its own contributions without clobbering a later (winning) apply.
#[derive(Debug, Clone)]
pub(crate) struct FreshApplyPreviousState {
    /// `conn.last_candidate_generation` before this apply.
    pub(crate) last_candidate_generation: u64,
    /// `conn.last_candidates_expires_at_ms` before this apply.
    pub(crate) last_candidates_expires_at_ms: Option<u64>,
}

/// A fresh apply recorded before its commit: the candidates this apply
/// installed (for the rollback), the payload (for the committed snapshot),
/// the candidate generation this apply advanced the peer's high-water to,
/// and the previous shared state the apply overwrote.
#[derive(Debug, Clone)]
pub(crate) struct PendingFreshApply {
    pub(crate) candidates: Vec<String>,
    pub(crate) fresh_candidates: Vec<String>,
    pub(crate) payload_hash: [u8; 32],
    pub(crate) candidates_expires_at_ms: Option<u64>,
    /// The candidate generation value this apply set on the connection (0
    /// when the apply did not advance it).
    pub(crate) candidate_generation: u64,
    /// Shared state the apply overwrote, restored by the losing commit's
    /// rollback only while it still equals what this apply set.
    pub(crate) previous: FreshApplyPreviousState,
}

impl PeerManager {
    /// Whether the NAT-sim harness allows loopback endpoints in the
    /// fresh-mapping flow.
    pub(crate) async fn fresh_mapping_harness_loopback_enabled(&self) -> bool {
        self.config.network.fresh_mapping_harness_loopback
    }

    /// Whether the local socket address is gathered as a Host candidate.
    pub(crate) async fn gather_host_candidates(&self) -> bool {
        self.config.network.gather_host_candidates
    }

    /// Whether extrapolated server-reflexive candidates may be advertised.
    pub(crate) async fn predicted_candidates_enabled(&self) -> bool {
        self.config.network.predicted_candidates_enabled
    }

    /// Whether the local NAT profile needs fresh-socket mapping prediction.
    ///
    /// Endpoint-independent / open NATs have a stable public port; only
    /// address/port-dependent (symmetric-class) mappings benefit from the
    /// measure-then-punch generation.  The NAT-sim harness forces the fresh
    /// path on so the deterministic dual-NAT simulation exercises it, unless
    /// an explicit experiment has disabled the strategy.
    pub(crate) async fn local_nat_requires_fresh_mapping_punch(&self) -> bool {
        if !self.config.network.fresh_mapping_punch_enabled {
            return false;
        }
        if self.fresh_mapping_harness_loopback_enabled().await {
            return true;
        }
        self.local_nat_profile
            .read()
            .await
            .as_ref()
            .is_some_and(|profile| {
                !profile.udp_blocked
                    && matches!(
                        profile.mapping_behavior,
                        MappingBehavior::AddressOrPortDependent
                    )
            })
    }

    /// Allocate the next per-peer punch generation number.
    pub(crate) async fn next_punch_generation(&self, peer_id: &str) -> u64 {
        let mut generations = self.punch_generations.write().await;
        let next = generations.get(peer_id).copied().unwrap_or(0).wrapping_add(1);
        generations.insert(peer_id.to_string(), next);
        next
    }

    /// Record the outcome of a successful fresh-mapping generation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn record_fresh_mapping(
        &self,
        peer_id: &str,
        model: PortModel,
        predicted_ports: Vec<u16>,
        socket_local_endpoint: SocketAddr,
        public_ip: Option<IpAddr>,
        punch_generation: u64,
        network_generation: u64,
    ) {
        let mut mappings = self.local_fresh_mappings.write().await;
        // A stale generation that completed late must never overwrite the
        // fresh state a newer generation already recorded.
        if mappings
            .get(peer_id)
            .is_some_and(|existing| existing.punch_generation > punch_generation)
        {
            return;
        }
        mappings.insert(
            peer_id.to_string(),
            LocalFreshMapping {
                punch_generation,
                network_generation,
                socket_local_endpoint,
                model,
                predicted_ports,
                public_ip,
                created_at: Instant::now(),
            },
        );
    }

    /// Prepare the admission of a fresh-mapping prediction identity signaled
    /// by the remote, WITHOUT mutating the high-water.
    ///
    /// Only a strictly newer (incarnation, generation) may be applied; an
    /// equal identity is an idempotent retry — admitted only when the retry's
    /// payload is byte-identical (candidates, sources, expiry) to the
    /// snapshot the identity was committed with, because a retry must never
    /// apply different candidates under the same identity.  An older identity
    /// is a superseded prediction sent late.  The high-water only advances in
    /// [`Self::commit_remote_fresh_prediction`] after the candidates were
    /// really applied, so a signal whose apply fails (peer missing, empty
    /// set, expired set, stale candidate generation) never consumes the
    /// identity and a later retry can still succeed.
    pub(crate) async fn prepare_remote_fresh_prediction(
        &self,
        peer_id: &str,
        id: crate::FreshPredictionId,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidates_expires_at_ms: Option<u64>,
    ) -> RemoteFreshAdmission {
        let payload_hash =
            fresh_payload_hash(candidates, candidate_sources, candidates_expires_at_ms);
        let high_water = self
            .remote_fresh_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match high_water.get(peer_id).copied() {
            None => RemoteFreshAdmission::Accepted,
            Some(current) if id > current => RemoteFreshAdmission::Accepted,
            Some(current) if id == current => {
                // Idempotent retry: the payload must match the snapshot the
                // identity was committed with.
                let snapshots = self
                    .remote_fresh_snapshots
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match snapshots.get(&(peer_id.to_string(), id)) {
                    Some(snapshot) if snapshot.payload_hash == payload_hash => {
                        RemoteFreshAdmission::AlreadyRecorded
                    }
                    Some(_) => RemoteFreshAdmission::PayloadMismatch,
                    None => {
                        // The identity is committed but no snapshot survived
                        // (state reset by an identity change): a retry cannot
                        // be verified against anything, so it is rejected
                        // rather than applied blind.
                        RemoteFreshAdmission::PayloadMismatch
                    }
                }
            }
            Some(_) => RemoteFreshAdmission::Stale,
        }
    }

    /// Apply the fresh signal's candidates and record the apply so the
    /// commit can either promote it to the durable snapshot or roll it back.
    ///
    /// The apply captures the shared state it overwrites (the peer's
    /// candidate-generation high-water and expiry) so a losing commit can
    /// restore or precisely remove exactly its own contributions.  The
    /// pre-apply shared candidate set is not restored wholesale: the
    /// prepare/apply/commit sequence is serialized by the control event loop,
    /// and when two applies DO run concurrently the loser's rollback removes
    /// only the candidates this apply installed that the winner's committed
    /// snapshot does not contain (see [`Self::rollback_remote_fresh_apply`]).
    pub(crate) async fn apply_remote_fresh_candidates(
        &self,
        peer_id: &str,
        id: crate::FreshPredictionId,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
    ) -> CandidateSetApplyResult {
        let (previous_generation, previous_expiry) = {
            let conns = self.connections.read().await;
            conns
                .get(peer_id)
                .map(|conn| {
                    (
                        conn.last_candidate_generation,
                        conn.last_candidates_expires_at_ms,
                    )
                })
                .unwrap_or((0, None))
        };
        let result = self
            .add_candidates_with_metadata(
                peer_id,
                candidates,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
            )
            .await;
        if result == CandidateSetApplyResult::Applied {
            let payload_hash =
                fresh_payload_hash(candidates, candidate_sources, candidates_expires_at_ms);
            let fresh_label = crate::fresh_prediction_source_label(id);
            let fresh_candidates = candidates
                .iter()
                .filter(|candidate| candidate_sources.get(*candidate) == Some(&fresh_label))
                .cloned()
                .collect();
            self.pending_fresh_applies
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    (peer_id.to_string(), id),
                    PendingFreshApply {
                        candidates: candidates.to_vec(),
                        fresh_candidates,
                        payload_hash,
                        candidates_expires_at_ms,
                        candidate_generation,
                        previous: FreshApplyPreviousState {
                            last_candidate_generation: previous_generation,
                            last_candidates_expires_at_ms: previous_expiry,
                        },
                    },
                );
        }
        result
    }

    /// Commit a fresh-mapping prediction identity as the peer's high-water
    /// and freeze its immutable candidate snapshot.
    ///
    /// The high-water CAS, the pending-apply promotion and the snapshot
    /// freeze are ONE lock transaction (high-water -> pending -> snapshots,
    /// the same order `prepare` uses for high-water -> snapshots): a retry
    /// of the identity can never observe "high-water advanced but snapshot
    /// missing".  The commit only succeeds when the apply was really
    /// recorded: without a pending apply there is no payload to freeze, so
    /// the high-water does NOT advance and the identity stays unconsumed for
    /// a later retry.  Exactly one concurrent commit of an identity wins; the
    /// loser must roll its own apply back.
    ///
    /// Only the current high-water's snapshot is retained: every older
    /// snapshot for the peer is pruned here, so the snapshot map cannot grow
    /// without bound across identities.
    pub(crate) async fn commit_remote_fresh_prediction(
        &self,
        peer_id: &str,
        id: crate::FreshPredictionId,
    ) -> bool {
        let mut high_water = self
            .remote_fresh_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match high_water.get(peer_id).copied() {
            Some(current) if id <= current => return false,
            _ => {}
        }
        let apply = {
            let mut pending = self
                .pending_fresh_applies
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // The apply must have been recorded for the SAME identity: a
            // commit without a recorded apply has no payload to freeze and
            // must not advance the high-water.
            let Some(apply) = pending.remove(&(peer_id.to_string(), id)) else {
                return false;
            };
            apply
        };
        high_water.insert(peer_id.to_string(), id);
        let mut snapshots = self
            .remote_fresh_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Freeze the committed snapshot and prune every older snapshot for
        // this peer: only the current high-water's snapshot is ever needed.
        snapshots.retain(|(owner, snapshot_id), _| owner != peer_id || *snapshot_id == id);
        snapshots.insert(
            (peer_id.to_string(), id),
            FreshPredictionSnapshot {
                candidates: apply.candidates,
                fresh_candidates: apply.fresh_candidates,
                payload_hash: apply.payload_hash,
                candidates_expires_at_ms: apply.candidates_expires_at_ms,
            },
        );
        true
    }

    /// Roll back an apply whose commit lost the CAS: remove precisely the
    /// state this apply caused that a later (winning) apply did not re-own.
    ///
    /// - The candidate-generation high-water and the expiry are restored to
    ///   their pre-apply values ONLY while they still equal what this apply
    ///   set (a later apply that advanced them is untouched).
    /// - The candidates this apply installed are removed only while they are
    ///   still labeled `Predicted` AND are absent from the winner's committed
    ///   snapshot: a candidate the winner re-signaled must survive, so a
    ///   losing apply can never tear down the winning prediction's set.
    pub(crate) async fn rollback_remote_fresh_apply(
        &self,
        peer_id: &str,
        id: crate::FreshPredictionId,
    ) {
        let Some(pending) = self
            .pending_fresh_applies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(peer_id.to_string(), id))
        else {
            return;
        };
        // The winner's committed snapshot bounds the rollback: a candidate
        // the winner re-signaled must never be removed by the loser.  The
        // lock order is high-water -> snapshots, matching `commit`.
        let winner_candidates = {
            let high_water = self
                .remote_fresh_generations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let winner_id = high_water.get(peer_id).copied().unwrap_or(id);
            drop(high_water);
            self.remote_fresh_snapshots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&(peer_id.to_string(), winner_id))
                .map(|snapshot| snapshot.candidates.clone())
                .unwrap_or_default()
        };
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(peer_id) else {
            return;
        };
        // Restore the high-water and expiry only while they still equal what
        // THIS apply set: a later (winning) apply owns them otherwise.
        if pending.candidate_generation != 0
            && conn.last_candidate_generation == pending.candidate_generation
        {
            conn.last_candidate_generation = pending.previous.last_candidate_generation;
        }
        if conn.last_candidates_expires_at_ms == pending.candidates_expires_at_ms {
            conn.last_candidates_expires_at_ms = pending.previous.last_candidates_expires_at_ms;
        }
        for candidate in &pending.candidates {
            let re_owned_by_winner = winner_candidates.contains(candidate);
            if !re_owned_by_winner
                && conn.candidate_sources.get(candidate) == Some(&CandidatePairSource::Predicted)
            {
                conn.candidates.retain(|existing| existing != candidate);
                conn.candidate_sources.remove(candidate);
                conn.signaled_candidates.remove(candidate);
                conn.candidate_pairs.retain(|pair| {
                    !(pair.source == CandidatePairSource::Predicted
                        && pair.remote_endpoint.to_string() == *candidate)
                });
            }
        }
    }

    /// The immutable committed snapshot for a fresh identity, if any.
    pub(crate) async fn remote_fresh_snapshot_for(
        &self,
        peer_id: &str,
        id: crate::FreshPredictionId,
    ) -> Option<FreshPredictionSnapshot> {
        self.remote_fresh_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&(peer_id.to_string(), id))
            .cloned()
    }

    /// Reset the remote fresh-generation high-water for a peer.
    ///
    /// Called on public-key identity change and other explicit identity
    /// resets: a new peer incarnation starts a fresh generation space, so the
    /// next prediction signal is accepted regardless of what the old
    /// incarnation sent.  A plain PeerLeft deliberately does NOT clear the
    /// high-water (see `remove_peer`): a late old-incarnation signal must
    /// stay rejected after the peer rejoins, and the new incarnation's
    /// strictly-monotonic counter supersedes it anyway.
    pub(crate) async fn reset_remote_fresh_generation(&self, peer_id: &str, reason: &str) {
        let removed = self
            .remote_fresh_generations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(peer_id)
            .is_some();
        self.remote_fresh_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(owner, _), _| owner != peer_id);
        self.pending_fresh_applies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|(owner, _), _| owner != peer_id);
        if removed {
            info!(
                event = "remote_fresh_generation_reset",
                peer_id = %peer_id,
                reason = %reason,
                "remote_fresh_generation_reset peer_id={} reason={}",
                peer_id,
                reason
            );
        }
    }

    /// Current fresh-mapping state for a peer, when still fresh and valid for
    /// the current network generation.
    pub(crate) async fn fresh_mapping_for_peer(&self, peer_id: &str) -> Option<LocalFreshMapping> {
        let generation = self.current_network_generation().await;
        let state = self.local_fresh_mappings.read().await.get(peer_id)?.clone();
        (state.created_at.elapsed() <= FRESH_MAPPING_STATE_MAX_AGE
            && state.network_generation == generation)
            .then_some(state)
    }

    /// Invalidate the fresh-mapping state for one peer.
    pub(crate) async fn clear_fresh_mapping(&self, peer_id: &str, reason: &str) {
        if self.local_fresh_mappings.write().await.remove(peer_id).is_some() {
            info!(
                event = "fresh_mapping_invalidated",
                peer_id = %peer_id,
                reason = %reason,
                "fresh_mapping_invalidated peer_id={} reason={}",
                peer_id,
                reason
            );
            self.record_direct_event(
                peer_id,
                "fresh_mapping_invalidated",
                None,
                None,
                None,
                format!("fresh-mapping model invalidated: {reason}"),
            )
            .await;
        }
    }

    /// Invalidate every fresh-mapping model after a local network generation
    /// change, socket rebuild or public-IP change.
    pub(crate) async fn clear_all_fresh_mappings(&self, reason: &str) {
        let invalidated = self
            .local_fresh_mappings
            .write()
            .await
            .drain()
            .map(|(peer_id, _)| peer_id)
            .collect::<Vec<_>>();
        for peer_id in invalidated {
            info!(
                event = "fresh_mapping_invalidated",
                peer_id = %peer_id,
                reason = %reason,
                "fresh_mapping_invalidated peer_id={} reason={}",
                peer_id,
                reason
            );
        }
    }

    /// Record how close the actually used peer-reflexive port was to the
    /// model prediction.  This feeds the time-limited NAT fingerprint used to
    /// tune the next generation's window.
    pub(crate) async fn record_fresh_mapping_prediction_result(
        &self,
        peer_id: &str,
        actual_endpoint: SocketAddr,
    ) {
        let Some(state) = self.fresh_mapping_for_peer(peer_id).await else {
            return;
        };
        let predicted_top = state.predicted_ports.first().copied();
        let actual_port = actual_endpoint.port();
        let error = match predicted_top {
            Some(predicted) => {
                let raw = i32::from(actual_port) - i32::from(predicted);
                if raw > 32767 {
                    raw - 65536
                } else if raw < -32768 {
                    raw + 65536
                } else {
                    raw
                }
            }
            None => 0,
        };
        let hit_window = state.predicted_ports.contains(&actual_port);
        // 0-indexed position of the actual port in the rank-ordered window;
        // `None` when it fell outside (a miss).  Distinct from hit_window,
        // which is only a boolean in/out: the rank is the calibration signal.
        let hit_rank = state
            .predicted_ports
            .iter()
            .position(|predicted| *predicted == actual_port)
            .map(|index| index as u8);
        let result = FreshMappingPredictionResult {
            punch_generation: state.punch_generation,
            predicted_top_port: predicted_top,
            actual_port,
            error,
            model_label: state.model.kind.label().to_string(),
            confidence: state.model.confidence,
            window_ports: state.predicted_ports.clone(),
            hit_window,
            hit_rank,
            hit_top1: hit_rank.is_some_and(|rank| rank < 1),
            hit_top6: hit_rank.is_some_and(|rank| rank < 6),
            hit_top24: hit_rank.is_some_and(|rank| rank < 24),
            hit_top96: hit_rank.is_some_and(|rank| rank < 96),
        };
        // The peer-reflexive notification can arrive many times for the same
        // peer-facing mapping (retransmissions, triggered checks), and the
        // same (generation, port) pair can reappear after other results
        // interleave.  One prediction result per (generation, actual port) is
        // enough for the diagnostics history and the hit/miss event stream.
        // The dedup check and the insert are one lock section: two concurrent
        // notifications can never both pass the check, so exactly the first
        // inserter records the hit/miss event.
        let inserted = {
            let mut history = self.fresh_mapping_history.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let entry = history.entry(peer_id.to_string()).or_default();
            if entry.iter().any(|recorded| {
                recorded.punch_generation == result.punch_generation
                    && recorded.actual_port == result.actual_port
            }) {
                false
            } else {
                entry.push_back(result.clone());
                while entry.len() > FRESH_MAPPING_RESULT_HISTORY_PER_PEER {
                    entry.pop_front();
                }
                true
            }
        };
        if !inserted {
            return;
        }
        // Logging and the event stream run outside the lock.
        info!(
            event = "fresh_mapping_prediction_result",
            peer_id = %peer_id,
            punch_generation = state.punch_generation,
            socket_local = %state.socket_local_endpoint,
            public_ip = state.public_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "none".to_string()),
            predicted_top = predicted_top.map(|port| port.to_string()).unwrap_or_else(|| "none".to_string()),
            actual_port = actual_port,
            prediction_error = error,
            model = %result.model_label,
            confidence = result.confidence,
            hit_window = hit_window,
            hit_rank = hit_rank.map(|rank| rank.to_string()).unwrap_or_else(|| "none".to_string()),
            window = ?result.window_ports,
            "fresh_mapping_prediction_result peer_id={} punch_generation={} socket_local={} public_ip={} predicted_top={:?} actual_port={} error={} model={} confidence={} hit_window={} hit_rank={:?}",
            peer_id,
            state.punch_generation,
            state.socket_local_endpoint,
            state.public_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "none".to_string()),
            predicted_top,
            actual_port,
            error,
            result.model_label,
            result.confidence,
            hit_window,
            hit_rank
        );
        self.record_direct_event(
                peer_id,
                if hit_window {
                    "fresh_mapping_prediction_hit"
                } else {
                    "fresh_mapping_prediction_miss"
                },
                Some(actual_endpoint),
                Some(state.predicted_ports.len()),
                None,
                format!(
                    "actual_port={actual_port} predicted_top={predicted_top:?} error={error} model={} confidence={} window={:?}",
                    result.model_label, result.confidence, result.window_ports
                ),
            )
            .await;
    }

    /// Stable authoritative public endpoint(s) to punch toward during a
    /// fresh-mapping generation.
    pub(crate) async fn stable_remote_punch_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        let generation = self.current_network_generation().await;
        // The NAT-sim harness allows loopback endpoints in the fresh-mapping
        // flow (config.network.fresh_mapping_harness_loopback).
        let allow_loopback = self.config.network.fresh_mapping_harness_loopback;
        let eligible = |endpoint: SocketAddr| {
            is_public_probe_endpoint(endpoint)
                || (allow_loopback && endpoint.ip().is_loopback())
        };
        let conns = self.connections.read().await;
        let Some(conn) = conns.get(node_id) else {
            return Vec::new();
        };
        let mut endpoints = conn
            .asymmetric_stable_endpoints_for_fresh_mapping(
                conn.probe_candidate_endpoints(),
                allow_loopback,
            )
            .into_iter()
            .filter(|endpoint| eligible(*endpoint))
            .collect::<Vec<_>>();
        endpoints.dedup();
        endpoints.truncate(1);
        if !endpoints.is_empty() {
            return endpoints;
        }
        // Fall back to any stable peer-reflexive endpoint learned recently.
        conn.candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == generation
                    && matches!(
                        pair.source,
                        CandidatePairSource::PeerReflexive | CandidatePairSource::Learned
                    )
                    && eligible(pair.remote_endpoint)
                    && pair
                        .last_success_at
                        .is_some_and(|at| at.elapsed() <= RELAY_PEER_CONFIRMATION_MAX_AGE)
            })
            .map(|pair| pair.remote_endpoint)
            .take(1)
            .collect()
    }

    /// Record that a signaled predicted candidate matched an authenticated
    /// probe (stable-side window hit diagnostics).
    pub(crate) async fn record_predicted_window_hit(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        signal_rank: u32,
    ) {
        self.record_direct_event(
            node_id,
            "predicted_window_hit",
            Some(endpoint),
            Some(1),
            None,
            format!("signaled predicted candidate matched at signal_rank={signal_rank}"),
        )
        .await;
        info!(
            event = "predicted_window_hit",
            peer_id = %node_id,
            remote_endpoint = %endpoint,
            signal_rank = signal_rank,
            "predicted_window_hit peer_id={} remote_endpoint={} signal_rank={}",
            node_id,
            endpoint,
            signal_rank
        );
    }

    /// Record a window hit when the endpoint belongs to a `Predicted`
    /// candidate pair signaled by the peer (stable-side role).
    pub(crate) async fn record_predicted_window_hit_if_predicted(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
    ) {
        let generation = self.current_network_generation().await;
        let pair = self
            .connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| {
                conn.candidate_pairs.iter().find(|pair| {
                    pair.local_generation == generation
                        && pair.remote_endpoint == endpoint
                        && pair.source == CandidatePairSource::Predicted
                })
            })
            .cloned();
        if let Some(pair) = pair {
            self.record_predicted_window_hit(
                node_id,
                endpoint,
                pair.signal_rank.unwrap_or(u32::MAX),
            )
            .await;
        }
    }
}

/// Serialized fresh-mapping diagnostics entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FreshMappingDiag {
    pub peer_id: String,
    pub punch_generation: u64,
    pub predicted_top: Option<u16>,
    pub actual_port: u16,
    pub error: i32,
    pub model: String,
    pub confidence: u8,
    pub hit_window: bool,
    /// 0-indexed position of `actual_port` in the rank-ordered prediction
    /// window (`None` on a miss).  The per-hit calibration signal: lets CLI/UI
    /// expose top-K accuracy, which window sizing and confidence calibration
    /// are tuned against.
    pub hit_rank: Option<u8>,
    /// Whether this observation landed in each calibration prefix.
    pub hit_top1: bool,
    pub hit_top6: bool,
    pub hit_top24: bool,
    pub hit_top96: bool,
}
