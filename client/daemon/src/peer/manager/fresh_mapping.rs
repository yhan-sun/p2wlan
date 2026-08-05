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
}

const FRESH_MAPPING_STATE_MAX_AGE: Duration = Duration::from_secs(30);
const FRESH_MAPPING_RESULT_HISTORY_PER_PEER: usize = 8;

impl PeerManager {
    /// Whether the local NAT profile needs fresh-socket mapping prediction.
    ///
    /// Endpoint-independent / open NATs have a stable public port; only
    /// address/port-dependent (symmetric-class) mappings benefit from the
    /// measure-then-punch generation.
    pub(crate) async fn local_nat_requires_fresh_mapping_punch(&self) -> bool {
        if !self.config.network.fresh_mapping_punch_enabled {
            return false;
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
        self.local_fresh_mappings.write().await.insert(
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
        let result = FreshMappingPredictionResult {
            punch_generation: state.punch_generation,
            predicted_top_port: predicted_top,
            actual_port,
            error,
            model_label: state.model.kind.label().to_string(),
            confidence: state.model.confidence,
            window_ports: state.predicted_ports.clone(),
            hit_window,
        };
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
            window = ?result.window_ports,
            "fresh_mapping_prediction_result peer_id={} punch_generation={} socket_local={} public_ip={} predicted_top={:?} actual_port={} error={} model={} confidence={} hit_window={}",
            peer_id,
            state.punch_generation,
            state.socket_local_endpoint,
            state.public_ip.map(|ip| ip.to_string()).unwrap_or_else(|| "none".to_string()),
            predicted_top,
            actual_port,
            error,
            result.model_label,
            result.confidence,
            hit_window
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
        {
            let mut history = self.fresh_mapping_history.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            history
                .entry(peer_id.to_string())
                .or_default()
                .push_back(result);
            while history.get(peer_id).is_some_and(|results| {
                results.len() > FRESH_MAPPING_RESULT_HISTORY_PER_PEER
            }) {
                history.get_mut(peer_id).expect("history entry").pop_front();
            }
        }
    }

    /// Stable authoritative public endpoint(s) to punch toward during a
    /// fresh-mapping generation.
    pub(crate) async fn stable_remote_punch_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        let generation = self.current_network_generation().await;
        let conns = self.connections.read().await;
        let Some(conn) = conns.get(node_id) else {
            return Vec::new();
        };
        let mut endpoints = conn
            .asymmetric_stable_public_endpoints(conn.probe_candidate_endpoints())
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
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
                    && is_public_probe_endpoint(pair.remote_endpoint)
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
}
