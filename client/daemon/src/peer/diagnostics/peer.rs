/// Serializable peer connection diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDiagnostics {
    pub node_id: String,
    pub device_name: String,
    pub app_version: String,
    pub virtual_ip: String,
    pub endpoint: Option<String>,
    pub nat_type: String,
    pub online: bool,
    pub last_seen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_relay_latency_ms: Option<u64>,
    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    pub direct_type: DirectPathType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_session_id: Option<String>,
    pub probe_key_type: String,
    pub selected_pair: Option<CandidatePairDiagnostics>,
    pub current_direct_pair: Option<CandidatePairDiagnostics>,
    pub consent_endpoint: Option<String>,
    pub is_public_udp_direct: bool,
    pub is_peer_reflexive_direct: bool,
    pub public_mapping_stable: bool,
    pub is_overlay_direct: bool,
    pub is_relay: bool,
    pub warning: Option<String>,
    pub connected_for_ms: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub relay_server: Option<String>,
    pub candidates: Vec<String>,
    pub direct: PathHealthDiagnostics,
    pub relay: PathHealthDiagnostics,
    pub direct_generation: u64,
    /// Relay endpoint whose ingress carried the confirming forced-relay probe
    /// ACK, when RelayPeerConfirmed (never from a local connect / queued
    /// registration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_confirmed_endpoint: Option<String>,
    /// Network generation in which the relay path was confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_confirmed_generation: Option<u64>,
    /// Path that became first usable for this peer (`Relay` or `Direct`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_usable_path: Option<NetworkPath>,
    /// Network generation of the first usable path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_usable_generation: Option<u64>,
    pub candidate_pair_stats: Vec<CandidatePairSourceStats>,
    pub candidate_pairs: Vec<CandidatePairDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_remaining_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_path_selection: Option<PathSelectionDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_path_selection: Option<PathSelectionDiagnostics>,
    pub path_events: Vec<PathSelectionEventDiagnostics>,
    pub direct_events: Vec<DirectTraversalEventDiagnostics>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fresh_mapping: Vec<FreshMappingDiag>,
    /// Failure-recovery epoch budget report (probe credit, fresh-mapping
    /// generations, HTTP publishes remaining), when a recovery epoch is
    /// active for the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryEpochDiagnostics>,
}

/// Serialized failure-recovery epoch budget report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecoveryEpochDiagnostics {
    pub epoch: u64,
    pub stage: String,
    pub stage_age_ms: u64,
    pub epoch_age_ms: u64,
    /// Remaining outbound probe credit for the epoch.
    pub probe_credit_remaining: u32,
    /// Remaining fresh-mapping generations (fresh sockets) for the epoch.
    pub fresh_generation_quota_remaining: u32,
    /// Remaining HTTP publishes for the epoch.
    pub http_quota_remaining: u32,
    /// Scatter windows sent this epoch.
    pub scatter_windows_sent: u32,
    pub ack_feedback_seen: bool,
}

impl PeerDiagnostics {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_connection_with_path_selection(
        conn: &PeerConnection,
        current_selection: Option<&PathSelection>,
        direct_retry_after: Option<Duration>,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
        traversal_history: Option<&TraversalHistory>,
        fresh_mapping_history: Option<&HashMap<String, VecDeque<FreshMappingPredictionResult>>>,
    ) -> Self {
        // The connection state and its selected pair are committed under the
        // same peer lock.  Once that snapshot says confirmed Direct, an older
        // selector result (usually a Relay decision captured before the ACK)
        // is stale and must not be allowed to describe the active path.
        let snapshot_direct_pair = conn.current_direct_pair_for_diagnostics(local_generation, None);
        let confirmed_direct_snapshot = conn.state == ConnectionState::Direct
            && snapshot_direct_pair.is_some_and(|pair| {
                pair.state == CandidatePairState::Selected
                    && is_public_probe_endpoint(pair.remote_endpoint)
            });
        let mut active_path = match current_selection {
            Some(selection) => match selection.path {
                Some(NetworkPath::Direct) if selection.direct_confirmed => {
                    Some(NetworkPath::Direct)
                }
                Some(NetworkPath::Direct)
                    if conn
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                {
                    Some(NetworkPath::Relay)
                }
                Some(NetworkPath::Relay)
                    if conn
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                {
                    Some(NetworkPath::Relay)
                }
                _ => None,
            },
            None => match conn.active_path() {
                Some(NetworkPath::Relay)
                    if !conn
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                {
                    None
                }
                path => path,
            },
        };
        if confirmed_direct_snapshot {
            active_path = Some(NetworkPath::Direct);
        }
        let selected_pair = conn.selected_candidate_pair_for_diagnostics(local_generation);
        if active_path.is_none()
            && conn.state == ConnectionState::Direct
            && selected_pair.is_some_and(|pair| !is_overlay_endpoint(pair.remote_endpoint))
            && conn.direct_health.consecutive_failures == 0
            && conn
                .direct_health
                .success_age()
                .is_some_and(|age| age <= RELAY_PEER_CONFIRMATION_MAX_AGE)
        {
            active_path = Some(NetworkPath::Direct);
        }
        let current_pair = if confirmed_direct_snapshot {
            snapshot_direct_pair
        } else {
            conn.current_direct_pair_for_diagnostics(local_generation, current_selection)
        };
        let current_pair_endpoint = current_pair.map(|pair| pair.remote_endpoint);
        let consent_endpoint = conn.selected_direct_endpoint_for_consent(local_generation);
        let direct_selection_confirmed = confirmed_direct_snapshot
            || (active_path == Some(NetworkPath::Direct)
            && current_selection
                .map(|selection| selection.direct_confirmed)
                .unwrap_or(conn.state == ConnectionState::Direct));
        let direct_confirmed = direct_selection_confirmed
            && current_pair.is_some_and(|pair| pair.state == CandidatePairState::Selected);
        let direct_type = classify_candidate_pair_path(active_path, current_pair, direct_confirmed);
        let selected_pair = selected_pair.map(|pair| {
            let is_current = Some(pair.remote_endpoint) == current_pair_endpoint;
            let pair_direct_confirmed =
                direct_selection_confirmed && (is_current || pair.state == CandidatePairState::Selected);
            let pair_active_path = if pair_direct_confirmed {
                Some(NetworkPath::Direct)
            } else {
                is_current.then_some(active_path).flatten()
            };
            CandidatePairDiagnostics::from_pair(
                pair,
                local_endpoint,
                pair_active_path,
                pair_direct_confirmed,
            )
        });
        let current_direct_pair = current_pair.map(|pair| {
            CandidatePairDiagnostics::from_pair(pair, local_endpoint, active_path, direct_confirmed)
        });
        let mut candidate_pairs = conn
            .candidate_pairs
            .iter()
            .map(|pair| {
                let is_current = Some(pair.remote_endpoint) == current_pair_endpoint;
                let pair_direct_confirmed = direct_selection_confirmed
                    && (is_current || pair.state == CandidatePairState::Selected);
                let pair_active_path = if pair_direct_confirmed {
                    Some(NetworkPath::Direct)
                } else {
                    is_current.then_some(active_path).flatten()
                };
                CandidatePairDiagnostics::from_pair(
                    pair,
                    local_endpoint,
                    pair_active_path,
                    pair_direct_confirmed,
                )
            })
            .collect::<Vec<_>>();
        candidate_pairs.sort_by(|a, b| {
            a.local_generation
                .cmp(&b.local_generation)
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });

        // A peer-reflexive pair over a real public IPv4 endpoint is still a
        // public UDP direct path: both endpoints are routable Internet
        // addresses.  Only overlay/relay paths are not public-IP direct.
        let is_public_udp_direct = matches!(
            direct_type,
            DirectPathType::PublicUdp | DirectPathType::PeerReflexive
        );
        let is_peer_reflexive_direct = direct_type == DirectPathType::PeerReflexive;
        let public_mapping_stable = direct_type == DirectPathType::PublicUdp;
        let is_overlay_direct = direct_type == DirectPathType::Overlay;
        let is_relay = direct_type == DirectPathType::Relay;
        let warning = is_overlay_direct
            .then(|| "direct path is overlay/utun, not public NAT traversal".to_string());

        Self {
            node_id: conn.node_id.clone(),
            device_name: conn.device_name.clone(),
            app_version: conn.app_version.clone(),
            virtual_ip: conn.virtual_ip.clone(),
            endpoint: conn.endpoint.map(|endpoint| endpoint.to_string()),
            nat_type: conn.nat_type.clone(),
            online: conn.online,
            last_seen: conn.last_seen,
            remote_relay_latency_ms: conn.remote_relay_rtt_ms,
            state: conn.state,
            active_path,
            direct_type,
            probe_session_id: conn.probe_session_id.clone(),
            probe_key_type: probe_key_type(conn).to_string(),
            selected_pair,
            current_direct_pair,
            consent_endpoint: consent_endpoint.map(|endpoint| endpoint.to_string()),
            is_public_udp_direct,
            is_peer_reflexive_direct,
            public_mapping_stable,
            is_overlay_direct,
            is_relay,
            warning,
            connected_for_ms: conn
                .connected_at
                .map(|connected_at| duration_millis(connected_at.elapsed())),
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            relay_server: conn.relay_server.clone(),
            candidates: conn.candidates.clone(),
            direct: PathHealthDiagnostics::from(&conn.direct_health),
            relay: PathHealthDiagnostics::from(&conn.relay_health),
            direct_generation: conn.direct_generation,
            relay_confirmed_endpoint: conn.relay_confirmed_endpoint.clone(),
            relay_confirmed_generation: conn.relay_confirmed_generation,
            first_usable_path: conn.first_usable_path,
            first_usable_generation: conn.first_usable_generation,
            candidate_pair_stats: candidate_pair_source_stats(
                &conn.candidate_pairs,
                local_generation,
                traversal_history,
            ),
            candidate_pairs,
            direct_retry_after_ms: direct_retry_after
                .map(|base| duration_millis(conn.direct_retry_after(base))),
            direct_retry_remaining_ms: direct_retry_after
                .map(|base| duration_millis(conn.direct_retry_remaining(base))),
            current_path_selection: if confirmed_direct_snapshot {
                current_pair.map(|pair| {
                    PathSelectionDiagnostics::from(&PathSelection::direct(
                        pair.remote_endpoint,
                        REASON_PATH_DIRECT_CONFIRMED,
                        "confirmed Direct snapshot",
                        true,
                    ))
                })
            } else {
                current_selection.map(PathSelectionDiagnostics::from)
            },
            last_path_selection: if confirmed_direct_snapshot {
                current_pair.map(|pair| {
                    PathSelectionDiagnostics::from(&PathSelection::direct(
                        pair.remote_endpoint,
                        REASON_PATH_DIRECT_CONFIRMED,
                        "confirmed Direct snapshot",
                        true,
                    ))
                })
            } else {
                conn.last_path_selection
                    .as_ref()
                    .map(PathSelectionDiagnostics::from)
            },
            path_events: conn
                .path_events
                .iter()
                .map(PathSelectionEventDiagnostics::from)
                .collect(),
            direct_events: conn
                .direct_events
                .iter()
                .map(DirectTraversalEventDiagnostics::from)
                .collect(),
            fresh_mapping: fresh_mapping_history
                .and_then(|history| history.get(&conn.node_id))
                .map(|results| {
                    results
                        .iter()
                        .map(|result| FreshMappingDiag {
                            peer_id: conn.node_id.clone(),
                            punch_generation: result.punch_generation,
                            predicted_top: result.predicted_top_port,
                            actual_port: result.actual_port,
                            error: result.error,
                            model: result.model_label.clone(),
                            confidence: result.confidence,
                            hit_window: result.hit_window,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            recovery: None,
        }
    }
}

impl From<&PeerConnection> for PeerDiagnostics {
    fn from(conn: &PeerConnection) -> Self {
        Self::from_connection_with_path_selection(
            conn,
            None,
            None,
            conn.direct_generation,
            None,
            None,
            None,
        )
    }
}
