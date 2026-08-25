/// Serializable peer connection diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDiagnostics {
    pub node_id: String,
    pub device_name: String,
    pub app_version: String,
    pub virtual_ip: String,
    pub endpoint: Option<String>,
    pub nat_type: String,
    /// Normalized remote NAT evidence decoded from the existing control label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_nat_capabilities: Option<NatCapabilities>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_nat_profile_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_nat_profile_received_at_ms: Option<u64>,
    #[serde(default)]
    pub remote_nat_profile_fresh: bool,
    /// Explainable attempt plan only; active path ownership remains with the
    /// existing candidate proof and selector state machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traversal_plan: Option<TraversalPlan>,
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
    /// Local relay transport incarnation that carried the confirming ACK.
    /// This is diagnostic only; it prevents same-endpoint renewal races from
    /// being mistaken for one continuous proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_confirmed_connection_id: Option<u64>,
    /// Relay transport readiness is deliberately separate from
    /// `relay_confirmed_*`: a ready writer/TLS connection is not peer-delivery
    /// evidence. These fields make that boundary visible in `/status`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_ready_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_ready_generation: Option<u64>,
    /// Local relay transport incarnation that carried the ready milestone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_ready_connection_id: Option<u64>,
    /// Generation in which the relay-first standby gate began, plus its
    /// daemon-local age. This is useful for diagnosing relay fallback state
    /// around a Direct ACK that may already be authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_first_gate_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_first_gate_age_ms: Option<u64>,
    #[serde(default)]
    pub relay_first_confirmation_pending: bool,
    #[serde(default)]
    pub relay_first_business_pending: bool,
    /// The two same-generation relay-first business-direction markers. Direct
    /// remains primary after an authoritative commit; these describe relay
    /// fallback readiness and historical startup evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_first_business_sent_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_first_business_received_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_first_business_exchange_generation: Option<u64>,
    /// Generation in which the relay-first business gate completed once.
    /// This remains set across relay ticket renewal so an established Direct
    /// path is not mistaken for a new first-business race.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_first_business_gate_completed_generation: Option<u64>,
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
        local_nat_capabilities: Option<&NatCapabilities>,
        relay_available: bool,
        traversal_history: Option<&TraversalHistory>,
        fresh_mapping_history: Option<&HashMap<String, VecDeque<FreshMappingPredictionResult>>>,
    ) -> Self {
        // The connection state and its selected pair are committed under the
        // same peer lock.  Once that snapshot says confirmed Direct, an older
        // selector result (usually a Relay decision captured before the ACK)
        // is stale and must not be allowed to describe the active path.
        let snapshot_direct_pair =
            conn.current_direct_pair_for_diagnostics(local_generation, current_selection);
        let confirmed_direct_snapshot = conn.state == ConnectionState::Direct
            && snapshot_direct_pair.is_some_and(|pair| {
                pair.state == CandidatePairState::Selected
                    && !conn.is_overlay_candidate_pair(pair)
            });
        let on_link_direct_snapshot = confirmed_direct_snapshot
            && snapshot_direct_pair
                .is_some_and(|pair| conn.is_on_link_host_candidate(pair.remote_endpoint));
        // Relay health is only a local observation (for example, a writer
        // completion or a validation packet). It is deliberately not enough
        // to expose Relay as the active path. Status must be backed by the
        // same-generation encrypted forced-relay ACK that gates the outbound
        // FIFO.
        let relay_peer_confirmed = conn.relay_confirmed_at.is_some()
            && conn.relay_confirmed_generation == Some(local_generation)
            && conn
                .relay_confirmed_endpoint
                .as_deref()
                .is_some_and(|endpoint| !endpoint.is_empty());
        // These relay-first fields remain useful fallback-proof diagnostics.
        // They do not override a current encrypted-confirmed Selected Direct
        // pair: after that commit Direct is the active path and Relay is only
        // the warm standby.
        let relay_first_pending = !on_link_direct_snapshot
            && conn.relay_first_confirmation_pending(local_generation, relay_available);
        let relay_first_business_pending =
            !on_link_direct_snapshot && conn.relay_first_business_pending(local_generation, relay_available);
        let confirmed_direct_active = confirmed_direct_snapshot;
        let mut active_path = match current_selection {
            Some(selection) => match selection.path {
                Some(NetworkPath::Direct)
                    if selection.direct_confirmed
                        && confirmed_direct_snapshot
                        && selection
                            .direct_endpoint
                            .is_some_and(|endpoint| !conn.is_overlay_direct_endpoint(endpoint)) =>
                    Some(NetworkPath::Direct),
                Some(NetworkPath::Direct)
                    if relay_peer_confirmed && !selection.direct_confirmed => {
                    Some(NetworkPath::Relay)
                }
                Some(NetworkPath::Relay) if relay_peer_confirmed => {
                    Some(NetworkPath::Relay)
                }
                _ => None,
            },
            None => match conn.active_path() {
                Some(NetworkPath::Relay) if relay_peer_confirmed => Some(NetworkPath::Relay),
                Some(NetworkPath::Direct) if confirmed_direct_active => {
                    Some(NetworkPath::Direct)
                }
                _ => None,
            },
        };
        // A confirmed Direct snapshot is authoritative over a stale selector
        // snapshot, except when the current selector has already made an
        // explicit quality-driven fallback to an actually peer-confirmed
        // Relay. This preserves make-before-break while still allowing a
        // real Direct ACK to correct an older `Relay` selector decision.
        let selector_is_confirmed_relay = !on_link_direct_snapshot
            && current_selection
            .is_some_and(|selection| selection.path == Some(NetworkPath::Relay) && relay_peer_confirmed);
        if confirmed_direct_active && !selector_is_confirmed_relay {
            active_path = Some(NetworkPath::Direct);
        }
        let selected_pair = conn.selected_candidate_pair_for_diagnostics(local_generation);
        if active_path.is_none()
            && conn.state == ConnectionState::Direct
            && selected_pair.is_some_and(|pair| !conn.is_overlay_candidate_pair(pair))
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
        let direct_selection_confirmed = confirmed_direct_active
            || (active_path == Some(NetworkPath::Direct)
            && current_selection
                .map(|selection| selection.direct_confirmed)
                .unwrap_or(conn.state == ConnectionState::Direct));
        let direct_confirmed = direct_selection_confirmed
            && current_pair.is_some_and(|pair| pair.state == CandidatePairState::Selected);
        let direct_type = classify_candidate_pair_path_with_on_link_host(
            active_path,
            current_pair,
            direct_confirmed,
            current_pair.is_some_and(|pair| conn.is_on_link_host_candidate(pair.remote_endpoint)),
        );
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
                conn.is_on_link_host_candidate(pair.remote_endpoint),
            )
        });
        let current_direct_pair = current_pair.map(|pair| {
            CandidatePairDiagnostics::from_pair(
                pair,
                local_endpoint,
                active_path,
                direct_confirmed,
                conn.is_on_link_host_candidate(pair.remote_endpoint),
            )
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
                    conn.is_on_link_host_candidate(pair.remote_endpoint),
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

        let default_local_capabilities = NatCapabilities::default();
        let local_capabilities = local_nat_capabilities.unwrap_or(&default_local_capabilities);
        let remote_nat_capabilities = conn
            .remote_nat_profile
            .as_ref()
            .map(|profile| profile.capabilities.clone());
        let default_remote_capabilities = NatCapabilities::default();
        let remote_capabilities = remote_nat_capabilities
            .as_ref()
            .unwrap_or(&default_remote_capabilities);
        let remote_nat_profile_fresh = conn.remote_nat_profile_is_fresh();
        let remote_profile_mapping_known = conn.remote_nat_profile.as_ref().is_some_and(|profile| {
            profile.capabilities.mapping_behavior != MappingBehavior::Unknown
        });
        let remote_candidate_endpoints = conn
            .candidates
            .iter()
            .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();
        let on_link_lan = remote_candidate_endpoints
            .iter()
            .any(|endpoint| conn.is_on_link_host_candidate(*endpoint));
        let global_ipv6_direct_available = local_endpoint.is_some_and(|endpoint| endpoint.is_ipv6())
            && remote_candidate_endpoints.iter().any(|endpoint| {
                endpoint.is_ipv6() && is_public_probe_endpoint(*endpoint)
            });
        let peer_reflexive_evidence = conn.candidate_pairs.iter().any(|pair| {
            matches!(pair.source, CandidatePairSource::PeerReflexive)
                && matches!(
                    pair.state,
                    CandidatePairState::Succeeded | CandidatePairState::Selected
                )
        });
        let learned_endpoint_evidence = conn.candidate_pairs.iter().any(|pair| {
            matches!(pair.source, CandidatePairSource::Learned)
                && matches!(
                    pair.state,
                    CandidatePairState::Succeeded | CandidatePairState::Selected
                )
        });
        let remote_stable_endpoint_available = remote_capabilities.is_stable_endpoint()
            || (!remote_profile_mapping_known
                && conn.endpoint.is_some_and(is_public_probe_endpoint));
        let fresh_mapping_available = fresh_mapping_history
            .and_then(|history| history.get(&conn.node_id))
            .is_some_and(|results| !results.is_empty());
        let traversal_context = TraversalContext {
            on_link_lan,
            global_ipv6_direct_available,
            peer_reflexive_evidence,
            learned_endpoint_evidence,
            local_stable_endpoint_available: local_capabilities.is_stable_endpoint(),
            remote_stable_endpoint_available,
            fresh_mapping_available,
            remote_profile_fresh: remote_nat_profile_fresh,
            relay_available,
            bounded_birthday_allowed: local_capabilities.birthday_candidate
                || remote_capabilities.birthday_candidate,
            ..TraversalContext::default()
        };
        let traversal_plan = Some(plan_traversal(
            local_capabilities,
            remote_capabilities,
            &traversal_context,
        ));
        if let Some(plan) = traversal_plan.as_ref() {
            debug!(
                event = "traversal_plan_selected",
                peer = %conn.node_id,
                network_generation = local_generation,
                remote_profile_generation = ?conn
                    .remote_nat_profile
                    .as_ref()
                    .and_then(|profile| profile.generation),
                mapping_behavior = ?local_capabilities.mapping_behavior,
                filtering_behavior = ?local_capabilities.filtering_behavior,
                allocation_model = ?local_capabilities.allocation_model,
                prediction_confidence = local_capabilities.prediction_confidence,
                plan = plan.strategy_label(),
                capability = ?plan.capability,
                reason = %plan.reason,
                fallback = plan.fallback_label(),
                relay_available,
                remote_profile_fresh = remote_nat_profile_fresh,
                network_hint = plan.network_hint.label(),
                "selected pairwise traversal plan for diagnostics"
            );
        }

        Self {
            node_id: conn.node_id.clone(),
            device_name: conn.device_name.clone(),
            app_version: conn.app_version.clone(),
            virtual_ip: conn.virtual_ip.clone(),
            endpoint: conn.endpoint.map(|endpoint| endpoint.to_string()),
            nat_type: conn.nat_type.clone(),
            remote_nat_capabilities,
            remote_nat_profile_generation: conn
                .remote_nat_profile
                .as_ref()
                .and_then(|profile| profile.generation),
            remote_nat_profile_received_at_ms: conn
                .remote_nat_profile
                .as_ref()
                .map(|profile| profile.received_at_ms),
            remote_nat_profile_fresh,
            traversal_plan,
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
            relay_confirmed_connection_id: conn.relay_confirmed_connection_id,
            relay_ready_endpoint: conn.relay_ready_endpoint.clone(),
            relay_ready_generation: conn.relay_ready_generation,
            relay_ready_connection_id: conn.relay_ready_connection_id,
            relay_first_gate_generation: conn.relay_first.gate_generation,
            relay_first_gate_age_ms: conn
                .relay_first.gate_started_at
                .map(|started_at| duration_millis(started_at.elapsed())),
            relay_first_confirmation_pending: relay_first_pending,
            relay_first_business_pending,
            relay_first_business_sent_generation: conn.relay_first.business_sent_generation,
            relay_first_business_received_generation: conn.relay_first.business_received_generation,
            relay_first_business_exchange_generation: conn.relay_first.business_exchange_generation,
            relay_first_business_gate_completed_generation: conn
                .relay_first
                .business_gate_completed_generation,
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
            current_path_selection: if confirmed_direct_active {
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
            last_path_selection: if confirmed_direct_active {
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
                            hit_rank: result.hit_rank,
                            hit_top1: result.hit_top1,
                            hit_top6: result.hit_top6,
                            hit_top24: result.hit_top24,
                            hit_top96: result.hit_top96,
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
            false,
            None,
            None,
        )
    }
}
