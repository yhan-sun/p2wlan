impl PeerManager {
    /// Create a new peer manager.
    pub fn new(config: Config) -> Self {
        let history_path = traversal_history_path(&config);
        let traversal_history = TraversalHistory::load(history_path.as_deref());
        Self::new_with_history(config, history_path, traversal_history)
    }

    fn new_with_history(
        config: Config,
        traversal_history_path: Option<PathBuf>,
        traversal_history: TraversalHistory,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            ip_to_node: Arc::new(RwLock::new(HashMap::new())),
            network_generation: Arc::new(RwLock::new(0)),
            local_nat_profile: Arc::new(RwLock::new(None)),
            traversal_history: Arc::new(RwLock::new(traversal_history)),
            traversal_history_path,
            config,
        }
    }

    /// Update the latest local NAT profile used by adaptive probe scheduling.
    pub async fn update_nat_profile(&self, profile: NatProfile) {
        *self.local_nat_profile.write().await = Some(profile);
    }

    /// Bound probe rounds from the observed local NAT behavior.  Endpoint-
    /// independent NATs benefit from a short synchronized burst; dependent
    /// mappings need a wider bounded window.  UDP-blocked networks retain one
    /// lightweight attempt so the path can recover after a transient change.
    pub async fn recommended_punch_attempts(&self, configured: u32) -> u32 {
        let configured = configured.clamp(1, 10);
        let profile = self.local_nat_profile.read().await;
        match profile.as_ref().map(|profile| profile.mapping_behavior) {
            Some(MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent) => {
                configured.min(4)
            }
            Some(MappingBehavior::AddressOrPortDependent) => configured.clamp(6, 8),
            Some(MappingBehavior::UdpBlocked) => 1,
            Some(MappingBehavior::Unknown) | None => configured.min(6),
        }
    }

    /// Serializable local traversal history diagnostics.
    pub async fn traversal_history_diagnostics(&self) -> TraversalHistoryDiagnostics {
        self.traversal_history.read().await.diagnostics()
    }

    async fn record_traversal_success(&self, source: CandidatePairSource) {
        if !source.is_persisted_history_source() {
            return;
        }
        let snapshot = {
            let mut history = self.traversal_history.write().await;
            history.record_success(source);
            history.clone()
        };
        self.persist_traversal_history(&snapshot);
    }

    async fn record_traversal_failures(&self, sources: Vec<CandidatePairSource>) {
        let mut unique_sources = Vec::new();
        for source in sources {
            if source.is_persisted_history_source() && !unique_sources.contains(&source) {
                unique_sources.push(source);
            }
        }
        if unique_sources.is_empty() {
            return;
        }

        let snapshot = {
            let mut history = self.traversal_history.write().await;
            for source in unique_sources {
                history.record_failure(source);
            }
            history.clone()
        };
        self.persist_traversal_history(&snapshot);
    }

    fn persist_traversal_history(&self, history: &TraversalHistory) {
        let Some(path) = self.traversal_history_path.as_deref() else {
            return;
        };
        if let Err(error) = history.save(path) {
            warn!(
                "Failed to persist traversal history at {}: {error}",
                path.display()
            );
        }
    }

    async fn local_nat_profile_for_probe_budget(&self) -> Option<NatProfile> {
        if !self.config.network.birthday_probing_enabled {
            return None;
        }
        self.local_nat_profile.read().await.clone()
    }

    /// Current local network generation.
    pub async fn current_network_generation(&self) -> u64 {
        *self.network_generation.read().await
    }

    /// Advance local network generation and invalidate confirmed direct paths.
    ///
    /// Existing remote candidates are kept so they can be reprobed, but prior
    /// direct success is no longer trusted for active-path selection.
    pub async fn advance_network_generation(&self, reason: impl Into<String>) -> u64 {
        let reason = reason.into();
        let generation = {
            let mut generation = self.network_generation.write().await;
            *generation = generation.saturating_add(1);
            *generation
        };

        let mut direct_reclaim_count = 0usize;
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            conn.direct_health.record_generation_change(reason.clone());
            conn.mark_network_generation_changed(generation, reason.clone());
            if conn.state == ConnectionState::Direct {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            if conn.start_direct_reclaim_window(generation, &reason) {
                direct_reclaim_count += 1;
            }
        }

        info!(
            "Local network generation advanced to {generation}: {reason}; opened {direct_reclaim_count} Direct reclaim window(s)"
        );
        generation
    }

    /// Advance local generation after a candidate refresh.
    ///
    /// Unlike a true interface transition, a periodic candidate refresh may
    /// change advertised public or gateway candidates while an authenticated
    /// low-latency private/LAN Direct path is still healthy. Preserve that
    /// selected private pair in the new generation so data traffic does not
    /// briefly fall back to relay on every refresh.
    pub async fn advance_candidate_refresh_generation(&self, reason: impl Into<String>) -> u64 {
        let reason = reason.into();
        let generation = {
            let mut generation = self.network_generation.write().await;
            *generation = generation.saturating_add(1);
            *generation
        };

        let mut retained_private_direct_count = 0usize;
        let mut direct_reclaim_count = 0usize;
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            let retained_private_direct =
                conn.mark_candidate_refresh_generation_changed(generation, reason.clone());
            if retained_private_direct {
                retained_private_direct_count += 1;
                continue;
            }

            conn.direct_health.record_generation_change(reason.clone());
            if conn.state == ConnectionState::Direct {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            if conn.start_direct_reclaim_window(generation, &reason) {
                direct_reclaim_count += 1;
            }
        }

        info!(
            "Local network generation advanced to {generation}: {reason}; retained {retained_private_direct_count} low-latency private direct path(s); opened {direct_reclaim_count} Direct reclaim window(s)"
        );
        generation
    }
}
