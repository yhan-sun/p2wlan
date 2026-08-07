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
            network_generation_sync: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            network_epoch_gate: Arc::new(tokio::sync::Mutex::new(())),
            direct_validation_registry: Arc::new(RwLock::new(None)),
            local_nat_profile: Arc::new(RwLock::new(None)),
            traversal_history: Arc::new(RwLock::new(traversal_history)),
            traversal_history_path,
            punch_generations: Arc::new(RwLock::new(HashMap::new())),
            local_fresh_mappings: Arc::new(RwLock::new(HashMap::new())),
            fresh_mapping_history: Arc::new(std::sync::Mutex::new(HashMap::new())),
            remote_fresh_generations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            remote_fresh_snapshots: Arc::new(std::sync::Mutex::new(HashMap::new())),
            pending_fresh_applies: Arc::new(std::sync::Mutex::new(HashMap::new())),
            remote_fresh_identity_keys: Arc::new(std::sync::Mutex::new(HashMap::new())),
            direct_peers: Arc::new(std::sync::Mutex::new(HashSet::new())),
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

    /// Whether this peer still needs the unauthenticated PNCH v1 compatibility
    /// datagram alongside an authenticated Probe v2 packet.
    pub(crate) async fn peer_requires_legacy_probe(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_none_or(|conn| !app_version_at_least(&conn.app_version, (0, 1, 25)))
    }

    /// Serializable local traversal history diagnostics.
    pub async fn traversal_history_diagnostics(&self) -> TraversalHistoryDiagnostics {
        self.traversal_history.read().await.diagnostics()
    }

    async fn record_traversal_success(&self, source: CandidatePairSource) {
        if !source.is_persisted_history_source() {
            return;
        }
        let mut history = self.traversal_history.write().await;
        history.record_success(source);
        self.persist_traversal_history(&history);
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

        let mut history = self.traversal_history.write().await;
        for source in unique_sources {
            history.record_failure(source);
        }
        self.persist_traversal_history(&history);
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

    /// Lock-free current network generation for checks that must run inside
    /// another subsystem's critical section (the UDP socket-state lock).
    ///
    /// The mirror is updated in the same critical section as the RwLock, so
    /// this never lags a completed advance; the generation only moves forward,
    /// so a check against this value can never pass with a stale generation.
    pub(crate) fn current_network_generation_sync(&self) -> u64 {
        self.network_generation_sync.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The shared network-epoch gate that serializes generation advances
    /// against the UDP socket-state mutations that commit, finalize, attach
    /// or adopt ownership stamped with a generation.
    ///
    /// The UDP transport acquires this gate (gate -> socket_state ->
    /// pending probes) around every generation-sensitive mutation so an
    /// advance can never bump the generation between the mutation's read and
    /// its write; the advances hold the same gate for their whole critical
    /// section.
    pub(crate) fn network_epoch_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.network_epoch_gate.clone()
    }

    /// Publish the validation ownership registry of the active UDP transport.
    ///
    /// Replacement is serialized with generation transitions.  The previous
    /// transport's workers and expectations are revoked before the new handle
    /// is made visible, so a dead/rebound socket cannot leave validation ACK
    /// state behind to promote a later transport.
    pub(crate) async fn register_direct_validation_registry(
        &self,
        registry: crate::udp::DirectValidationRegistry,
    ) {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_gate = epoch_gate.lock().await;
        let previous = self
            .direct_validation_registry
            .write()
            .await
            .replace(registry);
        if let Some(previous) = previous {
            previous.cancel_all().await;
        }
    }

    /// Cancel the registry that is current at the instant this lifecycle
    /// operation holds the epoch gate. A control-event handler may have cloned
    /// an old `UdpTransport` just before a rebind; resolving the registry here
    /// avoids leaving the replacement transport's validation owner alive.
    pub(crate) async fn cancel_active_direct_validation_for_peer(&self, peer_id: &str) {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_gate = epoch_gate.lock().await;
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry.cancel_peer(peer_id).await;
        }
    }

    /// Whether a peer connection currently exists, readable without awaiting.
    ///
    /// Used under the UDP adoption lock to refuse ACK/punch adoption for a
    /// peer whose connection was removed concurrently (PeerLeft): a late
    /// packet must never recreate affinity or candidate state for a peer that
    /// no longer exists.
    pub(crate) fn peer_exists_sync(&self, node_id: &str) -> bool {
        self.connections
            .try_read()
            .map(|connections| connections.contains_key(node_id))
            .unwrap_or(false)
    }

    /// Advance local network generation and invalidate confirmed direct paths.
    ///
    /// Existing remote candidates are kept so they can be reprobed, but prior
    /// direct success is no longer trusted for active-path selection.
    ///
    /// The whole advance runs under the shared network-epoch gate: no UDP
    /// socket-state mutation that read the old generation can commit, finalize,
    /// attach, adopt or register a pending probe in between, so after this
    /// returns every generation-sensitive transition belongs to the new
    /// generation.
    pub async fn advance_network_generation(&self, reason: impl Into<String>) -> u64 {
        let reason = reason.into();
        let epoch_gate = self.network_epoch_gate();
        let _epoch_gate = epoch_gate.lock().await;
        let generation = {
            let mut generation = self.network_generation.write().await;
            *generation = generation.saturating_add(1);
            // Keep the lock-free mirror in the same critical section: the UDP
            // socket-state checks read it without awaiting.
            self.network_generation_sync
                .store(*generation, std::sync::atomic::Ordering::Release);
            *generation
        };
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry.cancel_before_generation(generation).await;
        }

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
        drop(conns);
        self.clear_all_fresh_mappings("network_generation_changed").await;

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
    ///
    /// Like the full advance, the whole transition runs under the shared
    /// network-epoch gate so generation-sensitive UDP socket mutations are
    /// linearized against it.
    pub async fn advance_candidate_refresh_generation(&self, reason: impl Into<String>) -> u64 {
        let reason = reason.into();
        let epoch_gate = self.network_epoch_gate();
        let _epoch_gate = epoch_gate.lock().await;
        let generation = {
            let mut generation = self.network_generation.write().await;
            *generation = generation.saturating_add(1);
            // Keep the lock-free mirror in the same critical section (see
            // `current_network_generation_sync`).
            self.network_generation_sync
                .store(*generation, std::sync::atomic::Ordering::Release);
            *generation
        };
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry.cancel_before_generation(generation).await;
        }

        let mut retained_confirmed_direct_count = 0usize;
        let mut direct_reclaim_count = 0usize;
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            let retained_confirmed_direct =
                conn.mark_candidate_refresh_generation_changed(generation, reason.clone());
            if retained_confirmed_direct {
                retained_confirmed_direct_count += 1;
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
        drop(conns);
        self.clear_all_fresh_mappings("candidate_refresh_generation_changed").await;

        info!(
            "Local network generation advanced to {generation}: {reason}; retained {retained_confirmed_direct_count} confirmed direct path(s); opened {direct_reclaim_count} Direct reclaim window(s)"
        );
        generation
    }
}

fn app_version_at_least(version: &str, minimum: (u64, u64, u64)) -> bool {
    let mut components = version.trim().trim_start_matches(['v', 'V']).split('.');
    let parse_component = |component: Option<&str>| {
        component?
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .collect::<String>()
            .parse::<u64>()
            .ok()
    };
    let Some(major) = parse_component(components.next()) else {
        return false;
    };
    let Some(minor) = parse_component(components.next()) else {
        return false;
    };
    let Some(patch) = parse_component(components.next()) else {
        return false;
    };
    (major, minor, patch) >= minimum
}
