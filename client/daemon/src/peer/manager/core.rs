impl PeerManager {
    /// Whether startup/live candidate gathering may advertise extrapolated
    /// server-reflexive endpoints.  Keep this accessor in the core manager
    /// implementation so fast startup gathering does not depend on any
    /// experimental fresh-mapping worktree file.
    pub(crate) fn predicted_candidates_enabled_for_gather(&self) -> bool {
        self.config.network.predicted_candidates_enabled
    }

    /// Return the platform hint used only for bounded Hard↔Hard resource
    /// sizing.  Keep the configuration private; callers should not inspect
    /// the manager's full runtime configuration just to choose an Android
    /// socket/probe cap.
    pub(crate) fn is_android_platform(&self) -> bool {
        self.config.node.platform.eq_ignore_ascii_case("android")
    }

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
        let (committed_business_path_change_tx, _) = tokio::sync::watch::channel(0);
        let (dplpmtud_capability_tx, _) =
            tokio::sync::watch::channel(Arc::new(HashMap::new()));
        let (direct_business_budget_change_tx, _) = tokio::sync::watch::channel(0);
        let (local_mtu_feedback_tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            peer_membership: Arc::new(std::sync::Mutex::new(PeerMembershipState::default())),
            #[cfg(test)]
            authenticated_probe_verify_gate: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            relay_probe_snapshot_test_gate: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            hard_hard_cleanup_gate: Arc::new(std::sync::Mutex::new(None)),
            diagnostics_cache: Arc::new(std::sync::Mutex::new(None)),
            committed_business_paths: Arc::new(std::sync::Mutex::new(HashMap::new())),
            committed_business_path_change_tx,
            dplpmtud_capability_tx,
            direct_business_budget_change_tx,
            local_mtu_feedback_tx,
            local_mtu_feedback_limiter: Arc::new(std::sync::Mutex::new(
                crate::business_mtu::LocalMtuFeedbackRateLimiter::default(),
            )),
            ip_to_node: Arc::new(RwLock::new(HashMap::new())),
            network_generation: Arc::new(RwLock::new(0)),
            network_generation_sync: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            network_generation_handshake_cancel_hook: Arc::new(std::sync::Mutex::new(None)),
            network_epoch_gate: Arc::new(tokio::sync::Mutex::new(())),
            direct_validation_registry: Arc::new(RwLock::new(None)),
            dplpmtud_runtime: Arc::new(RwLock::new(None)),
            local_nat_profile: Arc::new(RwLock::new(None)),
            local_profile_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            local_interface_networks: Arc::new(RwLock::new(Vec::new())),
            traversal_history: Arc::new(RwLock::new(traversal_history)),
            traversal_history_path,
            punch_generations: Arc::new(RwLock::new(HashMap::new())),
            local_fresh_mappings: Arc::new(RwLock::new(HashMap::new())),
            hard_hard_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            hard_hard_cleanup_owners: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            hard_hard_winners: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            fresh_mapping_history: Arc::new(std::sync::Mutex::new(HashMap::new())),
            remote_fresh_generations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            remote_fresh_snapshots: Arc::new(std::sync::Mutex::new(HashMap::new())),
            pending_fresh_applies: Arc::new(std::sync::Mutex::new(HashMap::new())),
            remote_fresh_transaction_gate: Arc::new(tokio::sync::Mutex::new(())),
            remote_identity_ledger: Arc::new(
                std::sync::Mutex::new(RemoteIdentityLedger::default()),
            ),
            direct_peers: Arc::new(std::sync::Mutex::new(HashSet::new())),
            relay_first_required: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            recovery_epochs: Arc::new(RwLock::new(HashMap::new())),
            recovery_epoch_allocation_id: std::sync::atomic::AtomicU64::new(0),
            outbound_liveness_cache: Arc::new(RwLock::new(HashMap::new())),
            c0_pair_ledgers: Arc::new(RwLock::new(HashMap::new())),
            direct_commit_seq_mirror: Arc::new(std::sync::Mutex::new(HashMap::new())),
            direct_commit_notify: Arc::new(Notify::new()),
            direct_commit_pair_mirror: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_confirm_seq_mirror: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_confirm_notify: Arc::new(Notify::new()),
            relay_probe_expectations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            pending_relay_business_evidence: Arc::new(std::sync::Mutex::new(HashMap::new())),
            path_commit_expectations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            quarantined_peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            quarantine_deadline_mirror: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_not_found_grace: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            punch_cancel_hook: Arc::new(std::sync::Mutex::new(None)),
            relay_backoff_heartbeat_cancel_hook: Arc::new(std::sync::Mutex::new(None)),
            timeline: std::sync::Mutex::new(None),
            outbound_loss_slot: Arc::new(std::sync::Mutex::new(None)),
            outbound_loss_default: Arc::new(tokio::sync::Mutex::new(
                OutboundLossCounters::default(),
            )),
            config,
        }
    }

    /// Remember a negotiated capability at the WireGuard peer-session scope.
    /// The immutable watch value gives the business hot path a registry-free
    /// read and remains valid across a UDP socket publication replacement.
    pub(crate) fn mark_dplpmtud_capable_sync(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
    ) {
        let current = self.dplpmtud_capability_tx.borrow().clone();
        if current.get(peer_id) == Some(&peer_session_generation) {
            return;
        }
        let mut next = (*current).clone();
        next.retain(|candidate, generation| {
            self.peer_session_is_current_sync(candidate, *generation)
        });
        // This mirror is bounded by the authoritative live peer-session set,
        // not by the smaller DPLPMTUD worker/publication cap. Evicting a live
        // negotiated capability would incorrectly turn that modern peer into
        // a legacy bypass while its old runtime entry still existed.
        next.insert(peer_id.to_string(), peer_session_generation);
        self.dplpmtud_capability_tx.send_replace(Arc::new(next));
        self.notify_direct_business_budget_changed();
    }

    pub(crate) fn peer_supports_dplpmtud_sync(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
    ) -> bool {
        self.dplpmtud_capability_tx
            .borrow()
            .get(peer_id)
            .is_some_and(|generation| *generation == peer_session_generation)
    }

    pub(crate) fn direct_business_budget_change_sender(
        &self,
    ) -> tokio::sync::watch::Sender<u64> {
        self.direct_business_budget_change_tx.clone()
    }

    pub(crate) fn subscribe_direct_business_budget_changes(
        &self,
    ) -> tokio::sync::watch::Receiver<u64> {
        self.direct_business_budget_change_tx.subscribe()
    }

    pub(crate) fn notify_direct_business_budget_changed(&self) {
        self.direct_business_budget_change_tx.send_modify(|revision| {
            *revision = revision.wrapping_add(1);
        });
    }

    pub(crate) fn subscribe_local_mtu_feedback(
        &self,
    ) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.local_mtu_feedback_tx.subscribe()
    }

    pub(crate) fn emit_local_mtu_feedback(
        &self,
        peer_id: &str,
        original: &[u8],
        kind: crate::business_mtu::LocalMtuFeedbackKind,
    ) -> crate::business_mtu::LocalMtuFeedbackOutcome {
        use crate::business_mtu::{
            build_local_mtu_feedback, LocalMtuFeedbackOutcome, LocalMtuFeedbackSuppression,
        };

        let packet = match build_local_mtu_feedback(original, kind) {
            Ok(packet) => packet,
            Err(reason) => return LocalMtuFeedbackOutcome::Suppressed(reason),
        };
        let admitted = self
            .local_mtu_feedback_limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .admit(peer_id, tokio::time::Instant::now());
        if !admitted {
            return LocalMtuFeedbackOutcome::Suppressed(
                LocalMtuFeedbackSuppression::RateLimited,
            );
        }
        match self.local_mtu_feedback_tx.send(packet) {
            Ok(_) => LocalMtuFeedbackOutcome::Published,
            Err(_) => LocalMtuFeedbackOutcome::Suppressed(
                LocalMtuFeedbackSuppression::NoTunConsumer,
            ),
        }
    }

    /// Install the per-process connection timeline.  Called once by the daemon
    /// right after construction so path-confirmation events can emit.
    pub(crate) fn set_timeline(&self, timeline: Arc<ConnectionTimeline>) {
        *self
            .timeline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(timeline);
    }

    /// Install or remove the relay-first topology gate after control has
    /// resolved the current relay catalog. The gate is armed for every live
    /// peer under the same network-epoch lock used by Direct/relay commits,
    /// so relay-first remains the safe startup path until an authoritative
    /// Direct ACK commits a current Selected pair.
    pub(crate) async fn configure_relay_first(&self, required: bool) {
        self.relay_first_required
            .store(required, std::sync::atomic::Ordering::Release);
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let generation = self.current_network_generation_sync();
        let now = Instant::now();
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            if !conn.online || conn.state == ConnectionState::Closed {
                continue;
            }
            if required {
                if conn.relay_first.gate_generation != Some(generation) {
                    conn.relay_first.gate_generation = Some(generation);
                    conn.relay_first.gate_started_at = Some(now);
                    self.emit_timeline(
                        "relay_first_gate_armed",
                        Some("relay"),
                        None,
                        Some(format!(
                            "peer={} generation={} source=relay_catalog",
                            conn.node_id, generation
                        )),
                    );
                }
            } else if conn.relay_confirmed_generation != Some(generation) {
                conn.relay_first.gate_generation = None;
                conn.relay_first.gate_started_at = None;
            }
        }
    }

    /// Whether the resolved topology requires relay-first admission.
    pub(crate) fn relay_first_required(&self) -> bool {
        self.relay_first_required
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Emit a connection-timeline event; no-op when no timeline is installed.
    pub(crate) fn emit_timeline(
        &self,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) {
        let timeline = self
            .timeline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(timeline) = timeline {
            timeline.emit(event, path, reason_code, detail);
        }
    }

    /// Emit a correlation-aware diagnostic event at DEBUG level.  High-volume
    /// Direct lifecycle records are intentionally log-only; the peer's
    /// protected `direct_events` ring remains the structured `/status` source
    /// while the process milestone ring is not evicted by probe bursts.
    pub(crate) fn emit_timeline_debug(
        &self,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) {
        let timeline = self
            .timeline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(timeline) = timeline {
            timeline.log_debug(event, path, reason_code, detail);
        }
    }

    /// Emit a connection-timeline first-milestone event scoped to a
    /// peer + network generation; no-op when no timeline is installed or when
    /// the same (peer, generation, event) already emitted.  Returns whether it
    /// emitted.
    pub(crate) fn emit_timeline_first(
        &self,
        peer_id: &str,
        generation: u64,
        event: &'static str,
        path: Option<&str>,
        reason_code: Option<&str>,
        detail: Option<String>,
    ) -> bool {
        let timeline = self
            .timeline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let scope = format!("peer:{peer_id}:{generation}");
        match timeline {
            Some(timeline) => timeline.emit_first_scoped(&scope, event, path, reason_code, detail),
            None => false,
        }
    }

    /// Record the first-usable milestone and the persistent machine-readable
    /// summary at the same authoritative business-ingress commit. The caller
    /// supplies the already-validated business dimensions; transport readiness
    /// and relay confirmation alone cannot create this record.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_timeline_first_usable(
        &self,
        peer_id: &str,
        generation: u64,
        path: &str,
        reason_code: Option<&str>,
        detail: Option<String>,
        business_sent: bool,
        business_received: bool,
        business_exchange: bool,
        relay_id: Option<&str>,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let timeline = self
            .timeline
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        timeline.is_some_and(|timeline| {
            timeline.emit_first_usable(
                peer_id,
                generation,
                path,
                reason_code,
                detail,
                business_sent,
                business_received,
                business_exchange,
                relay_id,
                relay_connection_id,
            )
        })
    }

    /// Record dropped outbound business packets for a stable reason code so
    /// `/status` can report queue/startup-wait loss structurally.  Terminal
    /// loss only: a packet that was handed to a transport (even if the remote
    /// never got it) is not a drop here.
    pub(crate) async fn record_outbound_drop(
        &self,
        reason_code: &str,
        packets: usize,
        bytes: usize,
    ) {
        let sink = self.outbound_loss_sink();
        let mut loss = sink.lock().await;
        let entry = loss.drops.entry(reason_code.to_string()).or_default();
        entry.packets = entry.packets.saturating_add(packets as u64);
        entry.bytes = entry.bytes.saturating_add(bytes as u64);
    }

    /// Record a transient outbound send-failure ATTEMPT (the packet is
    /// re-parked and retried, so it is NOT a drop).  Kept separate from
    /// `outbound_drops` so a retried failure is observable without being
    /// double-counted as terminal loss.  Send failures are recorded by the
    /// WireGuard transport (which owns the shared sink), so this peer-manager
    /// entry point currently has no production caller and stays private.
    #[allow(dead_code)]
    pub(crate) async fn record_outbound_send_failure(&self, reason_code: &str, attempts: usize) {
        let sink = self.outbound_loss_sink();
        let mut loss = sink.lock().await;
        let entry = loss
            .send_failures
            .entry(reason_code.to_string())
            .or_default();
        entry.packets = entry.packets.saturating_add(attempts as u64);
    }

    /// The shared loss sink: the daemon's shared map when installed, the
    /// per-manager default otherwise.
    fn outbound_loss_sink(&self) -> Arc<tokio::sync::Mutex<OutboundLossCounters>> {
        self.outbound_loss_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .unwrap_or_else(|| self.outbound_loss_default.clone())
    }

    /// Share this peer manager's outbound-loss counters with the WireGuard
    /// transport so session-not-ready queue loss lands in the SAME map that
    /// `/status.stats` reads.  Installed once by the daemon before any
    /// traffic flows.
    pub fn set_outbound_loss_sink(&self, sink: Arc<tokio::sync::Mutex<OutboundLossCounters>>) {
        *self
            .outbound_loss_slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sink);
    }

    /// Snapshot of the process-wide outbound loss counters.
    pub async fn outbound_loss_stats(&self) -> OutboundLossCounters {
        self.outbound_loss_sink().lock().await.clone()
    }

    /// Append one structured outbound loss/send-failure event to the bounded
    /// process ledger.  Aggregates and this ledger intentionally share the
    /// same mutex so a status snapshot cannot observe one without the other.
    pub(crate) async fn record_outbound_loss_event(&self, event: OutboundLossEvent) {
        const MAX_OUTBOUND_LOSS_EVENTS: usize = 512;
        let sink = self.outbound_loss_sink();
        let mut loss = sink.lock().await;
        if loss.events.len() >= MAX_OUTBOUND_LOSS_EVENTS {
            loss.events.remove(0);
        }
        loss.events.push(event);
    }

    /// Update the latest local NAT profile used by adaptive probe scheduling.
    pub async fn update_nat_profile(&self, profile: NatProfile) {
        let (profile_generation, profile_changed) = {
            let mut current = self.local_nat_profile.write().await;
            if current.as_ref() == Some(&profile) {
                (self.current_local_profile_generation_sync(), false)
            } else {
                *current = Some(profile.clone());
                let previous = self
                    .local_profile_generation
                    .fetch_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |generation| Some(generation.saturating_add(1)),
                    )
                    .unwrap_or(u64::MAX);
                (previous.saturating_add(1), true)
            }
        };
        let network_generation = self.current_network_generation_sync();
        let capabilities =
            NatCapabilities::from_profile(&profile).with_profile_generation(profile_generation);
        debug!(
            event = "nat_profile_updated",
            network_generation,
            local_profile_generation = profile_generation,
            mapping_behavior = ?capabilities.mapping_behavior,
            filtering_behavior = ?capabilities.filtering_behavior,
            allocation_model = ?capabilities.allocation_model,
            prediction_confidence = capabilities.prediction_confidence,
            prediction_window = capabilities.prediction_window,
            "updated local NAT capability evidence"
        );
        if profile_changed {
            self.clear_hard_hard_sessions(None).await;
        }
    }

    pub(crate) fn current_local_profile_generation_sync(&self) -> u64 {
        self.local_profile_generation
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Publish the currently enumerated physical interface prefixes used by
    /// the bounded on-link Host fast lane. The snapshot is copied into every
    /// live connection so candidate ordering and diagnostics use one coherent
    /// local-network view.
    pub(crate) async fn set_local_interface_networks(&self, networks: Vec<LocalNetwork>) {
        *self.local_interface_networks.write().await = networks.clone();
        let mut connections = self.connections.write().await;
        for connection in connections.values_mut() {
            connection.set_local_interface_networks(networks.clone());
        }
    }

    pub(crate) async fn current_remote_candidate_epoch(&self, node_id: &str) -> Option<u64> {
        self.connections
            .read()
            .await
            .get(node_id)
            .map(PeerConnection::remote_candidate_epoch)
    }

    /// Bind a fresh-prediction candidate transaction to the remote NAT
    /// profile generation carried by the same authenticated Hard↔Hard
    /// envelope. A profile that is merely young, but belongs to an older
    /// candidate context, cannot be revived by this method.
    pub(crate) async fn bind_remote_nat_profile_to_candidate_epoch(
        &self,
        node_id: &str,
        profile_generation: u64,
    ) -> bool {
        let mut connections = self.connections.write().await;
        connections.get_mut(node_id).is_some_and(|connection| {
            connection.bind_remote_nat_profile_to_candidate_epoch(profile_generation)
        })
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
        self.traversal_history
            .try_read()
            .map(|history| history.diagnostics())
            .unwrap_or_else(|_| TraversalHistoryDiagnostics {
                sources: Vec::new(),
            })
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
        self.network_generation_sync
            .load(std::sync::atomic::Ordering::Acquire)
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
            registry
                .cancel_peer_with_reason(peer_id, "peer_lifecycle_or_session_removed")
                .await;
        }
    }

    /// Cancel a peer's Direct-validation ownership after an accepted remote
    /// candidate-set handover. Candidate publication releases the epoch gate
    /// before awaiting this cancellation, keeping the publication transaction
    /// bounded.
    pub(crate) async fn cancel_direct_validation_for_remote_candidate_change(&self, peer_id: &str) {
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry
                .cancel_peer_with_reason(peer_id, "remote_candidate_generation_changed")
                .await;
        }
    }

    /// Publish the DPLPMTUD runtime owned by the active UDP transport.
    /// Replacing a transport closes every old worker before the new handle is
    /// visible, so a rebound socket cannot reuse a stale Probe/ACK identity.
    pub(crate) async fn register_dplpmtud_runtime(
        &self,
        runtime: crate::dplpmtud::DplpmtudRuntime,
    ) {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let previous = self.dplpmtud_runtime.write().await.replace(runtime);
        if let Some(previous) = previous {
            previous.close(
                "udp_transport_replaced",
                tokio::time::Instant::now(),
            );
        }
    }

    pub(crate) async fn current_dplpmtud_runtime(
        &self,
    ) -> Option<crate::dplpmtud::DplpmtudRuntime> {
        self.dplpmtud_runtime.read().await.clone()
    }

    /// Cancel the current exact-path worker at a peer lifecycle boundary.
    pub(crate) async fn cancel_active_dplpmtud_for_peer(
        &self,
        peer_id: &str,
        reason: &str,
    ) {
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        if let Some(runtime) = self.dplpmtud_runtime.read().await.clone() {
            runtime.cancel_peer(peer_id, reason, tokio::time::Instant::now());
        }
    }

    /// Candidate publication releases the epoch gate before awaiting this
    /// cancellation, so DPLPMTUD peer cleanup does not block other epoch waiters.
    pub(crate) async fn cancel_dplpmtud_for_remote_candidate_change(
        &self,
        peer_id: &str,
    ) {
        if let Some(runtime) = self.dplpmtud_runtime.read().await.clone() {
            runtime.cancel_peer(
                peer_id,
                "remote_candidate_generation_changed",
                tokio::time::Instant::now(),
            );
        }
    }

    /// Exact no-await fence used immediately before a Probe send and while an
    /// ACK is consumed.  The state-machine snapshot is the active-path
    /// authority; the Direct-pair mirror additionally binds the local socket
    /// endpoint committed by the encrypted validation transaction.
    pub(crate) fn dplpmtud_path_is_current_sync(
        &self,
        identity: &crate::dplpmtud::DplpmtudPathIdentity,
    ) -> bool {
        let committed = self
            .committed_business_paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&identity.peer_id)
            .cloned();
        let Some(committed) = committed else {
            return false;
        };
        if !identity.matches_committed_path(
            committed.lifecycle,
            committed.epoch,
            &committed.active,
        ) {
            return false;
        }
        self.direct_commit_pair_mirror
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&identity.peer_id)
            .is_some_and(|pair| {
                pair.generation == identity.epoch.network_generation
                    && pair.remote_candidate_epoch == identity.epoch.remote_candidate_epoch
                    && pair.local_endpoint == Some(identity.local_endpoint)
            })
    }

    /// Whether a peer connection currently exists, readable without awaiting
    /// or contending on the async connection map.
    ///
    /// `add_peer` and `remove_peer` maintain this membership mirror at their
    /// lifecycle linearization points.  In particular, an unrelated writer on
    /// `connections` cannot turn an existing peer into a false negative.  This
    /// is used both by the serial control consumer and under the UDP adoption
    /// lock, where awaiting the connection map is not acceptable.
    pub(crate) fn peer_exists_sync(&self, node_id: &str) -> bool {
        self.peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(node_id)
    }

    /// Whether `expected` still names the online lifecycle that authenticated
    /// an inbound packet. The synchronous guard is never held across an await
    /// or while acquiring the connection/adoption locks.
    pub(crate) fn peer_session_is_current_sync(
        &self,
        node_id: &str,
        expected: PeerSessionGeneration,
    ) -> bool {
        self.peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_generation_is_current(node_id, expected)
    }

    /// Snapshot the currently-online peer lifecycle for delayed work which
    /// must fail closed across a same-node remove/re-add.  Callers re-check
    /// the returned generation with `peer_session_is_current_sync` immediately
    /// before committing their delayed action.
    pub(crate) fn peer_session_generation_sync(
        &self,
        node_id: &str,
    ) -> Option<PeerSessionGeneration> {
        self.peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active_generation(node_id)
    }

    fn peer_session_generation_any_sync(
        &self,
        node_id: &str,
    ) -> Option<PeerSessionGeneration> {
        self.peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .generation(node_id)
    }

    /// Hold the connection writer for deterministic lock-contention tests.
    /// Production code never needs to expose this guard; the test-only helper
    /// makes it possible to prove timing-sensitive paths do not await this
    /// lock.
    #[cfg(test)]
    pub(crate) async fn hold_connections_writer_for_test(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, HashMap<String, PeerConnection>> {
        self.connections.write().await
    }

    /// Hold a connection reader while a second task queues a writer.  This
    /// models Tokio's fair RwLock admission rule without timing sleeps.
    #[cfg(test)]
    pub(crate) async fn hold_connections_reader_for_test(
        &self,
    ) -> tokio::sync::OwnedRwLockReadGuard<HashMap<String, PeerConnection>> {
        self.connections.clone().read_owned().await
    }

    #[cfg(test)]
    pub(crate) fn install_authenticated_probe_verify_gate_for_test(
        &self,
        node_id: &str,
        gate: Arc<AuthenticatedProbeVerifyGate>,
    ) {
        *self
            .authenticated_probe_verify_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((node_id.to_string(), gate));
    }

    #[cfg(test)]
    pub(crate) async fn pause_after_authenticated_probe_verify_for_test(
        &self,
        node_id: &str,
    ) -> Option<Arc<AuthenticatedProbeVerifyGate>> {
        let gate = {
            let mut installed = self
                .authenticated_probe_verify_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if installed
                .as_ref()
                .is_some_and(|(expected, _)| expected == node_id)
            {
                installed.take().map(|(_, gate)| gate)
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.wait().await;
            Some(gate)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn connection_map_for_test(&self) -> Arc<RwLock<HashMap<String, PeerConnection>>> {
        self.connections.clone()
    }

    #[cfg(test)]
    pub(crate) fn peer_session_snapshot_for_test(
        &self,
        node_id: &str,
    ) -> Option<(PeerSessionGeneration, bool)> {
        self.peer_membership
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .peers
            .get(node_id)
            .map(|entry| (entry.session_generation, entry.online))
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
        let stale_handshake_probe_bindings =
            self.cancel_handshakes_before_network_generation(generation);
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry.cancel_before_generation(generation).await;
        }
        if let Some(runtime) = self.dplpmtud_runtime.read().await.clone() {
            runtime.cancel_before_network_generation(
                generation,
                "network_generation_advanced",
                tokio::time::Instant::now(),
            );
        }

        let mut direct_reclaim_count = 0usize;
        let mut relay_confirmation_cancellations = Vec::new();
        let mut conns = self.connections.write().await;
        for (peer_id, token) in stale_handshake_probe_bindings {
            if let Some(conn) = conns.get_mut(&peer_id) {
                conn.pending_probe_bindings.remove(&token);
            }
        }
        for conn in conns.values_mut() {
            let Some(peer_session_generation) =
                self.peer_session_generation_any_sync(&conn.node_id)
            else {
                continue;
            };
            let had_relay_confirmation = conn.relay_confirmed_at.is_some();
            conn.mark_network_generation_changed(
                generation,
                peer_session_generation,
                reason.clone(),
            );
            if had_relay_confirmation && conn.relay_confirmed_at.is_none() {
                relay_confirmation_cancellations.push(conn.node_id.clone());
            }
            if conn.start_direct_reclaim_window(generation, &reason) {
                direct_reclaim_count += 1;
            }
        }
        let peer_count = conns.len();
        drop(conns);
        let relay_confirmation_cancellation_count = relay_confirmation_cancellations.len();
        for peer_id in relay_confirmation_cancellations {
            self.bump_relay_confirm_seq(&peer_id);
        }
        self.clear_all_fresh_mappings("network_generation_changed")
            .await;
        self.clear_hard_hard_sessions(None).await;

        info!(
            "Local network generation advanced to {generation}: {reason}; opened {direct_reclaim_count} Direct reclaim window(s)"
        );
        self.emit_timeline(
            "network_generation_advanced",
            None,
            Some("network_generation_changed"),
            Some(format!(
                "generation={generation} reason={reason} peers={} direct_reclaim_windows={} relay_confirmations_cancelled={}",
                peer_count,
                direct_reclaim_count,
                relay_confirmation_cancellation_count
            )),
        );
        generation
    }

    /// Install the daemon-owned short transaction that retires handshake
    /// reservations when the local network generation advances.
    pub(crate) fn set_network_generation_handshake_cancel_hook(
        &self,
        hook: NetworkGenerationHandshakeCancelHook,
    ) {
        *self
            .network_generation_handshake_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    fn cancel_handshakes_before_network_generation(
        &self,
        generation: u64,
    ) -> Vec<(String, String)> {
        let hook = self
            .network_generation_handshake_cancel_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        hook.map_or_else(Vec::new, |cancel_stale_handshakes| {
            let (_, _, stale_probe_bindings) = cancel_stale_handshakes(generation);
            stale_probe_bindings
        })
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
        let stale_handshake_probe_bindings =
            self.cancel_handshakes_before_network_generation(generation);
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry.cancel_before_generation(generation).await;
        }
        if let Some(runtime) = self.dplpmtud_runtime.read().await.clone() {
            runtime.cancel_before_network_generation(
                generation,
                "candidate_refresh_generation_advanced",
                tokio::time::Instant::now(),
            );
        }

        let mut retained_confirmed_direct_count = 0usize;
        let mut direct_reclaim_count = 0usize;
        let mut conns = self.connections.write().await;
        for (peer_id, token) in stale_handshake_probe_bindings {
            if let Some(conn) = conns.get_mut(&peer_id) {
                conn.pending_probe_bindings.remove(&token);
            }
        }
        for conn in conns.values_mut() {
            let Some(peer_session_generation) =
                self.peer_session_generation_any_sync(&conn.node_id)
            else {
                continue;
            };
            let retained_confirmed_direct =
                conn.mark_candidate_refresh_generation_changed(
                    generation,
                    peer_session_generation,
                    reason.clone(),
                );
            if retained_confirmed_direct {
                retained_confirmed_direct_count += 1;
                continue;
            }

            if conn.start_direct_reclaim_window(generation, &reason) {
                direct_reclaim_count += 1;
            }
        }
        let peer_count = conns.len();
        drop(conns);
        self.clear_all_fresh_mappings("candidate_refresh_generation_changed")
            .await;
        self.clear_hard_hard_sessions(None).await;

        info!(
            "Local network generation advanced to {generation}: {reason}; retained {retained_confirmed_direct_count} confirmed direct path(s); opened {direct_reclaim_count} Direct reclaim window(s)"
        );
        self.emit_timeline(
            "candidate_refresh_generation_advanced",
            None,
            Some("candidate_refresh_generation_changed"),
            Some(format!(
                "generation={generation} reason={reason} peers={} retained_direct={} direct_reclaim_windows={}",
                peer_count,
                retained_confirmed_direct_count,
                direct_reclaim_count
            )),
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
