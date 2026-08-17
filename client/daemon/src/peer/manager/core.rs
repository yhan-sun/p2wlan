impl PeerManager {
    /// Whether startup/live candidate gathering may advertise extrapolated
    /// server-reflexive endpoints.  Keep this accessor in the core manager
    /// implementation so fast startup gathering does not depend on any
    /// experimental fresh-mapping worktree file.
    pub(crate) fn predicted_candidates_enabled_for_gather(&self) -> bool {
        self.config.network.predicted_candidates_enabled
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
            relay_first_required: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            recovery_epochs: Arc::new(RwLock::new(HashMap::new())),
            outbound_liveness_cache: Arc::new(RwLock::new(HashMap::new())),
            c0_pair_ledgers: Arc::new(RwLock::new(HashMap::new())),
            direct_commit_seq_mirror: Arc::new(std::sync::Mutex::new(HashMap::new())),
            direct_commit_notify: Arc::new(Notify::new()),
            relay_confirm_seq_mirror: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_confirm_notify: Arc::new(Notify::new()),
            relay_probe_expectations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            quarantined_peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            relay_not_found_grace: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            punch_cancel_hook: Arc::new(std::sync::Mutex::new(None)),
            relay_backoff_heartbeat_cancel_hook: Arc::new(std::sync::Mutex::new(None)),
            timeline: std::sync::Mutex::new(None),
            outbound_loss_slot: Arc::new(std::sync::Mutex::new(None)),
            outbound_loss_default: Arc::new(tokio::sync::Mutex::new(OutboundLossCounters::default())),
            config,
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
    /// so a Direct ACK racing relay startup cannot win by arriving first.
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
                if conn.relay_first_gate_generation != Some(generation) {
                    conn.relay_first_gate_generation = Some(generation);
                    conn.relay_first_gate_started_at = Some(now);
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
                conn.relay_first_gate_generation = None;
                conn.relay_first_gate_started_at = None;
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
            registry
                .cancel_peer_with_reason(peer_id, "peer_lifecycle_or_session_removed")
                .await;
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
        let mut relay_confirmation_cancellations = Vec::new();
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            let had_relay_confirmation = conn.relay_confirmed_at.is_some();
            conn.direct_health.record_generation_change(reason.clone());
            conn.mark_network_generation_changed(generation, reason.clone());
            if had_relay_confirmation && conn.relay_confirmed_at.is_none() {
                relay_confirmation_cancellations.push(conn.node_id.clone());
            }
            if conn.state == ConnectionState::Direct {
                conn.transition(ConnectionState::FallbackToRelay);
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
        self.clear_all_fresh_mappings("network_generation_changed").await;

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
        let peer_count = conns.len();
        drop(conns);
        self.clear_all_fresh_mappings("candidate_refresh_generation_changed").await;

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
