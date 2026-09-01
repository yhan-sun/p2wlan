// ============================================================
// Peer Connection
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeSessionBinding {
    token: Option<String>,
    session_id: Option<String>,
    ephemeral_shared: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct RetainedProbeSessionBinding {
    binding: ProbeSessionBinding,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct PendingProbeSessionBinding {
    binding: ProbeSessionBinding,
    expires_at: Instant,
    promote_on_match: bool,
}

/// The relay-first business gate state for one peer connection.
///
/// This is the set of fields that describe relay-first startup/fallback
/// evidence after a same-generation relay transport is ready and
/// peer-confirmed. Grouping them here (instead of flat on [`PeerConnection`])
/// keeps the legal/illegal state combinations locally contained: the gate is
/// one atomic concept with a bounded set of milestones, not N independent
/// booleans scattered across a 60-field struct. An authoritative current
/// Direct pair is primary and does not wait for these business markers.
#[derive(Debug, Clone, Default)]
pub(crate) struct RelayFirstBusinessState {
    /// Generation in which the first-business relay gate began waiting.  This
    /// is distinct from `relay_ready_at`: the gate may start as soon as the
    /// shared relay transport exists, before the per-peer session publishes
    /// its ready milestone.
    pub gate_generation: Option<u64>,
    /// Monotonic start of the bounded first-business relay gate.
    pub gate_started_at: Option<Instant>,
    /// Generation for which at least one real business packet was accepted by
    /// the confirmed relay writer. This is relay fallback evidence; an
    /// authoritative current Direct pair does not wait for both directions.
    /// The receive marker is kept separately because a peer can send its first
    /// packet over relay and later deliver the other direction directly.
    pub business_sent_generation: Option<u64>,
    /// Generation for which a normal decrypted business packet was received
    /// through the confirmed relay.  This closes the bidirectional relay-first
    /// race: local relay writer completion alone cannot authorize Direct for
    /// the other direction.
    pub business_received_generation: Option<u64>,
    /// Generation for which a relay business packet was sent locally and a
    /// normal relay business packet was received. Writer completion is not a
    /// peer-delivery proof; this two-direction marker records that both
    /// directions crossed the confirmed relay. The two component markers may
    /// arrive in either order.
    pub business_exchange_generation: Option<u64>,
    /// Generation for which a synthetic path-commit probe round-tripped over
    /// the confirmed relay, proving bidirectional relay data without natural
    /// traffic (audit P0-4). An alternative to `..._exchange_generation` for
    /// completing relay fallback evidence; it does not itself activate
    /// Direct.
    pub business_pathcommit_generation: Option<u64>,
    /// Generation in which the relay-first business gate completed at least
    /// once.  Unlike the per-transport business markers above, this survives
    /// a make-before-break relay ticket renewal: the replacement transport
    /// still needs a fresh encrypted relay confirmation for fallback, but an
    /// already-established Direct path must not be demoted and forced to
    /// repeat the initial relay-first gate.
    pub business_gate_completed_generation: Option<u64>,
}

/// No-await, generation-bound projection of one peer's committed business
/// path. It contains typed state-machine values rather than compatibility
/// booleans or an independently selected path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommittedBusinessPathSnapshot {
    pub(crate) peer_id: String,
    pub(crate) virtual_ip: String,
    pub(crate) lifecycle: PeerPathLifecycle,
    pub(crate) epoch: Option<PathEpoch>,
    pub(crate) active: ActiveBusinessPath,
}

impl CommittedBusinessPathSnapshot {
    pub(crate) fn active_path(&self) -> Option<NetworkPath> {
        self.active.network_path()
    }

    pub(crate) fn is_online_in_generation(&self, generation: u64) -> bool {
        self.lifecycle == PeerPathLifecycle::Online
            && self
                .epoch
                .is_some_and(|epoch| epoch.network_generation == generation)
    }
}

/// Information about a connection to a specific peer.
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Peer node ID.
    pub node_id: String,
    /// Human-readable peer device name.
    pub device_name: String,
    /// Peer application/daemon version reported by the control plane.
    pub app_version: String,
    /// Peer's static WireGuard/X25519 public key as hex.
    pub public_key: String,
    /// Symmetric MAC key for authenticated UDP Probe v2.
    pub probe_mac_key: Option<ProbeMacKey>,
    /// Current control-plane session ID used to bind Probe v2 MAC keys.
    pub probe_session_id: Option<String>,
    /// Session-local X25519 shared secret used to rotate Probe v2 MAC keys.
    pub probe_ephemeral_shared: Option<[u8; 32]>,
    /// Opaque handshake token associated with the current Probe-v2 binding.
    probe_binding_token: Option<String>,
    /// Replacement Probe-v2 binding staged transactionally during a handshake.
    pending_probe_bindings: HashMap<String, PendingProbeSessionBinding>,
    /// Prior Probe-v2 binding accepted during a rekey overlap or restored when
    /// publishing the replacement offer fails.
    previous_probe_binding: Option<RetainedProbeSessionBinding>,
    /// Peer's virtual IP.
    pub virtual_ip: String,
    /// Peer's public endpoint (ip:port) if known.
    pub endpoint: Option<SocketAddr>,
    /// Endpoint currently advertised by peer metadata. This is kept separate
    /// from an authenticated peer-reflexive endpoint learned on the wire.
    pub signaled_endpoint: Option<SocketAddr>,
    /// Peer's NAT type.
    pub nat_type: String,
    /// Structured remote NAT evidence carried by the compatibility control
    /// label. This is advisory until its generation and receive age pass the
    /// freshness fence; authenticated candidate/path evidence remains the
    /// authority for promotion.
    pub remote_nat_profile: Option<RemoteNatProfile>,
    /// Remote profile context captured when the profile was accepted. Age
    /// and profile generation alone cannot authorize Hard↔Hard after a newer
    /// candidate set has been published.
    remote_nat_profile_candidate_epoch: Option<u64>,
    /// Whether the control plane currently reports this peer online.
    pub online: bool,
    /// Last seen timestamp reported by the control plane.
    pub last_seen: u64,
    /// Peer-reported RTT to its selected relay server, in milliseconds.
    pub remote_relay_rtt_ms: Option<u64>,
    /// Current connection state.
    pub state: ConnectionState,
    /// Authoritative typed path state. `state` above is updated atomically as
    /// its compatibility projection by `commit_path_transition`.
    path_state_machine: PathStateMachine,
    /// When the connection was established.
    pub connected_at: Option<Instant>,
    /// Bytes sent to this peer.
    pub bytes_sent: u64,
    /// Bytes received from this peer.
    pub bytes_received: u64,
    /// Which relay server is being used (if connected via relay).
    pub relay_server: Option<String>,
    /// ICE candidates for this peer.
    pub candidates: Vec<String>,
    /// Candidate strings from the most recent peer offer/answer.
    signaled_candidates: HashSet<String>,
    /// Newer candidate sets replace older ones; generation 0 remains valid for
    /// legacy peers that have not yet been upgraded.
    last_candidate_generation: u64,
    /// Highest encoded remote daemon incarnation observed for this identity.
    ///
    /// This must not be derived from `last_candidate_generation`: a remote
    /// restart clears candidate/path state before the replacement signal is
    /// applied, and a second restart can arrive through the deferred responder
    /// lane during that gap. Keeping the incarnation high-water independent
    /// prevents an older deferred signal from rotating the lifecycle backwards.
    remote_candidate_incarnation_high_water: Option<u64>,
    /// Local monotonic epoch for the accepted remote candidate set. This is
    /// intentionally separate from the wire generation because legacy peers
    /// may repeatedly publish generation `0`.
    remote_candidate_epoch: u64,
    /// Directly-connected local interface prefixes used to identify a remote
    /// Host candidate as genuinely on-link. This prevents RFC1918/ULA or
    /// overlay addresses from being treated as LAN merely by address class.
    local_interface_networks: Vec<LocalNetwork>,
    last_candidates_expires_at_ms: Option<u64>,
    /// Local-only source metadata keyed by candidate endpoint string.
    pub candidate_sources: HashMap<String, CandidatePairSource>,
    /// Direct UDP path health.
    pub direct_health: PathHealth,
    /// Relay path health.
    pub relay_health: PathHealth,
    /// Local network generation in which the direct path was last confirmed.
    pub direct_generation: u64,
    /// Monotonic direct-commit sequence.  Bumped inside the network-epoch
    /// critical section every time the Direct confirmation changes (promotion
    /// or endpoint change); outbound punch loops gate every actual UDP send
    /// on this sequence.
    pub direct_commit_seq: u64,
    /// Local network generation in which a relay transport first became ready
    /// to carry this peer's traffic (the shared relay slot published an
    /// endpoint while the peer had an encrypting WireGuard session).  This is
    /// the per-peer `RelayTransportConnected` milestone: it is strictly weaker
    /// than [`relay_confirmed_generation`] (a TCP/TLS connect or a queued
    /// registration must never count as delivery).
    pub relay_ready_generation: Option<u64>,
    /// Monotonic instant (daemon-local) of the per-peer relay-ready milestone.
    pub relay_ready_at: Option<Instant>,
    /// Relay endpoint that carried the per-peer relay-ready milestone.
    pub relay_ready_endpoint: Option<String>,
    /// Local relay transport incarnation that carried the per-peer
    /// relay-ready milestone.  The endpoint may be reused by a reconnect, so
    /// endpoint + generation alone is not enough to bind readiness to the
    /// current writer/reader pair.
    pub relay_ready_connection_id: Option<u64>,
    /// Local network generation in which the relay path to this peer was
    /// confirmed by a matching forced-relay encrypted probe/ACK (the ACK's real
    /// ingress was relay).  Never set by a local TCP/TLS connect or by a
    /// command-queue accept.
    pub relay_confirmed_generation: Option<u64>,
    /// Monotonic instant (daemon-local) of the relay peer confirmation.
    pub relay_confirmed_at: Option<Instant>,
    /// Relay endpoint whose ingress carried the confirming ACK.
    pub relay_confirmed_endpoint: Option<String>,
    /// Local relay transport incarnation whose encrypted probe ACK confirmed
    /// the endpoint.  A reconnect/renewal can reuse the same endpoint, so an
    /// endpoint string alone cannot identify the connection that was proven.
    pub relay_confirmed_connection_id: Option<u64>,
    /// Relay-first startup/fallback business evidence state.
    pub(crate) relay_first: RelayFirstBusinessState,
    /// Monotonic relay-confirm sequence.  Bumped (and mirrored in the peer
    /// manager, notified to outbound waiters) every time the peer's relay
    /// confirmation changes, mirroring [`direct_commit_seq`].
    pub relay_confirm_seq: u64,
    /// Local network generation of the first confirmed usable path
    /// (`RelayPeerConfirmed` or `DirectConfirmed`), the first-business-packet
    /// milestone.
    pub first_usable_generation: Option<u64>,
    /// Monotonic instant (daemon-local) of the first usable path milestone.
    pub first_usable_at: Option<Instant>,
    /// Which path became first usable.
    pub first_usable_path: Option<NetworkPath>,
    /// Short window after a local generation change where previous Direct peers
    /// are reprobed aggressively before returning to normal retry backoff.
    direct_reclaim_until: Option<Instant>,
    /// Direct candidate-pair reachability table.
    pub candidate_pairs: Vec<CandidatePair>,
    /// Wide birthday rank committed by the last fully covered stable-side scan.
    /// Candidate source refreshes and Probe-v2 rekeys intentionally preserve it.
    birthday_probe_cursor: usize,
    /// Last selector decision made for outbound peer traffic.
    pub last_path_selection: Option<PathSelection>,
    /// Recent real outbound path-selector transitions.
    pub path_events: Vec<PathSelectionEvent>,
    /// Recent direct traversal timeline events.
    pub direct_events: Vec<DirectTraversalEvent>,
    /// Shared synchronous Direct-set mirror owned by the PeerManager.  Kept in
    /// lockstep from `transition` and `reset_for_identity_change`, so the UDP
    /// dynamic-socket eviction can re-verify "is this peer Direct?" under its
    /// own socket-state lock without awaiting the async manager there.
    direct_cache: Option<Arc<std::sync::Mutex<HashSet<String>>>>,
    /// Manager-owned lock-free snapshot of the exact pair selected by the
    /// latest Direct commit. It is cleared with the Direct-set mirror on any
    /// non-Direct transition so a generic state change cannot resurrect a
    /// stale Hard↔Hard pair.
    direct_pair_cache:
        Option<Arc<std::sync::Mutex<HashMap<String, DirectCommitPairSnapshot>>>>,
    /// Manager-owned, no-await projection of the committed typed path state.
    /// The validation harness and future observability consumers read this
    /// instead of treating a contended diagnostics cache as path authority.
    committed_business_path_cache: Option<
        Arc<std::sync::Mutex<HashMap<String, CommittedBusinessPathSnapshot>>>,
    >,
    /// Change stream for the committed-path projection. It is notified only
    /// after the reducer commit and its infallible side effects have completed
    /// under the connection writer.
    committed_business_path_change_tx: Option<tokio::sync::watch::Sender<u64>>,
}

impl PeerConnection {
    pub(crate) fn remote_candidate_epoch(&self) -> u64 {
        self.remote_candidate_epoch
    }

    pub(crate) fn remote_nat_profile_matches_candidate_epoch(&self) -> bool {
        self.remote_nat_profile_candidate_epoch == Some(self.remote_candidate_epoch)
    }

    pub(crate) fn bind_remote_nat_profile_to_candidate_epoch(
        &mut self,
        profile_generation: u64,
    ) -> bool {
        if !self.remote_nat_profile_is_fresh()
            || self
                .remote_nat_profile
                .as_ref()
                .and_then(|profile| profile.generation)
                != Some(profile_generation)
        {
            return false;
        }
        self.remote_nat_profile_candidate_epoch = Some(self.remote_candidate_epoch);
        true
    }

    pub(crate) fn set_local_interface_networks(&mut self, networks: Vec<LocalNetwork>) {
        self.local_interface_networks = networks;
    }

    /// Accept a remote NAT hint only when it does not move the profile
    /// generation backwards. Unversioned legacy labels remain useful as
    /// display/diagnostic data, but cannot replace a versioned profile.
    pub(crate) fn update_remote_nat_profile(
        &mut self,
        nat_type: &str,
        stable_endpoint: Option<SocketAddr>,
    ) -> bool {
        let hint = parse_nat_hint(nat_type);
        let incoming_generation = hint.profile_generation;
        let current_generation = self
            .remote_nat_profile
            .as_ref()
            .and_then(|profile| profile.generation);
        let accepts = match (current_generation, incoming_generation) {
            (Some(current), Some(incoming)) => incoming >= current,
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !accepts {
            debug!(
                peer = %self.node_id,
                current_generation = ?current_generation,
                incoming_generation = ?incoming_generation,
                "ignored stale or unversioned remote NAT profile"
            );
            return false;
        }
        let stable_endpoint = stable_endpoint.filter(|endpoint| is_public_probe_endpoint(*endpoint));
        self.remote_nat_profile = Some(RemoteNatProfile {
            capabilities: NatCapabilities::from_fingerprint_hint(&hint, stable_endpoint),
            generation: incoming_generation,
            received_at_ms: nat_profile_now_ms(),
        });
        self.remote_nat_profile_candidate_epoch = Some(self.remote_candidate_epoch);
        debug!(
            event = "remote_nat_profile_updated",
            peer = %self.node_id,
            remote_profile_generation = ?incoming_generation,
            mapping_behavior = ?hint.mapping,
            filtering_behavior = ?hint.filtering,
            prediction_confidence = ?hint.confidence,
            "accepted remote NAT capability hint"
        );
        true
    }

    pub(crate) fn remote_nat_profile_is_fresh(&self) -> bool {
        self.remote_nat_profile.as_ref().is_some_and(|profile| {
            profile.is_fresh(nat_profile_now_ms(), REMOTE_NAT_PROFILE_MAX_AGE)
        })
    }

    /// Create a new peer connection in Idle state.
    pub fn new(node_id: &str, virtual_ip: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            probe_mac_key: None,
            probe_session_id: None,
            probe_ephemeral_shared: None,
            probe_binding_token: None,
            pending_probe_bindings: HashMap::new(),
            previous_probe_binding: None,
            virtual_ip: virtual_ip.to_string(),
            endpoint: None,
            signaled_endpoint: None,
            nat_type: String::new(),
            remote_nat_profile: None,
            remote_nat_profile_candidate_epoch: None,
            online: true,
            last_seen: 0,
            remote_relay_rtt_ms: None,
            state: ConnectionState::Idle,
            path_state_machine: PathStateMachine::new(ConnectionState::Idle),
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            relay_server: None,
            candidates: Vec::new(),
            signaled_candidates: HashSet::new(),
            last_candidate_generation: 0,
            remote_candidate_incarnation_high_water: None,
            remote_candidate_epoch: 0,
            local_interface_networks: Vec::new(),
            last_candidates_expires_at_ms: None,
            candidate_sources: HashMap::new(),
            direct_health: PathHealth::default(),
            relay_health: PathHealth::default(),
            direct_generation: 0,
            direct_commit_seq: 0,
            relay_ready_generation: None,
            relay_ready_at: None,
            relay_ready_endpoint: None,
            relay_ready_connection_id: None,
            relay_confirmed_generation: None,
            relay_confirmed_at: None,
            relay_confirmed_endpoint: None,
            relay_confirmed_connection_id: None,
            relay_first: RelayFirstBusinessState::default(),
            relay_confirm_seq: 0,
            first_usable_generation: None,
            first_usable_at: None,
            first_usable_path: None,
            direct_reclaim_until: None,
            candidate_pairs: Vec::new(),
            birthday_probe_cursor: 0,
            last_path_selection: None,
            path_events: Vec::new(),
            direct_events: Vec::new(),
            direct_cache: None,
            direct_pair_cache: None,
            committed_business_path_cache: None,
            committed_business_path_change_tx: None,
        }
    }

    fn reset_for_identity_change(&mut self) {
        self.commit_path_transition(PathEvent::IdentityReset, |conn| {
            conn.endpoint = conn.signaled_endpoint;
            conn.remote_nat_profile = None;
            conn.remote_nat_profile_candidate_epoch = None;
            conn.probe_session_id = None;
            conn.probe_ephemeral_shared = None;
            conn.probe_binding_token = None;
            conn.pending_probe_bindings.clear();
            conn.previous_probe_binding = None;
            conn.candidates.clear();
            conn.signaled_candidates.clear();
            conn.last_candidate_generation = 0;
            conn.remote_candidate_incarnation_high_water = None;
            conn.remote_candidate_epoch = 0;
            conn.last_candidates_expires_at_ms = None;
            conn.candidate_sources.clear();
            conn.relay_server = None;
            conn.direct_health = PathHealth::default();
            conn.relay_health = PathHealth::default();
            conn.direct_generation = 0;
            conn.direct_reclaim_until = None;
            conn.relay_ready_generation = None;
            conn.relay_ready_at = None;
            conn.relay_ready_endpoint = None;
            conn.relay_ready_connection_id = None;
            conn.relay_confirmed_generation = None;
            conn.relay_confirmed_at = None;
            conn.relay_confirmed_endpoint = None;
            conn.relay_confirmed_connection_id = None;
            conn.relay_first = RelayFirstBusinessState::default();
            conn.first_usable_generation = None;
            conn.first_usable_at = None;
            conn.first_usable_path = None;
            conn.candidate_pairs.clear();
            conn.birthday_probe_cursor = 0;
            conn.last_path_selection = None;
            conn.path_events.clear();
            conn.direct_events.clear();
        });
    }

    /// Reset all transport/path state for a new remote daemon session while
    /// retaining the peer's long-lived identity and Probe MAC key.
    ///
    /// A remote daemon incarnation change is stronger than a candidate refresh:
    /// the old WireGuard session may still contain a high counter and the old
    /// relay confirmation may still be accepted by local path selection, even
    /// though the remote daemon that owned them has gone away. The caller must
    /// first stop the transport/UDP workers, then use this reset before starting
    /// the replacement handshake.
    pub(crate) fn reset_for_peer_session(&mut self) {
        let incarnation_high_water = self.remote_candidate_incarnation_high_water;
        let candidate_generation_replay_floor = self.last_candidate_generation;
        self.reset_for_identity_change();
        self.remote_candidate_incarnation_high_water = incarnation_high_water;
        self.last_candidate_generation = candidate_generation_replay_floor;
    }

    /// Whether the connection is active (direct or relay).
    pub fn is_active(&self) -> bool {
        self.path_state_machine.active_path().is_some()
    }

    /// Whether the connection is via relay.
    pub fn is_relay(&self) -> bool {
        self.path_state_machine.active_path() == Some(NetworkPath::Relay)
    }

    /// Transition to a new state.
    pub fn transition(&mut self, new_state: ConnectionState) {
        let epoch = self.path_state_machine.current_epoch().unwrap_or_else(|| {
            PathEpoch::unbound(self.direct_generation, self.remote_candidate_epoch)
        });
        self.commit_path_transition(
            PathEvent::CompatibilityStateRequested {
                epoch,
                state: new_state,
                direct_endpoint: self.endpoint,
                relay_endpoint: self
                    .relay_confirmed_endpoint
                    .clone()
                    .or_else(|| self.relay_ready_endpoint.clone())
                    .or_else(|| self.relay_server.clone()),
                relay_connection_id: self
                    .relay_confirmed_connection_id
                    .or(self.relay_ready_connection_id),
            },
            |_| {},
        );
    }

    /// The sole commit point for authoritative active-path changes and their
    /// compatibility/transport side effects. The pure reducer runs first; a
    /// rejected event therefore executes no side effects, while an accepted
    /// transition and its infallible mutation closure commit under the same
    /// `PeerConnection` writer guard.
    pub(crate) fn commit_path_transition(
        &mut self,
        event: PathEvent,
        apply_side_effects: impl FnOnce(&mut Self),
    ) -> PathTransitionOutcome {
        let event_epoch = event.epoch();
        let previous_active = self.path_state_machine.active_path();
        let previous_state = self.state;
        let transition = self.path_state_machine.reduce(event);
        let outcome = self.path_state_machine.commit(transition);
        if !outcome.accepted() {
            debug!(
                target: "p2pnet_daemon::peer::path_state_machine",
                event = "path_transition_rejected",
                peer_id = %self.node_id,
                epoch = ?event_epoch,
                decision = ?outcome.decision,
                revision = outcome.snapshot.revision,
                "rejected stale or illegal path event"
            );
            return outcome;
        }
        if !outcome.applies_side_effects() {
            debug!(
                target: "p2pnet_daemon::peer::path_state_machine",
                event = "path_transition_duplicate",
                peer_id = %self.node_id,
                epoch = ?event_epoch,
                decision = ?outcome.decision,
                revision = outcome.snapshot.revision,
                "ignored duplicate path event without executing side effects"
            );
            return outcome;
        }

        // Publish the compatibility projection before the closure so legacy
        // selector helpers observe the newly committed path; the connection
        // writer keeps this transaction externally atomic. A reducer or
        // revision rejection has already returned without running the closure.
        let current_active = outcome.snapshot.state.active.network_path();
        let new_state = outcome.snapshot.state.compatibility_state;
        self.state = new_state;
        apply_side_effects(self);

        if previous_active.is_none() && current_active.is_some() {
            self.connected_at = Some(Instant::now());
        } else if current_active.is_none() {
            self.connected_at = None;
        } else if self.connected_at.is_none() {
            self.connected_at = Some(Instant::now());
        }
        self.sync_direct_cache();
        self.sync_committed_business_path_cache();

        if previous_state != new_state || previous_active != current_active {
            info!(target: "p2pnet_daemon::peer::connection",
                event = "peer_connection_state_changed",
                peer_id = %self.node_id,
                previous_state = ?previous_state,
                new_state = ?new_state,
                previous_active_path = ?previous_active,
                active_path = ?current_active,
                path_revision = outcome.snapshot.revision,
                direct_generation = self.direct_generation,
                relay_ready_generation = ?self.relay_ready_generation,
                relay_confirmed_generation = ?self.relay_confirmed_generation,
                relay_confirmed_connection_id = ?self.relay_confirmed_connection_id,
                relay_server = ?self.relay_server,
                direct_endpoint = ?self.endpoint,
                "peer connection state changed peer_id={} previous={:?} new={:?}",
                self.node_id,
                previous_state,
                new_state,
            );
            info!("Peer {} state: {} → {}", self.node_id, previous_state, new_state);
        }
        outcome
    }

    #[allow(dead_code)]
    pub(crate) fn path_state_snapshot(&self) -> PathStateMachineSnapshot {
        self.path_state_machine.snapshot()
    }

    /// Keep the manager's synchronous Direct-set mirror in lockstep with this
    /// connection's state, so the UDP layer can re-verify the nonevictable
    /// set inside its socket-state lock.
    fn sync_direct_cache(&self) {
        if let Some(cache) = &self.direct_cache {
            let mut cache = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.state == ConnectionState::Direct {
                cache.insert(self.node_id.clone());
            } else {
                cache.remove(&self.node_id);
            }
        }
        if self.state != ConnectionState::Direct {
            if let Some(cache) = &self.direct_pair_cache {
                cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .remove(&self.node_id);
            }
        }
    }

    /// Attach the manager's synchronous Direct-set mirror (manager-owned).
    pub(crate) fn attach_direct_cache(&mut self, cache: Arc<std::sync::Mutex<HashSet<String>>>) {
        self.direct_cache = Some(cache);
        self.sync_direct_cache();
    }

    /// Attach the manager's lock-free exact Direct-pair mirror.
    pub(crate) fn attach_direct_pair_cache(
        &mut self,
        cache: Arc<std::sync::Mutex<HashMap<String, DirectCommitPairSnapshot>>>,
    ) {
        self.direct_pair_cache = Some(cache);
        self.sync_direct_cache();
    }

    fn sync_committed_business_path_cache(&self) {
        let Some(cache) = &self.committed_business_path_cache else {
            return;
        };
        let path = self.path_state_machine.snapshot().state;
        let snapshot = CommittedBusinessPathSnapshot {
            peer_id: self.node_id.clone(),
            virtual_ip: self.virtual_ip.clone(),
            lifecycle: path.lifecycle,
            epoch: path.epoch,
            active: path.active,
        };
        let changed = {
            let mut cache = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            cache
                .insert(self.node_id.clone(), snapshot.clone())
                .as_ref()
                != Some(&snapshot)
        };
        if changed {
            if let Some(changes) = &self.committed_business_path_change_tx {
                changes.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
            }
        }
    }

    /// Attach the manager's typed committed-path mirror and its lossless latest
    /// value notification stream.
    pub(crate) fn attach_committed_business_path_cache(
        &mut self,
        cache: Arc<std::sync::Mutex<HashMap<String, CommittedBusinessPathSnapshot>>>,
        changes: tokio::sync::watch::Sender<u64>,
    ) {
        self.committed_business_path_cache = Some(cache);
        self.committed_business_path_change_tx = Some(changes);
        self.sync_committed_business_path_cache();
    }

    /// Current selected traffic path, if active.
    pub fn active_path(&self) -> Option<NetworkPath> {
        self.path_state_machine.active_path()
    }

    /// Record bytes sent.
    pub fn record_sent(&mut self, n: u64) {
        self.bytes_sent += n;
    }

    /// Record bytes received.
    pub fn record_received(&mut self, n: u64) {
        self.bytes_received += n;
    }

    /// Record the first usable production ingress for this peer + generation.
    ///
    /// `path` is `Direct` or `Relay`.  The manager caller must supply the
    /// authenticated ingress of a normal decrypted overlay business packet;
    /// path confirmation and transport-local events are not substitutes for
    /// that evidence.  The validation harness may impose an additional
    /// bidirectional nonce/echo requirement before calling this method.
    /// Emits exactly once per peer + generation; later calls in the same
    /// generation no-op.
    pub fn record_first_usable(&mut self, path: NetworkPath, generation: u64) -> bool {
        if self.first_usable_generation == Some(generation) && self.first_usable_at.is_some() {
            return false;
        }
        self.first_usable_generation = Some(generation);
        self.first_usable_at = Some(Instant::now());
        self.first_usable_path = Some(path);
        true
    }
}

fn nat_profile_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
