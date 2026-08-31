/// The resolved socket for one owned encrypted direct-validation request.
///
/// Produced by `UdpTransport::prepare_direct_validation_send`: the index and
/// the socket are the exact ones recorded in the ACK expectation, so the send
/// uses this socket directly instead of re-resolving (which could observe a
/// detach or an affinity switch between the expectation registration and the
/// actual kernel send).
#[derive(Debug)]
pub(crate) struct PreparedDirectValidationSend {
    pub(crate) socket_index: usize,
    pub(crate) socket: Arc<UdpSocket>,
}

/// Why a validation send could not be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectValidationSendError {
    /// The validation owner no longer owns the endpoint (revoked, replaced
    /// or the network generation advanced): nothing was registered and the
    /// resolved socket lease was released.
    OwnerRevoked,
    /// No UDP socket could be resolved for the peer.
    NoSocket,
}

#[cfg(test)]
type RemoteIncarnationCleanupGateSlot =
    Arc<std::sync::Mutex<Option<(String, Arc<RemoteIncarnationCleanupGate>)>>>;

static NEXT_UDP_TRANSPORT_INSTANCE: AtomicU64 = AtomicU64::new(1);

/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    /// Process-local identity of this concrete UDP publication. Clones keep
    /// the identity; a newly bound/replaced transport gets a new one, so a
    /// cached fast-path socket index can never silently carry across a
    /// publication replacement that reused the same index.
    transport_instance_id: u64,
    /// The primary socket is used for STUN and remains the single-socket
    /// fallback. Additional sockets, when explicitly enabled, are only used
    /// for bounded symmetric-NAT traversal experiments.
    socket: Arc<UdpSocket>,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    /// Physical interface used to bypass a foreign system TUN. `None` keeps
    /// ordinary multi-interface routing when no capture route is present.
    outbound_interface: Option<Arc<str>>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    /// Local-only binding from a Hard↔Hard probe nonce to its rendezvous
    /// token. It never changes the UDP wire packet; the authenticated Probe
    /// v2 nonce is simply refused if its bounded session has been removed or
    /// superseded before the ACK arrives.
    hard_hard_probe_bindings: HardHardProbeBindings,
    stun_waiters: StunWaiters,
    /// Merged socket ownership state: dynamic punch sockets, per-peer
    /// affinity pins and the affinity epoch counter live under one mutex so
    /// every ownership transition is atomic and no lock ordering exists.
    socket_state: Arc<Mutex<SocketState>>,
    /// Shared network-epoch gate (owned by the peer manager) serializing
    /// generation advances against every generation-sensitive socket-state
    /// mutation: commit, finalize, attach, affinity adoption and pending-probe
    /// registration.  Lock order everywhere: network-epoch gate -> adoption
    /// lock -> socket_state -> pending probes.
    network_epoch_gate: Arc<tokio::sync::Mutex<()>>,
    /// Per-peer adoption locks serializing every pending-probe ACK adoption
    /// against `clear_pending_probes_for_peer`.
    ///
    /// An ACK handler matches the pending entry, removes it and then performs
    /// a sequence of awaits (WireGuard promotion, endpoint learning, socket
    /// pin, Direct promotion).  Without a fence, a PeerLeft / offline /
    /// public-key cleanup can interleave between those awaits and the ACK
    /// would recreate affinity, candidate or endpoint state for a peer that
    /// was cleaned.  The per-peer adoption lock makes each ACK's
    /// match+adoption one atomic section: the cleanup either runs before the
    /// ACK (the cleanup-epoch fence then refuses the adoption) or after it
    /// (the cleanup removes whatever the ACK created).  Lock order everywhere
    /// is: adoption lock -> socket_state -> pending probes.
    peer_adoption_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    socket_pool_active: Arc<AtomicBool>,
    socket_pool_diagnostics: Arc<Mutex<Vec<UdpSocketPoolMemberDiagnostics>>>,
    dynamic_socket_counter: Arc<AtomicUsize>,
    dynamic_socket_diagnostics: Arc<Mutex<HashMap<usize, UdpSocketPoolMemberDiagnostics>>>,
    /// Authenticated probe receive counters keyed by `(peer_id, generation)`.
    /// Aggregate socket counters remain available for topology-free diagnostics,
    /// but they must never be used as evidence for a single peer's timeout.
    peer_probe_rx_diagnostics: PeerProbeRxDiagnostics,
    inbound_tx: Option<mpsc::Sender<ReceivedEncryptedPacket>>,
    /// Owner of the daemon publication currently allowed to turn an
    /// authenticated UDP envelope into Direct-path state. Socket readers
    /// stamp this on every envelope; WireGuard inbound compares it with the
    /// live watch value after decryption so a packet queued by a withdrawn
    /// transport cannot be attributed to a replacement socket.
    inbound_publication_owner: Arc<AtomicU64>,
    /// Bounded per-peer newest-wins ingress for authenticated endpoint
    /// observations.  The daemon-side consumer owns the only receive loop;
    /// UDP readers submit synchronously and never wait on a worker queue.
    peer_reflexive_ingress: Option<PeerReflexiveIngress>,
    /// Optional daemon-registered ingress for daemon-internal
    /// direct-validation observations.
    ///
    /// The UDP layer cannot call the validation task directly (module
    /// layering: `udp` is below `lib`), so the daemon registers a closure at
    /// setup.  Both matched ACK and peer-reflexive paths call this same
    /// ingress; it only queues/merges evidence and never spawns a worker.
    validation_trigger: Option<Arc<dyn Fn(PeerReflexiveObservation) + Send + Sync>>,
    triggered_checks: TriggeredCheckState,
    nat_maintainers: NatMaintainerState,
    /// Dedicated per-(peer, socket) budget for NAT-state binding maintainer
    /// probes, fully isolated from the recovery-epoch traversal credit and
    /// the shared outbound probe budgets.
    nat_maintainer_budget: NatMaintainerBudgetState,
    /// Dedicated per-peer budget for the relay-backed recovery heartbeat.
    relay_backoff_heartbeat_budget: RelayBackoffHeartbeatBudgetState,
    /// Send-capability registry for relay-backoff heartbeat tasks: at most
    /// one send-capable worker per peer, with a quit handshake before
    /// replacement.
    relay_backoff_heartbeats: RelayBackoffHeartbeatState,
    /// Test-only hook that parks a heartbeat worker immediately before a UDP
    /// send, letting a deterministic test cancel the owner and assert that
    /// the worker re-validates its ownership before the actual send.
    #[cfg(test)]
    heartbeat_send_gate: Arc<std::sync::Mutex<Option<Arc<HeartbeatSendGate>>>>,
    /// Test-only physical-send seam. It is absent from production builds and
    /// disabled by default; tests can fail selected send attempts at the
    /// shared UDP send abstraction without closing or replacing the socket.
    #[cfg(test)]
    probe_send_failure_hook: Arc<std::sync::Mutex<Option<ProbeSendFailureHook>>>,
    #[cfg(test)]
    probe_send_failure_hook_enabled: Arc<AtomicBool>,
    /// One-shot lifecycle linearization seam used only by the remote-restart
    /// race regression.
    #[cfg(test)]
    remote_incarnation_cleanup_gate: RemoteIncarnationCleanupGateSlot,
    authenticated_punch_replay: AuthPunchReplayState,
    authenticated_punch_rate: AuthPunchRateState,
    outbound_probe_budget: OutboundProbeBudgetState,
    global_outbound_probe_budget: Option<Arc<GlobalOutboundProbeBudget>>,
    local_node_id: Option<String>,
    wireguard_transport: Option<WireGuardTransport>,
    /// Outstanding daemon-internal direct-validation requests per peer: the
    /// ACK handler only promotes Direct when the ACK token matches an
    /// expectation registered by the validation task, so a stale request can
    /// never confirm a new session.
    /// Shared validation session/expectation registry.  `PeerManager` holds a
    /// clone so a network-generation transition cancels old ownership while
    /// it is still inside the shared epoch gate.
    direct_validation: DirectValidationRegistry,
    /// DPLPMTUD state, capability receipts and exact-path workers owned by
    /// this concrete UDP publication.
    dplpmtud: crate::dplpmtud::DplpmtudRuntime,
    dplpmtud_worker_ingress: crate::dplpmtud::DplpmtudWorkerIngress,
    dplpmtud_local_virtual_ip: Option<Ipv4Addr>,
    /// Adaptive-prediction learner state for the current network generation.
    ///
    /// The fresh-mapping generator feeds each batch's observed ports into a
    /// shared [`StepLearner`] (cross-batch EWMA stride) and [`ReverseDetector`]
    /// (allocation direction) so the predictor can use a stride newer than
    /// this one batch's median and widen its window on reverse allocation.  All
    /// peers on one egress share the allocator, so the cache is keyed by
    /// public IP (not peer).  The whole cache resets when the network
    /// generation changes, since a new allocator invalidates every learned
    /// stride and direction.
    learning_cache: Arc<Mutex<LearningCache>>,
}

impl UdpTransport {
    /// Bind a UDP socket for direct peer traffic.
    pub async fn bind(bind_addr: SocketAddr, peers: Arc<PeerManager>) -> Result<Self> {
        Self::bind_to_interface(bind_addr, peers, None).await
    }

    /// Bind direct UDP to a physical interface. The kernel option is applied
    /// before bind so more-specific routes installed by a foreign TUN cannot
    /// capture STUN, punch, or encrypted peer traffic.
    pub async fn bind_to_interface(
        bind_addr: SocketAddr,
        peers: Arc<PeerManager>,
        outbound_interface: Option<String>,
    ) -> Result<Self> {
        let socket = p2pnet_netbind::bind_udp(bind_addr, outbound_interface.as_deref())
            .await
            .map_err(|e| {
                DaemonError::Network(format!("failed to bind UDP socket at {bind_addr}: {e}"))
            })?;
        let network_epoch_gate = peers.network_epoch_gate();

        let direct_validation = DirectValidationRegistry::new();
        peers
            .register_direct_validation_registry(direct_validation.clone())
            .await;
        let dplpmtud = crate::dplpmtud::DplpmtudRuntime::new();
        peers.register_dplpmtud_runtime(dplpmtud.clone()).await;

        Ok(Self {
            transport_instance_id: NEXT_UDP_TRANSPORT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            socket: Arc::new(socket),
            sockets: Arc::new(Vec::new()),
            outbound_interface: outbound_interface.map(Arc::<str>::from),
            peers,
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
            hard_hard_probe_bindings: Arc::new(Mutex::new(HashMap::new())),
            stun_waiters: Arc::new(Mutex::new(HashMap::new())),
            socket_state: Arc::new(Mutex::new(SocketState {
                dynamic: HashMap::new(),
                affinity: HashMap::new(),
                affinity_epoch: 0,
                probe_cleanup_epochs: HashMap::new(),
                committed_punch_generations: HashMap::new(),
            })),
            network_epoch_gate,
            peer_adoption_locks: Arc::new(Mutex::new(HashMap::new())),
            socket_pool_active: Arc::new(AtomicBool::new(false)),
            socket_pool_diagnostics: Arc::new(Mutex::new(vec![UdpSocketPoolMemberDiagnostics {
                socket_index: 0,
                ..Default::default()
            }])),
            dynamic_socket_counter: Arc::new(AtomicUsize::new(0)),
            dynamic_socket_diagnostics: Arc::new(Mutex::new(HashMap::new())),
            peer_probe_rx_diagnostics: Arc::new(Mutex::new(HashMap::new())),
            inbound_tx: None,
            inbound_publication_owner: Arc::new(AtomicU64::new(0)),
            peer_reflexive_ingress: None,
            validation_trigger: None,
            triggered_checks: Arc::new(Mutex::new(HashMap::new())),
            nat_maintainers: Arc::new(Mutex::new(HashMap::new())),
            nat_maintainer_budget: Arc::new(Mutex::new(HashMap::new())),
            relay_backoff_heartbeat_budget: default_global_relay_backoff_heartbeat_budget(),
            relay_backoff_heartbeats: Arc::new(std::sync::Mutex::new(
                RelayBackoffHeartbeatRegistry::default(),
            )),
            #[cfg(test)]
            heartbeat_send_gate: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            probe_send_failure_hook: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            probe_send_failure_hook_enabled: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            remote_incarnation_cleanup_gate: Arc::new(std::sync::Mutex::new(None)),
            authenticated_punch_replay: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_rate: Arc::new(Mutex::new(HashMap::new())),
            outbound_probe_budget: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_probe_budget: default_global_outbound_probe_budget(),
            local_node_id: None,
            wireguard_transport: None,
            direct_validation,
            dplpmtud,
            dplpmtud_worker_ingress: crate::dplpmtud::DplpmtudWorkerIngress::default(),
            dplpmtud_local_virtual_ip: None,
            learning_cache: Arc::new(Mutex::new(LearningCache::new())),
        })
    }

    /// Interface currently enforced for public UDP egress, if any.
    pub fn outbound_interface(&self) -> Option<&str> {
        self.outbound_interface.as_deref()
    }

    /// Stable identity for this concrete UDP publication. It is diagnostic
    /// and cache-fencing metadata only; it is never sent on the wire.
    pub(crate) fn transport_instance_id(&self) -> u64 {
        self.transport_instance_id
    }

    pub(crate) fn with_dplpmtud_local_virtual_ip(mut self, local_virtual_ip: Ipv4Addr) -> Self {
        self.dplpmtud_local_virtual_ip = Some(local_virtual_ip);
        self
    }

    pub(crate) fn dplpmtud_runtime(&self) -> crate::dplpmtud::DplpmtudRuntime {
        self.dplpmtud.clone()
    }

    pub(crate) fn dplpmtud_worker_ingress(
        &self,
    ) -> crate::dplpmtud::DplpmtudWorkerIngress {
        self.dplpmtud_worker_ingress.clone()
    }

    pub(crate) fn mark_peer_dplpmtud_supported(
        &self,
        peer_id: &str,
        peer_session_generation: PeerSessionGeneration,
    ) -> bool {
        self.dplpmtud
            .mark_supported(peer_id, peer_session_generation.value())
    }

    /// Reconcile DPLPMTUD only from the authoritative committed-path mirror.
    /// This never selects a path; it starts or cancels a worker for the exact
    /// Direct state which the Path State Machine already committed.
    pub(crate) async fn reconcile_dplpmtud_paths(&self) {
        let now = tokio::time::Instant::now();
        let snapshots = self.peers.committed_business_path_snapshots_sync();
        let known_peers = snapshots
            .iter()
            .map(|snapshot| snapshot.peer_id.clone())
            .collect::<HashSet<_>>();
        self.dplpmtud.retain_known_peers(&known_peers, now);

        let Some(local_virtual_ip) = self.dplpmtud_local_virtual_ip else {
            return;
        };

        for snapshot in snapshots {
            let validation = match snapshot.active {
                ActiveBusinessPath::Direct(validation)
                    if snapshot.lifecycle == PeerPathLifecycle::Online => validation,
                _ => {
                    self.dplpmtud.cancel_peer(
                        &snapshot.peer_id,
                        "active_path_not_direct",
                        now,
                    );
                    continue;
                }
            };
            let Some(epoch) = snapshot.epoch else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "path_identity_unbound", now);
                continue;
            };
            if validation.epoch != epoch {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "path_epoch_mismatch", now);
                continue;
            }
            let Some(remote_endpoint) = validation.commit_endpoint() else {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "direct_validation_not_authenticated",
                    now,
                );
                continue;
            };
            let Some(pair) = self
                .peers
                .direct_commit_pair_snapshot_sync(&snapshot.peer_id)
            else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "direct_pair_missing", now);
                continue;
            };
            let Some(local_endpoint) = pair.local_endpoint else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "local_endpoint_missing", now);
                continue;
            };
            if pair.generation != epoch.network_generation
                || pair.remote_candidate_epoch != epoch.remote_candidate_epoch
            {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "direct_pair_stale", now);
                continue;
            }
            let Some((socket_index, socket)) = self.socket_for_peer(Some(&snapshot.peer_id)).await
            else {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "local_socket_missing", now);
                continue;
            };
            if socket.local_addr().ok() != Some(local_endpoint) {
                self.dplpmtud
                    .cancel_peer(&snapshot.peer_id, "local_socket_changed", now);
                continue;
            }
            let Some(identity) = crate::dplpmtud::DplpmtudPathIdentity::from_committed_validation(
                snapshot.peer_id.clone(),
                validation,
                remote_endpoint,
                local_endpoint,
                self.transport_instance_id,
                socket_index,
            ) else {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "direct_validation_identity_incomplete",
                    now,
                );
                continue;
            };
            let previous_identity = self.dplpmtud.path_identity(&snapshot.peer_id);
            let previous_snapshot = self.dplpmtud.snapshot_for_peer(&snapshot.peer_id);
            if previous_identity.as_ref().is_some_and(|previous| previous != &identity) {
                self.peers.emit_timeline(
                    "dplpmtud_reset",
                    Some("direct"),
                    Some("path_identity_changed"),
                    Some(format!(
                        "peer={} previous_identity={:?} next_identity={:?}",
                        snapshot.peer_id, previous_identity, identity,
                    )),
                );
            }
            let protocol_supported = self
                .dplpmtud
                .is_supported(&snapshot.peer_id, epoch.peer_session_generation.value());
            let no_fragment_supported = p2pnet_netbind::udp_no_fragment_supported(
                &socket,
                remote_endpoint.ip(),
            );
            let supported = protocol_supported && no_fragment_supported;
            let unsupported_reason = if !protocol_supported {
                "capability_not_negotiated"
            } else {
                "no_fragment_probe_unsupported"
            };
            let identity_summary = identity.summary();
            let install = self.dplpmtud.install_path_with_reason(
                identity,
                supported,
                unsupported_reason,
                now,
            );
            if !supported
                && install.decision == crate::dplpmtud::DplpmtudInstallDecision::Unsupported
                && !previous_snapshot.is_some_and(|previous| {
                    previous.state == crate::dplpmtud::DplpmtudState::Unsupported
                        && previous.path_identity.as_ref() == Some(&identity_summary)
                })
            {
                self.peers.emit_timeline(
                    "dplpmtud_unsupported",
                    Some("direct"),
                    Some(unsupported_reason),
                    Some(format!(
                        "peer={} path_identity={:?} protocol_supported={} no_fragment_supported={} confirmed_udp_datagram_size=none search_upper_udp_datagram_size={}",
                        snapshot.peer_id,
                        identity_summary,
                        protocol_supported,
                        no_fragment_supported,
                        identity_summary
                            .outer_ip_family
                            .ceiling_udp_datagram_size()
                            .0,
                    )),
                );
            }
            if install.decision != crate::dplpmtud::DplpmtudInstallDecision::Spawned {
                debug!(
                    peer_id = %snapshot.peer_id,
                    decision = ?install.decision,
                    supported,
                    "DPLPMTUD path reconciliation did not spawn a worker"
                );
                continue;
            }
            let Some(lease) = install.worker else {
                continue;
            };
            let Ok(peer_virtual_ip) = snapshot.virtual_ip.parse::<Ipv4Addr>() else {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "peer_virtual_ip_not_ipv4",
                    now,
                );
                continue;
            };
            if !self
                .dplpmtud_worker_ingress
                .submit(crate::dplpmtud::DplpmtudWorkerStart {
                    lease,
                    socket,
                    local_virtual_ip,
                    peer_virtual_ip,
                })
            {
                self.dplpmtud.cancel_peer(
                    &snapshot.peer_id,
                    "worker_ingress_capacity_exceeded",
                    now,
                );
            }
        }
    }

    #[cfg(test)]
    fn with_global_probe_budget(mut self, budget: Arc<GlobalOutboundProbeBudget>) -> Self {
        self.global_outbound_probe_budget = Some(budget);
        self
    }

    #[cfg(test)]
    fn with_global_heartbeat_budget(
        mut self,
        budget: Arc<GlobalRelayBackoffHeartbeatBudget>,
    ) -> Self {
        self.relay_backoff_heartbeat_budget = budget;
        self
    }

    /// Park every heartbeat worker right before its next UDP send until the
    /// test releases the gate. The worker re-validates its ownership after
    /// the release, so a cancelled owner never sends a post-cancel packet.
    #[cfg(test)]
    fn with_heartbeat_send_gate(mut self, gate: Arc<HeartbeatSendGate>) -> Self {
        self.heartbeat_send_gate = Arc::new(std::sync::Mutex::new(Some(gate)));
        self
    }

    /// Fail the selected one-based physical send attempts in tests. The hook
    /// is deliberately cfg(test), opt-in and scoped to this transport clone.
    #[cfg(test)]
    pub(crate) fn set_probe_send_failures_for_test(
        &self,
        fail_on_attempts: impl IntoIterator<Item = usize>,
    ) -> ProbeSendFailureGuard {
        let fail_on_attempts = fail_on_attempts.into_iter().collect::<HashSet<_>>();
        let mut hook = self
            .probe_send_failure_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *hook = Some(ProbeSendFailureHook {
            fail_on_attempts: fail_on_attempts.clone(),
            physical_send_attempt: 0,
        });
        drop(hook);
        self.probe_send_failure_hook_enabled
            .store(!fail_on_attempts.is_empty(), Ordering::Release);
        ProbeSendFailureGuard {
            hook: self.probe_send_failure_hook.clone(),
            enabled: self.probe_send_failure_hook_enabled.clone(),
        }
    }

    /// Add up to `count - 1` ephemeral sockets for an explicitly enabled
    /// traversal experiment. The primary socket is always slot zero.
    pub async fn with_socket_pool(mut self, count: usize) -> Result<Self> {
        const MAX_SOCKET_POOL_SIZE: usize = 4;
        let requested = count.clamp(1, MAX_SOCKET_POOL_SIZE);
        let bind_addr = self.local_addr()?;
        let pool_bind_addr = SocketAddr::new(bind_addr.ip(), 0);
        let mut sockets = vec![self.socket.clone()];

        for _ in 1..requested {
            let socket =
                p2pnet_netbind::bind_udp(pool_bind_addr, self.outbound_interface.as_deref())
                    .await
                    .map_err(|e| {
                        DaemonError::Network(format!(
                            "failed to bind UDP socket pool member at {pool_bind_addr}: {e}"
                        ))
                    })?;
            sockets.push(Arc::new(socket));
        }

        self.sockets = Arc::new(sockets);
        *self.socket_pool_diagnostics.lock().await = (0..requested)
            .map(|socket_index| UdpSocketPoolMemberDiagnostics {
                socket_index,
                ..Default::default()
            })
            .collect();
        Ok(self)
    }

    fn active_sockets(&self) -> &[Arc<UdpSocket>] {
        if self.sockets.is_empty() {
            std::slice::from_ref(&self.socket)
        } else {
            self.sockets.as_slice()
        }
    }

    /// Number of live UDP sockets, including the primary data socket.
    pub fn socket_count(&self) -> usize {
        self.active_sockets().len()
    }

    /// Enable additional socket probing after the NAT profile has qualified
    /// this network for the experiment. Receive ownership remains active for
    /// every socket regardless, so an already-open mapping is never missed.
    pub fn set_socket_pool_active(&self, active: bool) {
        self.socket_pool_active.store(active, Ordering::Relaxed);
    }

    pub fn socket_pool_active(&self) -> bool {
        self.socket_pool_active.load(Ordering::Relaxed) && self.socket_count() > 1
    }

    /// A stable, endpoint-free view of the bounded socket pool activity.
    pub async fn socket_pool_diagnostics(&self) -> Vec<UdpSocketPoolMemberDiagnostics> {
        let mut sockets = self.socket_pool_diagnostics.lock().await.clone();
        // A fresh-mapping socket can become the adopted Direct socket. It is
        // just as relevant to an audited traversal run as the static pool,
        // so expose its counters in the same stable, endpoint-free view.
        sockets.extend(
            self.dynamic_socket_diagnostics
                .lock()
                .await
                .values()
                .cloned(),
        );
        sockets.sort_by_key(|member| member.socket_index);
        sockets
    }

    /// Aggregate receive-side probe counters across every bound UDP socket.
    ///
    /// The direct probe loops use this around a punch burst to distinguish
    /// "ACK was not matched" from the more useful runtime signal
    /// "no authenticated probe/ACK datagram reached this daemon at all".
    pub async fn probe_rx_snapshot(&self) -> UdpProbeRxSnapshot {
        let pool = self.socket_pool_diagnostics.lock().await.clone();
        let dynamic = self.dynamic_socket_diagnostics.lock().await.clone();
        pool.into_iter().chain(dynamic.into_values()).fold(
            UdpProbeRxSnapshot::default(),
            |mut snapshot, member| {
                snapshot.known_peer_ip_datagrams_received = snapshot
                    .known_peer_ip_datagrams_received
                    .saturating_add(member.known_peer_ip_datagrams_received);
                snapshot.authenticated_probe_packets_received = snapshot
                    .authenticated_probe_packets_received
                    .saturating_add(member.authenticated_probe_packets_received);
                snapshot.authenticated_probe_acks_observed = snapshot
                    .authenticated_probe_acks_observed
                    .saturating_add(member.authenticated_probe_acks_observed);
                snapshot.authenticated_probe_acks_unmatched = snapshot
                    .authenticated_probe_acks_unmatched
                    .saturating_add(member.authenticated_probe_acks_unmatched);
                snapshot.legacy_probe_acks_observed = snapshot
                    .legacy_probe_acks_observed
                    .saturating_add(member.legacy_probe_acks_observed);
                snapshot.legacy_probe_acks_unmatched = snapshot
                    .legacy_probe_acks_unmatched
                    .saturating_add(member.legacy_probe_acks_unmatched);
                snapshot.probe_acks_received = snapshot
                    .probe_acks_received
                    .saturating_add(member.probe_acks_received);
                snapshot
            },
        )
    }

    /// Return authenticated probe receive counters for exactly one peer in one
    /// local network generation and current Probe session. Unlike
    /// `probe_rx_snapshot`, this cannot be advanced by another peer sharing a
    /// socket pool or an older session for the same peer.
    #[allow(dead_code)] // retained for focused attribution tests; live loops pin a session below.
    pub(crate) async fn probe_rx_snapshot_for_peer(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> UdpProbeRxSnapshot {
        let session_id = self.peers.probe_session_id_for_peer(peer_id).await;
        self.probe_rx_snapshot_for_peer_session(peer_id, generation, session_id.as_deref())
            .await
    }

    /// Read counters for the exact Probe-v2 session which was active when a
    /// punch task started.  Callers that take a before/after delta must keep
    /// this session value stable for the lifetime of that task: looking up
    /// the *current* binding at the end would otherwise accidentally compare
    /// two different rekey epochs.
    pub(crate) async fn probe_rx_snapshot_for_peer_session(
        &self,
        peer_id: &str,
        generation: u64,
        session_id: Option<&str>,
    ) -> UdpProbeRxSnapshot {
        let now = Instant::now();
        let mut diagnostics = self.peer_probe_rx_diagnostics.lock().await;
        diagnostics.retain(|_, entry| {
            now.saturating_duration_since(entry.last_updated) < PEER_PROBE_RX_DIAGNOSTICS_RETENTION
        });
        diagnostics
            .get(&(
                peer_id.to_string(),
                generation,
                session_id.map(str::to_string),
            ))
            .map(|entry| entry.snapshot)
            .unwrap_or_default()
    }

    /// Update bounded authenticated probe counters for one verified peer and
    /// generation.  The key is derived from the authenticated Probe-v2 source
    /// identity (or a matched pending probe for legacy compatibility), never
    /// from an unauthenticated source address.
    pub(crate) async fn update_peer_probe_rx_diagnostics(
        &self,
        peer_id: &str,
        generation: u64,
        session_id: Option<&str>,
        update: impl FnOnce(&mut UdpProbeRxSnapshot),
    ) {
        let now = Instant::now();
        let key = (
            peer_id.to_string(),
            generation,
            session_id.map(str::to_string),
        );
        let mut diagnostics = self.peer_probe_rx_diagnostics.lock().await;
        diagnostics.retain(|_, entry| {
            now.saturating_duration_since(entry.last_updated) < PEER_PROBE_RX_DIAGNOSTICS_RETENTION
        });
        if !diagnostics.contains_key(&key)
            && diagnostics.len() >= PEER_PROBE_RX_DIAGNOSTICS_MAX_ENTRIES
        {
            if let Some(oldest) = diagnostics
                .iter()
                .min_by_key(|(_, entry)| entry.last_updated)
                .map(|(key, _)| key.clone())
            {
                diagnostics.remove(&oldest);
            }
        }
        let entry = diagnostics.entry(key).or_insert_with(|| PeerProbeRxEntry {
            snapshot: UdpProbeRxSnapshot::default(),
            last_updated: now,
        });
        update(&mut entry.snapshot);
        entry.last_updated = now;
    }

    async fn update_socket_diagnostics(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            if let Some(metrics) = self
                .dynamic_socket_diagnostics
                .lock()
                .await
                .get_mut(&socket_index)
            {
                update(metrics);
            }
            return;
        }
        if let Some(diagnostics) = self
            .socket_pool_diagnostics
            .lock()
            .await
            .get_mut(socket_index)
        {
            update(diagnostics);
        }
    }

    /// Best-effort diagnostics update for the encrypted business-packet path.
    ///
    /// The UDP receive loop must not wait for a diagnostics mutex before it
    /// hands an authenticated-encrypted candidate to the bounded transport
    /// queue. Probe/control packets may use the awaited helper above because
    /// they are not on the normal data path; business packets use this helper
    /// only after enqueue and silently skip a contended sample.
    fn update_socket_diagnostics_try(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            if let Ok(mut diagnostics) = self.dynamic_socket_diagnostics.try_lock() {
                if let Some(metrics) = diagnostics.get_mut(&socket_index) {
                    update(metrics);
                }
            }
            return;
        }
        if let Ok(mut diagnostics) = self.socket_pool_diagnostics.try_lock() {
            if let Some(metrics) = diagnostics.get_mut(socket_index) {
                update(metrics);
            }
        }
    }

    fn punch_socket_count(&self) -> usize {
        if self.socket_pool_active() {
            self.socket_count()
        } else {
            1
        }
    }

    pub(crate) async fn socket_index_for_peer(&self, peer_id: Option<&str>) -> usize {
        let socket_count = self.socket_count();
        let Some(peer_id) = peer_id else {
            return 0;
        };
        let state = self.socket_state.lock().await;
        let Some(pin) = state.affinity.get(peer_id).copied() else {
            return 0;
        };
        if pin.socket_index < socket_count {
            return pin.socket_index;
        }
        if pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            // The pin may only resolve to a dynamic socket that still belongs
            // to this peer and is Committed: a Provisional socket is owned by
            // its in-flight generation, and an entry re-purposed or evicted
            // must fall back to the pool instead of resolving to a dead
            // index.
            if state
                .dynamic
                .get(&pin.socket_index)
                .is_some_and(|entry| entry.peer_id == peer_id && entry.phase.is_usable())
            {
                return pin.socket_index;
            }
            drop(state);
            self.socket_state.lock().await.affinity.remove(peer_id);
            return 0;
        }
        0
    }

    pub(crate) async fn is_authenticated_direct_endpoint(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> bool {
        self.peers
            .is_authenticated_direct_endpoint(peer_id, endpoint, generation)
            .await
    }

    /// Resolve the UDP socket that should carry traffic for `peer_id` together
    /// with its ACTUAL index.
    ///
    /// A per-peer fresh-mapping punch socket takes precedence (it owns the
    /// peer-facing NAT mapping); otherwise the pool socket pinned by affinity.
    /// A dynamic socket whose network generation is stale is detached and the
    /// peer falls back to the pool, so a handover never keeps sending from a
    /// dead mapping.
    ///
    /// The index and the socket are resolved atomically under one lock
    /// acquisition: callers must record the returned index (not a separately
    /// resolved one) in their pending-probe bookkeeping, because the dynamic
    /// socket can be detached between two separate calls and the ACK would
    /// then never match the actual sending socket.
    pub async fn socket_for_peer(&self, peer_id: Option<&str>) -> Option<(usize, Arc<UdpSocket>)> {
        if let Some(peer_id) = peer_id {
            if let Some(index) = self.dynamic_socket_index_for_peer(peer_id).await {
                if let Some(socket) = self
                    .socket_state
                    .lock()
                    .await
                    .dynamic
                    .get(&index)
                    .map(|dynamic| dynamic.socket.clone())
                {
                    return Some((index, socket));
                }
            }
        }
        let index = self.socket_index_for_peer(peer_id).await;
        if index >= DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        self.active_sockets()
            .get(index)
            .cloned()
            .map(|socket| (index, socket))
    }

    /// Resolve the exact socket that received an authenticated direct packet.
    ///
    /// A response to a hole-punch validation request must leave through the
    /// same local mapping that received the request.  Resolving by peer
    /// affinity here is incorrect: a concurrent candidate observation may
    /// have pinned another pool/dynamic socket between ingress and the ACK,
    /// causing the NAT to see the ACK from a different source port.  The
    /// caller has already verified that `socket_index` belongs to the live
    /// UDP publication; this method additionally checks dynamic ownership and
    /// network generation so a stale index cannot be reused for another peer.
    pub(crate) async fn socket_for_inbound_peer_index(
        &self,
        peer_id: &str,
        socket_index: usize,
    ) -> Option<Arc<UdpSocket>> {
        if socket_index < self.socket_count() {
            return self.active_sockets().get(socket_index).cloned();
        }
        if socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let state = self.socket_state.lock().await;
        let dynamic = state.dynamic.get(&socket_index)?;
        if dynamic.peer_id != peer_id
            || dynamic.network_generation != self.peers.current_network_generation_sync()
        {
            return None;
        }
        Some(dynamic.socket.clone())
    }

    /// Dynamic punch socket index pinned for a peer, if any.
    ///
    /// A socket that no longer matches the current network generation is
    /// detached immediately: its NAT mapping belongs to an old network and
    /// must not keep receiving probes or data.  The network generation is
    /// read before locking, and the detachment re-verifies ownership under
    /// the lock, so no async work ever runs while the socket state is held.
    /// The entry must also belong to the peer and be Committed: a pin to a
    /// Provisional socket or to another peer's entry is stale and falls back
    /// to the pool.
    pub async fn dynamic_socket_index_for_peer(&self, peer_id: &str) -> Option<usize> {
        let mut state = self.socket_state.lock().await;
        let pin = state.affinity.get(peer_id).copied()?;
        if pin.socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let Some(dynamic) = state.dynamic.get(&pin.socket_index) else {
            // Evicted or detached: clear the stale affinity so later
            // lookups fall back to the pool instead of returning None.
            state.affinity.remove(peer_id);
            return None;
        };
        if dynamic.peer_id != peer_id || !dynamic.phase.is_usable() {
            state.affinity.remove(peer_id);
            return None;
        }
        // The generation is read under the socket-state lock (lock-free
        // mirror), so a network-generation change can never slip between the
        // read and the ownership check.
        if dynamic.network_generation != self.peers.current_network_generation_sync() {
            let detached = state
                .dynamic
                .remove(&pin.socket_index)
                .expect("dynamic socket verified above");
            state.affinity.remove(peer_id);
            drop(state);
            self.detach_dynamic_entry(detached, "network_generation_changed")
                .await;
            return None;
        }
        Some(pin.socket_index)
    }

    /// Resolve the peer's dynamic punch socket for a probe send and hold a
    /// send lease on it.
    ///
    /// The resolve re-validates peer ownership, a usable phase and the
    /// current network generation under the socket-state lock, and the lease
    /// is registered in the SAME critical section (the detach path waits for
    /// leases to drain before aborting the reader, so a resolve that won the
    /// lock can never race a detach's drain).  The lease keeps the entry's
    /// reader alive until the send completes; `send_probe_on_socket` then
    /// re-binds the lease to the pending probe so it survives until the ACK.
    pub(crate) async fn resolve_dynamic_socket_for_send(
        &self,
        peer_id: &str,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        let state = self.socket_state.lock().await;
        let pin = state.affinity.get(peer_id).copied()?;
        if pin.socket_index < DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        let dynamic = state.dynamic.get(&pin.socket_index)?;
        if dynamic.peer_id != peer_id
            || !dynamic.phase.is_usable()
            || dynamic.network_generation != self.peers.current_network_generation_sync()
        {
            return None;
        }
        let leases = dynamic.send_leases.clone();
        let socket = dynamic.socket.clone();
        let index = pin.socket_index;
        // Register the lease while the socket-state lock is still held: a
        // concurrent detach can only drain AFTER removing the entry under
        // this same lock, so it always observes this lease.
        leases.acquire();
        drop(state);
        Some((
            index,
            socket,
            DynamicSocketSendLease {
                state: leases,
                socket_index: index,
            },
        ))
    }

    /// Whether a dynamic punch socket is currently attached for this peer.
    pub async fn has_dynamic_socket_for_peer(&self, peer_id: &str) -> bool {
        self.dynamic_socket_index_for_peer(peer_id).await.is_some()
    }

    /// Return every committed/finalized speculative socket for a peer. The
    /// deterministic loopback NAT harness uses this to route one packet that
    /// arrived at a shared fake public endpoint to a deterministic live
    /// receiver; production sends still use the exact-index path and never
    /// multiply their target count.
    #[cfg(test)]
    pub(crate) async fn dynamic_sockets_for_peer_for_test(
        &self,
        peer_id: &str,
    ) -> Vec<(usize, Arc<UdpSocket>)> {
        let state = self.socket_state.lock().await;
        state
            .dynamic
            .iter()
            .filter(|(_, entry)| {
                entry.peer_id == peer_id
                    && entry.phase.is_usable()
                    && entry.network_generation == self.peers.current_network_generation_sync()
            })
            .map(|(index, entry)| (*index, entry.socket.clone()))
            .collect()
    }

    /// Adopt `socket_index` as the peer's traffic socket, backed by evidence
    /// whose epoch decides whether it may supersede the current pin.
    ///
    /// Affinity selection is based on evidence newness, never on socket type:
    /// a matched current-generation ACK from a pool socket is valid evidence
    /// and may restore the working pool path after a failed fresh generation,
    /// while older stamped evidence can never downgrade a newer commit.
    ///
    /// A dynamic socket is only valid evidence for the peer it belongs to,
    /// only once it is Committed (a provisional socket is still owned by its
    /// in-flight generation), and only while it matches the current network
    /// generation: an old generation's socket must never be adopted by stale
    /// inbound evidence.
    ///
    /// Every authenticated evidence observation (matched ACK, accepted
    /// authenticated punch, decrypted WireGuard data) is ALSO recorded on the
    /// dynamic socket entry itself: the watcher's post-commit rollback relies
    /// on the entry's own evidence counter, never on the indirect affinity
    /// epoch, so a socket that demonstrably carries the peer's traffic after
    /// its commit can never be rolled back and deleted by a cancellation
    /// that raced the commit.
    ///
    /// The whole adoption runs under the network-epoch gate: an advance can
    /// never bump the generation between the ownership check and the affinity
    /// insert, so an old generation's evidence can never become affinity.
    pub(crate) async fn remember_peer_socket(
        &self,
        peer_id: &str,
        socket_index: usize,
        evidence: SocketEvidence,
    ) {
        let epoch_guard = self.network_epoch_gate.lock().await;
        let generation = self.peers.current_network_generation_sync();
        let _ = self
            .remember_peer_socket_for_generation_in_epoch(
                &epoch_guard,
                peer_id,
                socket_index,
                generation,
                evidence,
            )
            .await;
    }

    /// Adopt a socket as affinity evidence while the caller owns the shared
    /// network-epoch gate and has already validated `generation`.
    ///
    /// Direct-validation ACK handling uses this together with expectation
    /// consumption and Direct promotion so a generation advance cannot land
    /// between a valid ACK and its affinity write.  The explicit generation
    /// fence also makes a pool-socket affinity impossible for a stale ACK
    /// (pool sockets do not themselves carry a generation field).
    pub(crate) async fn remember_peer_socket_for_generation_in_epoch(
        &self,
        _epoch_guard: &tokio::sync::MutexGuard<'_, ()>,
        peer_id: &str,
        socket_index: usize,
        generation: u64,
        evidence: SocketEvidence,
    ) -> bool {
        if generation != self.peers.current_network_generation_sync() {
            return false;
        }
        let mut state = self.socket_state.lock().await;
        if socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
            let Some(entry) = state.dynamic.get_mut(&socket_index) else {
                return false;
            };
            // The network generation is read under the socket-state lock
            // (lock-free mirror): a generation advance can never slip between
            // the read and this ownership check.
            if entry.peer_id != peer_id
                || !entry.phase.is_usable()
                || entry.network_generation != generation
            {
                return false;
            }
            // The evidence belongs to THIS entry: peer identity, network
            // generation and phase all matched.  Old sockets, old generations
            // and old network epochs can never bump a new owner's counter
            // because the entry itself is the evidence record.
            entry.authenticated_evidence = entry.authenticated_evidence.saturating_add(1);
        } else if socket_index >= self.socket_count() {
            return false;
        }
        let current = state.affinity.get(peer_id).copied();
        match evidence {
            SocketEvidence::Stamped(epoch) => {
                if current.is_some_and(|pin| epoch < pin.epoch) {
                    // Older evidence than the committed path: refuse.
                    return false;
                }
            }
            SocketEvidence::Fresh => {
                if current.is_some_and(|pin| pin.socket_index == socket_index) {
                    // Already pinned on this socket: the authenticated
                    // evidence was recorded on the entry above, so the
                    // watcher can still see it and keep the socket instead of
                    // restoring a predecessor.  The pin epoch stays stable so
                    // repeated inbound evidence never races newer stamps
                    // away.
                    return true;
                }
            }
        }
        let epoch = state.next_epoch();
        state.affinity.insert(
            peer_id.to_string(),
            PeerSocketPin {
                socket_index,
                epoch,
            },
        );
        true
    }

    /// The per-peer adoption lock serializing ACK adoption against peer
    /// cleanup.  Callers must hold the returned guard across the whole
    /// match/verify/adopt sequence (or, for cleanup, across the epoch bump
    /// and pending drop).  Entries are never removed so a stale lock can
    /// never be re-created for the same peer while a task still holds the
    /// old one.
    async fn adoption_lock_for(&self, peer_id: &str) -> Arc<Mutex<()>> {
        self.peer_adoption_locks
            .lock()
            .await
            .entry(peer_id.to_string())
            .or_default()
            .clone()
    }

    /// Acquire the same per-peer lifecycle fence used by authenticated punch
    /// ACKs and `PeerLeft` cleanup.  Encrypted direct-validation packets use
    /// this before entering the network-epoch transaction, preserving the
    /// global lock order `adoption -> epoch -> socket_state` and preventing a
    /// late validation ACK from promoting a peer incarnation that was removed
    /// and rejoined under the same node ID.
    pub(crate) async fn lock_peer_adoption_for_direct_validation(
        &self,
        peer_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.adoption_lock_for(peer_id).await.lock_owned().await
    }

    /// The peer's current affinity pin, for tests in other modules.
    #[cfg(test)]
    pub(crate) async fn affinity_pin_for_test(&self, peer_id: &str) -> Option<PeerSocketPin> {
        self.socket_state
            .lock()
            .await
            .affinity
            .get(peer_id)
            .copied()
    }

    /// Attach the encrypted-packet inbound channel used by socket readers.
    ///
    /// Called once by the UDP direct task before `run_inbound`, so dynamically
    /// attached punch sockets can start their own readers with the same
    /// receive destination.
    pub fn with_inbound_channel(mut self, tx: mpsc::Sender<ReceivedEncryptedPacket>) -> Self {
        self.inbound_tx = Some(tx);
        self
    }

    fn inbound_channel(&self) -> Option<mpsc::Sender<ReceivedEncryptedPacket>> {
        self.inbound_tx.clone()
    }

    /// Stamp this transport with the owner of the daemon publication that is
    /// currently allowed to use it for Direct-path evidence. Owner zero is
    /// deliberately reserved for unpublished transports.
    pub(crate) fn set_inbound_publication_owner(&self, owner: u64) {
        debug_assert_ne!(owner, 0, "UDP publication owner zero is reserved");
        self.inbound_publication_owner
            .store(owner, Ordering::Release);
    }

    /// Revoke an owner only when this transport still carries that exact
    /// publication. A late cleanup from a retired worker must never clear a
    /// transport which has already been republished under a newer owner.
    pub(crate) fn clear_inbound_publication_owner_if_matches(&self, owner: u64) -> bool {
        self.inbound_publication_owner
            .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// The owner token socket readers put on encrypted UDP envelopes. Zero
    /// means the reader belongs to no live daemon publication.
    pub(crate) fn inbound_publication_owner(&self) -> u64 {
        self.inbound_publication_owner.load(Ordering::Acquire)
    }

    /// Allocate a fresh dynamic socket index that never collides with the pool.
    pub(crate) fn next_dynamic_index(&self) -> usize {
        DYNAMIC_SOCKET_INDEX_BASE
            + self.dynamic_socket_counter.fetch_add(1, Ordering::Relaxed)
                % (usize::MAX - DYNAMIC_SOCKET_INDEX_BASE)
    }

    /// Drop every pending probe nonce owned by a peer and bump the peer's
    /// pending-probe cleanup epoch.
    ///
    /// Used when the peer leaves, goes offline, or its endpoint/public key
    /// changes: ACKs from the old endpoint/identity must not be matched and
    /// adopted afterwards, and an ACK handler racing the cleanup must not be
    /// able to re-insert an old pending entry (it stamps the cleanup epoch and
    /// re-insertion is refused once the epoch moved on).
    ///
    /// The whole transaction runs under the peer's adoption lock, the
    /// socket-state lock and the pending lock (in that order everywhere): no
    /// ACK handler can match, adopt or re-insert while the cleanup runs, and
    /// an ACK that already matched under the lock is followed by the cleanup
    /// removing every adoption it created.
    #[allow(dead_code)]
    pub(crate) async fn clear_pending_probes_for_peer(&self, peer_id: &str) {
        let adoption = self.adoption_lock_for(peer_id).await;
        let _adoption_guard = adoption.lock().await;
        let mut state = self.socket_state.lock().await;
        let cleanup_epoch = state
            .probe_cleanup_epochs
            .entry(peer_id.to_string())
            .or_insert(0);
        *cleanup_epoch = cleanup_epoch.saturating_add(1);
        let cleanup_epoch = *cleanup_epoch;
        // The drop runs while the epoch guard is still held: no concurrent
        // send can insert a fresh entry stamped with the pre-cleanup epoch
        // after this transaction completes.
        self.pending_probes
            .lock()
            .await
            .retain(|_, pending| pending.peer_id.as_deref() != Some(peer_id));
        self.prune_hard_hard_probe_bindings().await;
        drop(state);
        debug!("Cleared pending probes for peer {peer_id} (cleanup_epoch={cleanup_epoch})");
    }

    /// One atomic per-peer lifecycle cleanup: PeerLeft / offline /
    /// public-key-change removal is linearized against every ACK
    /// match -> verify -> endpoint learn -> socket adopt -> Direct promotion
    /// transaction for the same peer.
    ///
    /// The ENTIRE cleanup runs under the peer's adoption lock — the same lock
    /// every ACK handler holds for its whole adoption sequence — so the two
    /// can never interleave: either the ACK completes first and the cleanup
    /// then removes everything it created (connection, affinity, dynamic
    /// sockets, pending probes, endpoints, candidates), or the cleanup
    /// completes first and the cleanup-epoch fence refuses every late ACK.
    /// After this returns, no old ACK can leave pool affinity, an endpoint or
    /// a candidate behind, and nothing can pollute a new identity that joins
    /// under the same node ID.
    ///
    /// `remove_connection` controls whether the peer's connection entry is
    /// deleted (PeerLeft) or kept (offline / public-key change, where
    /// `add_peer` already reset the new identity's state).
    ///
    /// Lock order: adoption lock -> network-epoch gate -> socket_state ->
    /// pending probes; the connection removal runs under the adoption lock
    /// but never nests the other locks (no path takes adoption while holding
    /// connections).
    pub(crate) async fn cleanup_peer_lifecycle(
        &self,
        peer_id: &str,
        reason: &str,
        remove_connection: bool,
    ) {
        let adoption = self.adoption_lock_for(peer_id).await;
        let _adoption_guard = adoption.lock().await;
        self.cleanup_peer_lifecycle_under_adoption(peer_id, reason, remove_connection)
            .await;
    }

    /// Atomically erase the old UDP lifecycle and publish a claimed remote
    /// incarnation while owning the same adoption fence used by authenticated
    /// Probe handlers.
    ///
    /// WireGuard session removal happens before this call (`emit`), then this
    /// method owns `adoption` while cleanup and `finish` acquire `epoch`,
    /// preserving the canonical cross-layer order `emit -> adoption -> epoch`.
    pub(crate) async fn cleanup_peer_lifecycle_and_finish_remote_incarnation_reset(
        &self,
        peer_id: &str,
        reason: &str,
        old_incarnation: u64,
        claimed_incarnation: u64,
    ) -> bool {
        let adoption = self.adoption_lock_for(peer_id).await;
        let _adoption_guard = adoption.lock().await;
        self.cleanup_peer_lifecycle_under_adoption(peer_id, reason, false)
            .await;
        #[cfg(test)]
        self.pause_after_remote_incarnation_cleanup_for_test(peer_id)
            .await;
        self.peers
            .finish_claimed_remote_incarnation_reset(
                peer_id,
                old_incarnation,
                claimed_incarnation,
                reason,
            )
            .await
    }

    #[cfg(test)]
    pub(crate) fn install_remote_incarnation_cleanup_gate_for_test(
        &self,
        peer_id: &str,
        gate: Arc<RemoteIncarnationCleanupGate>,
    ) {
        *self
            .remote_incarnation_cleanup_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((peer_id.to_string(), gate));
    }

    #[cfg(test)]
    async fn pause_after_remote_incarnation_cleanup_for_test(&self, peer_id: &str) {
        let gate = {
            let mut installed = self
                .remote_incarnation_cleanup_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if installed
                .as_ref()
                .is_some_and(|(expected, _)| expected == peer_id)
            {
                installed.take().map(|(_, gate)| gate)
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.wait().await;
        }
    }

    /// Cleanup body for callers that already own this peer's adoption lock.
    async fn cleanup_peer_lifecycle_under_adoption(
        &self,
        peer_id: &str,
        reason: &str,
        remove_connection: bool,
    ) {
        // Revoke the validation owner before removing peer/socket state.  A
        // worker that was waiting for a handshake or ACK immediately observes
        // cancellation, and its owner-conditional cleanup cannot erase a
        // future session if this node ID later rejoins.
        self.peers
            .cancel_active_direct_validation_for_peer(peer_id)
            .await;
        self.peers
            .cancel_active_dplpmtud_for_peer(peer_id, reason)
            .await;
        if remove_connection {
            // The connection removal runs INSIDE the adoption-lock
            // transaction: an ACK that already passed its peer-existence
            // fence either completed before this removal (and the rest of
            // this cleanup removes what it created) or is refused by the
            // epoch fence below.
            self.peers.remove_peer(peer_id).await;
            // A rebind could have installed a new active registry between the
            // first cancellation and this removal. Revoke that current owner
            // as well; `begin_or_merge` also refuses the now-absent peer.
            self.peers
                .cancel_active_direct_validation_for_peer(peer_id)
                .await;
            self.peers
                .cancel_active_dplpmtud_for_peer(peer_id, reason)
                .await;
        }
        // Bump the cleanup epoch and drop the peer's pending probes under the
        // adoption lock: a late ACK can neither match nor re-insert.
        {
            let mut state = self.socket_state.lock().await;
            let cleanup_epoch = state
                .probe_cleanup_epochs
                .entry(peer_id.to_string())
                .or_insert(0);
            *cleanup_epoch = cleanup_epoch.saturating_add(1);
            let cleanup_epoch = *cleanup_epoch;
            self.pending_probes
                .lock()
                .await
                .retain(|_, pending| pending.peer_id.as_deref() != Some(peer_id));
            // Remove every dynamic socket owned by the peer and clear the
            // affinity inside the same transaction: an ACK adoption that
            // raced the cleanup can never leave a stale pool pin or a dead
            // dynamic entry behind.
            let entries = {
                let indices = state
                    .dynamic
                    .iter()
                    .filter(|(_, entry)| entry.peer_id == peer_id)
                    .map(|(index, _)| *index)
                    .collect::<Vec<_>>();
                let mut entries = Vec::with_capacity(indices.len());
                for index in indices {
                    if let Some(entry) = state.dynamic.remove(&index) {
                        entries.push(entry);
                    }
                }
                state.affinity.remove(peer_id);
                entries
            };
            drop(state);
            for entry in entries {
                self.detach_dynamic_entry(entry, reason).await;
            }
            debug!(
                "Cleaned up peer {peer_id} lifecycle (reason={reason}, remove_connection={remove_connection}, cleanup_epoch={cleanup_epoch})"
            );
        }
    }

    /// The peer's current pending-probe cleanup epoch (0 when never cleaned).
    ///
    /// A pending probe is only eligible for re-insertion by an ACK handler
    /// when this value still equals the probe's stamped epoch.
    async fn peer_probe_cleanup_epoch(&self, peer_id: &str) -> u64 {
        self.socket_state
            .lock()
            .await
            .probe_cleanup_epochs
            .get(peer_id)
            .copied()
            .unwrap_or(0)
    }

    /// Drop every pending probe that was sent from `socket_index` and release
    /// its send lease.
    ///
    /// Called by the detach path AFTER the lease-drain grace expired: the
    /// reader is about to be aborted, so those probes can never be matched
    /// anymore; removing them releases their leases so the detach never
    /// blocks on a probe that will never be ACKed.
    async fn drop_pending_probes_for_socket(&self, socket_index: usize) {
        self.pending_probes
            .lock()
            .await
            .retain(|_, pending| pending.socket_index != socket_index);
        self.prune_hard_hard_probe_bindings().await;
    }

    pub(crate) async fn clear_hard_hard_pending_probe_token(&self, nonce: ProbeNonce) {
        self.hard_hard_probe_bindings.lock().await.remove(&nonce);
    }

    /// Remove pending probes owned by one exact Hard↔Hard token.  The token
    /// binding is local-only, so this remains session-scoped even when the
    /// dynamic socket entry was already removed or its token tag was lost.
    /// Pending probes on an explicitly retained Direct socket are left in the
    /// ordinary pending table but lose their Hard↔Hard ownership binding.
    pub(crate) async fn clear_hard_hard_pending_probes_for_token(
        &self,
        peer_id: &str,
        token: &str,
        preserve_socket_index: Option<usize>,
    ) {
        let token_nonces = self
            .hard_hard_probe_bindings
            .lock()
            .await
            .iter()
            .filter(|(_, bound_token)| bound_token.as_str() == token)
            .map(|(nonce, _)| *nonce)
            .collect::<HashSet<_>>();
        if token_nonces.is_empty() {
            return;
        }
        self.pending_probes.lock().await.retain(|nonce, pending| {
            pending.peer_id.as_deref() != Some(peer_id)
                || !token_nonces.contains(nonce)
                || preserve_socket_index == Some(pending.socket_index)
        });
        self.hard_hard_probe_bindings
            .lock()
            .await
            .retain(|nonce, bound_token| {
                bound_token.as_str() != token || !token_nonces.contains(nonce)
            });
    }

    async fn prune_hard_hard_probe_bindings(&self) {
        let pending = self.pending_probes.lock().await;
        let mut bindings = self.hard_hard_probe_bindings.lock().await;
        bindings.retain(|nonce, _| pending.contains_key(nonce));
    }

    /// Number of live dedicated fresh-mapping punch sockets.
    pub async fn dynamic_socket_count(&self) -> usize {
        self.socket_state.lock().await.dynamic.len()
    }

    /// Number of Hard↔Hard-owned pending probe transactions for one peer.
    /// Test-only lifecycle assertions use this to prove a failed synchronized
    /// attempt did not leave an ACK admission lease behind; ordinary recovery
    /// probes are intentionally outside this counter.
    #[cfg(test)]
    pub(crate) async fn hard_hard_pending_probe_count_for_test(&self, peer_id: &str) -> usize {
        let pending = self.pending_probes.lock().await;
        let hard_hard_bindings = self.hard_hard_probe_bindings.lock().await;
        pending
            .iter()
            .filter(|(nonce, probe)| {
                probe.peer_id.as_deref() == Some(peer_id)
                    && hard_hard_bindings.contains_key(*nonce)
            })
            .count()
    }

    #[cfg(test)]
    pub(crate) async fn hard_hard_pending_probe_count_for_token_for_test(
        &self,
        peer_id: &str,
        token: &str,
    ) -> usize {
        let pending = self.pending_probes.lock().await;
        let hard_hard_bindings = self.hard_hard_probe_bindings.lock().await;
        pending
            .iter()
            .filter(|(nonce, probe)| {
                probe.peer_id.as_deref() == Some(peer_id)
                    && hard_hard_bindings.get(*nonce).is_some_and(|bound| bound == token)
            })
            .count()
    }

    /// Redacted lifecycle evidence for deterministic Hard↔Hard timeout
    /// diagnostics. Tokens and nonces never leave this method; only an
    /// equality bit and a short process-local digest are exposed.
    #[cfg(test)]
    pub(crate) async fn hard_hard_udp_lifecycle_snapshot_for_test(
        &self,
        peer_id: &str,
        expected_token: Option<&str>,
    ) -> HardHardUdpLifecycleSnapshot {
        let token_digest = |token: &str| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(token, &mut hasher);
            format!("{:08x}", std::hash::Hasher::finish(&hasher) as u32)
        };
        let mut dynamic_sockets = {
            let state = self.socket_state.lock().await;
            let selected = state.affinity.get(peer_id).map(|pin| pin.socket_index);
            state
                .dynamic
                .values()
                .filter(|entry| entry.peer_id == peer_id)
                .map(|entry| HardHardDynamicSocketLifecycleSnapshot {
                    socket_index: entry.socket_index,
                    phase: entry.phase,
                    network_generation: entry.network_generation,
                    punch_generation: entry.punch_generation,
                    token_present: entry.hard_hard_session_token.is_some(),
                    token_matches_expected: expected_token.is_some_and(|expected| {
                        entry.hard_hard_session_token.as_deref() == Some(expected)
                    }),
                    token_digest: entry
                        .hard_hard_session_token
                        .as_deref()
                        .map(token_digest),
                    authenticated_evidence: entry.authenticated_evidence,
                    outstanding_send_leases: entry.send_leases.outstanding(),
                    pending_probe_count: 0,
                    reader_finished: entry.reader.is_finished(),
                    affinity_selected: selected == Some(entry.socket_index),
                })
                .collect::<Vec<_>>()
        };
        dynamic_sockets.sort_by_key(|entry| entry.socket_index);
        let dynamic_indices = dynamic_sockets
            .iter()
            .map(|entry| entry.socket_index)
            .collect::<HashSet<_>>();

        let now = Instant::now();
        let pending = self.pending_probes.lock().await;
        let bindings = self.hard_hard_probe_bindings.lock().await;
        let mut pending_probes = pending
            .iter()
            .filter_map(|(nonce, probe)| {
                let binding = bindings.get(nonce);
                let peer_matches = probe.peer_id.as_deref() == Some(peer_id);
                let token_matches_expected = expected_token
                    .zip(binding.map(String::as_str))
                    .is_some_and(|(expected, actual)| expected == actual);
                (peer_matches
                    && (binding.is_some() || dynamic_indices.contains(&probe.socket_index))
                    || token_matches_expected)
                    .then_some(HardHardPendingProbeLifecycleSnapshot {
                        socket_index: probe.socket_index,
                        token_matches_expected,
                        peer_matches,
                        expired: probe.is_expired(now),
                        binding_present: binding.is_some(),
                    })
            })
            .collect::<Vec<_>>();
        pending_probes.sort_by_key(|probe| probe.socket_index);
        for socket in &mut dynamic_sockets {
            socket.pending_probe_count = pending_probes
                .iter()
                .filter(|probe| probe.socket_index == socket.socket_index)
                .count();
        }
        let orphan_probe_bindings = bindings
            .keys()
            .filter(|nonce| !pending.contains_key(*nonce))
            .count();

        HardHardUdpLifecycleSnapshot {
            peer_id: peer_id.to_string(),
            expected_token_present: expected_token.is_some(),
            dynamic_sockets,
            pending_probes,
            orphan_probe_bindings,
        }
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
    }

    /// Allocate one direct-validation worker lease or merge an observation
    /// into the currently owned worker.
    ///
    /// The registry is the single-flight authority.  For a matching peer and
    /// generation it never returns a second lease: it only publishes the
    /// newest endpoint through the existing worker's watch channel.  A new
    /// generation revokes the old owner before installing the new one, so an
    /// old worker can neither continue emitting packets nor remove the new
    /// owner's expectation during cleanup.
    #[cfg(test)]
    pub(crate) async fn begin_or_merge_direct_validation(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> DirectValidationSessionStart {
        let remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0);
        self.begin_or_merge_direct_validation_with_remote_epoch(
            peer_id,
            endpoint,
            generation,
            remote_candidate_epoch,
        )
        .await
    }

    pub(crate) async fn begin_or_merge_direct_validation_with_remote_epoch(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        generation: u64,
        remote_candidate_epoch: u64,
    ) -> DirectValidationSessionStart {
        // Generation lookup + registry insertion must share the same epoch
        // boundary as `PeerManager::advance_*`: otherwise a scheduler could
        // read generation N, lose the race to an advance to N+1, then create
        // an old owner after that advance had already cleared every old
        // session.  The gate makes the check and insert one transaction.
        let _epoch_gate = self.network_epoch_gate.lock().await;
        let current_generation = self.peers.current_network_generation_sync();
        if current_generation != generation {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                requested_generation = generation,
                current_generation,
                reason_code = "direct_validation_stale_generation",
                "direct validation admission rejected before registry lookup"
            );
            return DirectValidationSessionStart::IgnoredStaleGeneration;
        }
        let Some(peer_session_generation) =
            self.peers.peer_session_generation_sync(peer_id)
        else {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                reason_code = "direct_validation_peer_session_unavailable",
                "direct validation admission rejected for an offline peer lifecycle"
            );
            return DirectValidationSessionStart::IgnoredInactive;
        };
        let current_remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0);
        if current_remote_candidate_epoch != remote_candidate_epoch {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                requested_remote_candidate_epoch = remote_candidate_epoch,
                current_remote_candidate_epoch,
                reason_code = "direct_validation_stale_remote_candidate_epoch",
                "direct validation admission rejected for a retired remote candidate epoch"
            );
            return DirectValidationSessionStart::IgnoredStaleGeneration;
        }
        // Direct promotion and its registry cancellation share this epoch
        // gate. A queued observation that waited behind the promotion must
        // therefore be suppressed instead of recreating the session it just
        // cancelled.
        let direct_confirmed = self.peers.is_direct_sync(peer_id);
        let peer_eligible = self
            .peers
            .is_direct_validation_eligible_for_endpoint(peer_id, endpoint)
            .await;
        let transport_closed = self.direct_validation.is_closed();
        let slow_relay_suppressed = self
            .direct_validation
            .is_slow_relay_validation_suppressed(peer_id, generation)
            .await;
        if !peer_eligible || transport_closed || slow_relay_suppressed {
            let reason_code = if direct_confirmed && !peer_eligible {
                "direct_validation_peer_already_direct"
            } else if !peer_eligible {
                "direct_validation_peer_ineligible"
            } else if transport_closed {
                "direct_validation_transport_registry_closed"
            } else {
                "direct_validation_slow_relay_cooldown"
            };
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                reason_code,
                direct_confirmed,
                peer_eligible,
                transport_closed,
                slow_relay_suppressed,
                "direct validation admission rejected by lifecycle gate"
            );
            return DirectValidationSessionStart::IgnoredInactive;
        }
        let mut sessions = self.direct_validation.sessions.lock().await;
        // `cancel_all` does not need the network epoch gate during transport
        // teardown. Recheck after waiting for its sessions lock so a stale
        // scheduler cannot create an owner after the terminal cancellation.
        if self.direct_validation.is_closed() {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                reason_code = "direct_validation_transport_registry_closed_after_lock",
                "direct validation admission rejected after waiting for registry lock"
            );
            return DirectValidationSessionStart::IgnoredInactive;
        }
        if let Some((target_tx, current)) = sessions
            .get(peer_id)
            .map(|session| (session.target_tx.clone(), *session.target_tx.borrow()))
        {
            if !current.cancelled
                && current.generation == generation
                && current.peer_session_generation == peer_session_generation
                && current.remote_candidate_epoch == remote_candidate_epoch
            {
                let replace_target = self
                    .peers
                    .should_replace_direct_validation_target(
                        peer_id,
                        current.endpoint,
                        endpoint,
                    )
                    .await;
                let target_endpoint = if replace_target {
                    endpoint
                } else {
                    current.endpoint
                };
                let updated = DirectValidationTarget {
                    endpoint: target_endpoint,
                    ..current
                };
                target_tx.send_replace(updated);
                let target_class_upgraded = target_endpoint != current.endpoint
                    && self
                        .peers
                        .is_direct_validation_target_on_link_upgrade(
                            peer_id,
                            current.endpoint,
                            target_endpoint,
                        )
                        .await;
                if target_class_upgraded {
                    // A request sent to the lower-priority endpoint must not
                    // be promoted after a LAN target takes over.  The worker
                    // will observe the watch update and retry the preferred
                    // target; owner-bound cleanup rejects the old ACK.
                    let mut expectations = self.direct_validation.expectations.lock().await;
                    if expectations
                        .get(peer_id)
                        .is_some_and(|expectation| expectation.owner_token == current.owner_token)
                    {
                        expectations.remove(peer_id);
                    }
                }
                debug!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_observation_merged",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    previous_endpoint = %current.endpoint,
                    selected_endpoint = %target_endpoint,
                    target_replaced = target_endpoint != current.endpoint,
                    target_class_upgraded,
                    generation,
                    remote_candidate_epoch,
                    "merged direct-validation endpoint into existing worker"
                );
                return DirectValidationSessionStart::Merged;
            }

            // The old receiver sees cancellation before this map entry is
            // replaced.  Its owner-only cleanup becomes a no-op once the new
            // entry below owns the peer.
            target_tx.send_replace(DirectValidationTarget {
                cancelled: true,
                ..current
            });
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_session_replaced",
                peer_id = %peer_id,
                previous_endpoint = %current.endpoint,
                previous_generation = current.generation,
                previous_remote_candidate_epoch = current.remote_candidate_epoch,
                replacement_endpoint = %endpoint,
                replacement_generation = generation,
                replacement_remote_candidate_epoch = remote_candidate_epoch,
                "replaced stale direct-validation worker before spawning the new generation"
            );
            let mut expectations = self.direct_validation.expectations.lock().await;
            if expectations
                .get(peer_id)
                .is_some_and(|expectation| expectation.owner_token == current.owner_token)
            {
                expectations.remove(peer_id);
            }
        }

        let owner_token = next_direct_validation_owner_token();
        let target = DirectValidationTarget {
            endpoint,
            generation,
            peer_session_generation,
            remote_candidate_epoch,
            owner_token,
            cancelled: false,
        };
        let (target_tx, target_rx) = watch::channel(target);
        sessions.insert(peer_id.to_string(), DirectValidationSession { target_tx });
        debug!(target: "p2pnet_daemon::direct_validation",
            event = "direct_validation_session_spawned",
            peer_id = %peer_id,
            remote_endpoint = %endpoint,
            generation,
            remote_candidate_epoch,
            "created one owned direct-validation worker"
        );
        DirectValidationSessionStart::Spawn(DirectValidationSessionLease {
            peer_id: peer_id.to_string(),
            owner_token,
            target_rx,
        })
    }

    /// Cancel all validation workers, for a UDP transport shutdown or
    /// replacement.  This is intentionally stronger than the generation
    /// helper: no expectation owned by the old transport may survive.
    pub(crate) async fn cancel_all_direct_validation_sessions(&self) {
        self.direct_validation.cancel_all().await;
    }

    /// Quarantine new Direct validation owners after an encrypted ACK proved
    /// the candidate only through a delayed mapping while the relay remained
    /// confirmed.  This is peer/generation scoped, so a later generation can
    /// start relay-first validation afresh without inheriting old state.
    pub(crate) async fn suppress_direct_validation_for_slow_relay(
        &self,
        peer_id: &str,
        generation: u64,
    ) {
        self.direct_validation
            .suppress_slow_relay_validation(peer_id, generation)
            .await;
    }

    /// Return whether a peer/generation is currently in the slow-relay
    /// quarantine.  The scheduler uses this only to attach a structured
    /// diagnostic reason to an ignored observation.
    pub(crate) async fn direct_validation_suppressed_by_slow_relay(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> bool {
        self.direct_validation
            .is_slow_relay_validation_suppressed(peer_id, generation)
            .await
    }

    /// Remove a session only when the completing worker is still its owner.
    /// Returns whether the owner was current.  The expectation is cleared by
    /// the same owner check, preventing a retired worker from deleting a new
    /// session's request token.
    pub(crate) async fn finish_direct_validation_session(
        &self,
        peer_id: &str,
        owner_token: u64,
    ) -> bool {
        // A worker's session removal and owner-conditional expectation cleanup
        // share one lock boundary. This prevents a replacement session from
        // being observed between the two operations and keeps the registry
        // lock order identical to registration and ACK consumption.
        let mut sessions = self.direct_validation.sessions.lock().await;
        let owned_target = sessions.get(peer_id).and_then(|session| {
            let target = *session.target_tx.borrow();
            (target.owner_token == owner_token).then_some(target)
        });
        let owned = owned_target.is_some();
        if owned {
            // Removing the map entry is not enough: the worker owns a clone
            // of the watch receiver and can otherwise keep sending its
            // already-scheduled bounded request sequence after an ACK, a
            // slow-ACK retention decision, or a terminal timeout. Publish a
            // terminal state before removal so every worker that still holds
            // the receiver observes cancellation and exits before another
            // request is prepared.
            if let Some(session) = sessions.get(peer_id) {
                let current = *session.target_tx.borrow();
                session.target_tx.send_replace(DirectValidationTarget {
                    cancelled: true,
                    ..current
                });
            }
            sessions.remove(peer_id);
        }
        let mut expectations = self.direct_validation.expectations.lock().await;
        if expectations
            .get(peer_id)
            .is_some_and(|expectation| expectation.owner_token == owner_token)
        {
            expectations.remove(peer_id);
        }
        drop(expectations);
        drop(sessions);
        if let Some(target) = owned_target {
            self.peers
                .finish_direct_validation_attempt(
                    peer_id,
                    DirectValidationIdentity::owned(
                        crate::peer::PathEpoch::new(
                            target.generation,
                            target.peer_session_generation,
                            target.remote_candidate_epoch,
                        ),
                        owner_token,
                        None,
                        Some(target.endpoint),
                    ),
                )
                .await;
        }
        owned
    }

    /// Register the token an ACK must carry to confirm the direct-validation
    /// request this daemon is about to send to `peer_id`.
    ///
    /// Compatibility helper for focused token tests.  Runtime validation uses
    /// `expect_direct_validation_ack_owned` so cleanup is owner-bound.
    #[cfg(test)]
    pub(crate) async fn expect_direct_validation_ack(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
    ) {
        self.direct_validation.expectations.lock().await.insert(
            peer_id.to_string(),
            DirectValidationExpectation {
                request_id,
                generation,
                peer_session_generation: self
                    .peers
                    .peer_session_generation_sync(peer_id)
                    .unwrap_or(PeerSessionGeneration::UNBOUND),
                remote_candidate_epoch: 0,
                owner_token: 0,
                endpoint: None,
                socket_index: None,
                lease: None,
                sent_at: None,
                expires_at: Instant::now() + crate::DIRECT_VALIDATION_EXPECTATION_TTL,
            },
        );
    }

    /// Register an ACK expectation for exactly one validation worker.
    #[cfg(test)]
    pub(crate) async fn expect_direct_validation_ack_owned(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
        owner_token: u64,
        endpoint: SocketAddr,
    ) -> bool {
        self.expect_direct_validation_ack_owned_on_socket(
            peer_id,
            request_id,
            generation,
            owner_token,
            endpoint,
            None,
        )
        .await
    }

    /// Register an ACK expectation with the exact UDP socket used by the
    /// owned encrypted request.
    #[cfg(test)]
    pub(crate) async fn expect_direct_validation_ack_owned_on_socket(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
        owner_token: u64,
        endpoint: SocketAddr,
        socket_index: Option<usize>,
    ) -> bool {
        let remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0);
        let peer_session_generation = self
            .peers
            .peer_session_generation_sync(peer_id)
            .unwrap_or(PeerSessionGeneration::UNBOUND);
        self.register_direct_validation_expectation(
            peer_id,
            DirectValidationExpectation {
                request_id,
                generation,
                peer_session_generation,
                remote_candidate_epoch,
                owner_token,
                endpoint: Some(endpoint),
                socket_index,
                lease: None,
                sent_at: None,
                expires_at: Instant::now() + crate::DIRECT_VALIDATION_EXPECTATION_TTL,
            },
        )
        .await
    }

    /// Register an ACK expectation while holding the send lease of the exact
    /// socket that will carry the request.  `expectations` then owns the
    /// lease until the ACK, a cancellation, a timeout or a generation
    /// invalidation removes the expectation, which guarantees the socket's
    /// reader stays alive for the whole ACK window even if the socket is
    /// detached immediately after the send.
    async fn register_direct_validation_expectation(
        &self,
        peer_id: &str,
        expectation: DirectValidationExpectation,
    ) -> bool {
        // Keep the session lock while taking the expectation lock.  Lifecycle
        // cancellation follows this same order, so an owner can never insert
        // an expectation after it has already been removed from the session
        // registry.
        let sessions = self.direct_validation.sessions.lock().await;
        let active_owner = sessions.get(peer_id).is_some_and(|session| {
            let target = *session.target_tx.borrow();
            !target.cancelled
                && target.generation == expectation.generation
                && target.peer_session_generation == expectation.peer_session_generation
                && target.remote_candidate_epoch == expectation.remote_candidate_epoch
                && target.owner_token == expectation.owner_token
                && expectation.endpoint == Some(target.endpoint)
        });
        if !active_owner {
            return false;
        }
        self.direct_validation
            .expectations
            .lock()
            .await
            .insert(peer_id.to_string(), expectation);
        true
    }

    /// Resolve the socket that will actually carry one encrypted
    /// direct-validation request and hold its send lease.
    ///
    /// The resolution and the expectation registration happen in ONE logic
    /// path: the returned index is the exact socket the ACK must arrive on
    /// and the send uses the returned socket directly (never a re-resolution
    /// that could observe a detach or an affinity switch in between).  For a
    /// dynamic socket the lease is stored inside the expectation, so the
    /// socket's reader stays alive until the ACK or the expectation cleanup;
    /// a pool socket uses a noop lease.  When the owner no longer owns the
    /// endpoint, the lease is dropped and no expectation is left behind.
    pub(crate) async fn prepare_direct_validation_send(
        &self,
        peer_id: &str,
        validation: DirectValidationIdentity,
    ) -> std::result::Result<PreparedDirectValidationSend, DirectValidationSendError> {
        let request_id = validation
            .request_id
            .expect("Direct validation send identity has a request id");
        let generation = validation.epoch.network_generation;
        let peer_session_generation = validation.epoch.peer_session_generation;
        let remote_candidate_epoch = validation.epoch.remote_candidate_epoch;
        let owner_token = validation
            .owner_token
            .expect("Direct validation send identity has an owner token");
        let endpoint = validation
            .request_endpoint()
            .expect("Direct validation send identity has an endpoint");
        let (socket_index, socket, lease) = self
            .resolve_send_socket_with_lease(peer_id)
            .await
            .ok_or(DirectValidationSendError::NoSocket)?;
        let registered = self
            .register_direct_validation_expectation(
                peer_id,
                DirectValidationExpectation {
                    request_id,
                    generation,
                    peer_session_generation,
                    remote_candidate_epoch,
                    owner_token,
                    endpoint: Some(endpoint),
                    socket_index: Some(socket_index),
                    lease: Some(lease),
                    sent_at: None,
                    expires_at: Instant::now() + crate::DIRECT_VALIDATION_EXPECTATION_TTL,
                },
            )
            .await;
        if !registered {
            return Err(DirectValidationSendError::OwnerRevoked);
        }
        // Publish the exact request/endpoint identity before the packet can be
        // sent. The ACK reducer then requires this full identity rather than
        // accepting any request that happens to reuse the worker owner token.
        if !self
            .peers
            .mark_direct_validation_started(peer_id, validation)
            .await
        {
            self.clear_direct_validation_expectation_if_owned(peer_id, owner_token)
                .await;
            return Err(DirectValidationSendError::OwnerRevoked);
        }
        Ok(PreparedDirectValidationSend {
            socket_index,
            socket,
        })
    }

    /// Stamp the monotonic boundary immediately before an owned encrypted
    /// validation request is handed to the UDP socket.  The ACK handler uses
    /// this value to measure the real encrypted Request -> ACK RTT.
    pub(crate) async fn mark_direct_validation_send_started(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
        owner_token: u64,
    ) -> bool {
        let mut expectations = self.direct_validation.expectations.lock().await;
        let Some(expectation) = expectations.get_mut(peer_id) else {
            return false;
        };
        if expectation.request_id != request_id
            || expectation.generation != generation
            || expectation.owner_token != owner_token
            || expectation.expires_at <= Instant::now()
        {
            return false;
        }
        expectation.sent_at = Some(Instant::now());
        true
    }

    /// Resolve the socket for a direct-validation send under ONE
    /// socket-state critical section: a per-peer dynamic socket (with a real
    /// send lease) or the affinity-pinned pool socket (noop lease).  The
    /// peer falls back to pool index 0 when the pin is stale or detached.
    async fn resolve_send_socket_with_lease(
        &self,
        peer_id: &str,
    ) -> Option<(usize, Arc<UdpSocket>, DynamicSocketSendLease)> {
        let mut state = self.socket_state.lock().await;
        let socket_count = self.socket_count();
        let pin = state.affinity.get(peer_id).copied();
        if let Some(pin) = pin {
            if pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE {
                if let Some(dynamic) = state.dynamic.get(&pin.socket_index) {
                    if dynamic.peer_id == peer_id
                        && dynamic.phase.is_usable()
                        && dynamic.network_generation
                            == self.peers.current_network_generation_sync()
                    {
                        let leases = dynamic.send_leases.clone();
                        let socket = dynamic.socket.clone();
                        let index = pin.socket_index;
                        leases.acquire();
                        drop(state);
                        return Some((
                            index,
                            socket,
                            DynamicSocketSendLease {
                                state: leases,
                                socket_index: index,
                            },
                        ));
                    }
                }
                state.affinity.remove(peer_id);
            } else if pin.socket_index < socket_count {
                let index = pin.socket_index;
                let socket = self.active_sockets().get(index).cloned();
                drop(state);
                return socket.map(|socket| (index, socket, DynamicSocketSendLease::noop(index)));
            }
        }
        let index = 0usize;
        let socket = self.active_sockets().get(index).cloned();
        drop(state);
        socket.map(|socket| (index, socket, DynamicSocketSendLease::noop(index)))
    }

    /// Drop an expectation only if `owner_token` still owns its slot.  Used
    /// by the validation worker to withdraw a request that failed to send, so
    /// a late ACK can never match a request that never left this daemon.
    /// Dropping the expectation releases the socket send lease it held.
    pub(crate) async fn clear_direct_validation_expectation_if_owned(
        &self,
        peer_id: &str,
        owner_token: u64,
    ) -> bool {
        let mut expectations = self.direct_validation.expectations.lock().await;
        if expectations
            .get(peer_id)
            .is_some_and(|expectation| expectation.owner_token == owner_token)
        {
            expectations.remove(peer_id);
            true
        } else {
            false
        }
    }

    /// Consume a matched direct-validation ACK only while the caller holds
    /// the network epoch transaction for `current_generation`.
    ///
    /// The expectation's token generation, owner token and active registry
    /// target are verified under the registry's session -> expectation lock
    /// boundary.  The caller then uses the returned explicit generation for
    /// Direct promotion; it must not re-read current generation after this
    /// point.  Passing a stale `current_generation` is rejected before any
    /// expectation is consumed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn consume_direct_validation_ack(
        &self,
        peer_id: &str,
        request_id: u16,
        token_generation: u64,
        token_owner: u64,
        current_generation: u64,
        source: SocketAddr,
        socket_index: Option<usize>,
        endpoint_authenticated: bool,
    ) -> std::result::Result<DirectValidationExpectation, crate::udp::DirectValidationAckRejectReason>
    {
        if token_generation != current_generation {
            return Err(crate::udp::DirectValidationAckRejectReason::TokenGenerationMismatch);
        }
        let Some(current_peer_session_generation) =
            self.peers.peer_session_generation_sync(peer_id)
        else {
            return Err(
                crate::udp::DirectValidationAckRejectReason::ExpectationPeerSessionMismatch,
            );
        };
        let sessions = self.direct_validation.sessions.lock().await;
        let mut expectations = self.direct_validation.expectations.lock().await;
        let now = Instant::now();
        {
            let Some(expectation) = expectations.get(peer_id) else {
                return Err(crate::udp::DirectValidationAckRejectReason::NoExpectation);
            };
            if expectation.expires_at <= now {
                expectations.remove(peer_id);
                return Err(crate::udp::DirectValidationAckRejectReason::ExpectationExpired);
            }
            if expectation.request_id != request_id {
                return Err(crate::udp::DirectValidationAckRejectReason::RequestIdMismatch);
            }
            if expectation.generation != token_generation {
                return Err(
                    crate::udp::DirectValidationAckRejectReason::ExpectationGenerationMismatch,
                );
            }
            if expectation.peer_session_generation != current_peer_session_generation {
                return Err(
                    crate::udp::DirectValidationAckRejectReason::ExpectationPeerSessionMismatch,
                );
            }
            if expectation.owner_token != token_owner {
                return Err(crate::udp::DirectValidationAckRejectReason::OwnerMismatch);
            }
            if expectation
                .endpoint
                .is_some_and(|endpoint| endpoint != source)
                && !endpoint_authenticated
            {
                return Err(crate::udp::DirectValidationAckRejectReason::EndpointMismatch);
            }
            if expectation
                .socket_index
                .is_some_and(|expected| Some(expected) != socket_index)
            {
                return Err(crate::udp::DirectValidationAckRejectReason::SocketMismatch);
            }
        }
        let Some(session) = sessions.get(peer_id) else {
            return Err(crate::udp::DirectValidationAckRejectReason::SessionMissing);
        };
        let target = *session.target_tx.borrow();
        // `expectation.owner_token` equals `token_owner` (verified above), so
        // the active target is checked against the same owner the consumed
        // expectation carried.
        if target.cancelled {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetCancelled);
        }
        if target.generation != current_generation {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetGenerationMismatch);
        }
        if target.peer_session_generation != current_peer_session_generation {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetPeerSessionMismatch);
        }
        if target.remote_candidate_epoch
            != expectations
                .get(peer_id)
                .map(|expectation| expectation.remote_candidate_epoch)
                .unwrap_or(target.remote_candidate_epoch)
        {
            return Err(
                crate::udp::DirectValidationAckRejectReason::TargetRemoteCandidateEpochMismatch,
            );
        }
        if target.owner_token != token_owner {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetOwnerMismatch);
        }
        // Move the expectation out: it owns the send lease of the socket that
        // carried the request, released exactly when the caller drops the
        // consumed expectation after the promotion transaction.
        Ok(expectations
            .remove(peer_id)
            .expect("expectation remained present while the registry locks were held"))
    }

    /// Whether an ACK token confirms the outstanding validation request for
    /// `peer_id`.  Retained for callers that only need a boolean; new inbound
    /// transaction code should use `consume_direct_validation_ack` to retain
    /// the owner token and explicit generation.
    #[cfg(test)]
    pub(crate) async fn confirm_direct_validation_ack(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
    ) -> bool {
        let mut expectations = self.direct_validation.expectations.lock().await;
        let now = Instant::now();
        let Some(expectation) = expectations.get(peer_id) else {
            return false;
        };
        if expectation.expires_at <= now {
            expectations.remove(peer_id);
            return false;
        }
        if expectation.request_id != request_id || expectation.generation != generation {
            return false;
        }
        expectations.remove(peer_id);
        true
    }

    /// Whether any direct-validation expectation is outstanding for a peer
    /// (used by tests).
    #[cfg(test)]
    pub(crate) async fn has_direct_validation_expectation(&self, peer_id: &str) -> bool {
        let expectations = self.direct_validation.expectations.lock().await;
        let now = Instant::now();
        expectations
            .get(peer_id)
            .is_some_and(|expectation| expectation.expires_at > now)
    }

    /// Snapshot the active validation target for a peer (test-only).
    #[cfg(test)]
    pub(crate) async fn direct_validation_target(
        &self,
        peer_id: &str,
    ) -> Option<DirectValidationTarget> {
        self.direct_validation
            .sessions
            .lock()
            .await
            .get(peer_id)
            .map(|session| *session.target_tx.borrow())
    }

    /// Attach the WireGuard session registry so an authenticated pending
    /// Probe-v2 packet confirms the matching responder session first.
    pub fn with_wireguard_transport(mut self, transport: WireGuardTransport) -> Self {
        self.wireguard_transport = Some(transport);
        self
    }

    /// Attach the daemon's bounded per-peer peer-reflexive ingress.
    ///
    /// The ingress replaces the old bounded `mpsc` channel: a peer's newest
    /// endpoint always replaces its pending value, even when other peers have
    /// filled the bound.  This keeps endpoint churn from either blocking the
    /// UDP reader or silently discarding the value needed for the next check.
    pub fn with_peer_reflexive_observer(mut self, ingress: PeerReflexiveIngress) -> Self {
        self.peer_reflexive_ingress = Some(ingress);
        self
    }

    /// Register the daemon-side direct-validation trigger (see the field
    /// docs).  Called once by the UDP direct task at setup.
    pub fn with_validation_trigger(
        mut self,
        trigger: Arc<dyn Fn(PeerReflexiveObservation) + Send + Sync>,
    ) -> Self {
        self.validation_trigger = Some(trigger);
        self
    }

    /// Submit any authenticated endpoint observation to the daemon's one
    /// validation scheduler.  This is intentionally synchronous because the
    /// registered implementation is a bounded `try_send`; callers on the UDP
    /// receive path never await behind validation work.
    pub(crate) fn enqueue_direct_validation_observation(
        &self,
        observation: PeerReflexiveObservation,
    ) {
        // Endpoint-aware admission below still suppresses ordinary alternate
        // candidates for a Direct peer.  Keep this ingress open so a matched
        // LAN probe ACK can request a make-before-break validation while the
        // current public/UU path remains active.
        if self.peers.is_direct_sync(&observation.peer_id)
            && !self
                .peers
                .is_direct_validation_eligible_for_endpoint_sync(
                    &observation.peer_id,
                    observation.observed_endpoint,
                )
        {
            return;
        }
        let Some(trigger) = self.validation_trigger.as_ref() else {
            debug!(
                peer_id = %observation.peer_id,
                remote_endpoint = %observation.observed_endpoint,
                "no direct-validation scheduler ingress registered"
            );
            return;
        };
        trigger(observation);
    }

    /// Feed a matched authenticated ACK into the same observation ingress as
    /// the peer-reflexive loop.  The session registry, rather than a separate
    /// endpoint cooldown, supplies the hard worker bound and newest-wins
    /// endpoint policy.
    async fn trigger_encrypted_validation(&self, peer_id: &str, endpoint: SocketAddr) {
        self.enqueue_direct_validation_observation(PeerReflexiveObservation {
            peer_id: peer_id.to_string(),
            observed_endpoint: endpoint,
        });
    }
}
