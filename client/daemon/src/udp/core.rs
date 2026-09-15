use super::*;

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
        let socket_arc = Arc::new(socket);
        let (primary_socket, ipv6_socket, ipv6_socket_diagnostics) = if bind_addr.is_ipv6() {
            let diag = Arc::new(Mutex::new(Some(UdpSocketPoolMemberDiagnostics {
                socket_index: IPV6_SOCKET_INDEX,
                ..Default::default()
            })));
            (socket_arc.clone(), Some(socket_arc), diag)
        } else {
            let ipv6_bind_addr = if bind_addr.ip().is_loopback() {
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    socket_arc.local_addr().map(|a| a.port()).unwrap_or(0),
                )
            } else {
                SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    socket_arc.local_addr().map(|a| a.port()).unwrap_or(0),
                )
            };
            let v6_socket = match p2pnet_netbind::bind_udp(
                ipv6_bind_addr,
                outbound_interface.as_deref(),
            )
            .await
            {
                Ok(s) => Some(Arc::new(s)),
                Err(err) => {
                    let fallback_addr = SocketAddr::new(ipv6_bind_addr.ip(), 0);
                    match p2pnet_netbind::bind_udp(fallback_addr, outbound_interface.as_deref())
                        .await
                    {
                        Ok(s) => Some(Arc::new(s)),
                        Err(fallback_err) => {
                            debug!("IPv6 UDP socket bind failed (running IPv4-only): {err}, fallback: {fallback_err}");
                            None
                        }
                    }
                }
            };
            let diag = Arc::new(Mutex::new(v6_socket.as_ref().map(|_| {
                UdpSocketPoolMemberDiagnostics {
                    socket_index: IPV6_SOCKET_INDEX,
                    ..Default::default()
                }
            })));
            (socket_arc, v6_socket, diag)
        };
        let network_epoch_gate = peers.network_epoch_gate();

        let direct_validation = DirectValidationRegistry::new();
        peers
            .register_direct_validation_registry(direct_validation.clone())
            .await;
        let dplpmtud = crate::dplpmtud::DplpmtudRuntime::new_with_business_change_notifier(
            peers.direct_business_budget_change_sender(),
        );
        peers.register_dplpmtud_runtime(dplpmtud.clone()).await;

        Ok(Self {
            transport_instance_id: NEXT_UDP_TRANSPORT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            socket: primary_socket,
            sockets: Arc::new(Vec::new()),
            ipv6_socket,
            ipv6_socket_diagnostics,
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
            #[cfg(test)]
            direct_business_send_gate: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(test)]
            direct_business_emsgsize_once: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            direct_business_would_block: Arc::new(StdMutex::new(HashMap::new())),
            authenticated_punch_replay: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_rate: Arc::new(Mutex::new(HashMap::new())),
            outbound_probe_budget: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_probe_budget: default_global_outbound_probe_budget(),
            local_node_id: None,
            wireguard_transport: None,
            direct_validation,
            dplpmtud,
            dplpmtud_ack_reverse_routes: Arc::new(StdMutex::new(HashMap::new())),
            dplpmtud_worker_ingress: crate::dplpmtud::DplpmtudWorkerIngress::default(),
            dplpmtud_local_virtual_ip: None,
            learning_cache: Arc::new(Mutex::new(LearningCache::new())),
        })
    }

    /// Interface currently enforced for public UDP egress, if any.
    pub fn outbound_interface(&self) -> Option<&str> {
        self.outbound_interface.as_deref()
    }

    pub fn ipv6_socket(&self) -> Option<Arc<UdpSocket>> {
        self.ipv6_socket.clone()
    }

    pub fn ipv6_local_addr(&self) -> Option<SocketAddr> {
        self.ipv6_socket.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn with_ipv6_socket(mut self, ipv6_socket: Arc<UdpSocket>) -> Self {
        self.ipv6_socket = Some(ipv6_socket);
        self.ipv6_socket_diagnostics = Arc::new(Mutex::new(Some(UdpSocketPoolMemberDiagnostics {
            socket_index: IPV6_SOCKET_INDEX,
            ..Default::default()
        })));
        self
    }

    /// Stable identity for this concrete UDP publication. It is diagnostic
    /// and cache-fencing metadata only; it is never sent on the wire.
    pub(crate) fn transport_instance_id(&self) -> u64 {
        self.transport_instance_id
    }

    #[cfg(test)]
    pub(super) fn with_global_probe_budget(
        mut self,
        budget: Arc<GlobalOutboundProbeBudget>,
    ) -> Self {
        self.global_outbound_probe_budget = Some(budget);
        self
    }

    #[cfg(test)]
    pub(super) fn with_global_heartbeat_budget(
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
    pub(super) fn with_heartbeat_send_gate(mut self, gate: Arc<HeartbeatSendGate>) -> Self {
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

    pub(super) fn active_sockets(&self) -> &[Arc<UdpSocket>] {
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

    pub(super) fn punch_socket_count(&self) -> usize {
        if self.socket_pool_active() {
            self.socket_count()
        } else {
            1
        }
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
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
}
