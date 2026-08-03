/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    /// The primary socket is used for STUN and remains the single-socket
    /// fallback. Additional sockets, when explicitly enabled, are only used
    /// for bounded symmetric-NAT traversal experiments.
    socket: Arc<UdpSocket>,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    stun_waiters: StunWaiters,
    peer_socket_affinity: Arc<Mutex<HashMap<String, usize>>>,
    socket_pool_active: Arc<AtomicBool>,
    socket_pool_diagnostics: Arc<Mutex<Vec<UdpSocketPoolMemberDiagnostics>>>,
    peer_reflexive_tx: Option<mpsc::Sender<PeerReflexiveObservation>>,
    peer_reflexive_notifications: PeerReflexiveNotificationState,
    triggered_checks: TriggeredCheckState,
    nat_maintainers: NatMaintainerState,
    authenticated_punch_replay: AuthPunchReplayState,
    authenticated_punch_rate: AuthPunchRateState,
    outbound_probe_budget: OutboundProbeBudgetState,
    global_outbound_probe_budget: Option<Arc<GlobalOutboundProbeBudget>>,
    local_node_id: Option<String>,
}

impl UdpTransport {
    /// Bind a UDP socket for direct peer traffic.
    pub async fn bind(bind_addr: SocketAddr, peers: Arc<PeerManager>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DaemonError::Network(format!("failed to bind UDP socket at {bind_addr}: {e}"))
        })?;

        Ok(Self {
            socket: Arc::new(socket),
            sockets: Arc::new(Vec::new()),
            peers,
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
            stun_waiters: Arc::new(Mutex::new(HashMap::new())),
            peer_socket_affinity: Arc::new(Mutex::new(HashMap::new())),
            socket_pool_active: Arc::new(AtomicBool::new(false)),
            socket_pool_diagnostics: Arc::new(Mutex::new(vec![UdpSocketPoolMemberDiagnostics {
                socket_index: 0,
                ..Default::default()
            }])),
            peer_reflexive_tx: None,
            peer_reflexive_notifications: Arc::new(Mutex::new(HashMap::new())),
            triggered_checks: Arc::new(Mutex::new(HashMap::new())),
            nat_maintainers: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_replay: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_rate: Arc::new(Mutex::new(HashMap::new())),
            outbound_probe_budget: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_probe_budget: default_global_outbound_probe_budget(),
            local_node_id: None,
        })
    }

    #[cfg(test)]
    fn with_global_probe_budget(mut self, budget: Arc<GlobalOutboundProbeBudget>) -> Self {
        self.global_outbound_probe_budget = Some(budget);
        self
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
            let socket = UdpSocket::bind(pool_bind_addr).await.map_err(|e| {
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
        self.socket_pool_diagnostics.lock().await.clone()
    }

    /// Aggregate receive-side probe counters across every bound UDP socket.
    ///
    /// The direct probe loops use this around a punch burst to distinguish
    /// "ACK was not matched" from the more useful runtime signal
    /// "no authenticated probe/ACK datagram reached this daemon at all".
    pub async fn probe_rx_snapshot(&self) -> UdpProbeRxSnapshot {
        self.socket_pool_diagnostics.lock().await.iter().fold(
            UdpProbeRxSnapshot::default(),
            |mut snapshot, member| {
                snapshot.authenticated_probe_packets_received = snapshot
                    .authenticated_probe_packets_received
                    .saturating_add(member.authenticated_probe_packets_received);
                snapshot.probe_acks_received = snapshot
                    .probe_acks_received
                    .saturating_add(member.probe_acks_received);
                snapshot
            },
        )
    }

    async fn update_socket_diagnostics(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if let Some(diagnostics) = self
            .socket_pool_diagnostics
            .lock()
            .await
            .get_mut(socket_index)
        {
            update(diagnostics);
        }
    }

    fn punch_socket_count(&self) -> usize {
        if self.socket_pool_active() {
            self.socket_count()
        } else {
            1
        }
    }

    async fn socket_index_for_peer(&self, peer_id: Option<&str>) -> usize {
        let socket_count = self.socket_count();
        let Some(peer_id) = peer_id else {
            return 0;
        };
        self.peer_socket_affinity
            .lock()
            .await
            .get(peer_id)
            .copied()
            .filter(|index| *index < socket_count)
            .unwrap_or(0)
    }

    async fn remember_peer_socket(&self, peer_id: &str, socket_index: usize) {
        if socket_index < self.socket_count() {
            self.peer_socket_affinity
                .lock()
                .await
                .insert(peer_id.to_string(), socket_index);
        }
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
    }

    /// Attach a best-effort channel for relay-assisted peer-reflexive observations.
    pub fn with_peer_reflexive_observer(
        mut self,
        tx: mpsc::Sender<PeerReflexiveObservation>,
    ) -> Self {
        self.peer_reflexive_tx = Some(tx);
        self
    }
}
