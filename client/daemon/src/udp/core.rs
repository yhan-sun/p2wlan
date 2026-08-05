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
    dynamic_socket_counter: Arc<AtomicUsize>,
    dynamic_sockets: DynamicSocketState,
    dynamic_socket_diagnostics: Arc<Mutex<HashMap<usize, UdpSocketPoolMemberDiagnostics>>>,
    inbound_tx: Option<mpsc::Sender<ReceivedEncryptedPacket>>,
    peer_reflexive_tx: Option<mpsc::Sender<PeerReflexiveObservation>>,
    peer_reflexive_notifications: PeerReflexiveNotificationState,
    triggered_checks: TriggeredCheckState,
    nat_maintainers: NatMaintainerState,
    authenticated_punch_replay: AuthPunchReplayState,
    authenticated_punch_rate: AuthPunchRateState,
    outbound_probe_budget: OutboundProbeBudgetState,
    global_outbound_probe_budget: Option<Arc<GlobalOutboundProbeBudget>>,
    local_node_id: Option<String>,
    wireguard_transport: Option<WireGuardTransport>,
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
            dynamic_socket_counter: Arc::new(AtomicUsize::new(0)),
            dynamic_sockets: Arc::new(Mutex::new(HashMap::new())),
            dynamic_socket_diagnostics: Arc::new(Mutex::new(HashMap::new())),
            inbound_tx: None,
            peer_reflexive_tx: None,
            peer_reflexive_notifications: Arc::new(Mutex::new(HashMap::new())),
            triggered_checks: Arc::new(Mutex::new(HashMap::new())),
            nat_maintainers: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_replay: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_rate: Arc::new(Mutex::new(HashMap::new())),
            outbound_probe_budget: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_probe_budget: default_global_outbound_probe_budget(),
            local_node_id: None,
            wireguard_transport: None,
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
        let pool = self.socket_pool_diagnostics.lock().await.clone();
        let dynamic = self.dynamic_socket_diagnostics.lock().await.clone();
        pool.into_iter()
            .chain(dynamic.into_values())
            .fold(UdpProbeRxSnapshot::default(), |mut snapshot, member| {
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
            .filter(|index| *index < socket_count || *index >= DYNAMIC_SOCKET_INDEX_BASE)
            .unwrap_or(0)
    }

    /// The UDP socket that should carry traffic for `peer_id`.
    ///
    /// A per-peer fresh-mapping punch socket takes precedence (it owns the
    /// peer-facing NAT mapping); otherwise the pool socket pinned by affinity.
    pub async fn socket_for_peer(&self, peer_id: Option<&str>) -> Option<Arc<UdpSocket>> {
        if let Some(peer_id) = peer_id {
            if let Some(index) = self.dynamic_socket_index_for_peer(peer_id).await {
                if let Some(socket) = self
                    .dynamic_sockets
                    .lock()
                    .await
                    .get(&index)
                    .map(|dynamic| dynamic.socket.clone())
                {
                    return Some(socket);
                }
            }
        }
        let index = self.socket_index_for_peer(peer_id).await;
        if index >= DYNAMIC_SOCKET_INDEX_BASE {
            return None;
        }
        self.active_sockets().get(index).cloned()
    }

    /// Dynamic punch socket index pinned for a peer, if any.
    pub async fn dynamic_socket_index_for_peer(&self, peer_id: &str) -> Option<usize> {
        let index = *self.peer_socket_affinity.lock().await.get(peer_id)?;
        (index >= DYNAMIC_SOCKET_INDEX_BASE).then_some(index)
    }

    async fn remember_peer_socket(&self, peer_id: &str, socket_index: usize) {
        let valid = socket_index < self.socket_count()
            || (socket_index >= DYNAMIC_SOCKET_INDEX_BASE
                && self.dynamic_sockets.lock().await.contains_key(&socket_index));
        if valid {
            self.peer_socket_affinity
                .lock()
                .await
                .insert(peer_id.to_string(), socket_index);
        }
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

    /// Allocate a fresh dynamic socket index that never collides with the pool.
    pub(crate) fn next_dynamic_index(&self) -> usize {
        DYNAMIC_SOCKET_INDEX_BASE
            + self
                .dynamic_socket_counter
                .fetch_add(1, Ordering::Relaxed)
                % (usize::MAX - DYNAMIC_SOCKET_INDEX_BASE)
    }

    /// Number of live dedicated fresh-mapping punch sockets.
    pub async fn dynamic_socket_count(&self) -> usize {
        self.dynamic_sockets.lock().await.len()
    }

    /// Whether a dynamic punch socket is currently attached for this peer.
    pub async fn has_dynamic_socket_for_peer(&self, peer_id: &str) -> bool {
        self.dynamic_socket_index_for_peer(peer_id).await.is_some()
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

    /// Attach a best-effort channel for relay-assisted peer-reflexive observations.
    pub fn with_peer_reflexive_observer(
        mut self,
        tx: mpsc::Sender<PeerReflexiveObservation>,
    ) -> Self {
        self.peer_reflexive_tx = Some(tx);
        self
    }
}
