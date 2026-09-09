impl ControlClient {
    pub async fn register_room_profile(config: &mut Config) -> Result<()> {
        if !config.network.network_id.starts_with("room-")
            || config.network.manual
            || config.control.auth_token.trim().is_empty()
        {
            return Err(DaemonError::Config("room registration requires an authenticated managed profile".into()));
        }
        let http = control_http_client(config.control.proxy_mode)?;
        let (node_id, virtual_ip, cidr, relays, _, _) = register_device(
            &http,
            &normalize_http_base_url(&config.control.server_url),
            &config.control.auth_token,
            config,
        ).await?;
        let address = virtual_ip.parse::<std::net::Ipv4Addr>()
            .map_err(|_| DaemonError::Network("invalid room address".into()))?;
        let octets = address.octets();
        if octets[0] != 10 || octets[1] != 21 || !(1..=254).contains(&octets[3])
            || cidr != format!("10.21.{}.0/24", octets[2])
        {
            return Err(DaemonError::Network("invalid room subnet assignment".into()));
        }
        config.node.node_id = node_id;
        config.network.virtual_ip = virtual_ip;
        config.network.cidr = cidr;
        config.network.netmask = "255.255.255.0".into();
        if !relays.is_empty() {
            config.relay.servers = relays;
        }
        Ok(())
    }

    /// Create a new control client.
    ///
    /// When `enabled` is `false`, the background control loop is not spawned
    /// and no HTTP requests will be made even if a token is present. This is
    /// used for manual/offline mode.
    ///
    /// `config_path` is an optional path to save the config file after
    /// obtaining a device credential (so it persists across restarts).
    ///
    /// Returns the client handle and an event receiver.
    pub fn new(
        config: &Config,
        enabled: bool,
        config_path: Option<PathBuf>,
        relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
        timeline: Arc<ConnectionTimeline>,
    ) -> (Self, mpsc::UnboundedReceiver<ControlEvent>) {
        Self::new_with_health(
            config,
            enabled,
            config_path,
            relay_selection,
            timeline,
            None,
        )
    }

    /// Create a control client and attach the daemon health state directly to
    /// the HTTP polling runtime.  The control event consumer also handles the
    /// same health events, but it may be busy processing a peer handover; the
    /// polling task must be able to refresh the health timestamp independently
    /// so a slow data-plane transition cannot produce a false stale warning.
    pub fn new_with_health(
        config: &Config,
        enabled: bool,
        config_path: Option<PathBuf>,
        relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
        timeline: Arc<ConnectionTimeline>,
        health: Option<Arc<crate::tasks::HealthState>>,
    ) -> (Self, mpsc::UnboundedReceiver<ControlEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (critical_offer_tx, critical_offer_rx) = mpsc::channel(CRITICAL_OFFER_QUEUE_CAPACITY);
        let (critical_answer_tx, critical_answer_rx) =
            mpsc::channel(CRITICAL_ANSWER_QUEUE_CAPACITY);
        let (critical_ctrl_tx, critical_ctrl_rx) = mpsc::channel(CRITICAL_CTRL_QUEUE_CAPACITY);
        let (candidate_offer_tx, candidate_offer_rx) =
            mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
        let (critical_auth_tx, critical_auth_rx) = watch::channel(None);
        let event_loop_ready = Arc::new(AtomicBool::new(false));

        let state = Arc::new(RwLock::new(ClientState {
            room_authorization: Arc::new(crate::rooms::RoomAuthorization::new(&config.network.network_id)),
            registered: false,
            peers: HashMap::new(),
            virtual_ip: None,
            _relay_servers: config.relay.servers.clone(),
        }));

        let runtime_enabled = enabled && has_control_credential(config);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (shutdown_done_tx, shutdown_done_rx) = watch::channel(false);
        let shutdown_lifecycle = runtime_enabled.then(|| {
            Arc::new(ControlShutdown {
                requested: shutdown_tx.clone(),
                completed: shutdown_done_rx,
            })
        });
        let critical_lifecycle_tx = cmd_tx.clone();
        let client = Self {
            shutdown_lifecycle,
            event_loop_ready: event_loop_ready.clone(),
            event_tx: event_tx.clone(),
            cmd_tx: cmd_tx.clone(),
            critical_offer_tx,
            critical_answer_tx,
            critical_ctrl_tx,
            candidate_offer_tx,
            state: state.clone(),
            #[cfg(test)]
            test_signal_forwarder: None,
            #[cfg(test)]
            test_signal_from_node_id: String::new(),
            #[cfg(test)]
            test_signal_public_key: String::new(),
            #[cfg(test)]
            test_signal_generation: Arc::new(AtomicU64::new(0)),
        };

        if runtime_enabled {
            // The ordinary and critical lanes read the same route-aware
            // primary pool. Candidate refresh has a separate pool to avoid
            // head-of-line blocking, but both pools are rebuilt atomically
            // after a stable network-route change.
            let (http, candidate_http) = route_aware_control_http_clients(
                config.control.proxy_mode,
                &config.control.server_url,
            );
            let config = config.clone();
            let event_tx = client.event_tx.clone();
            let cfg_path = config_path.clone();
            let critical_event_tx = event_tx.clone();
            let critical_relay_selection = relay_selection.clone();
            let critical_http = http.clone();
            let critical_health = health.clone();
            let supervisor = ControlSupervisor {
                shutdown_tx,
                shutdown_rx: shutdown_rx.clone(),
                done_tx: shutdown_done_tx,
                auth_rx: critical_auth_rx.clone(),
                http: http.clone(),
                event_tx: event_tx.clone(),
                health: health.clone(),
                state: state.clone(),
            };
            let advertised_snapshot = Arc::new(std::sync::Mutex::new(
                AdvertisedEndpointSnapshot::default(),
            ));
            let critical_advertised_snapshot = advertised_snapshot.clone();
            let critical = async move {
                run_critical_control_loop(
                    critical_http,
                    candidate_http,
                    critical_answer_rx,
                    critical_offer_rx,
                    critical_ctrl_rx,
                    candidate_offer_rx,
                    critical_auth_rx,
                    critical_event_tx,
                    critical_relay_selection,
                    critical_health,
                    shutdown_rx,
                    critical_advertised_snapshot,
                    critical_lifecycle_tx,
                )
                .await;
            };
            let ordinary = async move {
                run_control_loop(
                    config,
                    http,
                    timeline,
                    &event_tx,
                    state,
                    &mut cmd_rx,
                    cfg_path,
                    relay_selection,
                    critical_auth_tx,
                    health,
                    advertised_snapshot,
                    event_loop_ready,
                )
                .await;
            };
            let tasks = ControlRuntimeTasks {
                ordinary: tokio::spawn(ordinary),
                critical: tokio::spawn(critical),
            };
            tokio::spawn(supervisor.run(tasks));
        }

        (client, event_rx)
    }

    /// Clone of the control event channel, for tests that drive the daemon's
    /// control event loop directly.
    #[cfg(test)]
    pub(crate) fn event_sender(&self) -> mpsc::UnboundedSender<ControlEvent> {
        self.event_tx.clone()
    }

    /// Build a client that never spawns the background control loop.
    ///
    /// Used by daemon unit tests that only need the command/event plumbing.
    #[cfg(test)]
    pub(crate) fn disabled_for_test() -> Self {
        let (event_tx, _event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, _cmd_rx) = mpsc::unbounded_channel();
        let (critical_offer_tx, mut critical_offer_rx) =
            mpsc::channel::<CriticalOfferCommand>(CRITICAL_OFFER_QUEUE_CAPACITY);
        let (critical_answer_tx, mut critical_answer_rx) =
            mpsc::channel::<CriticalAnswerCommand>(CRITICAL_ANSWER_QUEUE_CAPACITY);
        let (critical_ctrl_tx, mut critical_ctrl_rx) =
            mpsc::channel::<CriticalControlCommand>(CRITICAL_CTRL_QUEUE_CAPACITY);
        let (candidate_offer_tx, mut candidate_offer_rx) =
            mpsc::channel::<CandidateOfferCommand>(CANDIDATE_OFFER_QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(cmd) = critical_offer_rx.recv().await {
                let _ = cmd.response_tx.send(PeerOfferSendOutcome::Sent);
            }
        });
        tokio::spawn(async move {
            while let Some(cmd) = critical_answer_rx.recv().await {
                let _ = cmd.response_tx.send(Ok(()));
            }
        });
        tokio::spawn(async move {
            while let Some(cmd) = candidate_offer_rx.recv().await {
                let _ = cmd.response_tx.send(PeerOfferSendOutcome::Sent);
            }
        });
        tokio::spawn(async move {
            while let Some(cmd) = critical_ctrl_rx.recv().await {
                match cmd {
                    CriticalControlCommand::UpdateEndpoint { response_tx, .. } => {
                        let _ = response_tx.send(Ok(()));
                    }
                    CriticalControlCommand::Shutdown => break,
                }
            }
        });
        let state = Arc::new(RwLock::new(ClientState {
            room_authorization: Arc::new(crate::rooms::RoomAuthorization::new("default")),
            registered: false,
            peers: HashMap::new(),
            virtual_ip: None,
            _relay_servers: Vec::new(),
        }));
        Self {
            shutdown_lifecycle: None,
            event_loop_ready: Arc::new(AtomicBool::new(false)),
            event_tx,
            cmd_tx,
            critical_offer_tx,
            critical_answer_tx,
            critical_ctrl_tx,
            candidate_offer_tx,
            state,
            #[cfg(test)]
            test_signal_forwarder: None,
            #[cfg(test)]
            test_signal_from_node_id: String::new(),
            #[cfg(test)]
            test_signal_public_key: String::new(),
            #[cfg(test)]
            test_signal_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Allow the ordinary control runtime to start leasing signal rows only
    /// after the daemon has installed its main event consumer.  This closes
    /// the startup race where a first offer was leased before the state
    /// machine could apply it, causing ordered redelivery to wait for the
    /// server lease timeout.
    pub(crate) fn mark_event_loop_ready(&self) {
        self.event_loop_ready.store(true, Ordering::Release);
    }

    /// Install a test-only in-process signaling forwarder. The adapter is
    /// intentionally attached to the existing send methods so a two-peer
    /// harness exercises the same production control ingress and fresh
    /// candidate payload construction without requiring an HTTP server.
    #[cfg(test)]
    pub(crate) fn set_test_signal_forwarder(
        &mut self,
        from_node_id: impl Into<String>,
        public_key: impl Into<String>,
        forwarder: Arc<dyn Fn(TestControlSignal) + Send + Sync>,
    ) {
        self.test_signal_from_node_id = from_node_id.into();
        self.test_signal_public_key = public_key.into();
        self.test_signal_forwarder = Some(forwarder);
    }

    /// Deliver a candidate signal through the test-only control boundary.
    /// `None` means the normal production queue should be used.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn maybe_forward_test_signal(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        session_id: Option<&str>,
        fresh_ownership: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> Option<std::result::Result<(), PeerOfferSendFailure>> {
        let forwarder = self.test_signal_forwarder.as_ref()?.clone();
        if fresh_ownership.is_some_and(|ownership| ownership.is_cancelled()) {
            return Some(Err(PeerOfferSendFailure::Cancelled));
        }
        // The initial ordinary offer in the two-peer harness represents a
        // legacy candidate refresh over an already-seeded candidate set. Keep
        // its generation at zero so the receiver exercises the real ingress
        // without treating identical candidates as a new remote epoch before
        // the Hard↔Hard planner runs. Fresh predictions still use the
        // monotonic test-server generation below.
        let candidate_generation = if session_id.is_none() && fresh_ownership.is_none() {
            0
        } else {
            self.test_signal_generation
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1)
        };
        let candidates_expires_at_ms = punch_at_ms
            .map(|punch_at| punch_at.saturating_add(45_000))
            .or_else(|| Some(test_signal_now_ms().saturating_add(45_000)));
        forwarder(TestControlSignal {
            from_node_id: self.test_signal_from_node_id.clone(),
            sender_public_key: self.test_signal_public_key.clone(),
            to_node_id: to_node_id.to_string(),
            candidates: candidates.to_vec(),
            session_id: session_id.map(str::to_string),
            candidate_sources: candidate_sources.clone(),
            candidate_generation,
            candidates_expires_at_ms,
            punch_at_ms,
            handshake_init: handshake_init.to_vec(),
        });
        Some(Ok(()))
    }

    /// Get a snapshot of the known peers.
    pub async fn peers(&self) -> HashMap<String, PeerInfo> {
        self.state.read().await.peers.clone()
    }

    #[cfg(test)]
    pub async fn set_peer_for_test(&self, peer: PeerInfo) {
        self.state.write().await.peers.insert(peer.node_id.clone(), peer);
    }

    /// Get the assigned virtual IP.
    pub async fn virtual_ip(&self) -> Option<String> {
        self.state.read().await.virtual_ip.clone()
    }

    /// Send our updated endpoint to the control server.
    pub async fn update_endpoint(&self, endpoint: &str, nat_type: &str) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::UpdateEndpoint {
                endpoint: endpoint.to_string(),
                nat_type: nat_type.to_string(),
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx.await.map_err(|_| {
            DaemonError::ControlPlane("endpoint update response channel closed".into())
        })?
    }

    /// Publish an endpoint after a responder answer was issued.  This uses
    /// the bounded handshake control lane so a normal candidate refresh can
    /// never delay the answer's control signal.  The caller intentionally
    /// treats failure as best-effort: the answer is sent with its cached
    /// candidates regardless.
    pub(crate) async fn update_endpoint_for_handshake(
        &self,
        endpoint: &str,
        nat_type: &str,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.critical_ctrl_tx
            .send(CriticalControlCommand::UpdateEndpoint {
                endpoint: endpoint.to_string(),
                nat_type: nat_type.to_string(),
                response_tx,
            })
            .await
            .map_err(|_| DaemonError::ControlPlane("critical command channel closed".into()))?;
        response_rx.await.map_err(|_| {
            DaemonError::ControlPlane("critical endpoint update response channel closed".into())
        })?
    }

    /// Send a peer offer (initiate P2P connection).
    pub async fn send_peer_offer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_init: &[u8],
    ) -> Result<()> {
        match self
            .send_peer_offer_with_sources_and_punch_at(
                to_node_id,
                candidates,
                &HashMap::new(),
                handshake_init,
                None,
                None,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(PeerOfferSendFailure::Cancelled) => Ok(()),
            Err(PeerOfferSendFailure::SendFailed) => {
                Err(DaemonError::ControlPlane("peer offer send failed".into()))
            }
            Err(PeerOfferSendFailure::ChannelClosed) => {
                Err(DaemonError::ControlPlane("command channel closed".into()))
            }
        }
    }

    /// Send a peer offer with optional candidate source metadata.
    pub async fn send_peer_offer_with_sources(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
    ) -> Result<()> {
        match self
            .send_peer_offer_with_sources_and_punch_at(
                to_node_id,
                candidates,
                candidate_sources,
                handshake_init,
                None,
                None,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(PeerOfferSendFailure::Cancelled) => Ok(()),
            Err(PeerOfferSendFailure::SendFailed) => {
                Err(DaemonError::ControlPlane("peer offer send failed".into()))
            }
            Err(PeerOfferSendFailure::ChannelClosed) => {
                Err(DaemonError::ControlPlane("command channel closed".into()))
            }
        }
    }

    /// Send a peer offer with candidate sources and an optional synchronized punch window.
    ///
    /// `fresh_ownership` optionally carries the punch-session cancellation for
    /// a fresh-mapping prediction advertisement. The HTTP worker drops queued
    /// or in-flight work once the session is superseded; an in-flight request
    /// may already have reached the server, so `Cancelled` means delivery is
    /// ambiguous and the retired socket must not be finalized. `Sent` means
    /// the server accepted the request; `Failed` means the attempt failed.
    pub(crate) async fn send_peer_offer_with_sources_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        fresh_ownership: Option<Arc<crate::PunchSessionCancellation>>,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        #[cfg(test)]
        if let Some(result) = self.maybe_forward_test_signal(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_init,
            punch_at_ms,
            None,
            fresh_ownership.as_ref(),
        ) {
            return result;
        }
        // Candidate-only and fresh-mapping advertisements use the independent
        // bounded lane.  A payload carrying a WireGuard initiation is
        // latency-sensitive and uses the critical handshake lane below.
        if !handshake_init.is_empty() {
            return self
                .send_critical_peer_offer(
                    to_node_id,
                    candidates,
                    candidate_sources,
                    handshake_init,
                    punch_at_ms,
                    None,
                    None,
                )
                .await;
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.candidate_offer_tx
            .try_send(CandidateOfferCommand {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                fresh_ownership,
                response_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PeerOfferSendFailure::SendFailed,
                mpsc::error::TrySendError::Closed(_) => PeerOfferSendFailure::ChannelClosed,
            })?;
        match response_rx.await {
            Ok(PeerOfferSendOutcome::Sent) => Ok(()),
            Ok(PeerOfferSendOutcome::Cancelled) => Err(PeerOfferSendFailure::Cancelled),
            Ok(PeerOfferSendOutcome::Failed) => Err(PeerOfferSendFailure::SendFailed),
            Err(_) => Err(PeerOfferSendFailure::ChannelClosed),
        }
    }

    /// Send a fresh-mapping prediction advertisement.
    ///
    /// Unlike an ordinary peer offer this travels on the independent
    /// `peer_offer_fresh` signal type (queue key), so an ordinary candidate
    /// refresh can never overwrite the predicted window on the server, and the
    /// server's per-pair ordering delivers it in send order.
    ///
    /// Returns `Err(PeerOfferSendFailure::Cancelled)` when ownership is
    /// revoked while queued or while the HTTP request is in flight: the caller
    /// must NOT treat the prediction as advertised and must NOT finalize the
    /// generation's socket.
    pub(crate) async fn send_fresh_peer_offer_with_sources_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        fresh_ownership: Arc<crate::PunchSessionCancellation>,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        self.send_fresh_peer_offer_with_session_and_punch_at(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_init,
            punch_at_ms,
            None,
            fresh_ownership,
        )
        .await
    }

    /// Send a fresh-mapping prediction with an optional traversal session
    /// envelope.  `session_id` uses the existing signal field and remains
    /// opaque to older servers/clients, so Hard↔Hard coordination does not
    /// require a second protocol or a schema migration.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_fresh_peer_offer_with_session_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        session_id: Option<String>,
        fresh_ownership: Arc<crate::PunchSessionCancellation>,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        #[cfg(test)]
        if let Some(result) = self.maybe_forward_test_signal(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_init,
            punch_at_ms,
            session_id.as_deref(),
            Some(&fresh_ownership),
        ) {
            return result;
        }
        let (response_tx, response_rx) = oneshot::channel();
        self.candidate_offer_tx
            .try_send(CandidateOfferCommand {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id,
                probe_ephemeral_public_key: None,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                fresh_ownership: Some(fresh_ownership),
                response_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => PeerOfferSendFailure::SendFailed,
                mpsc::error::TrySendError::Closed(_) => PeerOfferSendFailure::ChannelClosed,
            })?;
        match response_rx.await {
            Ok(PeerOfferSendOutcome::Sent) => Ok(()),
            Ok(PeerOfferSendOutcome::Cancelled) => Err(PeerOfferSendFailure::Cancelled),
            Ok(PeerOfferSendOutcome::Failed) => Err(PeerOfferSendFailure::SendFailed),
            Err(_) => Err(PeerOfferSendFailure::ChannelClosed),
        }
    }

    /// Send a peer offer with an explicit traversal session ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_peer_offer_with_sources_punch_and_session(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        match self
            .send_critical_peer_offer(
                to_node_id,
                candidates,
                candidate_sources,
                handshake_init,
                punch_at_ms,
                session_id,
                probe_ephemeral_public_key,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(PeerOfferSendFailure::Cancelled) => Ok(()),
            Err(PeerOfferSendFailure::SendFailed) => {
                Err(DaemonError::ControlPlane("peer offer send failed".into()))
            }
            Err(PeerOfferSendFailure::ChannelClosed) => Err(DaemonError::ControlPlane(
                "critical command channel closed".into(),
            )),
        }
    }

    /// Send a peer answer.
    pub async fn send_peer_answer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_response: &[u8],
    ) -> Result<()> {
        self.send_peer_answer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            &HashMap::new(),
            handshake_response,
            None,
        )
        .await
    }

    /// Send a peer answer with optional candidate source metadata.
    pub async fn send_peer_answer_with_sources(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
    ) -> Result<()> {
        self.send_peer_answer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_response,
            None,
        )
        .await
    }

    /// Send a peer answer with candidate sources and an optional synchronized punch window.
    pub async fn send_peer_answer_with_sources_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
    ) -> Result<()> {
        self.send_peer_answer_with_sources_and_punch_schedule(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_response,
            punch_at_ms,
            None,
        )
        .await
    }

    /// Send a peer answer while preserving a server-selected rendezvous
    /// deadline from the offer when one is available.
    pub async fn send_peer_answer_with_sources_and_punch_schedule(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
    ) -> Result<()> {
        self.send_critical_peer_answer(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_response,
            punch_at_ms,
            punch_at_server_ms,
            None,
            None,
        )
        .await
    }

    /// Send a peer answer with an explicit traversal session ID.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_peer_answer_with_sources_schedule_and_session(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        self.send_critical_peer_answer(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_response,
            punch_at_ms,
            punch_at_server_ms,
            session_id,
            probe_ephemeral_public_key,
        )
        .await
    }

    /// Relay a peer-reflexive source address observed for the target peer.
    pub async fn send_peer_reflexive(
        &self,
        to_node_id: &str,
        observed_endpoint: &str,
        punch_at_ms: Option<u64>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerReflexive {
                to_node_id: to_node_id.to_string(),
                observed_endpoint: observed_endpoint.to_string(),
                punch_at_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx.await.map_err(|_| {
            DaemonError::ControlPlane("peer-reflexive response channel closed".into())
        })?
    }

    /// Request a port mapping tunnel.
    pub async fn create_tunnel(
        &self,
        protocol: &str,
        local_port: u16,
        remote_port: u16,
    ) -> Result<()> {
        self.cmd_tx
            .send(ControlCommand::CreateTunnel {
                protocol: protocol.to_string(),
                local_port,
                remote_port,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
    }

    /// Delete a port mapping tunnel.
    pub async fn delete_tunnel(&self, tunnel_id: &str) -> Result<()> {
        self.cmd_tx
            .send(ControlCommand::DeleteTunnel {
                tunnel_id: tunnel_id.to_string(),
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))
    }

    /// Request an immediate peer-list refresh.
    ///
    /// Used when a signal arrives from a peer that is not registered yet, so
    /// a cold-start handshake never waits out the regular poll cadence.
    pub(crate) fn refresh_peers_now(&self) {
        let _ = self.cmd_tx.send(ControlCommand::PollPeersNow);
    }

    /// Notify the existing control lifecycle that Android's physical network
    /// changed. The loop rebuilds its pooled HTTP clients and reconnects the
    /// optional signaling WebSocket through its normal registration path.
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    pub(crate) fn network_changed(&self) {
        let _ = self.cmd_tx.send(ControlCommand::NetworkChanged);
    }

    /// Shutdown the control client without waiting behind ordinary HTTP work.
    pub async fn shutdown(&self) -> Result<()> {
        if let Some(lifecycle) = self.shutdown_lifecycle.as_ref() {
            return lifecycle.stop().await;
        }
        let _ = self
            .critical_ctrl_tx
            .try_send(CriticalControlCommand::Shutdown);
        let (response_tx, response_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(ControlCommand::Shutdown { response_tx })
            .is_ok()
        {
            let _ = timeout(Duration::from_millis(1_500), response_rx).await;
        }
        Ok(())
    }

    /// Fetch a relay ticket from the control plane.
    /// Returns (ticket_jwt, expires_at_unix).
    pub async fn fetch_relay_ticket(&self, audience: &str, region: &str) -> Result<(String, i64)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::FetchRelayTicket {
                audience: audience.to_string(),
                region: region.to_string(),
                response_tx: tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        let resp = rx
            .await
            .map_err(|_| DaemonError::ControlPlane("ticket fetch cancelled".into()))??;
        Ok((resp.ticket, resp.expires_at))
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_critical_peer_offer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> std::result::Result<(), PeerOfferSendFailure> {
        let (response_tx, response_rx) = oneshot::channel();
        self.critical_offer_tx
            .send(CriticalOfferCommand {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id,
                probe_ephemeral_public_key,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                response_tx,
            })
            .await
            .map_err(|_| PeerOfferSendFailure::ChannelClosed)?;
        match response_rx.await {
            Ok(PeerOfferSendOutcome::Sent) => Ok(()),
            Ok(PeerOfferSendOutcome::Cancelled) => Err(PeerOfferSendFailure::Cancelled),
            Ok(PeerOfferSendOutcome::Failed) => Err(PeerOfferSendFailure::SendFailed),
            Err(_) => Err(PeerOfferSendFailure::ChannelClosed),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_critical_peer_answer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_response: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.critical_answer_tx
            .send(CriticalAnswerCommand {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id,
                probe_ephemeral_public_key,
                candidate_sources: candidate_sources.clone(),
                handshake_response: handshake_response.to_vec(),
                punch_at_ms,
                punch_at_server_ms,
                response_tx,
            })
            .await
            .map_err(|_| DaemonError::ControlPlane("critical command channel closed".into()))?;
        response_rx.await.map_err(|_| {
            DaemonError::ControlPlane("critical peer answer response channel closed".into())
        })?
    }
}

impl ControlClient {
    pub async fn room_authorization(&self) -> Arc<crate::rooms::RoomAuthorization> {
        self.state.read().await.room_authorization.clone()
    }
}
