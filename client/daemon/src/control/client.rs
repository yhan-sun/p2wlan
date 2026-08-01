impl ControlClient {
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
    ) -> (Self, mpsc::UnboundedReceiver<ControlEvent>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

        let state = Arc::new(RwLock::new(ClientState {
            registered: false,
            peers: HashMap::new(),
            virtual_ip: None,
            _relay_servers: config.relay.servers.clone(),
        }));

        let client = Self {
            event_tx,
            cmd_tx,
            state: state.clone(),
        };

        if enabled && has_control_credential(config) {
            let config = config.clone();
            let event_tx = client.event_tx.clone();
            let cfg_path = config_path.clone();
            tokio::spawn(async move {
                run_control_loop(
                    config,
                    &event_tx,
                    state,
                    &mut cmd_rx,
                    cfg_path,
                    relay_selection,
                )
                .await;
            });
        }

        (client, event_rx)
    }

    /// Get a snapshot of the known peers.
    pub async fn peers(&self) -> HashMap<String, PeerInfo> {
        self.state.read().await.peers.clone()
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

    /// Send a peer offer (initiate P2P connection).
    pub async fn send_peer_offer(
        &self,
        to_node_id: &str,
        candidates: &[String],
        handshake_init: &[u8],
    ) -> Result<()> {
        self.send_peer_offer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            &HashMap::new(),
            handshake_init,
            None,
        )
        .await
    }

    /// Send a peer offer with optional candidate source metadata.
    pub async fn send_peer_offer_with_sources(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
    ) -> Result<()> {
        self.send_peer_offer_with_sources_and_punch_at(
            to_node_id,
            candidates,
            candidate_sources,
            handshake_init,
            None,
        )
        .await
    }

    /// Send a peer offer with candidate sources and an optional synchronized punch window.
    pub async fn send_peer_offer_with_sources_and_punch_at(
        &self,
        to_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
    ) -> Result<()> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerOffer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer offer response channel closed".into()))?
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
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerOffer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id,
                probe_ephemeral_public_key,
                candidate_sources: candidate_sources.clone(),
                handshake_init: handshake_init.to_vec(),
                punch_at_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer offer response channel closed".into()))?
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
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerAnswer {
                to_node_id: to_node_id.to_string(),
                candidates: candidates.to_vec(),
                session_id: None,
                probe_ephemeral_public_key: None,
                candidate_sources: candidate_sources.clone(),
                handshake_response: handshake_response.to_vec(),
                punch_at_ms,
                punch_at_server_ms,
                response_tx,
            })
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer answer response channel closed".into()))?
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
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendPeerAnswer {
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
            .map_err(|_| DaemonError::ControlPlane("command channel closed".into()))?;
        response_rx
            .await
            .map_err(|_| DaemonError::ControlPlane("peer answer response channel closed".into()))?
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

    /// Shutdown the control client.
    pub async fn shutdown(&self) -> Result<()> {
        let _ = self.cmd_tx.send(ControlCommand::Shutdown);
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
}
