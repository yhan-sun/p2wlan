/// Sends and receives encrypted WireGuard datagrams through a relay server.
#[derive(Clone)]
pub struct RelayTransport {
    relay_region: String,
    relay_endpoint: String,
    connect_latency_ms: u64,
    client: Arc<Mutex<RelayClient>>,
    peers: Arc<PeerManager>,
}

impl RelayTransport {
    /// Connect to a relay server and register this node ID (legacy, no TLS/ticket).
    /// Prefers tcp:// prefix if not already present for bare host:port.
    pub async fn connect(
        relay_endpoint: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        // For backward compat, prefix bare host:port with tcp://
        let wire_endpoint = if !relay_endpoint.contains("://") {
            format!("tcp://{relay_endpoint}")
        } else {
            relay_endpoint.to_string()
        };
        let (mut transport, rx) =
            Self::connect_in_region(&wire_endpoint, "default", node_id, peers, None, true, None)
                .await
                .map_err(|e| {
                    DaemonError::Relay(format!("failed to connect to relay {relay_endpoint}: {e}"))
                })?;
        // Store the original endpoint for diagnostics consistency
        transport.relay_endpoint = relay_endpoint.to_string();
        Ok((transport, rx))
    }

    /// Connect with full A2 support: TLS endpoint, ticket, and CA cert.
    pub async fn connect_secure(
        relay_endpoint: &str,
        relay_region: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
        relay_ticket: Option<String>,
        allow_insecure_plaintext: bool,
        ca_cert_path: Option<String>,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_in_region(
            relay_endpoint,
            relay_region,
            node_id,
            peers,
            relay_ticket,
            allow_insecure_plaintext,
            ca_cert_path,
        )
        .await
        .map_err(|e| {
            DaemonError::Relay(format!("failed to connect to relay {relay_endpoint}: {e}"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_in_region(
        relay_endpoint: &str,
        relay_region: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
        relay_ticket: Option<String>,
        allow_insecure_plaintext: bool,
        ca_cert_path: Option<String>,
    ) -> std::result::Result<(Self, mpsc::Receiver<RelayMessage>), p2pnet_relay::RelayError> {
        let started = Instant::now();
        let mut config = RelayClientConfig {
            idle_timeout: RELAY_INBOUND_IDLE_TIMEOUT,
            keepalive_interval: RELAY_INBOUND_IDLE_TIMEOUT / 2,
            allow_insecure_plaintext,
            relay_ticket,
            ..Default::default()
        };

        // Set CA cert path if provided
        if let Some(ca_path) = &ca_cert_path {
            config.tls_ca_cert_path = Some(std::path::PathBuf::from(ca_path));
        }

        // Use the new A2 endpoint-based connection which supports tls:// and tcp://
        let (client, relay_rx) =
            RelayClient::connect_with_endpoint(relay_endpoint, node_id, config).await?;

        info!(
            "Connected to relay {} (region={}, {}ms)",
            relay_endpoint,
            relay_region,
            duration_millis(started.elapsed())
        );

        Ok((
            Self {
                relay_region: relay_region.to_string(),
                relay_endpoint: relay_endpoint.to_string(),
                connect_latency_ms: duration_millis(started.elapsed()),
                client: Arc::new(Mutex::new(client)),
                peers,
            },
            relay_rx,
        ))
    }

    /// Selected relay region label.
    pub fn region(&self) -> &str {
        &self.relay_region
    }

    /// Selected relay endpoint.
    pub fn endpoint(&self) -> &str {
        &self.relay_endpoint
    }

    /// TCP connect plus relay registration latency.
    pub fn connect_latency_ms(&self) -> u64 {
        self.connect_latency_ms
    }

    /// Send a single encrypted packet through the relay.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<()> {
        self.client
            .lock()
            .await
            .send_data(&packet.peer_id, &packet.wire_bytes)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!(
                    "relay send to peer {} via {} failed: {e}",
                    packet.peer_id, self.relay_endpoint
                ))
            })?;

        self.peers
            .record_relay_attempt(&packet.peer_id, &self.relay_endpoint)
            .await;
        debug!(
            "Sent {} encrypted bytes to peer {} through relay {}",
            packet.wire_bytes.len(),
            packet.peer_id,
            self.relay_endpoint
        );
        Ok(())
    }

    /// Convert relay messages into inbound encrypted datagrams for WireGuard.
    pub async fn run_inbound(
        self,
        mut relay_rx: mpsc::Receiver<RelayMessage>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
        relay_selection: Option<Arc<tokio::sync::RwLock<RelaySelectionDiagnostics>>>,
    ) -> Result<()> {
        while let Some(message) = relay_rx.recv().await {
            match message {
                RelayMessage::Closed => {
                    if let Some(ref diags) = relay_selection {
                        let mut d = diags.write().await;
                        d.selected_error_count = d.selected_error_count.saturating_add(1);
                        d.last_error = Some("relay connection closed by remote".to_string());
                        d.last_error_code = Some("transport_closed".to_string());
                    }
                    return Err(DaemonError::Relay(format!(
                        "relay {} connection closed",
                        self.relay_endpoint
                    )));
                }
                RelayMessage::Error { code, message } => {
                    let error_code = relay_error_code_name(code);
                    warn!(
                        "Received relay runtime error: code={}, error_code={}, message={}",
                        code, error_code, message
                    );
                    if let Some(ref diags) = relay_selection {
                        let mut d = diags.write().await;
                        d.selected_error_count = d.selected_error_count.saturating_add(1);
                        d.last_error = Some(message.clone());
                        d.last_error_code = Some(error_code.clone());
                    }
                    if let Some(peer_id) = relay_error_peer_id(&message).map(str::to_string) {
                        self.peers
                            .record_relay_failure(&peer_id, error_code, message)
                            .await;
                    }
                }
                RelayMessage::Pong { timestamp } => {
                    let received_at_ms = now_unix_millis();
                    if let Some(ref diags) = relay_selection {
                        let mut d = diags.write().await;
                        record_relay_pong(&mut d, timestamp, received_at_ms);
                    }
                    debug!(
                        "Received ping-pong keepalive response from relay {} with timestamp {} rtt={}ms",
                        self.relay_endpoint,
                        timestamp,
                        received_at_ms.saturating_sub(timestamp)
                    );
                }
                RelayMessage::Data { from_node, data } => {
                    inbound_tx
                        .send(ReceivedEncryptedPacket {
                            source: None,
                            local_endpoint: None,
                            relay_endpoint: Some(self.relay_endpoint.clone()),
                            relay_peer_id: Some(from_node),
                            wire_bytes: data,
                        })
                        .await
                        .map_err(|_| {
                            DaemonError::Network("relay inbound packet channel closed".to_string())
                        })?;
                }
            }
        }

        warn!("Relay inbound stream from {} ended", self.relay_endpoint);
        Ok(())
    }
}
