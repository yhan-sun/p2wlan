/// Sends and receives encrypted WireGuard datagrams through a relay server.
#[derive(Clone)]
pub struct RelayTransport {
    relay_region: String,
    relay_endpoint: String,
    connect_latency_ms: u64,
    client: Arc<RelayClient>,
    peers: Arc<PeerManager>,
    /// Ticket audience of the connection's auth ticket, when authenticated.
    ticket_audience: Option<String>,
    /// Ticket region of the connection's auth ticket, when authenticated.
    ticket_region: Option<String>,
    /// Ticket expiry (unix seconds) the server will enforce; the supervisor
    /// schedules the make-before-break renewal from this deadline.
    ticket_expires_at_unix: Option<i64>,
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
                client: Arc::new(client),
                peers,
                ticket_audience: None,
                ticket_region: None,
                ticket_expires_at_unix: None,
            },
            relay_rx,
        ))
    }

    /// Attach the auth ticket metadata so the supervisor can schedule the
    /// proactive make-before-break renewal.
    pub(crate) fn with_ticket_metadata(
        mut self,
        audience: &str,
        region: &str,
        expires_at_ms: i64,
    ) -> Self {
        self.ticket_audience = Some(audience.to_string());
        self.ticket_region = Some(region.to_string());
        self.ticket_expires_at_unix = Some(expires_at_ms);
        self
    }

    /// Whether this connection is authenticated with a ticket.
    pub(crate) fn ticket_expiry(&self) -> Option<(String, String, i64)> {
        match (
            self.ticket_audience.as_ref(),
            self.ticket_region.as_ref(),
            self.ticket_expires_at_unix,
        ) {
            (Some(audience), Some(region), Some(expires_at_unix)) => {
                Some((audience.clone(), region.clone(), expires_at_unix))
            }
            _ => None,
        }
    }

    /// Test-only transport shell for unit tests that exercise ticket
    /// metadata without a live relay connection.
    #[cfg(test)]
    pub(crate) fn connect_for_test(
        relay_region: &str,
        relay_endpoint: &str,
        peers: Arc<PeerManager>,
    ) -> Self {
        Self {
            relay_region: relay_region.to_string(),
            relay_endpoint: relay_endpoint.to_string(),
            connect_latency_ms: 0,
            client: Arc::new(p2pnet_relay::client::RelayClient::new_for_test()),
            peers,
            ticket_audience: None,
            ticket_region: None,
            ticket_expires_at_unix: None,
        }
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

    /// Immediately invalidate this relay connection.  This is used only when
    /// a completed command cannot be classified before the outbound deadline;
    /// a new generation must not inherit a writer that can emit the old
    /// ciphertext later.
    pub fn abort_writer(&self) {
        self.client.abort();
    }

    /// Send a single encrypted packet through the relay.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<()> {
        self.client
            .send_data(&packet.peer_id, &packet.wire_bytes)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!(
                    "relay send to peer {} via {} failed reason_code={}: {e}",
                    packet.peer_id,
                    self.relay_endpoint,
                    e.to_snake_case()
                ))
            })?;

        self.peers
            .record_relay_attempt(&packet.peer_id, &self.relay_endpoint)
            .await;
        debug!(
            event = "relay_outbound_write_completed",
            peer_id = %packet.peer_id,
            bytes = packet.wire_bytes.len(),
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
            relay_endpoint = %self.relay_endpoint,
            "opaque encrypted frame completed the relay client write boundary"
        );
        debug!(
            "Sent {} encrypted bytes to peer {} through relay {}",
            packet.wire_bytes.len(),
            packet.peer_id,
            self.relay_endpoint
        );
        Ok(())
    }

    /// Convert relay messages into inbound encrypted datagrams for WireGuard.
    ///
    /// A `RelayMessage::Closed` ends the inbound drain with a typed error that
    /// embeds the close-reason label, but it does NOT record relay-selection
    /// diagnostics here: the EOF may belong to a SUPERSEDED connection that a
    /// make-before-break renewal already replaced (the hub's newest-wins close
    /// of the old connection).  Only the supervisor can tell that apart, so it
    /// attributes the diagnostics after classifying the end (see
    /// [`crate::relay_runtime::RelaySupervisor`]).
    pub async fn run_inbound(
        self,
        mut relay_rx: mpsc::Receiver<RelayMessage>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
        relay_selection: Option<Arc<tokio::sync::RwLock<RelaySelectionDiagnostics>>>,
    ) -> Result<()> {
        while let Some(message) = relay_rx.recv().await {
            match message {
                RelayMessage::Closed { reason } => {
                    let reason_label = relay_close_reason_label(reason);
                    return Err(DaemonError::Relay(format!(
                        "relay {} connection closed; reason={reason_label}",
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
                        // Relay registration handoffs can emit the same 404
                        // more than once before the remote reconnects. Keep
                        // one diagnostic sample for an identical outstanding
                        // error instead of turning one transient window into a
                        // misleading error-count storm. A different peer/code
                        // (or any later different error) remains visible.
                        //
                        // A per-peer `peer_not_found` describes ONE peer's
                        // registration, not the relay connection's health.  It
                        // is deduplicated against its own most-recent message
                        // and never written into the connection-level
                        // `last_error`/`last_error_code` (which the supervisor
                        // uses to report genuine connection ends).  The
                        // peer-level revocation/quarantine below is the
                        // authoritative handling.
                        if error_code == "peer_not_found" {
                            let duplicate =
                                d.last_peer_not_found.as_deref() == Some(message.as_str());
                            if !duplicate {
                                d.selected_error_count = d.selected_error_count.saturating_add(1);
                                d.last_peer_not_found = Some(message.clone());
                            }
                        } else {
                            let duplicate = d.last_error_code.as_deref()
                                == Some(error_code.as_str())
                                && d.last_error.as_deref() == Some(message.as_str());
                            if !duplicate {
                                d.selected_error_count = d.selected_error_count.saturating_add(1);
                            }
                            d.last_error = Some(message.clone());
                            d.last_error_code = Some(error_code.clone());
                            d.last_peer_not_found = None;
                        }
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
                    debug!(
                        event = "relay_inbound_frame_accepted",
                        peer_id = %from_node,
                        bytes = data.len(),
                        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&data)),
                        relay_endpoint = %self.relay_endpoint,
                        "opaque encrypted frame accepted by the relay client reader"
                    );
                    inbound_tx
                        .send(ReceivedEncryptedPacket {
                            source: None,
                            local_endpoint: None,
                            relay_endpoint: Some(self.relay_endpoint.clone()),
                            relay_peer_id: Some(from_node),
                            socket_index: None,
                            udp_transport_owner: None,
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
