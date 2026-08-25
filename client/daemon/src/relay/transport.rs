/// Sends and receives encrypted WireGuard datagrams through a relay server.
#[derive(Clone)]
pub struct RelayTransport {
    /// Process-local incarnation of this relay connection. Clones retain the
    /// same id; reconnects and make-before-break replacements receive a new
    /// id even when endpoint and network generation are unchanged.
    relay_connection_id: u64,
    relay_region: String,
    relay_endpoint: String,
    connect_latency_ms: u64,
    /// Kernel route snapshot used when this connection was created. The
    /// supervisor compares it with the live route view so a socket pinned to
    /// an old Wi-Fi/Ethernet interface is replaced promptly after handover.
    route_signature: Vec<String>,
    client: Arc<RelayClient>,
    /// Synchronous lifetime gate for callbacks queued in the relay client's
    /// writer.  A same-endpoint make-before-break replacement does not change
    /// the peer/network generation, so those callbacks must also be retired
    /// with the exact transport incarnation.  The guard is deliberately held
    /// across expectation registration: retirement either wins first and the
    /// callback is rejected, or waits and then cancels the registered entry.
    write_boundaries_live: Arc<std::sync::Mutex<bool>>,
    peers: Arc<PeerManager>,
    /// Ticket audience of the connection's auth ticket, when authenticated.
    ticket_audience: Option<String>,
    /// Ticket region of the connection's auth ticket, when authenticated.
    ticket_region: Option<String>,
    /// Ticket expiry (unix seconds) the server will enforce; the supervisor
    /// schedules the make-before-break renewal from this deadline.
    ticket_expires_at_unix: Option<i64>,
}

static NEXT_RELAY_CONNECTION_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

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
        let routes = tokio::task::spawn_blocking(|| crate::netenv::direct_route_snapshot(&[]))
            .await
            .map_err(|error| {
                p2pnet_relay::RelayError::ConnectFailed(format!(
                    "relay route inspection task failed: {error}"
                ))
            })?;
        let route_signature = routes.signature.clone();
        config.outbound_interface = routes
            .direct_socket_interface()
            .map_err(p2pnet_relay::RelayError::ConnectFailed)?;
        if let Some(interface) = config.outbound_interface.as_deref() {
            debug!(
                interface,
                relay_endpoint, "Binding relay TCP connection to the physical interface"
            );
        }

        // Set CA cert path if provided
        if let Some(ca_path) = &ca_cert_path {
            config.tls_ca_cert_path = Some(std::path::PathBuf::from(ca_path));
        }

        // Use the new A2 endpoint-based connection which supports tls:// and tcp://
        let (client, relay_rx) =
            RelayClient::connect_with_endpoint(relay_endpoint, node_id, config).await?;

        let relay_connection_id =
            NEXT_RELAY_CONNECTION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        info!(
            event = "relay_transport_connected",
            relay_connection_id,
            relay_endpoint = %relay_endpoint,
            relay_region = %relay_region,
            connect_latency_ms = duration_millis(started.elapsed()),
            "relay transport connected and registered locally; peer delivery still requires encrypted confirmation"
        );

        Ok((
            Self {
                relay_connection_id,
                relay_region: relay_region.to_string(),
                relay_endpoint: relay_endpoint.to_string(),
                connect_latency_ms: duration_millis(started.elapsed()),
                route_signature,
                client: Arc::new(client),
                write_boundaries_live: Arc::new(std::sync::Mutex::new(true)),
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
            relay_connection_id: NEXT_RELAY_CONNECTION_ID
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            relay_region: relay_region.to_string(),
            relay_endpoint: relay_endpoint.to_string(),
            connect_latency_ms: 0,
            // Unit-test transports have no kernel socket and therefore do
            // not arm the production route watcher.
            route_signature: Vec::new(),
            client: Arc::new(p2pnet_relay::client::RelayClient::new_for_test()),
            write_boundaries_live: Arc::new(std::sync::Mutex::new(true)),
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

    /// Process-local connection incarnation used to reject ACKs delivered by
    /// a superseded relay reader after a same-endpoint replacement.
    pub(crate) fn connection_id(&self) -> u64 {
        self.relay_connection_id
    }

    /// TCP connect plus relay registration latency.
    pub fn connect_latency_ms(&self) -> u64 {
        self.connect_latency_ms
    }

    /// Route signature captured immediately before this TCP connection was
    /// created. Empty means route monitoring is unavailable on this platform
    /// or intentionally disabled for a test transport.
    pub(crate) fn route_signature(&self) -> &[String] {
        &self.route_signature
    }

    /// Immediately invalidate this relay connection.  This is used only when
    /// a completed command cannot be classified before the outbound deadline;
    /// a new generation must not inherit a writer that can emit the old
    /// ciphertext later.
    pub fn abort_writer(&self) {
        self.retire_write_boundaries();
        self.client.abort();
    }

    /// Retire callbacks queued by this exact relay connection.  The caller
    /// must subsequently remove expectations for `connection_id()`; holding
    /// this gate until any in-flight callback completes makes that removal a
    /// linearization point even when a writer dequeues concurrently.
    pub(crate) fn retire_write_boundaries(&self) {
        *self
            .write_boundaries_live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    }

    /// Send a single encrypted packet through the relay.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<()> {
        self.send_packet_inner(packet, None).await
    }

    /// Send a control packet whose expectation must be installed at the relay
    /// client's real writer boundary, after local command-queue delay.
    pub(crate) async fn send_packet_with_write_boundary<F>(
        &self,
        packet: &EncryptedPeerPacket,
        write_boundary: F,
    ) -> Result<()>
    where
        F: FnOnce(Instant) -> bool + Send + 'static,
    {
        self.send_packet_inner(packet, Some(Box::new(write_boundary)))
            .await
    }

    async fn send_packet_inner(
        &self,
        packet: &EncryptedPeerPacket,
        write_boundary: Option<Box<dyn FnOnce(Instant) -> bool + Send + 'static>>,
    ) -> Result<()> {
        debug!(
            event = "relay_outbound_write_submitted",
            peer_id = %packet.peer_id,
            relay_connection_id = self.relay_connection_id,
            relay_region = %self.relay_region,
            bytes = packet.wire_bytes.len(),
            counter = ?crate::transport::wire_counter(&packet.wire_bytes),
            is_business = packet.is_business,
            wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
            relay_endpoint = %self.relay_endpoint,
            "opaque encrypted frame submitted to the relay client's bounded command queue"
        );
        let send_result = match write_boundary {
            Some(write_boundary) => {
                let write_boundaries_live = Arc::clone(&self.write_boundaries_live);
                self.client
                    .send_data_with_write_boundary(
                        &packet.peer_id,
                        &packet.wire_bytes,
                        move |sent_at| {
                            let live = write_boundaries_live
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if !*live {
                                return false;
                            }
                            // Keep the transport-incarnation guard while the
                            // manager installs its expectation. Replacement
                            // retirement then cannot race past registration.
                            write_boundary(sent_at)
                        },
                    )
                    .await
            }
            None => {
                self.client
                    .send_data(&packet.peer_id, &packet.wire_bytes)
                    .await
            }
        };
        if let Err(error) = send_result {
            warn!(
                event = "relay_outbound_write_failed",
                peer_id = %packet.peer_id,
                relay_connection_id = self.relay_connection_id,
                relay_region = %self.relay_region,
                bytes = packet.wire_bytes.len(),
                counter = ?crate::transport::wire_counter(&packet.wire_bytes),
                is_business = packet.is_business,
                wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&packet.wire_bytes)),
                relay_endpoint = %self.relay_endpoint,
                error = %error,
                "relay client writer rejected or failed the encrypted frame"
            );
            return Err(DaemonError::RelaySend {
                endpoint: self.relay_endpoint.clone(),
                error,
            });
        }

        self.peers
            .record_relay_attempt(&packet.peer_id, &self.relay_endpoint)
            .await;
        debug!(
            event = "relay_outbound_write_completed",
            peer_id = %packet.peer_id,
            relay_connection_id = self.relay_connection_id,
            relay_region = %self.relay_region,
            bytes = packet.wire_bytes.len(),
            counter = ?crate::transport::wire_counter(&packet.wire_bytes),
            is_business = packet.is_business,
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
                    warn!(
                        event = "relay_transport_closed",
                        relay_connection_id = self.relay_connection_id,
                        relay_endpoint = %self.relay_endpoint,
                        relay_region = %self.relay_region,
                        reason_code = %reason_label,
                        "relay reader closed; any later reconnect has a new connection incarnation"
                    );
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
                RelayMessage::Pong {
                    timestamp,
                    round_trip_time,
                } => {
                    let received_at_ms = now_unix_millis();
                    if let Some(round_trip_time) = round_trip_time {
                        if let Some(ref diags) = relay_selection {
                            let mut d = diags.write().await;
                            record_relay_pong(&mut d, received_at_ms, round_trip_time);
                        }
                        debug!(
                            "Received matched ping-pong keepalive response from relay {} with token {} rtt={}ms",
                            self.relay_endpoint,
                            timestamp,
                            duration_millis(round_trip_time)
                        );
                    } else {
                        debug!(
                            "Ignored relay pong with unknown or expired token {} from {}",
                            timestamp, self.relay_endpoint
                        );
                    }
                }
                RelayMessage::Data { from_node, data } => {
                    let profiler = global_dataplane_profiler();
                    let profile_sampled = profiler.sample_next_packet();
                    let transport_queue_send_started = Instant::now();
                    profiler.record_value(
                        profile_sampled,
                        "rx_transport_inbound_queue_depth_before_send",
                        inbound_tx
                            .max_capacity()
                            .saturating_sub(inbound_tx.capacity()) as u64,
                    );
                    debug!(
                        event = "relay_inbound_frame_accepted",
                        peer_id = %from_node,
                        bytes = data.len(),
                        counter = ?crate::transport::wire_counter(&data),
                        wire_fp = format_args!("{:016x}", crate::transport::wire_fingerprint(&data)),
                        relay_endpoint = %self.relay_endpoint,
                        "opaque encrypted frame accepted by the relay client reader"
                    );
                    inbound_tx
                        .send(ReceivedEncryptedPacket {
                            source: None,
                            local_endpoint: None,
                            relay_endpoint: Some(self.relay_endpoint.clone()),
                            relay_connection_id: Some(self.relay_connection_id),
                            relay_peer_id: Some(from_node),
                            socket_index: None,
                            direct_socket: None,
                            udp_transport_owner: None,
                            network_generation: Some(self.peers.current_network_generation_sync()),
                            profile_sampled,
                            udp_received: None,
                            transport_queue_send_started: Some(transport_queue_send_started),
                            wire_bytes: data,
                        })
                        .await
                        .map_err(|_| {
                            DaemonError::Network("relay inbound packet channel closed".to_string())
                        })?;
                }
            }
        }

        warn!(
            event = "relay_transport_eof",
            relay_connection_id = self.relay_connection_id,
            relay_endpoint = %self.relay_endpoint,
            relay_region = %self.relay_region,
            "relay inbound stream ended; any later reconnect has a new connection incarnation"
        );
        Ok(())
    }
}
