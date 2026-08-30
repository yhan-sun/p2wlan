/// A raw IP packet routed to a specific virtual-network peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    /// Destination peer node ID.
    pub peer_id: String,
    /// Destination virtual IP.
    pub dst_ip: String,
    /// Raw IP packet bytes read from TUN.
    pub packet: Vec<u8>,
    /// Low-frequency userspace latency context. It is never used for routing
    /// or path selection and is absent for synthetic/control packets.
    pub(crate) trace: Option<DataplaneTxTrace>,
}

/// A raw IP packet decrypted from a peer and ready to write into TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundPacket {
    /// Source peer node ID.
    pub peer_id: String,
    /// Raw IP packet bytes decrypted from the peer transport session.
    pub packet: Vec<u8>,
    /// Opaque local transport-session instance that authenticated this
    /// packet. Synthetic/unit-test dataplane packets leave this unset. The
    /// inbound worker uses it to reject a packet that was decrypted just as
    /// the session was removed or replaced.
    pub session_instance: Option<u64>,
    /// True when the packet authenticated with the receive-only overlap key
    /// from the previous session. Such packets may still be delivered during
    /// the bounded WireGuard overlap window, but they are never path or
    /// first-usable evidence for the current session.
    pub from_previous_session: bool,
    /// Low-frequency userspace latency context, attached only by the live
    /// decrypt worker before the packet is written to TUN.
    pub(crate) trace: Option<DataplaneRxTrace>,
}

/// Reads packets from a virtual interface and routes them by destination IP.
pub struct DataPlane<T> {
    tun: T,
    peers: Arc<PeerManager>,
    outbound_tx: mpsc::Sender<OutboundPacket>,
    inbound_rx: Option<mpsc::Receiver<InboundPacket>>,
    local_feedback_rx: Option<tokio::sync::broadcast::Receiver<Vec<u8>>>,
    acl: Option<Arc<RwLock<AclEngine>>>,
    local_node_id: Option<String>,
    overlay_v4: Option<Ipv4Cidr>,
    #[cfg(target_os = "android")]
    tun_turnaround: TunTurnaroundCorrelator,
}

impl<T> DataPlane<T>
where
    T: VirtualInterface + Send + 'static,
{
    /// Create a data plane and a receiver for routed outbound packets.
    pub fn new(tun: T, peers: Arc<PeerManager>) -> (Self, mpsc::Receiver<OutboundPacket>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        let local_feedback_rx = peers.subscribe_local_mtu_feedback();
        (
            Self {
                tun,
                peers,
                outbound_tx,
                inbound_rx: None,
                local_feedback_rx: Some(local_feedback_rx),
                acl: None,
                local_node_id: None,
                overlay_v4: None,
                #[cfg(target_os = "android")]
                tun_turnaround: TunTurnaroundCorrelator::default(),
            },
            outbound_rx,
        )
    }

    /// Create a bidirectional data plane.
    ///
    /// Returns the data plane, outbound routed-packet receiver, and an inbound
    /// packet sender used by the decrypting transport layer.
    pub fn new_bidirectional(
        tun: T,
        peers: Arc<PeerManager>,
    ) -> (
        Self,
        mpsc::Receiver<OutboundPacket>,
        mpsc::Sender<InboundPacket>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        let local_feedback_rx = peers.subscribe_local_mtu_feedback();
        (
            Self {
                tun,
                peers,
                outbound_tx,
                inbound_rx: Some(inbound_rx),
                local_feedback_rx: Some(local_feedback_rx),
                acl: None,
                local_node_id: None,
                overlay_v4: None,
                #[cfg(target_os = "android")]
                tun_turnaround: TunTurnaroundCorrelator::default(),
            },
            outbound_rx,
            inbound_tx,
        )
    }

    /// Attach the live ACL used for both outbound and inbound overlay traffic.
    pub fn with_acl(
        mut self,
        acl: Arc<RwLock<AclEngine>>,
        local_node_id: impl Into<String>,
    ) -> Self {
        self.acl = Some(acl);
        self.local_node_id = Some(local_node_id.into());
        self
    }

    /// Attach the overlay IPv4 CIDR used to distinguish harmless OS source-address
    /// pollution from an actual attempt to impersonate another overlay node.
    pub fn with_overlay_cidr(mut self, cidr: &str) -> Self {
        self.overlay_v4 = Ipv4Cidr::parse(cidr);
        if self.overlay_v4.is_none() {
            warn!("Invalid or unsupported overlay CIDR {cidr}; strict source validation remains enabled");
        }
        self
    }

    /// Run the packet pump until the TUN device closes or an unrecoverable error occurs.
    pub async fn run(&mut self) -> Result<()> {
        let mut buf = vec![0u8; 65_535];
        let mut local_feedback_rx = self
            .local_feedback_rx
            .take()
            .expect("DataPlane::run may only be called once");

        if let Some(mut inbound_rx) = self.inbound_rx.take() {
            loop {
                tokio::select! {
                    result = self.read_packet(&mut buf) => {
                        let (packet, tun_read_started, tun_read_completed) = result?;
                        if !packet.is_empty() {
                            // The TUN read has completed.  Route outside the
                            // select future so a competing inbound packet
                            // cannot cancel after bytes were consumed.
                            self.route_outbound_packet(
                                &packet,
                                tun_read_started,
                                tun_read_completed,
                            )
                            .await?;
                        }
                    }
                    inbound = inbound_rx.recv() => {
                        let Some(packet) = inbound else {
                            warn!("Inbound data plane channel closed; continuing outbound-only");
                            break;
                        };
                        let profiler = global_dataplane_profiler();
                        let mut packet = packet;
                        if let Some(trace) = packet.trace.as_mut() {
                            trace.inbound_queue_dequeued = Some(std::time::Instant::now());
                            profiler.record_value(
                                trace.sampled,
                                "rx_dataplane_inbound_queue_depth",
                                inbound_rx.len() as u64,
                            );
                            if let Some(enqueued) = trace.inbound_queue_send_started {
                                let queue_wait = trace
                                    .inbound_queue_dequeued
                                    .expect("inbound dequeue timestamp was just set")
                                    .duration_since(enqueued);
                                profiler.record(
                                    trace.sampled,
                                    "rx_inbound_queue_wait_us",
                                    queue_wait,
                                );
                                // Preserve the Phase 4 diagnostic name for
                                // existing log consumers.
                                profiler.record(
                                    trace.sampled,
                                    "rx_dataplane_inbound_queue_wait_us",
                                    queue_wait,
                                );
                            }
                        }
                        self.write_inbound(packet).await?;
                    }
                    feedback = local_feedback_rx.recv() => {
                        match feedback {
                            Ok(packet) => self.write_local_feedback(&packet).await?,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!(
                                    event = "local_mtu_feedback_lagged",
                                    skipped,
                                    "local PMTU feedback receiver dropped a bounded backlog"
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        }

        loop {
            tokio::select! {
                result = self.read_and_route_once(&mut buf) => result?,
                feedback = local_feedback_rx.recv() => {
                    match feedback {
                        Ok(packet) => self.write_local_feedback(&packet).await?,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                event = "local_mtu_feedback_lagged",
                                skipped,
                                "local PMTU feedback receiver dropped a bounded backlog"
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
                    }
                }
            }
        }
    }

    async fn write_local_feedback(&mut self, packet: &[u8]) -> Result<()> {
        IpPacket::new(packet).map_err(|error| {
            DaemonError::Network(format!("invalid locally generated MTU feedback: {error}"))
        })?;
        let written = self
            .tun
            .write(packet)
            .await
            .map_err(|error| DaemonError::Network(format!("local MTU feedback TUN write failed: {error}")))?;
        if written != packet.len() {
            return Err(DaemonError::Network(format!(
                "short local MTU feedback TUN write: wrote {written} of {} bytes",
                packet.len()
            )));
        }
        debug!(
            event = "local_mtu_feedback_injected",
            bytes = packet.len(),
            "injected locally generated PMTU feedback into TUN"
        );
        Ok(())
    }

    async fn read_and_route_once(&mut self, buf: &mut [u8]) -> Result<()> {
        let (packet, tun_read_started, tun_read_completed) = self.read_packet(buf).await?;
        if packet.is_empty() {
            return Ok(());
        }
        self.route_outbound_packet(&packet, tun_read_started, tun_read_completed)
            .await
    }

    /// Read exactly one TUN packet without doing any further asynchronous
    /// work.  `run` deliberately completes this future before entering the
    /// peer-resolution/routing phase: cancelling a future after it has
    /// consumed a packet from a TUN implementation is a silent packet loss.
    async fn read_packet(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(Vec<u8>, std::time::Instant, std::time::Instant)> {
        let started = std::time::Instant::now();
        let n = self
            .tun
            .read(buf)
            .await
            .map_err(|e| DaemonError::Network(format!("TUN read failed: {e}")))?;
        Ok((buf[..n].to_vec(), started, std::time::Instant::now()))
    }

    /// Route a packet that has already been removed from the TUN read queue.
    /// This method may await peer state and ACL locks, but it is never placed
    /// directly in the `select!` that owns the TUN read operation.
    async fn route_outbound_packet(
        &mut self,
        packet: &[u8],
        tun_read_started: std::time::Instant,
        tun_read_completed: std::time::Instant,
    ) -> Result<()> {
        let profiler = global_dataplane_profiler();
        let sampled = profiler.sample_next_packet();
        #[cfg(target_os = "android")]
        if let Some(turnaround) = self
            .tun_turnaround
            .observe_reply(packet, tun_read_completed)
        {
            profiler.record(true, "android_tun_kernel_turnaround_us", turnaround);
        }
        // The read future can legitimately wait for the next packet. Keep that
        // idle wait diagnostic-only; TX latency starts at the completed packet.
        profiler.record(
            sampled,
            "tun_read_idle_wait_us",
            tun_read_completed.duration_since(tun_read_started),
        );
        let parsed = match IpPacket::new(packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!("Dropping invalid IP packet from TUN: {err}");
                return Ok(());
            }
        };

        let total_len = parsed.total_len().min(packet.len());
        let protocol = parsed.protocol();
        let dst_ip = parsed.dst_addr_string();
        let src_ip = parsed.src_addr_string();

        let Some(peer_id) = self.peers.resolve_virtual_ip(&dst_ip).await else {
            trace!("Dropping packet for unknown virtual IP {dst_ip} ({protocol})");
            return Ok(());
        };

        let routed_packet = if src_ip == self.tun.address() {
            packet[..total_len].to_vec()
        } else {
            match self.normalize_outbound_source(&packet[..total_len], &src_ip, &dst_ip, protocol) {
                Some(normalized) => normalized,
                None => return Ok(()),
            }
        };

        let parsed = match IpPacket::new(&routed_packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!("Dropping normalized outbound packet that no longer parses: {err}");
                return Ok(());
            }
        };

        if !self
            .acl_allows(
                self.local_node_id.as_deref().unwrap_or("local"),
                &peer_id,
                &parsed,
            )
            .await
        {
            warn!("ACL denied outbound {protocol} packet to peer {peer_id}");
            return Ok(());
        }

        let route_ready = std::time::Instant::now();
        profiler.record(
            sampled,
            "tx_tun_to_route_ready_us",
            route_ready.duration_since(tun_read_completed),
        );
        let mut routed = OutboundPacket {
            peer_id: peer_id.clone(),
            dst_ip: dst_ip.clone(),
            packet: routed_packet,
            trace: Some(DataplaneTxTrace {
                sampled,
                tun_read_started,
                tun_read_completed,
                route_ready: Some(route_ready),
                dataplane_queue_send_started: None,
                transport_queue_dequeued: None,
                transport_queue_send_started: None,
                network_queue_dequeued: None,
            }),
        };

        let queue_started = std::time::Instant::now();
        if let Some(trace) = routed.trace.as_mut() {
            trace.dataplane_queue_send_started = Some(queue_started);
        }
        profiler.record_value(
            sampled,
            "tx_outbound_queue_depth",
            self.outbound_tx
                .max_capacity()
                .saturating_sub(self.outbound_tx.capacity()) as u64,
        );
        self.outbound_tx
            .send(routed)
            .await
            .map_err(|_| DaemonError::Network("outbound packet channel closed".to_string()))?;
        let queue_wait = queue_started.elapsed();
        profiler.record(sampled, "tx_outbound_queue_wait_us", queue_wait);
        // Preserve the Phase 4 name for existing log consumers while the new
        // name makes the measured boundary explicit.
        profiler.record(sampled, "udp_send_queue_us", queue_wait);
        profiler.record(
            sampled,
            "tx_route_to_queue_send_us",
            queue_started.duration_since(tun_read_completed),
        );
        profiler.record(
            sampled,
            "tun_read_to_route_us",
            queue_started.duration_since(tun_read_completed),
        );
        if queue_wait >= DATAPLANE_STALL_THRESHOLD {
            tracing::debug!(
                event = "dataplane_stall",
                peer_id = %peer_id,
                active_path = if self.peers.is_direct_sync(&peer_id) { "direct" } else { "relay_or_unknown" },
                tun_to_send_us = queue_started
                    .duration_since(tun_read_started)
                    .as_micros() as u64,
                receive_to_tun_us = 0u64,
                candidate_gather_active = profiler.candidate_gather_active(),
                network_generation = self.peers.current_network_generation_sync(),
                queue_wait_us = queue_wait.as_micros() as u64,
                "outbound dataplane packet waited beyond the diagnostic stall threshold"
            );
        }
        self.peers.record_sent(&peer_id, total_len as u64).await;

        debug!("Routed {total_len} byte {protocol} packet to {peer_id} ({dst_ip})");
        Ok(())
    }

    async fn write_inbound(&mut self, packet: InboundPacket) -> Result<()> {
        let trace = packet.trace.clone();
        let validation_started = std::time::Instant::now();
        let parsed = match IpPacket::new(&packet.packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(
                    "Dropping invalid inbound IP packet from peer {}: {err}",
                    packet.peer_id
                );
                return Ok(());
            }
        };

        let protocol = parsed.protocol();
        let total_len = parsed.total_len().min(packet.packet.len());
        let mut inbound_packet = packet.packet[..total_len].to_vec();
        let src_ip = parsed.src_addr_string();
        let dst_ip = parsed.dst_addr_string();

        let Some(peer) = self.peers.get_connection(&packet.peer_id).await else {
            warn!(
                "Dropping inbound packet from unknown peer {}",
                packet.peer_id
            );
            return Ok(());
        };
        if dst_ip != self.tun.address() {
            warn!(
                "Dropping inbound packet from peer {} for unexpected destination {}; local TUN address is {}",
                packet.peer_id,
                dst_ip,
                self.tun.address()
            );
            return Ok(());
        }

        if src_ip != peer.virtual_ip {
            match self.normalize_inbound_source(
                &inbound_packet,
                &packet.peer_id,
                &src_ip,
                &peer.virtual_ip,
                &dst_ip,
                protocol,
            ) {
                Some(normalized) => inbound_packet = normalized,
                None => return Ok(()),
            }
        }

        let parsed = match IpPacket::new(&inbound_packet) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(
                    "Dropping normalized inbound packet from peer {} that no longer parses: {err}",
                    packet.peer_id
                );
                return Ok(());
            }
        };

        if !self
            .acl_allows(
                &packet.peer_id,
                self.local_node_id.as_deref().unwrap_or("local"),
                &parsed,
            )
            .await
        {
            warn!(
                "ACL denied inbound {protocol} packet from peer {}",
                packet.peer_id
            );
            return Ok(());
        }

        let tun_write_started = std::time::Instant::now();
        if let Some(trace) = trace.as_ref() {
            global_dataplane_profiler().record(
                trace.sampled,
                "rx_dataplane_validation_us",
                tun_write_started.duration_since(validation_started),
            );
        }
        let written = self
            .tun
            .write(&inbound_packet)
            .await
            .map_err(|e| DaemonError::Network(format!("TUN write failed: {e}")))?;
        let tun_write_completed = std::time::Instant::now();

        if written != inbound_packet.len() {
            return Err(DaemonError::Network(format!(
                "short TUN write for inbound packet from peer {}: wrote {} of {} bytes",
                packet.peer_id,
                written,
                inbound_packet.len()
            )));
        }

        #[cfg(target_os = "android")]
        if let Some(trace) = trace.as_ref() {
            self.tun_turnaround
                .record_request(&inbound_packet, tun_write_completed, trace.sampled);
        }

        if let Some(trace) = trace {
            let profiler = global_dataplane_profiler();
            let rx_start = trace.udp_received.unwrap_or(trace.transport_dequeued);
            let receive_to_tun = tun_write_completed.duration_since(rx_start);
            let tun_write = tun_write_completed.duration_since(tun_write_started);
            profiler.record(trace.sampled, "rx_tun_write_us", tun_write);
            profiler.record(
                trace.sampled,
                "rx_decrypt_queue_to_tun_us",
                tun_write_completed.duration_since(trace.transport_dequeued),
            );
            profiler.record(
                trace.sampled,
                "rx_decrypt_to_tun_write_us",
                tun_write_started.duration_since(trace.decrypt_completed),
            );
            profiler.record(
                trace.sampled,
                "decrypt_to_tun_write_us",
                tun_write_started.duration_since(trace.decrypt_completed),
            );
            profiler.record(trace.sampled, "total_userspace_rx_us", receive_to_tun);
            profiler.record(
                trace.sampled,
                if trace.udp_received.is_some() {
                    "rx_udp_total_userspace_us"
                } else {
                    "rx_relay_total_userspace_us"
                },
                receive_to_tun,
            );
            profiler.record_tail_event(
                "rx",
                &packet.peer_id,
                "inbound",
                receive_to_tun,
                DataplaneTailMetrics {
                    queue_wait_us: trace
                        .inbound_queue_send_started
                        .zip(trace.inbound_queue_dequeued)
                        .map(|(start, end)| end.duration_since(start).as_micros() as u64)
                        .unwrap_or_default(),
                    crypto_us: trace
                        .decrypt_completed
                        .duration_since(trace.decrypt_started)
                        .as_micros() as u64,
                    tun_write_us: tun_write.as_micros() as u64,
                    ..DataplaneTailMetrics::default()
                },
                profiler.candidate_gather_active(),
                self.peers.current_network_generation_sync(),
            );
            if receive_to_tun >= DATAPLANE_STALL_THRESHOLD {
                tracing::debug!(
                    event = "dataplane_stall",
                    peer_id = %packet.peer_id,
                    active_path = if self.peers.is_direct_sync(&packet.peer_id) { "direct" } else { "relay_or_unknown" },
                    tun_to_send_us = 0u64,
                    receive_to_tun_us = receive_to_tun.as_micros() as u64,
                    candidate_gather_active = profiler.candidate_gather_active(),
                    network_generation = self.peers.current_network_generation_sync(),
                    "inbound dataplane packet exceeded the diagnostic stall threshold"
                );
            }
        }

        self.peers
            .record_received(&packet.peer_id, inbound_packet.len() as u64)
            .await;

        debug!(
            "Wrote {} byte {protocol} packet from peer {} to TUN ({} -> {dst_ip})",
            inbound_packet.len(),
            packet.peer_id,
            IpPacket::new(&inbound_packet)
                .map(|packet| packet.src_addr_string())
                .unwrap_or(src_ip)
        );
        Ok(())
    }

    async fn acl_allows(&self, src_node: &str, dst_node: &str, packet: &IpPacket<'_>) -> bool {
        let Some(acl) = self.acl.as_ref() else {
            return true;
        };
        let protocol = packet.protocol().to_string().to_ascii_lowercase();
        let port = match protocol.as_str() {
            "tcp" | "udp" if packet.payload().len() >= 4 => {
                u16::from_be_bytes([packet.payload()[2], packet.payload()[3]])
            }
            _ => 0,
        };
        acl.read().await.check(src_node, dst_node, &protocol, port)
    }

    fn normalize_outbound_source(
        &self,
        packet: &[u8],
        src_ip: &str,
        dst_ip: &str,
        protocol: impl std::fmt::Display,
    ) -> Option<Vec<u8>> {
        let local_ip = self.tun.address();
        match normalize_overlay_source(packet, src_ip, local_ip, self.overlay_v4) {
            SourceNormalization::Normalized(normalized) => {
                debug!(
                    "Normalized outbound {protocol} source IP {src_ip} -> {local_ip} for {dst_ip}"
                );
                Some(normalized)
            }
            SourceNormalization::BlockedOverlaySpoof => {
                warn!(
                    "Dropping outbound {protocol} packet with overlay-spoofed source IP {src_ip}; local TUN address is {local_ip}, destination is {dst_ip}"
                );
                None
            }
            SourceNormalization::Unsupported => {
                warn!(
                    "Dropping outbound {protocol} packet with unexpected source IP {src_ip}; local TUN address is {local_ip}"
                );
                None
            }
        }
    }

    fn normalize_inbound_source(
        &self,
        packet: &[u8],
        peer_id: &str,
        src_ip: &str,
        peer_virtual_ip: &str,
        dst_ip: &str,
        protocol: impl std::fmt::Display,
    ) -> Option<Vec<u8>> {
        match normalize_overlay_source(packet, src_ip, peer_virtual_ip, self.overlay_v4) {
            SourceNormalization::Normalized(normalized) => {
                debug!(
                    "Normalized inbound {protocol} source IP {src_ip} -> {peer_virtual_ip} for peer {peer_id} ({dst_ip})"
                );
                Some(normalized)
            }
            SourceNormalization::BlockedOverlaySpoof => {
                warn!(
                    "Dropping inbound {protocol} packet from peer {peer_id} with overlay-spoofed source IP {src_ip}; expected {peer_virtual_ip}"
                );
                None
            }
            SourceNormalization::Unsupported => {
                warn!(
                    "Dropping inbound {protocol} packet from peer {peer_id} with spoofed source IP {src_ip}; expected {peer_virtual_ip}"
                );
                None
            }
        }
    }
}
