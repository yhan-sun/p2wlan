/// A raw IP packet routed to a specific virtual-network peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    /// Destination peer node ID.
    pub peer_id: String,
    /// Destination virtual IP.
    pub dst_ip: String,
    /// Raw IP packet bytes read from TUN.
    pub packet: Vec<u8>,
}

/// A raw IP packet decrypted from a peer and ready to write into TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundPacket {
    /// Source peer node ID.
    pub peer_id: String,
    /// Raw IP packet bytes decrypted from the peer transport session.
    pub packet: Vec<u8>,
}

/// Reads packets from a virtual interface and routes them by destination IP.
pub struct DataPlane<T> {
    tun: T,
    peers: Arc<PeerManager>,
    outbound_tx: mpsc::Sender<OutboundPacket>,
    inbound_rx: Option<mpsc::Receiver<InboundPacket>>,
    acl: Option<Arc<RwLock<AclEngine>>>,
    local_node_id: Option<String>,
    overlay_v4: Option<Ipv4Cidr>,
}

impl<T> DataPlane<T>
where
    T: VirtualInterface + Send + 'static,
{
    /// Create a data plane and a receiver for routed outbound packets.
    pub fn new(tun: T, peers: Arc<PeerManager>) -> (Self, mpsc::Receiver<OutboundPacket>) {
        let (outbound_tx, outbound_rx) = mpsc::channel(1024);
        (
            Self {
                tun,
                peers,
                outbound_tx,
                inbound_rx: None,
                acl: None,
                local_node_id: None,
                overlay_v4: None,
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
        (
            Self {
                tun,
                peers,
                outbound_tx,
                inbound_rx: Some(inbound_rx),
                acl: None,
                local_node_id: None,
                overlay_v4: None,
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

        if let Some(mut inbound_rx) = self.inbound_rx.take() {
            loop {
                tokio::select! {
                    result = self.read_packet(&mut buf) => {
                        let packet = result?;
                        if !packet.is_empty() {
                            // The TUN read has completed.  Route outside the
                            // select future so a competing inbound packet
                            // cannot cancel after bytes were consumed.
                            self.route_outbound_packet(&packet).await?;
                        }
                    }
                    inbound = inbound_rx.recv() => {
                        let Some(packet) = inbound else {
                            warn!("Inbound data plane channel closed; continuing outbound-only");
                            break;
                        };
                        self.write_inbound(packet).await?;
                    }
                }
            }
        }

        loop {
            self.read_and_route_once(&mut buf).await?;
        }
    }

    async fn read_and_route_once(&mut self, buf: &mut [u8]) -> Result<()> {
        let packet = self.read_packet(buf).await?;
        if packet.is_empty() {
            return Ok(());
        }
        self.route_outbound_packet(&packet).await
    }

    /// Read exactly one TUN packet without doing any further asynchronous
    /// work.  `run` deliberately completes this future before entering the
    /// peer-resolution/routing phase: cancelling a future after it has
    /// consumed a packet from a TUN implementation is a silent packet loss.
    async fn read_packet(&mut self, buf: &mut [u8]) -> Result<Vec<u8>> {
        let n = self
            .tun
            .read(buf)
            .await
            .map_err(|e| DaemonError::Network(format!("TUN read failed: {e}")))?;
        Ok(buf[..n].to_vec())
    }

    /// Route a packet that has already been removed from the TUN read queue.
    /// This method may await peer state and ACL locks, but it is never placed
    /// directly in the `select!` that owns the TUN read operation.
    async fn route_outbound_packet(&mut self, packet: &[u8]) -> Result<()> {
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

        let routed = OutboundPacket {
            peer_id: peer_id.clone(),
            dst_ip: dst_ip.clone(),
            packet: routed_packet,
        };

        self.outbound_tx
            .send(routed)
            .await
            .map_err(|_| DaemonError::Network("outbound packet channel closed".to_string()))?;
        self.peers.record_sent(&peer_id, total_len as u64).await;

        debug!("Routed {total_len} byte {protocol} packet to {peer_id} ({dst_ip})");
        Ok(())
    }

    async fn write_inbound(&mut self, packet: InboundPacket) -> Result<()> {
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

        let written = self
            .tun
            .write(&inbound_packet)
            .await
            .map_err(|e| DaemonError::Network(format!("TUN write failed: {e}")))?;

        if written != inbound_packet.len() {
            return Err(DaemonError::Network(format!(
                "short TUN write for inbound packet from peer {}: wrote {} of {} bytes",
                packet.peer_id,
                written,
                inbound_packet.len()
            )));
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
