use super::*;
use crate::transport::wire::wire_receiver_index;

impl WireGuardTransport {
    /// Consume encrypted network packets, decrypt them, and emit raw inbound IP packets.
    pub async fn run_inbound(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
    ) -> Result<()> {
        self.run_inbound_with_peers(encrypted_rx, inbound_tx, None, None)
            .await
    }

    /// Consume encrypted network packets and confirm direct UDP only after
    /// successful WireGuard decryption.
    ///
    /// `udp` optionally carries the direct UDP transport: a decrypted packet
    /// whose receive socket is known adopts the socket as the peer's fresh
    /// affinity evidence — raw encrypted UDP is never affinity evidence
    /// before decryption proves the datagram belongs to the peer.
    pub async fn run_inbound_with_peers(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp: Option<crate::udp::UdpTransport>,
    ) -> Result<()> {
        self.run_inbound_with_udp_source(
            encrypted_rx,
            inbound_tx,
            peers,
            InboundUdpTransport::Static(Box::new(udp)),
            None,
        )
        .await
    }

    /// Consume encrypted packets while resolving the UDP transport from the
    /// latest daemon publication for every packet.  `evidence` optionally
    /// carries the shared relay transport (for forced-relay probe ACKs) and the
    /// overlay ingress channel (real ingress metadata for decrypted overlay
    /// payloads).  This is intentionally separate from the static API above so
    /// unit tests and non-daemon users retain their simple
    /// `Option<UdpTransport>` setup.
    pub(crate) async fn run_inbound_with_peers_live_udp_and_relay(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp_updates: watch::Receiver<Option<crate::udp::UdpTransport>>,
        evidence: Option<InboundEvidenceFeed>,
    ) -> Result<()> {
        self.run_inbound_with_udp_source(
            encrypted_rx,
            inbound_tx,
            peers,
            InboundUdpTransport::Watch(udp_updates),
            evidence,
        )
        .await
    }

    /// Consume encrypted packets while resolving the UDP transport from the
    /// latest daemon publication for every packet.  This is intentionally
    /// separate from the static API above so unit tests and non-daemon users
    /// retain their simple `Option<UdpTransport>` setup.
    #[cfg(test)]
    pub(crate) async fn run_inbound_with_peers_live_udp(
        &self,
        encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp_updates: watch::Receiver<Option<crate::udp::UdpTransport>>,
    ) -> Result<()> {
        self.run_inbound_with_peers_live_udp_and_relay(
            encrypted_rx,
            inbound_tx,
            peers,
            udp_updates,
            None,
        )
        .await
    }

    pub(in crate::transport) async fn run_inbound_with_udp_source(
        &self,
        mut encrypted_rx: mpsc::Receiver<ReceivedEncryptedPacket>,
        inbound_tx: mpsc::Sender<InboundPacket>,
        peers: Option<Arc<PeerManager>>,
        udp_source: InboundUdpTransport,
        evidence: Option<InboundEvidenceFeed>,
    ) -> Result<()> {
        while let Some(packet) = encrypted_rx.recv().await {
            let profiler = global_dataplane_profiler();
            let sampled = packet.profile_sampled;
            let transport_dequeued = Instant::now();
            profiler.record_value(
                sampled,
                "rx_transport_inbound_queue_depth",
                encrypted_rx.len() as u64,
            );
            if let Some(enqueued) = packet.transport_queue_send_started {
                profiler.record(
                    sampled,
                    "rx_transport_queue_wait_us",
                    transport_dequeued.duration_since(enqueued),
                );
            }
            if let Some(udp_received) = packet.udp_received {
                profiler.record(
                    sampled,
                    "rx_udp_receive_to_decrypt_us",
                    Instant::now().duration_since(udp_received),
                );
            }
            let source = packet.source;
            let local_endpoint = packet.local_endpoint;
            let relay_endpoint = packet.relay_endpoint;
            let relay_connection_id = packet.relay_connection_id;
            let relay_peer_id = packet.relay_peer_id;
            let socket_index = packet.socket_index;
            let direct_socket = packet.direct_socket;
            let udp_transport_owner = packet.udp_transport_owner;
            let packet_network_generation = packet.network_generation;
            debug!(
                event = "wireguard_inbound_envelope_received",
                bytes = packet.wire_bytes.len(),
                receiver_index = ?wire_receiver_index(&packet.wire_bytes),
                counter = ?wire_counter(&packet.wire_bytes),
                wire_fp = format_args!("{:016x}", wire_fingerprint(&packet.wire_bytes)),
                source = ?source,
                local_endpoint = ?local_endpoint,
                socket_index = ?socket_index,
                relay_endpoint = ?relay_endpoint,
                relay_connection_id = ?relay_connection_id,
                relay_peer_id = ?relay_peer_id,
                network_generation = ?packet_network_generation,
                "encrypted datagram reached the daemon transport decrypt boundary"
            );
            let decrypt_started = Instant::now();
            match self.decrypt_inbound_classified(&packet.wire_bytes).await {
                Ok(Some(mut inbound)) => {
                    let decrypt_completed = Instant::now();
                    profiler.record(
                        sampled,
                        "rx_decrypt_us",
                        decrypt_completed.duration_since(decrypt_started),
                    );
                    profiler.record(
                        sampled,
                        "transport_queue_to_decrypt_us",
                        decrypt_started.duration_since(transport_dequeued),
                    );
                    profiler.record(
                        sampled,
                        "decrypt_us",
                        decrypt_completed.duration_since(decrypt_started),
                    );
                    inbound.trace = Some(DataplaneRxTrace {
                        sampled,
                        udp_received: packet.udp_received,
                        transport_queue_send_started: packet.transport_queue_send_started,
                        transport_dequeued,
                        decrypt_started,
                        decrypt_completed,
                        inbound_queue_send_started: None,
                        inbound_queue_dequeued: None,
                    });
                    debug!(
                        event = "wireguard_inbound_decrypt_succeeded",
                        peer_id = %inbound.peer_id,
                        receiver_index = ?wire_receiver_index(&packet.wire_bytes),
                        counter = ?wire_counter(&packet.wire_bytes),
                        wire_fp = format_args!("{:016x}", wire_fingerprint(&packet.wire_bytes)),
                        session_instance = ?inbound.session_instance,
                        from_previous_session = inbound.from_previous_session,
                        source = ?source,
                        relay_endpoint = ?relay_endpoint,
                        relay_connection_id = ?relay_connection_id,
                        network_generation = ?packet_network_generation,
                        "WireGuard authenticated and decrypted the envelope before lifecycle/path evidence gates"
                    );
                    if let (Some(relay_endpoint), Some(feed)) =
                        (relay_endpoint.as_deref(), evidence.as_ref())
                    {
                        if let Some(timeline) = feed.timeline.as_ref() {
                            let generation = packet_network_generation.unwrap_or_default();
                            let scope = format!("peer:{}:{generation}", inbound.peer_id);
                            timeline.emit_first_scoped(
                                &scope,
                                "relay_inbound_authenticated",
                                Some("relay"),
                                None,
                                Some(format!(
                                    "peer={} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} session_instance={:?} decrypt_us={} encrypted_queue_depth={}",
                                    inbound.peer_id,
                                    inbound.session_instance,
                                    decrypt_completed.duration_since(decrypt_started).as_micros(),
                                    encrypted_rx.len(),
                                )),
                            );
                        }
                    }
                    if let (Some(packet_generation), Some(peer_manager)) =
                        (packet_network_generation, peers.as_ref())
                    {
                        let current_generation = peer_manager.current_network_generation_sync();
                        if packet_generation != current_generation {
                            if let Some(feed) = evidence.as_ref() {
                                if let Some(timeline) = feed.timeline.as_ref() {
                                    timeline.emit(
                                        "stale_network_generation_packet",
                                        None,
                                        Some("stale_network_generation"),
                                        Some(format!(
                                            "peer={} packet_generation={packet_generation} current_generation={current_generation}",
                                            inbound.peer_id
                                        )),
                                    );
                                }
                            }
                            debug!(
                                peer_id = %inbound.peer_id,
                                packet_generation,
                                current_generation,
                                "dropping encrypted packet queued before the current network generation"
                            );
                            continue;
                        }
                    }
                    if let Some(session_instance) = inbound.session_instance {
                        let (retained, current) = self
                            .session_instance_state(&inbound.peer_id, session_instance)
                            .await;
                        if !retained || (!inbound.from_previous_session && !current) {
                            if let Some(feed) = evidence.as_ref() {
                                if let Some(timeline) = feed.timeline.as_ref() {
                                    timeline.emit(
                                        "stale_session_packet",
                                        None,
                                        Some("session_replaced_or_removed"),
                                        Some(format!(
                                            "peer={} session_instance={session_instance}",
                                            inbound.peer_id
                                        )),
                                    );
                                }
                            }
                            debug!(
                                peer_id = %inbound.peer_id,
                                session_instance,
                                "dropping packet decrypted by a removed or replaced transport session"
                            );
                            continue;
                        }
                    }
                    // The previous receive key is retained only as a bounded
                    // WireGuard rekey grace period. It may deliver an
                    // in-flight user packet, but it must never confirm a
                    // relay/direct path, advance affinity, or create current
                    // generation first-usable evidence.
                    let session_evidence_eligible = !inbound.from_previous_session;
                    // Do not retain a UDP watch snapshot across decrypt. A
                    // datagram can sit in the channel while its reader fails
                    // or its socket is rebound; only the current owner after
                    // decrypt may provide Direct evidence or affinity.
                    let udp = udp_source.snapshot();
                    let owns_direct_packet =
                        udp_source.owns_direct_packet(udp_transport_owner, udp.as_ref());
                    if relay_peer_id
                        .as_deref()
                        .is_some_and(|relay_peer_id| relay_peer_id != inbound.peer_id)
                    {
                        warn!(
                            "Dropping relay packet whose registered source {:?} does not match decrypted peer {}",
                            relay_peer_id, inbound.peer_id
                        );
                        continue;
                    }
                    // The relay probe loop is intentionally paced and can
                    // lose a scheduling race with the first encrypted frame
                    // arriving from a newly published relay reader.  Publish
                    // the per-peer transport-ready milestone at the decrypt
                    // boundary as well, before any probe/business evidence is
                    // processed.  Bind every relay envelope—not only probe
                    // ACKs—to the current transport incarnation: a draining
                    // old reader with the same endpoint must not deliver a
                    // user packet or create first-usable evidence for the new
                    // relay session.
                    let relay_ingress_is_current = if relay_endpoint.is_some() {
                        match evidence.as_ref() {
                            Some(feed) => {
                                let current_connection_id = feed
                                    .relay_transport
                                    .read()
                                    .await
                                    .as_ref()
                                    .map(RelayTransport::connection_id);
                                match (relay_connection_id, current_connection_id) {
                                    (Some(packet_id), Some(current_id)) => packet_id == current_id,
                                    (None, None) => true,
                                    _ => false,
                                }
                            }
                            // Standalone transport tests may not install a
                            // shared relay slot; without that owner there is
                            // no incarnation claim to compare.
                            None => true,
                        }
                    } else {
                        true
                    };
                    if !relay_ingress_is_current {
                        if let Some(feed) = evidence.as_ref() {
                            if let Some(timeline) = feed.timeline.as_ref() {
                                timeline.emit(
                                    "stale_relay_transport_packet",
                                    Some("relay"),
                                    Some("relay_transport_replaced"),
                                    Some(format!(
                                        "peer={} packet_connection_id={relay_connection_id:?}",
                                        inbound.peer_id
                                    )),
                                );
                            }
                        }
                        debug!(
                            peer_id = %inbound.peer_id,
                            relay_endpoint = ?relay_endpoint,
                            relay_connection_id = ?relay_connection_id,
                            "dropping encrypted relay packet from a superseded transport incarnation"
                        );
                        continue;
                    }
                    if let (Some(relay_endpoint), Some(peer_manager)) =
                        (relay_endpoint.as_deref(), peers.as_ref())
                    {
                        let generation = packet_network_generation
                            .unwrap_or_else(|| peer_manager.current_network_generation_sync());
                        // A relay frame can decrypt successfully just before
                        // a rekey publishes a replacement session.  Keep the
                        // old packet deliverable during receive overlap, but
                        // do not let it recreate the new generation's
                        // relay-ready milestone.
                        let session_guard = self
                            .acquire_current_session_evidence_guard(
                                &inbound.peer_id,
                                inbound.session_instance,
                            )
                            .await;
                        let session_current =
                            inbound.session_instance.is_none() || session_guard.is_some();
                        let peer_session_generation =
                            peer_manager.peer_session_generation_sync(&inbound.peer_id);
                        if session_current {
                            let _ = peer_manager.try_mark_relay_transport_ready_with_transport(
                                &inbound.peer_id,
                                relay_endpoint,
                                generation,
                                relay_connection_id,
                            );
                            if let (Some(peer_session_generation), Some(session_instance)) =
                                (peer_session_generation, inbound.session_instance)
                            {
                                let _ = peer_manager
                                    .try_commit_pending_relay_business_evidence_for_session(
                                        &inbound.peer_id,
                                        generation,
                                        peer_session_generation,
                                        session_instance,
                                        relay_endpoint,
                                        relay_connection_id,
                                    );
                                if session_evidence_eligible
                                    && is_real_overlay_business_packet(&inbound.packet)
                                {
                                    peer_manager
                                        .confirm_relay_peer_from_business_ingress_for_session(
                                            &inbound.peer_id,
                                            relay_endpoint,
                                            generation,
                                            relay_connection_id,
                                            peer_session_generation,
                                            session_instance,
                                        );
                                }
                            }
                        }
                        let legacy_business_confirmation = session_current
                            && inbound.session_instance.is_none()
                            && session_evidence_eligible
                            && is_real_overlay_business_packet(&inbound.packet);
                        drop(session_guard);
                        // A real encrypted overlay packet arriving through
                        // the current relay is itself an end-to-end relay
                        // proof.  It is legal for it to win the race against
                        // the forced path-probe ACK; waiting for the ACK in
                        // that case used to reject the packet as
                        // `first_relay_before_peer_confirmation`, lose the
                        // only WireGuard delivery evidence to replay
                        // protection, and leave the generation without a
                        // first-usable path.  Promote the relay confirmation
                        // from this business ingress before the evidence
                        // markers below are committed.  Direct remains
                        // independently gated by encrypted Direct validation
                        // and the bidirectional relay-business exchange.
                        if legacy_business_confirmation {
                            peer_manager
                                .confirm_relay_peer_from_business_ingress(
                                    &inbound.peer_id,
                                    relay_endpoint,
                                    generation,
                                    relay_connection_id,
                                )
                                .await;
                        }
                    }
                    // A decrypted relay datagram keeps the relay health
                    // bookkeeping fresh below, but it does NOT set
                    // RelayPeerConfirmed: per the relay-first contract that
                    // milestone is only reached by a matching forced-relay
                    // probe ACK whose real ingress was relay.  A local
                    // TCP/TLS connect or a command-queue accept is never
                    // delivery.
                    let internal_rekey_confirmation = is_rekey_confirmation_packet(&inbound.packet);
                    let direct_validation = parse_direct_validation_token(&inbound.packet);
                    let direct_validation_dplpmtud_capability = direct_validation.is_some()
                        && crate::dplpmtud::direct_validation_supports_dplpmtud(&inbound.packet);
                    let dplpmtud = crate::dplpmtud::parse_control_packet(&inbound.packet);
                    if relay_endpoint.is_some() {
                        if let Some(feed) = evidence.as_ref() {
                            if let Some(timeline) = feed.timeline.as_ref() {
                                let generation = packet_network_generation.unwrap_or_default();
                                let scope = format!("peer:{}:{generation}", inbound.peer_id);
                                timeline.emit_first_scoped(
                                    &scope,
                                    "relay_probe_classification_started",
                                    Some("relay"),
                                    None,
                                    Some(format!(
                                        "peer={} generation={generation} relay_connection_id={relay_connection_id:?} postdecrypt_us={}",
                                        inbound.peer_id,
                                        decrypt_completed.elapsed().as_micros(),
                                    )),
                                );
                            }
                        }
                    }
                    let relay_probe = crate::relay_probe::parse_relay_probe_token(&inbound.packet);
                    if let (Some(token), Some(feed)) = (relay_probe, evidence.as_ref()) {
                        if let Some(timeline) = feed.timeline.as_ref() {
                            let scope = format!("peer:{}:{}", inbound.peer_id, token.generation);
                            timeline.emit_first_scoped(
                                &scope,
                                "relay_probe_classified",
                                Some("relay"),
                                Some(match token.kind {
                                    crate::relay_probe::RelayProbeKind::Request => "request",
                                    crate::relay_probe::RelayProbeKind::Ack => "ack",
                                }),
                                Some(format!(
                                    "peer={} generation={} relay_connection_id={relay_connection_id:?} postdecrypt_us={}",
                                    inbound.peer_id,
                                    token.generation,
                                    decrypt_completed.elapsed().as_micros(),
                                )),
                            );
                        }
                    }
                    let path_commit = crate::path_commit::parse_path_commit_token(&inbound.packet);
                    if session_evidence_eligible {
                        if let Some(peers) = peers.as_ref() {
                            // Forced-relay path-probe / path-ack: consumed here and
                            // never forwarded to TUN.  Only a probe that ACTUALLY
                            // arrived over the relay may confirm the relay path (or
                            // be answered over it); a probe that somehow decrypted
                            // on a non-relay ingress is ignored.
                            if let Some(token) = relay_probe {
                                if relay_endpoint.is_some() {
                                    let token_kind = token.kind;
                                    // ACK consumption changes relay path state,
                                    // so keep the emit guard through the
                                    // manager commit. A request only sends an
                                    // idempotent response; its handler must
                                    // acquire the emit lock itself, therefore
                                    // it uses a final check without retaining
                                    // the guard here.
                                    let session_guard =
                                        if token_kind == crate::relay_probe::RelayProbeKind::Ack {
                                            self.acquire_current_session_evidence_guard(
                                                &inbound.peer_id,
                                                inbound.session_instance,
                                            )
                                            .await
                                        } else {
                                            None
                                        };
                                    let session_current = if inbound.session_instance.is_none() {
                                        true
                                    } else if token_kind == crate::relay_probe::RelayProbeKind::Ack
                                    {
                                        session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    if session_current {
                                        let probe = RelayProbeIngress {
                                            peer_id: &inbound.peer_id,
                                            packet: &inbound.packet,
                                            relay_endpoint: relay_endpoint
                                                .as_deref()
                                                .unwrap_or("unknown"),
                                            relay_connection_id,
                                            wireguard_session_instance: inbound.session_instance,
                                            token,
                                        };
                                        if token_kind == crate::relay_probe::RelayProbeKind::Ack {
                                            self.handle_relay_probe_ack(peers, probe);
                                        } else {
                                            self.handle_relay_probe_packet(
                                                peers,
                                                evidence.as_ref().map(|feed| &feed.relay_transport),
                                                probe,
                                            )
                                            .await;
                                        }
                                    } else {
                                        peers.emit_timeline(
                                            "stale_session_evidence",
                                            Some("relay"),
                                            Some("session_replaced_or_removed"),
                                            Some(format!(
                                                "peer={} session_instance={:?} relay_probe={:?}",
                                                inbound.peer_id,
                                                inbound.session_instance,
                                                token_kind,
                                            )),
                                        );
                                    }
                                    drop(session_guard);
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        "ignored relay probe {} that arrived without relay ingress",
                                        if token.kind == crate::relay_probe::RelayProbeKind::Ack {
                                            "ack"
                                        } else {
                                            "request"
                                        }
                                    );
                                }
                            }
                            // Synthetic path-commit probe/ack: a business-shaped
                            // authenticated packet round-tripped over the confirmed
                            // relay.  A matching ack closes the relay-first
                            // business gate for one-directional traffic (P0-4);
                            // a request is answered idempotently, exactly like the
                            // relay path-probe.
                            if let Some(path_token) = path_commit {
                                if relay_endpoint.is_some() {
                                    let path_kind = path_token.kind;
                                    let path_session_guard =
                                        if path_kind == crate::path_commit::PathCommitKind::Ack {
                                            self.acquire_current_session_evidence_guard(
                                                &inbound.peer_id,
                                                inbound.session_instance,
                                            )
                                            .await
                                        } else {
                                            None
                                        };
                                    let path_session_current = if inbound.session_instance.is_none()
                                    {
                                        true
                                    } else if path_kind == crate::path_commit::PathCommitKind::Ack {
                                        path_session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    if path_session_current {
                                        let probe = PathCommitIngress {
                                            peer_id: &inbound.peer_id,
                                            packet: &inbound.packet,
                                            relay_endpoint: relay_endpoint
                                                .as_deref()
                                                .unwrap_or("unknown"),
                                            relay_connection_id,
                                            token: path_token,
                                        };
                                        if path_kind == crate::path_commit::PathCommitKind::Ack {
                                            self.handle_path_commit_ack(peers, probe);
                                        } else {
                                            self.handle_path_commit_packet(
                                                peers,
                                                evidence.as_ref().map(|feed| &feed.relay_transport),
                                                probe,
                                            )
                                            .await;
                                        }
                                    }
                                    drop(path_session_guard);
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        "ignored path-commit packet that arrived without relay ingress"
                                    );
                                }
                            }
                            let binding_guard = self
                                .acquire_current_session_evidence_guard(
                                    &inbound.peer_id,
                                    inbound.session_instance,
                                )
                                .await;
                            let binding_session_current =
                                inbound.session_instance.is_none() || binding_guard.is_some();
                            if binding_session_current {
                                let promoted_tokens =
                                    self.pending_promoted_responder_tokens(&inbound.peer_id);
                                for token in promoted_tokens {
                                    let generation = packet_network_generation
                                        .unwrap_or_else(|| peers.current_network_generation_sync());
                                    match peers.try_confirm_pending_probe_session_binding(
                                        &inbound.peer_id,
                                        &token,
                                    ) {
                                        PendingProbeBindingCommitOutcome::Committed
                                        | PendingProbeBindingCommitOutcome::AlreadyCurrent => {
                                            self.acknowledge_promoted_responder_token(
                                                &inbound.peer_id,
                                                &token,
                                            );
                                            peers.emit_timeline_first(
                                                &inbound.peer_id,
                                                generation,
                                                "responder_probe_binding_promoted",
                                                relay_endpoint.as_ref().map(|_| "relay"),
                                                None,
                                                Some(format!(
                                                    "peer={} generation={generation} session_instance={:?}",
                                                    inbound.peer_id, inbound.session_instance
                                                )),
                                            );
                                        }
                                        PendingProbeBindingCommitOutcome::ContendedConnections => {
                                            peers.emit_timeline_first(
                                                &inbound.peer_id,
                                                generation,
                                                "responder_probe_binding_connections_contended",
                                                relay_endpoint.as_ref().map(|_| "relay"),
                                                Some("fair_rwlock_writer_unavailable"),
                                                Some(format!(
                                                    "peer={} generation={generation} session_instance={:?} queued_writer=false retry=next_authenticated_frame",
                                                    inbound.peer_id, inbound.session_instance
                                                )),
                                            );
                                        }
                                        PendingProbeBindingCommitOutcome::Missing => {}
                                    }
                                }
                            } else {
                                peers.emit_timeline(
                                    "stale_session_evidence",
                                    Some("relay"),
                                    Some("session_replaced_or_removed"),
                                    Some(format!(
                                        "peer={} session_instance={:?} responder_binding=stale",
                                        inbound.peer_id, inbound.session_instance,
                                    )),
                                );
                            }
                            drop(binding_guard);
                            if let Some(control) = dplpmtud {
                                if owns_direct_packet {
                                    let control_kind = control.kind;
                                    let peer_session_generation =
                                        peers.peer_session_generation_sync(&inbound.peer_id);
                                    let session_guard = if control_kind
                                        == crate::dplpmtud::DplpmtudControlKind::Ack
                                    {
                                        self.acquire_current_session_evidence_guard(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    } else {
                                        None
                                    };
                                    let session_current = if inbound.session_instance.is_none() {
                                        true
                                    } else if control_kind
                                        == crate::dplpmtud::DplpmtudControlKind::Ack
                                    {
                                        session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    // The exact authenticated session has been
                                    // snapshotted. DPLPMTUD owns its own
                                    // lifecycle/expectation transaction, so do
                                    // not carry the emit/session evidence fence
                                    // across its async locks and socket work.
                                    drop(session_guard);
                                    if let (true, Some(peer_session_generation), Some(udp)) =
                                        (session_current, peer_session_generation, udp.as_ref())
                                    {
                                        self.handle_dplpmtud_packet(
                                            peers,
                                            udp,
                                            &inbound.peer_id,
                                            &inbound.packet,
                                            packet.wire_bytes.len(),
                                            source,
                                            local_endpoint,
                                            socket_index,
                                            direct_socket.clone(),
                                            peer_session_generation,
                                            control,
                                        )
                                        .await;
                                    } else {
                                        peers.emit_timeline(
                                            "dplpmtud_stale_ack_rejected",
                                            Some("direct"),
                                            Some("session_replaced_or_removed"),
                                            Some(format!(
                                                "peer={} session_instance={:?} control_kind={:?}",
                                                inbound.peer_id,
                                                inbound.session_instance,
                                                control_kind,
                                            )),
                                        );
                                    }
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        packet_owner = ?udp_transport_owner,
                                        "ignored DPLPMTUD packet from retired or unpublished UDP transport"
                                    );
                                }
                            }
                            if let Some(token) = direct_validation {
                                // Daemon-internal direct-validation packets are
                                // consumed here and never forwarded to TUN: the
                                // request/ACK protocol proves the direct UDP path
                                // with the WireGuard session alone, without an OS
                                // ICMP echo reply or user traffic.
                                if owns_direct_packet {
                                    let token_kind = token.kind;
                                    // Snapshot the peer lifecycle before the
                                    // transport-session check awaits.  A
                                    // same-ID remove/re-add after this point
                                    // must not let the old authenticated
                                    // request enqueue work for the replacement
                                    // peer incarnation.
                                    let peer_session_generation =
                                        peers.peer_session_generation_sync(&inbound.peer_id);
                                    let session_guard = if token_kind == DirectValidationKind::Ack {
                                        self.acquire_current_session_evidence_guard(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    } else {
                                        None
                                    };
                                    let session_current = if inbound.session_instance.is_none() {
                                        true
                                    } else if token_kind == DirectValidationKind::Ack {
                                        session_guard.is_some()
                                    } else {
                                        self.session_instance_is_current(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await
                                    };
                                    // Direct validation revalidates the exact
                                    // peer lifecycle and owned request token.
                                    // Release the inbound evidence fence before
                                    // any of its async manager/UDP transactions.
                                    drop(session_guard);
                                    if let (true, Some(peer_session_generation)) =
                                        (session_current, peer_session_generation)
                                    {
                                        if direct_validation_dplpmtud_capability {
                                            if let Some(udp) = udp.as_ref() {
                                                udp.mark_peer_dplpmtud_supported(
                                                    &inbound.peer_id,
                                                    peer_session_generation,
                                                );
                                            }
                                        }
                                        self.handle_direct_validation_packet(
                                            peers,
                                            udp.as_ref(),
                                            &inbound.peer_id,
                                            &inbound.packet,
                                            source,
                                            local_endpoint,
                                            socket_index,
                                            direct_socket.clone(),
                                            peer_session_generation,
                                            token,
                                        )
                                        .await;
                                        if direct_validation_dplpmtud_capability {
                                            if let Some(udp) = udp.as_ref() {
                                                udp.reconcile_dplpmtud_paths().await;
                                            }
                                        }
                                    } else {
                                        peers.emit_timeline(
                                            "stale_session_evidence",
                                            Some("direct"),
                                            Some("session_replaced_or_removed"),
                                            Some(format!(
                                                "peer={} session_instance={:?} direct_validation={:?}",
                                                inbound.peer_id,
                                                inbound.session_instance,
                                                token_kind,
                                            )),
                                        );
                                    }
                                } else {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        packet_owner = ?udp_transport_owner,
                                        "ignored direct-validation packet from retired or unpublished UDP transport"
                                    );
                                }
                            } else if let Some(source) = source {
                                if internal_rekey_confirmation {
                                    debug!(
                                        "Consumed internal WireGuard rekey confirmation from peer {} as endpoint evidence only; encrypted Direct validation is still required",
                                        inbound.peer_id
                                    );
                                }
                                if dplpmtud.is_none()
                                    && should_request_direct_validation_after_decrypt(
                                        owns_direct_packet,
                                        Some(source),
                                        direct_validation,
                                    )
                                {
                                    let session_guard = self
                                        .acquire_current_session_evidence_guard(
                                            &inbound.peer_id,
                                            inbound.session_instance,
                                        )
                                        .await;
                                    let session_current = inbound.session_instance.is_none()
                                        || session_guard.is_some();
                                    // Endpoint learning is not a Relay/current-
                                    // session evidence commit and has its own
                                    // peer/UDP publication fences. Never await
                                    // those while retaining the emit guard.
                                    drop(session_guard);
                                    if !session_current {
                                        peers.emit_timeline(
                                            "stale_session_evidence",
                                            Some("direct"),
                                            Some("session_replaced_or_removed"),
                                            Some(format!(
                                                "peer={} session_instance={:?} direct_ingress=stale",
                                                inbound.peer_id, inbound.session_instance,
                                            )),
                                        );
                                    } else {
                                        peers
                                            .learn_authenticated_endpoint(&inbound.peer_id, source)
                                            .await;
                                        // A decrypted UDP payload (including an
                                        // internal rekey confirmation) is
                                        // authenticated endpoint evidence, not
                                        // Direct proof. Feed it into the same
                                        // owned request/ACK worker as
                                        // peer-reflexive evidence; do not adopt
                                        // socket affinity or promote here.
                                        if let Some(udp) = udp.as_ref() {
                                            let generation = packet_network_generation
                                                .unwrap_or_else(|| {
                                                    peers.current_network_generation_sync()
                                                });
                                            let evidence_kind = if internal_rekey_confirmation {
                                                "rekey confirmation"
                                            } else {
                                                "decrypted direct UDP payload"
                                            };
                                            peers
                                                .record_direct_event_for_generation_with_socket(
                                                    &inbound.peer_id,
                                                    generation,
                                                    "direct_validation_ingress_requested",
                                                    Some(source),
                                                    socket_index,
                                                    None,
                                                    None,
                                                    format!(
                                                        "{evidence_kind} requested owned encrypted validation"
                                                    ),
                                                )
                                                .await;
                                            if let Some(socket_index) = socket_index {
                                                // Decryption is sufficient to
                                                // remember the receiving socket
                                                // for the next owned validation
                                                // request, but not to promote the
                                                // path.
                                                udp.remember_peer_socket(
                                                    &inbound.peer_id,
                                                    socket_index,
                                                    crate::udp::SocketEvidence::Fresh,
                                                )
                                                .await;
                                            }
                                            udp.enqueue_direct_validation_observation(
                                                crate::udp::PeerReflexiveObservation {
                                                    peer_id: inbound.peer_id.clone(),
                                                    observed_endpoint: source,
                                                },
                                            );
                                        }
                                        debug!(
                                            "Authenticated direct UDP endpoint {source} for peer {}; awaiting owned encrypted validation",
                                            inbound.peer_id
                                        );
                                    }
                                } else if !owns_direct_packet {
                                    debug!(
                                        peer_id = %inbound.peer_id,
                                        packet_owner = ?udp_transport_owner,
                                        "forwarding decrypted data from retired or unpublished UDP transport without Direct evidence"
                                    );
                                }
                            } else if let Some(relay_endpoint) = relay_endpoint.as_deref() {
                                let session_guard = self
                                    .acquire_current_session_evidence_guard(
                                        &inbound.peer_id,
                                        inbound.session_instance,
                                    )
                                    .await;
                                let session_current =
                                    inbound.session_instance.is_none() || session_guard.is_some();
                                if session_current {
                                    // Every authenticated relay packet is a
                                    // liveness observation.  RTT is committed
                                    // only by the matching relay-probe ACK,
                                    // whose process-local Instant is bound to
                                    // the actual relay handoff.  The legacy
                                    // wall-clock validation payload remains
                                    // recognizable for wire compatibility but
                                    // is never interpreted as a timing sample.
                                    peers.try_record_relay_observation(
                                        &inbound.peer_id,
                                        relay_endpoint,
                                    );
                                    debug!(
                                    "Observed decrypted relay ingress through {relay_endpoint} for peer {}; relay confirmation still requires a matching encrypted ACK",
                                    inbound.peer_id
                                );
                                } else {
                                    peers.emit_timeline(
                                        "stale_session_evidence",
                                        Some("relay"),
                                        Some("session_replaced_or_removed"),
                                        Some(format!(
                                            "peer={} session_instance={:?} relay_observation=stale",
                                            inbound.peer_id, inbound.session_instance,
                                        )),
                                    );
                                }
                                drop(session_guard);
                            }
                        }
                    }
                    if internal_rekey_confirmation
                        || direct_validation.is_some()
                        || dplpmtud.is_some()
                        || relay_probe.is_some()
                        || path_commit.is_some()
                    {
                        continue;
                    }
                    // A normal decrypted packet is the production ingress
                    // proof. The mock overlay validator adds a stronger
                    // nonce/echo check, but production must not depend on
                    // that harness to ever emit first_usable. The ingress is
                    // taken from this packet's envelope and never inferred
                    // from the current selected path.
                    if session_evidence_eligible && is_real_overlay_business_packet(&inbound.packet)
                    {
                        if let Some(feed) = evidence.as_ref() {
                            let ingress = if let Some(relay_endpoint) = relay_endpoint.as_ref() {
                                Some((
                                    crate::peer::NetworkPath::Relay,
                                    format!("relay:{relay_endpoint}"),
                                    Some(relay_endpoint.as_str()),
                                ))
                            } else if owns_direct_packet && source.is_some() {
                                Some((crate::peer::NetworkPath::Direct, "direct".to_string(), None))
                            } else {
                                None
                            };
                            if let (Some(peer_manager), Some((path, ingress_label, relay_id))) =
                                (peers.as_ref(), ingress)
                            {
                                // The packet was decrypted before this point,
                                // but path evidence is a separate commit. Hold
                                // the same per-peer lifecycle fence through
                                // both relay-business and first-usable writes
                                // so a rekey cannot turn an old-session packet
                                // into evidence for the new session.
                                let session_guard_outcome = self
                                    .acquire_current_session_evidence_guard_outcome(
                                        &inbound.peer_id,
                                        inbound.session_instance,
                                    )
                                    .await;
                                let session_guard_contended = matches!(
                                    &session_guard_outcome,
                                    CurrentSessionEvidenceGuardOutcome::Contended
                                );
                                let session_guard = match session_guard_outcome {
                                    CurrentSessionEvidenceGuardOutcome::Current(guard) => {
                                        Some(guard)
                                    }
                                    CurrentSessionEvidenceGuardOutcome::Contended
                                    | CurrentSessionEvidenceGuardOutcome::Stale => None,
                                };
                                let session_current =
                                    inbound.session_instance.is_none() || session_guard.is_some();
                                if session_current {
                                    let generation =
                                        packet_network_generation.unwrap_or_else(|| {
                                            peer_manager.current_network_generation_sync()
                                        });
                                    let first_usable_recorded = if path
                                        == crate::peer::NetworkPath::Relay
                                    {
                                        let outcome = peer_manager
                                                .peer_session_generation_sync(&inbound.peer_id)
                                                .map_or(
                                                    crate::peer::RelayBusinessEvidenceCommitOutcome::RejectedLifecycle,
                                                    |peer_session_generation| {
                                                        peer_manager.try_commit_relay_business_evidence(
                                                            &inbound.peer_id,
                                                            generation,
                                                            peer_session_generation,
                                                            inbound.session_instance.unwrap_or(0),
                                                            relay_id.unwrap_or("unknown"),
                                                            relay_connection_id,
                                                            decrypt_completed,
                                                        )
                                                    },
                                                );
                                        matches!(
                                                outcome,
                                                crate::peer::RelayBusinessEvidenceCommitOutcome::Committed
                                                    | crate::peer::RelayBusinessEvidenceCommitOutcome::AlreadyCurrent
                                            )
                                    } else {
                                        peer_manager
                                            .peer_session_generation_sync(&inbound.peer_id)
                                            .is_some_and(|peer_session_generation| {
                                                peer_manager
                                                    .try_record_verified_direct_first_usable_for_lifecycle(
                                                        &inbound.peer_id,
                                                        generation,
                                                        peer_session_generation,
                                                    )
                                            })
                                    };
                                    // This is an ingress observation, not the
                                    // same milestone as first_usable_path.
                                    // Keep the first ingress event for backwards
                                    // compatibility, and also retain one event
                                    // for each meaningful path/transport/result
                                    // identity.  If a too-early Direct packet
                                    // is rejected and a later Relay packet is
                                    // accepted, the second event must remain
                                    // visible; a single first-event key would
                                    // otherwise hide the actual relay proof.
                                    if let Some(timeline) = feed.timeline.as_ref() {
                                        let scope =
                                            format!("peer:{}:{generation}", inbound.peer_id);
                                        let path_label = match path {
                                            crate::peer::NetworkPath::Relay => "relay",
                                            crate::peer::NetworkPath::Direct => "direct",
                                        };
                                        let first_usable_result = if first_usable_recorded {
                                            "first_usable_recorded"
                                        } else {
                                            "first_usable_not_recorded"
                                        };
                                        let relay_transport_key = relay_connection_id.map_or_else(
                                            || "none".to_string(),
                                            |id| id.to_string(),
                                        );
                                        let packet_identity = Ipv4Packet::new(&inbound.packet)
                                            .map(|packet| {
                                                format!(
                                                    "protocol={} src={} dst={}",
                                                    packet.protocol(),
                                                    packet.src_addr(),
                                                    packet.dst_addr(),
                                                )
                                            })
                                            .unwrap_or_else(|_| {
                                                "protocol=unknown src=unknown dst=unknown"
                                                    .to_string()
                                            });
                                        let detail = format!(
                                            "peer={} generation={generation} path_id={} relay_id={} relay_connection_id={} counter={} bytes={} {} overlay_fp={:016x} usable_recorded={first_usable_recorded}",
                                            inbound.peer_id,
                                            ingress_label,
                                            relay_id.unwrap_or("none"),
                                            relay_transport_key,
                                            wire_counter(&packet.wire_bytes).map_or_else(
                                                || "none".to_string(),
                                                |counter| counter.to_string(),
                                            ),
                                            inbound.packet.len(),
                                            packet_identity,
                                            wire_fingerprint(&inbound.packet),
                                        );
                                        let business_attribution_identity = if path
                                            == crate::peer::NetworkPath::Direct
                                            && owns_direct_packet
                                        {
                                            udp.as_ref().and_then(|udp| {
                                                    udp.hard_hard_business_attribution_identity_for_ingress(
                                                        &inbound.peer_id,
                                                        source,
                                                        local_endpoint,
                                                        socket_index,
                                                        udp_transport_owner,
                                                        packet_network_generation,
                                                    )
                                                })
                                        } else {
                                            None
                                        };
                                        timeline.emit_first_scoped_with_business_attribution_identity(
                                            &scope,
                                            &format!(
                                                "path={path_label} relay_connection_id={relay_transport_key} business_identity={business_attribution_identity:?} usable={first_usable_recorded}"
                                            ),
                                            "business_ingress_observed",
                                            Some(path_label),
                                            Some(first_usable_result),
                                            Some(detail.clone()),
                                            business_attribution_identity,
                                        );
                                        timeline.emit_first_scoped(
                                            &scope,
                                            "first_real_business_ingress",
                                            Some(path_label),
                                            (!first_usable_recorded)
                                                .then_some("first_usable_gate_rejected"),
                                            Some(detail),
                                        );
                                    }
                                } else {
                                    let retained = session_guard_contended
                                        && path == crate::peer::NetworkPath::Relay
                                        && peer_manager
                                            .peer_session_generation_sync(&inbound.peer_id)
                                            .is_some_and(|peer_session_generation| {
                                                let generation = packet_network_generation
                                                    .unwrap_or_else(|| {
                                                        peer_manager
                                                            .current_network_generation_sync()
                                                    });
                                                peer_manager
                                                    .retain_relay_business_evidence_for_retry(
                                                        &inbound.peer_id,
                                                        generation,
                                                        peer_session_generation,
                                                        inbound
                                                            .session_instance
                                                            .unwrap_or_default(),
                                                        relay_id.unwrap_or("unknown"),
                                                        relay_connection_id,
                                                        decrypt_completed,
                                                    )
                                            });
                                    if let Some(timeline) = feed.timeline.as_ref() {
                                        timeline.emit(
                                            if session_guard_contended {
                                                "business_ingress_evidence_deferred"
                                            } else {
                                                "stale_session_evidence"
                                            },
                                            Some(match path {
                                                crate::peer::NetworkPath::Relay => "relay",
                                                crate::peer::NetworkPath::Direct => "direct",
                                            }),
                                            Some(if session_guard_contended {
                                                "session_or_emit_contended"
                                            } else {
                                                "session_replaced_or_removed"
                                            }),
                                            Some(format!(
                                                "peer={} session_instance={:?} business_ingress={} evidence_retained={retained} queued_writer=false",
                                                inbound.peer_id,
                                                inbound.session_instance,
                                                if session_guard_contended {
                                                    "deferred"
                                                } else {
                                                    "stale"
                                                },
                                            )),
                                        );
                                    }
                                }
                                drop(session_guard);
                            }
                        }
                    }
                    // Forward a decrypted overlay candidate to the independent
                    // overlay validation harness WITH its real ingress (derived
                    // from this envelope, never from the active path).
                    if session_evidence_eligible {
                        if let Some(feed) = evidence.as_ref() {
                            if is_overlay_payload_candidate(&inbound.packet) {
                                let ingress = if let Some(relay_endpoint) = relay_endpoint.as_ref()
                                {
                                    Some(OverlayIngress::Relay(relay_endpoint.clone()))
                                } else if owns_direct_packet && source.is_some() {
                                    Some(OverlayIngress::Direct)
                                } else {
                                    // No attributable ingress (relay nor owned
                                    // direct): do not guess.
                                    None
                                };
                                if let Some(ingress) = ingress {
                                    if let Some(tx) = &feed.overlay_ingress_tx {
                                        let connection_generation = packet_network_generation
                                            .or_else(|| {
                                                peers.as_ref().map(|manager| {
                                                    manager.current_network_generation_sync()
                                                })
                                            })
                                            .unwrap_or_default();
                                        let _ = tx
                                            .send(OverlayIngressEvent {
                                                peer_id: inbound.peer_id.clone(),
                                                packet: inbound.packet.clone(),
                                                ingress,
                                                connection_generation,
                                            })
                                            .await;
                                    }
                                }
                            }
                        }
                    }
                    let validation_completed = Instant::now();
                    // Decryption proves the packet belongs to a peer. This
                    // separate stage covers only the post-decrypt generation,
                    // session, path-evidence, and overlay-validation work
                    // before the packet enters the TUN-facing queue.
                    profiler.record(
                        sampled,
                        "rx_postdecrypt_evidence_us",
                        validation_completed.duration_since(decrypt_completed),
                    );
                    profiler.record(
                        sampled,
                        "rx_generation_session_validation_us",
                        validation_completed.duration_since(decrypt_completed),
                    );
                    if let Some(trace) = inbound.trace.as_mut() {
                        trace.inbound_queue_send_started = Some(Instant::now());
                        profiler.record_value(
                            trace.sampled,
                            "rx_dataplane_inbound_queue_depth_before_send",
                            inbound_tx
                                .max_capacity()
                                .saturating_sub(inbound_tx.capacity())
                                as u64,
                        );
                    }
                    if let (Some(relay_endpoint), Some(feed)) =
                        (relay_endpoint.as_deref(), evidence.as_ref())
                    {
                        if let Some(timeline) = feed.timeline.as_ref() {
                            let generation = packet_network_generation.unwrap_or_default();
                            let scope = format!("peer:{}:{generation}", inbound.peer_id);
                            timeline.emit_first_scoped(
                                &scope,
                                "relay_inbound_queue_handoff",
                                Some("relay"),
                                None,
                                Some(format!(
                                    "peer={} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} session_instance={:?} postdecrypt_us={} inbound_queue_depth={}",
                                    inbound.peer_id,
                                    inbound.session_instance,
                                    validation_completed.duration_since(decrypt_completed).as_micros(),
                                    inbound_tx
                                        .max_capacity()
                                        .saturating_sub(inbound_tx.capacity()),
                                )),
                            );
                        }
                    }
                    inbound_tx.send(inbound).await.map_err(|_| {
                        DaemonError::Network("inbound packet channel closed".to_string())
                    })?;
                }
                Ok(None) => {
                    debug!("Inbound encrypted packet has no matching WireGuard session");
                }
                Err(err) => {
                    if err.is_replay() {
                        // The per-peer hedge-duplicate counter was already
                        // attributed and logged rate-limited inside
                        // `decrypt_inbound`; per-datagram WARNs would only
                        // recreate the storm this classification removes.
                        debug!("Dropping inbound encrypted packet from {:?}: {err}", source);
                    } else {
                        warn!("Dropping inbound encrypted packet from {:?}: {err}", source);
                    }
                }
            }
        }

        Ok(())
    }
}
