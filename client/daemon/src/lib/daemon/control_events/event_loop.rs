use futures_util::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;

/// The serial control receiver owns fresh-prediction admission and short
/// state commits.  Slow STUN/HTTP work runs here instead of directly in the
/// receiver, with every producer supplying a per-peer reservation and this
/// global cap providing a hard upper bound during a control-plane burst.
type ControlEventWork<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

const MAX_CONTROL_EVENT_SLOW_WORK: usize = 64;

fn control_event_kind(event: &control::ControlEvent) -> &'static str {
    match event {
        control::ControlEvent::DeliveredSignal { event, .. } => control_event_kind(event),
        control::ControlEvent::Registered { .. } => "registered",
        control::ControlEvent::PeerJoined(_) => "peer_joined",
        control::ControlEvent::PeerUpdated(_) => "peer_updated",
        control::ControlEvent::PeerLeft(_) => "peer_left",
        control::ControlEvent::PeerOffer { .. } => "peer_offer",
        control::ControlEvent::PeerAnswer { .. } => "peer_answer",
        control::ControlEvent::PeerReflexive { .. } => "peer_reflexive",
        control::ControlEvent::PeerRejected { .. } => "peer_rejected",
        control::ControlEvent::TunnelCreated { .. } => "tunnel_created",
        control::ControlEvent::ServerError { .. } => "server_error",
        control::ControlEvent::Disconnected => "disconnected",
        control::ControlEvent::ReauthRequired { .. } => "reauth_required",
        control::ControlEvent::ControlRecovered { .. } => "control_recovered",
        control::ControlEvent::ControlHealthy => "control_healthy",
    }
}

impl Daemon {
    async fn run_control_event_loop(
        &mut self,
        relay_started: &mut bool,
        network_inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) {
        // Process control events until shutdown is requested.
        // Move the receiver out first so the event loop can hold immutable
        // borrows of the daemon in its cooperative slow-work set.  All daemon
        // state is already interior-synchronized; the receiver is the sole
        // field that needs mutable access.
        let (_replacement_tx, replacement_rx) = mpsc::unbounded_channel();
        let mut control_rx = std::mem::replace(&mut self.control_rx, replacement_rx);
        let daemon: &Daemon = &*self;
        let mut slow_work: FuturesUnordered<ControlEventWork<'_>> = FuturesUnordered::new();
        // Retries have a distinct bounded lane. A full general slow-work lane
        // must never turn an already-prepared initiation into a lost first
        // usable attempt.
        let mut retry_work: FuturesUnordered<ControlEventWork<'_>> = FuturesUnordered::new();
        let mut deferred_initiators: InitiatorQueue<control::PeerInfo> = InitiatorQueue::new();
        // Keep responder answers out of the general slow-work budget. A
        // blocked candidate refresh or peer-reflexive HTTP task must not
        // prevent a received WireGuard initiation from producing an answer.
        let mut responder_work: FuturesUnordered<ControlEventWork<'_>> = FuturesUnordered::new();
        // Candidate application has independent per-peer owners and futures.
        // Its durable receipt commits at bounded local enqueue, so neither a
        // connection writer nor slow UDP work can head-of-line block the next
        // signal from the same sender.
        let mut candidate_work: FuturesUnordered<ControlEventWork<'_>> = FuturesUnordered::new();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut task_shutdown_rx = self.task_manager.shutdown_rx();
        let mut handshake_retry_kick_rx = self.handshake_retry_kick_tx.subscribe();
        let mut handshake_retry_tick = tokio::time::interval(Duration::from_millis(25));
        handshake_retry_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("Shutdown signal received in main event loop");
                            break;
                        }
                    }
                    _ = task_shutdown_rx.changed() => {
                        if *task_shutdown_rx.borrow() {
                            warn!("Task manager requested daemon shutdown");
                            break;
                        }
                    }
                    _ = slow_work.next(), if !slow_work.is_empty() => {
                        // Completion frees a bounded slot. Admit the oldest still
                        // live deferred peer immediately instead of waiting for a
                        // later control poll.
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                    _ = retry_work.next(), if !retry_work.is_empty() => {
                        // A retry completion frees the exact prepared
                        // initiation owner. Revisit both the retry ledger and
                        // any deferred roster edge without waiting for an
                        // unrelated control signal.
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                    _ = responder_work.next(), if !responder_work.is_empty() => {
                        // Responder workers own their per-peer pending state and
                        // release it on every terminal/cancellation path. Their
                        // completion can also free a pending initiator's
                        // reservation, so retry deferred roster work here even
                        // when the general slow-work lane is otherwise idle.
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                    _ = candidate_work.next(), if !candidate_work.is_empty() => {
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                    changed = handshake_retry_kick_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        handshake_retry_kick_rx.borrow_and_update();
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                    _ = handshake_retry_tick.tick() => {
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                    event = control_rx.recv() => {
                        let Some(event) = event else {
                            warn!("Control event channel closed");
                            break;
                        };
                        let (event, mut signal_delivery_receipt, signal_context) = match event {
                            ControlEvent::DeliveredSignal {
                                event,
                                receipt,
                                signal_id,
                                signal_seq,
                                signal_type,
                            } => (
                                *event,
                                Some(receipt),
                                Some((
                                    control::bounded_signal_log_value(&signal_id),
                                    signal_seq,
                                    control::bounded_signal_log_value(&signal_type),
                                )),
                            ),
                            event => (event, None, None),
                        };
                        let event_kind = control_event_kind(&event);
                        info!(
                            event = "control_event_phase",
                            phase = "dequeued",
                            kind = event_kind,
                            "control_event_phase phase=dequeued kind={}",
                            event_kind
                        );
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=dequeued id={} type={} seq={:?} network_generation={}",
                                signal_id,
                                signal_type,
                                signal_seq,
                                self.peers.current_network_generation_sync()
                            );
                        }
                        if let Some(receipt) = signal_delivery_receipt.as_ref() {
                            receipt.record_phase("dequeued", "control_event_loop");
                        }
                        info!(
                            event = "control_event_phase",
                            phase = "dispatch_started",
                            kind = event_kind,
                            "control_event_phase phase=dispatch_started kind={}",
                            event_kind
                        );
                        match event {
                    ControlEvent::Registered {
                        node_id,
                        virtual_ip,
                        cidr,
                        relay_servers,
                        relay_catalog,
                    } => {
                        if crate::rooms::registration_requires_room_restart(
                            &self.config,
                            node_id.as_deref(),
                            &virtual_ip,
                            cidr.as_deref(),
                        ) {
                            self.control.room_authorization().await.invalidate();
                            self.timeline.emit("room_assignment_changed", None, Some("room_restart_required"),
                                Some("Room address or identity changed; reconnect this room to rebuild its TUN and routes".into()));
                            warn!("Room assignment changed; stopping this room daemon instead of retaining the old TUN address");
                            self.shutdown_tx.send_replace(true);
                            break;
                        }
                        self.health.mark_control_success().await;
                        if !*relay_started {
                            let relay_node_id =
                                node_id.unwrap_or_else(|| self.config.node.node_id.clone());
                            let relay_servers = if relay_servers.is_empty() {
                                self.config.relay.servers.clone()
                            } else {
                                relay_servers
                            };
                            let relay_candidates =
                                relay_candidates_from_sources(&relay_catalog, &relay_servers);
                            if relay_candidates.is_empty() {
                                self.peers.configure_relay_first(false).await;
                                debug!("No relay servers advertised by control plane");
                                if let Some(receipt) = signal_delivery_receipt.take() {
                                    receipt.complete(control::SignalApplyOutcome::Applied);
                                }
                                continue;
                            }
                            self.peers.configure_relay_first(true).await;
                            *relay_started = true;
                            let allow_insecure_plaintext = effective_relay_allow_insecure_plaintext(
                                &self.config.control.server_url,
                                &relay_catalog,
                                &relay_servers,
                                self.config.relay.allow_insecure_plaintext,
                            );
                            if allow_insecure_plaintext
                                && !self.config.relay.allow_insecure_plaintext
                            {
                                info!(
                                    "Allowing plaintext relay because HTTP control plane supplied legacy relay candidates"
                                );
                            }
            spawn_relay_inbound(RelayInboundSpawnContext {
                task_manager: self.task_manager.clone(),
                relay_candidates,
                preferred_regions: self.config.relay.preferred_regions.clone(),
                selection_timeout: Duration::from_millis(
            self.config.relay.selection_timeout_ms.max(1),
                ),
                node_id: relay_node_id,
                peers: self.peers.clone(),
                relay_transport: self.relay_transport.clone(),
                relay_selection: self.relay_selection.clone(),
                relay_available_tx: self.relay_available_tx.clone(),
                timeline: self.timeline.clone(),
                inbound_tx: network_inbound_tx.clone(),
                control: self.control.clone(),
                android_network_change_rx: self.android_network_change_relay_rx.clone(),
                allow_insecure_plaintext,
                ca_cert_path: self.config.relay.ca_cert_path.clone(),
            })
            .await;
                        }
                    }

                    ControlEvent::PeerJoined(peer_info) => {
                        let peer_join_started = std::time::Instant::now();
                        info!(
                            "Peer joined: {} ({})",
                            peer_info.node_id, peer_info.virtual_ip
                        );
                        self.timeline.emit_first(
                            "peer_roster_ready",
                            None,
                            None,
                            Some(format!(
                                "peer={} virtual_ip={} online={}",
                                peer_info.node_id, peer_info.virtual_ip, peer_info.online
                            )),
                        );
                        self.peers.add_peer(&peer_info).await;
                        let peer_state_elapsed = peer_join_started.elapsed();
                        if peer_state_elapsed >= Duration::from_millis(250) {
                            warn!(
                                "PeerJoined state install was slow: peer={} elapsed_ms={}",
                                peer_info.node_id,
                                peer_state_elapsed.as_millis()
                            );
                        } else {
                            debug!(
                                "PeerJoined state installed: peer={} elapsed_ms={}",
                                peer_info.node_id,
                                peer_state_elapsed.as_millis()
                            );
                        }

                        if peer_info.online {
                            // `peer_roster_ready` is a process-level control-plane
                            // milestone and is intentionally not a usable-path
                            // clock.  Start the per-peer data-plane clock only
                            // after the peer has been installed locally, and bind
                            // it to the current network generation.  This keeps
                            // relay-first measurements from charging relay setup
                            // for time spent waiting for a later roster poll.
                            let session_generation = self.peers.current_network_generation().await;
                            let session_scope = format!(
                                "peer:{}:{session_generation}",
                                peer_info.node_id
                            );
                            self.timeline.emit_first_scoped(
                                &session_scope,
                                "peer_session_started",
                                None,
                                None,
                                Some(format!(
                                    "peer={} generation={} virtual_ip={} online=true",
                                    peer_info.node_id, session_generation, peer_info.virtual_ip
                                )),
                            );
                            let should_start_initiator =
                                self.should_start_initiator_handshake(&peer_info);
                            if should_start_initiator
                                && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                            {
                                let queued = enqueue_deferred_initiator_handshake(
                                    &mut deferred_initiators,
                                    peer_info.clone(),
                                );
                                let reason_code = if queued {
                                    "control_slow_work_full_queued"
                                } else {
                                    "control_slow_work_deferred_queue_full"
                                };
                                warn!(
                                    "Deferring peer-join handshake for {}: reason_code={} slow_work={} deferred_queue={}",
                                    peer_info.node_id,
                                    reason_code,
                                    slow_work.len(),
                                    deferred_initiators.len(),
                                );
                                self.peers
                                    .record_direct_event(
                                        &peer_info.node_id,
                                        "initiator_handshake_deferred",
                                        None,
                                        None,
                                        None,
                                        format!(
                                            "reason_code={reason_code} slow_work={} deferred_queue={}",
                                            slow_work.len(),
                                            deferred_initiators.len()
                                        ),
                                    )
                                    .await;
                                self.timeline.emit(
                                    "initiator_handshake_deferred",
                                    None,
                                    Some(reason_code),
                                    Some(format!(
                                        "peer={} slow_work={} deferred_queue={}",
                                        peer_info.node_id,
                                        slow_work.len(),
                                        deferred_initiators.len()
                                    )),
                                );
                            } else if should_start_initiator {
                                if let Some(reservation) = self
                                    .reserve_event_initiator_handshake(&peer_info.node_id)
                                    .into_reservation()
                                {
                                    debug!(
                                        "PeerJoined handshake reserved: peer={} elapsed_ms={}",
                                        peer_info.node_id,
                                        peer_join_started.elapsed().as_millis()
                                    );
                                    let peer_info = peer_info.clone();
                                    slow_work.push(Box::pin(async move {
                                        daemon
                                            .run_event_initiator_handshake(peer_info, reservation)
                                            .await;
                                    }));
                                } else {
                                    // Do not lose the roster edge merely because an
                                    // older initiator is still preparing or waiting
                                    // for its answer. The newest peer snapshot will
                                    // be retried after a slow-work slot is released.
                                    let queued = enqueue_deferred_initiator_handshake(
                                        &mut deferred_initiators,
                                        peer_info.clone(),
                                    );
                                    let reason_code = if queued {
                                        "initiator_reservation_busy_queued"
                                    } else {
                                        "initiator_reservation_busy_queue_full"
                                    };
                                    self.timeline.emit(
                                        "initiator_handshake_deferred",
                                        None,
                                        Some(reason_code),
                                        Some(format!("peer={}", peer_info.node_id)),
                                    );
                                }
                            } else {
                                schedule_candidate_republication(
                                    daemon,
                                    &mut responder_work,
                                    peer_info.node_id.clone(),
                                    "responder peer join",
                                );
                            }

                            if self.dns.is_enabled() {
                                self.dns
                                    .register(
                                        &peer_info.node_id,
                                        &peer_info.virtual_ip,
                                        Some(&peer_info.node_id),
                                    )
                                    .await;
                            }
                            debug!(
                                "PeerJoined event complete: peer={} elapsed_ms={}",
                                peer_info.node_id,
                                peer_join_started.elapsed().as_millis()
                            );
                        } else {
                            debug!(
                                "Peer {} is currently offline; keeping it in diagnostics without starting traversal",
                                peer_info.node_id
                            );
                        }
                    }

                    ControlEvent::PeerUpdated(peer_info) => {
                        // Public-key/offline publication and old-session removal
                        // are fenced by PeerSessionGeneration and exact pending
                        // ownership.  This branch intentionally does not own the
                        // handshake arbiter across connection/session/UDP actor
                        // awaits; old work is cancelled synchronously in the
                        // pending store before it can publish into the new life.
                        let previous_peer_session_generation = self
                            .peers
                            .peer_session_generation_sync(&peer_info.node_id);
                        info!(
                            event = "control_event_phase",
                            kind = "peer_updated",
                            phase = "waiting_for_resource",
                            resource = "peer_manager_add_peer",
                            "control_event_phase kind=peer_updated phase=waiting_for_resource resource=peer_manager_add_peer"
                        );
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=waiting_for_resource id={} type={} seq={:?} resource=peer_manager_add_peer",
                                signal_id, signal_type, signal_seq
                            );
                        }
                        let update = self
                            .peers
                            .add_peer_with_signal_context(
                                &peer_info,
                                signal_context.as_ref().map(|(signal_id, sequence, signal_type)| {
                                    (signal_id.as_str(), *sequence, signal_type.as_str())
                                }),
                            )
                            .await;
                        info!(
                            event = "control_event_phase",
                            kind = "peer_updated",
                            phase = "state_committed",
                            resource = "peer_manager_add_peer",
                            "control_event_phase kind=peer_updated phase=state_committed resource=peer_manager_add_peer"
                        );
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=state_committed id={} type={} seq={:?} commit=peer_updated peer_session_generation={:?}",
                                signal_id,
                                signal_type,
                                signal_seq,
                                self.peers.peer_session_generation_sync(&peer_info.node_id).map(|generation| generation.value())
                            );
                        }
                        let peer_rejoined = update.was_offline && peer_info.online;
                        match previous_peer_session_generation {
                            Some(previous_generation)
                                if !peer_info.online
                                    || update.public_key_changed
                                    || update.virtual_ip_changed
                                    || peer_rejoined =>
                            {
                                self.punch_attempts
                                    .retire_peer_session(&peer_info.node_id, previous_generation);
                            }
                            _ => {}
                        }
                        if update.last_seen_only {
                            // The roster heartbeat must reach diagnostics, but it
                            // is not new connectivity evidence. Starting another
                            // initiator/recovery turn every poll would continuously
                            // replace handshake ownership for an unchanged peer.
                            if let Some(receipt) = signal_delivery_receipt.take() {
                                receipt.complete(control::SignalApplyOutcome::Applied);
                            }
                            continue;
                        }
                        if !peer_info.online {
                            remove_deferred_initiator_handshake(
                                &mut deferred_initiators,
                                &peer_info.node_id,
                            );
                            self.clear_peer_handshake_lifecycle(
                                &peer_info.node_id,
                                "peer_offline",
                            );
                            self.transport
                                .remove_session_with_reason(
                                    &peer_info.node_id,
                                    "peer_offline",
                                    "control_events.peer_updated_offline",
                                )
                                .await;
                            if previous_peer_session_generation.is_none() {
                                self.punch_attempts.cancel(&peer_info.node_id);
                            }
                            self.peers
                                .clear_fresh_mapping(&peer_info.node_id, "peer_offline")
                                .await;
                            if let Some(udp) = self.udp_transport.read().await.clone() {
                                // One atomic lifecycle cleanup under the peer's
                                // adoption lock: the pending probes drop and the
                                // cleanup epoch moves on, the dynamic sockets
                                // detach and the affinity clears, all in one
                                // transaction, so a late ACK can neither match,
                                // re-insert nor leave pool affinity behind.
                                udp.cleanup_peer_lifecycle(
                                    &peer_info.node_id,
                                    "peer_offline",
                                    false,
                                )
                                .await;
                            }
                            if self.dns.is_enabled() {
                                if let Some(previous_virtual_ip) = update.previous_virtual_ip.as_ref() {
                                    self.dns.unregister(previous_virtual_ip).await;
                                } else {
                                    self.dns.unregister(&peer_info.virtual_ip).await;
                                }
                            }
                            debug!(
                                "Peer {} is offline according to control plane; cleared active sessions and skipped traversal",
                                peer_info.node_id
                            );
                            if let Some(receipt) = signal_delivery_receipt.take() {
                                receipt.complete(control::SignalApplyOutcome::Applied);
                            }
                            continue;
                        }
                        if update.public_key_changed || peer_rejoined || update.virtual_ip_changed {
                            remove_deferred_initiator_handshake(
                                &mut deferred_initiators,
                                &peer_info.node_id,
                            );
                            let (reason, caller) = if update.virtual_ip_changed {
                                ("peer_address_changed", "control_events.peer_updated_address")
                            } else if peer_rejoined {
                                ("peer_rejoined", "control_events.peer_updated_rejoined")
                            } else {
                                (
                                    "public_key_changed",
                                    "control_events.peer_updated_public_key",
                                )
                            };
                            self.clear_peer_handshake_lifecycle(
                                &peer_info.node_id,
                                reason,
                            );
                            self.transport
                                .remove_session_with_reason(
                                    &peer_info.node_id,
                                    reason,
                                    caller,
                                )
                                .await;
                            if update.virtual_ip_changed {
                                info!("Peer {} address changed; discarded the old WireGuard session", peer_info.node_id);
                            } else if peer_rejoined {
                                info!(
                                    "Peer {} rejoined after going offline; discarded the old WireGuard session and UDP lifecycle",
                                    peer_info.node_id
                                );
                            } else {
                                info!(
                                    "Peer {} public key changed; discarded the old WireGuard session",
                                    peer_info.node_id
                                );
                            }
                            // A changed public key is a new peer incarnation: the
                            // old punch owner, pending probe ownership, fresh
                            // model and every dynamic socket belong to the old
                            // identity and must not keep mutating state or send
                            // to the old binding.
                            if previous_peer_session_generation.is_none() {
                                self.punch_attempts.cancel(&peer_info.node_id);
                            }
                            self.peers
                                .clear_fresh_mapping(&peer_info.node_id, reason)
                                .await;
                            if let Some(udp) = self.udp_transport.read().await.clone() {
                                udp.cleanup_peer_lifecycle(
                                    &peer_info.node_id,
                                    reason,
                                    false,
                                )
                                .await;
                            }
                        } else if update.endpoint_changed {
                            // Endpoint metadata changes are normal NAT/candidate
                            // churn. They must not tear down a confirmed relay or
                            // WireGuard session. A same-node restart is reset only
                            // when a later peer offer carries a different encoded
                            // candidate-generation incarnation.
                            self.punch_attempts.cancel(&peer_info.node_id);
                            if let Some(udp) = self.udp_transport.read().await.clone() {
                                udp.clear_pending_probes_for_peer(&peer_info.node_id).await;
                            }
                        }
                        let was_offline = update.was_offline;
                        if (update.virtual_ip_changed || was_offline) && self.dns.is_enabled() {
                            if let Some(previous_virtual_ip) = update.previous_virtual_ip.as_ref() {
                                self.dns.unregister(previous_virtual_ip).await;
                            }
                            self.dns
                                .register(
                                    &peer_info.node_id,
                                    &peer_info.virtual_ip,
                                    Some(&peer_info.node_id),
                                )
                                .await;
                        }
                        if was_offline || update.public_key_changed || update.virtual_ip_changed || update.endpoint_changed {
                            // A peer that comes back online or whose endpoint changed has lost its copy of
                            // our candidate snapshot. Replay it even when our
                            // local snapshot/hash is unchanged; waiting for the
                            // next NAT/ STUN change recreates the Air-first cold
                            // start failure.
                            schedule_candidate_republication(
                                daemon,
                                &mut responder_work,
                                peer_info.node_id.clone(),
                                "peer online lifecycle",
                            );
                        }
                        let should_start_initiator =
                            self.should_start_initiator_handshake(&peer_info);
                        if should_start_initiator
                            && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                        {
                            let queued = enqueue_deferred_initiator_handshake(
                                &mut deferred_initiators,
                                peer_info.clone(),
                            );
                            let reason_code = if queued {
                                "control_slow_work_full_queued"
                            } else {
                                "control_slow_work_deferred_queue_full"
                            };
                            warn!(
                                "Deferring peer-update handshake for {}: reason_code={} slow_work={} deferred_queue={}",
                                peer_info.node_id,
                                reason_code,
                                slow_work.len(),
                                deferred_initiators.len(),
                            );
                            self.peers
                                .record_direct_event(
                                    &peer_info.node_id,
                                    "initiator_handshake_deferred",
                                    None,
                                    None,
                                    None,
                                    format!(
                                        "reason_code={reason_code} slow_work={} deferred_queue={}",
                                        slow_work.len(),
                                        deferred_initiators.len()
                                    ),
                                )
                                .await;
                            self.timeline.emit(
                                "initiator_handshake_deferred",
                                None,
                                Some(reason_code),
                                Some(format!(
                                    "peer={} slow_work={} deferred_queue={}",
                                    peer_info.node_id,
                                    slow_work.len(),
                                    deferred_initiators.len()
                                )),
                            );
                        } else if should_start_initiator {
                            if let Some(reservation) = self
                                .reserve_event_initiator_handshake(&peer_info.node_id)
                                .into_reservation()
                            {
                                let peer_info = peer_info.clone();
                                slow_work.push(Box::pin(async move {
                                    daemon
                                        .run_event_initiator_handshake(peer_info, reservation)
                                        .await;
                                }));
                            } else {
                                // Preserve the newest online/endpoint update
                                // instead of silently dropping the handshake
                                // trigger while the previous owner is live.
                                let queued = enqueue_deferred_initiator_handshake(
                                    &mut deferred_initiators,
                                    peer_info.clone(),
                                );
                                let reason_code = if queued {
                                    "initiator_reservation_busy_queued"
                                } else {
                                    "initiator_reservation_busy_queue_full"
                                };
                                self.timeline.emit(
                                    "initiator_handshake_deferred",
                                    None,
                                    Some(reason_code),
                                    Some(format!("peer={}", peer_info.node_id)),
                                );
                            }
                        }
                    }

                    ControlEvent::PeerLeft(node_id) => {
                        info!("Peer left: {}", node_id);
                        let retiring_peer_session =
                            self.peers.peer_session_generation_sync(&node_id);
                        if let Some(retiring_peer_session) = retiring_peer_session {
                            self.punch_attempts
                                .retire_peer_session(&node_id, retiring_peer_session);
                        } else {
                            self.punch_attempts.cancel(&node_id);
                        }
                        remove_deferred_initiator_handshake(&mut deferred_initiators, &node_id);
                        if let Some(previous) = self.peers.get_connection(&node_id).await {
                            if self.dns.is_enabled() {
                                self.dns.unregister(&previous.virtual_ip).await;
                            }
                        }
                        // Cancel the exact reservation/retry first.  This is a
                        // short in-memory transaction; the subsequent session
                        // and UDP actor cleanup owns no handshake arbiter lease.
                        self.clear_peer_handshake_lifecycle(&node_id, "peer_left");
                        self.transport
                            .remove_session_with_reason(
                                &node_id,
                                "peer_left",
                                "control_events.peer_left",
                            )
                            .await;
                        // Keep the slot read guard through the selected cleanup.
                        // A UDP task cannot publish between observing `None` and
                        // structural removal (or replace a `Some` transport while
                        // its adoption transaction is running).
                        let udp_slot = self.udp_transport.read().await;
                        if let Some(udp) = udp_slot.clone() {
                            // One atomic lifecycle cleanup under the peer's
                            // adoption lock: the connection removal, the pending
                            // probe drop with the cleanup-epoch bump, the dynamic
                            // socket detach and the affinity clear form ONE
                            // transaction, linearized against every ACK adoption
                            // for this peer.  A late ACK can neither match, nor
                            // re-insert, nor leave pool affinity / endpoint /
                            // candidate state behind for a new identity that
                            // later rejoins under the same node ID.
                            udp.cleanup_peer_lifecycle(&node_id, "peer_left", true)
                                .await;
                        } else {
                            // The UDP task publishes its transport asynchronously,
                            // so control events can be consumed during a short
                            // startup window in which no adoption registry exists
                            // yet. Structural removal must not depend on that
                            // optional data-plane handle: otherwise a PeerLeft in
                            // this window leaves both the connection and the
                            // lifecycle mirror present, and a same-node rejoin is
                            // misclassified as an in-place update instead of a new
                            // lifecycle. When UDP is present, the branch above
                            // remains the single removal owner so connection and
                            // socket cleanup stay one adoption-lock transaction.
                            self.peers.remove_peer(&node_id).await;
                        }
                    }

                    ControlEvent::PeerOffer {
                        from_node_id,
                        candidates,
                        session_id,
                        probe_ephemeral_public_key,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                        handshake_init,
                        punch_at_ms,
                        punch_at_server_ms,
                        sender_public_key,
                    } => {
                        let delivery_receipt = signal_delivery_receipt.take();
                        if let Some(receipt) = delivery_receipt.as_ref() {
                            receipt.record_phase("dispatch_started", "peer_offer");
                        }
                        let network_generation = self.peers.current_network_generation_sync();
                        info!(
                            "Received peer offer from {} ({} candidates)",
                            from_node_id,
                            candidates.len()
                        );
                        self.peers.record_direct_event_non_queuing(
                            &from_node_id,
                            "peer_offer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received offer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_init.len()
                            ),
                        );
                        self.timeline.emit(
                            "peer_offer_received",
                            None,
                            None,
                            Some(format!(
                                "peer={} candidate_generation={} handshake_bytes={} candidates={}",
                                from_node_id,
                                candidate_generation,
                                handshake_init.len(),
                                candidates.len()
                            )),
                        );
                        let peer_known = self.peers.peer_exists_sync(&from_node_id);
                        let peer_online = self
                            .peers
                            .peer_session_generation_sync(&from_node_id)
                            .is_some();
                        let identity_matches = self.signal_sender_identity_matches_peer(
                            &from_node_id,
                            sender_public_key.as_deref(),
                        );
                        if peer_known && peer_online && identity_matches {
                            // Fast path: peer is known, online, and sender identity matches.
                        } else if !peer_known || !peer_online {
                            // REST signal delivery can beat the independent roster poll,
                            // or the peer is known from a previous poll but recorded as offline.
                            // Both bounded owners wait for identity/online publication; waking
                            // the poll keeps that interval short without blocking this actor.
                            self.control.refresh_peers_now();
                            let reason = if !peer_known {
                                "peer_unknown"
                            } else {
                                "peer_lifecycle_pending"
                            };
                            self.timeline.emit(
                                "remote_signal_deferred",
                                None,
                                Some(reason),
                                Some(format!(
                                    "peer={from_node_id} candidate_generation={candidate_generation}"
                                )),
                            );
                        } else {
                            // Peer is known and online, but sender public key does not match.
                            self.peers.record_direct_event_non_queuing(
                                &from_node_id,
                                "remote_signal_stale_identity",
                                None,
                                None,
                                None,
                                format!(
                                    "ignored signal before incarnation/handshake/candidate mutation candidate_generation={candidate_generation}"
                                ),
                            );
                            self.timeline.emit(
                                "remote_signal_rejected",
                                None,
                                Some("sender_key_mismatch"),
                                Some(format!(
                                    "peer={from_node_id} candidate_generation={candidate_generation}"
                                )),
                            );
                            if let Some(receipt) = delivery_receipt.as_ref() {
                                receipt.complete(control::SignalApplyOutcome::TerminalRejected);
                            }
                            continue;
                        }

                        // Retain the candidate half first in its own bounded ledger.
                        // No durable receipt enters this worker: successful local
                        // admission is the application commit, and the owner repairs
                        // connection/epoch contention independently.
                        let candidate_admission = {
                            let mut state = self.pending_handshakes.lock();
                            state.enqueue_candidate_offer_work(PendingPeerOffer {
                                from_node_id: from_node_id.clone(),
                                candidates: candidates.clone(),
                                candidate_sources: candidate_sources.clone(),
                                candidate_generation,
                                network_generation,
                                peer_session_generation: self
                                    .peers
                                    .peer_session_generation_sync(&from_node_id),
                                candidates_expires_at_ms,
                                sender_public_key: sender_public_key.clone(),
                                handshake_init: handshake_init.clone(),
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id: session_id.clone(),
                                probe_ephemeral_public_key: probe_ephemeral_public_key.clone(),
                                delivery_receipt: None,
                            })
                        };
                        let candidate_signal_trace = signal_context
                            .as_ref()
                            .map(|(signal_id, signal_seq, signal_type)| {
                                format!(
                                    "signal_fp={:016x} signal_seq={signal_seq:?} signal_type={signal_type}",
                                    crate::transport::wire_fingerprint(signal_id.as_bytes())
                                )
                            })
                            .unwrap_or_else(|| {
                                "signal_fp=none signal_seq=none signal_type=none".to_string()
                            });
                        let candidate_signal_outcome = match candidate_admission {
                            CandidateOfferWorkAdmission::Started(reservation, offer) => {
                                self.timeline.emit(
                                    "peer_offer_candidate_work_admitted",
                                    None,
                                    None,
                                    Some(format!(
                                        "peer_fp={:016x} owner={} network_generation={} candidate_generation={} candidates={} {}",
                                        crate::transport::wire_fingerprint(from_node_id.as_bytes()),
                                        reservation.owner,
                                        network_generation,
                                        candidate_generation,
                                        candidates.len(),
                                        candidate_signal_trace
                                    )),
                                );
                                candidate_work.push(Box::pin(async move {
                                    daemon
                                        .run_candidate_offer_worker(*offer, reservation)
                                        .await;
                                }));
                                control::SignalApplyOutcome::Applied
                            }
                            CandidateOfferWorkAdmission::Coalesced => {
                                self.timeline.emit(
                                    "peer_offer_candidate_work_coalesced",
                                    None,
                                    Some("newest_wins_coalesced"),
                                    Some(format!(
                                        "peer_fp={:016x} network_generation={} candidate_generation={} candidates={} {}",
                                        crate::transport::wire_fingerprint(from_node_id.as_bytes()),
                                        network_generation,
                                        candidate_generation,
                                        candidates.len(),
                                        candidate_signal_trace
                                    )),
                                );
                                control::SignalApplyOutcome::Applied
                            }
                            CandidateOfferWorkAdmission::RejectedIdentity => {
                                control::SignalApplyOutcome::TerminalRejected
                            }
                            CandidateOfferWorkAdmission::Capacity => {
                                self.timeline.emit(
                                    "peer_offer_candidate_work_rejected",
                                    None,
                                    Some("candidate_owner_capacity"),
                                    Some(format!(
                                        "peer={} capacity={}",
                                        from_node_id, MAX_CANDIDATE_OFFER_WORKERS
                                    )),
                                );
                                control::SignalApplyOutcome::Retry
                            }
                        };
                        if candidate_signal_outcome == control::SignalApplyOutcome::Applied {
                            if let Some(receipt) = delivery_receipt.as_ref() {
                                receipt.record_phase("work_admitted", "candidate_offer");
                            }
                        }

                        if handshake_init.is_empty() {
                            // The exact candidate payload is now owned locally. ACK its
                            // durable row immediately so the sender's next independently
                            // encrypted handshake signal is not head-of-line blocked.
                            if let Some(receipt) = delivery_receipt.as_ref() {
                                receipt.complete(candidate_signal_outcome);
                            }
                            // This branch continues the receiver loop before the
                            // common post-event drain.  Revisit the retry ledger
                            // here so a prepared encrypted offer that became
                            // ready during candidate admission is not left
                            // waiting for an unrelated control event.
                            daemon.drain_initiator_retry_ledger(&mut retry_work);
                            daemon.drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                            continue;
                        }

                        if candidate_signal_outcome != control::SignalApplyOutcome::Applied {
                            // A combined offer is one durable transaction. If
                            // its candidate half could not enter the bounded
                            // local ledger, do not acknowledge only the
                            // responder half and silently discard candidates.
                            // Server redelivery replays the exact encrypted
                            // offer once capacity or identity turnover clears.
                            if let Some(receipt) = delivery_receipt.as_ref() {
                                receipt.complete(candidate_signal_outcome);
                            }
                            continue;
                        }

                        // Handshake material has a disjoint per-peer owner. It retains
                        // the durable receipt until the exact responder transaction is
                        // Applied/TerminalRejected; candidate work cannot occupy this slot.
                        let admitted = {
                            let mut state = self.pending_handshakes.lock();
                            state.enqueue_responder_work(PendingPeerOffer {
                                from_node_id: from_node_id.clone(),
                                candidates,
                                candidate_sources,
                                candidate_generation,
                                network_generation,
                                peer_session_generation: self
                                    .peers
                                    .peer_session_generation_sync(&from_node_id),
                                candidates_expires_at_ms,
                                sender_public_key,
                                handshake_init,
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id: session_id.clone(),
                                probe_ephemeral_public_key,
                                delivery_receipt: delivery_receipt.clone(),
                            })
                        };
                        if let Some((reservation, offer)) = admitted {
                            if let Some(receipt) = delivery_receipt.as_ref() {
                                receipt.record_phase("work_admitted", "responder_offer");
                            }
                            self.timeline.emit(
                                "peer_offer_responder_work_admitted",
                                None,
                                None,
                                Some(format!(
                                    "peer={} owner={} network_generation={} candidate_generation={} session_fp={} deferred={}",
                                    from_node_id,
                                    reservation.owner,
                                    network_generation,
                                    candidate_generation,
                                    handshake_token_fingerprint(session_id.as_deref()),
                                    !peer_known || !peer_online
                                )),
                            );
                            responder_work.push(Box::pin(async move {
                                daemon.run_responder_offer_worker(offer, reservation).await;
                            }));
                        } else {
                            if let Some(receipt) = delivery_receipt.as_ref() {
                                receipt.record_phase("work_coalesced", "responder_offer");
                            }
                            self.timeline.emit(
                                "peer_offer_responder_work_coalesced",
                                None,
                                Some("newest_wins_coalesced"),
                                Some(format!(
                                    "peer={} network_generation={} candidate_generation={} session_fp={} queued=true",
                                    from_node_id,
                                    network_generation,
                                    candidate_generation,
                                    handshake_token_fingerprint(session_id.as_deref())
                                )),
                            );
                        }
                        continue;
                    }

                    ControlEvent::PeerAnswer {
                        from_node_id,
                        candidates,
                        session_id,
                        probe_ephemeral_public_key,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                        handshake_response,
                        punch_at_ms,
                        punch_at_server_ms: _,
                        sender_public_key,
                    } => {
                        let answer_delivery_receipt = signal_delivery_receipt.take();
                        let mut answer_signal_outcome = control::SignalApplyOutcome::Applied;
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=dispatch_started id={} type={} seq={:?} peer={} stage=peer_answer",
                                signal_id, signal_type, signal_seq, from_node_id
                            );
                        }
                        info!(
                            "Received peer answer from {} ({} candidates)",
                            from_node_id,
                            candidates.len()
                        );
                        // An answer may arrive before the peer-list poll registers
                        // its sender: wake the peer poll so the pending initiator
                        // transaction can be consumed without waiting out the
                        // regular cadence.
                        if !self.peers.peer_exists_sync(&from_node_id)
                            || self.peers.peer_session_generation_sync(&from_node_id).is_none()
                        {
                            self.control.refresh_peers_now();
                        }
                        self.peers.record_direct_event_non_queuing(
                            &from_node_id,
                            "peer_answer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received answer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_response.len()
                            ),
                        );
                        self.timeline.emit(
                            "peer_answer_received",
                            None,
                            None,
                            Some(format!(
                                "peer={} candidate_generation={} handshake_bytes={} candidates={}",
                                from_node_id,
                                candidate_generation,
                                handshake_response.len(),
                                candidates.len()
                            )),
                        );
                        // The answer can be the first signal observed after the
                        // remote daemon restarted. Fence the retired transport but
                        // preserve the exact local initiator that this answer is
                        // about to complete.
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=waiting_for_resource id={} type={} seq={:?} resource=remote_incarnation_reset",
                                signal_id, signal_type, signal_seq
                            );
                        }
                        if let Some(receipt) = answer_delivery_receipt.as_ref() {
                            receipt.record_phase("waiting_for_resource", "remote_incarnation_reset");
                        }
                        let remote_incarnation_reset = match self
                            .reset_peer_for_remote_incarnation_if_needed_for_identity(
                                &from_node_id,
                                candidate_generation,
                                sender_public_key.as_deref(),
                                if handshake_response.is_empty() {
                                    RemoteIncarnationResetWork::ClearAll
                                } else {
                                    RemoteIncarnationResetWork::PreserveInitiator
                                },
                            )
                            .await
                        {
                            RemoteIncarnationResetOutcome::Changed => true,
                            RemoteIncarnationResetOutcome::Unchanged => false,
                            RemoteIncarnationResetOutcome::RejectedIdentity => {
                                debug!(
                                    "Ignored peer answer from {from_node_id}: signal sender public key is stale"
                                );
                                if let Some(receipt) = answer_delivery_receipt.as_ref() {
                                    receipt.complete(control::SignalApplyOutcome::TerminalRejected);
                                }
                                continue;
                            }
                            RemoteIncarnationResetOutcome::RejectedLifecycle => {
                                if let Some(receipt) = answer_delivery_receipt.as_ref() {
                                    receipt.complete(
                                        control::SignalApplyOutcome::TerminalRejected,
                                    );
                                }
                                continue;
                            }
                            outcome if outcome.retryable() => {
                                if let Some(receipt) = answer_delivery_receipt.as_ref() {
                                    receipt.complete(control::SignalApplyOutcome::Retry);
                                }
                                continue;
                            }
                            _ => false,
                        };
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=resource_ready id={} type={} seq={:?} resource=remote_incarnation_reset",
                                signal_id, signal_type, signal_seq
                            );
                        }
                        if let Some(receipt) = answer_delivery_receipt.as_ref() {
                            receipt.record_phase("resource_ready", "remote_incarnation_reset");
                        }
                        // Consume the WireGuard answer before candidate refresh or
                        // fresh-mapping work. Those paths may perform HTTP/STUN
                        // I/O and must remain a background upgrade; delaying the
                        // answer here leaves the responder staged but prevents
                        // the initiator from ever publishing its active session.
                        if !handshake_response.is_empty() {
                            if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                                info!(
                                    "Control signal phase=waiting_for_resource id={} type={} seq={:?} resource=wireguard_answer_commit",
                                    signal_id, signal_type, signal_seq
                                );
                            }
                            if let Some(receipt) = answer_delivery_receipt.as_ref() {
                                receipt.record_phase("waiting_for_resource", "wireguard_answer_commit");
                            }
                            self.peers
                                .record_direct_event(
                                    &from_node_id,
                                    "peer_answer_dispatch_started",
                                    None,
                                    Some(candidates.len()),
                                    None,
                                    format!(
                                        "dispatching handshake response before candidate/fresh work bytes={} session_fp={}",
                                        handshake_response.len(),
                                        handshake_token_fingerprint(session_id.as_deref())
                                    ),
                                )
                                .await;
                            match self
                                .handle_peer_answer_for_identity(
                                    &from_node_id,
                                    &handshake_response,
                                    session_id.clone(),
                                    probe_ephemeral_public_key.clone(),
                                    sender_public_key.as_deref(),
                                )
                                .await
                            {
                                Ok(true) => {}
                                Ok(false) => {
                                    answer_signal_outcome =
                                        control::SignalApplyOutcome::TerminalRejected;
                                }
                                Err(err) => {
                                    answer_signal_outcome =
                                        control::SignalApplyOutcome::TerminalRejected;
                                    warn!("Failed to handle peer answer from {from_node_id}: {err}");
                                }
                            }
                            if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                                info!(
                                    "Control signal phase=state_committed id={} type={} seq={:?} commit=wireguard_answer outcome={:?}",
                                    signal_id, signal_type, signal_seq, answer_signal_outcome
                                );
                            }
                            if let Some(receipt) = answer_delivery_receipt.as_ref() {
                                receipt.record_phase(
                                    match answer_signal_outcome {
                                        control::SignalApplyOutcome::Applied => "state_committed",
                                        control::SignalApplyOutcome::TerminalRejected => {
                                            "terminal_rejected"
                                        }
                                        control::SignalApplyOutcome::Retry => "retry_decided",
                                        control::SignalApplyOutcome::Pending => unreachable!(
                                            "answer disposition must be terminal before receipt"
                                        ),
                                    },
                                    "wireguard_answer",
                                );
                            }
                        }
                        // Fresh-prediction verification happens after the
                        // handshake transaction and before candidate state is
                        // used for background punching (see the offer path).
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=waiting_for_resource id={} type={} seq={:?} resource=candidate_refresh",
                                signal_id, signal_type, signal_seq
                            );
                        }
                        if let Some(receipt) = answer_delivery_receipt.as_ref() {
                            receipt.record_phase("waiting_for_resource", "candidate_refresh");
                        }
                        let (_fresh_verdict, candidate_apply_result, fresh_punch) = self
                            .fresh_prediction_transaction(
                                &from_node_id,
                                &candidates,
                                &candidate_sources,
                                candidate_generation,
                                candidates_expires_at_ms,
                                sender_public_key.as_deref(),
                                false,
                            )
                            .await;
                        if let Some((signal_id, signal_seq, signal_type)) = signal_context.as_ref() {
                            info!(
                                "Control signal phase=state_committed id={} type={} seq={:?} commit=candidate_refresh result={:?}",
                                signal_id, signal_type, signal_seq, candidate_apply_result
                            );
                        }
                        if let Some(receipt) = answer_delivery_receipt.as_ref() {
                            receipt.record_phase("state_evaluated", "candidate_refresh");
                        }
                        if !handshake_response.is_empty()
                            && answer_signal_outcome == control::SignalApplyOutcome::Applied
                        {
                            // See the offer path above.  An encrypted answer
                            // is authenticated liveness evidence and is the
                            // normal signal emitted by a rekeying Android
                            // peer; re-arm the bounded recovery window before
                            // starting its synchronized punch.
                            self.peers
                                .recovery_reopen_on_evidence(
                                    &from_node_id,
                                    "authenticated_peer_answer",
                                )
                                .await;
                        }
                        match fresh_punch {
                            FreshPunchDecision::Fresh(id, frozen_targets) => {
                                self.start_hole_punch_at(
                                    &from_node_id,
                                    punch_at_ms,
                                    Some(id),
                                    Some(frozen_targets),
                                )
                                .await;
                            }
                            FreshPunchDecision::Degraded => {
                                if !handshake_response.is_empty() {
                                    debug!(
                                        "Degrading synchronized punch for {from_node_id}: the fresh snapshot is expired or empty; punching at ordinary priority"
                                    );
                                    self.start_hole_punch_at(
                                        &from_node_id,
                                        punch_at_ms,
                                        None,
                                        None,
                                    )
                                    .await;
                                } else {
                                    debug!(
                                        "Skipping punch for candidate-only answer from {from_node_id}: its fresh snapshot is expired or empty"
                                    );
                                }
                            }
                            FreshPunchDecision::None => {
                                if candidate_signal_starts_synchronized_punch(
                                    &handshake_response,
                                    candidate_apply_result,
                                ) {
                                    self.start_hole_punch_at(
                                        &from_node_id,
                                        punch_at_ms,
                                        None,
                                        None,
                                    )
                                    .await;
                                } else {
                                    debug!(
                                        "Skipping synchronized punch for rejected candidate-only answer from {from_node_id}: {candidate_apply_result:?}"
                                    );
                                }
                            }
                        }
                        if remote_incarnation_reset {
                            // The answer proves the remote incarnation is new,
                            // but it does not carry our local candidate set. A
                            // restart can therefore leave the peer punching an
                            // obsolete local mapping forever. Replay our current
                            // candidates after the answer transaction commits.
                            schedule_candidate_republication(
                                daemon,
                                &mut responder_work,
                                from_node_id.clone(),
                                "remote incarnation answer",
                            );
                        }
                        if let Some(receipt) = answer_delivery_receipt {
                            receipt.complete(answer_signal_outcome);
                        }
                    }

                    ControlEvent::PeerReflexive {
                        from_node_id,
                        observed_endpoint,
                        punch_at_ms,
                    } => {
                        let delivery_receipt = signal_delivery_receipt.take();
                        // A peer-reflexive observation may arrive before the
                        // peer-list poll registers the sender; wake the poll so a
                        // cold-start handshake is not delayed by the cadence.
                        if !self.peers.peer_exists_sync(&from_node_id)
                            || self.peers.peer_session_generation_sync(&from_node_id).is_none()
                        {
                            self.control.refresh_peers_now();
                        }
                        let work = PendingPeerReflexive {
                            from_node_id: from_node_id.clone(),
                            observed_endpoint,
                            punch_at_ms,
                            peer_session_generation: self
                                .peers
                                .peer_session_generation_sync(&from_node_id),
                            delivery_receipt,
                        };
                        let admitted = {
                            let mut state = self.pending_handshakes.lock();
                            if !state.has_peer_reflexive_worker(&from_node_id)
                                && slow_work.len() >= MAX_CONTROL_EVENT_SLOW_WORK
                            {
                                warn!(
                                    "Dropping peer-reflexive work for {from_node_id}: control slow-work cap {} is full",
                                    MAX_CONTROL_EVENT_SLOW_WORK,
                                );
                                work.complete_delivery(control::SignalApplyOutcome::Retry);
                                None
                            } else {
                                state.enqueue_peer_reflexive_work(work)
                            }
                        };
                        if let Some((reservation, work)) = admitted {
                            if let Some(receipt) = work.delivery_receipt.as_ref() {
                                receipt.record_phase("work_admitted", "peer_reflexive");
                            }
                            slow_work.push(Box::pin(async move {
                                daemon.run_peer_reflexive_worker(work, reservation).await;
                            }));
                        }
                    }

                    ControlEvent::PeerRejected {
                        from_node_id,
                        reason,
                    } => {
                        warn!("Peer {} rejected connection: {}", from_node_id, reason);
                    }

                    ControlEvent::TunnelCreated {
                        tunnel_id,
                        public_endpoint,
                    } => {
                        info!("Tunnel created: {} → {}", tunnel_id, public_endpoint);
                        self.port_mappings
                            .activate(&tunnel_id, &public_endpoint)
                            .await
                            .ok();
                    }

                    ControlEvent::ServerError { code, message } => {
                        error!("Control server error: {} - {}", code, message);
                    }

                    ControlEvent::Disconnected => {
                        // Control loop will re-register; do not shut down the daemon.
                        self.health.set_control_connected(false);
                        warn!("Disconnected from control server; waiting for recovery");
                    }

                    ControlEvent::ReauthRequired { message } => {
                        error!("Reauthentication required: {message}");
                        self.health.set_reauth_required(true);
                        // Keep running so operator can re-auth; do not exit daemon.
                    }

                    ControlEvent::ControlRecovered { .. } => {
                        info!("Control plane recovered after disconnection");
                        self.health.mark_control_success().await;
                    }
                    ControlEvent::ControlHealthy => {
                        self.health.mark_control_success().await;
                    }
                    ControlEvent::DeliveredSignal { receipt, .. } => {
                        // The poller emits exactly one envelope. A nested envelope
                        // has no well-defined ownership, so reject it terminally
                        // instead of leaving either durable delivery pending.
                        receipt.complete(control::SignalApplyOutcome::TerminalRejected);
                        if let Some(receipt) = signal_delivery_receipt.take() {
                            receipt.complete(control::SignalApplyOutcome::TerminalRejected);
                        }
                    }
                        }
                        if let Some(receipt) = signal_delivery_receipt {
                            receipt.complete(control::SignalApplyOutcome::Applied);
                        }
                        // An answer or lifecycle event may release an
                        // initiator reservation without completing a future
                        // in either cooperative lane. Revisit the newest
                        // deferred roster edge before waiting for another
                        // unrelated event.
                        daemon.drain_initiator_retry_ledger(&mut retry_work);
                        daemon
                            .drain_deferred_initiator_handshakes(
                                &mut slow_work,
                                &mut deferred_initiators,
                            );
                    }
                }
        }
        // Drop all borrowed background work before restoring the receiver.
        // Dropping these futures also releases any STUN/HTTP wait promptly on
        // daemon shutdown rather than leaving detached work behind.
        drop(slow_work);
        drop(retry_work);
        drop(responder_work);
        drop(candidate_work);
        self.control_rx = control_rx;
    }
}
