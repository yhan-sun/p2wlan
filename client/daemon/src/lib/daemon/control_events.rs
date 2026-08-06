fn candidate_signal_starts_synchronized_punch(
    handshake_payload: &[u8],
    apply_result: CandidateSetApplyResult,
) -> bool {
    !handshake_payload.is_empty() || apply_result == CandidateSetApplyResult::Applied
}

/// Whether an offer/answer carries a fresh-mapping prediction window.
///
/// Ordinary ICE gathering emits `predicted` candidate labels, so only the
/// distinct `predicted_fresh:<boot_epoch>:<punch_generation>` label counts as
/// a fresh prediction.  The embedded incarnation+generation orders
/// predictions by NAT measurement generation instead of by HTTP send time: a
/// superseded task that sends late cannot masquerade as a newer prediction,
/// and a restarted daemon incarnation supersedes the old one.  Signals
/// without the label (old clients, ordinary refreshes) degrade to an ordinary
/// synchronized punch session.
///
/// Every fresh label in one payload must agree: when the payload mixes two
/// different valid identities the signal is inconsistent and is rejected
/// deterministically instead of letting HashMap iteration pick an arbitrary
/// one.
fn fresh_prediction_from_sources(
    candidate_sources: &HashMap<String, String>,
) -> std::result::Result<Option<crate::FreshPredictionId>, ()> {
    let mut found = None;
    for source in candidate_sources.values() {
        let Some(id) = crate::parse_fresh_prediction_source_label(source) else {
            continue;
        };
        match found {
            None => found = Some(id),
            Some(previous) if previous == id => {}
            Some(_) => return Err(()),
        }
    }
    Ok(found)
}

/// Verdict for a signal's fresh-mapping prediction payload.
#[derive(Debug, Clone, Copy)]
enum FreshSignalVerdict {
    /// No fresh prediction label: an ordinary signal.
    None,
    /// The label is newer than the peer's high-water: candidates may be
    /// applied and, once the apply really succeeds, the identity is committed
    /// and a priority-2 punch session may claim.
    Accepted(crate::FreshPredictionId),
    /// The label equals the high-water AND the payload matches the snapshot
    /// the identity was committed with: an idempotent retry.  Candidates are
    /// not re-applied; the fresh punch starts from the COMMITTED snapshot.
    AlreadyRecorded(crate::FreshPredictionId),
    /// The label equals the high-water but the payload differs from the
    /// committed snapshot (or no snapshot exists): a retry must never apply
    /// different candidates under the same identity.
    PayloadMismatch(crate::FreshPredictionId),
    /// The label is older than the high-water: a superseded prediction sent
    /// late.  Its candidates must not be applied and no punch may start from
    /// them.
    Stale,
    /// The payload carried conflicting fresh labels: rejected
    /// deterministically like a stale signal.
    Inconsistent,
}

impl Daemon {
    /// Freeze the immutable candidate snapshot bound to a fresh identity.
    ///
    /// The snapshot is the payload the identity was committed with (stored by
    /// the commit transaction) — never the current ordinary refresh set and
    /// never a retry's possibly-reordered payload: a later ordinary refresh
    /// must never change the targets of a running fresh session.  The
    /// snapshot's own expiry deadline is honored: an idempotent retry of an
    /// already-recorded identity must never punch toward prediction ports
    /// that have expired since the commit.
    async fn freeze_fresh_punch_targets(
        &self,
        from_node_id: &str,
        id: crate::FreshPredictionId,
    ) -> Option<Vec<SocketAddr>> {
        let snapshot = self
            .peers
            .remote_fresh_snapshot_for(from_node_id, id)
            .await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        if snapshot
            .candidates_expires_at_ms
            .is_some_and(|expires_at| {
                expires_at.saturating_add(crate::peer::CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS)
                    <= now_ms
            })
        {
            debug!(
                "Fresh-mapping prediction {id:?} from {from_node_id} expired since its commit; no punch starts from it"
            );
            return None;
        }
        let targets = snapshot
            .candidates
            .iter()
            .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return None;
        }
        Some(targets)
    }

    /// The prepare/apply/commit transaction for one fresh signal, shared by
    /// the offer and answer paths.
    ///
    /// 1. prepare compares the identity against the peer's high-water AND
    ///    verifies an equal-id retry's payload against the committed
    ///    snapshot (payload mismatch is rejected).
    /// 2. apply installs the candidates and records the apply.
    /// 3. commit is a strict CAS (`id > current`): exactly one concurrent
    ///    commit of an identity wins and freezes its immutable snapshot; the
    ///    loser rolls its own apply back and starts no punch.
    #[allow(clippy::too_many_arguments)]
    async fn fresh_prediction_transaction(
        &self,
        from_node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
    ) -> (
        FreshSignalVerdict,
        CandidateSetApplyResult,
        Option<crate::FreshPredictionId>,
        Option<Vec<SocketAddr>>,
    ) {
        let fresh_verdict = match fresh_prediction_from_sources(candidate_sources) {
            Err(()) => {
                self.peers
                    .record_direct_event(
                        from_node_id,
                        "fresh_prediction_inconsistent",
                        None,
                        Some(candidates.len()),
                        None,
                        "offer carried conflicting fresh-mapping prediction labels; candidates ignored",
                    )
                    .await;
                FreshSignalVerdict::Inconsistent
            }
            Ok(None) => FreshSignalVerdict::None,
            Ok(Some(id)) => {
                match self
                    .peers
                    .prepare_remote_fresh_prediction(
                        from_node_id,
                        id,
                        candidates,
                        candidate_sources,
                        candidates_expires_at_ms,
                    )
                    .await
                {
                    crate::peer::RemoteFreshAdmission::Accepted => FreshSignalVerdict::Accepted(id),
                    crate::peer::RemoteFreshAdmission::AlreadyRecorded => {
                        self.peers
                            .record_direct_event(
                                from_node_id,
                                "fresh_prediction_retry",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "offer is an idempotent retry of the committed fresh-mapping prediction {id:?}; candidates are not re-applied"
                                ),
                            )
                            .await;
                        FreshSignalVerdict::AlreadyRecorded(id)
                    }
                    crate::peer::RemoteFreshAdmission::PayloadMismatch => {
                        self.peers
                            .record_direct_event(
                                from_node_id,
                                "fresh_prediction_payload_mismatch",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "offer retries the committed fresh-mapping prediction {id:?} with a different candidate payload/expiry; rejected"
                                ),
                            )
                            .await;
                        FreshSignalVerdict::PayloadMismatch(id)
                    }
                    crate::peer::RemoteFreshAdmission::Stale => {
                        self.peers
                            .record_direct_event(
                                from_node_id,
                                "fresh_prediction_stale",
                                None,
                                Some(candidates.len()),
                                None,
                                format!(
                                    "offer carried a superseded fresh-mapping prediction {id:?}; candidates ignored"
                                ),
                            )
                            .await;
                        FreshSignalVerdict::Stale
                    }
                }
            }
        };
        let (candidate_apply_result, fresh_punch, frozen_targets) = match fresh_verdict {
            FreshSignalVerdict::None => (
                self.peers
                    .add_candidates_with_metadata(
                        from_node_id,
                        candidates,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                    )
                    .await,
                None,
                None,
            ),
            FreshSignalVerdict::Accepted(id) => {
                let apply_result = self
                    .peers
                    .apply_remote_fresh_candidates(
                        from_node_id,
                        id,
                        candidates,
                        candidate_sources,
                        candidate_generation,
                        candidates_expires_at_ms,
                    )
                    .await;
                if apply_result != CandidateSetApplyResult::Applied {
                    // PeerMissing, empty, expired or a stale candidate
                    // generation: the fresh ID is NOT consumed so the same
                    // signal retried later (after the peer registers, for
                    // example) still applies.
                    self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_not_applied",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "fresh prediction {id:?} was not applied ({apply_result:?}); the fresh identity stays unconsumed"
                            ),
                        )
                        .await;
                    (apply_result, None, None)
                } else if self
                    .peers
                    .commit_remote_fresh_prediction(from_node_id, id)
                    .await
                {
                    // The identity is committed with an immutable snapshot:
                    // the punch targets are frozen from THAT snapshot.
                    let frozen = self
                        .freeze_fresh_punch_targets(from_node_id, id)
                        .await;
                    (apply_result, Some(id), frozen)
                } else {
                    // The commit lost the CAS to a newer identity: roll this
                    // apply's candidates back so they cannot pollute the
                    // shared candidate set, and start no punch.
                    self.peers
                        .rollback_remote_fresh_apply(from_node_id, id)
                        .await;
                    self.peers
                        .record_direct_event(
                            from_node_id,
                            "fresh_prediction_superseded",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "fresh prediction {id:?} was applied but a newer identity committed first; its candidates were rolled back and no punch starts from it"
                            ),
                        )
                        .await;
                    (CandidateSetApplyResult::IgnoredStale, None, None)
                }
            }
            FreshSignalVerdict::AlreadyRecorded(id) => {
                // The candidates were applied by the first attempt; the punch
                // may still start from the committed snapshot.
                let frozen = self.freeze_fresh_punch_targets(from_node_id, id).await;
                (CandidateSetApplyResult::Applied, Some(id), frozen)
            }
            FreshSignalVerdict::PayloadMismatch(id) => {
                debug!(
                    "Fresh-mapping prediction {id:?} from {from_node_id} was rejected: the retry payload differs from the committed snapshot"
                );
                (CandidateSetApplyResult::IgnoredStale, None, None)
            }
            FreshSignalVerdict::Stale | FreshSignalVerdict::Inconsistent => {
                // The current candidate set stays authoritative; only the
                // handshake below may proceed.
                (CandidateSetApplyResult::IgnoredStale, None, None)
            }
        };
        (fresh_verdict, candidate_apply_result, fresh_punch, frozen_targets)
    }

    async fn run_control_event_loop(
        &mut self,
        relay_started: &mut bool,
        network_inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) {
        // Process control events until shutdown is requested.
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut task_shutdown_rx = self.task_manager.shutdown_rx();
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
                event = self.control_rx.recv() => {
                    let Some(event) = event else {
                        warn!("Control event channel closed");
                        break;
                    };
                    match event {
                ControlEvent::Registered {
                    node_id,
                    virtual_ip: _,
                    cidr: _,
                    relay_servers,
                    relay_catalog,
                } => {
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
                            debug!("No relay servers advertised by control plane");
                            continue;
                        }
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
            inbound_tx: network_inbound_tx.clone(),
            control: self.control.clone(),
            allow_insecure_plaintext,
            ca_cert_path: self.config.relay.ca_cert_path.clone(),
        })
        .await;
                    }
                }

                ControlEvent::PeerJoined(peer_info) => {
                    info!(
                        "Peer joined: {} ({})",
                        peer_info.node_id, peer_info.virtual_ip
                    );
                    self.peers.add_peer(&peer_info).await;

                    if peer_info.online {
                        let mut sent_handshake_offer = false;
                        match self.maybe_initiate_handshake(&peer_info).await {
                            Ok(punch_at_ms) => {
                                sent_handshake_offer = punch_at_ms.is_some();
                                self.start_hole_punch_at(&peer_info.node_id, punch_at_ms, None, None).await;
                            }
                            Err(err) => {
                                warn!(
                                    "Failed to initiate WireGuard handshake with {}: {err}",
                                    peer_info.node_id
                                );
                                self.start_hole_punch(&peer_info.node_id).await;
                            }
                        }
                        if !sent_handshake_offer {
                            self.publish_current_candidates_to_peer(
                                &peer_info.node_id,
                                "peer joined",
                            )
                            .await;
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
                    } else {
                        debug!(
                            "Peer {} is currently offline; keeping it in diagnostics without starting traversal",
                            peer_info.node_id
                        );
                    }
                }

                ControlEvent::PeerUpdated(peer_info) => {
                    let previous = self.peers.get_connection(&peer_info.node_id).await;
                    let update = self.peers.add_peer(&peer_info).await;
                    if !peer_info.online {
                        self.transport.remove_session(&peer_info.node_id).await;
                        self.pending_handshakes
                            .lock()
                            .await
                            .clear_peer(&peer_info.node_id);
                        self.punch_attempts.cancel(&peer_info.node_id);
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            udp.detach_dynamic_punch_socket(&peer_info.node_id, "peer_offline")
                                .await;
                            // The peer is gone: its pending probes must not be
                            // matched or re-inserted by late ACKs, so the
                            // cleanup epoch moves on while the probes drop.
                            udp.clear_pending_probes_for_peer(&peer_info.node_id)
                                .await;
                        }
                        if self.dns.is_enabled() {
                            if let Some(previous) = previous.as_ref() {
                                self.dns.unregister(&previous.virtual_ip).await;
                            } else {
                                self.dns.unregister(&peer_info.virtual_ip).await;
                            }
                        }
                        debug!(
                            "Peer {} is offline according to control plane; cleared active sessions and skipped traversal",
                            peer_info.node_id
                        );
                        continue;
                    }
                    if update.public_key_changed {
                        self.transport.remove_session(&peer_info.node_id).await;
                        self.pending_handshakes
                            .lock()
                            .await
                            .clear_peer(&peer_info.node_id);
                        info!(
                            "Peer {} public key changed; discarded the old WireGuard session",
                            peer_info.node_id
                        );
                        // A changed public key is a new peer incarnation: the
                        // old punch owner, pending probe ownership, fresh
                        // model and every dynamic socket belong to the old
                        // identity and must not keep mutating state or send
                        // to the old binding.
                        self.punch_attempts.cancel(&peer_info.node_id);
                        self.peers
                            .clear_fresh_mapping(&peer_info.node_id, "public_key_changed")
                            .await;
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            udp.detach_dynamic_punch_socket(
                                &peer_info.node_id,
                                "public_key_changed",
                            )
                            .await;
                            udp.clear_pending_probes_for_peer(&peer_info.node_id)
                                .await;
                        }
                    } else if update.endpoint_changed {
                        // The peer moved to a different public endpoint:
                        // fresh generations aimed at the old endpoint must be
                        // invalidated so no old task keeps committing toward
                        // it.  The old dynamic socket itself keeps working as
                        // the peer's current mapping until a new generation
                        // commits or peer-level cleanup runs (the state
                        // machine preserves it on failure).
                        self.punch_attempts.cancel(&peer_info.node_id);
                        self.peers
                            .clear_fresh_mapping(&peer_info.node_id, "endpoint_changed")
                            .await;
                        if let Some(udp) = self.udp_transport.read().await.clone() {
                            udp.clear_pending_probes_for_peer(&peer_info.node_id)
                                .await;
                        }
                    }
                    let was_offline = previous.as_ref().is_some_and(|peer| !peer.online);
                    if (update.virtual_ip_changed || was_offline) && self.dns.is_enabled() {
                        if let Some(previous) = previous {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                        self.dns
                            .register(
                                &peer_info.node_id,
                                &peer_info.virtual_ip,
                                Some(&peer_info.node_id),
                            )
                            .await;
                    }
                    let mut sent_handshake_offer = false;
                    match self.maybe_initiate_handshake(&peer_info).await {
                        Ok(punch_at_ms) => {
                            sent_handshake_offer = punch_at_ms.is_some();
                            self.start_hole_punch_at(&peer_info.node_id, punch_at_ms, None, None).await;
                        }
                        Err(err) => {
                            warn!(
                                "Failed to refresh WireGuard handshake with {} after peer update: {err}",
                                peer_info.node_id
                            );
                            self.start_hole_punch(&peer_info.node_id).await;
                        }
                    }
                    if !sent_handshake_offer {
                        self.publish_current_candidates_to_peer(
                            &peer_info.node_id,
                            "peer updated",
                        )
                        .await;
                    }
                }

                ControlEvent::PeerLeft(node_id) => {
                    info!("Peer left: {}", node_id);
                    if let Some(previous) = self.peers.get_connection(&node_id).await {
                        if self.dns.is_enabled() {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                    }
                    self.transport.remove_session(&node_id).await;
                    self.pending_handshakes.lock().await.clear_peer(&node_id);
                    self.punch_attempts.cancel(&node_id);
                    self.peers.remove_peer(&node_id).await;
                    if let Some(udp) = self.udp_transport.read().await.clone() {
                        udp.detach_dynamic_punch_socket(&node_id, "peer_left").await;
                        // Pending probes of the departed peer are dropped and
                        // the cleanup epoch moves on: a late ACK handler can
                        // neither match nor re-insert them.
                        udp.clear_pending_probes_for_peer(&node_id).await;
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
                } => {
                    info!(
                        "Received peer offer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_offer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received offer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_init.len()
                            ),
                        )
                        .await;
                    // Fresh-prediction verification happens BEFORE any
                    // candidate state is touched: a superseded prediction
                    // must not pollute the candidate set, while the handshake
                    // itself is still handled below.  The prepare/apply/commit
                    // transaction is shared with the answer path.
                    let (_fresh_verdict, candidate_apply_result, fresh_punch, frozen_targets) = self
                        .fresh_prediction_transaction(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                        )
                        .await;
                    if !handshake_init.is_empty() {
                        if let Err(err) = self
                            .handle_peer_offer(
                                &from_node_id,
                                &candidates,
                                &handshake_init,
                                punch_at_ms,
                                punch_at_server_ms,
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
                            )
                            .await
                        {
                            warn!("Failed to handle peer offer from {from_node_id}: {err}");
                        }
                    }
                    if candidate_signal_starts_synchronized_punch(
                        &handshake_init,
                        candidate_apply_result,
                    ) {
                        self.start_hole_punch_at(
                            &from_node_id,
                            punch_at_ms,
                            fresh_punch,
                            frozen_targets,
                        )
                        .await;
                    } else {
                        debug!(
                            "Skipping synchronized punch for rejected candidate-only offer from {from_node_id}: {candidate_apply_result:?}"
                        );
                    }
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
                } => {
                    info!(
                        "Received peer answer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_answer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received answer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_response.len()
                            ),
                        )
                        .await;
                    // Fresh-prediction verification happens BEFORE any
                    // candidate state is touched (see the offer path).
                    let (_fresh_verdict, candidate_apply_result, fresh_punch, frozen_targets) = self
                        .fresh_prediction_transaction(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                        )
                        .await;
                    if !handshake_response.is_empty() {
                        if let Err(err) = self
                            .handle_peer_answer(
                                &from_node_id,
                                &handshake_response,
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
                            )
                            .await
                        {
                            warn!("Failed to handle peer answer from {from_node_id}: {err}");
                        }
                    }
                    if candidate_signal_starts_synchronized_punch(
                        &handshake_response,
                        candidate_apply_result,
                    ) {
                        self.start_hole_punch_at(
                            &from_node_id,
                            punch_at_ms,
                            fresh_punch,
                            frozen_targets,
                        )
                        .await;
                    } else {
                        debug!(
                            "Skipping synchronized punch for rejected candidate-only answer from {from_node_id}: {candidate_apply_result:?}"
                        );
                    }
                }

                ControlEvent::PeerReflexive {
                    from_node_id,
                    observed_endpoint,
                    punch_at_ms,
                } => {
                    let already_direct = self
                        .peers
                        .should_defer_relay_assisted_punch(&from_node_id)
                        .await;
                    let local_candidate_changed = self
                        .add_local_peer_reflexive_candidate(&observed_endpoint)
                        .await;
                    if let Ok(observed_addr) = observed_endpoint.parse::<SocketAddr>() {
                        self.peers
                            .record_fresh_mapping_prediction_result(&from_node_id, observed_addr)
                            .await;
                    }
                    let punch_at_ms =
                        punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms()));
                    let (candidates, candidate_sources) =
                        self.current_local_candidate_set().await;
                    let selected_remote_endpoint = self
                        .peers
                        .selected_direct_endpoint_for_consent(&from_node_id)
                        .await;
                    let schedule_punch = !already_direct;
                    let skip_reason = if already_direct {
                        Some("direct_confirmed_healthy")
                    } else {
                        None
                    };
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_reflexive_received",
                            observed_endpoint.parse().ok(),
                            Some(candidates.len()),
                            None,
                            format!(
                                "peer observed our UDP source as {observed_endpoint}; already_advertised={} already_direct={already_direct} selected_remote_endpoint={:?} schedule_punch={schedule_punch} skip_reason={skip_reason:?}",
                                !local_candidate_changed,
                                selected_remote_endpoint,
                            ),
                        )
                        .await;
                    if already_direct {
                        continue;
                    }
                    if local_candidate_changed && !candidates.is_empty() {
                        if let Err(err) = self
                            .control
                            .send_peer_offer_with_sources_and_punch_at(
                                &from_node_id,
                                &candidates,
                                &candidate_sources,
                                &[],
                                punch_at_ms,
                                None,
                            )
                            .await
                        {
                            warn!(
                                "Failed to re-advertise peer-reflexive local candidate to {from_node_id}: {err}"
                            );
                        } else {
                            self.peers
                                .record_direct_event(
                                    &from_node_id,
                                    "peer_reflexive_offer_sent",
                                    observed_endpoint.parse().ok(),
                                    Some(candidates.len()),
                                    None,
                                    "re-advertised local candidates after peer-reflexive observation",
                                )
                                .await;
                        }
                    } else if !local_candidate_changed {
                        self.peers
                            .record_direct_event(
                                &from_node_id,
                                "peer_reflexive_offer_skipped",
                                observed_endpoint.parse().ok(),
                                Some(candidates.len()),
                                None,
                                "peer-reflexive candidate already advertised; skipped full offer re-advertisement",
                            )
                            .await;
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms, None, None).await;
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
                    }
                }
            }
        }
    }
}
