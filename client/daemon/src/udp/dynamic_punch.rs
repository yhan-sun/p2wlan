use p2pnet_nat::mapping::{
    build_model_for_batch, predict_ports, MappingBatch, MappingObservation, ModelRejection,
    PortModelKind,
};

const MEASUREMENT_SOFTWARE_TAG: &str = "P2WLAN/0.2";

impl UdpTransport {
    /// Bind a brand-new dedicated punch socket for one fresh-mapping generation.
    ///
    /// The socket is intentionally fresh: it has never contacted any observer
    /// or peer, so its next mappings follow the NAT's allocation sequence from
    /// a clean slate.
    pub(crate) async fn bind_fresh_punch_socket(&self) -> Result<(usize, Arc<UdpSocket>)> {
        let bind_addr = match self.socket.local_addr() {
            Ok(addr) if !addr.ip().is_unspecified() => SocketAddr::new(addr.ip(), 0),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|error| {
            DaemonError::Network(format!(
                "failed to bind fresh-mapping punch socket at {bind_addr}: {error}"
            ))
        })?;
        let socket_index = self.next_dynamic_index();
        Ok((socket_index, Arc::new(socket)))
    }

    /// Register a dedicated punch socket with the transport.
    ///
    /// Spawns an inbound reader for the socket so STUN responses, peer
    /// punches and ACKs all flow through the ordinary receive pipeline from
    /// the first measurement request onward.
    pub(crate) async fn attach_dynamic_punch_socket(
        &self,
        peer_id: &str,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        network_generation: u64,
        punch_generation: u64,
    ) -> Result<()> {
        let evict = {
            let dynamic = self.dynamic_sockets.lock().await;
            if dynamic.len() < MAX_DYNAMIC_PUNCH_SOCKETS {
                None
            } else {
                let mut candidates = dynamic
                    .iter()
                    .map(|(index, entry)| (*index, entry.peer_id.clone(), entry.created_at))
                    .collect::<Vec<_>>();
                candidates.sort_by_key(|(_, _, created_at)| *created_at);
                drop(dynamic);
                let mut evict = None;
                for (index, candidate_peer, _) in candidates {
                    if !self.peers.is_direct(&candidate_peer).await {
                        evict = Some((index, candidate_peer));
                        break;
                    }
                }
                evict
            }
        };
        if let Some((evict_index, evicted_peer)) = evict {
            let evicted = self
                .dynamic_sockets
                .lock()
                .await
                .remove(&evict_index)
                .expect("evicted dynamic socket");
            self.detach_dynamic_entry(evicted, "dynamic_socket_cap_reached")
                .await;
            // Drop any affinity that pointed at the evicted socket so the
            // peer cleanly falls back to its pool socket.  Direct peers are
            // never evicted, so this only affects peers that were already
            // probing or reconnecting.
            let mut affinity = self.peer_socket_affinity.lock().await;
            if affinity.get(&evicted_peer) == Some(&evict_index) {
                affinity.remove(&evicted_peer);
            }
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let reader = {
            let transport = self.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                transport
                    .run_dynamic_inbound_socket(socket_index, socket, shutdown_rx)
                    .await
            })
        };
        {
            let mut dynamic = self.dynamic_sockets.lock().await;
            dynamic.insert(
                socket_index,
                DynamicPunchSocket {
                    socket_index,
                    socket: socket.clone(),
                    peer_id: peer_id.to_string(),
                    network_generation,
                    punch_generation,
                    created_at: Instant::now(),
                    shutdown_tx,
                    reader,
                },
            );
        }
        self.dynamic_socket_diagnostics.lock().await.insert(
            socket_index,
            UdpSocketPoolMemberDiagnostics {
                socket_index,
                ..Default::default()
            },
        );
        debug!(
            "Attached fresh-mapping punch socket index={socket_index} local={} peer={peer_id} network_generation={network_generation} punch_generation={punch_generation}",
            format_optional_endpoint(socket.local_addr().ok())
        );
        Ok(())
    }

    /// Remove a dynamic socket entry and stop its reader.
    async fn detach_dynamic_entry(&self, entry: DynamicPunchSocket, reason: &str) {
        entry.shutdown_tx.send_replace(true);
        entry.reader.abort();
        self.dynamic_socket_diagnostics.lock().await.remove(&entry.socket_index);
        debug!(
            "Detached fresh-mapping punch socket index={} local={} peer={} network_generation={} punch_generation={} reason={reason}",
            entry.socket_index,
            format_optional_endpoint(entry.local_endpoint()),
            entry.peer_id,
            entry.network_generation,
            entry.punch_generation
        );
    }

    /// Detach the dedicated punch socket for a peer, if any.
    pub(crate) async fn detach_dynamic_punch_socket(&self, peer_id: &str, reason: &str) {
        let index = {
            let mut affinity = self.peer_socket_affinity.lock().await;
            match affinity.get(peer_id).copied() {
                Some(index) if index >= DYNAMIC_SOCKET_INDEX_BASE => {
                    affinity.remove(peer_id);
                    Some(index)
                }
                _ => None,
            }
        };
        let entry = {
            let mut dynamic = self.dynamic_sockets.lock().await;
            let index = match index {
                Some(index) => Some(index),
                None => dynamic
                    .iter()
                    .find(|(_, entry)| entry.peer_id == peer_id)
                    .map(|(index, _)| *index),
            };
            index.and_then(|index| dynamic.remove(&index))
        };
        if let Some(entry) = entry {
            self.detach_dynamic_entry(entry, reason).await;
        }
    }

    /// Detach every dedicated punch socket (daemon shutdown / teardown).
    pub(crate) async fn detach_all_dynamic_punch_sockets(&self, reason: &str) {
        let entries = self
            .dynamic_sockets
            .lock()
            .await
            .drain()
            .map(|(_, entry)| entry)
            .collect::<Vec<_>>();
        self.dynamic_socket_diagnostics.lock().await.clear();
        self.peer_socket_affinity
            .lock()
            .await
            .retain(|_, index| *index < DYNAMIC_SOCKET_INDEX_BASE);
        for entry in entries {
            self.detach_dynamic_entry(entry, reason).await;
        }
    }

    /// Measure the NAT's public port sequence with a dedicated socket.
    ///
    /// All requests are sent back-to-back in a fixed order; responses may
    /// arrive in any order, but the observations are returned sorted by send
    /// sequence so the model can never be fooled by response reordering.
    /// Between the last request and the caller's first peer-directed punch
    /// this socket is exclusively owned by the generation: no refresh,
    /// maintainer or relay traffic may consume the next mapping.
    async fn measure_fresh_mapping_batch(
        &self,
        socket: &Arc<UdpSocket>,
        observers: &[SocketAddr],
        stun_timeout: Duration,
    ) -> Vec<MappingObservation> {
        let started_ms = monotonic_millis();
        let mut sent = Vec::with_capacity(observers.len());
        for (sequence, observer) in observers.iter().enumerate() {
            let mut request = StunMessage::binding_request();
            request.add_attribute(StunAttribute::Software(MEASUREMENT_SOFTWARE_TAG.to_string()));
            let transaction_id = request.transaction_id;
            let encoded = request.encode();
            let (response_tx, response_rx) = oneshot::channel();
            self.stun_waiters.lock().await.insert(transaction_id, response_tx);
            let sent_at_ms = monotonic_millis();
            match socket.send_to(&encoded, observer).await {
                Ok(_) => {
                    sent.push((sequence, *observer, transaction_id, response_rx, sent_at_ms));
                }
                Err(error) => {
                    self.stun_waiters.lock().await.remove(&transaction_id);
                    debug!(
                        "Fresh-mapping STUN send {sequence} to {observer} failed: {error}"
                    );
                }
            }
        }

        let mut observations = Vec::with_capacity(sent.len());
        for (sequence, observer, transaction_id, response_rx, sent_at_ms) in sent {
            let budget_elapsed = monotonic_millis().saturating_sub(started_ms);
            let remaining_budget = FRESH_MAPPING_MEASURE_BUDGET
                .as_millis()
                .saturating_sub(budget_elapsed as u128);
            let per_sample_timeout = stun_timeout
                .min(FRESH_MAPPING_STUN_TIMEOUT)
                .min(Duration::from_millis(remaining_budget.min(u128::from(u64::MAX)) as u64));
            let result = tokio::time::timeout(per_sample_timeout, response_rx).await;
            let responded_at_ms = monotonic_millis();
            let parsed = match result {
                Ok(Ok((data, source))) if source == observer => {
                    match StunMessage::decode(&data) {
                        Ok(response)
                            if response.transaction_id == transaction_id
                                && response.msg_type == p2pnet_nat::BINDING_RESPONSE =>
                        {
                            response.get_reflexive_address()
                        }
                        Ok(_) => None,
                        Err(_) => None,
                    }
                }
                _ => None,
            };
            if let Some(observed) = parsed {
                observations.push(MappingObservation {
                    sequence: sequence as u16,
                    observer,
                    observed,
                    sent_at_ms,
                    responded_at_ms,
                    local_endpoint: socket.local_addr().ok().unwrap_or_else(|| {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                    }),
                });
            } else {
                debug!(
                    "Fresh-mapping STUN {sequence} to {observer} got no usable response within {:?}",
                    per_sample_timeout
                );
            }
        }
        observations.sort_by_key(|observation| observation.sequence);
        observations
    }

    /// Run one atomic fresh-mapping punch generation for a peer.
    ///
    /// 1. Bind a fresh dedicated socket (never used before).
    /// 2. Measure 3-4 distinct STUN observers in send order.
    /// 3. Model the port sequence and build the rank-ordered prediction.
    /// 4. Punch the peer's stable public endpoint from the same socket,
    ///    creating the peer-facing mapping predicted by the model.
    ///
    /// The dedicated socket stays attached for the peer, so a successful
    /// Direct path continues to use it (and only it) as the data socket.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_fresh_mapping_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        stable_targets: &[SocketAddr],
        probe_interval: Duration,
        attempts: u32,
    ) -> FreshMappingOutcome {
        if !self.peers.local_nat_requires_fresh_mapping_punch().await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat);
        }
        let stable_targets = stable_targets
            .iter()
            .copied()
            .filter(|endpoint| fresh_mapping_target_eligible(*endpoint))
            .collect::<Vec<_>>();
        if stable_targets.is_empty() {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::NoStablePeerEndpoint);
        }
        if self.local_node_id.is_none()
            || self.peers.probe_key_for_peer(peer_id).await.is_none()
        {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::MissingProbeKey);
        }
        if self.peers.is_direct(peer_id).await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        // A new generation owns a brand-new socket: the previous dedicated
        // socket's mapping sequence is no longer fresh and must not stay
        // pinned to the peer.
        self.detach_dynamic_punch_socket(peer_id, "new_generation").await;

        let network_generation = self.peers.current_network_generation().await;
        let punch_generation = self.peers.next_punch_generation(peer_id).await;
        let (socket_index, socket) = match self.bind_fresh_punch_socket().await {
            Ok(bound) => bound,
            Err(error) => {
                warn!("Fresh-mapping punch socket bind failed for peer {peer_id}: {error}");
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BindFailed);
            }
        };
        if let Err(error) = self
            .attach_dynamic_punch_socket(
                peer_id,
                socket_index,
                socket.clone(),
                network_generation,
                punch_generation,
            )
            .await
        {
            warn!("Failed to attach fresh-mapping punch socket for peer {peer_id}: {error}");
            return FreshMappingOutcome::Rejected(FreshMappingRejection::BindFailed);
        }

        let observers = observers
            .iter()
            .copied()
            .filter(|observer| observer.is_ipv4())
            .take(FRESH_MAPPING_OBSERVERS_PER_BATCH)
            .collect::<Vec<_>>();
        if observers.len() < 3 {
            self.detach_dynamic_punch_socket(peer_id, "insufficient_observers").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
        }

        let local_endpoint = socket
            .local_addr()
            .ok()
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_generation_started",
                None,
                Some(observers.len()),
                None,
                format!(
                    "punch_generation={punch_generation} network_generation={network_generation} socket_local={local_endpoint} socket_index={socket_index} observers={} targets={}",
                    observers.len(),
                    stable_targets.len()
                ),
            )
            .await;

        let started_ms = monotonic_millis();
        let observations = self
            .measure_fresh_mapping_batch(&socket, &observers, stun_timeout)
            .await;
        let finished_ms = monotonic_millis();
        let batch = MappingBatch {
            generation: punch_generation,
            network_generation,
            socket_identity: local_endpoint,
            observations,
            started_at_ms: started_ms,
            finished_at_ms: finished_ms,
        };
        let sample_count = batch.successful_samples();

        for observation in &batch.observations {
            info!(
                event = "fresh_mapping_observer",
                peer_id = %peer_id,
                network_generation = network_generation,
                punch_generation = punch_generation,
                socket_local = %observation.local_endpoint,
                sequence = observation.sequence,
                observer = %observation.observer,
                srflx = %observation.observed,
                rtt_ms = observation.rtt_ms().unwrap_or(0),
                "fresh_mapping_observer peer_id={} punch_generation={} seq={} observer={} srflx={} rtt_ms={}",
                peer_id,
                punch_generation,
                observation.sequence,
                observation.observer,
                observation.observed,
                observation.rtt_ms().unwrap_or(0)
            );
        }

        if sample_count < 3 {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    "insufficient STUN samples for a mapping model",
                )
                .await;
            self.detach_dynamic_punch_socket(peer_id, "insufficient_samples").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
        }

        if batch.public_ip().is_none() {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    "observed public IP changed across the measurement batch",
                )
                .await;
            self.detach_dynamic_punch_socket(peer_id, "public_ip_changed").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
        }

        let now_ms = monotonic_millis();
        let model = match build_model_for_batch(&batch, FRESH_MAPPING_MODEL_MAX_AGE, now_ms) {
            Ok(model) => model,
            Err(ModelRejection::BatchStale) => {
                self.detach_dynamic_punch_socket(peer_id, "batch_stale").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
            }
            Err(ModelRejection::InconsistentBatch) => {
                self.detach_dynamic_punch_socket(peer_id, "inconsistent_batch").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InconsistentBatch);
            }
            Err(ModelRejection::InsufficientSamples) => {
                self.detach_dynamic_punch_socket(peer_id, "insufficient_samples").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
            }
            Err(ModelRejection::PublicIpChanged) => {
                self.detach_dynamic_punch_socket(peer_id, "public_ip_changed").await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
            }
            Err(ModelRejection::NarrowRandom | ModelRejection::NoConsistentStep) => {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "fresh_mapping_rejected",
                        None,
                        Some(sample_count),
                        None,
                        format!(
                            "port sequence is not consistently linear: sequence={:?} deltas={:?}",
                            batch.ordered_ports(),
                            model_deltas(&batch)
                        ),
                    )
                    .await;
                self.detach_dynamic_punch_socket(peer_id, "unpredictable_sequence").await;
                return FreshMappingOutcome::Rejected(
                    FreshMappingRejection::UnpredictableSequence,
                );
            }
        };

        let step = match &model.kind {
            PortModelKind::FixedStep { step } | PortModelKind::Linear { step }
            | PortModelKind::NoisyLinear { step } => Some(*step),
            _ => None,
        };
        if step.is_some_and(|step| u32::from(step.unsigned_abs()) > FRESH_MAPPING_MAX_ABS_STEP as u32) {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    format!(
                        "model step {} exceeds the {FRESH_MAPPING_MAX_ABS_STEP} bound; treating as unpredictable",
                        step.unwrap_or(0)
                    ),
                )
                .await;
            self.detach_dynamic_punch_socket(peer_id, "unpredictable_sequence").await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::UnpredictableSequence);
        }

        let ports = batch.ordered_ports();
        let last = *ports.last().expect("three or more samples");
        let predicted = predict_ports(&model, last);
        let predicted_ports = predicted.iter().map(|candidate| candidate.port).collect::<Vec<_>>();
        let public_ip = batch.public_ip();

        let sequence_label = format!("{:?}", ports);
        let deltas_label = format!("{:?}", model.deltas);
        info!(
            event = "fresh_mapping_model",
            peer_id = %peer_id,
            network_generation = network_generation,
            punch_generation = punch_generation,
            socket_local = %local_endpoint,
            model = ?model.kind,
            confidence = model.confidence,
            sequence = %sequence_label,
            deltas = %deltas_label,
            sample_age_ms = now_ms.saturating_sub(batch.started_at_ms),
            predicted = ?predicted_ports,
            "fresh_mapping_model peer_id={} punch_generation={} model={:?} confidence={} sequence={} deltas={} predicted={:?}",
            peer_id,
            punch_generation,
            model.kind,
            model.confidence,
            sequence_label,
            deltas_label,
            predicted_ports
        );
        self.peers
            .record_fresh_mapping(
                peer_id,
                p2pnet_nat::mapping::PortModel::clone(&model),
                predicted_ports.clone(),
                local_endpoint,
                public_ip,
                punch_generation,
                network_generation,
            )
            .await;

        // Pin the dedicated socket for this peer before punching so every
        // follow-up probe and the future data path use the measured mapping.
        self.remember_peer_socket(peer_id, socket_index).await;

        let first_punch_sent_at_ms = monotonic_millis();
        let mut sent = 0u32;
        for round in 0..attempts {
            for target in &stable_targets {
                match self
                    .send_probe_on_socket(
                        socket_index,
                        socket.clone(),
                        Some(peer_id),
                        *target,
                        true,
                        PendingProbePurpose::ConnectivityCheck,
                    )
                    .await
                {
                    Ok(_) => {
                        sent = sent.saturating_add(1);
                        if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                            sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                        }
                    }
                    Err(error) => {
                        debug!(
                            "Fresh-mapping punch from socket {socket_index} to {} failed: {error}",
                            target
                        );
                    }
                }
                if round + 1 < attempts && !probe_interval.is_zero() {
                    sleep(probe_interval.min(Duration::from_millis(50))).await;
                }
            }
        }
        let last_punch_sent_at_ms = monotonic_millis();

        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_punch_sent",
                stable_targets.first().copied(),
                Some(stable_targets.len()),
                Some(sent),
                format!(
                    "punch_generation={punch_generation} socket_local={local_endpoint} first_sent_ms={first_punch_sent_at_ms} last_sent_ms={last_punch_sent_at_ms} targets={} sent={sent}",
                    stable_targets.len()
                ),
            )
            .await;
        debug!(
            "Fresh-mapping punch generation {punch_generation} sent {sent} probes to peer {peer_id} from {local_endpoint}"
        );

        FreshMappingOutcome::Accepted(Box::new(FreshMappingResult {
            punch_generation,
            network_generation,
            socket_local_endpoint: local_endpoint,
            socket_index,
            model,
            predicted_ports,
            public_ip,
            first_punch_sent_at_ms,
            last_punch_sent_at_ms,
        }))
    }

    /// Probe the peer's candidates from the dedicated punch socket only.
    ///
    /// Used by the synchronized punch flow after a fresh-mapping generation,
    /// so the predictable mapping socket carries the whole candidate sweep
    /// while the other pool sockets stay untouched.
    pub(crate) async fn punch_candidates_from_dynamic_socket(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<PunchSendReport> {
        let Some(index) = self.dynamic_socket_index_for_peer(peer_id).await else {
            return Ok(PunchSendReport::default());
        };
        let Some(socket) = self
            .dynamic_sockets
            .lock()
            .await
            .get(&index)
            .map(|dynamic| dynamic.socket.clone())
        else {
            return Ok(PunchSendReport::default());
        };
        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        let mut packets_sent = 0u32;
        let mut sent_endpoints = HashSet::new();
        for round in schedule {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }
            for candidate in round.endpoints {
                match self
                    .send_probe_on_socket(
                        index,
                        socket.clone(),
                        Some(peer_id),
                        candidate,
                        false,
                        PendingProbePurpose::ConnectivityCheck,
                    )
                    .await
                {
                    Ok(_) => {
                        packets_sent = packets_sent.saturating_add(1);
                        sent_endpoints.insert(candidate);
                        self.peers.record_direct_probe_sent(peer_id, candidate).await;
                        if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                            sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                        }
                    }
                    Err(error) => {
                        debug!(
                            "Dynamic-socket punch to peer {peer_id} candidate {candidate} failed: {error}"
                        );
                    }
                }
            }
        }
        Ok(PunchSendReport {
            packets_sent,
            unique_target_endpoints: u32::try_from(sent_endpoints.len()).unwrap_or(u32::MAX),
        })
    }
}

fn model_deltas(batch: &MappingBatch) -> Vec<i16> {
    let ports = batch.ordered_ports();
    ports
        .windows(2)
        .map(|pair| p2pnet_nat::modular_difference(pair[0], pair[1]))
        .collect()
}

/// Whether a target endpoint may receive a fresh-mapping punch.
///
/// Production filters to real public probe endpoints; unit tests simulate the
/// peer's public side on the loopback NAT address.
fn fresh_mapping_target_eligible(endpoint: SocketAddr) -> bool {
    if is_public_probe_endpoint(endpoint) {
        return true;
    }
    #[cfg(test)]
    {
        endpoint.ip().is_loopback()
    }
    #[cfg(not(test))]
    {
        let _ = endpoint;
        false
    }
}

fn monotonic_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
