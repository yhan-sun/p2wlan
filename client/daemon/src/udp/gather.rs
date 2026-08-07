impl UdpTransport {
    /// Return the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DaemonError::Network(format!("failed to read UDP local addr: {e}")))
    }

    /// Gather ICE-style candidate endpoints for this UDP socket.
    pub async fn gather_candidates(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<Vec<String>> {
        let report = self
            .gather_candidate_report(stun_servers, stun_timeout)
            .await?;

        Ok(report
            .candidates
            .into_iter()
            .map(|candidate| candidate.endpoint.to_string())
            .collect())
    }

    /// Gather ICE-style candidates plus STUN/NAT behavior diagnostics.
    pub async fn gather_candidate_report(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let config = IceConfig {
            stun_servers,
            stun_timeout,
            gather_host: self.peers.gather_host_candidates().await,
            gather_srflx: true,
        };

        let mut report = gather_candidate_report(&self.socket, &config)
            .await
            .map_err(|e| DaemonError::Network(format!("ICE candidate gathering failed: {e}")))?;

        self.set_socket_pool_active(socket_pool_is_eligible(&report));
        self.append_pool_socket_candidates_direct(&mut report, &config)
            .await;
        Ok(report)
    }

    /// Gather candidates while `run_inbound` owns all reads from the UDP socket.
    pub async fn gather_candidate_report_live(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let local_addr = self.local_addr()?;
        let mut observations = Vec::with_capacity(stun_servers.len());

        for server in &stun_servers {
            if server.is_ipv4() != local_addr.is_ipv4() {
                continue;
            }
            observations.push(
                self.query_stun_live_on_socket(&self.socket, *server, stun_timeout)
                    .await,
            );
        }

        let mut report = candidate_report_from_observations(
            local_addr,
            self.peers.gather_host_candidates().await,
            observations,
        );
        self.set_socket_pool_active(socket_pool_is_eligible(&report));
        self.append_pool_socket_candidates_live(&mut report, &stun_servers, stun_timeout)
            .await;
        Ok(report)
    }

    async fn query_stun_live_on_socket(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        stun_timeout: Duration,
    ) -> StunObservation {
        let started = Instant::now();
        let mut request = StunMessage::binding_request();
        request.add_attribute(StunAttribute::Software("P2WLAN/0.1".to_string()));
        let transaction_id = request.transaction_id;
        let encoded = request.encode();
        let (response_tx, response_rx) = oneshot::channel();

        self.stun_waiters
            .lock()
            .await
            .insert(transaction_id, response_tx);

        let result = async {
            socket
                .send_to(&encoded, server)
                .await
                .map_err(|error| format!("send_to failed: {error}"))?;
            let (data, source) = timeout(stun_timeout, response_rx)
                .await
                .map_err(|_| format!("no response from {server} after {stun_timeout:?}"))?
                .map_err(|_| "STUN response dispatcher closed".to_string())?;
            if source != server {
                return Err(format!(
                    "response source mismatch: expected {server}, received {source}"
                ));
            }
            let response = StunMessage::decode(&data)
                .map_err(|error| format!("invalid STUN response: {error}"))?;
            if response.transaction_id != transaction_id {
                return Err("STUN transaction ID mismatch".to_string());
            }
            if response.msg_type != BINDING_RESPONSE {
                if let Some((code, reason)) = response.get_error_code() {
                    return Err(format!("STUN error response: {code} {reason}"));
                }
                return Err(format!(
                    "unexpected STUN message type: 0x{:04X}",
                    response.msg_type
                ));
            }
            response
                .get_reflexive_address()
                .ok_or_else(|| "STUN response has no mapped address".to_string())
        }
        .await;

        self.stun_waiters.lock().await.remove(&transaction_id);
        match result {
            Ok(mapped_address) => StunObservation {
                server: server.to_string(),
                mapped_address: Some(mapped_address.to_string()),
                rtt_ms: Some(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
                error: None,
            },
            Err(error) => StunObservation {
                server: server.to_string(),
                mapped_address: None,
                rtt_ms: None,
                error: Some(error),
            },
        }
    }

    async fn append_pool_socket_candidates_direct(
        &self,
        report: &mut CandidateGatherReport,
        config: &IceConfig,
    ) {
        if self.socket_count() <= 1 {
            return;
        }

        let servers = pool_stun_servers(&config.stun_servers, self.local_addr().ok());
        for (socket_index, socket) in self.active_sockets().iter().enumerate().skip(1) {
            let observations = self
                .query_stun_direct(socket, &servers, config.stun_timeout)
                .await;
            let Some(local_addr) = socket.local_addr().ok() else {
                continue;
            };
            let pool_report = candidate_report_from_observations(local_addr, false, observations);
            self.append_pool_candidates(report, pool_report.candidates, socket_index)
                .await;
        }
    }

    async fn append_pool_socket_candidates_live(
        &self,
        report: &mut CandidateGatherReport,
        stun_servers: &[SocketAddr],
        stun_timeout: Duration,
    ) {
        if self.socket_count() <= 1 {
            return;
        }

        let servers = pool_stun_servers(stun_servers, self.local_addr().ok());
        for (socket_index, socket) in self.active_sockets().iter().enumerate().skip(1) {
            let mut observations = Vec::with_capacity(servers.len());
            for server in &servers {
                observations.push(
                    self.query_stun_live_on_socket(socket, *server, stun_timeout)
                        .await,
                );
            }
            let Some(local_addr) = socket.local_addr().ok() else {
                continue;
            };
            let pool_report = candidate_report_from_observations(local_addr, false, observations);
            self.append_pool_candidates(report, pool_report.candidates, socket_index)
                .await;
        }
    }

    async fn query_stun_direct(
        &self,
        socket: &UdpSocket,
        servers: &[SocketAddr],
        stun_timeout: Duration,
    ) -> Vec<StunObservation> {
        if socket.local_addr().is_err() {
            return Vec::new();
        }
        let client = StunClient::with_timeout(stun_timeout);
        let mut observations = Vec::with_capacity(servers.len());
        for server in servers {
            let started = Instant::now();
            let observation = match client.binding_request(socket, *server).await {
                Ok(response) => StunObservation {
                    server: server.to_string(),
                    mapped_address: response
                        .reflexive_address
                        .map(|address| address.to_string()),
                    rtt_ms: Some(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
                    error: None,
                },
                Err(error) => StunObservation {
                    server: server.to_string(),
                    mapped_address: None,
                    rtt_ms: None,
                    error: Some(error.to_string()),
                },
            };
            observations.push(observation);
        }
        observations
    }

    async fn append_pool_candidates(
        &self,
        report: &mut CandidateGatherReport,
        candidates: Vec<p2pnet_nat::IceCandidate>,
        socket_index: usize,
    ) {
        let discovered_stun_mappings = merge_pool_candidates(report, candidates);
        if discovered_stun_mappings > 0 {
            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.stun_mappings_discovered = metrics
                    .stun_mappings_discovered
                    .saturating_add(discovered_stun_mappings)
            })
            .await;
        }
    }
}

fn merge_pool_candidates(
    report: &mut CandidateGatherReport,
    candidates: Vec<p2pnet_nat::IceCandidate>,
) -> u64 {
    let mut discovered_stun_mappings = 0u64;
    for candidate in candidates {
        let is_stun_observed =
            candidate.source == p2pnet_nat::CandidateSource::StunObserved;
        if is_stun_observed {
            discovered_stun_mappings = discovered_stun_mappings.saturating_add(1);
        }

        let endpoint = candidate.endpoint.to_string();
        if let Some(existing) = report
            .candidates
            .iter_mut()
            .find(|existing| existing.endpoint.to_string() == endpoint)
        {
            // A later pool socket can observe a port that an earlier socket
            // merely predicted. Keep the endpoint once, but promote the
            // evidence so signaling and probe ranking treat it as real.
            if is_stun_observed
                && existing.source == p2pnet_nat::CandidateSource::Predicted
            {
                existing.source = p2pnet_nat::CandidateSource::StunObserved;
                existing.candidate_type = candidate.candidate_type;
                existing.priority = existing.priority.max(candidate.priority);
            }
            continue;
        }
        report.candidates.push(candidate);
    }
    discovered_stun_mappings
}
