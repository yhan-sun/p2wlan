use futures_util::future::join_all;

/// RFC 5780 CHANGE-REQUEST is best-effort: many public STUN services do not
/// implement it. Keep the live probe bounded so it cannot hold up the regular
/// candidate refresh when a server silently drops the request.
const LIVE_FILTERING_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

impl UdpTransport {
    /// Gather the first usable candidate set while the normal inbound reader
    /// owns UDP receives.
    ///
    /// The startup path needs a fresh public candidate before the first
    /// Direct punch. Querying observers serially makes one unreachable STUN
    /// server add its full timeout to the next one; on a real Air/Mini pair
    /// that delayed the public offer by roughly two seconds. This path sends
    /// all observer requests concurrently and keeps the existing reader-owned
    /// receive/transaction validation boundary.
    ///
    /// This function only changes candidate-observation scheduling. Direct is
    /// still promoted exclusively by the encrypted validation ACK path.
    pub async fn gather_candidate_report_live_parallel(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        // Startup must not wait for the slowest configured observer.  The
        // caller publishes this bounded report immediately; the regular
        // candidate-refresh loop performs the same parallel gather with the
        // full configured timeout right afterwards, so a slow observer can
        // enrich later signals without delaying relay-first or Direct.
        self.gather_candidate_report_live_parallel_with_timeout(
            stun_servers,
            stun_timeout.min(crate::DIRECT_STARTUP_STUN_TIMEOUT),
            false,
        )
        .await
    }

    /// Gather the candidate set with the caller's complete observer timeout.
    ///
    /// This is used after the bounded startup window to obtain the full NAT
    /// profile without serializing observers or stealing encrypted datagrams
    /// from the inbound reader.
    pub async fn gather_candidate_report_live_parallel_full(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        self.gather_candidate_report_live_parallel_with_timeout(stun_servers, stun_timeout, true)
            .await
    }

    async fn gather_candidate_report_live_parallel_with_timeout(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
        probe_filtering: bool,
    ) -> Result<CandidateGatherReport> {
        let local_addr = self.local_addr()?;
        let primary_servers = stun_servers
            .iter()
            .copied()
            .filter(|server| server.is_ipv4() == local_addr.is_ipv4())
            .collect::<Vec<_>>();
        let observations = join_all(primary_servers.into_iter().map(|server| async move {
            self.query_stun_live_on_socket(&self.socket, server, stun_timeout)
                .await
        }))
        .await;

        let mut report = candidate_report_from_observations(
            local_addr,
            self.peers.gather_host_candidates().await,
            observations,
        );
        if self.socket_count() > 1 {
            let pool_servers = pool_stun_servers(&stun_servers, Some(local_addr));
            let pool_sockets = self
                .active_sockets()
                .iter()
                .cloned()
                .enumerate()
                .skip(1)
                .collect::<Vec<_>>();
            let pool_reports = join_all(pool_sockets.into_iter().map(|(socket_index, socket)| {
                let pool_servers = pool_servers.clone();
                async move {
                    let observations = join_all(pool_servers.into_iter().map(|server| {
                        let socket = socket.clone();
                        async move {
                            self.query_stun_live_on_socket(&socket, server, stun_timeout)
                                .await
                        }
                    }))
                    .await;
                    let local_addr = socket.local_addr().ok()?;
                    let pool_report = candidate_report_from_observations(
                        local_addr,
                        false,
                        observations,
                    );
                    Some((socket_index, pool_report))
                }
            }))
            .await;

            for (socket_index, pool_report) in pool_reports.into_iter().flatten() {
                // A primary socket can legitimately report no STUN response
                // while another bound socket has a live public mapping.  The
                // old code discarded that distinction: it classified the
                // whole daemon as UDP-blocked and left the pool inactive,
                // even though it had just gathered the 96 real pool targets
                // later offered to the peer.  Keep the observations and
                // promote the profile before deciding whether the pool is
                // usable, so startup Direct and recovery use the same
                // evidence that candidate signaling uses.
                merge_pool_nat_profile(&mut report, &pool_report);
                self.append_pool_candidates(
                    &mut report,
                    pool_report.candidates,
                    socket_index,
                )
                .await;
            }
        }

        // The live gather uses the reader-owned STUN waiter registry instead
        // of reading the UDP socket directly. That means it cannot reuse the
        // ICE module's standalone active-probe helper; run the same bounded
        // CHANGE-REQUEST checks through this transport after the normal
        // observations have produced a profile. Startup deliberately skips
        // this extra round and the full background refresh fills it in.
        if probe_filtering {
            self.probe_live_filtering_behavior(&mut report, &stun_servers, stun_timeout)
                .await;
        }

        // This must happen after pool gathering.  A primary STUN failure is
        // not proof that UDP is blocked when a secondary bound socket has a
        // real server-reflexive mapping.  In that case the pool is the
        // available direct path and must remain active for punch/retry.
        self.set_socket_pool_active(socket_pool_is_eligible(&report));

        if !self.peers.predicted_candidates_enabled_for_gather() {
            report
                .candidates
                .retain(|candidate| candidate.source != p2pnet_nat::CandidateSource::Predicted);
        }
        Ok(report)
    }

    async fn probe_live_filtering_behavior(
        &self,
        report: &mut CandidateGatherReport,
        stun_servers: &[SocketAddr],
        stun_timeout: Duration,
    ) {
        if report.nat_profile.udp_blocked
            || report.nat_profile.mapping_behavior
                != MappingBehavior::EndpointIndependent
            || report.nat_profile.filtering_behavior != FilteringBehavior::Unknown
        {
            return;
        }

        let Some(server) = report.nat_profile.observations.iter().find_map(|observation| {
            let server = observation.server.parse::<SocketAddr>().ok()?;
            (observation.error.is_none()
                && observation.mapped_address.is_some()
                && stun_servers.contains(&server))
            .then_some(server)
        }) else {
            return;
        };
        let timeout = stun_timeout_for_live_filtering_probe(stun_timeout);

        if let Ok(response) = self
            .query_stun_live_response(&self.socket, server, timeout, true, true)
            .await
        {
            if let Some(filtering) = classify_live_filtering_response(server, response.source) {
                report.nat_profile.filtering_behavior = filtering;
                return;
            }
        }

        if let Ok(response) = self
            .query_stun_live_response(&self.socket, server, timeout, false, true)
            .await
        {
            if response.source.ip() == server.ip() && response.source != server {
                report.nat_profile.filtering_behavior = FilteringBehavior::AddressDependent;
            }
        }
    }
}

fn stun_timeout_for_live_filtering_probe(timeout: Duration) -> Duration {
    timeout.min(LIVE_FILTERING_PROBE_TIMEOUT).max(Duration::from_millis(50))
}

fn classify_live_filtering_response(
    server: SocketAddr,
    response_source: SocketAddr,
) -> Option<FilteringBehavior> {
    if response_source.ip() != server.ip() {
        Some(FilteringBehavior::EndpointIndependent)
    } else if response_source != server {
        Some(FilteringBehavior::AddressDependent)
    } else {
        None
    }
}

/// Fold evidence from one socket-pool member into the daemon-level NAT
/// profile.  The primary socket's profile is still authoritative whenever it
/// has evidence of its own.  When it says `UdpBlocked` but a pool member has a
/// real STUN mapping, the correct diagnosis is instead "primary mapping
/// unavailable; pool-backed mapping-dependent Direct is available".
///
/// This is deliberately conservative: it does not invent a port delta or a
/// predicted window from a single pool member.  It only changes the gates
/// needed to keep the proven pool alive and to schedule bounded scatter/retry.
fn merge_pool_nat_profile(
    report: &mut CandidateGatherReport,
    pool_report: &CandidateGatherReport,
) -> bool {
    let observed_endpoints = pool_report
        .candidates
        .iter()
        .filter(|candidate| candidate.source == p2pnet_nat::CandidateSource::StunObserved)
        .filter_map(|candidate| candidate.endpoint.to_string().parse::<SocketAddr>().ok())
        .filter(|endpoint| is_public_probe_endpoint(*endpoint))
        .collect::<Vec<_>>();
    if observed_endpoints.is_empty() {
        return false;
    }

    report
        .nat_profile
        .observations
        .extend(pool_report.nat_profile.observations.iter().cloned());

    if !report.nat_profile.udp_blocked {
        return false;
    }

    let first = observed_endpoints[0];
    let distinct_ips = observed_endpoints
        .iter()
        .map(|endpoint| endpoint.ip())
        .collect::<HashSet<_>>();
    let distinct_ports = observed_endpoints
        .iter()
        .map(|endpoint| endpoint.port())
        .collect::<HashSet<_>>();

    report.nat_profile.udp_blocked = false;
    report.nat_profile.public_endpoint = Some(first.to_string());
    report.nat_profile.public_ip_stable = Some(distinct_ips.len() == 1);
    report.nat_profile.public_port_stable = Some(distinct_ports.len() == 1);
    report.nat_profile.mapping_behavior = p2pnet_nat::MappingBehavior::AddressOrPortDependent;
    report.nat_profile.filtering_behavior =
        p2pnet_nat::FilteringBehavior::Unknown;
    report.nat_profile.likely_symmetric = Some(true);
    report.nat_profile.prediction_candidate = false;
    report.nat_profile.predicted_endpoints.clear();
    report.nat_profile.birthday_candidate = true;
    report.nat_profile.confidence = report.nat_profile.confidence.max(50);
    true
}
