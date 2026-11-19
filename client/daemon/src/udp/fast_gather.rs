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
        self.gather_startup_candidates(stun_servers, stun_timeout, None)
            .await
    }

    pub(crate) async fn gather_startup_candidates(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
        progress: Option<watch::Sender<[Option<SocketAddr>; 2]>>,
    ) -> Result<CandidateGatherReport> {
        self.gather_candidate_report_live_parallel_with_timeout(
            stun_servers,
            stun_timeout.min(crate::DIRECT_STARTUP_STUN_TIMEOUT),
            false,
            true,
            progress,
        )
        .await
    }

    /// Gather the candidate set with the caller's complete observer timeout.
    ///
    /// This is used after the bounded startup window to obtain the full NAT
    /// profile without serializing observers or stealing encrypted datagrams
    /// from the inbound reader. The caller must apply the returned socket-pool
    /// policy only after accepting this report against its candidate snapshot;
    /// gateway discovery can otherwise let an older report finish last.
    pub async fn gather_candidate_report_live_parallel_full(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        self.gather_candidate_report_live_parallel_with_timeout(
            stun_servers,
            stun_timeout,
            true,
            false,
            None,
        )
        .await
    }

    async fn gather_candidate_report_live_parallel_with_timeout(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
        probe_filtering: bool,
        apply_socket_pool_policy: bool,
        progress: Option<watch::Sender<[Option<SocketAddr>; 2]>>,
    ) -> Result<CandidateGatherReport> {
        let local_addr = self.local_addr()?;
        let hosts = self.peers.gather_host_candidates().await;
        let pool_servers = pool_stun_servers(&stun_servers, Some(local_addr));
        let primary = self.gather_socket_observations(
            &self.socket,
            &stun_servers,
            stun_timeout,
            progress.as_ref(),
        );
        let ipv6 = async {
            let socket = self.ipv6_socket.as_ref()?;
            let address = socket.local_addr().ok()?;
            let observations = self
                .gather_socket_observations(socket, &stun_servers, stun_timeout, progress.as_ref())
                .await;
            Some(p2pnet_nat::candidate_report_from_unordered_observations(
                address,
                hosts,
                observations,
            ))
        };
        let pool = join_all(self.active_sockets().iter().enumerate().skip(1).map(
            |(index, socket)| {
                let servers = &pool_servers;
                async move {
                    let address = socket.local_addr().ok()?;
                    let observations = self
                        .gather_socket_observations(socket, servers, stun_timeout, None)
                        .await;
                    Some((
                        index,
                        p2pnet_nat::candidate_report_from_unordered_observations(
                            address,
                            false,
                            observations,
                        ),
                    ))
                }
            },
        ));
        let (observations, ipv6, pool) = tokio::join!(primary, ipv6, pool);
        let mut report = p2pnet_nat::candidate_report_from_unordered_observations(
            local_addr,
            hosts,
            observations,
        );
        if let Some(ipv6) = ipv6 {
            self.append_ipv6_candidates(&mut report, ipv6.candidates)
                .await;
        }
        for (index, pool_report) in pool.into_iter().flatten() {
            merge_pool_nat_profile(&mut report, &pool_report);
            self.append_pool_candidates(&mut report, pool_report.candidates, index)
                .await;
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
        if apply_socket_pool_policy {
            self.apply_candidate_report_socket_pool_policy(&report);
        }

        if !self.peers.predicted_candidates_enabled_for_gather() {
            report
                .candidates
                .retain(|candidate| candidate.source != p2pnet_nat::CandidateSource::Predicted);
        }
        Ok(report)
    }

    async fn gather_socket_observations(
        &self,
        socket: &UdpSocket,
        servers: &[SocketAddr],
        timeout: Duration,
        progress: Option<&watch::Sender<[Option<SocketAddr>; 2]>>,
    ) -> Vec<StunObservation> {
        let Ok(bound) = socket.local_addr() else {
            return Vec::new();
        };
        let mut seen = HashSet::new();
        join_all(
            servers
                .iter()
                .copied()
                .filter(|server| server.is_ipv4() == bound.is_ipv4() && seen.insert(*server))
                .map(|server| async move {
                    let sample = self
                        .query_stun_live_on_socket(socket, server, timeout)
                        .await;
                    if let (Some(tx), Some(mapped)) = (
                        progress,
                        sample
                            .mapped_address
                            .as_deref()
                            .and_then(|s| s.parse::<SocketAddr>().ok())
                            .filter(|addr| is_public_probe_endpoint(*addr)),
                    ) {
                        tx.send_if_modified(|both| {
                            let first = &mut both[usize::from(bound.is_ipv6())];
                            if first.is_some() {
                                return false;
                            }
                            *first = Some(mapped);
                            true
                        });
                    }
                    sample
                }),
        )
        .await
    }

    pub(crate) fn apply_candidate_report_socket_pool_policy(&self, report: &CandidateGatherReport) {
        self.set_socket_pool_active(socket_pool_is_eligible(report));
    }

    async fn probe_live_filtering_behavior(
        &self,
        report: &mut CandidateGatherReport,
        stun_servers: &[SocketAddr],
        stun_timeout: Duration,
    ) {
        if report.nat_profile.udp_blocked
            || report.nat_profile.filtering_behavior != FilteringBehavior::Unknown
        {
            return;
        }

        let Some(server) = report
            .nat_profile
            .observations
            .iter()
            .find_map(|observation| {
                let server = observation.server.parse::<SocketAddr>().ok()?;
                (observation.error.is_none()
                    && observation.mapped_address.is_some()
                    && stun_servers.contains(&server))
                .then_some(server)
            })
        else {
            return;
        };
        let timeout = stun_timeout_for_live_filtering_probe(stun_timeout);

        if let Ok(response) = self
            .query_stun_live_response(&self.socket, server, timeout, true, true)
            .await
        {
            if !response
                .mapped_address
                .is_some_and(|addr| addr.is_ipv4() == server.is_ipv4())
            {
                return;
            }
            if let Some(filtering) = p2pnet_nat::ice::classify_filtering_probe_response(
                server,
                response.source,
                stun_servers,
            ) {
                report.nat_profile.filtering_behavior = filtering;
            }
        }
        // Port-only success cannot separate EIF from ADF without a verified
        // uncontacted alternate-IP experiment. Keep the filtering axis unknown.
    }
}

fn stun_timeout_for_live_filtering_probe(timeout: Duration) -> Duration {
    timeout
        .min(LIVE_FILTERING_PROBE_TIMEOUT)
        .max(Duration::from_millis(50))
}

#[cfg(test)]
fn classify_live_filtering_response(
    server: SocketAddr,
    response_source: SocketAddr,
) -> Option<FilteringBehavior> {
    p2pnet_nat::ice::classify_filtering_probe_response(server, response_source, &[server])
}

/// Promote pool-backed reachability without treating independent UDP sockets
/// as one sequential port-allocation experiment. `NatProfile.observations`
/// belongs to `local_addr` and is consumed by the allocation-model inference;
/// appending pool observations there can falsely label a predictable primary
/// socket as random, or invent an ordering that was never measured.
///
fn merge_pool_nat_profile(
    report: &mut CandidateGatherReport,
    pool_report: &CandidateGatherReport,
) -> bool {
    let endpoint = pool_report.candidates.iter().find_map(|candidate| {
        if candidate.source != p2pnet_nat::CandidateSource::StunObserved {
            return None;
        }
        let endpoint = candidate.endpoint.to_string().parse::<SocketAddr>().ok()?;
        is_public_probe_endpoint(endpoint).then_some(endpoint)
    });
    let Some(endpoint) = endpoint else {
        return false;
    };
    let profile = &mut report.nat_profile;
    if !profile.udp_blocked
        && (profile.public_endpoint.is_some()
            || profile.mapping_behavior != MappingBehavior::Unknown)
    {
        return false;
    }
    // A pool member answered. Its actual address is usable, but neither its
    // mapping behavior nor any allocation sequence belongs to the primary.
    profile.public_endpoint = Some(endpoint.to_string());
    profile.udp_blocked = false;
    profile.public_ip_stable = None;
    profile.public_port_stable = None;
    profile.port_preserved = None;
    profile.port_delta = None;
    profile.mapping_behavior = MappingBehavior::Unknown;
    profile.filtering_behavior = FilteringBehavior::Unknown;
    profile.likely_symmetric = None;
    profile.prediction_candidate = false;
    profile.predicted_endpoints.clear();
    profile.birthday_candidate = false;
    true
}
