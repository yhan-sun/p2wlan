use futures_util::future::join_all;

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
        self.set_socket_pool_active(socket_pool_is_eligible(&report));

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
                    Some((socket_index, pool_report.candidates))
                }
            }))
            .await;

            for (socket_index, candidates) in pool_reports.into_iter().flatten() {
                self.append_pool_candidates(&mut report, candidates, socket_index)
                    .await;
            }
        }

        Ok(report)
    }
}
