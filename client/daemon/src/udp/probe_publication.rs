use super::*;

const PROBE_PUBLICATION_HANDOFF_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
pub(super) struct ProbePublicationFence {
    owner: u64,
    generation: u64,
}

impl UdpTransport {
    pub(crate) fn with_probe_publication_identity(mut self, owner: u64, generation: u64) -> Self {
        self.probe_publication_fence = Some(ProbePublicationFence { owner, generation });
        self
    }

    pub(crate) fn probe_publication_identity(&self) -> Option<(u64, u64)> {
        self.probe_publication_fence
            .map(|fence| (fence.owner, fence.generation))
    }

    pub(super) async fn send_publication_scoped_probe_datagram(
        &self,
        socket: &UdpSocket,
        bytes: &[u8],
        endpoint: SocketAddr,
    ) -> std::result::Result<usize, ProbeSendFailure> {
        let physical_error = |error: std::io::Error| {
            ProbeSendFailure::with_physical_send_error(
                DaemonError::Network(format!("UDP probe send to {endpoint} failed: {error}")),
                bytes.len(),
            )
        };
        let Some(fence) = self.probe_publication_fence else {
            return self
                .send_probe_datagram(socket, bytes, endpoint)
                .await
                .map_err(physical_error);
        };
        let send = async {
            loop {
                socket.writable().await.map_err(|error| {
                    ProbeSendFailure::new(
                        ProbeSendFailureKind::SocketUnavailable,
                        DaemonError::Network(error.to_string()),
                    )
                })?;
                let attempt = {
                    let _epoch = self.network_epoch_gate.lock().await;
                    self.dplpmtud.try_with_business_publication_gate(|| {
                        // Generation advances and owner withdrawal use these
                        // original gates. No await separates their final check
                        // from this one nonblocking kernel handoff.
                        if fence.owner == 0 || self.inbound_publication_owner() != fence.owner {
                            return Err(ProbeSendFailure::new(
                                ProbeSendFailureKind::SocketRevoked,
                                DaemonError::Network("probe UDP publication was replaced".into()),
                            ));
                        }
                        if self.peers.current_network_generation_sync() != fence.generation {
                            return Err(ProbeSendFailure::new(
                                ProbeSendFailureKind::NetworkGenerationChanged,
                                DaemonError::Network("probe network generation changed".into()),
                            ));
                        }
                        #[cfg(test)]
                        if self.should_fail_probe_send_for_test() {
                            return Err(physical_error(std::io::Error::other(
                                "test-injected physical probe send failure",
                            )));
                        }
                        match socket.try_send_to(bytes, endpoint) {
                            Ok(sent) => Ok(Some(sent)),
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                Ok(None)
                            }
                            Err(error) => Err(physical_error(error)),
                        }
                    })
                };
                match attempt {
                    Some(Ok(Some(sent))) => return Ok(sent),
                    Some(Err(failure)) => return Err(failure),
                    // Neither a busy synchronous publication gate nor stale
                    // writable readiness can spin or retain the epoch gate.
                    None | Some(Ok(None)) => sleep(Duration::from_millis(1)).await,
                }
            }
        };
        timeout(PROBE_PUBLICATION_HANDOFF_TIMEOUT, send)
            .await
            .map_err(|_| {
                ProbeSendFailure::new(
                    ProbeSendFailureKind::PreHandoffTimeout,
                    DaemonError::Network("probe publication/readiness wait timed out".into()),
                )
            })?
    }
}

#[cfg(test)]
#[path = "tests/probe_publication.rs"]
mod tests;
