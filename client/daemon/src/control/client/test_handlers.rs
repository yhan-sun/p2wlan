#[cfg(test)]
pub(crate) struct CapturedCriticalOffer {
    pub(crate) to_node_id: String,
    pub(crate) candidates: Vec<String>,
    pub(crate) handshake_init: Vec<u8>,
    pub(crate) session_id: Option<String>,
}

impl ControlClient {
    /// Observe the actual bounded critical queue rather than the independent
    /// candidate-signaling forwarder. Only the test consumer is replaced;
    /// production offer construction, queue admission and response waiting run.
    #[cfg(test)]
    pub(crate) fn capture_critical_offers_for_test(
        &mut self,
    ) -> mpsc::UnboundedReceiver<CapturedCriticalOffer> {
        let (critical_tx, mut critical_rx) =
            mpsc::channel::<CriticalOfferCommand>(CRITICAL_OFFER_QUEUE_CAPACITY);
        let (capture_tx, capture_rx) = mpsc::unbounded_channel();
        self.critical_offer_tx = critical_tx;
        tokio::spawn(async move {
            while let Some(command) = critical_rx.recv().await {
                let _ = capture_tx.send(CapturedCriticalOffer {
                    to_node_id: command.to_node_id,
                    candidates: command.candidates,
                    handshake_init: command.handshake_init,
                    session_id: command.session_id,
                });
                let _ = command.response_tx.send(PeerOfferSendOutcome::Sent);
            }
        });
        capture_rx
    }

    /// Process a received control message (internal).
    #[cfg(test)]
    async fn handle_message(&self, msg: ControlMessage) {
        match msg {
            ControlMessage::Registered {
                virtual_ip,
                relay_servers,
            } => {
                let mut state = self.state.write().await;
                state.registered = true;
                state.virtual_ip = Some(virtual_ip.clone());
                state._relay_servers = relay_servers.clone();
                drop(state);

                let _ = self.event_tx.send(ControlEvent::Registered {
                    node_id: None,
                    virtual_ip,
                    cidr: Some("10.20.0.0/16".to_string()),
                    relay_servers,
                    relay_catalog: Vec::new(),
                });
            }

            ControlMessage::PeerJoin {
                node_id,
                public_key,
                endpoint,
                nat_type,
                virtual_ip,
            } => {
                let peer = PeerInfo {
                    node_id: node_id.clone(),
                    device_name: String::new(),
                    app_version: String::new(),
                    public_key,
                    endpoint,
                    nat_type,
                    virtual_ip,
                    online: true,
                    last_seen: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    relay_rtt_ms: None,
                };

                self.state
                    .write()
                    .await
                    .peers
                    .insert(node_id.clone(), peer.clone());
                let _ = self.event_tx.send(ControlEvent::PeerJoined(peer));
            }

            ControlMessage::PeerLeave { node_id } => {
                if let Some(mut peer) = self.state.write().await.peers.remove(&node_id) {
                    peer.online = false;
                }
                let _ = self.event_tx.send(ControlEvent::PeerLeft(node_id));
            }

            ControlMessage::PeerOffer {
                from_node_id,
                candidates,
                session_id,
                probe_ephemeral_public_key,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
                handshake_init,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_init,
                    punch_at_ms,
                    punch_at_server_ms: None,
                    sender_public_key: None,
                });
            }

            ControlMessage::PeerAnswer {
                from_node_id,
                candidates,
                session_id,
                probe_ephemeral_public_key,
                candidate_sources,
                candidate_generation,
                candidates_expires_at_ms,
                handshake_response,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    session_id,
                    probe_ephemeral_public_key,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_response,
                    punch_at_ms,
                    punch_at_server_ms: None,
                    sender_public_key: None,
                });
            }

            ControlMessage::PeerReflexive {
                from_node_id,
                observed_endpoint,
                punch_at_ms,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerReflexive {
                    from_node_id,
                    observed_endpoint,
                    punch_at_ms,
                });
            }

            ControlMessage::PeerReject {
                from_node_id,
                reason,
                ..
            } => {
                let _ = self.event_tx.send(ControlEvent::PeerRejected {
                    from_node_id,
                    reason,
                });
            }

            ControlMessage::TunnelCreated {
                tunnel_id,
                public_endpoint,
            } => {
                let _ = self.event_tx.send(ControlEvent::TunnelCreated {
                    tunnel_id,
                    public_endpoint,
                });
            }

            ControlMessage::Error { code, message } => {
                warn!("Control server error: {} - {}", code, message);
                let _ = self
                    .event_tx
                    .send(ControlEvent::ServerError { code, message });
            }

            ControlMessage::HeartbeatAck { timestamp } => {
                debug!("Heartbeat ack for timestamp {}", timestamp);
            }

            _ => {
                debug!("Unhandled control message: {:?}", msg);
            }
        }
    }
}
