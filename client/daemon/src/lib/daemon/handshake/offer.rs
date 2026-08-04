impl Daemon {
    #[allow(clippy::too_many_arguments)]
    async fn handle_peer_offer(
        &mut self,
        from_node_id: &str,
        _candidates: &[String],
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let initiation = MessageInitiation::from_bytes(handshake_init)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard initiation: {e}")))?;
        let identity = self.local_identity()?;
        let mut responder = HandshakeResponder::new(identity, None);
        let (response, keys) = responder
            .consume_initiation_and_respond(&initiation)
            .map_err(|e| DaemonError::Peer(format!("WireGuard response failed: {e}")))?;

        if let Some(known_peer) = self.control.peers().await.get(from_node_id).cloned() {
            let expected_public = decode_x25519_key(&known_peer.public_key, "peer public key")?;
            if responder.initiator_public_key() != Some(&expected_public) {
                return Err(DaemonError::Peer(format!(
                    "WireGuard initiation public key mismatch for peer {from_node_id}"
                )));
            }
        }

        let (response_probe_ephemeral_public_key, probe_ephemeral_shared) = match (
            session_id.as_ref(),
            probe_ephemeral_public_key.as_deref(),
        ) {
            (Some(_), Some(peer_probe_public_key)) => {
                let (local_probe_ephemeral, local_probe_public_key) = new_probe_ephemeral_keypair();
                match derive_probe_ephemeral_shared(&local_probe_ephemeral, peer_probe_public_key) {
                    Ok(shared) => (Some(local_probe_public_key), Some(shared)),
                    Err(err) => {
                        warn!(
                            "Ignoring malformed probe ephemeral public key from {from_node_id}: {err}"
                        );
                        (None, None)
                    }
                }
            }
            _ => (None, None),
        };

        if session_id.is_some() || probe_ephemeral_shared.is_some() {
            self.peers
                .set_probe_session_binding(from_node_id, session_id.clone(), probe_ephemeral_shared)
                .await;
        }

        let previous_session = self
            .transport
            .replace_session(from_node_id.to_string(), TransportSession::new(keys))
            .await;
        if !self.peers.is_relay(from_node_id).await {
            self.peers
                .update_state(from_node_id, ConnectionState::Connecting)
                .await;
        }

        let response_bytes = response.to_bytes();
        let (candidates, candidate_sources) =
            self.local_candidate_set_for_signal("handshake answer").await;
        if let Err(error) = self
            .control
            .send_peer_answer_with_sources_schedule_and_session(
                from_node_id,
                &candidates,
                &candidate_sources,
                &response_bytes,
                // Echo the offer's server deadline so both peers use the
                // same rendezvous window. WebSocket-only peers have no
                // server deadline and retain the previous local fallback.
                punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms())),
                punch_at_server_ms,
                session_id.clone(),
                response_probe_ephemeral_public_key,
            )
            .await
        {
            self.transport
                .restore_session(from_node_id, previous_session)
                .await;
            return Err(error);
        }
        self.transport
            .flush_pending_outbound_for_peer(from_node_id)
            .await;
        info!(
            "Installed WireGuard responder session for {from_node_id} and sent response ({} bytes, {} candidates)",
            response_bytes.len(),
            candidates.len()
        );
        self.peers
            .record_direct_event(
                from_node_id,
                "peer_answer_sent",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "sent answer handshake_bytes={} session_id={}",
                    response_bytes.len(),
                    session_id.as_deref().unwrap_or("legacy")
                ),
            )
            .await;
        Ok(())
    }

}
