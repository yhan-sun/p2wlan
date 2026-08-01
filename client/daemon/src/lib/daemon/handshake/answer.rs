impl Daemon {
    async fn handle_peer_answer(
        &mut self,
        from_node_id: &str,
        handshake_response: &[u8],
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let response = MessageResponse::from_bytes(handshake_response)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard response: {e}")))?;
        let (keys, clear_session_binding, probe_ephemeral_shared) = {
            let mut state = self.pending_handshakes.lock().await;
            let expected_session_id = state.session_id(from_node_id).map(str::to_string);
            if let (Some(expected), Some(received)) =
                (expected_session_id.as_deref(), session_id.as_deref())
            {
                if expected != received {
                    warn!(
                        "Ignoring WireGuard answer from {from_node_id} with mismatched session_id"
                    );
                    return Ok(());
                }
            }

            let Some(initiator) = state.pending.get_mut(from_node_id) else {
                warn!("No pending WireGuard handshake for answer from {from_node_id}");
                return Ok(());
            };

            let keys = match initiator.consume_response(&response) {
                Ok(keys) => keys,
                Err(err) => {
                    warn!(
                        "Ignoring WireGuard answer from {from_node_id} that does not match the pending handshake: {err}"
                    );
                    return Ok(());
                }
            };

            let probe_ephemeral_shared = match (
                expected_session_id.as_ref(),
                state.probe_ephemeral(from_node_id),
                probe_ephemeral_public_key.as_deref(),
            ) {
                (Some(_), Some(local_probe_ephemeral), Some(peer_probe_public_key)) => {
                    match derive_probe_ephemeral_shared(
                        &local_probe_ephemeral,
                        peer_probe_public_key,
                    ) {
                        Ok(shared) => Some(shared),
                        Err(err) => {
                            warn!(
                                "Ignoring malformed probe ephemeral public key from {from_node_id}: {err}"
                            );
                            None
                        }
                    }
                }
                _ => None,
            };

            state.remove(from_node_id);
            state.attempts.remove(from_node_id);
            (
                keys,
                expected_session_id.is_some() && session_id.is_none(),
                probe_ephemeral_shared,
            )
        };

        if let Some(session_id) = session_id {
            self.peers
                .set_probe_session_binding(from_node_id, Some(session_id), probe_ephemeral_shared)
                .await;
        } else if clear_session_binding {
            self.peers.set_probe_session_id(from_node_id, None).await;
        }

        // Replace old session with new one (rekey case).
        let new_session = TransportSession::new(keys);
        self.transport
            .add_session(from_node_id.to_string(), new_session)
            .await;
        if !self.peers.is_relay(from_node_id).await {
            self.peers
                .update_state(from_node_id, ConnectionState::Connecting)
                .await;
        }
        info!("Installed WireGuard initiator session for {from_node_id}");
        self.peers
            .record_direct_event(
                from_node_id,
                "peer_answer_applied",
                None,
                None,
                None,
                format!(
                    "installed initiator session from {} response bytes",
                    handshake_response.len()
                ),
            )
            .await;
        Ok(())
    }

}
