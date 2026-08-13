match cmd {
                        ControlCommand::PollPeersNow => {
                            // A signal arrived from a peer that the daemon has
                            // not registered yet: bring the peer list current
                            // immediately instead of waiting out the regular
                            // poll cadence, then re-arm the regular tick so
                            // this does not create a poll burst.
                            peer_roster_tick.reset();
                            let poll_result = poll_peers(&http, &base_url, &token, &config, &self_node_id, &state, event_tx).await;
                            match &poll_result {
                                Ok(_) => {
                                    poll_failures = 0;
                                    let _ = event_tx.send(ControlEvent::ControlHealthy);
                                }
                                Err(err) => {
                                    warn!("Immediate peer polling failed: {err}");
                                    poll_failures = poll_failures.saturating_add(1);
                                }
                            }
                        }
                        ControlCommand::CreateTunnel { protocol, local_port, remote_port } => {
                            let res = create_tunnel(&http, &base_url, &token, &self_node_id, &protocol, local_port, remote_port).await;
                            match res {
                                Ok((tunnel_id, public_endpoint)) => {
                                    let _ = event_tx.send(ControlEvent::TunnelCreated { tunnel_id, public_endpoint });
                                }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let code = if is_permanent_auth_error(&err_str) { 401u16 } else { 3000u16 };
                                    let _ = event_tx.send(ControlEvent::ServerError { code, message: err_str });
                                    if code == 401 {
                                        break;
                                    }
                                }
                            }
                        }
                        ControlCommand::UpdateEndpoint { endpoint, nat_type, response_tx } => {
                            let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
                            let res = update_endpoint(
                                &http,
                                &base_url,
                                &token,
                                &self_node_id,
                                &endpoint,
                                &nat_type,
                                relay_rtt_ms,
                            )
                            .await;
                            match &res {
                                Ok(()) => {
                                    advertised_endpoint = endpoint;
                                    advertised_nat_type = nat_type;
                                    debug!("Updated endpoint for {self_node_id}: {advertised_endpoint} ({advertised_nat_type})");
                                    let _ = event_tx.send(ControlEvent::ControlHealthy);
                                }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 2000, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::SendPeerOffer { to_node_id, candidates, session_id, probe_ephemeral_public_key, candidate_sources, handshake_init, punch_at_ms, fresh_ownership, response_tx } => {
                            // The outcome is explicit: a fresh-mapping
                            // prediction that was cancelled before the HTTP
                            // request MUST NOT be reported as sent, so the
                            // caller never finalizes a socket whose prediction
                            // the peer never received.
                            let outcome = if fresh_ownership.is_some_and(|ownership| ownership.is_cancelled()) {
                                // The fresh-mapping prediction's punch session
                                // was superseded while this command waited in
                                // the queue: sending it would let the receiver
                                // claim a stale window.
                                debug!("Skipped queued peer offer to {to_node_id}: fresh-mapping prediction ownership was revoked before the HTTP request");
                                PeerOfferSendOutcome::Cancelled
                            } else {
                                // Fresh predictions travel on the ordinary
                                // `peer_offer` wire type: the fresh identity
                                // lives in the `predicted_fresh:*` candidate
                                // source labels, and the receiver's per-peer
                                // fresh high-water is the authority on
                                // supersession.  Keeping one wire type makes a
                                // new client work against an old server (which
                                // would otherwise reject `peer_offer_fresh`
                                // with 400) and an old client against a new
                                // server (which would otherwise hand it an
                                // unknown type it silently drops).  The server
                                // never overwrites queued signals, so delivery
                                // order is the per-pair sequence either way.
                                let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_offer", &candidates, &candidate_sources, &handshake_init, punch_at_ms, None, session_id.as_deref(), probe_ephemeral_public_key.as_deref(), signal_signing_identity.as_ref()).await;
                                match &res {
                                    Ok(()) => {
                                        debug!("Sent peer_offer to {to_node_id} punch_at_ms={punch_at_ms:?}");
                                        PeerOfferSendOutcome::Sent
                                    }
                                    Err(err) => {
                                        let err_str = err.to_string();
                                        let _ = event_tx.send(ControlEvent::ServerError { code: 4000, message: err_str.clone() });
                                        if is_permanent_auth_error(&err_str) {
                                            let _ = response_tx.send(PeerOfferSendOutcome::Failed);
                                            break;
                                        }
                                        PeerOfferSendOutcome::Failed
                                    }
                                }
                            };
                            let _ = response_tx.send(outcome);
                        }
                        ControlCommand::SendPeerReflexive { to_node_id, observed_endpoint, punch_at_ms, response_tx } => {
                            let candidates = vec![observed_endpoint.clone()];
                            let candidate_sources = HashMap::from([
                                (observed_endpoint.clone(), "peer_reflexive".to_string())
                            ]);
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_reflexive", &candidates, &candidate_sources, &[], punch_at_ms, None, None, None, None).await;
                            match &res {
                                Ok(()) => {
                                    debug!(
                                        "Sent peer-reflexive observation to {to_node_id}: {observed_endpoint} punch_at_ms={punch_at_ms:?}"
                                    );
                                }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 4002, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::DeleteTunnel { tunnel_id } => {
                            debug!("Tunnel deletion queued locally for {tunnel_id}");
                        }
                        ControlCommand::FetchRelayTicket { audience, region, response_tx } => {
                            let result = fetch_relay_ticket_http(&http, &base_url, &token, &audience, &region).await;
                            let _ = response_tx.send(result);
                        }
                        ControlCommand::Shutdown => {
                            let _ = event_tx.send(ControlEvent::Disconnected);
                            return;
                        }
                    }
