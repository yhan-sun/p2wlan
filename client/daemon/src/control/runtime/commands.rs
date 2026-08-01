match cmd {
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
                        ControlCommand::SendPeerOffer { to_node_id, candidates, session_id, probe_ephemeral_public_key, candidate_sources, handshake_init, punch_at_ms, response_tx } => {
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_offer", &candidates, &candidate_sources, &handshake_init, punch_at_ms, None, session_id.as_deref(), probe_ephemeral_public_key.as_deref(), signal_signing_identity.as_ref()).await;
                            match &res {
                                Ok(()) => { debug!("Sent peer offer to {to_node_id} punch_at_ms={punch_at_ms:?}"); }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 4000, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
                        }
                        ControlCommand::SendPeerAnswer { to_node_id, candidates, session_id, probe_ephemeral_public_key, candidate_sources, handshake_response, punch_at_ms, punch_at_server_ms, response_tx } => {
                            let res = send_signal(&http, &base_url, &token, &self_node_id, &to_node_id, "peer_answer", &candidates, &candidate_sources, &handshake_response, punch_at_ms, punch_at_server_ms, session_id.as_deref(), probe_ephemeral_public_key.as_deref(), signal_signing_identity.as_ref()).await;
                            match &res {
                                Ok(()) => { debug!("Sent peer answer to {to_node_id} punch_at_ms={punch_at_ms:?}"); }
                                Err(err) => {
                                    let err_str = err.to_string();
                                    let _ = event_tx.send(ControlEvent::ServerError { code: 4001, message: err_str.clone() });
                                    if is_permanent_auth_error(&err_str) {
                                        break;
                                    }
                                }
                            }
                            let _ = response_tx.send(res);
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
