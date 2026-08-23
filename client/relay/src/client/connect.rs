use super::*;

/// Write one frame unless the connection has been invalidated.  A shutdown
/// signal racing `write_all` is classified as delivery-uncertain: the frame
/// may have been partially accepted by the kernel, so callers must consume
/// its counter and must not retry the old ciphertext.
async fn write_all_or_shutdown<W>(
    writer: &mut W,
    bytes: &[u8],
    close_rx: &mut watch::Receiver<bool>,
) -> std::result::Result<(), RelayError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        result = writer.write_all(bytes) => result.map_err(RelayError::from),
        changed = close_rx.changed() => {
            let _ = changed;
            Err(RelayError::WriteUncertain(
                "writer interrupted after command acceptance".into(),
            ))
        }
    }
}

impl RelayClient {
    pub async fn connect(
        addr: &str,
        node_id: &str,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_with_config(addr, node_id, RelayClientConfig::default()).await
    }

    /// Connect with config.
    pub async fn connect_with_config(
        addr: &str,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        config.validate()?;
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| RelayError::ConnectFailed(format!("invalid address '{addr}': {e}")))?;

        Self::connect_to_addr_with_config(socket_addr, node_id, config).await
    }

    /// Connect, register, and wait for the server's confirmation.
    pub async fn connect_verified(
        addr: &str,
        node_id: &str,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect(addr, node_id).await
    }

    /// Connect verified with config.
    pub async fn connect_verified_with_config(
        addr: &str,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_with_config(addr, node_id, config).await
    }

    /// Connect to a relay using the tls:// or tcp:// scheme with optional auth.
    ///
    /// This is the A2 entry point that supports:
    /// - `tls://host:port` — TLS 1.3 with certificate validation
    /// - `tcp://host:port` — plaintext (only if config.allow_insecure_plaintext)
    /// - Auth register with relay ticket (if config.relay_ticket is set)
    pub async fn connect_with_endpoint(
        endpoint: &str,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        config.validate()?;

        let parsed = crate::tls::parse_endpoint(endpoint, config.allow_insecure_plaintext)?;

        match parsed.scheme.as_str() {
            "tls" => {
                let connector = crate::tls::build_tls_connector(config.tls_ca_cert_path.as_ref())?;
                let server_name = config
                    .tls_server_name
                    .clone()
                    .unwrap_or_else(|| parsed.host.clone());

                let tcp_stream = tokio::time::timeout(
                    config.connect_timeout,
                    p2pnet_netbind::connect_tcp_host(
                        &parsed.host,
                        parsed.port,
                        config.outbound_interface.as_deref(),
                    ),
                )
                .await
                .map_err(|_| RelayError::Timeout("connect timed out".into()))?
                .map_err(|e| RelayError::ConnectFailed(e.to_string()))?;

                tcp_stream.set_nodelay(true).ok();

                let tls_stream = tokio::time::timeout(
                    config.register_timeout,
                    crate::tls::tls_connect(tcp_stream, &server_name, &connector),
                )
                .await
                .map_err(|_| RelayError::Timeout("TLS handshake timed out".into()))??;

                Self::finish_connect_with_stream(tls_stream, node_id, config).await
            }
            "tcp" => {
                let stream = tokio::time::timeout(
                    config.connect_timeout,
                    p2pnet_netbind::connect_tcp_host(
                        &parsed.host,
                        parsed.port,
                        config.outbound_interface.as_deref(),
                    ),
                )
                .await
                .map_err(|_| RelayError::Timeout("connect timed out".into()))?
                .map_err(|e| RelayError::ConnectFailed(e.to_string()))?;

                stream.set_nodelay(true).ok();
                Self::finish_connect_with_stream(stream, node_id, config).await
            }
            _ => Err(RelayError::TlsError(format!(
                "unsupported scheme: {}",
                parsed.scheme
            ))),
        }
    }

    /// Internal helper: finish connection after transport is established.
    pub(super) async fn finish_connect_with_stream<S>(
        mut stream: S,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio::io::AsyncWriteExt;

        // Send Register or Auth Register frame
        if let Some(ref ticket) = config.relay_ticket {
            let auth_payload = crate::auth::encode_auth_register(node_id, ticket)
                .map_err(|e| RelayError::Protocol(format!("auth register encode: {e}")))?;
            let auth_frame =
                crate::protocol::Frame::new(crate::protocol::MSG_AUTH_REGISTER, auth_payload);
            let encoded = auth_frame.encode();
            tokio::time::timeout(config.register_timeout, stream.write_all(&encoded))
                .await
                .map_err(|_| RelayError::Timeout("registration write timed out".into()))??;
        } else {
            let reg_frame = crate::protocol::Frame::register(node_id);
            let encoded = reg_frame.encode();
            tokio::time::timeout(config.register_timeout, stream.write_all(&encoded))
                .await
                .map_err(|_| RelayError::Timeout("registration write timed out".into()))??;
        }

        let (reader, mut writer) = tokio::io::split(stream);

        // Channels
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientCommand>(config.cmd_queue_capacity);
        let (msg_tx, msg_rx) = mpsc::channel::<RelayMessage>(config.inbound_queue_capacity);
        let (reg_tx, reg_rx) = tokio::sync::oneshot::channel::<Result<()>>();
        let (close_tx, close_rx) = tokio::sync::watch::channel(false);
        // Shared close-reason attribution shared by both background tasks.
        let close_reason = Arc::new(std::sync::Mutex::new(RelayCloseReason::Unknown));
        let ping_expectations = new_ping_expectations(effective_idle_timeout(
            config.idle_timeout,
            config.keepalive_interval,
        ));

        // Write task
        let write_close_tx = close_tx.clone();
        let mut write_close_rx = close_rx.clone();
        let max_payload = config.max_frame_payload;
        let write_reason = close_reason.clone();
        let write_ping_expectations = ping_expectations.clone();
        let keepalive_interval = config.keepalive_interval;
        let _write_task = tokio::spawn(async move {
            let mut keepalive = tokio::time::interval(keepalive_interval);
            keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            keepalive.tick().await;

            loop {
                tokio::select! {
                    command = cmd_rx.recv() => {
                        let Some(cmd) = command else { break; };
                        match cmd {
                            ClientCommand::SendFrame(frame) => {
                                if frame.payload.len() > max_payload { continue; }
                                if let Err(err) = write_all_or_shutdown(
                                    &mut writer,
                                    &frame.encode(),
                                    &mut write_close_rx,
                                )
                                .await
                                {
                                    warn!("Relay write error: {}", err);
                                    note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                                    break;
                                }
                            }
                            ClientCommand::SendData {
                                dst,
                                data,
                                write_boundary,
                                completion,
                            } => {
                                let data_len = data.len();
                                debug!(
                                    event = "relay_write_dequeued",
                                    peer_id = %dst,
                                    bytes = data_len,
                                    "relay writer dequeued an accepted data command"
                                );
                                let result = match Frame::forward(&dst, &data) {
                                    Ok(frame) if frame.payload.len() > max_payload => {
                                        Err(RelayError::FrameTooLarge(frame.payload.len(), max_payload))
                                    }
                                    Ok(frame) => {
                                        let encoded = frame.encode();
                                        let write_started = std::time::Instant::now();
                                        let boundary_accepted = write_boundary
                                            .map(|hook| hook(write_started))
                                            .unwrap_or(true);
                                        if !boundary_accepted {
                                            Err(RelayError::WriteBoundaryRejected)
                                        } else {
                                            debug!(
                                                event = "relay_write_started",
                                                peer_id = %dst,
                                                bytes = data_len,
                                                "relay writer passed the write-boundary guard and is entering write_all"
                                            );
                                            write_all_or_shutdown(
                                                &mut writer,
                                                &encoded,
                                                &mut write_close_rx,
                                            )
                                            .await
                                        }
                                    }
                                    Err(err) => Err(err),
                                };
                                let failed = result.is_err();
                                let boundary_rejected =
                                    matches!(&result, Err(RelayError::WriteBoundaryRejected));
                                if !failed {
                                    debug!(
                                        event = "relay_write_completed",
                                        peer_id = %dst,
                                        bytes = data_len,
                                        "relay writer completed write_all; this is not a peer-delivery acknowledgement"
                                    );
                                } else if boundary_rejected {
                                    debug!(
                                        event = "relay_write_boundary_rejected",
                                        peer_id = %dst,
                                        bytes = data_len,
                                        "relay frame rejected at the writer boundary before write_all"
                                    );
                                } else {
                                    warn!(
                                        event = "relay_write_failed",
                                        peer_id = %dst,
                                        bytes = data_len,
                                        reason_code = "relay_write_uncertain_or_failed",
                                        error = ?result.as_ref().err(),
                                        "relay writer failed after command acceptance; ciphertext delivery is uncertain"
                                    );
                                }
                                let _ = completion.send(result);
                                if failed && !boundary_rejected {
                                    note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                                    break;
                                }
                            }
                            ClientCommand::Ping => {
                                let (ping_token, frame) = begin_ping(&write_ping_expectations);
                                if let Err(err) = write_all_or_shutdown(
                                    &mut writer,
                                    &frame.encode(),
                                    &mut write_close_rx,
                                )
                                .await
                                {
                                    cancel_ping(&write_ping_expectations, ping_token);
                                    warn!("Relay ping write error: {}", err);
                                    note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                                    break;
                                }
                            }
                        }
                    }
                    _ = keepalive.tick() => {
                        let (ping_token, frame) = begin_ping(&write_ping_expectations);
                        if let Err(err) = write_all_or_shutdown(
                            &mut writer,
                            &frame.encode(),
                            &mut write_close_rx,
                        )
                        .await
                        {
                            cancel_ping(&write_ping_expectations, ping_token);
                            warn!("Relay keepalive write error: {}", err);
                            note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                            break;
                        }
                        debug!("Relay keepalive ping sent (interval={:?})", keepalive_interval);
                    }
                    changed = write_close_rx.changed() => {
                        if changed.is_ok() && *write_close_rx.borrow() {
                            note_close_reason(&write_reason, RelayCloseReason::LocalShutdown);
                            break;
                        }
                    }
                }
            }
            let _ = write_close_tx.send(true);
            debug!("Relay write task ended");
        });

        // Read task
        let msg_tx_clone = msg_tx.clone();
        let mut reg_tx = Some(reg_tx);
        let read_close_tx = close_tx.clone();
        let mut read_close_rx = close_rx.clone();
        let idle_timeout = effective_idle_timeout(config.idle_timeout, config.keepalive_interval);
        let registration_timeout = config.register_timeout;
        let read_reason = close_reason.clone();
        let read_ping_expectations = ping_expectations;
        tokio::spawn(async move {
            let mut reader = reader;
            let mut buf = vec![0u8; max_payload + FRAME_HEADER_SIZE];

            loop {
                let read_header_fut = reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]);
                let read_timeout = if reg_tx.is_some() {
                    registration_timeout
                } else {
                    idle_timeout
                };
                let read_res = tokio::select! {
                    res = tokio::time::timeout(read_timeout, read_header_fut) => match res {
                        Ok(Ok(_)) => Ok(true),
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout")),
                    },
                    changed = read_close_rx.changed() => {
                        let _ = changed;
                        Ok(false)
                    }
                };

                match read_res {
                    Ok(true) => {}
                    Ok(false) => {
                        // The write task already attributed the end (or the
                        // connection was shut down locally); leave the first
                        // attribution in place.
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        note_close_reason(&read_reason, RelayCloseReason::ServerEof);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        note_close_reason(&read_reason, RelayCloseReason::TcpReset);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        if let Some(tx) = reg_tx.take() {
                            let _ = tx.send(Err(RelayError::Timeout(
                                "registration confirmation timed out".into(),
                            )));
                        } else {
                            note_close_reason(&read_reason, RelayCloseReason::IdleTimeout);
                            let _ = msg_tx_clone.try_send(RelayMessage::Error {
                                code: ERR_IDLE_TIMEOUT,
                                message: "idle timeout".to_string(),
                            });
                        }
                        break;
                    }
                    Err(e) => {
                        warn!("Relay read error: {}", e);
                        note_close_reason(&read_reason, RelayCloseReason::IoError);
                        break;
                    }
                }

                if buf[..4] != MAGIC {
                    break;
                }
                let version = buf[4];
                if version != VERSION {
                    if let Some(tx) = reg_tx.take() {
                        let _ = tx.send(Err(RelayError::UnsupportedVersion(version)));
                    }
                    break;
                }
                let msg_type = buf[5];
                let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

                if payload_len > max_payload {
                    if let Some(tx) = reg_tx.take() {
                        let _ = tx.send(Err(RelayError::FrameTooLarge(payload_len, max_payload)));
                    }
                    break;
                }

                if payload_len > 0 {
                    if buf.len() < FRAME_HEADER_SIZE + payload_len {
                        buf.resize(FRAME_HEADER_SIZE + payload_len, 0);
                    }
                    let read_payload_fut = reader
                        .read_exact(&mut buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len]);
                    let read_timeout = if reg_tx.is_some() {
                        registration_timeout
                    } else {
                        idle_timeout
                    };
                    let read_payload_res = tokio::select! {
                        res = tokio::time::timeout(read_timeout, read_payload_fut) => match res {
                            Ok(Ok(_)) => Ok(true),
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout")),
                        },
                        changed = read_close_rx.changed() => { let _ = changed; Ok(false) }
                    };
                    match read_payload_res {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            if let Some(tx) = reg_tx.take() {
                                let _ = tx.send(Err(RelayError::Timeout(
                                    "registration confirmation timed out during payload".into(),
                                )));
                            } else {
                                note_close_reason(&read_reason, RelayCloseReason::IdleTimeout);
                                let _ = msg_tx_clone.try_send(RelayMessage::Error {
                                    code: ERR_IDLE_TIMEOUT,
                                    message: "idle timeout during payload".to_string(),
                                });
                            }
                            break;
                        }
                        Err(e) => {
                            warn!("Relay payload read error: {}", e);
                            note_close_reason(&read_reason, RelayCloseReason::IoError);
                            break;
                        }
                    }
                }

                let payload = &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

                match msg_type {
                    MSG_RECEIVED => {
                        let frame = Frame::new(MSG_RECEIVED, payload.to_vec());
                        match frame.parse_forward_payload() {
                            Ok((src, data)) => {
                                // Preserve every frame while applying bounded
                                // backpressure.  `try_send` here used to
                                // close the read task as soon as the local
                                // inbound queue filled, which made relay
                                // frames disappear without an error visible
                                // to the dataplane (notably on a 256-packet
                                // burst).  Awaiting the bounded channel keeps
                                // the frame until the consumer accepts it;
                                // the relay's own bounded queue then provides
                                // the next backpressure boundary.
                                if msg_tx_clone
                                    .send(RelayMessage::Data {
                                        from_node: src.to_string(),
                                        data: data.to_vec(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    note_close_reason(
                                        &read_reason,
                                        RelayCloseReason::LocalShutdown,
                                    );
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse received frame: {}", e);
                            }
                        }
                    }
                    MSG_REGISTERED => {
                        if let Some(tx) = reg_tx.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    MSG_PONG => {
                        let ts = if payload.len() >= 8 {
                            u64::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3], payload[4],
                                payload[5], payload[6], payload[7],
                            ])
                        } else {
                            0
                        };
                        let round_trip_time = consume_ping_rtt(&read_ping_expectations, ts);
                        if msg_tx_clone
                            .try_send(RelayMessage::Pong {
                                timestamp: ts,
                                round_trip_time,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    MSG_ERROR => {
                        let frame = Frame::new(MSG_ERROR, payload.to_vec());
                        let (code, message) = frame.parse_error().unwrap_or((0, "unknown".into()));
                        if let Some(tx) = reg_tx.take() {
                            let _ = tx.send(Err(RelayError::ServerError(code, message.clone())));
                        }
                        if msg_tx_clone
                            .try_send(RelayMessage::Error { code, message })
                            .is_err()
                        {
                            break;
                        }
                    }
                    MSG_CLOSE => {
                        note_close_reason(&read_reason, RelayCloseReason::ServerCloseFrame);
                        break;
                    }
                    _ => {
                        warn!("Unexpected message type {:#04X}", msg_type);
                    }
                }
            }

            let reason = resolve_close_reason(&read_reason);
            let _ = msg_tx_clone.try_send(RelayMessage::Closed { reason });
            let _ = read_close_tx.send(true);
            debug!("Relay read task ended; close_reason={reason:?}");
        });

        // Wait for registration confirmation
        match tokio::time::timeout(config.register_timeout, reg_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => return Err(e),
            Ok(Err(_)) => return Err(RelayError::Closed("registration channel dropped".into())),
            Err(_) => {
                return Err(RelayError::Timeout(
                    "registration confirmation timed out".into(),
                ))
            }
        }

        Ok((Self { cmd_tx, close_tx }, msg_rx))
    }
}
