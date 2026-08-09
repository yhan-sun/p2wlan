use super::*;

impl RelayClient {
    #[allow(dead_code)]
    pub(super) async fn connect_to_addr(
        addr: SocketAddr,
        node_id: &str,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_to_addr_with_keepalive(addr, node_id, RELAY_KEEPALIVE_INTERVAL).await
    }

    #[allow(dead_code)]
    pub(super) async fn connect_to_addr_with_keepalive(
        addr: SocketAddr,
        node_id: &str,
        keepalive_interval: Duration,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        let config = RelayClientConfig {
            keepalive_interval,
            ..Default::default()
        };
        Self::connect_to_addr_with_config(addr, node_id, config).await
    }

    pub(super) async fn connect_to_addr_with_config(
        addr: SocketAddr,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        debug!("Connecting to relay server at {}", addr);

        let stream = tokio::time::timeout(config.register_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| RelayError::Timeout("connect timed out".into()))?
            .map_err(|e| RelayError::ConnectFailed(e.to_string()))?;

        stream.set_nodelay(true).ok();
        let (mut reader, mut writer) = stream.into_split();

        // Send Register frame immediately
        let reg_frame = Frame::register(node_id);
        writer.write_all(&reg_frame.encode()).await?;

        info!(
            "Connected to relay server at {} (node_id={})",
            addr, node_id
        );

        // Channels
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientCommand>(config.cmd_queue_capacity);
        let (msg_tx, msg_rx) = mpsc::channel::<RelayMessage>(config.inbound_queue_capacity);
        let (reg_tx, reg_rx) = oneshot::channel::<Result<()>>();
        let (close_tx, close_rx) = watch::channel(false);
        // Shared close-reason attribution shared by both background tasks.
        let close_reason = Arc::new(std::sync::Mutex::new(RelayCloseReason::Unknown));

        // Write task: processes commands and writes to the TCP stream
        let write_close_tx = close_tx.clone();
        let mut write_close_rx = close_rx.clone();
        let max_payload = config.max_frame_payload;
        let write_reason = close_reason.clone();
        let keepalive_interval = config.keepalive_interval;
        let _write_task = tokio::spawn(async move {
            let mut writer = writer;
            let mut keepalive = tokio::time::interval(keepalive_interval);
            keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);
            keepalive.tick().await;

            loop {
                tokio::select! {
                    command = cmd_rx.recv() => {
                        let Some(cmd) = command else {
                            note_close_reason(&write_reason, RelayCloseReason::LocalShutdown);
                            break;
                        };
                        match cmd {
                            ClientCommand::SendFrame(frame) => {
                                if frame.payload.len() > max_payload {
                                    warn!("Frame payload exceeds max limit");
                                    continue;
                                }
                                if let Err(err) = writer.write_all(&frame.encode()).await {
                                    warn!("Relay write error: {}", err);
                                    note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                                    break;
                                }
                            }
                            ClientCommand::SendData { dst, data } => match Frame::forward(&dst, &data) {
                                Ok(frame) => {
                                    if frame.payload.len() > max_payload {
                                        warn!("Frame payload exceeds max limit");
                                        continue;
                                    }
                                    if let Err(err) = writer.write_all(&frame.encode()).await {
                                        warn!("Relay write error: {}", err);
                                        note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to build forward frame: {}", e);
                                }
                            },
                            ClientCommand::Ping => {
                                let frame = Frame::ping();
                                if let Err(err) = writer.write_all(&frame.encode()).await {
                                    warn!("Relay ping write error: {}", err);
                                    note_close_reason(&write_reason, RelayCloseReason::LocalWriteFailed);
                                    break;
                                }
                            }
                            ClientCommand::Close => {
                                let frame = Frame::close(CLOSE_NORMAL);
                                let _ = writer.write_all(&frame.encode()).await;
                                note_close_reason(&write_reason, RelayCloseReason::LocalShutdown);
                                break;
                            }
                        }
                    }
                    _ = keepalive.tick() => {
                        let frame = Frame::ping();
                        if let Err(err) = writer.write_all(&frame.encode()).await {
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

        // Read task: reads frames and dispatches messages
        let msg_tx_clone = msg_tx.clone();
        let mut reg_tx = Some(reg_tx);
        let read_close_tx = close_tx.clone();
        let mut read_close_rx = close_rx.clone();
        let idle_timeout = config.idle_timeout;
        let read_reason = close_reason.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; max_payload + FRAME_HEADER_SIZE];

            loop {
                // Read header
                let read_header_fut = reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]);
                let read_res = tokio::select! {
                    res = tokio::time::timeout(idle_timeout, read_header_fut) => match res {
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
                        // connection was shut down locally).
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        debug!("Relay server disconnected");
                        note_close_reason(&read_reason, RelayCloseReason::ServerEof);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                        warn!("Relay TCP connection reset");
                        note_close_reason(&read_reason, RelayCloseReason::TcpReset);
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        warn!("Relay client idle timeout");
                        note_close_reason(&read_reason, RelayCloseReason::IdleTimeout);
                        let _ = msg_tx_clone.try_send(RelayMessage::Error {
                            code: ERR_IDLE_TIMEOUT,
                            message: "idle timeout".to_string(),
                        });
                        break;
                    }
                    Err(e) => {
                        warn!("Relay read error: {}", e);
                        note_close_reason(&read_reason, RelayCloseReason::IoError);
                        break;
                    }
                }

                // Parse header
                if buf[..4] != MAGIC {
                    warn!("Invalid magic from relay server");
                    break;
                }
                let version = buf[4];
                if version != VERSION {
                    warn!("Unsupported version {} from relay server", version);
                    if let Some(tx) = reg_tx.take() {
                        let _ = tx.send(Err(RelayError::Protocol(format!(
                            "unsupported version: {}",
                            version
                        ))));
                    }
                    break;
                }
                let msg_type = buf[5];
                let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

                if payload_len > max_payload {
                    warn!(
                        "Payload length {} exceeds configured maximum {}",
                        payload_len, max_payload
                    );
                    if let Some(tx) = reg_tx.take() {
                        let _ = tx.send(Err(RelayError::FrameTooLarge(payload_len, max_payload)));
                    }
                    break;
                }

                // Read payload
                if payload_len > 0 {
                    if buf.len() < FRAME_HEADER_SIZE + payload_len {
                        buf.resize(FRAME_HEADER_SIZE + payload_len, 0);
                    }
                    let read_payload_fut = reader
                        .read_exact(&mut buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len]);
                    let read_payload_res = tokio::select! {
                        res = tokio::time::timeout(idle_timeout, read_payload_fut) => match res {
                            Ok(Ok(_)) => Ok(true),
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout")),
                        },
                        changed = read_close_rx.changed() => {
                            let _ = changed;
                            Ok(false)
                        }
                    };
                    match read_payload_res {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            warn!("Relay client idle timeout during payload");
                            note_close_reason(&read_reason, RelayCloseReason::IdleTimeout);
                            let _ = msg_tx_clone.try_send(RelayMessage::Error {
                                code: ERR_IDLE_TIMEOUT,
                                message: "idle timeout during payload".to_string(),
                            });
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
                        // Data from a peer
                        let frame = Frame::new(MSG_RECEIVED, payload.to_vec());
                        match frame.parse_forward_payload() {
                            Ok((src, data)) => {
                                if msg_tx_clone
                                    .try_send(RelayMessage::Data {
                                        from_node: src.to_string(),
                                        data: data.to_vec(),
                                    })
                                    .is_err()
                                {
                                    warn!("msg_tx full or closed, closing connection");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse received frame: {}", e);
                            }
                        }
                    }

                    MSG_REGISTERED => {
                        // Server confirmed registration — signal via oneshot
                        debug!("Relay registration confirmed");
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
                        if msg_tx_clone
                            .try_send(RelayMessage::Pong { timestamp: ts })
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
                        debug!("Relay server sent close");
                        note_close_reason(&read_reason, RelayCloseReason::ServerCloseFrame);
                        break;
                    }

                    _ => {
                        warn!("Unexpected or unknown message type {:#04X}", msg_type);
                    }
                }
            }

            // Signal end of stream with the classified close reason
            let reason = resolve_close_reason(&read_reason);
            let _ = msg_tx_clone.try_send(RelayMessage::Closed { reason });
            let _ = read_close_tx.send(true);
            debug!("Relay read task ended; close_reason={reason:?}");
        });

        // Wait for registration confirmation before returning
        match tokio::time::timeout(config.register_timeout, reg_rx).await {
            Ok(Ok(Ok(()))) => {
                debug!("Registration confirmed by relay server");
            }
            Ok(Ok(Err(e))) => return Err(e),
            Ok(Err(_)) => {
                return Err(RelayError::Closed("registration channel dropped".into()));
            }
            Err(_) => {
                return Err(RelayError::Timeout(
                    "registration confirmation timed out".into(),
                ));
            }
        }

        Ok((Self { cmd_tx }, msg_rx))
    }
}
