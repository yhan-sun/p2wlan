use super::*;

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

                // Use host:port directly — TcpStream::connect handles DNS resolution
                let host_port = parsed.host_port();
                let tcp_stream = tokio::time::timeout(
                    config.register_timeout,
                    tokio::net::TcpStream::connect(&host_port),
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
                let host_port = parsed.host_port();
                let stream = tokio::time::timeout(
                    config.register_timeout,
                    tokio::net::TcpStream::connect(&host_port),
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
            stream.write_all(&auth_frame.encode()).await?;
        } else {
            let reg_frame = crate::protocol::Frame::register(node_id);
            stream.write_all(&reg_frame.encode()).await?;
        }

        let (reader, mut writer) = tokio::io::split(stream);

        // Channels
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientCommand>(config.cmd_queue_capacity);
        let (msg_tx, msg_rx) = mpsc::channel::<RelayMessage>(config.inbound_queue_capacity);
        let (reg_tx, reg_rx) = tokio::sync::oneshot::channel::<Result<()>>();
        let (close_tx, close_rx) = tokio::sync::watch::channel(false);

        // Write task
        let write_close_tx = close_tx.clone();
        let mut write_close_rx = close_rx.clone();
        let max_payload = config.max_frame_payload;
        let _write_task = tokio::spawn(async move {
            let mut keepalive = tokio::time::interval(config.keepalive_interval);
            keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            keepalive.tick().await;

            loop {
                tokio::select! {
                    command = cmd_rx.recv() => {
                        let Some(cmd) = command else { break; };
                        match cmd {
                            ClientCommand::SendFrame(frame) => {
                                if frame.payload.len() > max_payload { continue; }
                                if writer.write_all(&frame.encode()).await.is_err() { break; }
                            }
                            ClientCommand::SendData { dst, data } => match Frame::forward(&dst, &data) {
                                Ok(frame) => {
                                    if frame.payload.len() > max_payload { continue; }
                                    if writer.write_all(&frame.encode()).await.is_err() { break; }
                                }
                                Err(e) => { warn!("Failed to build forward frame: {}", e); }
                            },
                            ClientCommand::Ping => {
                                let frame = Frame::ping();
                                if writer.write_all(&frame.encode()).await.is_err() { break; }
                            }
                            ClientCommand::Close => {
                                let frame = Frame::close(CLOSE_NORMAL);
                                let _ = writer.write_all(&frame.encode()).await;
                                break;
                            }
                        }
                    }
                    _ = keepalive.tick() => {
                        let frame = Frame::ping();
                        if writer.write_all(&frame.encode()).await.is_err() { break; }
                    }
                    changed = write_close_rx.changed() => {
                        if changed.is_ok() && *write_close_rx.borrow() { break; }
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
        let idle_timeout = config.idle_timeout;
        tokio::spawn(async move {
            let mut reader = reader;
            let mut buf = vec![0u8; max_payload + FRAME_HEADER_SIZE];

            loop {
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
                    Ok(false) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        let _ = msg_tx_clone.try_send(RelayMessage::Error {
                            code: ERR_IDLE_TIMEOUT,
                            message: "idle timeout".to_string(),
                        });
                        break;
                    }
                    Err(e) => {
                        warn!("Relay read error: {}", e);
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
                    let read_payload_res = tokio::select! {
                        res = tokio::time::timeout(idle_timeout, read_payload_fut) => match res {
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
                            let _ = msg_tx_clone.try_send(RelayMessage::Error {
                                code: ERR_IDLE_TIMEOUT,
                                message: "idle timeout during payload".to_string(),
                            });
                            break;
                        }
                        Err(e) => {
                            warn!("Relay payload read error: {}", e);
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
                                if msg_tx_clone
                                    .try_send(RelayMessage::Data {
                                        from_node: src.to_string(),
                                        data: data.to_vec(),
                                    })
                                    .is_err()
                                {
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
                        break;
                    }
                    _ => {
                        warn!("Unexpected message type {:#04X}", msg_type);
                    }
                }
            }

            let _ = msg_tx_clone.try_send(RelayMessage::Closed);
            let _ = read_close_tx.send(true);
            debug!("Relay read task ended");
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

        Ok((Self { cmd_tx }, msg_rx))
    }
}
