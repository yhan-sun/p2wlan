/// Handle a single client connection.
pub(super) async fn handle_client(
    stream: Box<dyn AsyncReadWrite>,
    peer_table: PeerTable,
    conn_id: u64,
    config: RelayServerConfig,
    verifier: Option<Arc<TicketVerifier>>,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<Vec<u8>>(config.outbound_queue_capacity);
    let (reader, writer) = tokio::io::split(stream);

    let write_task = tokio::spawn(async move {
        let mut writer = writer;
        let mut rx = rx;
        while let Some(frame_bytes) = rx.recv().await {
            if let Err(e) = writer.write_all(&frame_bytes).await {
                warn!("Write error to client: {}", e);
                break;
            }
        }
        let _ = AsyncWriteExt::shutdown(&mut writer).await;
        debug!("Write task ended");
    });

    let (res, registered_key) = handle_client_inner(
        reader,
        tx,
        conn_id,
        config,
        verifier,
        shutdown_rx,
        peer_table.clone(),
    )
    .await;

    if let Some(ref key) = registered_key {
        let mut table = peer_table.lock().await;
        if let Some(active) = table.get(key) {
            if active.conn_id == conn_id {
                table.remove(key);
                debug!("Removed '{}' (conn_id={}) from peer table", key, conn_id);
            }
        }
    }

    write_task.abort();
    let _ = write_task.await;

    res
}

async fn handle_client_inner(
    mut reader: tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>,
    tx: mpsc::Sender<Vec<u8>>,
    conn_id: u64,
    config: RelayServerConfig,
    verifier: Option<Arc<TicketVerifier>>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    peer_table: PeerTable,
) -> (Result<()>, Option<NetworkNodeKey>) {
    let (dup_shutdown_tx, mut dup_shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Registration phase with register_timeout
    let first_frame =
        read_first_frame(&mut reader, &config, &mut shutdown_rx, &mut dup_shutdown_rx).await;

    let first_frame = match first_frame {
        Ok(frame) => frame,
        Err((e, _)) => {
            // Send appropriate error frame before closing
            let err_code = match &e {
                RelayError::FrameTooLarge(_, _) => ERR_FRAME_TOO_LARGE,
                RelayError::Timeout(_) => ERR_REGISTRATION_TIMEOUT,
                RelayError::UnsupportedVersion(_) => ERR_UNSUPPORTED_VERSION,
                RelayError::InvalidMagic => ERR_INVALID_FRAME,
                _ => ERR_INVALID_FRAME,
            };
            let _ = tx.try_send(Frame::error(err_code, &e.to_string()).encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            return (Err(e), None);
        }
    };

    // ---- Handle legacy MSG_REGISTER (0x01) ----
    if first_frame.msg_type == MSG_REGISTER {
        if config.require_authentication && !config.allow_legacy_unauthenticated {
            let _ = tx.try_send(
                Frame::error(RelayErrorCode::AUTH_REQUIRED, "authentication required").encode(),
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            return (
                Err(RelayError::AuthError(
                    RelayErrorCode::AUTH_REQUIRED,
                    "legacy register rejected in secure mode".into(),
                )),
                None,
            );
        }

        let node_id = match std::str::from_utf8(&first_frame.payload) {
            Ok(s) => s.to_string(),
            Err(_) => {
                let _ =
                    tx.try_send(Frame::error(ERR_INVALID_FRAME, "invalid node ID UTF-8").encode());
                tokio::time::sleep(Duration::from_millis(50)).await;
                return (
                    Err(RelayError::Protocol("invalid node ID UTF-8".into())),
                    None,
                );
            }
        };

        if node_id.is_empty() || node_id.len() > MAX_NODE_ID_LEN {
            let _ = tx.try_send(Frame::error(ERR_INVALID_FRAME, "invalid node ID length").encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            return (
                Err(RelayError::Protocol("invalid node ID length".into())),
                None,
            );
        }

        // Legacy: register with empty network_id
        let network_key = NetworkNodeKey::new(String::new(), node_id.clone());

        let my_connection = PeerConnection {
            tx: tx.clone(),
            shutdown_tx: Arc::new(Mutex::new(Some(dup_shutdown_tx))),
            conn_id,
        };

        {
            let mut table = peer_table.lock().await;
            if let Some(old_conn) = table.get(&network_key) {
                warn!("Disconnecting duplicate connection for '{}'", network_key);
                if let Some(old_s_tx) = old_conn.shutdown_tx.lock().await.take() {
                    let _ = old_s_tx.send(());
                }
            }
            table.insert(network_key.clone(), my_connection);
        }

        let registered_key = Some(network_key);

        if tx.try_send(Frame::registered(&node_id).encode()).is_err() {
            return (
                Err(RelayError::Closed(
                    "write channel closed on registered reply".into(),
                )),
                registered_key,
            );
        }

        return run_read_loop(
            reader,
            tx,
            conn_id,
            &config,
            shutdown_rx,
            dup_shutdown_rx,
            peer_table,
            &node_id,
            String::new(),
            registered_key,
            None,
        )
        .await;
    }

    // ---- Handle MSG_AUTH_REGISTER (0x09) ----
    if first_frame.msg_type == MSG_AUTH_REGISTER {
        if !config.require_authentication {
            // In dev mode with auth disabled, reject auth register
            let _ = tx.try_send(
                Frame::error(ERR_INVALID_FRAME, "auth register not supported in dev mode").encode(),
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            return (
                Err(RelayError::Protocol(
                    "auth register not supported in dev mode".into(),
                )),
                None,
            );
        }

        // Parse auth register payload
        let (frame_node_id, ticket) = match decode_auth_register(&first_frame.payload) {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.try_send(Frame::error(RelayErrorCode::INVALID_TICKET, &e).encode());
                tokio::time::sleep(Duration::from_millis(50)).await;
                return (
                    Err(RelayError::AuthError(RelayErrorCode::INVALID_TICKET, e)),
                    None,
                );
            }
        };

        // Verify JWT ticket with the configured verifier
        let verifier = match &verifier {
            Some(v) => v,
            None => {
                let _ = tx.try_send(
                    Frame::error(
                        RelayErrorCode::INVALID_TICKET,
                        "ticket verification not configured",
                    )
                    .encode(),
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
                return (
                    Err(RelayError::AuthError(
                        RelayErrorCode::INVALID_TICKET,
                        "ticket verification not configured".into(),
                    )),
                    None,
                );
            }
        };

        let verified = match verifier.verify(&ticket) {
            Ok(v) => v,
            Err(e) => {
                let code = e
                    .error_code()
                    .map(|c| c.to_u16())
                    .unwrap_or(RelayErrorCode::INVALID_TICKET);
                let _ = tx.try_send(Frame::error(code, &e.to_string()).encode());
                tokio::time::sleep(Duration::from_millis(50)).await;
                return (Err(e), None);
            }
        };

        // Validate identity: frame node_id must match ticket node_id
        if frame_node_id != verified.claims.node_id {
            let _ = tx.try_send(
                Frame::error(
                    RelayErrorCode::IDENTITY_MISMATCH,
                    "node_id does not match ticket",
                )
                .encode(),
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            return (
                Err(RelayError::AuthError(
                    RelayErrorCode::IDENTITY_MISMATCH,
                    "node_id mismatch".into(),
                )),
                None,
            );
        }

        let network_id = verified.claims.network_id.clone();
        let node_id = verified.claims.node_id.clone();
        let ticket_expiry = verified.claims.exp;

        // Register in peer table with network binding
        let network_key = NetworkNodeKey::new(network_id.clone(), node_id.clone());

        let my_connection = PeerConnection {
            tx: tx.clone(),
            shutdown_tx: Arc::new(Mutex::new(Some(dup_shutdown_tx))),
            conn_id,
        };

        {
            let mut table = peer_table.lock().await;
            if let Some(old_conn) = table.get(&network_key) {
                warn!("Disconnecting duplicate connection for '{}'", network_key);
                if let Some(old_s_tx) = old_conn.shutdown_tx.lock().await.take() {
                    let _ = old_s_tx.send(());
                }
            }
            table.insert(network_key.clone(), my_connection);
        }

        let registered_key = Some(network_key.clone());

        if tx.try_send(Frame::registered(&node_id).encode()).is_err() {
            return (
                Err(RelayError::Closed(
                    "write channel closed on registered reply".into(),
                )),
                registered_key,
            );
        }

        return run_read_loop(
            reader,
            tx,
            conn_id,
            &config,
            shutdown_rx,
            dup_shutdown_rx,
            peer_table,
            &node_id,
            network_id,
            registered_key,
            ticket_expiry,
        )
        .await;
    }

    // Unknown first frame type
    if config.require_authentication {
        let _ = tx.try_send(
            Frame::error(RelayErrorCode::AUTH_REQUIRED, "authentication required").encode(),
        );
    } else {
        let _ =
            tx.try_send(Frame::error(ERR_REGISTRATION_REQUIRED, "registration required").encode());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    (
        Err(RelayError::Protocol(
            "first frame must be register or auth register".into(),
        )),
        None,
    )
}
