/// Avoid treating a busy executor as an idle peer. The read deadline is
/// measured by Tokio's monotonic clock, so a relay task that is descheduled
/// while a keepalive is already queued can observe the timeout before it gets
/// a chance to consume that frame. Keep the grace bounded for normal (large)
/// production timeouts while making sub-second timeouts tolerant of one
/// scheduling hiccup.
fn effective_idle_timeout(idle_timeout: Duration) -> Duration {
    let grace = (idle_timeout / 2).min(Duration::from_secs(1));
    idle_timeout.saturating_add(grace)
}

/// Read loop after successful registration. Forwards data between peers
/// scoped to the source's network.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_read_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    tx: mpsc::Sender<Vec<u8>>,
    _conn_id: u64,
    config: &RelayServerConfig,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    mut dup_shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    peer_table: PeerTable,
    node_id: &str,
    network_id: String,
    registered_key: Option<NetworkNodeKey>,
    ticket_expiry: Option<i64>,
) -> (Result<()>, Option<NetworkNodeKey>) {
    let node_id = node_id.to_string();

    // Build optional ticket expiry deadline
    let expiry_deadline = ticket_expiry.and_then(|exp| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if exp > now {
            let remaining = Duration::from_secs((exp - now) as u64);
            Some(tokio::time::Instant::now() + remaining)
        } else {
            None
        }
    });

    macro_rules! try_queue {
        ($tx:expr, $frame:expr) => {
            match $tx.try_send($frame) {
                Ok(_) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!("Outbound queue full, closing connection");
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    debug!("Outbound queue closed, exiting");
                    break;
                }
            }
        };
    }

    let mut buf = vec![0u8; config.max_frame_payload + FRAME_HEADER_SIZE];
    let idle_timeout = effective_idle_timeout(config.idle_timeout);

    loop {
        // ---- Read header with timeout, shutdown, duplicate, ticket expiry ----
        let read_header_fut = reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]);
        let read_res = tokio::select! {
            _ = shutdown_rx.recv() => {
                debug!("Client '{}' connection closed by server shutdown", node_id);
                break;
            }
            _ = &mut dup_shutdown_rx => {
                debug!("Client '{}' connection closed by duplicate registration", node_id);
                break;
            }
            _ = async {
                if let Some(deadline) = expiry_deadline {
                    tokio::time::sleep_until(deadline).await;
                    true
                } else {
                    std::future::pending::<bool>().await
                }
            }, if expiry_deadline.is_some() => {
                debug!("Client '{}' ticket expired", node_id);
                try_queue!(tx, Frame::error(RelayErrorCode::TICKET_EXPIRED, "ticket expired").encode());
                tokio::time::sleep(Duration::from_millis(50)).await;
                break;
            }
            res = tokio::time::timeout(idle_timeout, read_header_fut) => match res {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Client '{}' disconnected", node_id);
                    break;
                }
                Ok(Err(e)) => Err(RelayError::Io(e)),
                Err(_) => {
                    debug!("Client '{}' idle timeout", node_id);
                    try_queue!(tx, Frame::error(ERR_IDLE_TIMEOUT, "idle timeout").encode());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    break;
                }
            }
        };

        if let Err(e) = read_res {
            warn!("Read error from '{}': {}", node_id, e);
            break;
        }

        if buf[..4] != MAGIC {
            warn!("Invalid magic from '{}'", node_id);
            try_queue!(
                tx,
                Frame::error(ERR_INVALID_FRAME, "invalid magic").encode()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }
        let version = buf[4];
        if version != VERSION {
            warn!("Unsupported version {} from '{}'", version, node_id);
            try_queue!(
                tx,
                Frame::error(ERR_UNSUPPORTED_VERSION, "unsupported version").encode()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }
        let msg_type = buf[5];
        let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        if payload_len > config.max_frame_payload {
            warn!(
                "Payload length {} exceeds limit {}",
                payload_len, config.max_frame_payload
            );
            try_queue!(
                tx,
                Frame::error(ERR_FRAME_TOO_LARGE, "frame too large").encode()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }

        // ---- Read payload with same timeout/shutdown/duplicate/expiry as header ----
        if payload_len > 0 {
            if buf.len() < FRAME_HEADER_SIZE + payload_len {
                buf.resize(FRAME_HEADER_SIZE + payload_len, 0);
            }
            let read_payload_fut =
                reader.read_exact(&mut buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len]);
            let read_payload_res = tokio::select! {
                _ = shutdown_rx.recv() => { break; }
                _ = &mut dup_shutdown_rx => { break; }
                _ = async {
                    if let Some(deadline) = expiry_deadline {
                        tokio::time::sleep_until(deadline).await;
                        true
                    } else {
                        std::future::pending::<bool>().await
                    }
                }, if expiry_deadline.is_some() => {
                    try_queue!(tx, Frame::error(RelayErrorCode::TICKET_EXPIRED, "ticket expired").encode());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    break;
                }
                res = tokio::time::timeout(idle_timeout, read_payload_fut) => match res {
                    Ok(Ok(_)) => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(_) => {
                        warn!("Client '{}' idle timeout during payload", node_id);
                        Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))
                    }
                },
            };
            if let Err(e) = read_payload_res {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    try_queue!(tx, Frame::error(ERR_IDLE_TIMEOUT, "idle timeout").encode());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                } else {
                    warn!("Payload read error from '{}': {}", node_id, e);
                }
                break;
            }
        }

        let payload = &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

        match msg_type {
            MSG_REGISTER => {
                let new_id = match std::str::from_utf8(payload) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        try_queue!(
                            tx,
                            Frame::error(ERR_INVALID_FRAME, "invalid node ID").encode()
                        );
                        continue;
                    }
                };
                if new_id != node_id {
                    try_queue!(
                        tx,
                        Frame::error(
                            ERR_DUPLICATE_REGISTRATION,
                            "already registered with a different node ID"
                        )
                        .encode()
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    break;
                } else {
                    try_queue!(tx, Frame::registered(&new_id).encode());
                }
            }

            MSG_FORWARD => {
                if payload.is_empty() {
                    try_queue!(
                        tx,
                        Frame::error(ERR_INVALID_FRAME, "empty forward payload").encode()
                    );
                    continue;
                }

                let dst_len = payload[0] as usize;
                if payload.len() < 1 + dst_len {
                    try_queue!(
                        tx,
                        Frame::error(ERR_INVALID_FRAME, "malformed forward").encode()
                    );
                    continue;
                }

                let dst_id = match std::str::from_utf8(&payload[1..1 + dst_len]) {
                    Ok(s) => s,
                    Err(_) => {
                        try_queue!(
                            tx,
                            Frame::error(ERR_INVALID_FRAME, "invalid dst ID").encode()
                        );
                        continue;
                    }
                };

                let data = &payload[1 + dst_len..];

                let total_received_len = 1 + node_id.len() + data.len();
                if total_received_len > config.max_frame_payload {
                    try_queue!(
                        tx,
                        Frame::error(ERR_FRAME_TOO_LARGE, "forward payload too large").encode()
                    );
                    continue;
                }

                // Network-scoped lookup: only find destination in the same network
                let dst_key = NetworkNodeKey::new(network_id.clone(), dst_id.to_string());
                let dst_conn = {
                    let table = peer_table.lock().await;
                    table.get(&dst_key).cloned()
                };

                match dst_conn {
                    Some(dst) => match Frame::received(&node_id, data) {
                        Ok(frame) => match dst.tx.try_send(frame.encode()) {
                            Ok(_) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!("Target '{}' is slow consumer, closing it", dst_id);
                                if let Some(s_tx) = dst.shutdown_tx.lock().await.take() {
                                    let _ = s_tx.send(());
                                }
                                try_queue!(
                                    tx,
                                    Frame::error(
                                        ERR_PEER_BACKPRESSURE,
                                        &format!("peer backpressure: {dst_id}")
                                    )
                                    .encode()
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                try_queue!(
                                    tx,
                                    Frame::error(
                                        ERR_PEER_NOT_FOUND,
                                        &format!("peer disconnected: {dst_id}")
                                    )
                                    .encode()
                                );
                            }
                        },
                        Err(e) => {
                            try_queue!(
                                tx,
                                Frame::error(ERR_INVALID_FRAME, &e.to_string()).encode()
                            );
                        }
                    },
                    None => {
                        try_queue!(
                            tx,
                            Frame::error(ERR_PEER_NOT_FOUND, &format!("peer not found: {dst_id}"))
                                .encode()
                        );
                    }
                }
            }

            MSG_PING => {
                let ts = if payload.len() >= 8 {
                    u64::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                        payload[6], payload[7],
                    ])
                } else {
                    0
                };
                try_queue!(tx, Frame::pong(ts).encode());
            }

            MSG_CLOSE => {
                debug!("Client '{}' sent close", node_id);
                break;
            }

            _ => {
                warn!(
                    "Unexpected message type {:#04X} from client '{}'",
                    msg_type, node_id
                );
                try_queue!(
                    tx,
                    Frame::error(ERR_INVALID_FRAME, "unexpected message type").encode()
                );
            }
        }
    }

    (Ok(()), registered_key)
}
