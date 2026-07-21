use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::auth::{decode_auth_register, NetworkNodeKey, TicketVerifier, MSG_AUTH_REGISTER};
use crate::error::{RelayError, RelayErrorCode, Result};
use crate::protocol::*;
use crate::RelayServerConfig;

/// A peer connection representation in the server.
#[derive(Clone)]
struct PeerConnection {
    /// Channel to send frames to the connection's write task.
    tx: mpsc::Sender<Vec<u8>>,
    /// Trigger to shut down this connection (used on duplicate registration).
    shutdown_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    /// Generation identifier to resolve unregistration races.
    conn_id: u64,
}

type PeerTable = Arc<Mutex<HashMap<NetworkNodeKey, PeerConnection>>>;

/// A DERP-like relay server.
pub struct RelayServer {
    /// The address the server is listening on.
    pub addr: SocketAddr,
    /// Handle to the server task.
    handle: tokio::task::JoinHandle<()>,
    /// Shutdown trigger broadcast channel.
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl RelayServer {
    /// Start a relay server on the given address with default config.
    pub async fn start(addr: &str) -> Result<Self> {
        Self::start_with_config(addr, RelayServerConfig::default()).await
    }

    /// Start a relay server on the given address with custom config.
    pub async fn start_with_config(addr: &str, config: RelayServerConfig) -> Result<Self> {
        config.validate()?;

        // Build ticket verifier if authentication is required
        let verifier: Option<Arc<TicketVerifier>> = if config.require_authentication {
            let v = config
                .build_verifier()
                .map_err(|e| RelayError::Protocol(format!("ticket verifier: {e}")))?;
            Some(Arc::new(v))
        } else {
            None
        };

        // Determine listener: TLS or plaintext
        let has_tls = config.tls_cert_chain_path.is_some() && config.tls_private_key_path.is_some();

        let (listener, actual_addr) = if has_tls {
            let tls_config = crate::tls::load_tls_server_config(
                config.tls_cert_chain_path.as_ref().unwrap(),
                config.tls_private_key_path.as_ref().unwrap(),
            )
            .map_err(|e| RelayError::Protocol(format!("failed to load TLS server config: {e}")))?;
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
            let tcp_listener = TcpListener::bind(addr).await?;
            let addr = tcp_listener.local_addr()?;
            info!("Relay server listening on {} with TLS 1.3", addr);
            (
                AcceptStream::Tls {
                    listener: tcp_listener,
                    acceptor,
                },
                addr,
            )
        } else {
            let listener = TcpListener::bind(addr).await?;
            let addr = listener.local_addr()?;
            if config.allow_insecure_plaintext {
                warn!(
                    "Relay server listening on {} in PLAINTEXT mode (development only)",
                    addr
                );
            }
            info!("Relay server listening on {}", addr);
            (AcceptStream::Tcp(listener), addr)
        };

        let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(config.max_connections));
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        let c_config = config.clone();
        let c_verifier = verifier.clone();
        let s_tx = shutdown_tx.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let handle = tokio::spawn(async move {
            let mut join_set = tokio::task::JoinSet::new();
            let mut next_conn_id = 0u64;

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        debug!("Accept loop exiting due to shutdown signal");
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok(accepted) => {
                                // Connection limit check BEFORE TLS handshake
                                match semaphore.clone().try_acquire_owned() {
                                    Ok(permit) => {
                                        let table = peer_table.clone();
                                        let client_cfg = c_config.clone();
                                        let verifier = c_verifier.clone();
                                        next_conn_id += 1;
                                        let conn_id = next_conn_id;
                                        let conn_shutdown_rx = s_tx.subscribe();
                                        let handshake_timeout = client_cfg.register_timeout;
                                        join_set.spawn(async move {
                                            let _permit = permit;

                                            // TLS handshake (if configured) happens in task, with timeout
                                            let stream: Box<dyn AsyncReadWrite> = if let Some(acceptor) = accepted.tls_acceptor {
                                                match tokio::time::timeout(
                                                    handshake_timeout,
                                                    acceptor.accept(accepted.stream),
                                                ).await {
                                                    Ok(Ok(tls_stream)) => Box::new(tls_stream),
                                                    Ok(Err(e)) => {
                                                        warn!("TLS handshake failed: {}", e);
                                                        return;
                                                    }
                                                    Err(_) => {
                                                        warn!("TLS handshake timed out");
                                                        return;
                                                    }
                                                }
                                            } else {
                                                Box::new(accepted.stream)
                                            };

                                            if let Err(e) = handle_client(stream, table, conn_id, client_cfg, verifier, conn_shutdown_rx).await {
                                                warn!("Client connection error: {}", e);
                                            }
                                        });
                                    }
                                    Err(_) => {
                                        let mut stream = accepted.stream;
                                        let _ = tokio::time::timeout(Duration::from_millis(50), async {
                                            let _ = stream.write_all(&Frame::error(ERR_CONNECTION_LIMIT, "connection limit exceeded").encode()).await;
                                            let _ = AsyncWriteExt::shutdown(&mut stream).await;
                                        }).await;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Accept error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = join_set.join_next(), if !join_set.is_empty() => {}
                }
            }

            while join_set.join_next().await.is_some() {}
        });

        Ok(Self {
            addr: actual_addr,
            handle,
            shutdown_tx,
        })
    }

    /// Start a relay server on a random port (for testing) — uses dev mode.
    pub async fn start_random() -> Result<Self> {
        let config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            allow_legacy_unauthenticated: true,
            ..Default::default()
        };
        Self::start_with_config("127.0.0.1:0", config).await
    }

    /// Shut down the relay server.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.handle.await;
        info!("Relay server shut down");
    }
}

/// Enum abstracting over plaintext and TLS acceptors.
/// TCP accept is fast (just accept the socket); TLS handshake is deferred
/// to the per-connection task so it cannot block the accept loop.
enum AcceptStream {
    Tcp(TcpListener),
    Tls {
        listener: TcpListener,
        acceptor: TlsAcceptor,
    },
}

struct AcceptedConn {
    stream: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
}

impl AcceptStream {
    async fn accept(&self) -> std::io::Result<AcceptedConn> {
        match self {
            AcceptStream::Tcp(listener) => {
                let (stream, _addr) = listener.accept().await?;
                stream.set_nodelay(true).ok();
                Ok(AcceptedConn {
                    stream,
                    tls_acceptor: None,
                })
            }
            AcceptStream::Tls { listener, acceptor } => {
                let (tcp_stream, _addr) = listener.accept().await?;
                tcp_stream.set_nodelay(true).ok();
                Ok(AcceptedConn {
                    stream: tcp_stream,
                    tls_acceptor: Some(acceptor.clone()),
                })
            }
        }
    }
}

/// Trait for types that are both AsyncRead and AsyncWrite.
trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Handle a single client connection.
async fn handle_client(
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

/// Read and validate the first frame from a new connection.
async fn read_first_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    config: &RelayServerConfig,
    shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
    dup_shutdown_rx: &mut tokio::sync::oneshot::Receiver<()>,
) -> std::result::Result<Frame, (RelayError, Option<NetworkNodeKey>)> {
    let first_frame_fut = async {
        let mut buf = [0u8; FRAME_HEADER_SIZE + MAX_NODE_ID_LEN];
        reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]).await?;
        if buf[..4] != MAGIC {
            return Err(RelayError::InvalidMagic);
        }
        let version = buf[4];
        if version != VERSION {
            return Err(RelayError::UnsupportedVersion(version));
        }
        let msg_type = buf[5];
        let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        if payload_len > config.max_frame_payload {
            return Err(RelayError::FrameTooLarge(
                payload_len,
                config.max_frame_payload,
            ));
        }

        // For MSG_AUTH_REGISTER, payload could be larger; use a dynamic buffer
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload).await?;
        }
        Ok(Frame::new(msg_type, payload))
    };

    match tokio::select! {
        _ = shutdown_rx.recv() => {
            Err((RelayError::Closed("shutdown".into()), None))
        }
        _ = dup_shutdown_rx => {
            Err((RelayError::Closed("duplicate".into()), None))
        }
        res = tokio::time::timeout(config.register_timeout, first_frame_fut) => match res {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(e)) => Err((e, None)),
            Err(_) => Err((RelayError::Timeout("registration timed out".into()), None)),
        }
    } {
        Ok(frame) => Ok(frame),
        Err((e, key)) => Err((e, key)),
    }
}

/// Read loop after successful registration. Forwards data between peers
/// scoped to the source's network.
#[allow(clippy::too_many_arguments)]
async fn run_read_loop<R: AsyncRead + Unpin>(
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
            res = tokio::time::timeout(config.idle_timeout, read_header_fut) => match res {
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
                res = tokio::time::timeout(config.idle_timeout, read_payload_fut) => match res {
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
                                        "target peer outbound queue full"
                                    )
                                    .encode()
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                try_queue!(
                                    tx,
                                    Frame::error(
                                        ERR_PEER_NOT_FOUND,
                                        "target peer write channel closed"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RelayClient;
    use crate::{RelayClientConfig, RelayErrorCode, RelayMessage};
    use std::time::Duration;

    /// Create a dev-mode config for localhost testing.
    fn dev_config() -> RelayServerConfig {
        RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            allow_legacy_unauthenticated: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_server_start_and_shutdown() {
        let server = RelayServer::start_random().await.unwrap();
        assert!(server.addr.port() > 0);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_client_register_and_forward() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        // Client A registers
        let (mut client_a, mut rx_a) = RelayClient::connect(&addr.to_string(), "nodeA")
            .await
            .unwrap();

        // Client B registers
        let (mut client_b, mut rx_b) = RelayClient::connect(&addr.to_string(), "nodeB")
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // A sends data to B
        client_a.send_data("nodeB", b"hello from A").await.unwrap();

        // B should receive it
        let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        if let RelayMessage::Data { from_node, data } = received {
            assert_eq!(from_node, "nodeA");
            assert_eq!(data, b"hello from A");
        } else {
            panic!("Expected Data, got {:?}", received);
        }

        // B sends data back to A
        client_b.send_data("nodeA", b"hi from B").await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        if let RelayMessage::Data { from_node, data } = received {
            assert_eq!(from_node, "nodeB");
            assert_eq!(data, b"hi from B");
        } else {
            panic!("Expected Data, got {:?}", received);
        }

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_forward_to_nonexistent_peer() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "lonely")
            .await
            .unwrap();

        // Send to a peer that doesn't exist
        client.send_data("ghost", b"data").await.unwrap();

        // Should receive an error
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert!(matches!(received, RelayMessage::Error { code: 404, .. }));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_ping_pong() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
            .await
            .unwrap();

        client.ping().await.unwrap();

        // Should receive a pong
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert!(matches!(received, RelayMessage::Pong { .. }));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_multiple_peers() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        // Register 3 clients
        let (_c1, mut rx1) = RelayClient::connect(&addr.to_string(), "p1").await.unwrap();
        let (_c2, mut rx2) = RelayClient::connect(&addr.to_string(), "p2").await.unwrap();
        let (mut c3, _rx3) = RelayClient::connect(&addr.to_string(), "p3").await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // p3 sends to p1 and p2
        c3.send_data("p1", b"to p1").await.unwrap();
        c3.send_data("p2", b"to p2").await.unwrap();

        let r1 = tokio::time::timeout(Duration::from_secs(2), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r1,
            RelayMessage::Data {
                from_node: "p3".to_string(),
                data: b"to p1".to_vec()
            }
        );

        let r2 = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            r2,
            RelayMessage::Data {
                from_node: "p3".to_string(),
                data: b"to p2".to_vec()
            }
        );

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_large_data_transfer() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client_a, _rxa) = RelayClient::connect(&addr.to_string(), "bigA")
            .await
            .unwrap();
        let (_client_b, mut rxb) = RelayClient::connect(&addr.to_string(), "bigB")
            .await
            .unwrap();

        // Send 60KB of data
        let big_data = vec![0x42u8; 60000];
        client_a.send_data("bigB", &big_data).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rxb.recv())
            .await
            .unwrap()
            .unwrap();

        if let RelayMessage::Data { from_node, data } = received {
            assert_eq!(from_node, "bigA");
            assert_eq!(data.len(), 60000);
            assert!(data.iter().all(|&b| b == 0x42));
        } else {
            panic!("Expected Data, got {:?}", received);
        }

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_invalid_limits() {
        let config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            max_connections: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        assert!(RelayServer::start_with_config("127.0.0.1:0", config)
            .await
            .is_err());

        let client_cfg = RelayClientConfig {
            cmd_queue_capacity: 0,
            ..Default::default()
        };
        assert!(client_cfg.validate().is_err());
    }

    #[tokio::test]
    async fn test_client_command_and_inbound_queue_bounded() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let config = RelayClientConfig {
            cmd_queue_capacity: 1,
            inbound_queue_capacity: 1,
            ..Default::default()
        };

        let (_client, _rx) =
            RelayClient::connect_verified_with_config(&addr.to_string(), "client-bounded", config)
                .await
                .unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_server_outbound_queue_full_policy() {
        let config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            outbound_queue_capacity: 1,
            ..dev_config()
        };

        let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));
        let (bob_tx, _bob_rx) = mpsc::channel::<Vec<u8>>(1);
        bob_tx
            .try_send(Frame::received("existing", b"queued").unwrap().encode())
            .unwrap();
        let (bob_shutdown_tx, mut bob_shutdown_rx) = tokio::sync::oneshot::channel();
        peer_table.lock().await.insert(
            NetworkNodeKey::new(String::new(), "bob".to_string()),
            PeerConnection {
                tx: bob_tx,
                shutdown_tx: Arc::new(Mutex::new(Some(bob_shutdown_tx))),
                conn_id: 1,
            },
        );

        let (mut client_side, server_side) = tokio::io::duplex(4096);
        let (alice_tx, mut alice_rx) = mpsc::channel::<Vec<u8>>(4);
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let (_dup_shutdown_tx, dup_shutdown_rx) = tokio::sync::oneshot::channel();
        let registered_key = Some(NetworkNodeKey::new(String::new(), "alice".to_string()));
        let shutdown_rx = shutdown_tx.subscribe();

        let task = tokio::spawn(async move {
            run_read_loop(
                server_side,
                alice_tx,
                2,
                &config,
                shutdown_rx,
                dup_shutdown_rx,
                peer_table.clone(),
                "alice",
                String::new(),
                registered_key,
                None,
            )
            .await
        });

        client_side
            .write_all(&Frame::forward("bob", b"payload").unwrap().encode())
            .await
            .unwrap();

        let error_bytes = tokio::time::timeout(Duration::from_secs(1), alice_rx.recv())
            .await
            .expect("timed out waiting for backpressure error")
            .expect("alice outbound queue closed before error");
        let (error_frame, consumed) = Frame::decode(&error_bytes).unwrap();
        assert_eq!(consumed, error_bytes.len());
        assert_eq!(error_frame.msg_type, MSG_ERROR);
        let (code, message) = error_frame.parse_error().unwrap();
        assert_eq!(code, ERR_PEER_BACKPRESSURE);
        assert!(message.contains("outbound queue full"));

        tokio::time::timeout(Duration::from_secs(1), &mut bob_shutdown_rx)
            .await
            .expect("timed out waiting for slow peer shutdown")
            .expect("slow peer shutdown sender dropped");

        let _ = shutdown_tx.send(());
        drop(client_side);
        let _ = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("relay read loop did not shut down");
    }

    #[tokio::test]
    async fn test_register_timeout() {
        let server_config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            register_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let frame = Frame::decode(&buf[..n]);
        if let Ok((f, _)) = frame {
            assert_eq!(f.msg_type, MSG_ERROR);
            let (code, _) = f.parse_error().unwrap();
            assert_eq!(code, ERR_REGISTRATION_TIMEOUT);
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_idle_timeout() {
        let server_config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            idle_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let (_client, mut rx) = RelayClient::connect_verified(&addr.to_string(), "client-idle")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let msg = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(msg, RelayMessage::Error { code: 4009, .. }));
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_max_connections() {
        let server_config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            max_connections: 1,
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let (_client1, _rx1) = RelayClient::connect_verified(&addr.to_string(), "c1")
            .await
            .unwrap();
        let res = RelayClient::connect_verified(&addr.to_string(), "c2").await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        if let RelayError::ServerError(code, _) = err {
            assert_eq!(code, ERR_CONNECTION_LIMIT);
        } else {
            panic!("Expected server error, got: {:?}", err);
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_oversized_frame_rejected_before_payload() {
        let server_config = RelayServerConfig {
            allow_insecure_plaintext: true,
            require_authentication: false,
            max_frame_payload: 10,
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let reg = Frame::register("c1").encode();
        stream.write_all(&reg).await.unwrap();
        let mut buf = [0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC);
        header.push(VERSION);
        header.push(MSG_FORWARD);
        header.extend_from_slice(&1000u16.to_be_bytes());
        stream.write_all(&header).await.unwrap();

        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_ERROR);
        let (code, _) = f.parse_error().unwrap();
        assert_eq!(code, ERR_FRAME_TOO_LARGE);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_duplicate_registration_race_and_ownership() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let client1 = RelayClient::connect_verified(&addr.to_string(), "dup")
            .await
            .unwrap()
            .0;
        let (_client2, mut rx2) = RelayClient::connect_verified(&addr.to_string(), "dup")
            .await
            .unwrap();

        // client1 exiting should be clean
        drop(client1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (mut client3, _rx3) = RelayClient::connect_verified(&addr.to_string(), "sender3")
            .await
            .unwrap();
        client3.send_data("dup", b"still here").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        if let RelayMessage::Data { from_node, data } = msg {
            assert_eq!(from_node, "sender3");
            assert_eq!(data, b"still here");
        } else {
            panic!("Expected Data, got {:?}", msg);
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_duplicate_registration_same_connection() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let reg1 = Frame::register("node-a").encode();
        stream.write_all(&reg1).await.unwrap();
        let mut buf = [0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        stream.write_all(&reg1).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        let reg2 = Frame::register("node-b").encode();
        stream.write_all(&reg2).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_ERROR);
        let (code, _) = f.parse_error().unwrap();
        assert_eq!(code, ERR_DUPLICATE_REGISTRATION);
        server.shutdown().await;
    }

    #[test]
    fn test_unknown_wire_error_code() {
        let frame = Frame::error(9999, "unknown issue");
        let (code, msg) = frame.parse_error().unwrap();
        assert_eq!(code, 9999);
        assert_eq!(msg, "unknown issue");

        let ec = RelayErrorCode::from_u16(9999);
        assert!(ec.is_none());
    }

    #[tokio::test]
    async fn test_real_shutdown_lifecycle() {
        let server_config = dev_config();
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let (mut client, mut rx) =
            RelayClient::connect_verified(&addr.to_string(), "lifecycle-node")
                .await
                .unwrap();

        client.ping().await.unwrap();
        let pong = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(pong, RelayMessage::Pong { .. }));

        server.shutdown().await;

        let closed_msg = tokio::time::timeout(Duration::from_millis(500), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(closed_msg, RelayMessage::Closed);
    }

    /// Deterministic registration cleanup test: shares the server's peer_table directly
    /// and verifies the mapping is absent after the handler task exits.
    #[tokio::test]
    async fn test_error_after_registration_cleanup_deterministic() {
        // Build server internals so we can inspect peer_table directly.
        let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept loop: spawn a single client handler, then stop.
        let table_clone = peer_table.clone();
        let s_tx = shutdown_tx.clone();
        let handler_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let shutdown_rx = s_tx.subscribe();
            let config = dev_config();
            handle_client(Box::new(stream), table_clone, 1, config, None, shutdown_rx).await
        });

        // --- Client side ---
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(&Frame::register("errnode").encode())
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        // Verify the mapping is present right after registration.
        {
            let table = peer_table.lock().await;
            let key = NetworkNodeKey::new(String::new(), "errnode".to_string());
            assert!(
                table.contains_key(&key),
                "peer table must contain errnode after registration"
            );
        }

        // Send a bad-version frame to force a protocol error that tears down the handler.
        let mut bad_frame = Vec::new();
        bad_frame.extend_from_slice(&MAGIC);
        bad_frame.push(99); // bad version
        bad_frame.push(MSG_PING);
        bad_frame.extend_from_slice(&0u16.to_be_bytes());
        stream.write_all(&bad_frame).await.unwrap();

        // Read until the connection is closed (error frame + EOF).
        let total_read = tokio::time::timeout(Duration::from_secs(2), async {
            let mut total_read = 0usize;
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total_read += n,
                }
            }
            total_read
        })
        .await
        .expect("connection did not close within 2s");
        assert!(total_read > 0, "expected at least an error frame");

        // Wait for the handler task to finish (guarantees cleanup ran).
        tokio::time::timeout(Duration::from_secs(2), handler_task)
            .await
            .expect("handler did not finish within 2s")
            .expect("handler task panicked")
            .ok();

        // The mapping must now be gone.
        {
            let table = peer_table.lock().await;
            let key = NetworkNodeKey::new(String::new(), "errnode".to_string());
            assert!(
                !table.contains_key(&key),
                "peer table must NOT contain errnode after handler exit"
            );
        }
    }

    #[tokio::test]
    async fn test_client_config_invalid() {
        let config = RelayClientConfig {
            idle_timeout: Duration::from_secs(5),
            keepalive_interval: Duration::from_secs(10),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config2 = RelayClientConfig {
            keepalive_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(config2.validate().is_err());
    }

    /// Verify that a silent server (never responds to pings) triggers idle timeout and
    /// the client delivers Error{4009} + Closed.
    #[tokio::test]
    async fn test_client_idle_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let (f, _) = Frame::decode(&buf[..n]).unwrap();
            assert_eq!(f.msg_type, MSG_REGISTER);
            // Reply with Registered, then go silent — never respond to Ping.
            stream
                .write_all(&Frame::registered("client-idle").encode())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let config = RelayClientConfig {
            idle_timeout: Duration::from_millis(100),
            keepalive_interval: Duration::from_millis(40),
            ..Default::default()
        };
        let (_client, mut rx) =
            RelayClient::connect_verified_with_config(&addr.to_string(), "client-idle", config)
                .await
                .unwrap();

        let msg1 = tokio::time::timeout(Duration::from_millis(400), rx.recv())
            .await
            .expect("timed out waiting for idle-timeout error")
            .expect("channel closed unexpectedly");
        assert_eq!(
            msg1,
            RelayMessage::Error {
                code: 4009,
                message: "idle timeout".to_string()
            }
        );

        let msg2 = tokio::time::timeout(Duration::from_millis(400), rx.recv())
            .await
            .expect("timed out waiting for Closed")
            .expect("channel closed unexpectedly");
        assert_eq!(msg2, RelayMessage::Closed);
    }

    /// Verify that a working relay server (responds with Pong) does NOT trigger idle
    /// timeout even when the client's idle_timeout is short.
    #[tokio::test]
    async fn test_keepalive_prevents_idle_timeout() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        // idle_timeout=200ms, keepalive_interval=60ms — pings arrive well within timeout.
        let config = RelayClientConfig {
            idle_timeout: Duration::from_millis(200),
            keepalive_interval: Duration::from_millis(60),
            ..Default::default()
        };
        let (_client, mut rx) =
            RelayClient::connect_verified_with_config(&addr.to_string(), "keepalive-node", config)
                .await
                .unwrap();

        // Over ~400ms (several keepalive cycles) we should receive only Pong messages,
        // no Error{4009} or Closed.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
        let mut pong_count = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(RelayMessage::Pong { .. })) => {
                    pong_count += 1;
                }
                Ok(Some(RelayMessage::Error { code, message })) => {
                    panic!("unexpected error during keepalive: code={code}, msg={message}");
                }
                Ok(Some(RelayMessage::Closed)) => {
                    panic!("connection closed unexpectedly during keepalive test");
                }
                Ok(Some(other)) => {
                    panic!("unexpected message: {other:?}");
                }
                Ok(None) | Err(_) => break,
            }
        }

        assert!(
            pong_count >= 2,
            "expected at least 2 Pong responses during keepalive window, got {pong_count}"
        );
        server.shutdown().await;
    }
}
