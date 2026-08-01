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

mod connection;

use connection::handle_client;
#[cfg(test)]
use connection::run_read_loop;

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

#[cfg(test)]
mod tests;
