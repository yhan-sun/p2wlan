//! Coordinate one active open on the already authenticated TCP connection.
//! Both ends must authenticate the new stream and agree on the result before
//! the old connection is released. The dialed endpoint is always the peer pin.
use super::*;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const ACTIVE_SETUP: Duration = Duration::from_millis(1400);
const READY: u8 = 1;
const VERIFIED: u8 = 2;

pub(super) struct AuthenticatedStream {
    pub stream: TcpStream,
    pub key: [u8; 32],
    pub opening: TcpOpening,
}

/// Two role-bound decisions on the coordinator: socket ready, then verified.
/// The session key is unique to this particular mutually authenticated stream.
pub(super) async fn exchange_decision(
    control: &mut TcpStream,
    key: &[u8; 32],
    client: bool,
    stage: u8,
    decision: bool,
) -> io::Result<bool> {
    let message = [stage, u8::from(client), u8::from(decision)];
    let mut record = [0; 33];
    record[0] = message[2];
    record[1..].copy_from_slice(&hmac(key, &message));
    control.write_all(&record).await?;
    control.read_exact(&mut record).await?;
    let expected = hmac(key, &[stage, u8::from(!client), record[0]]);
    if record[0] > 1 || !bool::from(record[1..].ct_eq(&expected)) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(record[0] == 1)
}

pub(super) async fn establish(
    peers: &PeerManager,
    peer: &str,
    grant: &Grant,
    mut control: TcpStream,
    client: bool,
    requested: bool,
) -> io::Result<AuthenticatedStream> {
    control.set_nodelay(true)?;
    let mut key = grant.handshake_key(&peers.config.network.network_id, peer);
    if requested {
        key = hmac(&key, b"P2WLAN simultaneous-open coordinator v1");
    }
    let key = wire::authenticate(&mut control, key, client).await?;
    if requested {
        let socket = if grant.simultaneous && peers.tcp_setup_current(peer, grant).await {
            match p2pnet_netbind::bind_shared_tcp(grant.listener.bound) {
                Ok(socket) => Some(socket),
                Err(err) => {
                    debug!(peer, reason_code = "TCP_SIMULTANEOUS_BIND_UNAVAILABLE", %err);
                    None
                }
            }
        } else {
            None
        };
        let ready = exchange_decision(&mut control, &key, client, READY, socket.is_some()).await?;
        if let Some(socket) = socket.filter(|_| ready) {
            let active = async {
                if !peers.tcp_setup_current(peer, grant).await {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let mut stream = socket.connect(grant.endpoint).await?;
                if stream.local_addr()? != grant.listener.bound
                    || stream.peer_addr()? != grant.endpoint
                {
                    return Err(io::ErrorKind::AddrNotAvailable.into());
                }
                stream.set_nodelay(true)?;
                // No listener can answer this proof: it needs the secrets of
                // this exact coordinator and the other active-open role.
                let key = hmac(&key, b"P2WLAN simultaneous-open data v1");
                let key = wire::authenticate(&mut stream, key, client).await?;
                if !peers.tcp_setup_current(peer, grant).await {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                io::Result::Ok(AuthenticatedStream {
                    stream,
                    key,
                    opening: TcpOpening::Simultaneous,
                })
            };
            let active = match timeout(ACTIVE_SETUP, active).await {
                Ok(Ok(active)) => Some(active),
                Ok(Err(err)) => {
                    debug!(peer, reason_code = "TCP_SIMULTANEOUS_SETUP_FAILED", %err);
                    None
                }
                Err(_) => {
                    debug!(peer, reason_code = "TCP_SIMULTANEOUS_SETUP_TIMEOUT");
                    None
                }
            };
            let verified =
                exchange_decision(&mut control, &key, client, VERIFIED, active.is_some()).await?;
            if let Some(active) = active.filter(|_| verified) {
                return Ok(active);
            }
        }
    }
    Ok(AuthenticatedStream {
        stream: control,
        key,
        opening: TcpOpening::DialListen,
    })
}
