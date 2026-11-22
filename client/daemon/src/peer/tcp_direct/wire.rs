//! Fixed-size authenticated liveness exchanges and length-framed WireGuard data.
use super::{hmac, io};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(super) const PING: u16 = 0;
pub(super) const PONG: u16 = 1;
pub(super) const MAX_ID: usize = 128;
const HEADER: &[u8; 4] = b"PDT1";

pub(super) async fn identify(stream: &mut TcpStream, id: &str) -> io::Result<()> {
    if id.is_empty() || id.len() > MAX_ID {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    stream.write_all(HEADER).await?;
    stream.write_u8(id.len() as u8).await?;
    stream.write_all(id.as_bytes()).await
}

pub(super) async fn read_identity(stream: &mut TcpStream) -> io::Result<String> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let len = usize::from(stream.read_u8().await?);
    if &header != HEADER || !(1..=MAX_ID).contains(&len) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut id = vec![0; len];
    stream.read_exact(&mut id).await?;
    String::from_utf8(id).map_err(|_| io::ErrorKind::InvalidData.into())
}

// Each role proves possession twice against independently sampled nonces.
// The preceding authenticated transcript feeds the next round and heartbeat key.
pub(super) async fn authenticate(
    stream: &mut TcpStream,
    mut key: [u8; 32],
    client: bool,
) -> io::Result<[u8; 32]> {
    for round in 0..2 {
        let local: [u8; 32] = rand::random();
        let mut remote = [0; 32];
        stream.write_all(&local).await?;
        stream.read_exact(&mut remote).await?;
        let (a, b) = if client {
            (local, remote)
        } else {
            (remote, local)
        };
        let mut transcript = [0; 66];
        transcript[0] = round;
        transcript[2..34].copy_from_slice(&a);
        transcript[34..].copy_from_slice(&b);
        transcript[1] = u8::from(client);
        stream.write_all(&hmac(&key, &transcript)).await?;
        transcript[1] = u8::from(!client);
        let mut tag = [0; 32];
        stream.read_exact(&mut tag).await?;
        if !bool::from(tag.ct_eq(&hmac(&key, &transcript))) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        transcript[1] = 2;
        key = hmac(&key, &transcript);
    }
    Ok(key)
}

pub(super) fn data_record(wire: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(wire.len()).ok()?;
    if len < 32 || crate::transport::wire_counter(wire).is_none() {
        return None;
    }
    let mut record = Vec::with_capacity(2 + wire.len());
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(wire);
    Some(record)
}

pub(super) fn heartbeat(key: &[u8; 32], kind: u16, client: bool, nonce: &[u8; 32]) -> [u8; 66] {
    let mut body = [0; 35];
    body[..2].copy_from_slice(&kind.to_be_bytes());
    body[2] = u8::from(client);
    body[3..].copy_from_slice(nonce);
    let mut record = [0; 66];
    record[..2].copy_from_slice(&kind.to_be_bytes());
    record[2..34].copy_from_slice(nonce);
    record[34..].copy_from_slice(&hmac(key, &body));
    record
}
