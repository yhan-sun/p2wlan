use super::{RelayClientConfig, RelayError, Result};
use crate::protocol::{MSG_FORWARD, MSG_RECEIVED};
use bytes::{Bytes, BytesMut};
use quinn::{crypto::rustls::QuicClientConfig, Connection, Endpoint, RecvStream, SendStream};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

const ALPN: &[u8] = b"p2wlan-relay-dgram/1";
const FRAME_HEADER: usize = 8;
const FRAGMENT_HEADER: usize = 13;
const CHUNK: usize = 1024;
const MAX_ASSEMBLIES: usize = 24;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);
pub(super) const CONNECT_BUDGET: Duration = Duration::from_millis(720);

pub(super) async fn dial(
    host: &str,
    port: u16,
    server_name: &str,
    config: &RelayClientConfig,
) -> Result<QuicIo> {
    let mut tls = crate::tls::build_client_tls(config.tls_ca_cert_path.as_ref())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|error| RelayError::TlsError(error.to_string()))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut parameters = quinn::TransportConfig::default();
    let quic_idle = config.idle_timeout.min(Duration::from_millis(6500));
    let quic_idle: quinn::IdleTimeout =
        quic_idle
            .try_into()
            .map_err(|error: quinn::VarIntBoundsExceeded| {
                RelayError::ConnectFailed(error.to_string())
            })?;
    parameters
        .max_idle_timeout(Some(quic_idle))
        .keep_alive_interval(Some(config.keepalive_interval.min(Duration::from_secs(2))))
        .max_concurrent_bidi_streams(0u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .datagram_receive_buffer_size(Some(256 * 1024))
        .datagram_send_buffer_size(128 * 1024);
    client.transport_config(Arc::new(parameters));

    let addrs = tokio::net::lookup_host((host, port)).await?;
    let mut attempts = tokio::task::JoinSet::new();
    for remote in addrs.take(4) {
        let interface = config.outbound_interface.clone();
        let client = client.clone();
        let name = server_name.to_owned();
        let limit = config.max_frame_payload;
        attempts.spawn(async move {
            dial_addr(remote, interface.as_deref(), &name, client, limit).await
        });
    }
    let mut last = RelayError::ConnectFailed("no usable UDP relay address".into());
    while let Some(result) = attempts.join_next().await {
        match result {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last = error,
            Err(error) => last = RelayError::ConnectFailed(error.to_string()),
        }
    }
    Err(last)
}

async fn dial_addr(
    remote: SocketAddr,
    interface: Option<&str>,
    name: &str,
    client: quinn::ClientConfig,
    max_payload: usize,
) -> Result<QuicIo> {
    let local = SocketAddr::new(
        if remote.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        },
        0,
    );
    let interface = interface.filter(|_| !remote.ip().is_loopback());
    let socket = p2pnet_netbind::bind_udp(local, interface)
        .await?
        .into_std()?;
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client);
    let connection = endpoint
        .connect(remote, name)
        .map_err(|error| RelayError::ConnectFailed(error.to_string()))?
        .await
        .map_err(|error| RelayError::ConnectFailed(error.to_string()))?;
    if connection
        .max_datagram_size()
        .is_none_or(|size| size < CHUNK + FRAGMENT_HEADER)
    {
        return Err(RelayError::ConnectFailed(
            "relay DATAGRAM payload unavailable".into(),
        ));
    }
    let (writer, reader) = connection.open_bi().await.map_err(io::Error::other)?;
    Ok(QuicIo {
        _endpoint: endpoint,
        connection: connection.clone(),
        writer,
        read: Some(QuicRead {
            connection,
            reader,
            reliable: BytesMut::new(),
            fragments: HashMap::new(),
            maximum: max_payload + FRAME_HEADER,
        }),
        read_future: None,
        output: Bytes::new(),
        write_future: None,
        stream_remaining: 0,
        sequence: 0,
    })
}

struct Assembly {
    data: Vec<u8>,
    seen: u128,
    received: usize,
    deadline: Instant,
}

struct QuicRead {
    connection: Connection,
    reader: RecvStream,
    reliable: BytesMut,
    fragments: HashMap<u64, Assembly>,
    maximum: usize,
}

impl QuicRead {
    async fn next(&mut self) -> io::Result<Bytes> {
        let mut input = [0u8; 2048];
        loop {
            if self.reliable.len() >= FRAME_HEADER {
                let size = FRAME_HEADER
                    + usize::from(u16::from_be_bytes([self.reliable[6], self.reliable[7]]));
                if size > self.maximum || self.reliable[5] == MSG_RECEIVED {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid relay control frame",
                    ));
                }
                if self.reliable.len() >= size {
                    return Ok(self.reliable.split_to(size).freeze());
                }
            }
            tokio::select! {
                biased;
                result = self.reader.read(&mut input) => {
                    let len = result.map_err(io::Error::other)?.ok_or(io::ErrorKind::UnexpectedEof)?;
                    self.reliable.extend_from_slice(&input[..len]);
                }
                result = self.connection.read_datagram() => {
                    if let Some(frame) = self.push_fragment(result.map_err(io::Error::other)?, Instant::now()) {
                        return Ok(frame);
                    }
                }
            }
        }
    }

    fn push_fragment(&mut self, bytes: Bytes, now: Instant) -> Option<Bytes> {
        let id = u64::from_be_bytes(bytes.get(..8)?.try_into().ok()?);
        let len = u32::from_be_bytes(bytes.get(8..12)?.try_into().ok()?) as usize;
        let part = usize::from(*bytes.get(12)?);
        let offset = part * CHUNK;
        let payload = bytes.get(FRAGMENT_HEADER..)?;
        if len < FRAME_HEADER
            || len > self.maximum
            || offset >= len
            || payload.len() != CHUNK.min(len - offset)
        {
            return None;
        }
        if len <= CHUNK {
            return received_frame(bytes.slice(FRAGMENT_HEADER..));
        }
        self.fragments.retain(|_, assembly| now < assembly.deadline);
        if self.fragments.len() >= MAX_ASSEMBLIES && !self.fragments.contains_key(&id) {
            return None;
        }
        let entry = self.fragments.entry(id).or_insert_with(|| Assembly {
            data: vec![0; len],
            seen: 0,
            received: 0,
            deadline: now + REASSEMBLY_TIMEOUT,
        });
        if entry.data.len() != len || entry.seen & (1u128 << part) != 0 {
            return None;
        }
        entry.seen |= 1u128 << part;
        entry.data[offset..offset + payload.len()].copy_from_slice(payload);
        entry.received += payload.len();
        if entry.received == len {
            received_frame(self.fragments.remove(&id)?.data.into())
        } else {
            None
        }
    }
}

fn received_frame(bytes: Bytes) -> Option<Bytes> {
    (bytes[5] == MSG_RECEIVED
        && usize::from(u16::from_be_bytes([bytes[6], bytes[7]])) == bytes.len() - FRAME_HEADER)
        .then_some(bytes)
}

type ReadFuture = Pin<Box<dyn Future<Output = (QuicRead, io::Result<Bytes>)> + Send>>;
type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

pub(super) struct QuicIo {
    _endpoint: Endpoint,
    connection: Connection,
    writer: SendStream,
    read: Option<QuicRead>,
    read_future: Option<ReadFuture>,
    output: Bytes,
    write_future: Option<WriteFuture>,
    stream_remaining: usize,
    sequence: u64,
}

impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.output.is_empty() {
            if let Some(mut reader) = self.read.take() {
                self.read_future = Some(Box::pin(async move {
                    let result = reader.next().await;
                    (reader, result)
                }));
            }
            let Some(future) = self.read_future.as_mut() else {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            };
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready((reader, result)) => {
                    self.read_future = None;
                    self.read = Some(reader);
                    self.output = result?;
                }
            }
        }
        let actual = self.output.len().min(output.remaining());
        output.put_slice(&self.output.split_to(actual));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_future.is_none() {
            if self.stream_remaining == 0
                && input.get(5) == Some(&MSG_FORWARD)
                && input.len() >= FRAME_HEADER
            {
                let bytes = Bytes::copy_from_slice(input);
                let connection = self.connection.clone();
                self.sequence = self.sequence.wrapping_add(1);
                let id = self.sequence;
                self.write_future = Some(Box::pin(async move {
                    tokio::time::timeout(
                        Duration::from_millis(500),
                        send_fragments(connection, id, bytes),
                    )
                    .await
                    .map_err(|_| io::ErrorKind::TimedOut)?
                }));
            } else {
                let result = AsyncWrite::poll_write(Pin::new(&mut self.writer), cx, input);
                if let Poll::Ready(Ok(written)) = result {
                    self.stream_remaining = input.len().saturating_sub(written);
                }
                return result;
            }
        }
        if let Some(future) = self.write_future.as_mut() {
            let result = future.as_mut().poll(cx);
            if result.is_ready() {
                self.write_future = None;
            }
            result
        } else {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.writer), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.writer), cx)
    }
}

async fn send_fragments(connection: Connection, id: u64, frame: Bytes) -> io::Result<usize> {
    for (part, chunk) in frame.chunks(CHUNK).enumerate() {
        let mut encoded = BytesMut::with_capacity(FRAGMENT_HEADER + chunk.len());
        encoded.extend_from_slice(&id.to_be_bytes());
        encoded.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&[part as u8]);
        encoded.extend_from_slice(chunk);
        connection
            .send_datagram_wait(encoded.freeze())
            .await
            .map_err(io::Error::other)?;
    }
    Ok(frame.len())
}

impl Drop for QuicIo {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"");
    }
}
