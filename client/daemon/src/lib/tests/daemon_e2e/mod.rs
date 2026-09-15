// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;
/// Pair of WireGuard transport sessions (outbound for the test daemon,
/// remote session that can decrypt the emitted wire bytes for verification).
pub(super) fn part03_establish_sessions() -> (TransportSession, TransportSession) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();

    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);

    let init = initiator.create_initiation().unwrap();
    let (response, node_b_keys) = responder.consume_initiation_and_respond(&init).unwrap();
    let node_a_keys = initiator.consume_response(&response).unwrap();

    (
        TransportSession::new(node_a_keys),
        TransportSession::new(node_b_keys),
    )
}

/// Build a transport with an active WireGuard session for `peer_id` and
/// return it together with the worker's RAW outbound receiver and the REMOTE
/// session that can decrypt the bytes the worker eventually emits.
pub(super) async fn part03_outbound_transport(
    peer_id: &str,
) -> (
    WireGuardTransport,
    mpsc::Receiver<OutboundPacket>,
    TransportSession,
) {
    let (transport, outbound_rx) = WireGuardTransport::new();
    let (local_session, remote_session) = part03_establish_sessions();
    transport.add_session(peer_id, local_session).await;
    (transport, outbound_rx, remote_session)
}

pub(super) struct HandshakeControlCapture {
    pub(super) base_url: String,
    registered_rx: watch::Receiver<bool>,
    signal_revision_rx: watch::Receiver<u64>,
    signal_bodies: Arc<std::sync::Mutex<Vec<String>>>,
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl HandshakeControlCapture {
    pub(super) async fn wait_registered(&mut self) {
        while !*self.registered_rx.borrow() {
            self.registered_rx
                .changed()
                .await
                .expect("handshake control capture stopped before registration");
        }
    }

    pub(super) async fn wait_for_signal_count(&mut self, expected: usize) {
        while self
            .signal_bodies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
            < expected
        {
            self.signal_revision_rx
                .changed()
                .await
                .expect("handshake control capture stopped before signal delivery");
        }
    }

    pub(super) fn signal_bodies(&self) -> Vec<String> {
        self.signal_bodies
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) async fn stop(self) {
        self.shutdown_tx.send_replace(true);
        self.task
            .await
            .expect("handshake control capture task panicked");
    }
}

pub(super) async fn start_handshake_control_capture() -> HandshakeControlCapture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let (registered_tx, registered_rx) = watch::channel(false);
    let (signal_revision_tx, signal_revision_rx) = watch::channel(0u64);
    let signal_bodies = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let server_bodies = signal_bodies.clone();
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                biased;
                changed = shutdown_rx.changed() => {
                    let _ = changed;
                    return;
                }
                accepted = listener.accept() => accepted,
            };
            let Ok((mut stream, _)) = accepted else {
                return;
            };
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            let header_end = loop {
                let Ok(read) = stream.read(&mut chunk).await else {
                    break None;
                };
                if read == 0 {
                    break None;
                }
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break Some(position + 4);
                }
            };
            let Some(header_end) = header_end else {
                continue;
            };
            let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
            let content_length = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let Ok(read) = stream.read(&mut chunk).await else {
                    break;
                };
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let body = String::from_utf8_lossy(
                &request[header_end..request.len().min(header_end + content_length)],
            )
            .into_owned();
            let response_body = if head.contains("/api/v1/devices") {
                registered_tx.send_replace(true);
                r#"{"success":true,"node_id":"node-local","virtual_ip":"10.20.0.1","cidr":"10.20.0.0/16","relay_servers":[]}"#
            } else if head.starts_with("POST") && head.contains("/api/v1/signals") {
                let revision = {
                    let mut bodies = server_bodies
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    bodies.push(body);
                    bodies.len() as u64
                };
                signal_revision_tx.send_replace(revision);
                r#"{"success":true,"protocol_version":1}"#
            } else {
                r#"{"signals":[],"server_time_ms":0}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    HandshakeControlCapture {
        base_url,
        registered_rx,
        signal_revision_rx,
        signal_bodies,
        shutdown_tx,
        task,
    }
}

mod control_event_contention;
mod handshake_arbiter;
mod handshake_contention;
mod incarnation_fencing;
mod network_outbound;
mod relay_and_stun;
mod responder_cache;
mod session_lifecycle;
