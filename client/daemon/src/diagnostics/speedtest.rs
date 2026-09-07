const SPEEDTEST_PORT: u16 = 39278;
const SPEEDTEST_MAGIC: &str = "P2WLAN_SPEEDTEST";
const SPEEDTEST_DEFAULT_DURATION_MS: u64 = 10_000;
const SPEEDTEST_MIN_DURATION_MS: u64 = 2_000;
const SPEEDTEST_MAX_DURATION_MS: u64 = 30_000;
const SPEEDTEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SPEEDTEST_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const SPEEDTEST_ACK_TIMEOUT: Duration = Duration::from_secs(3);
const SPEEDTEST_TRANSFER_GRACE: Duration = Duration::from_secs(2);
const SPEEDTEST_BUFFER_SIZE: usize = 64 * 1024;
const SPEEDTEST_MAX_CONNECTIONS: usize = 8;
const SPEEDTEST_MAX_CONNECTIONS_PER_PEER: usize = 2;
static SPEEDTEST_CLIENT_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedtestResult {
    pub peer_virtual_ip: String,
    pub duration_ms: u64,
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub download_bytes: u64,
    pub upload_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpeedtestMode {
    Download,
    Upload,
}

#[derive(Default)]
struct SpeedtestAdmission {
    peers: std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>,
}

impl SpeedtestAdmission {
    fn acquire(self: &Arc<Self>, peer: std::net::IpAddr) -> Option<SpeedtestPermit> {
        let mut peers = self.peers.lock().ok()?;
        if peers.values().sum::<usize>() >= SPEEDTEST_MAX_CONNECTIONS
            || peers.get(&peer).copied().unwrap_or(0) >= SPEEDTEST_MAX_CONNECTIONS_PER_PEER
        {
            return None;
        }
        *peers.entry(peer).or_default() += 1;
        Some(SpeedtestPermit { admission: self.clone(), peer })
    }
}

struct SpeedtestPermit {
    admission: Arc<SpeedtestAdmission>,
    peer: std::net::IpAddr,
}

impl Drop for SpeedtestPermit {
    fn drop(&mut self) {
        let mut peers = self.admission.peers.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = peers.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&self.peer);
            }
        }
    }
}

async fn diagnostics_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow_and_update() {
            return;
        }
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

pub async fn run_speedtest_server_with_retry(
    virtual_ip: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let bind = format!("{virtual_ip}:{SPEEDTEST_PORT}");
    let mut attempt = 0usize;
    loop {
        if *shutdown_rx.borrow() || shutdown_rx.has_changed().is_err() {
            return Ok(());
        }
        match run_speedtest_server(bind.clone(), shutdown_rx.clone()).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
                attempt = attempt.saturating_add(1);
                if attempt == 1 || attempt.is_power_of_two() {
                    warn!("Speedtest endpoint start failed on {bind} (attempt {attempt}): {err}");
                }
            }
        }
        tokio::select! {
            _ = sleep(DIAGNOSTICS_BIND_RETRY_INTERVAL) => {}
            _ = diagnostics_shutdown(&mut shutdown_rx) => return Ok(()),
        }
    }
}

async fn run_speedtest_server(
    bind: String,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        DaemonError::Network(format!("failed to bind speedtest endpoint at {bind}: {e}"))
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| DaemonError::Network(format!("failed to read speedtest local addr: {e}")))?;
    info!("Speedtest endpoint listening at {local_addr}");
    serve_speedtest(listener, shutdown_rx).await
}

async fn serve_speedtest(
    listener: TcpListener,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let admission = Arc::new(SpeedtestAdmission::default());
    let mut tasks = tokio::task::JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = diagnostics_shutdown(&mut shutdown_rx) => break Ok(()),
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(err)) = completed {
                    debug!("speedtest task failed: {err}");
                }
            }
            accepted = listener.accept() => {
                let (stream, remote_addr) = match accepted {
                    Ok(value) => value,
                    Err(err) => break Err(DaemonError::Network(format!("speedtest accept failed: {err}"))),
                };
                let Some(permit) = admission.acquire(remote_addr.ip()) else {
                    drop(stream);
                    continue;
                };
                tasks.spawn(async move {
                    let _permit = permit;
                    let budget = Duration::from_millis(SPEEDTEST_MAX_DURATION_MS)
                        + SPEEDTEST_COMMAND_TIMEOUT + SPEEDTEST_TRANSFER_GRACE + SPEEDTEST_ACK_TIMEOUT;
                    match timeout(budget, handle_speedtest_connection(stream)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => debug!("speedtest request from {remote_addr} failed: {err}"),
                        Err(_) => debug!("speedtest request from {remote_addr} exceeded total deadline"),
                    }
                });
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

async fn handle_speedtest_connection(mut stream: TcpStream) -> Result<()> {
    let (mode, duration) = read_speedtest_command(&mut stream).await?;
    match mode {
        SpeedtestMode::Download => send_speedtest_payload(&mut stream, duration).await,
        SpeedtestMode::Upload => receive_speedtest_payload(&mut stream, duration).await,
    }
}

async fn read_speedtest_line(
    stream: &mut TcpStream,
    limit: usize,
    budget: Duration,
) -> Result<Vec<u8>> {
    timeout(budget, async {
        let mut line = Vec::with_capacity(limit);
        let mut byte = [0u8; 1];
        while line.len() < limit {
            let n = stream.read(&mut byte).await
                .map_err(|e| DaemonError::Network(format!("speedtest line read failed: {e}")))?;
            if n == 0 {
                return Err(DaemonError::Network("incomplete speedtest line".to_string()));
            }
            if byte[0] == b'\n' {
                return Ok(line);
            }
            line.push(byte[0]);
        }
        Err(DaemonError::Network("speedtest line too long".to_string()))
    }).await.map_err(|_| DaemonError::Network("speedtest line timed out".to_string()))?
}

async fn read_speedtest_command(stream: &mut TcpStream) -> Result<(SpeedtestMode, Duration)> {
    let command = read_speedtest_line(stream, 128, SPEEDTEST_COMMAND_TIMEOUT).await?;
    let line = String::from_utf8(command)
        .map_err(|_| DaemonError::Network("speedtest command is not utf-8".to_string()))?;
    let mut parts = line.split_whitespace();
    if parts.next() != Some(SPEEDTEST_MAGIC) {
        return Err(DaemonError::Network("invalid speedtest magic".to_string()));
    }
    let mode = match parts.next().unwrap_or_default() {
        "download" => SpeedtestMode::Download,
        "upload" => SpeedtestMode::Upload,
        other => return Err(DaemonError::Network(format!("invalid speedtest mode '{other}'"))),
    };
    let duration_ms = match parts.next() {
        Some(value) => value.parse::<u64>()
            .map_err(|_| DaemonError::Network("invalid speedtest duration".to_string()))?,
        None => SPEEDTEST_DEFAULT_DURATION_MS,
    }.clamp(100, SPEEDTEST_MAX_DURATION_MS);
    if parts.next().is_some() {
        return Err(DaemonError::Network("invalid speedtest command".to_string()));
    }
    Ok((mode, Duration::from_millis(duration_ms)))
}

async fn send_speedtest_payload(stream: &mut TcpStream, duration: Duration) -> Result<()> {
    let payload = vec![0xA5u8; SPEEDTEST_BUFFER_SIZE];
    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, stream.write(&payload)).await {
            Ok(Ok(0)) => return Err(DaemonError::Network("speedtest download write returned zero".to_string())),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(DaemonError::Network(format!("speedtest download write failed: {e}"))),
            Err(_) => break,
        }
    }
    Ok(())
}

async fn receive_speedtest_payload(stream: &mut TcpStream, duration: Duration) -> Result<()> {
    let mut buffer = vec![0u8; SPEEDTEST_BUFFER_SIZE];
    let mut bytes = 0u64;
    let deadline = tokio::time::Instant::now() + duration + SPEEDTEST_TRANSFER_GRACE;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(DaemonError::Network(
                "speedtest upload exceeded total deadline".to_string(),
            ));
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await
            .map_err(|_| DaemonError::Network("speedtest upload exceeded total deadline".to_string()))?
            .map_err(|e| DaemonError::Network(format!("speedtest upload read failed: {e}")))?;
        if n == 0 {
            break;
        }
        bytes = bytes.saturating_add(n as u64);
    }
    let ack = format!("OK {bytes}\n");
    timeout(SPEEDTEST_ACK_TIMEOUT, stream.write_all(ack.as_bytes())).await
        .map_err(|_| DaemonError::Network("speedtest upload ack timed out".to_string()))?
        .map_err(|e| DaemonError::Network(format!("speedtest upload ack failed: {e}")))?;
    Ok(())
}

async fn run_speedtest_from_query(
    context: DiagnosticsContext,
    query: Option<&str>,
) -> std::result::Result<SpeedtestResult, String> {
    let peer_virtual_ip = query_param(query, "peer")
        .or_else(|| query_param(query, "peer_virtual_ip"))
        .ok_or_else(|| "missing peer virtual IP".to_string())?;
    let duration_ms = query_param(query, "duration_ms")
        .or_else(|| query_param(query, "duration"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SPEEDTEST_DEFAULT_DURATION_MS)
        .clamp(SPEEDTEST_MIN_DURATION_MS, SPEEDTEST_MAX_DURATION_MS);
    let parsed_ip = peer_virtual_ip.parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("invalid peer virtual IP '{peer_virtual_ip}'"))?;
    if peer_virtual_ip == context.config.network.virtual_ip {
        return Err("cannot speedtest the local virtual IP".to_string());
    }
    let _permit = SPEEDTEST_CLIENT_SLOT.try_acquire()
        .map_err(|_| "speedtest already running".to_string())?;
    timeout(Duration::from_secs(2), ensure_peer_is_direct(&context, &peer_virtual_ip)).await
        .map_err(|_| "speedtest peer validation timed out".to_string())??;
    let addr = std::net::SocketAddr::from((parsed_ip, SPEEDTEST_PORT));
    run_speedtest_client(addr, peer_virtual_ip, Duration::from_millis(duration_ms)).await
}

async fn ensure_peer_is_direct(
    context: &DiagnosticsContext,
    peer_virtual_ip: &str,
) -> std::result::Result<(), String> {
    let udp = context.udp_transport.read().await.clone();
    let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
    let relay_connected = context.relay_transport.read().await.is_some();
    let peers = context.peers.diagnostics_with_path_selection(
        context.config.relay.prefer_direct,
        relay_connected,
        DIRECT_RETRY_BASE_INTERVAL,
        udp_local_endpoint,
    ).await;
    let peer = peers.into_iter().find(|peer| peer.virtual_ip == peer_virtual_ip)
        .ok_or_else(|| format!("peer {peer_virtual_ip} is not in the current catalog"))?;
    if !peer.online {
        return Err(format!("peer {peer_virtual_ip} is offline"));
    }
    if peer.active_path != Some(NetworkPath::Direct) {
        return Err(format!("peer {peer_virtual_ip} is not using a confirmed direct path"));
    }
    Ok(())
}

async fn run_speedtest_client(
    peer_addr: std::net::SocketAddr,
    peer_virtual_ip: String,
    duration: Duration,
) -> std::result::Result<SpeedtestResult, String> {
    timeout(duration + Duration::from_secs(25), async {
        let half = (duration / 2).max(Duration::from_millis(250));
        let download_bytes = speedtest_download(peer_addr, half).await?;
        let upload_bytes = speedtest_upload(peer_addr, half).await?;
        let sample_secs = half.as_secs_f64().max(0.001);
        Ok(SpeedtestResult {
            peer_virtual_ip,
            duration_ms: duration.as_millis().min(u128::from(u64::MAX)) as u64,
            download_mbps: bits_per_second_to_mbps(download_bytes, sample_secs),
            upload_mbps: bits_per_second_to_mbps(upload_bytes, sample_secs),
            download_bytes,
            upload_bytes,
        })
    }).await.map_err(|_| "speedtest exceeded total deadline".to_string())?
}

async fn speedtest_download(
    peer_addr: std::net::SocketAddr,
    duration: Duration,
) -> std::result::Result<u64, String> {
    let mut stream = timeout(SPEEDTEST_CONNECT_TIMEOUT, TcpStream::connect(peer_addr)).await
        .map_err(|_| format!("speedtest connect to {peer_addr} timed out"))?
        .map_err(|e| format!("speedtest connect to {peer_addr} failed: {e}"))?;
    let command = format!("{SPEEDTEST_MAGIC} download {}\n", duration.as_millis());
    timeout(SPEEDTEST_COMMAND_TIMEOUT, stream.write_all(command.as_bytes())).await
        .map_err(|_| "speedtest download command timed out".to_string())?
        .map_err(|e| format!("speedtest download command failed: {e}"))?;
    let deadline = tokio::time::Instant::now() + duration;
    let mut buffer = vec![0u8; SPEEDTEST_BUFFER_SIZE];
    let mut bytes = 0u64;
    while tokio::time::Instant::now() < deadline {
        let n = match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(format!("speedtest download read failed: {e}")),
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        bytes = bytes.saturating_add(n as u64);
    }
    Ok(bytes)
}

async fn speedtest_upload(
    peer_addr: std::net::SocketAddr,
    duration: Duration,
) -> std::result::Result<u64, String> {
    let mut stream = timeout(SPEEDTEST_CONNECT_TIMEOUT, TcpStream::connect(peer_addr)).await
        .map_err(|_| format!("speedtest connect to {peer_addr} timed out"))?
        .map_err(|e| format!("speedtest connect to {peer_addr} failed: {e}"))?;
    let command = format!("{SPEEDTEST_MAGIC} upload {}\n", duration.as_millis());
    timeout(SPEEDTEST_COMMAND_TIMEOUT, stream.write_all(command.as_bytes())).await
        .map_err(|_| "speedtest upload command timed out".to_string())?
        .map_err(|e| format!("speedtest upload command failed: {e}"))?;
    let payload = vec![0x5Au8; SPEEDTEST_BUFFER_SIZE];
    let deadline = tokio::time::Instant::now() + duration;
    let mut bytes = 0u64;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, stream.write(&payload)).await {
            Ok(Ok(0)) => return Err("speedtest upload write returned zero".to_string()),
            Ok(Ok(n)) => bytes = bytes.saturating_add(n as u64),
            Ok(Err(e)) => return Err(format!("speedtest upload write failed: {e}")),
            Err(_) => break,
        }
    }
    timeout(SPEEDTEST_ACK_TIMEOUT, stream.shutdown()).await
        .map_err(|_| "speedtest upload shutdown timed out".to_string())?
        .map_err(|e| format!("speedtest upload shutdown failed: {e}"))?;
    let ack = read_speedtest_line(&mut stream, 64, SPEEDTEST_ACK_TIMEOUT).await
        .map_err(|e| format!("speedtest upload ack failed: {e}"))?;
    let confirmed = parse_speedtest_upload_ack(&ack)
        .ok_or_else(|| "speedtest upload acknowledgement is malformed".to_string())?;
    if confirmed > bytes {
        return Err("speedtest upload acknowledgement exceeds sent bytes".to_string());
    }
    Ok(confirmed)
}

fn parse_speedtest_upload_ack(bytes: &[u8]) -> Option<u64> {
    let ack = std::str::from_utf8(bytes).ok()?;
    let mut parts = ack.split_whitespace();
    if parts.next()? != "OK" {
        return None;
    }
    let count = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(count)
}

fn bits_per_second_to_mbps(bytes: u64, seconds: f64) -> f64 {
    ((bytes as f64) * 8.0 / seconds) / 1_000_000.0
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if url_decode(name) == key {
            return Some(url_decode(value));
        }
    }
    None
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_value(bytes[i + 1]);
                let lo = hex_value(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod speedtest_reliability_tests {
    use super::*;

    #[test]
    fn admission_is_bounded_globally_and_per_peer_and_releases_on_drop() {
        let admission = Arc::new(SpeedtestAdmission::default());
        let peer = "127.0.0.1".parse().unwrap();
        let first = admission.acquire(peer).unwrap();
        let second = admission.acquire(peer).unwrap();
        assert!(admission.acquire(peer).is_none());
        drop(first);
        let first = admission.acquire(peer).unwrap();
        let mut permits = vec![first, second];
        for suffix in 2..=7 {
            permits.push(admission.acquire(format!("127.0.0.{suffix}").parse().unwrap()).unwrap());
        }
        assert!(admission.acquire("127.0.0.8".parse().unwrap()).is_none());
        drop(permits);
        assert!(admission.peers.lock().unwrap().is_empty());
    }

    #[test]
    fn acknowledgements_require_exactly_a_valid_count() {
        assert_eq!(parse_speedtest_upload_ack(b"OK 123"), Some(123));
        for ack in [b"".as_slice(), b"OK", b"OK -1", b"OK NaN", b"OK 2 extra", b"NO 3"] {
            assert_eq!(parse_speedtest_upload_ack(ack), None);
        }
    }

    #[tokio::test]
    async fn stalled_download_write_stops_at_the_sample_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        timeout(Duration::from_secs(2), send_speedtest_payload(&mut server, Duration::from_millis(100)))
            .await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn upload_receiver_has_a_total_deadline_even_with_an_open_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(b"still connected").await.unwrap();
        let result = timeout(Duration::from_secs(4), receive_speedtest_payload(&mut server, Duration::from_millis(100)))
            .await.unwrap();
        assert!(result.unwrap_err().to_string().contains("total deadline"));
    }

    #[tokio::test]
    async fn upload_receiver_bounds_a_continuous_writer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let writer = tokio::spawn(async move {
            let payload = vec![0u8; SPEEDTEST_BUFFER_SIZE];
            while client.write_all(&payload).await.is_ok() {}
        });
        let result = timeout(
            Duration::from_secs(4),
            receive_speedtest_payload(&mut server, Duration::from_millis(100)),
        ).await.unwrap();
        assert!(result.unwrap_err().to_string().contains("total deadline"));
        drop(server);
        timeout(Duration::from_secs(1), writer).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_and_inflated_upload_acknowledgements_are_errors() {
        for ack in ["not-an-ack\n", "OK 18446744073709551615\n", ""] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_speedtest_command(&mut stream).await.unwrap();
                let mut buffer = vec![0u8; SPEEDTEST_BUFFER_SIZE];
                while stream.read(&mut buffer).await.unwrap() != 0 {}
                stream.write_all(ack.as_bytes()).await.unwrap();
            });
            let result = speedtest_upload(addr, Duration::from_millis(100)).await;
            assert!(result.is_err(), "acknowledgement {ack:?} was accepted");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn shutdown_drains_active_speedtest_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(serve_speedtest(listener, shutdown_rx));
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"P2WLAN_SPEEDTEST upload 30000\n").await.unwrap();
        tokio::task::yield_now().await;
        shutdown_tx.send(true).unwrap();
        timeout(Duration::from_secs(1), task).await.unwrap().unwrap().unwrap();
        let mut byte = [0u8; 1];
        let read = timeout(Duration::from_secs(1), client.read(&mut byte)).await.unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn repeated_speedtests_release_connection_slots() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(serve_speedtest(listener, shutdown_rx));
        for _ in 0..3 {
            let result = run_speedtest_client(addr, "127.0.0.1".to_string(), Duration::from_millis(600))
                .await.unwrap();
            assert!(result.download_bytes > 0);
            assert!(result.upload_bytes > 0);
        }
        shutdown_tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
