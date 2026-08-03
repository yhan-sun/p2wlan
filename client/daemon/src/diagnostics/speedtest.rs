const SPEEDTEST_PORT: u16 = 39278;
const SPEEDTEST_MAGIC: &str = "P2WLAN_SPEEDTEST";
const SPEEDTEST_DEFAULT_DURATION_MS: u64 = 10_000;
const SPEEDTEST_MIN_DURATION_MS: u64 = 2_000;
const SPEEDTEST_MAX_DURATION_MS: u64 = 30_000;
const SPEEDTEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SPEEDTEST_IO_TIMEOUT: Duration = Duration::from_secs(35);
const SPEEDTEST_BUFFER_SIZE: usize = 64 * 1024;

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

pub async fn run_speedtest_server_with_retry(
    virtual_ip: String,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let bind = format!("{virtual_ip}:{SPEEDTEST_PORT}");
    let mut attempt = 0usize;
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }

        match run_speedtest_server(bind.clone(), shutdown_rx.clone()).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
                attempt = attempt.saturating_add(1);
                warn!(
                    "Speedtest endpoint start failed on {bind} (attempt {attempt}); retrying in {} ms: {err}",
                    DIAGNOSTICS_BIND_RETRY_INTERVAL.as_millis()
                );
            }
        }

        tokio::select! {
            _ = sleep(DIAGNOSTICS_BIND_RETRY_INTERVAL) => {}
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
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
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut shutdown_rx = shutdown_rx;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Speedtest server received shutdown signal");
                    break;
                }
            }
            result = listener.accept() => {
                let (stream, remote_addr) = result
                    .map_err(|e| DaemonError::Network(format!("speedtest accept failed: {e}")))?;
                tokio::spawn(async move {
                    if let Err(err) = handle_speedtest_connection(stream).await {
                        debug!("speedtest request from {remote_addr} failed: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_speedtest_connection(mut stream: TcpStream) -> Result<()> {
    let (mode, duration) = read_speedtest_command(&mut stream).await?;
    match mode {
        SpeedtestMode::Download => send_speedtest_payload(&mut stream, duration).await,
        SpeedtestMode::Upload => receive_speedtest_payload(&mut stream).await,
    }
}

async fn read_speedtest_command(stream: &mut TcpStream) -> Result<(SpeedtestMode, Duration)> {
    let mut command = Vec::with_capacity(96);
    let mut byte = [0u8; 1];
    while command.len() < 128 {
        let n = timeout(Duration::from_secs(3), stream.read(&mut byte))
            .await
            .map_err(|_| DaemonError::Network("speedtest command timed out".to_string()))?
            .map_err(|e| DaemonError::Network(format!("speedtest command read failed: {e}")))?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        command.push(byte[0]);
    }

    let line = String::from_utf8(command)
        .map_err(|_| DaemonError::Network("speedtest command is not utf-8".to_string()))?;
    let mut parts = line.split_whitespace();
    let magic = parts.next().unwrap_or_default();
    if magic != SPEEDTEST_MAGIC {
        return Err(DaemonError::Network("invalid speedtest magic".to_string()));
    }
    let mode = match parts.next().unwrap_or_default() {
        "download" => SpeedtestMode::Download,
        "upload" => SpeedtestMode::Upload,
        other => {
            return Err(DaemonError::Network(format!(
                "invalid speedtest mode '{other}'"
            )))
        }
    };
    let duration_ms = parts
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(SPEEDTEST_DEFAULT_DURATION_MS)
        .clamp(100, SPEEDTEST_MAX_DURATION_MS);
    Ok((mode, Duration::from_millis(duration_ms)))
}

async fn send_speedtest_payload(stream: &mut TcpStream, duration: Duration) -> Result<()> {
    let payload = vec![0xA5u8; SPEEDTEST_BUFFER_SIZE];
    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        stream
            .write_all(&payload)
            .await
            .map_err(|e| DaemonError::Network(format!("speedtest download write failed: {e}")))?;
    }
    Ok(())
}

async fn receive_speedtest_payload(stream: &mut TcpStream) -> Result<()> {
    let mut buffer = vec![0u8; SPEEDTEST_BUFFER_SIZE];
    let mut bytes = 0u64;
    loop {
        let n = timeout(SPEEDTEST_IO_TIMEOUT, stream.read(&mut buffer))
            .await
            .map_err(|_| DaemonError::Network("speedtest upload read timed out".to_string()))?
            .map_err(|e| DaemonError::Network(format!("speedtest upload read failed: {e}")))?;
        if n == 0 {
            break;
        }
        bytes = bytes.saturating_add(n as u64);
    }
    let ack = format!("OK {bytes}\n");
    stream
        .write_all(ack.as_bytes())
        .await
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

    let parsed_ip = peer_virtual_ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| format!("invalid peer virtual IP '{peer_virtual_ip}'"))?;
    if peer_virtual_ip == context.config.network.virtual_ip {
        return Err("cannot speedtest the local virtual IP".to_string());
    }
    ensure_peer_is_direct(&context, &peer_virtual_ip).await?;

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
    let peers = context
        .peers
        .diagnostics_with_path_selection(
            context.config.relay.prefer_direct,
            relay_connected,
            DIRECT_RETRY_BASE_INTERVAL,
            udp_local_endpoint,
        )
        .await;
    let peer = peers
        .into_iter()
        .find(|peer| peer.virtual_ip == peer_virtual_ip)
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
}

async fn speedtest_download(
    peer_addr: std::net::SocketAddr,
    duration: Duration,
) -> std::result::Result<u64, String> {
    let mut stream = timeout(SPEEDTEST_CONNECT_TIMEOUT, TcpStream::connect(peer_addr))
        .await
        .map_err(|_| format!("speedtest connect to {peer_addr} timed out"))?
        .map_err(|e| format!("speedtest connect to {peer_addr} failed: {e}"))?;
    let command = format!(
        "{SPEEDTEST_MAGIC} download {}\n",
        duration.as_millis().min(u128::from(u64::MAX))
    );
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(|e| format!("speedtest download command failed: {e}"))?;

    let deadline = tokio::time::Instant::now() + duration;
    let mut buffer = vec![0u8; SPEEDTEST_BUFFER_SIZE];
    let mut bytes = 0u64;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let n = match timeout(remaining.max(Duration::from_millis(1)), stream.read(&mut buffer))
            .await
        {
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
    let mut stream = timeout(SPEEDTEST_CONNECT_TIMEOUT, TcpStream::connect(peer_addr))
        .await
        .map_err(|_| format!("speedtest connect to {peer_addr} timed out"))?
        .map_err(|e| format!("speedtest connect to {peer_addr} failed: {e}"))?;
    let command = format!(
        "{SPEEDTEST_MAGIC} upload {}\n",
        duration.as_millis().min(u128::from(u64::MAX))
    );
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(|e| format!("speedtest upload command failed: {e}"))?;

    let payload = vec![0x5Au8; SPEEDTEST_BUFFER_SIZE];
    let deadline = tokio::time::Instant::now() + duration;
    let mut bytes = 0u64;
    while tokio::time::Instant::now() < deadline {
        stream
            .write_all(&payload)
            .await
            .map_err(|e| format!("speedtest upload write failed: {e}"))?;
        bytes = bytes.saturating_add(payload.len() as u64);
    }
    stream
        .shutdown()
        .await
        .map_err(|e| format!("speedtest upload shutdown failed: {e}"))?;

    let mut ack = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    while ack.len() < 64 {
        let n = timeout(SPEEDTEST_IO_TIMEOUT, stream.read(&mut byte))
            .await
            .map_err(|_| "speedtest upload ack timed out".to_string())?
            .map_err(|e| format!("speedtest upload ack failed: {e}"))?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        ack.push(byte[0]);
    }
    Ok(parse_speedtest_upload_ack(&ack).unwrap_or(bytes))
}

fn parse_speedtest_upload_ack(bytes: &[u8]) -> Option<u64> {
    let ack = std::str::from_utf8(bytes).ok()?;
    let mut parts = ack.split_whitespace();
    if parts.next()? != "OK" {
        return None;
    }
    parts.next()?.parse::<u64>().ok()
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
