const DIAGNOSTICS_MAX_HEADER_BYTES: usize = 16 * 1024;
const DIAGNOSTICS_HEADER_TIMEOUT: Duration = Duration::from_secs(3);
const DIAGNOSTICS_MAX_CONNECTIONS: usize = 64;

type DiagnosticsHeadError = (u16, &'static str);

async fn read_diagnostics_head(
    stream: &mut TcpStream,
) -> std::result::Result<String, DiagnosticsHeadError> {
    timeout(DIAGNOSTICS_HEADER_TIMEOUT, async {
        let mut bytes = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                let head = std::str::from_utf8(&bytes[..end + 4])
                    .map_err(|_| (400, "invalid request encoding\n"))?;
                validate_diagnostics_head(head)?;
                return Ok(head.to_string());
            }
            let remaining = DIAGNOSTICS_MAX_HEADER_BYTES.saturating_sub(bytes.len());
            if remaining == 0 {
                return Err((431, "request headers too large\n"));
            }
            let capacity = remaining.min(chunk.len());
            let n = stream.read(&mut chunk[..capacity]).await
                .map_err(|_| (400, "request read failed\n"))?;
            if n == 0 {
                return Err((400, "incomplete request headers\n"));
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
    }).await.map_err(|_| (408, "request headers timed out\n"))?
}

fn validate_diagnostics_head(head: &str) -> std::result::Result<(), DiagnosticsHeadError> {
    let invalid = (400, "invalid request headers\n");
    let mut lines = head.split("\r\n");
    let mut request = lines.next().ok_or(invalid)?.split_whitespace();
    let method = request.next().ok_or(invalid)?;
    let target = request.next().ok_or(invalid)?;
    let version = request.next().ok_or(invalid)?;
    if request.next().is_some()
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !target.starts_with('/')
        || target.bytes().any(|byte| byte.is_ascii_control())
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(invalid);
    }
    let mut authorization = false;
    let mut content_length = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(invalid)?;
        if name.is_empty()
            || !name.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || b"!#$%&'*+-.^_`|~".contains(&byte))
            || value.bytes().any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(invalid);
        }
        if name.eq_ignore_ascii_case("authorization") {
            if authorization {
                return Err(invalid);
            }
            authorization = true;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err((400, "request bodies are not supported\n"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length || value.trim().parse::<u64>() != Ok(0) {
                return Err((400, "request bodies are not supported\n"));
            }
            content_length = true;
        }
    }
    Ok(())
}

async fn until_diagnostics_client_disconnect<T>(
    stream: &mut TcpStream,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    operation: impl std::future::Future<Output = T>,
) -> Option<T> {
    let mut byte = [0u8; 1];
    tokio::select! {
        biased;
        _ = diagnostics_shutdown(&mut shutdown_rx) => None,
        _ = stream.read(&mut byte) => None,
        value = operation => Some(value),
    }
}

#[cfg(test)]
mod http_request_reliability_tests {
    use super::*;

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn fragmented_authorization_is_read_completely() {
        let (mut client, mut server) = pair().await;
        let read = tokio::spawn(async move { read_diagnostics_head(&mut server).await });
        client.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\nAuthoriz").await.unwrap();
        tokio::task::yield_now().await;
        client.write_all(b"ation: Bearer correct-secret\r\n\r\n").await.unwrap();
        let head = read.await.unwrap().unwrap();
        assert_eq!(bearer_token(&head), Some("correct-secret"));
    }

    #[tokio::test]
    async fn headers_larger_than_one_tcp_read_are_accepted() {
        let (mut client, mut server) = pair().await;
        let head = format!("GET /health HTTP/1.1\r\nX-Padding: {}\r\n\r\n", "a".repeat(4096));
        client.write_all(head.as_bytes()).await.unwrap();
        assert_eq!(read_diagnostics_head(&mut server).await.unwrap(), head);
    }

    #[tokio::test]
    async fn incomplete_and_oversized_headers_are_rejected() {
        let (mut client, mut server) = pair().await;
        client.write_all(b"GET /health HTTP/1.1\r\n").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_diagnostics_head(&mut server).await.unwrap_err().0, 400);
        let (mut client, mut server) = pair().await;
        let read = tokio::spawn(async move { read_diagnostics_head(&mut server).await });
        client.write_all(&vec![b'a'; DIAGNOSTICS_MAX_HEADER_BYTES]).await.unwrap();
        assert_eq!(read.await.unwrap().unwrap_err().0, 431);
    }

    #[test]
    fn duplicate_auth_and_request_smuggling_are_rejected() {
        for head in [
            "GET /status HTTP/1.1\r\nAuthorization: Bearer a\r\nauthorization: Bearer b\r\n\r\n",
            "POST /shutdown HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "POST /shutdown HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /shutdown HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
            "GET /health\r\n\r\n",
            "GET /health HTTP/1.1\r\n Folded: bad\r\n\r\n",
        ] {
            assert!(validate_diagnostics_head(head).is_err(), "{head:?}");
        }
    }

    #[tokio::test]
    async fn disconnect_drops_the_in_flight_operation_and_its_permit() {
        let (client, mut server) = pair().await;
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let operation = async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        };
        drop(client);
        let result = timeout(Duration::from_secs(1),
            until_diagnostics_client_disconnect(&mut server, shutdown_rx, operation)).await.unwrap();
        assert!(result.is_none());
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn shutdown_cancels_without_waiting_for_the_http_operation() {
        let (_client, mut server) = pair().await;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx.send(true).unwrap();
        let result = timeout(Duration::from_secs(1),
            until_diagnostics_client_disconnect(&mut server, shutdown_rx, std::future::pending::<()>())).await.unwrap();
        assert!(result.is_none());
    }
}
