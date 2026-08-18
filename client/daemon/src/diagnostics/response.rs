async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    cors_origin: Option<&str>,
) -> Result<()> {
    write_response_with_headers(stream, status, content_type, body, cors_origin, "").await
}

async fn write_response_with_headers(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    cors_origin: Option<&str>,
    extra_headers: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let cors_header = cors_origin
        .map(|origin| format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{extra_headers}{cors_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    timeout(Duration::from_secs(5), stream.write_all(response.as_bytes()))
        .await
        .map_err(|_| DaemonError::Network("diagnostics write timed out".to_string()))?
        .map_err(|e| DaemonError::Network(format!("diagnostics write failed: {e}")))?;
    Ok(())
}
