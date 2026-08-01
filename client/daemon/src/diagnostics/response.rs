async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    cors_origin: Option<&str>,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let cors_header = cors_origin
        .map(|origin| format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{cors_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| DaemonError::Network(format!("diagnostics write failed: {e}")))?;
    Ok(())
}
