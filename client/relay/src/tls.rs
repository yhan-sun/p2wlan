//! TLS transport helpers for relay connections.
//!
//! Handles TLS 1.3 negotiation, certificate validation, and endpoint parsing
//! for `tls://` and `tcp://` schemes.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::error::RelayError;

// ============================================================
// Endpoint parsing
// ============================================================

/// Parsed relay endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEndpoint {
    /// "tls" or "tcp"
    pub scheme: String,
    /// Hostname or IP address.
    pub host: String,
    /// Port number.
    pub port: u16,
}

/// Parse a relay endpoint string.
///
/// Supported formats:
/// - `tls://host:port` — TLS 1.3
/// - `tcp://host:port` — plaintext (development only)
/// - `host:port` — legacy, treated as tcp:// for backward compat
///
/// IPv6 addresses must be wrapped in brackets: `tls://[::1]:18081`.
pub fn parse_endpoint(
    endpoint: &str,
    allow_insecure_plaintext: bool,
) -> Result<ParsedEndpoint, RelayError> {
    let endpoint = endpoint.trim();

    let (scheme, host_port) = if let Some(rest) = endpoint.strip_prefix("tls://") {
        ("tls", rest)
    } else if let Some(rest) = endpoint.strip_prefix("tcp://") {
        if !allow_insecure_plaintext {
            return Err(RelayError::TlsError(
                "tcp:// scheme is not allowed when allow_insecure_plaintext is disabled".into(),
            ));
        }
        ("tcp", rest)
    } else {
        // Legacy: bare host:port is treated as tcp:// for backward compat
        if !allow_insecure_plaintext {
            return Err(RelayError::TlsError(
                "bare host:port is not allowed in secure mode; use tls://host:port".into(),
            ));
        }
        ("tcp", endpoint)
    };

    // Parse host:port, handling IPv6 brackets
    let (host, port_str) = if let Some(bracket_end) = host_port.rfind(']') {
        // IPv6 with brackets: [::1]:18081
        if !host_port.starts_with('[') {
            return Err(RelayError::TlsError(format!(
                "invalid endpoint: {endpoint} — unmatched bracket"
            )));
        }
        let after_bracket = &host_port[bracket_end + 1..];
        if !after_bracket.starts_with(':') {
            return Err(RelayError::TlsError(format!(
                "invalid endpoint: {endpoint} — missing port after IPv6 address"
            )));
        }
        (
            host_port[..=bracket_end].to_string(),
            after_bracket[1..].to_string(),
        )
    } else {
        // IPv4 or hostname: host:port
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.to_string()),
            None => {
                return Err(RelayError::TlsError(format!(
                    "invalid endpoint: {endpoint} — missing port"
                )));
            }
        }
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| RelayError::TlsError(format!("invalid port in endpoint: {endpoint}")))?;

    Ok(ParsedEndpoint {
        scheme: scheme.to_string(),
        host,
        port,
    })
}

impl ParsedEndpoint {
    /// Returns a `SocketAddr` if the host is an IP address, otherwise returns an error.
    pub fn to_socket_addr(&self) -> Result<SocketAddr, RelayError> {
        let addr_str = format!("{}:{}", self.host, self.port);
        addr_str
            .parse()
            .map_err(|e| RelayError::TlsError(format!("failed to resolve '{}': {e}", addr_str)))
    }

    /// Returns the host:port string suitable for DNS resolution.
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ============================================================
// TLS connector configuration
// ============================================================

/// Build a `TlsConnector` configured for TLS 1.3 only with system root CAs
/// and optional additional CA certificate bundle.
pub fn build_tls_connector(ca_cert_path: Option<&PathBuf>) -> Result<TlsConnector, RelayError> {
    let mut root_store = rustls::RootCertStore::empty();

    // Load system root certificates
    let native_result = rustls_native_certs::load_native_certs();
    let native_certs = native_result.certs;
    if !native_result.errors.is_empty() {
        debug!(
            "Warnings loading system root certificates: {:?}",
            native_result.errors
        );
    }

    let mut loaded_count = 0;
    for cert in native_certs {
        if root_store.add(cert).is_ok() {
            loaded_count += 1;
        }
    }
    debug!("Loaded {loaded_count} system root certificates");

    // Load additional CA certificates if specified
    if let Some(ca_path) = ca_cert_path {
        let ca_pem = std::fs::read(ca_path).map_err(|e| {
            RelayError::TlsError(format!(
                "failed to read CA certificate file '{}': {e}",
                ca_path.display()
            ))
        })?;

        let mut added = 0;
        for cert_result in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
            let cert = cert_result.map_err(|e| {
                RelayError::TlsError(format!("failed to parse CA certificate: {e}"))
            })?;
            root_store.add(cert).map_err(|e| {
                RelayError::TlsError(format!("failed to add CA certificate to root store: {e}"))
            })?;
            added += 1;
        }
        debug!(
            "Added {added} certificates from CA bundle '{}'",
            ca_path.display()
        );
    }

    // Configure TLS 1.3 only. Do not rely on rustls defaults here: dev/test
    // feature unification can make TLS 1.2 available, but relay A2 requires
    // TLS 1.3-only transport semantics.
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Perform a TLS handshake on an already-connected TCP stream.
pub async fn tls_connect(
    tcp_stream: TcpStream,
    server_name: &str,
    connector: &TlsConnector,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, RelayError> {
    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|e| RelayError::TlsError(format!("invalid server name '{server_name}': {e}")))?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| RelayError::TlsError(format!("TLS handshake failed: {e}")))?;

    Ok(tls_stream)
}

/// Load a certificate chain and private key for a TLS server.
pub fn load_tls_server_config(
    cert_chain_path: &PathBuf,
    private_key_path: &PathBuf,
) -> Result<rustls::ServerConfig, RelayError> {
    // Load certificate chain
    let cert_pem = std::fs::read(cert_chain_path).map_err(|e| {
        RelayError::TlsError(format!(
            "failed to read certificate chain '{}': {e}",
            cert_chain_path.display()
        ))
    })?;

    let mut certs = Vec::new();
    for cert_result in rustls_pemfile::certs(&mut cert_pem.as_slice()) {
        let cert = cert_result
            .map_err(|e| RelayError::TlsError(format!("failed to parse certificate: {e}")))?;
        certs.push(cert);
    }

    if certs.is_empty() {
        return Err(RelayError::TlsError(
            "no certificates found in certificate chain file".into(),
        ));
    }

    // Load private key
    let key_pem = std::fs::read(private_key_path).map_err(|e| {
        RelayError::TlsError(format!(
            "failed to read private key '{}': {e}",
            private_key_path.display()
        ))
    })?;

    let private_key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| RelayError::TlsError(format!("failed to read private key: {e}")))?
        .ok_or_else(|| RelayError::TlsError("no private key found in private key file".into()))?;

    let config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .map_err(|e| RelayError::TlsError(format!("failed to configure TLS server: {e}")))?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tls_endpoint() {
        let ep = parse_endpoint("tls://relay.example.com:18081", false).unwrap();
        assert_eq!(ep.scheme, "tls");
        assert_eq!(ep.host, "relay.example.com");
        assert_eq!(ep.port, 18081);
    }

    #[test]
    fn test_parse_tls_endpoint_ipv4() {
        let ep = parse_endpoint("tls://127.0.0.1:18081", false).unwrap();
        assert_eq!(ep.scheme, "tls");
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 18081);
    }

    #[test]
    fn test_parse_tls_endpoint_ipv6() {
        let ep = parse_endpoint("tls://[::1]:18081", false).unwrap();
        assert_eq!(ep.scheme, "tls");
        assert_eq!(ep.host, "[::1]");
        assert_eq!(ep.port, 18081);
    }

    #[test]
    fn test_manifest_does_not_enable_tls12() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            !manifest.contains("tls12"),
            "relay crate must not enable rustls tls12; A2 requires TLS 1.3-only transport"
        );
    }

    #[test]
    fn test_parse_tcp_endpoint_allowed() {
        let ep = parse_endpoint("tcp://127.0.0.1:8080", true).unwrap();
        assert_eq!(ep.scheme, "tcp");
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 8080);
    }

    #[test]
    fn test_parse_tcp_endpoint_rejected_in_secure_mode() {
        let result = parse_endpoint("tcp://127.0.0.1:8080", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_legacy_endpoint_rejected_in_secure_mode() {
        let result = parse_endpoint("127.0.0.1:8080", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_legacy_endpoint_allowed_in_dev() {
        let ep = parse_endpoint("127.0.0.1:18081", true).unwrap();
        assert_eq!(ep.scheme, "tcp");
        assert_eq!(ep.host, "127.0.0.1");
        assert_eq!(ep.port, 18081);
    }

    #[test]
    fn test_parse_invalid_endpoint() {
        assert!(parse_endpoint("tls://host", false).is_err());
        assert!(parse_endpoint("tls://host:", false).is_err());
        assert!(parse_endpoint("", false).is_err());
    }
}
