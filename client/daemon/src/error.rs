//! Error types for the daemon.

use thiserror::Error;

/// Result type alias for daemon operations.
pub type Result<T> = std::result::Result<T, DaemonError>;

/// Errors that can occur in the daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Network/interface error.
    #[error("network error: {0}")]
    Network(String),

    /// Peer connection error.
    #[error("peer error: {0}")]
    Peer(String),

    /// Tunnel error.
    #[error("tunnel error: {0}")]
    Tunnel(String),

    /// Control plane communication error.
    #[error("control plane error: {0}")]
    ControlPlane(String),

    /// Relay error.
    #[error("relay error: {0}")]
    Relay(String),

    /// Port mapping error.
    #[error("port mapping error: {0}")]
    PortMapping(String),

    /// DNS error.
    #[error("DNS error: {0}")]
    Dns(String),

    /// ACL error.
    #[error("ACL error: {0}")]
    Acl(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Auth/credential is permanently invalid.
    #[error("authentication failed: {0}")]
    Auth(String),

    /// Handshake timed out.
    #[error("handshake timeout for {0}")]
    HandshakeTimeout(String),

    /// Task crashed.
    #[error("task crashed: {0}")]
    TaskCrash(String),
}

/// Determine whether a control-plane error is retryable.
/// 4xx errors (other than 429) are permanent; 5xx and network errors are retryable.
pub fn is_retryable_control_error(code: u16) -> bool {
    match code {
        401 | 403 | 404 => false,
        429 => true,
        _ => code >= 500,
    }
}

/// Classify an HTTP status code for control-plane operations.
pub fn classify_http_status(status: u16) -> ControlErrorKind {
    match status {
        200..=399 => ControlErrorKind::Success,
        401..=404 => ControlErrorKind::Auth,
        429 => ControlErrorKind::RateLimit,
        400..=499 => ControlErrorKind::Client,
        500..=599 => ControlErrorKind::Server,
        _ => ControlErrorKind::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlErrorKind {
    Success,
    Auth,
    RateLimit,
    Client,
    Server,
    Unknown,
}

impl std::fmt::Display for ControlErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Auth => write!(f, "auth"),
            Self::RateLimit => write!(f, "rate_limit"),
            Self::Client => write!(f, "client_error"),
            Self::Server => write!(f, "server_error"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = DaemonError::Config("bad config".into());
        assert!(e.to_string().contains("bad config"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let daemon_err: DaemonError = io_err.into();
        assert!(matches!(daemon_err, DaemonError::Io(_)));
    }

    #[test]
    fn test_is_retryable() {
        assert!(!is_retryable_control_error(401));
        assert!(!is_retryable_control_error(403));
        assert!(!is_retryable_control_error(404));
        assert!(is_retryable_control_error(429));
        assert!(is_retryable_control_error(500));
        assert!(is_retryable_control_error(502));
        assert!(is_retryable_control_error(503));
    }

    #[test]
    fn test_classify_http_status() {
        assert_eq!(classify_http_status(200), ControlErrorKind::Success);
        assert_eq!(classify_http_status(401), ControlErrorKind::Auth);
        assert_eq!(classify_http_status(403), ControlErrorKind::Auth);
        assert_eq!(classify_http_status(404), ControlErrorKind::Auth);
        assert_eq!(classify_http_status(429), ControlErrorKind::RateLimit);
        assert_eq!(classify_http_status(400), ControlErrorKind::Client);
        assert_eq!(classify_http_status(500), ControlErrorKind::Server);
    }
}
