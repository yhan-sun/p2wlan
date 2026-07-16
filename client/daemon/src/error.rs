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
}
