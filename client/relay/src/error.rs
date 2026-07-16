//! Error types for the relay module.

use thiserror::Error;

/// Result type alias for relay operations.
pub type Result<T> = std::result::Result<T, RelayError>;

/// Errors that can occur during relay operations.
#[derive(Debug, Error)]
pub enum RelayError {
    /// I/O error (network read/write failure).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol violation (invalid frame, bad magic, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Failed to connect to relay server.
    #[error("connect failed: {0}")]
    ConnectFailed(String),

    /// Not connected to relay server.
    #[error("not connected to relay")]
    NotConnected,

    /// Target peer not found on the relay server.
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Received an unexpected message type.
    #[error("unexpected message type: {0:#04X}")]
    UnexpectedMessageType(u8),

    /// Server returned an error.
    #[error("server error (code {0}): {1}")]
    ServerError(u16, String),

    /// Connection closed by remote.
    #[error("connection closed: {0}")]
    Closed(String),

    /// Frame too large.
    #[error("frame too large: {0} bytes (max {1})")]
    FrameTooLarge(usize, usize),

    /// Channel communication error.
    #[error("channel error: {0}")]
    Channel(String),
}

impl From<tokio::sync::mpsc::error::SendError<Vec<u8>>> for RelayError {
    fn from(e: tokio::sync::mpsc::error::SendError<Vec<u8>>) -> Self {
        RelayError::Channel(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let e = RelayError::Protocol("bad magic".into());
        assert!(e.to_string().contains("bad magic"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let relay_err: RelayError = io_err.into();
        assert!(matches!(relay_err, RelayError::Io(_)));
    }
}
