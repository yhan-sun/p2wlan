//! Error types for NAT traversal module.

use thiserror::Error;

/// Errors that can occur during NAT traversal operations.
#[derive(Error, Debug)]
pub enum NatError {
    /// STUN protocol error (malformed message, invalid attribute, etc.)
    #[error("STUN error: {0}")]
    Stun(String),

    /// Invalid or unparseable STUN message
    #[error("invalid STUN message: {0}")]
    InvalidStunMessage(String),

    /// Invalid or unparseable STUN attribute
    #[error("invalid STUN attribute: {0}")]
    InvalidAttribute(String),

    /// Network I/O error
    #[error("network error: {0}")]
    Network(String),

    /// Operation timed out
    #[error("timeout: {0}")]
    Timeout(String),

    /// NAT type detection failed
    #[error("NAT detection failed: {0}")]
    DetectionFailed(String),

    /// UDP hole punching failed
    #[error("hole punch failed: {0}")]
    PunchFailed(String),

    /// No candidates available
    #[error("no candidates available")]
    NoCandidates,

    /// IO error wrapper
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for NAT traversal operations.
pub type Result<T> = std::result::Result<T, NatError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            NatError::Stun("bad msg".into()).to_string(),
            "STUN error: bad msg"
        );
        assert_eq!(NatError::Timeout("5s".into()).to_string(), "timeout: 5s");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let nat_err: NatError = io_err.into();
        assert!(matches!(nat_err, NatError::Io(_)));
    }
}
