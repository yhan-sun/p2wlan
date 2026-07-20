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

    /// Unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Invalid magic header.
    #[error("invalid magic header")]
    InvalidMagic,
}

/// Stable error codes matching Go relay implementation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RelayErrorCode {
    InvalidFrame = 4000,
    UnsupportedVersion = 4001,
    RegistrationRequired = 4002,
    RegistrationTimeout = 4003,
    DuplicateRegistration = 4004,
    ConnectionLimit = 4005,
    FrameTooLarge = 4006,
    PeerNotFound = 404,
    PeerBackpressure = 4008,
    IdleTimeout = 4009,
    TransportClosed = 4010,
}

impl RelayErrorCode {
    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            4000 => Some(Self::InvalidFrame),
            4001 => Some(Self::UnsupportedVersion),
            4002 => Some(Self::RegistrationRequired),
            4003 => Some(Self::RegistrationTimeout),
            4004 => Some(Self::DuplicateRegistration),
            4005 => Some(Self::ConnectionLimit),
            4006 => Some(Self::FrameTooLarge),
            404 => Some(Self::PeerNotFound),
            4008 => Some(Self::PeerBackpressure),
            4009 => Some(Self::IdleTimeout),
            4010 => Some(Self::TransportClosed),
            _ => None,
        }
    }

    pub fn to_u16(self) -> u16 {
        self as u16
    }

    pub fn to_snake_case(self) -> &'static str {
        match self {
            Self::InvalidFrame => "invalid_frame",
            Self::UnsupportedVersion => "unsupported_version",
            Self::RegistrationRequired => "registration_required",
            Self::RegistrationTimeout => "registration_timeout",
            Self::DuplicateRegistration => "duplicate_registration",
            Self::ConnectionLimit => "connection_limit",
            Self::FrameTooLarge => "frame_too_large",
            Self::PeerNotFound => "peer_not_found",
            Self::PeerBackpressure => "peer_backpressure",
            Self::IdleTimeout => "idle_timeout",
            Self::TransportClosed => "transport_closed",
        }
    }
}

impl RelayError {
    pub fn error_code(&self) -> Option<RelayErrorCode> {
        match self {
            RelayError::ServerError(code, _) => RelayErrorCode::from_u16(*code),
            RelayError::UnsupportedVersion(_) => Some(RelayErrorCode::UnsupportedVersion),
            RelayError::InvalidMagic => Some(RelayErrorCode::InvalidFrame),
            RelayError::FrameTooLarge(_, _) => Some(RelayErrorCode::FrameTooLarge),
            _ => None,
        }
    }

    pub fn to_snake_case(&self) -> &'static str {
        match self {
            RelayError::ServerError(code, _) => {
                if let Some(ec) = RelayErrorCode::from_u16(*code) {
                    ec.to_snake_case()
                } else {
                    "unknown_server_error"
                }
            }
            RelayError::Protocol(_) => "protocol_error",
            RelayError::Timeout(_) => "timeout",
            RelayError::ConnectFailed(_) => "connect_failed",
            RelayError::NotConnected => "not_connected",
            RelayError::PeerNotFound(_) => "peer_not_found",
            RelayError::FrameTooLarge(_, _) => "frame_too_large",
            RelayError::Channel(_) => "channel_error",
            RelayError::Closed(_) => "connection_closed",
            RelayError::Io(_) => "io_error",
            RelayError::UnexpectedMessageType(_) => "unexpected_message_type",
            RelayError::UnsupportedVersion(_) => "unsupported_version",
            RelayError::InvalidMagic => "invalid_magic",
        }
    }
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

    #[test]
    fn test_error_code_mapping() {
        assert_eq!(
            RelayErrorCode::from_u16(404),
            Some(RelayErrorCode::PeerNotFound)
        );
        assert_eq!(
            RelayErrorCode::PeerNotFound.to_snake_case(),
            "peer_not_found"
        );
        let err = RelayError::ServerError(4008, "backpressure".into());
        assert_eq!(err.to_snake_case(), "peer_backpressure");
    }
}
