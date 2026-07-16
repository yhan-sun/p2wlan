//! Error types for the TUN module.

use std::io;

use thiserror::Error;

/// All errors that can occur in the TUN module.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error from the operating system.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// The provided interface name is invalid (too long, contains illegal chars, etc.).
    #[error("invalid interface name: {0}")]
    InvalidInterfaceName(String),

    /// The provided IP address string could not be parsed.
    #[error("invalid IP address: {0}")]
    InvalidIpAddress(String),

    /// The IP packet is too short to contain a valid header.
    #[error("packet too short: got {0} bytes, expected at least {1}")]
    PacketTooShort(usize, usize),

    /// The IP version field is not 4 or 6.
    #[error("invalid IP version: {0}")]
    InvalidIpVersion(u8),

    /// The IPv4 header length (IHL) field is invalid.
    #[error("invalid IPv4 header length: {0}")]
    InvalidHeaderLength(usize),

    /// A required dynamic library (e.g. wintun.dll) was not found.
    #[error("dynamic library not found: {0}")]
    LibraryNotFound(String),

    /// A required symbol was not found in the dynamic library.
    #[error("symbol not found in library: {0}")]
    SymbolNotFound(String),

    /// The TUN device has been closed or is no longer usable.
    #[error("device closed")]
    DeviceClosed,

    /// The Wintun adapter could not be created.
    #[error("failed to create Wintun adapter: error code {0}")]
    WintunCreateFailed(u32),

    /// The Wintun session could not be started.
    #[error("failed to start Wintun session: error code {0}")]
    WintunSessionFailed(u32),

    /// Sending a packet failed because the ring buffer is full.
    #[error("send buffer full")]
    SendBufferFull,

    /// A platform-specific error with a descriptive message.
    #[error("{0}")]
    Platform(String),

    /// The operation is not supported on this platform.
    #[error("operation not supported on this platform")]
    Unsupported,
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, Error>;
