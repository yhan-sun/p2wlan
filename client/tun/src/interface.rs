//! The virtual interface abstraction trait.
//!
//! All platform-specific implementations (Linux TUN, Windows Wintun,
//! macOS utun, and the Mock device) implement this trait.

use async_trait::async_trait;

use crate::error::Result;

/// The core trait for a virtual network interface.
///
/// Implementations provide async packet read/write operations.
/// The trait is object-safe, allowing `Box<dyn VirtualInterface>`.
#[async_trait]
pub trait VirtualInterface: Send {
    /// Read a single IP packet from the interface into `buf`.
    ///
    /// Returns the number of bytes read, or an error if the read fails.
    /// This method is async and will yield when no data is available.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive the packet data. Should be at least MTU-sized.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Write a single IP packet to the interface.
    ///
    /// Returns the number of bytes written, or an error if the write fails.
    ///
    /// # Arguments
    ///
    /// * `buf` - The packet data to write (a complete IP packet).
    async fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Get the interface name (e.g. "p2pnet0", "wintun0").
    fn name(&self) -> &str;

    /// Get the configured MTU.
    fn mtu(&self) -> u32;

    /// Get the assigned IPv4 address as a string.
    fn address(&self) -> &str;

    /// Check if the interface is still open and usable.
    fn is_up(&self) -> bool;
}
