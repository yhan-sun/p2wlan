//! Unified TUN device type.
//!
//! `TunDevice` is a type alias for the platform-specific implementation:
//!
//! - Linux: [`LinuxTun`](crate::platform::linux::LinuxTun)
//! - Windows: [`WintunDevice`](crate::platform::windows::WintunDevice)
//! - macOS: [`UtunDevice`](crate::platform::macos::UtunDevice)
//!
//! All implementations satisfy the [`VirtualInterface`] trait.

use crate::config::InterfaceConfig;
use crate::error::Result;
use crate::platform::PlatformTun;

/// The platform-specific TUN device.
///
/// Create one with [`TunDevice::create`], then use the async `read`/`write`
/// methods (provided by the [`VirtualInterface`](crate::VirtualInterface) trait).
///
/// # Example
///
/// ```no_run
/// use p2pnet_tun::{InterfaceConfig, TunDevice, VirtualInterface};
///
/// #[tokio::main]
/// async fn main() -> p2pnet_tun::Result<()> {
///     let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420)?;
///     let mut dev = TunDevice::create(&config)?;
///
///     let mut buf = [0u8; 65535];
///     let n = dev.read(&mut buf).await?;
///     println!("Read {} bytes", n);
///     Ok(())
/// }
/// ```
pub type TunDevice = PlatformTun;

/// Constructor methods available on all platform-specific devices.
///
/// This trait is implemented by each platform's device struct.
/// It provides the `create` method that builds the device from a config.
pub trait TunDeviceExt: Sized {
    /// Create a new TUN device from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The system does not have permission to create network interfaces
    /// - The dynamic library (wintun.dll on Windows) is not found
    /// - The interface name is invalid or already in use
    fn create(config: &InterfaceConfig) -> Result<Self>;
}

impl TunDeviceExt for TunDevice {
    fn create(config: &InterfaceConfig) -> Result<Self> {
        PlatformTun::create(config)
    }
}
