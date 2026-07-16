//! Platform-specific TUN device implementations.
//!
//! Each platform module exports a device struct with a consistent API:
//!
//! - `create(config: &InterfaceConfig) -> Result<Self>`
//! - `async read(&mut self, buf: &mut [u8]) -> Result<usize>`
//! - `async write(&mut self, buf: &[u8]) -> Result<usize>`
//! - `name(&self) -> &str`
//! - `mtu(&self) -> u32`
//! - `address(&self) -> &str`
//! - `is_up(&self) -> bool`

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

// Re-export the platform-specific device as `PlatformTun`
#[cfg(target_os = "linux")]
pub use linux::LinuxTun as PlatformTun;

#[cfg(target_os = "windows")]
pub use windows::WintunDevice as PlatformTun;

#[cfg(target_os = "macos")]
pub use macos::UtunDevice as PlatformTun;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
compile_error!("p2pnet-tun is only supported on Linux, Windows, and macOS");
