//! HarmonyOS TUN device backed by the fd created by `VpnConnection.create()`.
//!
//! HarmonyOS owns vNIC configuration and routing through its VPN extension
//! API. This backend only adopts the fd supplied by that extension; it never
//! opens `/dev/net/tun` or attempts Linux interface ioctls.

use async_trait::async_trait;
use std::os::fd::OwnedFd;

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;
use crate::platform::android::AndroidTun;

/// A raw-IP HarmonyOS VPN interface supplied by the VPN extension.
pub struct OhosTun {
    inner: AndroidTun,
}

impl OhosTun {
    /// Adopt an already-owned descriptor from the same-process native bridge.
    ///
    /// The bridge must pass a duplicate of the `VpnConnection` descriptor;
    /// this object owns and closes only that duplicate.
    pub fn from_owned_fd(fd: OwnedFd, config: &InterfaceConfig) -> Result<Self> {
        AndroidTun::from_owned_fd_if_nonblocking(fd, config).map(|inner| Self { inner })
    }

    /// HarmonyOS vNICs must be created by `VpnConnection`; creating a Linux
    /// TUN device from the daemon is not valid on this target.
    pub fn create(_config: &InterfaceConfig) -> Result<Self> {
        Err(Error::Platform(
            "HarmonyOS TUN requires an fd from the VPN extension".to_string(),
        ))
    }
}

#[async_trait]
impl VirtualInterface for OhosTun {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf).await
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.write(buf).await
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn mtu(&self) -> u32 {
        self.inner.mtu()
    }

    fn address(&self) -> &str {
        self.inner.address()
    }

    fn is_up(&self) -> bool {
        self.inner.is_up()
    }
}
