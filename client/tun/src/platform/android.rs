//! Android TUN device backed by an fd established by `VpnService.Builder`.
//!
//! Android does not allow an application to create a kernel TUN interface in
//! the same way as Linux. The Java/Kotlin `VpnService` owns route/address
//! setup and passes the non-blocking fd returned by `establish()` to Rust.
//! The fd carries raw IP packets because the builder is configured without
//! packet-information or Ethernet headers.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;

/// A raw-IP Android VPN interface supplied by `VpnService`.
pub struct AndroidTun {
    fd: AsyncFd<OwnedFd>,
    name: String,
    mtu: u32,
    /// This is the daemon's logical overlay address. It may differ from the
    /// provisional address used while Android establishes the VPN before a
    /// managed control-plane registration returns the final VIP.
    address: String,
    is_up: bool,
}

impl AndroidTun {
    /// Wrap an fd returned by `ParcelFileDescriptor.detachFd()`.
    ///
    /// Ownership transfers to this object. The fd is closed automatically when
    /// the daemon shuts down.
    pub fn from_raw_fd(fd: i32, config: &InterfaceConfig) -> Result<Self> {
        if fd < 0 {
            return Err(Error::Platform(format!(
                "Android VPN returned an invalid TUN fd: {fd}"
            )));
        }

        // Safety: the Android VPN service transfers ownership of this valid fd
        // to Rust exactly once via detachFd().
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw_fd = owned_fd.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
            if flags < 0 {
                return Err(Error::Io(io::Error::last_os_error()));
            }
            if libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(Error::Io(io::Error::last_os_error()));
            }
        }

        let async_fd = AsyncFd::new(owned_fd)?;
        Ok(Self {
            fd: async_fd,
            name: config.name.clone(),
            mtu: config.mtu,
            address: config.address.to_string(),
            is_up: true,
        })
    }

    /// Android VPN interfaces are created by the platform service, not by
    /// opening `/dev/net/tun` from the daemon.
    pub fn create(_config: &InterfaceConfig) -> Result<Self> {
        Err(Error::Unsupported)
    }
}

#[async_trait]
impl VirtualInterface for AndroidTun {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: the fd is owned by this object and the slice is valid.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result.map_err(Error::Io),
                Err(_would_block) => continue,
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: the fd is owned by this object and the slice is valid.
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result.map_err(Error::Io),
                Err(_would_block) => continue,
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn address(&self) -> &str {
        &self.address
    }

    fn is_up(&self) -> bool {
        self.is_up
    }
}

impl Drop for AndroidTun {
    fn drop(&mut self) {
        self.is_up = false;
        tracing::info!("Android VPN TUN interface {} closed", self.name);
    }
}
