//! Linux TUN device implementation using `/dev/net/tun`.
//!
//! Uses `TUNSETIFF` ioctl to create a TUN interface, and `AsyncFd`
//! from tokio for non-blocking async I/O.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use async_trait::async_trait;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use tokio::io::unix::AsyncFd;

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;

// --- Linux constants ---

/// Path to the TUN device file.
const TUN_DEVICE: &str = "/dev/net/tun";

/// ioctl magic for TUN devices.
const TUN_IOCTL: libc::c_ulong = 0x400454ca; // TUNSETIFF

/// IFF_TUN flag (no Ethernet headers, raw IP packets).
const IFF_TUN: libc::c_short = 0x0001;

/// IFF_NO_PI flag (don't prepend packet info header).
const IFF_NO_PI: libc::c_short = 0x1000;

/// Interface request structure for TUNSETIFF.
#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Linux TUN device backed by an async file descriptor.
pub struct LinuxTun {
    /// Async file descriptor wrapper around the TUN device fd.
    fd: AsyncFd<OwnedFd>,
    /// Interface name (e.g. "p2pnet0").
    name: String,
    /// MTU value.
    mtu: u32,
    /// Assigned IPv4 address.
    address: String,
    /// Whether the device is still open.
    is_up: bool,
}

impl LinuxTun {
    /// Create a new TUN interface with the given configuration.
    ///
    /// This opens `/dev/net/tun`, configures the interface with TUNSETIFF,
    /// and sets the IP address and MTU via ioctl.
    ///
    /// # Requirements
    ///
    /// - Must be run as root (or with CAP_NET_ADMIN capability).
    /// - The `/dev/net/tun` device must exist (it usually does on Linux).
    pub fn create(config: &InterfaceConfig) -> Result<Self> {
        tracing::info!("Creating Linux TUN interface: {}", config.name);

        // Open /dev/net/tun
        let tun_path = CString::new(TUN_DEVICE).unwrap();
        let fd = open(tun_path.as_c_str(), OFlag::O_RDWR, Mode::empty())
            .map_err(|e| Error::Platform(format!("failed to open {TUN_DEVICE}: {e}")))?;

        // Safety: fd is valid and we own it.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Set non-blocking mode
        // On Linux, we set O_NONBLOCK on the fd
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

        // Prepare the Ifreq structure
        let mut ifr = Ifreq {
            name: [0u8; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };

        // Copy interface name
        let name_bytes = config.name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        // Issue TUNSETIFF ioctl
        unsafe {
            let ret = libc::ioctl(raw_fd, TUN_IOCTL as _, &mut ifr as *mut Ifreq);
            if ret < 0 {
                let err = io::Error::last_os_error();
                tracing::error!("TUNSETIFF failed: {err}");
                return Err(Error::Platform(format!("TUNSETIFF ioctl failed: {err}")));
            }
        }

        // Read back the actual interface name (kernel may have modified it)
        let actual_name = {
            let name_end = ifr.name.iter().position(|&b| b == 0).unwrap_or(16);
            String::from_utf8_lossy(&ifr.name[..name_end]).to_string()
        };

        tracing::info!("TUN interface created: {actual_name}");

        // Set the IP address on the interface
        set_interface_address(&actual_name, config.address, config.netmask)?;

        // Set the MTU
        set_interface_mtu(&actual_name, config.mtu)?;

        // Bring the interface up
        set_interface_up(&actual_name)?;

        // Wrap the fd in AsyncFd for async I/O
        let fd = AsyncFd::new(owned_fd)?;

        Ok(Self {
            fd,
            name: actual_name,
            mtu: config.mtu,
            address: config.address.to_string(),
            is_up: true,
        })
    }
}

#[async_trait]
impl VirtualInterface for LinuxTun {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: reading from a valid fd into a valid buffer.
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => {
                    return result.map_err(Error::Io);
                }
                Err(_would_block) => {
                    // Not ready yet, loop to re-register interest.
                    continue;
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: writing from a valid buffer to a valid fd.
                let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => {
                    return result.map_err(Error::Io);
                }
                Err(_would_block) => {
                    continue;
                }
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

impl Drop for LinuxTun {
    fn drop(&mut self) {
        self.is_up = false;
        // The OwnedFd will be closed automatically when dropped.
        // We could also bring the interface down here, but on Linux
        // closing the fd destroys the TUN device automatically.
        tracing::info!("TUN interface {} closed", self.name);
    }
}

// --- Helper functions ---

/// Set the IPv4 address and netmask on a network interface.
fn set_interface_address(name: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    tracing::debug!("Setting {name} address: {addr}/{netmask}");

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    // Safety: ensure the socket is closed when we're done.
    let _guard = ScopeGuard::new(|| unsafe {
        libc::close(sock);
    });

    // Build sockaddr_in for the address
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Set address
    ifr.ifr_ifru.ifru_addr.sin_family = libc::AF_INET as u16;
    ifr.ifr_ifru.ifru_addr.sin_addr.s_addr = u32::from(addr).to_be();
    unsafe {
        if libc::ioctl(sock, libc::SIOCSIFADDR, &ifr) < 0 {
            let err = io::Error::last_os_error();
            tracing::error!("SIOCSIFADDR failed: {err}");
            return Err(Error::Platform(format!("SIOCSIFADDR failed: {err}")));
        }
    }

    // Set netmask
    ifr.ifr_ifru.ifru_netmask.sin_family = libc::AF_INET as u16;
    ifr.ifr_ifru.ifru_netmask.sin_addr.s_addr = u32::from(netmask).to_be();
    unsafe {
        if libc::ioctl(sock, libc::SIOCSIFNETMASK, &ifr) < 0 {
            let err = io::Error::last_os_error();
            tracing::error!("SIOCSIFNETMASK failed: {err}");
            return Err(Error::Platform(format!("SIOCSIFNETMASK failed: {err}")));
        }
    }

    Ok(())
}

/// Set the MTU on a network interface.
fn set_interface_mtu(name: &str, mtu: u32) -> Result<()> {
    tracing::debug!("Setting {name} MTU: {mtu}");

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let _guard = ScopeGuard::new(|| unsafe {
        libc::close(sock);
    });

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    ifr.ifr_ifru.ifru_mtu = mtu as i32;

    unsafe {
        if libc::ioctl(sock, libc::SIOCSIFMTU, &ifr) < 0 {
            let err = io::Error::last_os_error();
            tracing::error!("SIOCSIFMTU failed: {err}");
            return Err(Error::Platform(format!("SIOCSIFMTU failed: {err}")));
        }
    }

    Ok(())
}

/// Bring a network interface up (set IFF_UP | IFF_RUNNING).
fn set_interface_up(name: &str) -> Result<()> {
    tracing::debug!("Bringing interface {name} up");

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::Io(io::Error::last_os_error()));
    }

    let _guard = ScopeGuard::new(|| unsafe {
        libc::close(sock);
    });

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // Get current flags
    unsafe {
        if libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr) < 0 {
            let err = io::Error::last_os_error();
            return Err(Error::Platform(format!("SIOCGIFFLAGS failed: {err}")));
        }
    }

    // Set IFF_UP | IFF_RUNNING
    ifr.ifr_ifru.ifru_flags |= libc::IFF_UP | libc::IFF_RUNNING;

    unsafe {
        if libc::ioctl(sock, libc::SIOCSIFFLAGS, &ifr) < 0 {
            let err = io::Error::last_os_error();
            tracing::error!("SIOCSIFFLAGS failed: {err}");
            return Err(Error::Platform(format!("SIOCSIFFLAGS failed: {err}")));
        }
    }

    tracing::info!("Interface {name} is up");
    Ok(())
}

/// RAII guard that runs a closure when dropped.
struct ScopeGuard<F: FnOnce()> {
    f: Option<F>,
}

impl<F: FnOnce()> ScopeGuard<F> {
    fn new(f: F) -> Self {
        Self { f: Some(f) }
    }
}

impl<F: FnOnce()> Drop for ScopeGuard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.f.take() {
            f();
        }
    }
}
