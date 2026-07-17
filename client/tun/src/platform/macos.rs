//! macOS utun device implementation.
//!
//! Uses the `PF_SYSTEM` / `SYSPROTO_CONTROL` socket to create a utun
//! device. On macOS, utun devices are kernel extensions that provide
//! TUN-like functionality.

use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;

// --- macOS constants ---

/// Control panel ID for utun (com.apple.net.utun_control).
const CTL_NAME: &str = "com.apple.net.utun_control";

/// UTUN_OPT_IFNAME constant from net/if_utun.h.
const UTUN_OPT_IFNAME: u32 = 2;

/// macOS utun device.
pub struct UtunDevice {
    /// Async file descriptor wrapper.
    fd: AsyncFd<OwnedFd>,
    /// Interface name (e.g. "utun0").
    name: String,
    /// MTU value.
    mtu: u32,
    /// Assigned IPv4 address.
    address: String,
    /// Whether the device is still open.
    is_up: bool,
}

impl UtunDevice {
    /// Create a new utun interface with the given configuration.
    ///
    /// # Requirements
    ///
    /// - Must be run as root.
    /// - The kernel must support utun (macOS 10.7+).
    pub fn create(config: &InterfaceConfig) -> Result<Self> {
        tracing::info!("Creating macOS utun interface: {}", config.name);

        // Create a PF_SYSTEM socket
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Set non-blocking mode
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

        // Find the control ID for utun
        let mut ctl_info: ctl_info = unsafe { std::mem::zeroed() };
        let ctl_name = std::ffi::CString::new(CTL_NAME).unwrap();
        let name_ptr = ctl_name.as_bytes_with_nul().as_ptr() as *const libc::c_char;

        // Copy the control name
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_ptr,
                ctl_info.ctl_name.as_mut_ptr() as *mut libc::c_char,
                CTL_NAME.len().min(96),
            );
        }

        unsafe {
            if libc::ioctl(raw_fd, libc::CTLIOCGINFO, &mut ctl_info) < 0 {
                let err = io::Error::last_os_error();
                tracing::error!("CTLIOCGINFO failed: {err}");
                return Err(Error::Platform(format!("CTLIOCGINFO failed: {err}")));
            }
        }

        // Connect to the utun control
        let mut addr: sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = ctl_info.ctl_id;
        addr.sc_unit = 0; // Let the kernel assign a unit number

        unsafe {
            let ret = libc::connect(
                raw_fd,
                &addr as *const sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ctl>() as libc::socklen_t,
            );
            if ret < 0 {
                let err = io::Error::last_os_error();
                tracing::error!("utun connect failed: {err}");
                return Err(Error::Platform(format!("utun connect failed: {err}")));
            }
        }

        // Get the actual interface name assigned by the kernel. macOS utun
        // names are kernel-assigned and must be queried from the control
        // socket; deriving the name from a unit number can point at the wrong
        // utun device and route traffic away from this fd.
        let mut ifname = [0 as libc::c_char; libc::IF_NAMESIZE];
        let mut len = ifname.len() as libc::socklen_t;
        unsafe {
            if libc::getsockopt(
                raw_fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME as libc::c_int,
                ifname.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            ) < 0
            {
                let err = io::Error::last_os_error();
                return Err(Error::Platform(format!(
                    "getsockopt UTUN_OPT_IFNAME failed: {err}"
                )));
            }
        }

        let actual_name = unsafe { CStr::from_ptr(ifname.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if actual_name.is_empty() {
            return Err(Error::Platform(
                "getsockopt UTUN_OPT_IFNAME returned an empty interface name".to_string(),
            ));
        }
        tracing::info!("utun interface created: {actual_name}");

        // Set the IP address
        set_interface_address(&actual_name, config.address, config.netmask)?;

        // Set the MTU
        set_interface_mtu(&actual_name, config.mtu)?;

        // Bring the interface up
        set_interface_up(&actual_name)?;

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
impl VirtualInterface for UtunDevice {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;

            // On macOS utun, the first 4 bytes are the protocol family.
            // We read into a buffer that has room for the prefix, then skip it.
            let mut read_buf = [0u8; 65535 + 4];

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: reading from a valid fd into a valid buffer.
                let n = unsafe {
                    libc::read(
                        fd,
                        read_buf.as_mut_ptr() as *mut libc::c_void,
                        read_buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => {
                    let n = result.map_err(Error::Io)?;
                    // Skip the 4-byte protocol family prefix
                    if n <= 4 {
                        return Ok(0);
                    }
                    let pkt_len = n - 4;
                    let copy_len = pkt_len.min(buf.len());
                    buf[..copy_len].copy_from_slice(&read_buf[4..4 + copy_len]);
                    return Ok(copy_len);
                }
                Err(_would_block) => {
                    continue;
                }
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;

            // Prepend the 4-byte protocol family.
            // AF_INET = 2 for IPv4, AF_INET6 = 30 for IPv6
            let mut write_buf = Vec::with_capacity(buf.len() + 4);
            let af = if !buf.is_empty() && (buf[0] >> 4) == 4 {
                libc::AF_INET as u32
            } else {
                libc::AF_INET6 as u32
            };
            write_buf.extend_from_slice(&af.to_be_bytes());
            write_buf.extend_from_slice(buf);

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                // Safety: writing from a valid buffer to a valid fd.
                let n = unsafe {
                    libc::write(
                        fd,
                        write_buf.as_ptr() as *const libc::c_void,
                        write_buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => {
                    let _n = result.map_err(Error::Io)?;
                    // Return the original packet size (not including the prefix)
                    return Ok(buf.len());
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

impl Drop for UtunDevice {
    fn drop(&mut self) {
        self.is_up = false;
        tracing::info!("utun interface {} closed", self.name);
    }
}

// --- macOS FFI types ---

/// ctl_info structure for CTLIOCGINFO ioctl.
#[repr(C)]
struct ctl_info {
    ctl_id: u32,
    ctl_name: [libc::c_char; 96],
}

/// sockaddr_ctl structure for connecting to a kernel control.
#[repr(C)]
struct sockaddr_ctl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

// --- Helper functions (similar to Linux) ---

fn set_interface_address(name: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    run_ifconfig([
        name,
        "inet",
        &addr.to_string(),
        &addr.to_string(),
        "netmask",
        &netmask.to_string(),
        "up",
    ])?;

    tracing::info!("Interface {name} address set to {addr}/{netmask}");
    Ok(())
}

fn set_interface_mtu(name: &str, mtu: u32) -> Result<()> {
    let mtu = mtu.to_string();
    run_ifconfig([name, "mtu", &mtu])?;
    Ok(())
}

fn set_interface_up(name: &str) -> Result<()> {
    run_ifconfig([name, "up"])?;
    tracing::info!("Interface {name} is up");
    Ok(())
}

fn run_ifconfig<'a, I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let args: Vec<&str> = args.into_iter().collect();
    let output = Command::new("/sbin/ifconfig")
        .args(&args)
        .output()
        .map_err(Error::Io)?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if stderr.is_empty() { stdout } else { stderr };

    Err(Error::Platform(format!(
        "ifconfig {} failed: {detail}",
        args.join(" ")
    )))
}
