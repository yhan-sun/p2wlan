//! VPN TUN device backed by an fd established by the platform VPN API.
//!
//! Android and HarmonyOS create the interface through their VPN service or
//! extension, then hand its fd to Rust. The fd carries raw IP packets.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use async_trait::async_trait;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;

/// Selects the VPN TUN read implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AndroidTunMode {
    /// The default implementation: Tokio waits for readiness on a nonblocking
    /// fd and performs the read/write in the daemon task.
    #[default]
    AsyncFd,
    /// The experiment implementation: the platform supplies a blocking fd and a
    /// bounded reader/writer pair owns the blocking syscalls on dedicated
    /// threads. It can be removed independently if the A/B data does not
    /// justify it.
    DedicatedBlocking,
}

impl FromStr for AndroidTunMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "async_fd" | "async" => Ok(Self::AsyncFd),
            "dedicated_blocking" | "blocking" => Ok(Self::DedicatedBlocking),
            other => Err(format!(
                "unsupported VPN TUN mode {other:?}; expected async_fd or dedicated_blocking"
            )),
        }
    }
}

struct BlockingWriteRequest {
    packet: Vec<u8>,
    response: oneshot::Sender<io::Result<usize>>,
}

struct DedicatedBlockingTun {
    read_rx: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    write_tx: Option<mpsc::Sender<BlockingWriteRequest>>,
    stop: Arc<AtomicBool>,
    reader_thread: Option<thread::JoinHandle<()>>,
    writer_thread: Option<thread::JoinHandle<()>>,
}

impl DedicatedBlockingTun {
    const QUEUE_CAPACITY: usize = 128;
    const POLL_TIMEOUT_MS: i32 = 250;

    fn new(writer_fd: OwnedFd) -> Result<Self> {
        let reader_raw_fd = unsafe { libc::dup(writer_fd.as_raw_fd()) };
        if reader_raw_fd < 0 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        // Safety: dup returned a new owned descriptor on success.
        let reader_fd = unsafe { OwnedFd::from_raw_fd(reader_raw_fd) };
        let stop = Arc::new(AtomicBool::new(false));
        let (read_tx, read_rx) = mpsc::channel(Self::QUEUE_CAPACITY);
        let (write_tx, write_rx) = mpsc::channel(Self::QUEUE_CAPACITY);

        let reader_stop = Arc::clone(&stop);
        let reader_thread = match thread::Builder::new()
            .name("p2wlan-vpn-tun-reader".to_string())
            .spawn(move || Self::reader_loop(reader_fd, read_tx, reader_stop))
        {
            Ok(thread) => thread,
            Err(error) => return Err(Error::Io(error)),
        };

        let writer_stop = Arc::clone(&stop);
        let writer_thread = match thread::Builder::new()
            .name("p2wlan-vpn-tun-writer".to_string())
            .spawn(move || Self::writer_loop(writer_fd, write_rx, writer_stop))
        {
            Ok(thread) => thread,
            Err(error) => {
                stop.store(true, Ordering::Release);
                drop(read_rx);
                let _ = reader_thread.join();
                return Err(Error::Io(error));
            }
        };

        Ok(Self {
            read_rx: Some(read_rx),
            write_tx: Some(write_tx),
            stop,
            reader_thread: Some(reader_thread),
            writer_thread: Some(writer_thread),
        })
    }

    fn poll_fd(fd: &OwnedFd, events: libc::c_short, stop: &AtomicBool) -> io::Result<bool> {
        let mut descriptor = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(false);
            }
            let result = unsafe { libc::poll(&mut descriptor, 1, Self::POLL_TIMEOUT_MS) };
            if result > 0 {
                if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "VPN TUN fd was closed",
                    ));
                }
                return Ok(descriptor.revents & events != 0);
            }
            if result == 0 {
                continue;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    fn reader_loop(fd: OwnedFd, read_tx: mpsc::Sender<io::Result<Vec<u8>>>, stop: Arc<AtomicBool>) {
        let mut buffer = vec![0u8; 65_535];
        while !stop.load(Ordering::Acquire) {
            let ready = match Self::poll_fd(&fd, libc::POLLIN, &stop) {
                Ok(ready) => ready,
                Err(error) => {
                    let _ = read_tx.blocking_send(Err(error));
                    break;
                }
            };
            if !ready {
                continue;
            }
            let result = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if result > 0 {
                let packet = buffer[..result as usize].to_vec();
                if read_tx.blocking_send(Ok(packet)).is_err() {
                    break;
                }
                continue;
            }
            if result == 0 {
                let _ = read_tx.blocking_send(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "VPN TUN returned EOF",
                )));
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            let _ = read_tx.blocking_send(Err(error));
            break;
        }
    }

    fn writer_loop(
        fd: OwnedFd,
        mut write_rx: mpsc::Receiver<BlockingWriteRequest>,
        stop: Arc<AtomicBool>,
    ) {
        while !stop.load(Ordering::Acquire) {
            let Some(request) = write_rx.blocking_recv() else {
                break;
            };
            if stop.load(Ordering::Acquire) {
                let _ = request.response.send(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "VPN TUN writer stopped",
                )));
                break;
            }
            let result = match Self::poll_fd(&fd, libc::POLLOUT, &stop) {
                Ok(true) => unsafe {
                    let written = libc::write(
                        fd.as_raw_fd(),
                        request.packet.as_ptr() as *const libc::c_void,
                        request.packet.len(),
                    );
                    if written < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(written as usize)
                    }
                },
                Ok(false) => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "VPN TUN writer stopped",
                )),
                Err(error) => Err(error),
            };
            let _ = request.response.send(result);
        }
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let Some(read_rx) = self.read_rx.as_mut() else {
            return Err(Error::DeviceClosed);
        };
        match read_rx.recv().await {
            Some(Ok(packet)) => {
                if packet.len() > buf.len() {
                    return Err(Error::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VPN TUN packet exceeds read buffer",
                    )));
                }
                buf[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            }
            Some(Err(error)) => Err(Error::Io(error)),
            None => Err(Error::DeviceClosed),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let Some(write_tx) = self.write_tx.as_ref() else {
            return Err(Error::DeviceClosed);
        };
        let (response_tx, response_rx) = oneshot::channel();
        write_tx
            .send(BlockingWriteRequest {
                packet: buf.to_vec(),
                response: response_tx,
            })
            .await
            .map_err(|_| Error::DeviceClosed)?;
        response_rx
            .await
            .map_err(|_| Error::DeviceClosed)?
            .map_err(Error::Io)
    }
}

impl Drop for DedicatedBlockingTun {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Dropping the receiver/sender wakes a blocked channel operation so
        // both dedicated threads can observe STOP and exit. Their poll waits
        // are bounded by POLL_TIMEOUT_MS, so lifecycle teardown is bounded and
        // never leaves a reader/writer thread behind.
        self.read_rx.take();
        self.write_tx.take();
        if let Some(thread) = self.reader_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.writer_thread.take() {
            let _ = thread.join();
        }
    }
}

enum AndroidTunIo {
    Async(AsyncFd<OwnedFd>),
    Dedicated(DedicatedBlockingTun),
}

/// A raw-IP VPN interface supplied by the platform VPN service.
pub struct AndroidTun {
    io: AndroidTunIo,
    name: String,
    mtu: u32,
    /// This is the daemon's logical overlay address. It may differ from the
    /// provisional address used while the platform establishes the VPN before a
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
        Self::from_raw_fd_with_mode(fd, config, AndroidTunMode::AsyncFd)
    }

    /// Wrap a platform VPN fd using the selected read/write mode.
    pub fn from_raw_fd_with_mode(
        fd: i32,
        config: &InterfaceConfig,
        mode: AndroidTunMode,
    ) -> Result<Self> {
        if fd < 0 {
            return Err(Error::Platform(format!(
                "VPN service returned an invalid TUN fd: {fd}"
            )));
        }

        // Safety: the platform VPN service transfers ownership of this valid
        // fd to Rust exactly once.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::from_owned_fd_with_mode(owned_fd, config, mode)
    }

    /// Adopt an already-owned VPN descriptor without converting through a
    /// raw fd. Harmony's native bridge supplies a duplicate; the system-owned
    /// descriptor stays with `VpnConnection`.
    pub fn from_owned_fd(fd: OwnedFd, config: &InterfaceConfig) -> Result<Self> {
        Self::from_owned_fd_with_mode(fd, config, AndroidTunMode::AsyncFd)
    }

    /// Adopt a descriptor only when the platform has already marked it
    /// nonblocking. Harmony's fd contract is not device-verified, so this path
    /// fails closed instead of changing file-status flags on a `dup()` that
    /// shares the VPN descriptor's open-file description.
    pub fn from_owned_fd_if_nonblocking(
        owned_fd: OwnedFd,
        config: &InterfaceConfig,
    ) -> Result<Self> {
        let owned_fd = super::fd::validate_ohos_vpn_fd(owned_fd)?;
        let io = AndroidTunIo::Async(AsyncFd::new(owned_fd)?);
        Ok(Self {
            io,
            name: config.name.clone(),
            mtu: config.mtu,
            address: config.address.to_string(),
            is_up: true,
        })
    }

    /// Adopt an owned descriptor using the selected read/write mode.
    pub fn from_owned_fd_with_mode(
        owned_fd: OwnedFd,
        config: &InterfaceConfig,
        mode: AndroidTunMode,
    ) -> Result<Self> {
        let io = match mode {
            AndroidTunMode::AsyncFd => {
                let raw_fd = owned_fd.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
                    if flags < 0 {
                        return Err(Error::Io(io::Error::last_os_error()));
                    }
                    if libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                        return Err(Error::Io(io::Error::last_os_error()));
                    }
                    let verified = libc::fcntl(raw_fd, libc::F_GETFL, 0);
                    if verified < 0 {
                        return Err(Error::Io(io::Error::last_os_error()));
                    }
                    if verified & libc::O_NONBLOCK == 0 {
                        return Err(Error::Platform(
                            "VPN TUN fd did not retain nonblocking mode".to_string(),
                        ));
                    }
                }
                AndroidTunIo::Async(AsyncFd::new(owned_fd)?)
            }
            AndroidTunMode::DedicatedBlocking => {
                let raw_fd = owned_fd.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(raw_fd, libc::F_GETFL, 0);
                    if flags < 0 {
                        return Err(Error::Io(io::Error::last_os_error()));
                    }
                    if libc::fcntl(raw_fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) < 0 {
                        return Err(Error::Io(io::Error::last_os_error()));
                    }
                    let verified = libc::fcntl(raw_fd, libc::F_GETFL, 0);
                    if verified < 0 {
                        return Err(Error::Io(io::Error::last_os_error()));
                    }
                    if verified & libc::O_NONBLOCK != 0 {
                        return Err(Error::Platform(
                            "VPN TUN fd did not retain blocking mode".to_string(),
                        ));
                    }
                }
                AndroidTunIo::Dedicated(DedicatedBlockingTun::new(owned_fd)?)
            }
        };
        Ok(Self {
            io,
            name: config.name.clone(),
            mtu: config.mtu,
            address: config.address.to_string(),
            is_up: true,
        })
    }

    /// VPN interfaces are created by the platform service, not by
    /// opening `/dev/net/tun` from the daemon.
    pub fn create(_config: &InterfaceConfig) -> Result<Self> {
        Err(Error::Unsupported)
    }
}

#[async_trait]
impl VirtualInterface for AndroidTun {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if let AndroidTunIo::Dedicated(tun) = &mut self.io {
            return tun.read(buf).await;
        }
        loop {
            let AndroidTunIo::Async(fd) = &mut self.io else {
                unreachable!("dedicated VPN TUN mode returned above");
            };
            let mut guard = fd.readable().await?;
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
        if let AndroidTunIo::Dedicated(tun) = &mut self.io {
            return tun.write(buf).await;
        }
        loop {
            let AndroidTunIo::Async(fd) = &mut self.io else {
                unreachable!("dedicated VPN TUN mode returned above");
            };
            let mut guard = fd.writable().await?;
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
        tracing::info!("VPN TUN interface {} closed", self.name);
    }
}
