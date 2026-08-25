//! Android TUN device backed by an fd established by `VpnService.Builder`.
//!
//! Android does not allow an application to create a kernel TUN interface in
//! the same way as Linux. The Java/Kotlin `VpnService` owns route/address
//! setup and passes the non-blocking fd returned by `establish()` to Rust.
//! The fd carries raw IP packets because the builder is configured without
//! packet-information or Ethernet headers.

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

/// Selects the Android VPN TUN read implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AndroidTunMode {
    /// The default implementation: Tokio waits for readiness on a nonblocking
    /// fd and performs the read/write in the daemon task.
    #[default]
    AsyncFd,
    /// The experiment implementation: Android supplies a blocking fd and a
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
                "unsupported Android TUN mode {other:?}; expected async_fd or dedicated_blocking"
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
            .name("p2wlan-android-tun-reader".to_string())
            .spawn(move || Self::reader_loop(reader_fd, read_tx, reader_stop))
        {
            Ok(thread) => thread,
            Err(error) => return Err(Error::Io(error)),
        };

        let writer_stop = Arc::clone(&stop);
        let writer_thread = match thread::Builder::new()
            .name("p2wlan-android-tun-writer".to_string())
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
                        "Android VPN TUN fd was closed",
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
                    "Android VPN TUN returned EOF",
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
                    "Android VPN TUN writer stopped",
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
                    "Android VPN TUN writer stopped",
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
                        "Android VPN TUN packet exceeds read buffer",
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

/// A raw-IP Android VPN interface supplied by `VpnService`.
pub struct AndroidTun {
    io: AndroidTunIo,
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
        Self::from_raw_fd_with_mode(fd, config, AndroidTunMode::AsyncFd)
    }

    /// Wrap an Android VPN fd using the selected read/write experiment mode.
    pub fn from_raw_fd_with_mode(
        fd: i32,
        config: &InterfaceConfig,
        mode: AndroidTunMode,
    ) -> Result<Self> {
        if fd < 0 {
            return Err(Error::Platform(format!(
                "Android VPN returned an invalid TUN fd: {fd}"
            )));
        }

        // Safety: the Android VPN service transfers ownership of this valid fd
        // to Rust exactly once via detachFd().
        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
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

    /// Android VPN interfaces are created by the platform service, not by
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
                unreachable!("dedicated Android TUN mode returned above");
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
                unreachable!("dedicated Android TUN mode returned above");
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
        tracing::info!("Android VPN TUN interface {} closed", self.name);
    }
}
