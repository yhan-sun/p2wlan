use super::clock::monotonic_ns;
use super::registry::CaptureSession;
use p2pnet_tun::{
    InterfaceConfig, PacketReadContext, PacketWriteContext, TunDevice, VirtualInterface,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

/// The constructor path, rather than an arbitrary VirtualInterface or raw fd,
/// certifies the device. Only Linux-created system devices currently mint
/// kernel observations. Android raw-fd attachment remains explicitly opaque.
pub(crate) struct SystemTun {
    inner: TunDevice,
    created_system_device: bool,
    capture: Option<Weak<CaptureSession>>,
    device: Option<Arc<DeviceLease>>,
    last_read: Option<PacketReadContext>,
    ordinal: u64,
    write_ordinal: u64,
}

pub(super) struct DeviceLease {
    live: AtomicBool,
}

/// No constructor or deserializer is visible outside this concrete read site.
/// It contains no strong keeper for the device or the descriptor scope.
pub(super) struct KernelRead {
    device: Weak<DeviceLease>,
    ordinal: u64,
    at: Instant,
    monotonic_ns: u64,
}

/// Constructed only after this concrete system backend returned a nonempty
/// complete write. An untrusted context or caller-supplied length cannot mint it.
pub(super) struct KernelWrite {
    device: Weak<DeviceLease>,
    ordinal: u64,
    at: Instant,
    monotonic_ns: u64,
}

impl KernelWrite {
    pub(super) fn same_device_as(&self, read: &KernelRead) -> bool {
        self.device.ptr_eq(&read.device)
    }

    pub(super) fn is_current(&self) -> bool {
        self.ordinal != 0
            && self.monotonic_ns != 0
            && self
                .device
                .upgrade()
                .is_some_and(|device| device.live.load(Ordering::Acquire))
    }
    pub(super) fn belongs_to(&self, device: &Weak<DeviceLease>) -> bool {
        self.device.ptr_eq(device)
    }
    pub(super) fn at(&self) -> Instant {
        self.at
    }
    #[cfg(unix)]
    pub(super) fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub(super) fn monotonic_ns(&self) -> u64 {
        self.monotonic_ns
    }
}

impl KernelRead {
    pub(super) fn is_current(&self) -> bool {
        self.ordinal != 0
            && self.monotonic_ns != 0
            && self
                .device
                .upgrade()
                .is_some_and(|device| device.live.load(Ordering::Acquire))
    }
    pub(super) fn same_device(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.device, &other.device)
    }
    pub(super) fn belongs_to(&self, device: &Weak<DeviceLease>) -> bool {
        self.device.ptr_eq(device)
    }
    #[cfg(unix)]
    pub(super) fn ordinal(&self) -> u64 {
        self.ordinal
    }
    pub(super) fn at(&self) -> Instant {
        self.at
    }
    pub(super) fn monotonic_ns(&self) -> u64 {
        self.monotonic_ns
    }
}

impl SystemTun {
    #[cfg(not(target_os = "android"))]
    pub(crate) fn create(config: &InterfaceConfig) -> p2pnet_tun::Result<Self> {
        // This exact factory completes the platform's real system creation.
        let inner = TunDevice::create(config)?;
        Ok(Self::wrap(inner, cfg!(target_os = "linux")))
    }

    #[cfg(target_os = "android")]
    pub(crate) fn from_raw_fd_with_mode(
        fd: std::os::fd::RawFd,
        config: &InterfaceConfig,
        mode: p2pnet_tun::AndroidTunMode,
    ) -> p2pnet_tun::Result<Self> {
        let inner = TunDevice::from_raw_fd_with_mode(fd, config, mode)?;
        Ok(Self::wrap(inner, false))
    }

    #[cfg(target_env = "ohos")]
    pub(crate) fn from_owned_fd(
        fd: std::os::fd::OwnedFd,
        config: &InterfaceConfig,
    ) -> p2pnet_tun::Result<Self> {
        let inner = TunDevice::from_owned_fd(fd, config)?;
        Ok(Self::wrap(inner, false))
    }

    fn wrap(inner: TunDevice, created_system_device: bool) -> Self {
        Self {
            inner,
            created_system_device,
            capture: None,
            device: None,
            last_read: None,
            ordinal: 0,
            write_ordinal: 0,
        }
    }

    pub(crate) fn with_capture(mut self, capture: Arc<CaptureSession>) -> Self {
        // A live concrete owner cannot be rebound to a new capture lease.
        // Retained weak read/write sources must never inherit another scope.
        if self.capture.is_some() || self.device.is_some() {
            capture.retire();
            return self;
        }
        if self.created_system_device {
            let device = Arc::new(DeviceLease {
                live: AtomicBool::new(true),
            });
            if capture.bind_system_device(&device) {
                self.device = Some(device);
                self.capture = Some(Arc::downgrade(&capture));
            } else {
                capture.retire();
            }
        }
        self
    }

    pub(crate) fn tracks_registered_reads(&self) -> bool {
        self.capture.is_some()
    }
}

impl Drop for SystemTun {
    fn drop(&mut self) {
        if let Some(device) = &self.device {
            device.live.store(false, Ordering::Release);
        }
    }
}

// The explicit async-trait-expanded signatures avoid a new dependency and
// retain the existing VirtualInterface cancellation/ownership contract.
impl VirtualInterface for SystemTun {
    fn read<'a, 'b, 'future>(
        &'a mut self,
        buf: &'b mut [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'future>>
    where
        'a: 'future,
        'b: 'future,
        Self: 'future,
    {
        // The default path directly returns the original platform future:
        // no second future allocation, clock query or registry lookup.
        self.last_read = None;
        if self
            .capture
            .as_ref()
            .is_none_or(|scope| scope.strong_count() == 0)
        {
            self.capture = None;
            self.device = None;
            return self.inner.read(buf);
        }
        Box::pin(async move {
            let n = self.inner.read(buf).await?;
            if n != 0 {
                if let (Some(capture), Some(device)) =
                    (self.capture.as_ref().and_then(Weak::upgrade), &self.device)
                {
                    let Some(clock) = monotonic_ns() else {
                        capture.retire();
                        return Ok(n);
                    };
                    if let (Some(ordinal), Some(packet)) =
                        (self.ordinal.checked_add(1), buf.get(..n))
                    {
                        self.ordinal = ordinal;
                        let original = KernelRead {
                            device: Arc::downgrade(device),
                            ordinal,
                            at: Instant::now(),
                            monotonic_ns: clock,
                        };
                        self.last_read = capture
                            .observe_system_read(original, packet)
                            .map(|binding| Box::new(binding) as PacketReadContext);
                    } else {
                        capture.retire();
                    }
                }
            }
            Ok(n)
        })
    }

    fn write<'a, 'b, 'future>(
        &'a mut self,
        buf: &'b [u8],
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'future>>
    where
        'a: 'future,
        'b: 'future,
        Self: 'future,
    {
        self.inner.write(buf)
    }
    fn write_with_context<'a, 'b, 'future>(
        &'a mut self,
        buf: &'b [u8],
        context: PacketWriteContext,
    ) -> Pin<Box<dyn Future<Output = p2pnet_tun::Result<usize>> + Send + 'future>>
    where
        'a: 'future,
        'b: 'future,
        Self: 'future,
    {
        let binding = match context.downcast::<Arc<super::KernelIngressBinding>>() {
            Ok(binding) if self.created_system_device && self.capture.is_some() => *binding,
            _ => return self.inner.write(buf),
        };
        Box::pin(async move {
            let n = self.inner.write(buf).await?;
            if n != 0 && n == buf.len() {
                if let (Some(capture), Some(device)) =
                    (self.capture.as_ref().and_then(Weak::upgrade), &self.device)
                {
                    let (Some(ordinal), Some(clock)) =
                        (self.write_ordinal.checked_add(1), monotonic_ns())
                    else {
                        capture.retire();
                        return Ok(n);
                    };
                    self.write_ordinal = ordinal;
                    let original = KernelWrite {
                        device: Arc::downgrade(device),
                        ordinal,
                        at: Instant::now(),
                        monotonic_ns: clock,
                    };
                    capture.observe_system_write(original, binding, buf);
                }
            }
            Ok(n)
        })
    }
    fn take_last_read_context(&mut self) -> Option<PacketReadContext> {
        self.last_read.take()
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
