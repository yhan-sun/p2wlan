// --- Wintun device ---

/// Windows Wintun virtual network interface.
///
/// Uses a background thread for packet reading because Wintun's ring
/// buffer uses a Windows event (not IOCP), which doesn't integrate
/// directly with tokio's async I/O. The thread reads packets and sends
/// them through a tokio channel.
pub struct WintunDevice {
    /// The Wintun session handle (stored as usize for Send safety).
    session: WINTUN_SESSION_HANDLE,
    /// The Wintun adapter handle (stored as usize for Send safety).
    adapter: WINTUN_ADAPTER_HANDLE,
    /// Cached API for write operations.
    api: Arc<WintunApi>,
    /// Channel for receiving packets from the read thread.
    read_rx: mpsc::Receiver<Vec<u8>>,
    /// Shutdown flag for the read thread.
    shutdown: Arc<AtomicBool>,
    /// The read thread handle (joined on drop).
    read_thread: Option<thread::JoinHandle<()>>,
    /// Interface name.
    name: String,
    /// MTU value.
    mtu: u32,
    /// Assigned IPv4 address.
    address: String,
    /// Whether the device is still open.
    is_up: bool,
}

// Safety: WintunDevice is safe to send between threads because:
// - The session/adapter handles are used from a single async task for writes
// - The read thread accesses the session through function pointers (thread-safe)
// - The Wintun API uses internal synchronization
unsafe impl Send for WintunDevice {}

impl WintunDevice {
    /// Create a new Wintun interface with the given configuration.
    ///
    /// # Requirements
    ///
    /// - `wintun.dll` must be available (in the executable directory or PATH).
    /// - Must be run as Administrator.
    /// - The Wintun driver will be auto-installed by the DLL on first use.
    pub fn create(config: &InterfaceConfig) -> Result<Self> {
        info!("Creating Wintun interface: {}", config.name);

        // Load the Wintun API
        let api = Arc::new(WintunApi::load()?);

        // Log driver version (best-effort)
        if let Some(version) = WintunApi::try_get_driver_version() {
            info!("Wintun driver version: {version}");
        }

        // Convert interface name to wide string
        let name_wide = to_wide_string(&config.name);
        let tunnel_type = to_wide_string("P2PNet");

        // Create the adapter (no requested GUID, let Wintun generate one)
        let adapter_ptr = unsafe {
            (api.create_adapter)(name_wide.as_ptr(), tunnel_type.as_ptr(), std::ptr::null())
        };

        if adapter_ptr.is_null() {
            let err = io::Error::last_os_error();
            error!("WintunCreateAdapter failed: {err}");
            return Err(Error::WintunCreateFailed(
                err.raw_os_error().unwrap_or(0) as u32
            ));
        }

        info!("Wintun adapter created: {}", config.name);

        // Get the adapter LUID for IP configuration
        let mut luid: u64 = 0;
        unsafe { (api.get_adapter_luid)(adapter_ptr, &mut luid) };
        info!("Adapter LUID: 0x{luid:016x}");

        // Set the IP address using netsh
        set_interface_address(&config.name, config.address, config.netmask)?;

        // Set the MTU
        set_interface_mtu(&config.name, config.mtu).ok();

        // Start a session with a 4MB ring buffer (0x400000)
        let ring_capacity: u32 = 0x400_000;
        let session_ptr = unsafe { (api.start_session)(adapter_ptr, ring_capacity) };

        if session_ptr.is_null() {
            let err = io::Error::last_os_error();
            error!("WintunStartSession failed: {err}");
            unsafe { (api.close_adapter)(adapter_ptr) };
            return Err(Error::WintunSessionFailed(
                err.raw_os_error().unwrap_or(0) as u32
            ));
        }

        info!("Wintun session started (ring buffer: 4MB)");

        // Set up the read thread + channel
        let (read_tx, read_rx) = mpsc::channel(256);
        let shutdown = Arc::new(AtomicBool::new(false));

        let read_thread = spawn_read_thread(
            session_ptr as usize,
            api.receive_packet,
            api.release_receive_packet,
            api.get_read_wait_event,
            read_tx,
            shutdown.clone(),
        );

        Ok(Self {
            session: session_ptr as WINTUN_SESSION_HANDLE,
            adapter: adapter_ptr as WINTUN_ADAPTER_HANDLE,
            api,
            read_rx,
            shutdown,
            read_thread: Some(read_thread),
            name: config.name.clone(),
            mtu: config.mtu,
            address: config.address.to_string(),
            is_up: true,
        })
    }
}

#[async_trait]
impl VirtualInterface for WintunDevice {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.is_up {
            return Err(Error::DeviceClosed);
        }

        match self.read_rx.recv().await {
            Some(data) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            None => Err(Error::DeviceClosed),
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.is_up {
            return Err(Error::DeviceClosed);
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let packet_size = u32::try_from(buf.len()).map_err(|_| {
            Error::Platform(format!(
                "packet too large for Wintun send ring: {} bytes",
                buf.len()
            ))
        })?;

        // Wintun requires outbound packets to be allocated from its send ring
        // before submission. WintunSendPacket only accepts pointers returned by
        // WintunAllocateSendPacket; passing an arbitrary Rust slice pointer can
        // make inbound peer packets disappear before they reach the Windows IP
        // stack.
        let session_ptr = self.session as *mut std::ffi::c_void;
        let packet_ptr = unsafe { (self.api.allocate_send_packet)(session_ptr, packet_size) };

        if packet_ptr.is_null() {
            let err = io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(111) => Err(Error::SendBufferFull),
                Some(code) => Err(Error::Platform(format!(
                    "WintunAllocateSendPacket failed: error code {code}"
                ))),
                None => Err(Error::Platform(
                    "WintunAllocateSendPacket failed without OS error".to_string(),
                )),
            };
        }

        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), packet_ptr, buf.len());
            (self.api.send_packet)(session_ptr, packet_ptr);
        }

        Ok(buf.len())
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

impl Drop for WintunDevice {
    fn drop(&mut self) {
        self.is_up = false;

        // Signal the read thread to stop
        self.shutdown.store(true, Ordering::SeqCst);

        // End the session (this also signals the read wait event)
        let session_ptr = self.session as *mut std::ffi::c_void;
        if !session_ptr.is_null() {
            unsafe { (self.api.end_session)(session_ptr) };
        }

        // Wait for the read thread to finish
        if let Some(handle) = self.read_thread.take() {
            let _ = handle.join();
        }

        // Close the adapter
        let adapter_ptr = self.adapter as *mut std::ffi::c_void;
        if !adapter_ptr.is_null() {
            unsafe { (self.api.close_adapter)(adapter_ptr) };
        }

        info!("Wintun interface {} closed", self.name);
    }
}
