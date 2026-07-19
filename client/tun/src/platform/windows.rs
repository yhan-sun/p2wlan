//! Windows Wintun device implementation.
//!
//! Uses the Wintun driver (https://www.wintun.net/) to create a virtual
//! network interface on Windows. The `wintun.dll` must be present either
//! in the same directory as the executable or in the system PATH.
//!
//! ## How it works
//!
//! 1. Dynamically loads `wintun.dll` at runtime.
//! 2. Creates a Wintun adapter with the configured name.
//! 3. Starts a session with a ring buffer.
//! 4. A background thread reads packets from the ring buffer and sends
//!    them through a tokio channel for async consumption.
//! 5. Writes allocate a Wintun send packet, copy the IP packet into it, and
//!    submit it to the ring buffer (non-blocking).
//!
//! ## IP Address Configuration
//!
//! Wintun does not set the IP address automatically. After creating the
//! adapter, we use `netsh` to assign the IPv4 address, netmask, and MTU.

use std::ffi::OsStr;
use std::io;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use async_trait::async_trait;
use libloading::{Library, Symbol};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

use crate::config::InterfaceConfig;
use crate::error::{Error, Result};
use crate::interface::VirtualInterface;

// --- Wintun FFI types ---

/// Opaque handle to a Wintun adapter (raw pointer as usize for Send).
#[allow(non_camel_case_types)]
type WINTUN_ADAPTER_HANDLE = usize;

/// Opaque handle to a Wintun session (raw pointer as usize for Send).
#[allow(non_camel_case_types)]
type WINTUN_SESSION_HANDLE = usize;

/// GUID structure for adapter identification.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// --- Wintun function pointer types ---

type WintunCreateAdapterFunc = unsafe extern "C" fn(
    name: *const u16,
    tunnel_type: *const u16,
    requested_guid: *const Guid,
) -> *mut std::ffi::c_void;

type WintunCloseAdapterFunc = unsafe extern "C" fn(adapter: *mut std::ffi::c_void);

type WintunStartSessionFunc =
    unsafe extern "C" fn(adapter: *mut std::ffi::c_void, capacity: u32) -> *mut std::ffi::c_void;

type WintunEndSessionFunc = unsafe extern "C" fn(session: *mut std::ffi::c_void);

type WintunGetReadWaitEventFunc =
    unsafe extern "C" fn(session: *mut std::ffi::c_void) -> *mut std::ffi::c_void;

type WintunReceivePacketFunc =
    unsafe extern "C" fn(session: *mut std::ffi::c_void, packet_size: *mut u32) -> *mut u8;

type WintunReleaseReceivePacketFunc =
    unsafe extern "C" fn(session: *mut std::ffi::c_void, packet: *const u8);

type WintunAllocateSendPacketFunc =
    unsafe extern "C" fn(session: *mut std::ffi::c_void, packet_size: u32) -> *mut u8;

type WintunSendPacketFunc = unsafe extern "C" fn(session: *mut std::ffi::c_void, packet: *const u8);

type WintunGetAdapterLuidFunc =
    unsafe extern "C" fn(adapter: *mut std::ffi::c_void, luid: *mut u64);

type WintunGetRunningDriverVersionFunc = unsafe extern "C" fn() -> u32;

// --- Wintun API wrapper ---

/// Holds dynamically-loaded Wintun function pointers.
///
/// The `Library` is kept alive for the lifetime of the API wrapper,
/// ensuring the function pointers remain valid.
struct WintunApi {
    _lib: Library,
    create_adapter: WintunCreateAdapterFunc,
    close_adapter: WintunCloseAdapterFunc,
    start_session: WintunStartSessionFunc,
    end_session: WintunEndSessionFunc,
    get_read_wait_event: WintunGetReadWaitEventFunc,
    receive_packet: WintunReceivePacketFunc,
    release_receive_packet: WintunReleaseReceivePacketFunc,
    allocate_send_packet: WintunAllocateSendPacketFunc,
    send_packet: WintunSendPacketFunc,
    get_adapter_luid: WintunGetAdapterLuidFunc,
}

impl WintunApi {
    fn dll_candidates() -> Vec<PathBuf> {
        let mut candidates = Vec::new();
        if let Ok(path) = std::env::var("P2WLAN_WINTUN_DLL") {
            if !path.trim().is_empty() {
                candidates.push(PathBuf::from(path));
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("wintun.dll"));
            }
        }
        if let Ok(dir) = std::env::current_dir() {
            candidates.push(dir.join("wintun.dll"));
        }
        candidates.push(PathBuf::from("wintun.dll"));
        candidates
    }

    fn load_library() -> Result<Library> {
        let mut errors = Vec::new();
        for candidate in Self::dll_candidates() {
            match unsafe { Library::new(&candidate) } {
                Ok(lib) => {
                    info!("Loaded Wintun runtime from {}", candidate.display());
                    return Ok(lib);
                }
                Err(err) => {
                    errors.push(format!("{}: {err}", candidate.display()));
                }
            }
        }
        Err(Error::LibraryNotFound(format!(
            "wintun.dll not found or not loadable. Tried: {}",
            errors.join("; ")
        )))
    }

    /// Load the Wintun DLL and resolve all required function pointers.
    fn load() -> Result<Self> {
        let lib = Self::load_library()?;

        let create_adapter = unsafe {
            *lib.get::<WintunCreateAdapterFunc>(b"WintunCreateAdapter\0")
                .map_err(|_| Error::SymbolNotFound("WintunCreateAdapter".to_string()))?
        };

        let close_adapter = unsafe {
            *lib.get::<WintunCloseAdapterFunc>(b"WintunCloseAdapter\0")
                .map_err(|_| Error::SymbolNotFound("WintunCloseAdapter".to_string()))?
        };

        let start_session = unsafe {
            *lib.get::<WintunStartSessionFunc>(b"WintunStartSession\0")
                .map_err(|_| Error::SymbolNotFound("WintunStartSession".to_string()))?
        };

        let end_session = unsafe {
            *lib.get::<WintunEndSessionFunc>(b"WintunEndSession\0")
                .map_err(|_| Error::SymbolNotFound("WintunEndSession".to_string()))?
        };

        let get_read_wait_event = unsafe {
            *lib.get::<WintunGetReadWaitEventFunc>(b"WintunGetReadWaitEvent\0")
                .map_err(|_| Error::SymbolNotFound("WintunGetReadWaitEvent".to_string()))?
        };

        let receive_packet = unsafe {
            *lib.get::<WintunReceivePacketFunc>(b"WintunReceivePacket\0")
                .map_err(|_| Error::SymbolNotFound("WintunReceivePacket".to_string()))?
        };

        let release_receive_packet = unsafe {
            *lib.get::<WintunReleaseReceivePacketFunc>(b"WintunReleaseReceivePacket\0")
                .map_err(|_| Error::SymbolNotFound("WintunReleaseReceivePacket".to_string()))?
        };

        let allocate_send_packet = unsafe {
            *lib.get::<WintunAllocateSendPacketFunc>(b"WintunAllocateSendPacket\0")
                .map_err(|_| Error::SymbolNotFound("WintunAllocateSendPacket".to_string()))?
        };

        let send_packet = unsafe {
            *lib.get::<WintunSendPacketFunc>(b"WintunSendPacket\0")
                .map_err(|_| Error::SymbolNotFound("WintunSendPacket".to_string()))?
        };

        let get_adapter_luid = unsafe {
            *lib.get::<WintunGetAdapterLuidFunc>(b"WintunGetAdapterLUID\0")
                .map_err(|_| Error::SymbolNotFound("WintunGetAdapterLUID".to_string()))?
        };

        Ok(Self {
            _lib: lib,
            create_adapter,
            close_adapter,
            start_session,
            end_session,
            get_read_wait_event,
            receive_packet,
            release_receive_packet,
            allocate_send_packet,
            send_packet,
            get_adapter_luid,
        })
    }

    /// Try to get the running driver version (best-effort, non-fatal).
    fn try_get_driver_version() -> Option<u32> {
        let lib = Self::load_library().ok()?;
        let func: Symbol<WintunGetRunningDriverVersionFunc> =
            unsafe { lib.get(b"WintunGetRunningDriverVersion\0") }.ok()?;
        Some(unsafe { func() })
    }
}

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

// --- Helper functions ---

/// Convert a Rust string to a null-terminated UTF-16 wide string.
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Spawn a background thread that reads packets from the Wintun ring buffer
/// and sends them through a tokio channel.
///
/// The session handle is passed as `usize` to satisfy `Send` requirements.
fn spawn_read_thread(
    session_usize: usize,
    receive_packet: WintunReceivePacketFunc,
    release_receive_packet: WintunReleaseReceivePacketFunc,
    get_read_wait_event: WintunGetReadWaitEventFunc,
    tx: mpsc::Sender<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Convert usize back to raw pointer
        let session = session_usize as *mut std::ffi::c_void;
        // Get the read wait event handle
        let read_event = unsafe { get_read_wait_event(session) };

        if read_event.is_null() {
            error!("WintunGetReadWaitEvent returned null");
            return;
        }

        info!("Wintun read thread started");

        loop {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            // Try to receive a packet from the ring buffer
            let mut packet_size: u32 = 0;
            let packet_ptr = unsafe { receive_packet(session, &mut packet_size) };

            if !packet_ptr.is_null() {
                // We got a packet - copy it and release the ring buffer slot
                let packet_data =
                    unsafe { std::slice::from_raw_parts(packet_ptr, packet_size as usize) };
                let data = packet_data.to_vec();

                // Release the packet back to the ring buffer
                unsafe { release_receive_packet(session, packet_ptr) };

                // Send through the channel (blocking_send works from a std thread)
                if tx.blocking_send(data).is_err() {
                    // Channel closed, exit
                    break;
                }
            } else {
                // No packet available - wait for the read event
                // Use a short timeout so we can check the shutdown flag periodically
                unsafe {
                    WaitForSingleObject(read_event, 100); // 100ms timeout
                }
            }
        }

        info!("Wintun read thread stopped");
    })
}

fn hidden_command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// Set the IPv4 address and netmask on an interface using netsh.
fn set_interface_address(name: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    let prefix_len = u32::from(netmask).count_ones();
    let cidr = format!("{addr}/{prefix_len}");

    info!("Setting interface {name} address: {cidr}");

    let output = hidden_command("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "address",
            name,
            "static",
            &addr.to_string(),
            &netmask.to_string(),
        ])
        .output()
        .map_err(|e| Error::Platform(format!("failed to run netsh: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        warn!("netsh address set failed: {stderr}{stdout}");
        // Don't fail hard - the interface might still work with manual config
    } else {
        info!("IP address set: {addr}/{netmask}");
    }

    Ok(())
}

/// Set the MTU on an interface using netsh.
fn set_interface_mtu(name: &str, mtu: u32) -> Result<()> {
    info!("Setting MTU for {name}: {mtu}");

    let output = hidden_command("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            name,
            "mtu",
            &mtu.to_string(),
            "store=persistent",
        ])
        .output()
        .map_err(|e| Error::Platform(format!("failed to run netsh: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("netsh MTU set failed: {stderr}");
    }

    Ok(())
}
