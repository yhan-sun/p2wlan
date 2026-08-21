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

type WintunOpenAdapterFunc =
    unsafe extern "C" fn(name: *const u16) -> *mut std::ffi::c_void;

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
    open_adapter: WintunOpenAdapterFunc,
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

        let open_adapter = unsafe {
            *lib.get::<WintunOpenAdapterFunc>(b"WintunOpenAdapter\0")
                .map_err(|_| Error::SymbolNotFound("WintunOpenAdapter".to_string()))?
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
            open_adapter,
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
