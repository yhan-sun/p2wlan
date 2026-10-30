use crate::shutdown::ShutdownGate;
use crate::snapshot::{
    EngineKey, EngineSettingsV1, P2wlanVpnNetworkRequestV1, P2wlanVpnStartRequestV1,
    StartRequestV1, VpnNetworkRequestV1,
};
use crate::{
    STATUS_ALREADY_RUNNING, STATUS_BAD_ARGUMENT, STATUS_CONFIG_INVALID, STATUS_DAEMON_START_FAILED,
    STATUS_ENGINE_BUSY, STATUS_ENGINE_HISTORY_FULL, STATUS_IDENTITY_STORE_FAILED,
    STATUS_INVALID_REQUEST, STATUS_NETWORK_PREFLIGHT_FAILED, STATUS_ROUTE_PROOF_INVALID,
    STATUS_STALE_GENERATION, STATUS_START_CANCELLED, STATUS_START_TIMEOUT, STATUS_STOPPED,
    STATUS_TUN_FD_DUP_FAILED, STATUS_TUN_FD_INVALID_MODE, STATUS_TUN_FD_NOT_NONBLOCKING,
    STATUS_UNKNOWN_IDENTITY,
};
use p2pnet_crypto::{Ed25519KeyPair, NodeIdentity};
use p2pnet_daemon::{
    config::{Config, NodeConfig},
    route::{OhosVpnIdentity, OhosVpnRouteConfirmation},
    Daemon, DaemonError,
};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const START_READY_TIMEOUT: Duration = Duration::from_secs(5);
const IDENTITY_FILE_MAX_BYTES: u64 = 156;
const RUNTIME_CONFIG_FILE_MAX_BYTES: u64 = 1024 * 1024;
const IDENTITY_HISTORY_LIMIT: usize = 16;
const MAX_TRACKED_INSTANCE_IDS: usize = 1024;

#[repr(C)]
pub struct P2wlanPreparedVpnEngineV1 {
    request: Option<StartRequestV1>,
    fd: Option<OwnedFd>,
    session: Arc<EngineSession>,
    activated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EngineState {
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed(i32),
}

impl EngineState {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed(_))
    }
}

struct EngineSession {
    key: EngineKey,
    state: Mutex<EngineState>,
    changed: Condvar,
    shutdown_gate: ShutdownGate,
    launch_complete: AtomicBool,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl EngineSession {
    fn new(key: EngineKey) -> Self {
        Self {
            key,
            state: Mutex::new(EngineState::Starting),
            changed: Condvar::new(),
            shutdown_gate: ShutdownGate::new(),
            launch_complete: AtomicBool::new(false),
            worker: Mutex::new(None),
        }
    }

    fn state(&self) -> EngineState {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn is_drained(&self) -> bool {
        self.state().is_terminal()
            && self.launch_complete.load(Ordering::Acquire)
            && self
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_none_or(JoinHandle::is_finished)
    }

    fn mark_ready(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *state == EngineState::Starting {
            *state = if self.shutdown_gate.is_requested() {
                EngineState::Stopping
            } else {
                EngineState::Ready
            };
            self.changed.notify_all();
        }
    }

    fn install_shutdown(&self, shutdown: tokio::sync::watch::Sender<bool>) {
        self.shutdown_gate.install(Arc::new(move || {
            let _ = shutdown.send(true);
        }));
    }

    fn install_worker(&self, worker: JoinHandle<()>) {
        *self
            .worker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(worker);
        self.launch_complete.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    fn launch_failed(&self, code: i32) {
        self.finish(code);
        self.launch_complete.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    fn finish(&self, failure_code: i32) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *state = if self.shutdown_gate.is_requested() {
            EngineState::Stopped
        } else {
            EngineState::Failed(failure_code)
        };
        self.changed.notify_all();
    }

    fn request_stop(&self) {
        self.shutdown_gate.request();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !state.is_terminal() {
                *state = EngineState::Stopping;
            }
            self.changed.notify_all();
        }
    }

    fn wait_for_ready(&self) -> i32 {
        let deadline = Instant::now() + START_READY_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            match *state {
                EngineState::Ready => return crate::STATUS_OK,
                EngineState::Failed(code) => return code,
                EngineState::Stopped | EngineState::Stopping => return STATUS_START_CANCELLED,
                EngineState::Starting => {}
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                drop(state);
                self.request_stop();
                return STATUS_START_TIMEOUT;
            };
            let (next, timeout) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && *state == EngineState::Starting {
                drop(state);
                self.request_stop();
                return STATUS_START_TIMEOUT;
            }
        }
    }

    fn wait_for_stop(&self, timeout: Option<Duration>) -> bool {
        let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let terminal = state.is_terminal();
            let launch_complete = self.launch_complete.load(Ordering::Acquire);
            let worker_finished = self
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_none_or(JoinHandle::is_finished);
            if terminal && launch_complete && worker_finished {
                drop(state);
                if let Some(worker) = self
                    .worker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    let _ = worker.join();
                }
                return true;
            }

            let wait_for = deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(30));
            if wait_for.is_zero() {
                return false;
            }
            let (next, result) = self
                .changed
                .wait_timeout(state, wait_for)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if result.timed_out() && deadline.is_some() {
                let terminal_now = state.is_terminal();
                let launched_now = self.launch_complete.load(Ordering::Acquire);
                let finished_now = self
                    .worker
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .is_none_or(JoinHandle::is_finished);
                if !(terminal_now && launched_now && finished_now) {
                    return false;
                }
            }
        }
    }
}

#[derive(Default)]
struct EngineRegistry {
    current: Option<Arc<EngineSession>>,
    retired: VecDeque<Arc<EngineSession>>,
    high_generation: HashMap<String, u64>,
}

fn registry() -> &'static Mutex<EngineRegistry> {
    static REGISTRY: OnceLock<Mutex<EngineRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(EngineRegistry::default()))
}

fn reserve_session(key: EngineKey) -> Result<Arc<EngineSession>, i32> {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(current) = registry.current.as_ref() {
        if !current.is_drained() {
            return Err(if current.key == key {
                STATUS_ALREADY_RUNNING
            } else {
                STATUS_ENGINE_BUSY
            });
        }
    }
    if !registry.high_generation.contains_key(&key.instance_id)
        && registry.high_generation.len() >= MAX_TRACKED_INSTANCE_IDS
    {
        return Err(STATUS_ENGINE_HISTORY_FULL);
    }
    let high = registry
        .high_generation
        .get(&key.instance_id)
        .copied()
        .unwrap_or(0);
    if key.generation <= high {
        return Err(STATUS_STALE_GENERATION);
    }
    if let Some(current) = registry.current.take() {
        registry.retired.push_back(current);
    }
    registry
        .high_generation
        .insert(key.instance_id.clone(), key.generation);
    let session = Arc::new(EngineSession::new(key));
    registry.current = Some(session.clone());
    while registry.retired.len() > IDENTITY_HISTORY_LIMIT {
        registry.retired.pop_front();
    }
    Ok(session)
}

fn remove_reserved(session: &Arc<EngineSession>) {
    let mut registry = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if registry
        .current
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, session))
    {
        registry.current = None;
        registry.high_generation.remove(&session.key.instance_id);
    }
}

fn find_session(key: &EngineKey) -> Result<Arc<EngineSession>, i32> {
    let registry = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(current) = registry
        .current
        .as_ref()
        .filter(|session| &session.key == key)
    {
        return Ok(current.clone());
    }
    registry
        .retired
        .iter()
        .find(|session| &session.key == key)
        .cloned()
        .ok_or(STATUS_UNKNOWN_IDENTITY)
}

impl Drop for P2wlanPreparedVpnEngineV1 {
    fn drop(&mut self) {
        if !self.activated {
            self.session.launch_failed(STATUS_START_CANCELLED);
            remove_reserved(&self.session);
        }
    }
}

/// Duplicate and validate the VpnConnection fd synchronously before the N-API
/// callback returns. The borrowed request strings are copied before ownership
/// of the prepared handle transfers to the caller.
///
/// # Safety
/// `request` and all nested string/list pointers must remain readable for this
/// call. `output` must point to writable storage for one opaque handle.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_prepare_vpn_engine_v1(
    request: *const P2wlanVpnStartRequestV1,
    output: *mut *mut P2wlanPreparedVpnEngineV1,
) -> i32 {
    if output.is_null() || request.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    // SAFETY: `output` was validated non-null and is writable by caller contract.
    unsafe { output.write(std::ptr::null_mut()) };
    // SAFETY: the public function requires all request views to remain valid
    // until this synchronous copy completes.
    let request = match unsafe { StartRequestV1::copy_from_ffi(request) } {
        Ok(request) => request,
        Err(_) => return STATUS_INVALID_REQUEST,
    };

    // `dup()` happens on the JS entry thread, before an async worker is queued.
    let duplicated = unsafe { libc::dup(request.fd) };
    if duplicated < 0 {
        return STATUS_TUN_FD_DUP_FAILED;
    }
    // SAFETY: dup returned a new descriptor owned exclusively by this value.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(duplicated) };
    let descriptor_flags = unsafe { libc::fcntl(duplicated, libc::F_GETFD) };
    let file_flags = unsafe { libc::fcntl(duplicated, libc::F_GETFL) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                duplicated,
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        drop(owned_fd);
        return STATUS_TUN_FD_DUP_FAILED;
    }
    if file_flags < 0 || file_flags & libc::O_NONBLOCK == 0 {
        drop(owned_fd);
        return STATUS_TUN_FD_NOT_NONBLOCKING;
    }
    if file_flags & libc::O_ACCMODE != libc::O_RDWR {
        drop(owned_fd);
        return STATUS_TUN_FD_INVALID_MODE;
    }

    let key = request.identity.key();
    let session = match reserve_session(key) {
        Ok(session) => session,
        Err(code) => return code,
    };
    let prepared = Box::new(P2wlanPreparedVpnEngineV1 {
        request: Some(request),
        fd: Some(owned_fd),
        session,
        activated: false,
    });
    // SAFETY: `output` was validated non-null above and is writable by caller contract.
    unsafe { output.write(Box::into_raw(prepared)) };
    crate::STATUS_OK
}

/// Starts the real OHOS daemon and waits for its one-shot TUN/core readiness.
/// This function blocks and is intended to run on an N-API async-work thread.
///
/// # Safety
/// `prepared` must be a non-null handle returned by `prepare_vpn_engine_v1`
/// that has not previously been activated or aborted.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_activate_vpn_engine_v1(
    prepared: *mut P2wlanPreparedVpnEngineV1,
) -> i32 {
    if prepared.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    // SAFETY: the API contract transfers this unique boxed handle exactly once.
    let mut prepared = unsafe { Box::from_raw(prepared) };
    prepared.activated = true;
    let request = match prepared.request.take() {
        Some(request) => request,
        None => {
            prepared.session.launch_failed(STATUS_BAD_ARGUMENT);
            return STATUS_BAD_ARGUMENT;
        }
    };
    let fd = match prepared.fd.take() {
        Some(fd) => fd,
        None => {
            prepared.session.launch_failed(STATUS_BAD_ARGUMENT);
            return STATUS_BAD_ARGUMENT;
        }
    };
    let session = prepared.session.clone();
    let worker_session = session.clone();
    let worker = thread::Builder::new()
        .name("p2wlan-harmony-daemon".to_string())
        .spawn(move || {
            let failure = run_engine(request, fd, worker_session.clone());
            worker_session.finish(failure);
        });
    match worker {
        Ok(worker) => session.install_worker(worker),
        Err(_) => session.launch_failed(STATUS_DAEMON_START_FAILED),
    }
    session.wait_for_ready()
}

/// Cancel a prepared handle when N-API could not queue its async worker.
///
/// # Safety
/// `prepared` must be a non-null handle returned by `prepare_vpn_engine_v1`
/// that has not previously been activated or aborted.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_abort_vpn_engine_v1(
    prepared: *mut P2wlanPreparedVpnEngineV1,
) {
    if !prepared.is_null() {
        // SAFETY: the API contract transfers this unique boxed handle exactly once.
        drop(unsafe { Box::from_raw(prepared) });
    }
}

/// Request a graceful stop and wait without a deadline. It returns only once
/// the daemon thread has exited and dropped its owned duplicate of the TUN fd.
///
/// # Safety
/// `instance_id` must point to `instance_id_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_stop_vpn_engine_v1(
    instance_id: *const u8,
    instance_id_len: usize,
    generation: u64,
) -> i32 {
    // SAFETY: pointer validity is forwarded to `stop_engine`'s checked contract.
    unsafe { stop_engine(instance_id, instance_id_len, generation, None) }
}

/// Bounded variant for extension destruction. A timeout leaves the owner in
/// the registry, still holding the fd, so a later stop can finish draining.
///
/// # Safety
/// `instance_id` must point to `instance_id_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_stop_vpn_engine_bounded_v1(
    instance_id: *const u8,
    instance_id_len: usize,
    generation: u64,
    timeout_ms: u32,
) -> i32 {
    // SAFETY: pointer validity is forwarded to `stop_engine`'s checked contract.
    unsafe {
        stop_engine(
            instance_id,
            instance_id_len,
            generation,
            Some(Duration::from_millis(u64::from(timeout_ms))),
        )
    }
}

unsafe fn stop_engine(
    instance_id: *const u8,
    instance_id_len: usize,
    generation: u64,
    timeout: Option<Duration>,
) -> i32 {
    if instance_id.is_null() || instance_id_len == 0 || instance_id_len > 128 || generation == 0 {
        return STATUS_BAD_ARGUMENT;
    }
    // SAFETY: forwarded from the public C function's documented pointer contract.
    let bytes = unsafe { std::slice::from_raw_parts(instance_id, instance_id_len) };
    let Ok(instance_id) = std::str::from_utf8(bytes) else {
        return STATUS_BAD_ARGUMENT;
    };
    if instance_id.trim().is_empty() || instance_id.as_bytes().contains(&0) {
        return STATUS_BAD_ARGUMENT;
    }
    let key = EngineKey {
        instance_id: instance_id.to_string(),
        generation,
    };
    let session = match find_session(&key) {
        Ok(session) => session,
        Err(code) => return code,
    };
    session.request_stop();
    if session.wait_for_stop(timeout) {
        STATUS_STOPPED
    } else {
        crate::STATUS_DRAINING
    }
}

/// A compact status query for the exact identity/generation. No config,
/// credential, path, or daemon diagnostic text crosses this API.
///
/// # Safety
/// `instance_id` must point to `instance_id_len` readable bytes and `output`
/// must point to writable storage for one status code.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_get_vpn_engine_status_v1(
    instance_id: *const u8,
    instance_id_len: usize,
    generation: u64,
    output: *mut i32,
) -> i32 {
    if output.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    if instance_id.is_null() || instance_id_len == 0 || instance_id_len > 128 || generation == 0 {
        return STATUS_BAD_ARGUMENT;
    }
    // SAFETY: forwarded from this function's documented pointer contract.
    let bytes = unsafe { std::slice::from_raw_parts(instance_id, instance_id_len) };
    let Ok(instance_id) = std::str::from_utf8(bytes) else {
        return STATUS_BAD_ARGUMENT;
    };
    let key = EngineKey {
        instance_id: instance_id.to_string(),
        generation,
    };
    let session = match find_session(&key) {
        Ok(session) => session,
        Err(code) => return code,
    };
    let status = match session.state() {
        EngineState::Starting => crate::STATUS_ENGINE_STARTING,
        EngineState::Ready => crate::STATUS_ENGINE_READY,
        EngineState::Stopping => crate::STATUS_ENGINE_STOPPING,
        EngineState::Stopped => crate::STATUS_ENGINE_STOPPED,
        EngineState::Failed(code) => crate::STATUS_ENGINE_FAILED_BASE.saturating_add(code),
    };
    // SAFETY: `output` was validated non-null and is writable by caller contract.
    unsafe { output.write(status) };
    crate::STATUS_OK
}

/// Resolve and reserve the exact VPN network tuple before creating the
/// platform TUN. The authenticated control request stays inside Rust; only
/// the assigned IPv4 address and CIDR are returned to ArkTS.
///
/// # Safety
/// `request` and its nested views must be readable for this call. Both output
/// buffers must be writable for their declared capacities.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_prepare_vpn_network_v1(
    request: *const P2wlanVpnNetworkRequestV1,
    virtual_ip_output: *mut u8,
    virtual_ip_capacity: usize,
    cidr_output: *mut u8,
    cidr_capacity: usize,
) -> i32 {
    if request.is_null()
        || virtual_ip_output.is_null()
        || cidr_output.is_null()
        || virtual_ip_capacity == 0
        || cidr_capacity == 0
    {
        return STATUS_BAD_ARGUMENT;
    }
    // SAFETY: the public function forwards its pointer contract.
    let request = match unsafe { VpnNetworkRequestV1::copy_from_ffi(request) } {
        Ok(request) => request,
        Err(_) => return STATUS_INVALID_REQUEST,
    };
    match prepare_vpn_network(request) {
        Ok((virtual_ip, cidr)) => {
            if !unsafe { write_ffi_string(virtual_ip_output, virtual_ip_capacity, &virtual_ip) }
                || !unsafe { write_ffi_string(cidr_output, cidr_capacity, &cidr) }
            {
                return STATUS_BAD_ARGUMENT;
            }
            crate::STATUS_OK
        }
        Err(code) => code,
    }
}

/// Discard the incarnation reservation when platform authorization or TUN
/// creation fails before the native daemon consumes it.
///
/// # Safety
/// `identity_store_path` must point to `path_len` readable UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn p2wlan_harmony_discard_vpn_network_v1(
    identity_store_path: *const u8,
    path_len: usize,
) -> i32 {
    if identity_store_path.is_null() || path_len == 0 || path_len > 4096 {
        return STATUS_BAD_ARGUMENT;
    }
    // SAFETY: pointer validity is required by this function's public contract.
    let bytes = unsafe { std::slice::from_raw_parts(identity_store_path, path_len) };
    let Ok(path) = std::str::from_utf8(bytes) else {
        return STATUS_BAD_ARGUMENT;
    };
    if Path::new(path).file_name().and_then(|name| name.to_str())
        != Some("vpn-engine-identity-v1.bin")
    {
        return STATUS_BAD_ARGUMENT;
    }
    let runtime_config_path =
        PathBuf::from(path).with_file_name("vpn-engine-runtime-config-v1.json");
    p2pnet_daemon::incarnation::discard_prepared_boot_incarnation_at(&runtime_config_path);
    crate::STATUS_OK
}

unsafe fn write_ffi_string(output: *mut u8, capacity: usize, value: &str) -> bool {
    if value.len().saturating_add(1) > capacity {
        return false;
    }
    // SAFETY: the caller provides a writable output buffer with `capacity` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(value.as_ptr(), output, value.len());
        output.add(value.len()).write(0);
    }
    true
}

fn prepare_vpn_network(request: VpnNetworkRequestV1) -> Result<(String, String), i32> {
    let settings = request.settings_snapshot.settings;
    let identity_path = PathBuf::from(&request.identity_store_path);
    let identity = load_or_update_identity(
        &identity_path,
        &settings,
        request.settings_snapshot.revision,
    )?;
    let runtime_config_path = identity_path.with_file_name("vpn-engine-runtime-config-v1.json");
    let mut config = load_runtime_config(&runtime_config_path, &settings)?;
    apply_engine_settings(&mut config, identity, &settings, &runtime_config_path)?;

    let reserved_incarnation = if settings.manual_mode {
        false
    } else {
        if p2pnet_daemon::incarnation::reserve_boot_incarnation(&config).is_none() {
            return Err(STATUS_IDENTITY_STORE_FAILED);
        }
        true
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            if reserved_incarnation {
                p2pnet_daemon::incarnation::discard_prepared_boot_incarnation(&config);
            }
            return Err(STATUS_NETWORK_PREFLIGHT_FAILED);
        }
    };
    if runtime
        .block_on(p2pnet_daemon::control::ControlClient::prepare_vpn_profile(
            &mut config,
        ))
        .is_err()
    {
        if reserved_incarnation {
            p2pnet_daemon::incarnation::discard_prepared_boot_incarnation(&config);
        }
        return Err(STATUS_NETWORK_PREFLIGHT_FAILED);
    }
    drop(runtime);

    let mut persisted = config.clone();
    persisted.control.auth_token.clear();
    persisted.diagnostics.auth_token = None;
    persisted.diagnostics.auth_token_path = None;
    persisted.diagnostics.log_path = None;
    if persisted.save_to_file(&runtime_config_path).is_err() {
        if reserved_incarnation {
            p2pnet_daemon::incarnation::discard_prepared_boot_incarnation(&config);
        }
        return Err(STATUS_CONFIG_INVALID);
    }
    Ok((config.network.virtual_ip, config.network.cidr))
}

fn apply_engine_settings(
    config: &mut Config,
    identity: NodeConfig,
    settings: &EngineSettingsV1,
    runtime_config_path: &Path,
) -> Result<(), i32> {
    let Some((socket_pool_enabled, socket_pool_size)) = settings.socket_pool_config() else {
        return Err(STATUS_INVALID_REQUEST);
    };
    config.config_path = Some(runtime_config_path.to_path_buf());
    config.node = identity;
    config.node.device_name = settings.device_name.clone();
    config.node.platform = "HarmonyOS".to_string();
    config.control.server_url = settings.control_server.clone();
    config.control.auth_token = settings.auth_token.clone();
    config.network.network_id = settings.network_id.clone();
    config.network.manual = settings.manual_mode;
    config.network.virtual_ip = settings.virtual_ip.clone();
    config.network.cidr = settings.overlay_cidr.clone();
    config.network.netmask = cidr_netmask(&settings.overlay_cidr).ok_or(STATUS_CONFIG_INVALID)?;
    config.network.interface = settings.tun_interface.clone();
    config.network.mtu = settings.mtu;
    config.network.udp_bind = settings.udp_bind.clone();
    config.network.udp_advertise = settings
        .udp_advertise
        .as_deref()
        .filter(|advertise| !advertise.trim().is_empty())
        .map(ToOwned::to_owned);
    config.network.socket_pool_enabled = socket_pool_enabled;
    config.network.socket_pool_size = socket_pool_size;
    config.relay.servers = settings.relay_servers.clone();
    Ok(())
}

fn run_engine(request: StartRequestV1, fd: OwnedFd, session: Arc<EngineSession>) -> i32 {
    if session.shutdown_gate.is_requested() {
        drop(fd);
        return STATUS_START_CANCELLED;
    }
    let settings = request.settings_snapshot.settings;
    let identity_path = PathBuf::from(&request.identity_store_path);
    let identity = match load_or_update_identity(
        &identity_path,
        &settings,
        request.settings_snapshot.revision,
    ) {
        Ok(identity) => identity,
        Err(code) => {
            drop(fd);
            return code;
        }
    };
    let runtime_config_path = identity_path.with_file_name("vpn-engine-runtime-config-v1.json");
    let mut config =
        match load_runtime_config(&runtime_config_path, &settings).and_then(|mut config| {
            apply_engine_settings(&mut config, identity, &settings, &runtime_config_path)?;
            Ok(config)
        }) {
            Ok(config) => config,
            Err(code) => {
                drop(fd);
                return code;
            }
        };

    let vpn_identity =
        match OhosVpnIdentity::new(request.identity.instance_id, request.identity.generation) {
            Ok(identity) => identity,
            Err(_) => {
                drop(fd);
                return STATUS_INVALID_REQUEST;
            }
        };
    let route_confirmation = match OhosVpnRouteConfirmation::after_successful_create(
        vpn_identity.clone(),
        request.configured_routes,
    ) {
        Ok(confirmation) => confirmation,
        Err(_) => {
            drop(fd);
            return STATUS_ROUTE_PROOF_INVALID;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return STATUS_DAEMON_START_FAILED,
    };

    let diagnostics_auth = match crate::diagnostics::DiagnosticsAuth::create(
        identity_path.with_file_name("p2wlan-daemon.diag-auth"),
    ) {
        Ok(auth) => auth,
        Err(_) => return STATUS_DAEMON_START_FAILED,
    };
    config.diagnostics.enabled = true;
    config.diagnostics.bind = "127.0.0.1:39277".to_string();
    config.diagnostics.auth_token = Some(diagnostics_auth.token().to_owned());
    config.diagnostics.auth_token_path = Some(diagnostics_auth.path().to_path_buf());

    let run_result = runtime.block_on(async move {
        // Daemon construction can start the managed Control client immediately
        // when credentials are configured. Construct it inside the runtime so
        // those tokio::spawn calls have an active scheduler/reactor.
        let mut daemon =
            match Daemon::new_with_ohos_tun(config, fd, vpn_identity, Some(route_confirmation)) {
                Ok(daemon) => daemon,
                Err(_) => return STATUS_ROUTE_PROOF_INVALID,
            };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        if daemon.set_ohos_startup_ready(ready_tx).is_err() {
            return STATUS_DAEMON_START_FAILED;
        }
        session.install_shutdown(daemon.shutdown_sender());
        let run = daemon.run();
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => classify_run_result(result),
            ready = ready_rx => {
                if ready.is_err() {
                    return STATUS_DAEMON_START_FAILED;
                }
                session.mark_ready();
                classify_run_result(run.await)
            }
        }
    });
    drop(runtime);
    drop(diagnostics_auth);
    run_result
}

fn load_runtime_config(path: &Path, settings: &EngineSettingsV1) -> Result<Config, i32> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.len() > RUNTIME_CONFIG_FILE_MAX_BYTES
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(crate::STATUS_CONFIG_INVALID);
            }
            let mut config =
                Config::load_from_file(path).map_err(|_| crate::STATUS_CONFIG_INVALID)?;
            if config.control.server_url != settings.control_server {
                config.control.device_credential.clear();
                config.control.credential_issued = false;
                config.control.registration_seq = None;
            }
            Ok(config)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Config::generate_default(&settings.control_server, &settings.network_id)
                .map_err(|_| crate::STATUS_CONFIG_INVALID)
        }
        Err(_) => Err(crate::STATUS_CONFIG_INVALID),
    }
}

fn classify_run_result(result: Result<(), DaemonError>) -> i32 {
    match result {
        Ok(()) => STATUS_DAEMON_START_FAILED,
        Err(DaemonError::Auth(_)) => crate::STATUS_AUTH_FAILED,
        Err(
            DaemonError::OhosRouteConfirmationInvalid { .. }
            | DaemonError::OhosRouteConfirmationMissing
            | DaemonError::OhosRouteConfirmationStale { .. }
            | DaemonError::OhosRouteNotConfigured { .. },
        ) => STATUS_ROUTE_PROOF_INVALID,
        Err(DaemonError::Config(_)) => crate::STATUS_CONFIG_INVALID,
        Err(_) => STATUS_DAEMON_START_FAILED,
    }
}

struct IdentityRecordV1 {
    node_id: [u8; 8],
    public_key: [u8; 32],
    private_key: [u8; 32],
    ed25519_public_key: [u8; 32],
    ed25519_private_key: [u8; 32],
    last_settings_revision: u64,
}

impl IdentityRecordV1 {
    fn from_config(config: &Config) -> Result<Self, i32> {
        Ok(Self {
            node_id: decode_key::<8>(&config.node.node_id)?,
            public_key: decode_key::<32>(&config.node.public_key)?,
            private_key: decode_key::<32>(&config.node.private_key)?,
            ed25519_public_key: decode_key::<32>(&config.node.ed25519_public_key)?,
            ed25519_private_key: decode_key::<32>(&config.node.ed25519_private_key)?,
            last_settings_revision: 0,
        })
    }

    fn validate_and_node_config(&self) -> Result<NodeConfig, i32> {
        let identity = NodeIdentity::from_private_key(self.private_key);
        if identity.node_id() != hex::encode(self.node_id)
            || identity.public_key() != self.public_key
        {
            return Err(STATUS_IDENTITY_STORE_FAILED);
        }
        let signing_key = Ed25519KeyPair::from_private_key(&self.ed25519_private_key);
        if signing_key.public_key() != self.ed25519_public_key {
            return Err(STATUS_IDENTITY_STORE_FAILED);
        }
        Ok(NodeConfig {
            node_id: hex::encode(self.node_id),
            public_key: hex::encode(self.public_key),
            private_key: hex::encode(self.private_key),
            device_name: "Harmony device".to_string(),
            platform: "HarmonyOS".to_string(),
            ed25519_public_key: hex::encode(self.ed25519_public_key),
            ed25519_private_key: hex::encode(self.ed25519_private_key),
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(IDENTITY_FILE_MAX_BYTES as usize);
        bytes.extend_from_slice(b"P2WHIDV1");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&self.last_settings_revision.to_le_bytes());
        bytes.extend_from_slice(&self.node_id);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.private_key);
        bytes.extend_from_slice(&self.ed25519_public_key);
        bytes.extend_from_slice(&self.ed25519_private_key);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, i32> {
        if bytes.len() != IDENTITY_FILE_MAX_BYTES as usize || &bytes[0..8] != b"P2WHIDV1" {
            return Err(STATUS_IDENTITY_STORE_FAILED);
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != 1 {
            return Err(STATUS_IDENTITY_STORE_FAILED);
        }
        let last_settings_revision = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        Ok(Self {
            last_settings_revision,
            node_id: bytes[20..28]
                .try_into()
                .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?,
            public_key: bytes[28..60]
                .try_into()
                .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?,
            private_key: bytes[60..92]
                .try_into()
                .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?,
            ed25519_public_key: bytes[92..124]
                .try_into()
                .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?,
            ed25519_private_key: bytes[124..156]
                .try_into()
                .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?,
        })
    }
}

fn decode_key<const N: usize>(value: &str) -> Result<[u8; N], i32> {
    let decoded = hex::decode(value).map_err(|_| STATUS_IDENTITY_STORE_FAILED)?;
    decoded.try_into().map_err(|_| STATUS_IDENTITY_STORE_FAILED)
}

fn load_or_update_identity(
    path: &Path,
    settings: &EngineSettingsV1,
    revision: u64,
) -> Result<NodeConfig, i32> {
    let parent = path.parent().ok_or(STATUS_IDENTITY_STORE_FAILED)?;
    fs::create_dir_all(parent).map_err(|_| STATUS_IDENTITY_STORE_FAILED)?;
    let record = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.len() > IDENTITY_FILE_MAX_BYTES
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(STATUS_IDENTITY_STORE_FAILED);
            }
            let mut file = File::open(path).map_err(|_| STATUS_IDENTITY_STORE_FAILED)?;
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(IDENTITY_FILE_MAX_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?;
            if bytes.len() as u64 > IDENTITY_FILE_MAX_BYTES {
                return Err(STATUS_IDENTITY_STORE_FAILED);
            }
            IdentityRecordV1::decode(&bytes)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let base = Config::generate_default(&settings.control_server, &settings.network_id)
                .map_err(|_| STATUS_DAEMON_START_FAILED)?;
            IdentityRecordV1::from_config(&base)?
        }
        Err(_) => return Err(STATUS_IDENTITY_STORE_FAILED),
    };
    let mut record = record;
    if record.last_settings_revision > revision {
        return Err(crate::STATUS_STALE_SETTINGS_SNAPSHOT);
    }
    let should_write = record.last_settings_revision < revision;
    record.last_settings_revision = revision;
    let node = record.validate_and_node_config()?;
    if should_write {
        write_identity_atomically(path, &record)?;
    }
    Ok(node)
}

fn write_identity_atomically(path: &Path, record: &IdentityRecordV1) -> Result<(), i32> {
    let parent = path.parent().ok_or(STATUS_IDENTITY_STORE_FAILED)?;
    let bytes = record.encode();
    if bytes.len() as u64 > IDENTITY_FILE_MAX_BYTES {
        return Err(STATUS_IDENTITY_STORE_FAILED);
    }
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".vpn-engine-identity-v1.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?;
    let write_result = file
        .write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| STATUS_IDENTITY_STORE_FAILED);
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(_) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(STATUS_IDENTITY_STORE_FAILED);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| STATUS_IDENTITY_STORE_FAILED)?;
    Ok(())
}

static TEMP_FILE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn cidr_netmask(cidr: &str) -> Option<String> {
    let (_, prefix) = cidr.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = crate::snapshot::prefix_mask(prefix);
    Some(std::net::Ipv4Addr::from(mask).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn runtime_settings(control_server: &str) -> EngineSettingsV1 {
        EngineSettingsV1 {
            control_server: control_server.to_string(),
            auth_token: "current-user-token".to_string(),
            network_id: "network-a".to_string(),
            manual_mode: false,
            virtual_ip: "10.20.0.8".to_string(),
            device_name: "Harmony device".to_string(),
            overlay_cidr: "10.20.0.0/16".to_string(),
            tun_interface: "p2wlan0".to_string(),
            mtu: 1420,
            udp_bind: "0.0.0.0:0".to_string(),
            udp_advertise: None,
            socket_pool: "3".to_string(),
            relay_servers: Vec::new(),
        }
    }

    #[test]
    fn identity_keys_are_verified_and_reused() {
        let root = std::env::temp_dir().join(format!(
            "p2wlan-harmony-identity-{}-{}",
            std::process::id(),
            TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("vpn-engine-identity-v1.bin");
        let config = Config::generate_default("https://control.example.test", "network-a").unwrap();
        let mut record = IdentityRecordV1::from_config(&config).unwrap();
        record.last_settings_revision = 1;
        write_identity_atomically(&path, &record).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let stored = IdentityRecordV1::decode(&fs::read(&path).unwrap()).unwrap();
        let identity = stored.validate_and_node_config().unwrap();
        assert_eq!(identity.node_id, config.node.node_id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_record_detects_key_mismatch() {
        let config = Config::generate_default("https://control.example.test", "network-a").unwrap();
        let mut record = IdentityRecordV1::from_config(&config).unwrap();
        record.public_key = [0; 32];
        assert_eq!(
            record.validate_and_node_config().unwrap_err(),
            STATUS_IDENTITY_STORE_FAILED
        );
    }

    #[test]
    fn runtime_config_preserves_device_credential_for_the_same_control() {
        let root = std::env::temp_dir().join(format!(
            "p2wlan-harmony-runtime-config-{}-{}",
            std::process::id(),
            TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("vpn-engine-runtime-config-v1.json");
        let mut config =
            Config::generate_default("https://control.example.test", "network-a").unwrap();
        config.control.device_credential = "device-credential".to_string();
        config.control.credential_issued = true;
        config.control.registration_seq = Some(42);
        config.save_to_file(&path).unwrap();

        let loaded =
            load_runtime_config(&path, &runtime_settings("https://control.example.test")).unwrap();
        assert_eq!(loaded.control.device_credential, "device-credential");
        assert!(loaded.control.credential_issued);
        assert_eq!(loaded.control.registration_seq, Some(42));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_config_drops_credentials_when_control_changes() {
        let root = std::env::temp_dir().join(format!(
            "p2wlan-harmony-runtime-config-{}-{}",
            std::process::id(),
            TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("vpn-engine-runtime-config-v1.json");
        let mut config =
            Config::generate_default("https://control.example.test", "network-a").unwrap();
        config.control.device_credential = "device-credential".to_string();
        config.control.credential_issued = true;
        config.control.registration_seq = Some(42);
        config.save_to_file(&path).unwrap();

        let loaded =
            load_runtime_config(&path, &runtime_settings("https://other.example.test")).unwrap();
        assert!(loaded.control.device_credential.is_empty());
        assert!(!loaded.control.credential_issued);
        assert_eq!(loaded.control.registration_seq, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cidr_mask_handles_prefix_edges() {
        assert_eq!(cidr_netmask("10.0.0.0/0").as_deref(), Some("0.0.0.0"));
        assert_eq!(
            cidr_netmask("10.0.0.0/32").as_deref(),
            Some("255.255.255.255")
        );
        assert_eq!(cidr_netmask("10.0.0.0/33"), None);
    }
}
