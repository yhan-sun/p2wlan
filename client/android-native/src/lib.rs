//! JNI bridge between Android's `VpnService` and the Rust P2WLAN daemon.
//!
//! The Android service owns the VPN lifecycle and establishes the TUN fd. This
//! library owns the fd after `detachFd()`, runs the existing daemon on a Tokio
//! runtime thread, and exposes only a small start/stop/status surface to the
//! Flutter Android host.

pub mod lifecycle;

#[cfg(target_os = "android")]
mod android_bridge {
    use super::lifecycle::{NetworkHintDecision, OwnerId, PhysicalNetworkHintAuthority};

    use std::os::fd::RawFd;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::{Path, PathBuf};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex, OnceLock,
    };
    use std::thread;
    use std::time::Duration;
    use std::{
        fs::{File, OpenOptions},
        io::{self, Write},
    };

    use jni::objects::{GlobalRef, JObject, JString, JValue};
    use jni::sys::{jboolean, jint, jlong, jstring};
    use jni::{JNIEnv, JavaVM};
    use rand::RngCore;
    use serde::Deserialize;
    use tokio::runtime::Builder;
    use tokio::sync::{broadcast, watch};

    use p2pnet_daemon::config::{Config, ControlProxyMode};
    use p2pnet_daemon::Daemon;
    use p2pnet_tun::AndroidTunMode;

    const DEFAULT_DIAGNOSTICS_BIND: &str = "127.0.0.1:39277";
    const DEFAULT_CONTROL_SERVER: &str = "http://47.109.40.237:18080";
    const DEFAULT_OVERLAY_CIDR: &str = "10.20.0.0/16";
    const DEFAULT_INTERFACE: &str = "p2wlan-vpn";
    const DEFAULT_VIRTUAL_IP: &str = "10.20.0.1";

    #[derive(Debug, Default, Deserialize)]
    struct AndroidStartRequest {
        #[serde(default)]
        config_path: String,
        #[serde(default)]
        control_server: String,
        #[serde(default)]
        network_id: String,
        #[serde(default)]
        auth_token: String,
        #[serde(default)]
        device_name: String,
        #[serde(default)]
        virtual_ip: String,
        #[serde(default)]
        manual_mode: bool,
        #[serde(default)]
        overlay_cidr: String,
        #[serde(default)]
        mtu: u32,
        #[serde(default)]
        udp_bind: String,
        #[serde(default)]
        udp_advertise: String,
        #[serde(default)]
        relay_servers: String,
        #[serde(default)]
        socket_pool: String,
        #[serde(default)]
        diagnostics_bind: String,
        #[serde(default)]
        log_path: String,
        #[serde(default)]
        diagnostics_auth_path: String,
        #[serde(default = "default_android_tun_mode")]
        android_tun_mode: String,
    }

    fn default_android_tun_mode() -> String {
        "async_fd".to_string()
    }

    #[derive(Clone)]
    struct RuntimeHandle {
        owner: OwnerId,
        shutdown_tx: watch::Sender<bool>,
        running: Arc<AtomicBool>,
        ready: Arc<AtomicBool>,
        network_change_tx: broadcast::Sender<p2pnet_daemon::AndroidNetworkChangeHint>,
        physical_network_authority: Arc<Mutex<PhysicalNetworkHintAuthority>>,
    }

    static RUNTIME: OnceLock<Mutex<Option<RuntimeHandle>>> = OnceLock::new();
    #[derive(Debug)]
    struct OwnedLastError {
        owner: OwnerId,
        message: String,
    }

    static LATEST_OWNER: AtomicU64 = AtomicU64::new(0);
    static START_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    static LAST_ERROR: OnceLock<Mutex<Option<OwnedLastError>>> = OnceLock::new();
    static ANDROID_SOCKET_PROTECTOR: OnceLock<Mutex<Option<AndroidSocketProtector>>> =
        OnceLock::new();

    struct AndroidSocketProtector {
        owner: OwnerId,
        vm: JavaVM,
        service: GlobalRef,
    }

    fn runtime_slot() -> &'static Mutex<Option<RuntimeHandle>> {
        RUNTIME.get_or_init(|| Mutex::new(None))
    }

    fn start_lock() -> &'static Mutex<()> {
        START_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn android_socket_protector_slot() -> &'static Mutex<Option<AndroidSocketProtector>> {
        ANDROID_SOCKET_PROTECTOR.get_or_init(|| Mutex::new(None))
    }

    fn protect_android_socket(fd: RawFd) -> io::Result<()> {
        let guard = android_socket_protector_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let protector = guard.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Android VpnService protector is not installed",
            )
        })?;
        let mut env = protector.vm.attach_current_thread().map_err(|error| {
            io::Error::other(format!("failed to attach socket thread to JVM: {error}"))
        })?;
        let protected = env
            .call_method(
                protector.service.as_obj(),
                "protect",
                "(I)Z",
                &[JValue::Int(fd as jint)],
            )
            .map_err(|error| io::Error::other(format!("VpnService.protect(fd) failed: {error}")))?
            .z()
            .map_err(|error| {
                io::Error::other(format!(
                    "VpnService.protect(fd) returned an invalid value: {error}"
                ))
            })?;
        if protected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("VpnService.protect({fd}) returned false"),
            ))
        }
    }

    fn install_android_socket_protector(
        env: &mut JNIEnv<'_>,
        service: JObject<'_>,
        owner: OwnerId,
    ) -> Result<(), String> {
        let vm = env
            .get_java_vm()
            .map_err(|error| format!("failed to acquire Android JavaVM: {error}"))?;
        let service = env
            .new_global_ref(service)
            .map_err(|error| format!("failed to retain Android VpnService: {error}"))?;
        *android_socket_protector_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(AndroidSocketProtector { owner, vm, service });
        p2pnet_netbind::set_android_socket_protector(protect_android_socket);
        Ok(())
    }

    fn clear_android_socket_protector(owner: OwnerId) {
        // Hold the protector slot while clearing netbind's process-wide callback.
        // This closes the otherwise possible A-clear/B-install/A-clear ordering:
        // B cannot install until both the owner check and the netbind clear finish.
        let mut guard = android_socket_protector_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard
            .as_ref()
            .is_some_and(|protector| protector.owner == owner)
        {
            p2pnet_netbind::clear_android_socket_protector();
            *guard = None;
        }
    }

    fn last_error_slot() -> &'static Mutex<Option<OwnedLastError>> {
        LAST_ERROR.get_or_init(|| Mutex::new(None))
    }

    fn register_owner(owner: OwnerId) {
        let mut latest = LATEST_OWNER.load(Ordering::Acquire);
        while owner.raw() > latest {
            match LATEST_OWNER.compare_exchange_weak(
                latest,
                owner.raw(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => latest = observed,
            }
        }
    }

    /// Record an error only for the newest runtime owner. An old runtime can
    /// finish after a replacement has started; its late error must not become
    /// the replacement's diagnostic state.
    fn set_last_error(owner: OwnerId, error: Option<String>) {
        if owner.raw() < LATEST_OWNER.load(Ordering::Acquire) {
            return;
        }
        let mut guard = last_error_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard
            .as_ref()
            .is_some_and(|previous| previous.owner.raw() > owner.raw())
        {
            return;
        }
        *guard = error.map(|message| OwnedLastError { owner, message });
    }

    fn last_error() -> Option<String> {
        let current_owner = runtime_incarnation();
        last_error_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|error| current_owner.is_none_or(|owner| owner == error.owner))
            .map(|error| error.message.clone())
    }

    fn last_error_for(owner: OwnerId) -> Option<String> {
        last_error_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|error| error.owner == owner)
            .map(|error| error.message.clone())
    }

    fn runtime_running() -> bool {
        runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|handle| handle.running.load(Ordering::Acquire))
    }

    fn runtime_ready() -> bool {
        runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|handle| handle.ready.load(Ordering::Acquire))
    }

    fn runtime_incarnation() -> Option<OwnerId> {
        runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .filter(|handle| handle.running.load(Ordering::Acquire))
            .map(|handle| handle.owner)
    }

    fn close_raw_fd(fd: jint) {
        if fd >= 0 {
            // Safety: this is only called on startup paths where ownership has
            // not yet been transferred into AndroidTun. Once Daemon takes the fd,
            // its OwnedFd is responsible for closing it.
            unsafe { drop(OwnedFd::from_raw_fd(fd)) };
        }
    }

    fn read_request(
        env: &mut JNIEnv<'_>,
        request_json: JString<'_>,
    ) -> Result<AndroidStartRequest, String> {
        let request = env
            .get_string(&request_json)
            .map_err(|error| format!("failed to read Android VPN request: {error}"))?
            .to_string_lossy()
            .into_owned();
        serde_json::from_str(&request)
            .map_err(|error| format!("invalid Android VPN request JSON: {error}"))
    }

    fn non_empty(value: &str, fallback: &str) -> String {
        let value = value.trim();
        if value.is_empty() {
            fallback.to_string()
        } else {
            value.to_string()
        }
    }

    fn overlay_prefix_and_netmask(cidr: &str) -> (String, String) {
        let prefix = cidr
            .split_once('/')
            .and_then(|(_, prefix)| prefix.parse::<u32>().ok())
            .filter(|prefix| *prefix <= 32)
            .unwrap_or(16);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        (
            prefix.to_string(),
            std::net::Ipv4Addr::from(mask).to_string(),
        )
    }

    fn write_diagnostics_auth(path: &Path) -> Result<String, String> {
        let parent = path
            .parent()
            .ok_or_else(|| "diagnostics auth path has no parent directory".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create Android daemon directory: {error}"))?;

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        std::fs::write(path, token.as_bytes())
            .map_err(|error| format!("failed to write diagnostics auth token: {error}"))?;

        protect_private_file(path)
            .map_err(|error| format!("failed to protect diagnostics auth token: {error}"))?;
        Ok(token)
    }

    /// Android's app directory is private by default, but files created by a
    /// native process still inherit the process umask.  Explicitly enforce
    /// owner-only permissions for every daemon log/auth file, including files
    /// created by an older release with broader permissions.
    fn protect_private_file(path: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path)?.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions)?;
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    fn open_private_append(path: &Path) -> io::Result<File> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        if let Err(error) = protect_private_file(path) {
            drop(file);
            return Err(error);
        }
        Ok(file)
    }

    fn prepare_config(request: &AndroidStartRequest) -> Result<(Config, PathBuf), String> {
        let config_path = PathBuf::from(request.config_path.trim());
        if config_path.as_os_str().is_empty() {
            return Err("Android daemon config path is empty".to_string());
        }
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create Android config directory: {error}"))?;
        }

        let control_server = non_empty(&request.control_server, DEFAULT_CONTROL_SERVER);
        let network_id = non_empty(&request.network_id, "default");
        let mut config = if config_path.exists() {
            Config::load_from_file(&config_path)
                .map_err(|error| format!("failed to load Android daemon config: {error}"))?
        } else {
            Config::generate_default(&control_server, &network_id)
                .map_err(|error| format!("failed to generate Android daemon identity: {error}"))?
        };

        let cidr = non_empty(&request.overlay_cidr, DEFAULT_OVERLAY_CIDR);
        let (_prefix, netmask) = overlay_prefix_and_netmask(&cidr);
        let configured_vip = if request.virtual_ip.trim().is_empty() {
            non_empty(&config.network.virtual_ip, DEFAULT_VIRTUAL_IP)
        } else {
            request.virtual_ip.trim().to_string()
        };
        let mtu = if request.mtu == 0 {
            config.network.mtu
        } else {
            request.mtu.clamp(576, 65535)
        };

        config.config_path = Some(config_path.clone());
        config.control.server_url = control_server;
        config.control.auth_token = request.auth_token.trim().to_string();
        config.control.proxy_mode = ControlProxyMode::Direct;
        config.network.network_id = network_id;
        let has_control_credential = !config.control.auth_token.trim().is_empty()
            || !config.control.device_credential.trim().is_empty();
        config.network.manual = request.manual_mode || !has_control_credential;
        config.network.virtual_ip = configured_vip;
        config.network.cidr = cidr;
        config.network.netmask = netmask;
        config.network.mtu = mtu;
        config.network.interface = DEFAULT_INTERFACE.to_string();
        if !request.udp_bind.trim().is_empty() {
            config.network.udp_bind = request.udp_bind.trim().to_string();
        }
        config.network.udp_advertise = if request.udp_advertise.trim().is_empty() {
            None
        } else {
            Some(request.udp_advertise.trim().to_string())
        };
        if !request.device_name.trim().is_empty() {
            config.node.device_name = request.device_name.trim().to_string();
        }
        config.node.platform = "android".to_string();
        if !request.relay_servers.trim().is_empty() {
            config.relay.servers = request
                .relay_servers
                .split(',')
                .map(str::trim)
                .filter(|server| !server.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        }
        match request.socket_pool.trim().to_ascii_lowercase().as_str() {
            "on" | "auto" => {
                config.network.socket_pool_enabled = true;
            }
            "off" => {
                config.network.socket_pool_enabled = false;
            }
            value => {
                if let Ok(size) = value.parse::<usize>() {
                    config.network.socket_pool_size = size.clamp(1, 16);
                    config.network.socket_pool_enabled = size > 1;
                }
            }
        }

        let diagnostics_bind = non_empty(&request.diagnostics_bind, DEFAULT_DIAGNOSTICS_BIND);
        let log_path = non_empty(
            &request.log_path,
            &config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("p2wlan-daemon.log")
                .to_string_lossy(),
        );
        let auth_path = non_empty(
            &request.diagnostics_auth_path,
            &config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("p2wlan-daemon.diag-auth")
                .to_string_lossy(),
        );
        let auth_path = PathBuf::from(auth_path);
        let auth_token = write_diagnostics_auth(&auth_path)?;
        config.diagnostics.enabled = true;
        config.diagnostics.bind = diagnostics_bind;
        config.diagnostics.log_path = Some(PathBuf::from(log_path));
        config.diagnostics.auth_token = Some(auth_token);
        config.diagnostics.auth_token_path = Some(auth_path);

        // Persist identity and network defaults, but never persist the user JWT
        // or the per-process diagnostics token.
        let mut persisted = config.clone();
        persisted.control.auth_token.clear();
        persisted.diagnostics.auth_token = None;
        persisted.diagnostics.auth_token_path = None;
        persisted.diagnostics.log_path = None;
        persisted
            .save_to_file(&config_path)
            .map_err(|error| format!("failed to persist Android daemon config: {error}"))?;

        Ok((config, config_path))
    }

    fn append_log(path: &Path, message: &str) {
        if let Ok(mut file) = open_private_append(path) {
            let _ = writeln!(file, "{message}");
        }
    }

    /// Install the process-wide Rust subscriber once. The desktop executable does
    /// this in its `main`, but Android enters through JNI and otherwise all
    /// `tracing` records would disappear, leaving the user with an empty local
    /// log when the VPN failed during startup.
    fn init_logging(path: &Path) {
        static LOGGING: OnceLock<()> = OnceLock::new();
        LOGGING.get_or_init(|| {
            let Ok(file) = open_private_append(path) else {
                return;
            };
            let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            let _ = tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_ansi(false)
                .with_writer(move || {
                    file.try_clone()
                        .expect("failed to clone Android daemon log file handle")
                })
                .try_init();
        });
    }

    fn start_runtime(
        tun_fd: jint,
        request: AndroidStartRequest,
        owner: OwnerId,
        service_owner: u64,
    ) -> Result<(), String> {
        {
            let guard = runtime_slot()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard
                .as_ref()
                .is_some_and(|handle| handle.running.load(Ordering::Acquire))
            {
                close_raw_fd(tun_fd);
                return Err("an existing Android P2WLAN daemon is still running".to_string());
            }
        }

        let (config, config_path) = match prepare_config(&request) {
            Ok(value) => value,
            Err(error) => {
                close_raw_fd(tun_fd);
                return Err(error);
            }
        };
        let tun_mode = match request.android_tun_mode.parse::<AndroidTunMode>() {
            Ok(mode) => mode,
            Err(error) => {
                close_raw_fd(tun_fd);
                return Err(error);
            }
        };
        let log_path = config
            .diagnostics
            .log_path
            .clone()
            .unwrap_or_else(|| config_path.with_file_name("p2wlan-daemon.log"));
        let running = Arc::new(AtomicBool::new(true));
        let ready = Arc::new(AtomicBool::new(false));
        let (network_change_tx, _network_change_rx) = broadcast::channel(32);
        let physical_network_authority = Arc::new(Mutex::new(PhysicalNetworkHintAuthority::new(
            service_owner,
            owner,
        )));
        let running_for_thread = Arc::clone(&running);
        let ready_for_thread = Arc::clone(&ready);
        let network_change_tx_for_thread = network_change_tx.clone();
        let physical_network_authority_for_thread = Arc::clone(&physical_network_authority);
        // This channel acknowledges only that the runtime handle has been
        // installed. Actual daemon readiness is published separately through
        // `ready_for_thread` by Daemon::run after registration, TUN attachment,
        // diagnostics, and dataplane setup have completed.
        let (handle_tx, handle_rx) = mpsc::sync_channel::<Result<RuntimeHandle, String>>(1);

        let thread_result = thread::Builder::new()
            .name("p2wlan-daemon".to_string())
            .spawn(move || {
                let mut fd_owned_by_thread = true;
                let startup_result = catch_unwind(AssertUnwindSafe(|| {
                    init_logging(&log_path);
                    let runtime = Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| format!("failed to create Tokio runtime: {error}"))?;
                    // Daemon::new creates the managed control workers with
                    // tokio::spawn. JNI threads do not automatically enter the
                    // runtime they just built, so construct the daemon inside an
                    // explicit runtime context or managed Android starts panic
                    // before the first control request is sent.
                    let mut daemon = {
                        let _runtime_guard = runtime.enter();
                        let mut daemon =
                            Daemon::new_with_android_tun_mode(config, tun_fd, tun_mode);
                        fd_owned_by_thread = false;
                        daemon.set_android_startup_ready(Arc::clone(&ready_for_thread));
                        daemon.set_android_runtime_incarnation(owner.raw());
                        daemon.set_android_network_change_sender(
                            network_change_tx_for_thread.clone(),
                        );
                        let handle = RuntimeHandle {
                            owner,
                            shutdown_tx: daemon.shutdown_sender(),
                            running: Arc::clone(&running_for_thread),
                            ready: Arc::clone(&ready_for_thread),
                            network_change_tx: network_change_tx_for_thread.clone(),
                            physical_network_authority: Arc::clone(
                                &physical_network_authority_for_thread,
                            ),
                        };
                        handle_tx
                            .send(Ok(handle))
                            .map_err(|_| "Android daemon launch waiter disconnected".to_string())?;
                        daemon
                    };
                    if let Err(error) = runtime.block_on(daemon.run()) {
                        let message = format!("Android daemon exited with error: {error}");
                        set_last_error(owner, Some(message.clone()));
                        append_log(&log_path, &message);
                    }
                    Ok::<(), String>(())
                }));

                if fd_owned_by_thread {
                    close_raw_fd(tun_fd);
                }

                match startup_result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        set_last_error(owner, Some(error.clone()));
                        append_log(&log_path, &error);
                        let _ = handle_tx.send(Err(error));
                    }
                    Err(_) => {
                        let error = "Android daemon thread panicked during startup".to_string();
                        set_last_error(owner, Some(error.clone()));
                        append_log(&log_path, &error);
                        let _ = handle_tx.send(Err(error));
                    }
                }
                ready_for_thread.store(false, Ordering::Release);
                running_for_thread.store(false, Ordering::Release);
                let mut guard = runtime_slot()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if guard.as_ref().is_some_and(|handle| handle.owner == owner) {
                    *guard = None;
                }
                clear_android_socket_protector(owner);
            })
            .map_err(|error| format!("failed to start Android daemon thread: {error}"));
        if let Err(error) = thread_result {
            close_raw_fd(tun_fd);
            return Err(error);
        }

        let handle = handle_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|error| format!("Android daemon runtime did not start: {error}"))??;
        let mut guard = runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The daemon thread may have exited between sending the handle and
        // this publication. Do not install an already-dead handle after its
        // owner-scoped cleanup has run; doing so would make the next start
        // observe stale runtime state.
        if !handle.running.load(Ordering::Acquire) {
            return Err(last_error_for(owner).unwrap_or_else(|| {
                "Android daemon exited before its runtime handle became active".to_string()
            }));
        }
        *guard = Some(handle);
        Ok(())
    }

    fn stop_runtime(expected_owner: Option<OwnerId>) -> bool {
        let guard = runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = guard.as_ref() {
            if expected_owner.is_some_and(|owner| owner != handle.owner) {
                return false;
            }
            let _ = handle.shutdown_tx.send(true);
            true
        } else {
            false
        }
    }

    fn new_string_or_null(env: &mut JNIEnv<'_>, error: Option<String>) -> jstring {
        match error {
            Some(error) => env
                .new_string(error)
                .map(|value| value.into_raw())
                .unwrap_or(std::ptr::null_mut()),
            None => std::ptr::null_mut(),
        }
    }

    /// Start the Rust daemon around the Android VPN fd. A null return means the
    /// daemon runtime handle was installed; actual readiness is reported by the
    /// diagnostics endpoint and `nativeIsReady`. A non-null string means the
    /// runtime could not be launched. Before the startup thread is created the
    /// caller still owns the fd; after that handoff Rust closes or drops it on
    /// every startup/error path.
    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeStart(
        mut env: JNIEnv<'_>,
        _object: JObject<'_>,
        service: JObject<'_>,
        service_incarnation: jlong,
        tun_fd: jint,
        request_json: JString<'_>,
    ) -> jstring {
        // Serialize the complete native start handoff, including protector
        // installation and runtime-slot publication. Without this guard two
        // concurrent MethodChannel starts could both observe an empty slot,
        // then the older thread could publish over the newer owner.
        let _start_guard = start_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut owner = None;
        let result = match read_request(&mut env, request_json) {
            Ok(_request) if runtime_running() => {
                close_raw_fd(tun_fd);
                Err("an existing Android P2WLAN daemon is still running".to_string())
            }
            Ok(request) => {
                if service_incarnation <= 0 {
                    close_raw_fd(tun_fd);
                    return new_string_or_null(
                        &mut env,
                        Some("invalid Android service incarnation".to_string()),
                    );
                }
                let runtime_owner = OwnerId::allocate();
                register_owner(runtime_owner);
                set_last_error(runtime_owner, None);
                owner = Some(runtime_owner);
                match install_android_socket_protector(&mut env, service, runtime_owner) {
                    Ok(()) => {
                        start_runtime(tun_fd, request, runtime_owner, service_incarnation as u64)
                    }
                    Err(error) => {
                        close_raw_fd(tun_fd);
                        Err(error)
                    }
                }
            }
            Err(error) => {
                // The fd is still owned by Kotlin when JSON parsing fails, so
                // close it here before returning the JNI error. Once
                // start_runtime has spawned the daemon, ownership is transferred
                // to the Rust startup thread and its error paths close/drop it.
                close_raw_fd(tun_fd);
                Err(error)
            }
        };
        if let Err(error) = &result {
            if let Some(owner) = owner {
                set_last_error(owner, Some(error.clone()));
            }
            if let Some(owner) = owner {
                clear_android_socket_protector(owner);
            }
        }
        new_string_or_null(&mut env, result.err())
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeAdoptService(
        mut env: JNIEnv<'_>,
        _object: JObject<'_>,
        service: JObject<'_>,
        service_incarnation: jlong,
        expected_bridge_incarnation: jlong,
    ) -> jstring {
        let _start_guard = start_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let decision = if service_incarnation <= 0 || expected_bridge_incarnation <= 0 {
            NetworkHintDecision::Failed
        } else {
            let expected_owner = OwnerId::from_raw(expected_bridge_incarnation as u64);
            let handle = runtime_slot()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let Some(handle) = handle else {
                return new_string_or_null(
                    &mut env,
                    Some(NetworkHintDecision::StaleRejected.wire_name().to_string()),
                );
            };
            if !handle.running.load(Ordering::Acquire) || handle.owner != expected_owner {
                NetworkHintDecision::StaleRejected
            } else {
                let mut authority = handle
                    .physical_network_authority
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if expected_owner != authority.bridge_owner()
                    || service_incarnation as u64 <= authority.service_owner()
                {
                    if expected_owner != authority.bridge_owner()
                        || (service_incarnation as u64) < authority.service_owner()
                    {
                        NetworkHintDecision::StaleRejected
                    } else {
                        NetworkHintDecision::Duplicate
                    }
                } else {
                    match install_android_socket_protector(&mut env, service, expected_owner) {
                        Ok(()) => authority
                            .rebind_service_owner(expected_owner, service_incarnation as u64),
                        Err(error) => {
                            set_last_error(handle.owner, Some(error));
                            NetworkHintDecision::Failed
                        }
                    }
                }
            }
        };
        new_string_or_null(&mut env, Some(decision.wire_name().to_string()))
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeNotifyPhysicalNetworkChanged(
        mut env: JNIEnv<'_>,
        _object: JObject<'_>,
        service_incarnation: jlong,
        expected_bridge_incarnation: jlong,
        kotlin_network_generation: jlong,
        network_identity_hash: JString<'_>,
    ) -> jstring {
        // Serialize callback admission with service adoption. Otherwise an
        // old callback could win the authority mutex just before a new
        // service owner is installed and its hint could be delivered after
        // the owner transition. The callback is linearized either before the
        // adoption (valid) or after it (stale), never in between.
        let _start_guard = start_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hash = match env.get_string(&network_identity_hash) {
            Ok(value) => value.to_string_lossy().into_owned(),
            Err(_) => {
                return new_string_or_null(
                    &mut env,
                    Some(NetworkHintDecision::Failed.wire_name().to_string()),
                );
            }
        };
        let Some(handle) = runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        else {
            return new_string_or_null(
                &mut env,
                Some(NetworkHintDecision::StaleRejected.wire_name().to_string()),
            );
        };
        let expected_owner = (expected_bridge_incarnation > 0)
            .then(|| OwnerId::from_raw(expected_bridge_incarnation as u64));
        let decision = if service_incarnation <= 0 || kotlin_network_generation <= 0 {
            NetworkHintDecision::Failed
        } else if !handle.running.load(Ordering::Acquire) || expected_owner != Some(handle.owner) {
            NetworkHintDecision::StaleRejected
        } else {
            let mut authority = handle
                .physical_network_authority
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let decision = authority.accept(
                service_incarnation as u64,
                handle.owner,
                kotlin_network_generation as u64,
                &hash,
            );
            if decision == NetworkHintDecision::Applied {
                let hint = p2pnet_daemon::AndroidNetworkChangeHint {
                    kotlin_network_generation: kotlin_network_generation as u64,
                    network_identity_hash: hash,
                };
                if handle.network_change_tx.send(hint).is_err() {
                    NetworkHintDecision::Failed
                } else {
                    decision
                }
            } else {
                decision
            }
        };
        new_string_or_null(&mut env, Some(decision.wire_name().to_string()))
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeStop(
        _env: JNIEnv<'_>,
        _object: JObject<'_>,
        expected_incarnation: jlong,
    ) -> jboolean {
        let expected_owner =
            (expected_incarnation > 0).then(|| OwnerId::from_raw(expected_incarnation as u64));
        if stop_runtime(expected_owner) {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeIsRunning(
        _env: JNIEnv<'_>,
        _object: JObject<'_>,
    ) -> jboolean {
        if runtime_running() {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeIsReady(
        _env: JNIEnv<'_>,
        _object: JObject<'_>,
    ) -> jboolean {
        if runtime_ready() {
            1
        } else {
            0
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeLastError(
        mut env: JNIEnv<'_>,
        _object: JObject<'_>,
    ) -> jstring {
        new_string_or_null(&mut env, last_error())
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_nativeIncarnation(
        _env: JNIEnv<'_>,
        _object: JObject<'_>,
    ) -> jlong {
        runtime_incarnation().map_or(0, |owner| owner.raw() as jlong)
    }
}
