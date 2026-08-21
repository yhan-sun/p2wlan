//! JNI bridge between Android's `VpnService` and the Rust P2WLAN daemon.
//!
//! The Android service owns the VPN lifecycle and establishes the TUN fd. This
//! library owns the fd after `detachFd()`, runs the existing daemon on a Tokio
//! runtime thread, and exposes only a small start/stop/status surface to the
//! Flutter Android host.

#![cfg(target_os = "android")]

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex, OnceLock,
};
use std::thread;
use std::time::Duration;
use std::{fs::OpenOptions, io::Write};

use jni::objects::{JObject, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;
use rand::RngCore;
use serde::Deserialize;
use tokio::runtime::Builder;
use tokio::sync::watch;

use p2pnet_daemon::config::{Config, ControlProxyMode};
use p2pnet_daemon::Daemon;

const DEFAULT_DIAGNOSTICS_BIND: &str = "127.0.0.1:39277";
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
}

#[derive(Clone)]
struct RuntimeHandle {
    shutdown_tx: watch::Sender<bool>,
    running: Arc<AtomicBool>,
}

static RUNTIME: OnceLock<Mutex<Option<RuntimeHandle>>> = OnceLock::new();

fn runtime_slot() -> &'static Mutex<Option<RuntimeHandle>> {
    RUNTIME.get_or_init(|| Mutex::new(None))
}

fn runtime_running() -> bool {
    runtime_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|handle| handle.running.load(Ordering::Acquire))
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(path)
            .map_err(|error| format!("failed to inspect diagnostics auth token: {error}"))?
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(path, permissions)
            .map_err(|error| format!("failed to protect diagnostics auth token: {error}"))?;
    }
    Ok(token)
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

    let control_server = non_empty(&request.control_server, "http://control.example.com:18080");
    let network_id = non_empty(&request.network_id, "default");
    let mut config = if config_path.exists() {
        Config::load_from_file(&config_path)
            .or_else(|_| Config::generate_default(&control_server, &network_id))
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
    config.network.manual = request.manual_mode || config.control.auth_token.trim().is_empty();
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
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
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
        let Some(parent) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(file) = OpenOptions::new().create(true).append(true).open(path) else {
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

fn start_runtime(tun_fd: jint, request: AndroidStartRequest) -> Result<(), String> {
    {
        let guard = runtime_slot()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard
            .as_ref()
            .is_some_and(|handle| handle.running.load(Ordering::Acquire))
        {
            return Err("an existing Android P2WLAN daemon is still running".to_string());
        }
    }

    let (config, config_path) = prepare_config(&request)?;
    let log_path = config
        .diagnostics
        .log_path
        .clone()
        .unwrap_or_else(|| config_path.with_file_name("p2wlan-daemon.log"));
    let running = Arc::new(AtomicBool::new(true));
    let running_for_thread = Arc::clone(&running);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);

    thread::Builder::new()
        .name("p2wlan-daemon".to_string())
        .spawn(move || {
            init_logging(&log_path);
            let runtime = match Builder::new_multi_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(error) => {
                    append_log(
                        &log_path,
                        &format!("failed to create Tokio runtime: {error}"),
                    );
                    running_for_thread.store(false, Ordering::Release);
                    return;
                }
            };
            let mut daemon = Daemon::new_with_android_tun(config, tun_fd);
            let shutdown_tx = daemon.shutdown_sender();
            let _ = ready_tx.send(shutdown_tx);
            if let Err(error) = runtime.block_on(daemon.run()) {
                append_log(
                    &log_path,
                    &format!("Android daemon exited with error: {error}"),
                );
            }
            running_for_thread.store(false, Ordering::Release);
            let mut guard = runtime_slot()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard
                .as_ref()
                .is_some_and(|handle| Arc::ptr_eq(&handle.running, &running_for_thread))
            {
                *guard = None;
            }
        })
        .map_err(|error| format!("failed to start Android daemon thread: {error}"))?;

    let shutdown_tx = ready_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| format!("Android daemon did not initialize: {error}"))?;
    let handle = RuntimeHandle {
        shutdown_tx,
        running,
    };
    let mut guard = runtime_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(handle);
    Ok(())
}

fn stop_runtime() -> bool {
    let guard = runtime_slot()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(handle) = guard.as_ref() {
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
/// daemon thread was launched; a non-null string is a user-visible startup
/// error and ownership of the fd remains with the caller.
#[no_mangle]
pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_start(
    mut env: JNIEnv<'_>,
    _object: JObject<'_>,
    tun_fd: jint,
    request_json: JString<'_>,
) -> jstring {
    let result =
        read_request(&mut env, request_json).and_then(|request| start_runtime(tun_fd, request));
    new_string_or_null(&mut env, result.err())
}

#[no_mangle]
pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_stop(
    _env: JNIEnv<'_>,
    _object: JObject<'_>,
) -> jboolean {
    if stop_runtime() {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "system" fn Java_com_example_p2wlan_1flutter_1client_P2wlanNative_isRunning(
    _env: JNIEnv<'_>,
    _object: JObject<'_>,
) -> jboolean {
    if runtime_running() {
        1
    } else {
        0
    }
}
