use std::{
    env,
    error::Error,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
use std::io::Write;

#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;

use tao::{
    event::{Event, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
    Icon, TrayIcon, TrayIconBuilder,
};

const STATUS_URL: &str = p2wlan_desktop_host::DEFAULT_DIAGNOSTICS_STATUS_URL;
const COPY_PEER_IP_PREFIX: &str = "copy-peer-ip:";
const MAX_TRAY_DEVICES: usize = 12;
const DAEMON_NAME: &str = if cfg!(windows) {
    "p2wlan-daemon.exe"
} else {
    "p2wlan-daemon"
};

include!("main/model.rs");
include!("main/runtime.rs");
include!("main/app.rs");
include!("main/status.rs");
include!("main/daemon.rs");
include!("main/external.rs");
include!("main/macos.rs");
