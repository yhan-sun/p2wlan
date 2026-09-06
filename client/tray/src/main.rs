use std::{
    env,
    error::Error,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
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
use std::process::Stdio;

use trayicon::{Icon, MenuBuilder, TrayIcon, TrayIconBuilder};
use winit::{
    application::ApplicationHandler,
    event::WindowEvent,
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy},
    window::WindowId,
};

#[cfg(target_os = "macos")]
use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};

const STATUS_URL: &str = p2wlan_desktop_host::DEFAULT_DIAGNOSTICS_STATUS_URL;
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
