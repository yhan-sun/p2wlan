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

include!("windows/api.rs");
include!("windows/device.rs");
include!("windows/helpers.rs");
