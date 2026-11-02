use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "windows"
))]
use std::process::Command;
use std::sync::Mutex;
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "windows"
))]
use tracing::info;
#[cfg(target_os = "windows")]
use tracing::warn;

#[cfg(target_os = "windows")]
const WINDOWS_ROUTE_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

include!("route/common.rs");
include!("route/linux.rs");
include!("route/macos.rs");
include!("route/windows.rs");
include!("route/unsupported.rs");
include!("route/tests.rs");
