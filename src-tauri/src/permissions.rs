use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::Path;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::Command;

use crate::daemon_manager::DaemonManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCheck {
    pub id: String,
    pub label: String,
    pub status: String, // "pass" | "warn" | "fail" | "unknown"
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionStatus {
    pub platform: String,
    pub can_create_tun: String,    // "true" | "false" | "unknown"
    pub can_modify_routes: String, // "true" | "false" | "unknown"
    pub needs_elevation: bool,
    pub recommended_action: String,
    pub sudo_command: Option<String>,
    pub details: Vec<String>,
    pub checks: Vec<PermissionCheck>,
}

#[cfg(unix)]
fn get_euid() -> u32 {
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(unix)]
fn suggested_sudo_command() -> String {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let daemon_path = DaemonManager::resolve_daemon_binary(Some("P2WLAN_DAEMON_BIN"), &current_dir)
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "p2pnet-daemon".to_string());
    let quoted = shell_quote(&daemon_path);
    let config_path = DaemonManager::default_config_path();
    let quoted_config = shell_quote(&config_path.display().to_string());
    format!(
        "sudo -E P2WLAN_DAEMON_BIN={} {} --config {} --diagnostics-bind 127.0.0.1:39277",
        quoted, quoted, quoted_config
    )
}

#[cfg(target_os = "windows")]
fn is_windows_administrator() -> bool {
    Command::new("net")
        .arg("session")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
fn wintun_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = std::env::var("P2WLAN_WINTUN_DLL") {
        if !path.trim().is_empty() {
            paths.push(PathBuf::from(path));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("wintun.dll"));
        }
    }
    if let Ok(dir) = std::env::current_dir() {
        paths.push(dir.join("wintun.dll"));
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&path_var).map(|path| path.join("wintun.dll")));
    }
    paths
}

#[cfg(target_os = "windows")]
fn find_wintun_dll() -> Option<PathBuf> {
    wintun_search_paths().into_iter().find(|path| path.exists())
}

pub fn check_permission_status() -> PermissionStatus {
    let mut checks = Vec::new();
    let mut details = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let euid = get_euid();
        let is_root = euid == 0;

        checks.push(PermissionCheck {
            id: "root_user".to_string(),
            label: "Effective User ID Check".to_string(),
            status: if is_root {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            detail: if is_root {
                format!("Running as root (euid={})", euid)
            } else {
                format!(
                    "Running as standard user (euid={}). TUN and routing changes will fail.",
                    euid
                )
            },
        });

        let dev_tun_exists = Path::new("/dev/net/tun").exists() || Path::new("/dev/tun").exists();
        checks.push(PermissionCheck {
            id: "dev_tun".to_string(),
            label: "TUN Device node".to_string(),
            status: if dev_tun_exists { "pass".to_string() } else { "warn".to_string() },
            detail: if dev_tun_exists {
                "TUN device node exists in /dev".to_string()
            } else {
                "Standard /dev/net/tun not found. macOS uses dynamic utun interfaces, which requires root euid.".to_string()
            },
        });

        let needs_elevation = !is_root;
        let can_create_tun = if is_root {
            // macOS utun creation is dynamic and has no stable /dev node to probe safely.
            // Root is necessary, but this check deliberately avoids claiming success
            // without performing a destructive interface operation.
            "unknown".to_string()
        } else {
            "false".to_string()
        };
        let can_modify_routes = if is_root {
            "true".to_string()
        } else {
            "false".to_string()
        };

        let recommended_action = if needs_elevation {
            "Start p2pnet-daemon with sudo to allow virtual adapter creation and routing updates."
                .to_string()
        } else {
            "Elevation is available. TUN creation still needs runtime verification.".to_string()
        };

        if needs_elevation {
            details.push(
                "Process lacks root privileges required for ioctl calls on network interfaces."
                    .to_string(),
            );
        }

        PermissionStatus {
            platform: "macos".to_string(),
            can_create_tun,
            can_modify_routes,
            needs_elevation,
            recommended_action,
            sudo_command: if needs_elevation {
                Some(suggested_sudo_command())
            } else {
                None
            },
            details,
            checks,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let euid = get_euid();
        let is_root = euid == 0;

        checks.push(PermissionCheck {
            id: "root_user".to_string(),
            label: "Effective User ID Check".to_string(),
            status: if is_root { "pass".to_string() } else { "fail".to_string() },
            detail: if is_root {
                format!("Running as root (euid={})", euid)
            } else {
                format!("Running as standard user (euid={}). cap_net_admin capability needed otherwise.", euid)
            },
        });

        let dev_net_tun = Path::new("/dev/net/tun").exists();
        checks.push(PermissionCheck {
            id: "dev_net_tun".to_string(),
            label: "TUN device path /dev/net/tun".to_string(),
            status: if dev_net_tun {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            detail: if dev_net_tun {
                "/dev/net/tun device node is accessible".to_string()
            } else {
                "/dev/net/tun not found. TUN adapter creation is impossible.".to_string()
            },
        });

        let needs_elevation = !is_root;
        let can_create_tun = if is_root {
            "true".to_string()
        } else {
            "unknown".to_string()
        };
        let can_modify_routes = if is_root {
            "true".to_string()
        } else {
            "unknown".to_string()
        };

        let recommended_action = if needs_elevation {
            "Run daemon with sudo or apply CAP_NET_ADMIN capabilities to the binary using setcap: sudo setcap cap_net_admin+ep <path>".to_string()
        } else {
            "Ready. Daemon has sufficient privileges.".to_string()
        };

        PermissionStatus {
            platform: "linux".to_string(),
            can_create_tun,
            can_modify_routes,
            needs_elevation,
            recommended_action,
            sudo_command: if needs_elevation {
                Some(suggested_sudo_command())
            } else {
                None
            },
            details,
            checks,
        }
    }

    #[cfg(target_os = "windows")]
    {
        let is_admin = is_windows_administrator();
        let wintun_path = find_wintun_dll();

        checks.push(PermissionCheck {
            id: "win_admin".to_string(),
            label: "Windows Administrator".to_string(),
            status: if is_admin { "pass" } else { "fail" }.to_string(),
            detail: if is_admin {
                "Running with Administrator privileges.".to_string()
            } else {
                "Administrator privileges are required to install Wintun adapters and update routes.".to_string()
            },
        });
        checks.push(PermissionCheck {
            id: "wintun_dll".to_string(),
            label: "Wintun runtime".to_string(),
            status: if wintun_path.is_some() { "pass" } else { "fail" }.to_string(),
            detail: wintun_path
                .as_ref()
                .map(|path| format!("Found wintun.dll at {}", path.display()))
                .unwrap_or_else(|| {
                    "wintun.dll was not found next to the app/daemon, in P2WLAN_WINTUN_DLL, or in PATH.".to_string()
                }),
        });

        PermissionStatus {
            platform: "windows".to_string(),
            can_create_tun: if is_admin && wintun_path.is_some() {
                "true".to_string()
            } else {
                "false".to_string()
            },
            can_modify_routes: if is_admin {
                "true".to_string()
            } else {
                "false".to_string()
            },
            needs_elevation: !is_admin,
            recommended_action: if is_admin && wintun_path.is_some() {
                "Ready. Windows has Administrator privileges and Wintun runtime is available."
                    .to_string()
            } else if !is_admin {
                "Click Authorize TUN to approve Windows UAC. Keep wintun.dll next to p2pnet-daemon.exe or set P2WLAN_WINTUN_DLL.".to_string()
            } else {
                "Place wintun.dll next to p2pnet-daemon.exe, next to the desktop app, or set P2WLAN_WINTUN_DLL.".to_string()
            },
            sudo_command: None,
            details: vec![
                "Windows TUN mode uses Wintun and requires Administrator approval.".to_string(),
                "The desktop app does not store the Windows password; UAC is handled by the operating system.".to_string(),
            ],
            checks,
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        PermissionStatus {
            platform: "unknown".to_string(),
            can_create_tun: "unknown".to_string(),
            can_modify_routes: "unknown".to_string(),
            needs_elevation: true,
            recommended_action:
                "Ensure daemon is executed with root or network admin capabilities.".to_string(),
            sudo_command: None,
            details: vec!["Unsupported platform detected.".to_string()],
            checks,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_diagnostics_structure() {
        let status = check_permission_status();
        assert!(!status.platform.is_empty());
        assert!(!status.checks.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn shell_quote_handles_spaces_and_quotes() {
        assert_eq!(shell_quote("/tmp/p2 wlan/bin"), "'/tmp/p2 wlan/bin'");
        assert_eq!(shell_quote("/tmp/p2'wlan/bin"), "'/tmp/p2'\\''wlan/bin'");
    }
}
