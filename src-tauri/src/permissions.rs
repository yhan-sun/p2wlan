use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::path::Path;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(unix)]
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
    #[cfg(target_os = "macos")]
    let mut details: Vec<String> = Vec::new();
    #[cfg(any(
        target_os = "linux",
        not(any(target_os = "macos", target_os = "windows"))
    ))]
    let details: Vec<String> = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let euid = get_euid();
        let is_root = euid == 0;

        checks.push(PermissionCheck {
            id: "root_user".to_string(),
            label: "有效用户权限".to_string(),
            status: if is_root {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            detail: if is_root {
                format!("已以 root 身份运行 (euid={})", euid)
            } else {
                format!("当前是普通用户 (euid={})，TUN 创建和路由修改会失败。", euid)
            },
        });

        let dev_tun_exists = Path::new("/dev/net/tun").exists() || Path::new("/dev/tun").exists();
        checks.push(PermissionCheck {
            id: "dev_tun".to_string(),
            label: "TUN 设备节点".to_string(),
            status: if dev_tun_exists {
                "pass".to_string()
            } else {
                "warn".to_string()
            },
            detail: if dev_tun_exists {
                "/dev 中存在 TUN 设备节点".to_string()
            } else {
                "未找到标准 /dev/net/tun。macOS 使用动态 utun 网卡，需要 root 权限。".to_string()
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
            "请通过管理员授权启动 p2pnet-daemon，以允许创建虚拟网卡和修改路由。".to_string()
        } else {
            "权限已满足，TUN 创建仍需运行时验证。".to_string()
        };

        if needs_elevation {
            details.push("当前进程缺少网络接口 ioctl 调用所需的 root 权限。".to_string());
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
            label: "有效用户权限".to_string(),
            status: if is_root {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            detail: if is_root {
                format!("已以 root 身份运行 (euid={})", euid)
            } else {
                format!(
                    "当前是普通用户 (euid={})，需要 root 或 cap_net_admin 能力。",
                    euid
                )
            },
        });

        let dev_net_tun = Path::new("/dev/net/tun").exists();
        checks.push(PermissionCheck {
            id: "dev_net_tun".to_string(),
            label: "TUN 设备路径 /dev/net/tun".to_string(),
            status: if dev_net_tun {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            detail: if dev_net_tun {
                "/dev/net/tun 设备节点可访问".to_string()
            } else {
                "未找到 /dev/net/tun，无法创建 TUN 网卡。".to_string()
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
            "请使用 sudo 启动 daemon，或通过 setcap 给二进制添加 CAP_NET_ADMIN：sudo setcap cap_net_admin+ep <path>".to_string()
        } else {
            "权限已满足，daemon 可以创建网卡并修改路由。".to_string()
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
            label: "Windows 管理员权限".to_string(),
            status: if is_admin { "pass" } else { "fail" }.to_string(),
            detail: if is_admin {
                "当前已具备管理员权限。".to_string()
            } else {
                "安装 Wintun 虚拟网卡和更新路由需要管理员权限。".to_string()
            },
        });
        checks.push(PermissionCheck {
            id: "wintun_dll".to_string(),
            label: "Wintun 运行库".to_string(),
            status: if wintun_path.is_some() {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            detail: wintun_path
                .as_ref()
                .map(|path| format!("已找到 wintun.dll：{}", path.display()))
                .unwrap_or_else(|| {
                    "未在客户端/daemon 同级目录、P2WLAN_WINTUN_DLL 或 PATH 中找到 wintun.dll。"
                        .to_string()
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
                "Windows 管理员权限和 Wintun 运行库均已就绪。".to_string()
            } else if !is_admin {
                "请点击“授权启动 TUN”，并在 Windows UAC 弹窗中确认。请确保 wintun.dll 与 p2pnet-daemon.exe 在同一目录，或设置 P2WLAN_WINTUN_DLL。".to_string()
            } else {
                "请把 wintun.dll 放到 p2pnet-daemon.exe 或桌面客户端同级目录，或设置 P2WLAN_WINTUN_DLL。".to_string()
            },
            sudo_command: None,
            details: vec![
                "Windows TUN 模式使用 Wintun，需要管理员授权。".to_string(),
                "p2wlan 不会读取或保存 Windows 密码，UAC 授权由系统完成。".to_string(),
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
            recommended_action: "请确保 daemon 以 root 或网络管理员权限运行。".to_string(),
            sudo_command: None,
            details: vec!["检测到暂不支持的平台。".to_string()],
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
