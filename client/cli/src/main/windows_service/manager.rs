#[path = "scm.rs"]
mod scm;

use super::ServiceCommand;
use p2pnet_daemon::incarnation::{read_boot_incarnation, INCARNATION_FILE_NAME};
use p2pnet_daemon::windows_service_paths::{self as paths, ServicePaths};
use p2pnet_daemon::{same_windows_device, Config, WindowsIdentityLease};
use std::io::{self, Read};
use std::path::Path;

pub(super) fn run(source: &Path, command: ServiceCommand) -> Result<(), String> {
    match command {
        ServiceCommand::Status { json } => status(json),
        ServiceCommand::Install { migrate_identity } => {
            if !migrate_identity {
                return Err("迁移前必须显式确认 --migrate-identity".into());
            }
            install(source)
        }
        ServiceCommand::Uninstall => uninstall(),
    }
}

fn read_config(path: &Path) -> Result<Config, String> {
    const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
    let file = paths::open_regular_file(path).map_err(|e| format!("无法安全读取身份配置：{e}"))?;
    let mut content = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(admin_error)?;
    if content.len() > MAX_CONFIG_BYTES as usize {
        return Err("身份配置超过 1 MiB".into());
    }
    serde_json::from_slice(&content).map_err(|_| "身份配置 JSON 不合法".into())
}

fn machine_config(path: &Path) -> Result<Config, String> {
    let mut config = read_config(path)?;
    let url = reqwest::Url::parse(&config.control.server_url)
        .map_err(|_| "控制面地址必须为 HTTPS URL")?;
    if config.network.manual
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || config.control.device_credential.trim().is_empty()
        || !config.control.credential_issued
    {
        return Err(
            "请先使用 HTTPS 控制面启动所选配置并等待设备凭据签发，再停止桌面 daemon 后迁移".into(),
        );
    }
    if config.relay.ca_cert_path.is_some() {
        return Err("迁移前请移除用户配置中的自定义 Relay CA 文件路径，或继续使用桌面模式".into());
    }
    config.control.auth_token.clear();
    config.network.overlay_start_gate_file = None;
    config.diagnostics.enabled = true;
    config.diagnostics.bind = "127.0.0.1:39287".into();
    config.diagnostics.resource_capture = false;
    config.diagnostics.auth_token = None;
    config.diagnostics.auth_token_path = None;
    config.diagnostics.log_path = None;
    Ok(config)
}

fn install(source: &Path) -> Result<(), String> {
    let manager = scm::Manager::with_install_access().map_err(admin_error)?;
    let paths = ServicePaths::resolve().map_err(admin_error)?;
    paths.validate_installation().map_err(|e| {
        format!("请从官方安装包选择为所有用户安装到 Program Files\\P2WLAN 后再启用系统服务：{e}")
    })?;
    let provisioning = WindowsIdentityLease::acquire_provisioning().map_err(admin_error)?;
    paths
        .prepare_profile()
        .map_err(|e| format!("机器配置目录未通过权限检查：{e}"))?;
    let args = paths.command_line().map_err(admin_error)?;
    let existing = manager.open_for_install().map_err(admin_error)?;
    if let Some(service) = &existing {
        service.verify(&args).map_err(admin_error)?;
    }
    let config = machine_config(source)?;
    let configuration = paths.config();
    println!(
        "设备身份将用于 Windows 开机服务。机器配置仅允许 SYSTEM 和管理员访问，原用户配置保留。"
    );
    if configuration.exists() {
        let mut machine = read_config(&configuration)?;
        if !same_windows_device(&config, &machine) {
            return Err(
                "机器配置已关联另一台设备。请停止服务并由管理员备份该机器配置后再迁移".into(),
            );
        }
        if machine.control.device_credential != config.control.device_credential {
            let _lease = WindowsIdentityLease::acquire(&config)
                .map_err(|e| format!("请先停用开机服务并断开桌面设备，再更新设备凭据：{e}"))?;
            if let Some(service) = &existing {
                service.ensure_stopped().map_err(admin_error)?;
            }
            let fresh = machine_config(source)?;
            if !same_windows_device(&fresh, &machine) {
                return Err("源配置中的设备身份已变化，请重新确认要迁移的设备".into());
            }
            machine.control.device_credential = fresh.control.device_credential;
            machine.control.credential_issued = true;
            machine.control.auth_token.clear();
            machine
                .save_to_file(&configuration)
                .map_err(|e| e.to_string())?;
        }
    } else {
        // An existing desktop process may update its credential while shutting
        // down. Acquire the startup identity lease while taking the snapshot.
        let _lease = WindowsIdentityLease::acquire(&config)
            .map_err(|e| format!("请从桌面客户端断开所选设备后重试：{e}"))?;
        migrate_profile(&paths, source, &config)?;
    }
    let profile = if config.network.network_id.starts_with("room-") {
        scm::Profile::Room
    } else {
        scm::Profile::Personal
    };
    let service = match existing {
        Some(service) => service,
        None => manager.create(&args).map_err(admin_error)?,
    };
    service.configure(profile).map_err(admin_error)?;
    drop(provisioning);
    service.start().map_err(admin_error)?;
    println!("P2WLAN 开机服务已启动。设备在线状态请在控制面查看。");
    Ok(())
}

fn migrate_profile(paths: &ServicePaths, source: &Path, original: &Config) -> Result<(), String> {
    let config = machine_config(source)?;
    if !same_windows_device(original, &config) {
        return Err("源配置中的设备身份已变化，请重新确认要迁移的设备".into());
    }
    let source_counter = source.with_file_name(INCARNATION_FILE_NAME);
    let counter_file = paths::open_regular_file(&source_counter)
        .map_err(|e| format!("无法安全读取当前注册代数。请先启动一次所选桌面配置：{e}"))?;
    let state = read_boot_incarnation(counter_file).map_err(admin_error)?;
    let content = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    paths
        .write_new_private_file(&paths.root.join(INCARNATION_FILE_NAME), &content)
        .map_err(admin_error)?;
    paths
        .write_new_private_file(&paths.root.join("incarnation.lock"), b"")
        .map_err(admin_error)?;
    let content = serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?;
    paths
        .write_new_private_file(&paths.config(), &content)
        .map_err(admin_error)
}

fn uninstall() -> Result<(), String> {
    let manager = scm::Manager::read_only().map_err(admin_error)?;
    let Some(service) = manager.open_for_uninstall().map_err(admin_error)? else {
        println!("P2WLAN 开机服务未安装。");
        return Ok(());
    };
    let paths = ServicePaths::resolve().map_err(admin_error)?;
    service
        .verify(&paths.command_line().map_err(admin_error)?)
        .map_err(admin_error)?;
    service.stop_and_delete().map_err(admin_error)?;
    println!("P2WLAN 开机服务已移除，管理员专用机器配置已保留。");
    Ok(())
}

fn status(json: bool) -> Result<(), String> {
    let manager = scm::Manager::read_only().map_err(admin_error)?;
    let status = manager.status().map_err(admin_error)?;
    if json {
        println!("{status}");
    } else {
        println!(
            "P2WLAN 开机服务：{}",
            status["state"].as_str().unwrap_or("unknown")
        );
    }
    Ok(())
}

fn admin_error(error: io::Error) -> String {
    if error.kind() == io::ErrorKind::PermissionDenied {
        format!("请在提升权限的管理员终端中运行命令，并确认路径和服务权限：{error}")
    } else {
        format!("Windows 服务操作失败：{error}")
    }
}
