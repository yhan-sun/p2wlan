fn open_flutter_client() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    {
        let app = find_flutter_app()
            .ok_or("未找到 Flutter 版 P2WLAN.app；请先运行 flutter build macos --debug")?;
        let status = Command::new("open").arg(app).status()?;
        if status.success() {
            Ok(())
        } else {
            Err("open command failed".into())
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let binary = if cfg!(windows) {
            "P2WLAN.exe"
        } else {
            "p2wlan_flutter_client"
        };
        Command::new(binary).spawn()?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn find_flutter_app() -> Option<PathBuf> {
    if let Some(path) = env::var_os("P2WLAN_FLUTTER_APP").map(PathBuf::from) {
        if path.exists() {
            return Some(path);
        }
    }
    let root = find_repo_root()?;
    [
        root.join("apps/flutter_client/build/macos/Build/Products/Debug/P2WLAN.app"),
        root.join("apps/flutter_client/build/macos/Build/Products/Release/P2WLAN.app"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

fn find_repo_root() -> Option<PathBuf> {
    let mut starts = Vec::new();
    if let Ok(current_dir) = env::current_dir() {
        starts.push(current_dir);
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            starts.push(parent.to_path_buf());
        }
    }

    for mut dir in starts {
        for _ in 0..12 {
            if dir.join("Cargo.toml").exists() && dir.join("client").exists() {
                return Some(dir);
            }
            if !dir.pop() {
                break;
            }
        }
    }
    None
}

fn open_log_directory() -> Result<(), Box<dyn Error>> {
    let dir = p2wlan_desktop_host::default_log_dir();
    fs::create_dir_all(&dir)?;
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("open").arg(&dir).status()?;
        if status.success() {
            Ok(())
        } else {
            Err("open logs command failed".into())
        }
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("explorer").arg(&dir).spawn()?;
        Ok(())
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        Command::new("xdg-open").arg(&dir).spawn()?;
        Ok(())
    }
}

fn copy_to_clipboard(value: &str) -> Result<(), Box<dyn Error>> {
    let mut clipboard = arboard::Clipboard::new()?;
    clipboard.set_text(value.to_string())?;
    Ok(())
}

fn tray_icon_image(running: bool) -> Result<Icon, Box<dyn Error>> {
    static TRAY_ICON_OFF: &[u8] = include_bytes!("../../assets/tray_icon_off.ico");
    static TRAY_ICON_ON: &[u8] = include_bytes!("../../assets/tray_icon_on.ico");
    let buffer = if running { TRAY_ICON_ON } else { TRAY_ICON_OFF };
    Ok(Icon::from_buffer(buffer, None, None)?)
}
