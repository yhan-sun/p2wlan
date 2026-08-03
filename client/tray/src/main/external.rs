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
    let size = 32_u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let primary = if running {
        [0x16, 0xa3, 0x4a, 0xff]
    } else {
        [0x94, 0xa3, 0xb8, 0xff]
    };
    for y in 0..size {
        for x in 0..size {
            let dx = x as i32 - 16;
            let dy = y as i32 - 16;
            let distance_sq = dx * dx + dy * dy;
            let pixel = if (7 * 7..=12 * 12).contains(&distance_sq) {
                primary
            } else if (12..=20).contains(&x) && (12..=20).contains(&y) {
                [0x0f, 0x17, 0x2a, 0xff]
            } else {
                [0, 0, 0, 0]
            };
            rgba.extend_from_slice(&pixel);
        }
    }
    Ok(Icon::from_rgba(rgba, size, size)?)
}
