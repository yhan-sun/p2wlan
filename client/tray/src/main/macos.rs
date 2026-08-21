#[cfg(target_os = "macos")]
fn user_owner_for_paths() -> Option<String> {
    for key in ["SUDO_USER", "USER", "LOGNAME"] {
        let value = env::var(key).ok()?;
        if !value.trim().is_empty() && value != "root" {
            return Some(value);
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
