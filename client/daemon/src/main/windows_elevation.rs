/// Return whether the daemon's own process token is genuinely elevated.
///
/// This deliberately inspects the access token instead of asking PowerShell
/// whether the account belongs to Administrators. A filtered UAC token can
/// belong to that group while still lacking the elevated token required by
/// Wintun and route configuration.
#[cfg(target_os = "windows")]
fn windows_elevated_token() -> std::io::Result<bool> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe {
            GetLastError()
        } as i32));
    }

    let result = (|| {
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned_length = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned_length,
            )
        } == 0
        {
            return Err(std::io::Error::from_raw_os_error(unsafe {
                GetLastError()
            } as i32));
        }
        Ok(elevation.TokenIsElevated != 0)
    })();

    unsafe {
        CloseHandle(token);
    }
    result
}
