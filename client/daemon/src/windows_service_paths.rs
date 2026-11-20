use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE,
    OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
};

const PRIVATE_FILE_SDDL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
const PRIVATE_SDDL: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const SYSTEM_SID: &str = "S-1-5-18";
const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const INSTALLER_SID: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
// File write/append, write EA/attributes, delete-child, DELETE, WRITE_DAC,
// WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE.
const WRITE_ACCESS: u32 = 0x500d_0156;
const REPLACE_ACCESS: u32 = 0x500d_0040;

pub struct ServicePaths {
    pub root: PathBuf,
    pub app: PathBuf,
}

impl ServicePaths {
    pub fn resolve() -> io::Result<Self> {
        Ok(Self {
            root: known_folder(&FOLDERID_ProgramData)?.join("p2wlan"),
            app: known_folder(&FOLDERID_ProgramFiles)?.join("P2WLAN"),
        })
    }

    pub fn config(&self) -> PathBuf {
        self.root.join("p2wlan-config.json")
    }

    pub fn command_line(&self) -> io::Result<OsString> {
        let mut command = quoted(&self.app.join("p2wlan-daemon.exe"))?;
        command.push(" --windows-service --windows-service-name P2WLAN --config ");
        command.push(quoted(&self.config())?);
        command.push(" --log-file ");
        command.push(quoted(&self.root.join("p2wlan-daemon.log"))?);
        Ok(command)
    }

    pub fn validate_installation(&self) -> io::Result<()> {
        no_reparse_ancestors(&self.app)?;
        let parent = self.app.parent().ok_or_else(access_denied)?;
        check_acl(parent, REPLACE_ACCESS, true)?;
        check_acl(&self.app, WRITE_ACCESS, true)?;
        for entry in fs::read_dir(&self.app)? {
            let path = entry?.path();
            let is_dll = path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"));
            if is_dll {
                regular_file(&path)?;
                check_acl(&path, WRITE_ACCESS, true)?;
            }
        }
        for path in [
            self.app.join("p2wlan-daemon.exe"),
            self.app.join("wintun.dll"),
        ] {
            regular_file(&path)?;
            check_acl(&path, WRITE_ACCESS, true)?;
        }
        Ok(())
    }

    pub fn prepare_profile(&self) -> io::Result<()> {
        let parent = self.root.parent().ok_or_else(access_denied)?;
        no_reparse_ancestors(parent)?;
        check_acl(parent, REPLACE_ACCESS, true)?;
        let descriptor = LocalAllocation::descriptor(PRIVATE_SDDL)?;
        let attrs = descriptor.attributes();
        if unsafe { CreateDirectoryW(wide(self.root.as_os_str()).as_ptr(), &attrs) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error);
            }
        }
        self.check_profile_root()?;
        for entry in fs::read_dir(&self.root)? {
            self.check_private_file(&entry?.path())?;
        }
        Ok(())
    }

    pub fn check_profile_root(&self) -> io::Result<()> {
        no_reparse_ancestors(&self.root)?;
        check_acl(
            self.root.parent().ok_or_else(access_denied)?,
            REPLACE_ACCESS,
            true,
        )?;
        check_acl(&self.root, u32::MAX, false)
    }

    pub fn check_private_file(&self, path: &Path) -> io::Result<()> {
        regular_file(path)?;
        check_acl(path, u32::MAX, false)
    }

    pub fn write_new_private_file(&self, path: &Path, content: &[u8]) -> io::Result<()> {
        // Separate administrative CLI and daemon temporary writes so a retry
        // cannot remove another process's in-flight replacement.
        let tmp = path.with_extension(format!("migration-tmp-{}", std::process::id()));
        let descriptor = LocalAllocation::descriptor(PRIVATE_FILE_SDDL)?;
        let attrs = descriptor.attributes();
        match fs::remove_file(&tmp) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let handle = unsafe {
            CreateFileW(
                wide(tmp.as_os_str()).as_ptr(),
                GENERIC_WRITE,
                0,
                &attrs,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut file = unsafe { fs::File::from_raw_handle(handle.cast()) };
            file.write_all(content)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

pub fn regular_file(path: &Path) -> io::Result<()> {
    open_regular_file(path).map(|_| ())
}

/// Open a local profile input without following a reparse point as its file.
pub fn open_regular_file(path: &Path) -> io::Result<fs::File> {
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        no_reparse_ancestors(parent)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || is_reparse(&metadata) {
        return Err(access_denied());
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.nNumberOfLinks != 1 || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(access_denied());
    }
    Ok(file)
}

fn no_reparse_ancestors(path: &Path) -> io::Result<()> {
    for path in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || is_reparse(&metadata) {
            return Err(access_denied());
        }
    }
    Ok(())
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn quoted(path: &Path) -> io::Result<OsString> {
    if path.as_os_str().encode_wide().any(|c| matches!(c, 0 | 34)) || !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid service path",
        ));
    }
    let mut value = OsString::from("\"");
    value.push(path);
    value.push("\"");
    Ok(value)
}

pub fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain([0]).collect()
}

/// # Safety
/// The pointer must reference a terminated UTF-16 string valid for the returned lifetime.
pub unsafe fn nul_terminated<'a>(value: *const u16) -> &'a [u16] {
    let len = (0..).take_while(|&i| *value.add(i) != 0).count();
    std::slice::from_raw_parts(value, len)
}

fn known_folder(id: &GUID) -> io::Result<PathBuf> {
    let mut value = null_mut();
    let status = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut value) };
    let result = if status < 0 || value.is_null() {
        Err(io::Error::other(format!(
            "SHGetKnownFolderPath failed: {status:#x}"
        )))
    } else {
        Ok(PathBuf::from(OsString::from_wide(unsafe {
            nul_terminated(value)
        })))
    };
    unsafe { CoTaskMemFree(value.cast()) };
    result
}

struct LocalAllocation(*mut std::ffi::c_void);

impl LocalAllocation {
    fn descriptor(sddl: &str) -> io::Result<Self> {
        let mut descriptor = Self(null_mut());
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor.0,
                null_mut(),
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(descriptor)
        }
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn check_acl(path: &Path, mask: u32, allow_installer: bool) -> io::Result<()> {
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = LocalAllocation(null_mut());
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide(path.as_os_str()).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor.0,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if dacl.is_null() || !trusted_sid(owner, allow_installer)? {
        return Err(access_denied());
    }
    for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 && allow_installer {
            continue;
        }
        match header.AceType {
            // ACCESS_ALLOWED_ACE_TYPE. Any unconventional allow ACE fails closed.
            0 => {
                if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                    return Err(access_denied());
                }
                let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
                if ace.Mask & mask != 0 && !trusted_sid(sid, allow_installer)? {
                    return Err(access_denied());
                }
            }
            // Deny ACEs cannot grant access.
            1 | 6 | 10 | 12 => (),
            _ => return Err(access_denied()),
        }
    }
    Ok(())
}

fn trusted_sid(sid: *mut std::ffi::c_void, allow_installer: bool) -> io::Result<bool> {
    let mut value = null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(access_denied());
    }
    let allocation = LocalAllocation(value.cast());
    let sid = String::from_utf16_lossy(unsafe { nul_terminated(allocation.0.cast()) });
    Ok(matches!(sid.as_str(), SYSTEM_SID | ADMINISTRATORS_SID)
        || allow_installer && sid == INSTALLER_SID)
}

fn access_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "service path or security descriptor is unsafe",
    )
}
