//! Atomic Unix config publication within one pinned directory. The desktop
//! preparation command owns path authorization; this writer never follows a
//! config/temp link or derives ownership from an environment variable.

use fs2::FileExt;
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy)]
struct ConfigOwner {
    uid: u32,
    gid: u32,
    elevated: bool,
}

impl ConfigOwner {
    fn from_directory(directory: &Metadata) -> Self {
        let elevated = unsafe { libc::geteuid() } == 0;
        Self {
            uid: if elevated {
                directory.uid()
            } else {
                unsafe { libc::geteuid() }
            },
            gid: directory.gid(),
            elevated,
        }
    }

    fn accepts_existing_uid(self, uid: u32) -> bool {
        uid == self.uid || (self.elevated && uid == 0)
    }
}

fn file_name(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "config name contains NUL"))
}

fn inspect_target(
    directory: &File,
    name: &CString,
    owner: ConfigOwner,
) -> io::Result<Option<(FileIdentity, File)>> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    // openat returned a new descriptor, which this File owns exactly once.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config target must be a regular file with one link",
        ));
    }
    if !owner.accepts_existing_uid(metadata.uid()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "config target belongs to a different user",
        ));
    }
    Ok(Some((
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        file,
    )))
}

struct PendingConfig<'a> {
    directory: &'a File,
    name: CString,
    file: File,
    published: bool,
}

impl<'a> PendingConfig<'a> {
    fn create(directory: &'a File) -> io::Result<Self> {
        for _ in 0..8 {
            let name = CString::new(format!(
                ".p2wlan-config-{:032x}.tmp",
                rand::random::<u128>()
            ))
            .expect("fixed hexadecimal temporary name has no NUL");
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd >= 0 {
                return Ok(Self {
                    directory,
                    name,
                    file: unsafe { File::from_raw_fd(fd) },
                    published: false,
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "config temporary name collision budget exhausted",
        ))
    }
}

impl Drop for PendingConfig<'_> {
    fn drop(&mut self) {
        if !self.published {
            // The random name belongs to this exclusive creation and all
            // operations remain relative to the same directory descriptor.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

pub(super) fn save(
    path: &Path,
    content: &[u8],
    expected_protection: Option<&super::IdentityProtection>,
) -> io::Result<()> {
    let name = file_name(path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "config path has no file name")
    })?)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(parent)?;
    let directory_metadata = directory.metadata()?;
    let owner = ConfigOwner::from_directory(&directory_metadata);
    // Scope the short publication lock to this pinned directory descriptor.
    // Inspect and compare the current envelope before creating a temp file.
    directory.try_lock_exclusive()?;
    let expected = match inspect_target(&directory, &name, owner)? {
        Some((identity, file)) => {
            super::check_identity_protection_before_save(file, expected_protection)?;
            Some(identity)
        }
        None => None,
    };
    let mut pending = PendingConfig::create(&directory)?;
    if owner.elevated
        && unsafe { libc::fchown(pending.file.as_raw_fd(), owner.uid, owner.gid) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    pending
        .file
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    pending.file.write_all(content)?;
    pending.file.sync_all()?;

    let current_directory = directory.metadata()?;
    if (current_directory.uid(), current_directory.gid())
        != (directory_metadata.uid(), directory_metadata.gid())
        || inspect_target(&directory, &name, owner)?.map(|(identity, _)| identity) != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "config directory ownership or target changed during save",
        ));
    }
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            pending.name.as_ptr(),
            directory.as_raw_fd(),
            name.as_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    pending.published = true;
    directory.sync_all()
}
