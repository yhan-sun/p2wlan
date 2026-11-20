use p2pnet_daemon::windows_service_paths::{nul_terminated, wide};
use serde_json::{json, Value};
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE,
};
use windows_sys::Win32::System::Services::*;

const NAME: &str = "P2WLAN";
const DELETE: u32 = 0x0001_0000;
const INSTALL_ACCESS: u32 =
    SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START;

#[derive(Clone, Copy)]
pub(super) enum Profile {
    Personal,
    Room,
}

impl Profile {
    fn label(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Room => "room",
        }
    }

    fn description(self) -> String {
        format!("P2WLAN boot-time overlay ({})", self.label())
    }
}

pub(super) struct Manager(Handle);

pub(super) struct Service(Handle);

struct Handle {
    raw: SC_HANDLE,
}

impl Handle {
    fn new(handle: SC_HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { raw: handle })
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.raw) };
    }
}

impl Manager {
    pub(super) fn read_only() -> io::Result<Self> {
        Self::open(SC_MANAGER_CONNECT)
    }

    pub(super) fn with_install_access() -> io::Result<Self> {
        Self::open(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
    }

    fn open(access: u32) -> io::Result<Self> {
        Handle::new(unsafe { OpenSCManagerW(null(), null(), access) }).map(Self)
    }

    fn service(&self, access: u32) -> io::Result<Option<Service>> {
        let handle = unsafe { OpenServiceW(self.0.raw, wide(NAME).as_ptr(), access) };
        match Handle::new(handle) {
            Ok(handle) => Ok(Some(Service(handle))),
            Err(error)
                if matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_SERVICE_DOES_NOT_EXIST | ERROR_SERVICE_MARKED_FOR_DELETE)
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn open_for_install(&self) -> io::Result<Option<Service>> {
        self.service(INSTALL_ACCESS)
    }

    pub(super) fn open_for_uninstall(&self) -> io::Result<Option<Service>> {
        self.service(
            DELETE
                | SERVICE_QUERY_CONFIG
                | SERVICE_CHANGE_CONFIG
                | SERVICE_QUERY_STATUS
                | SERVICE_STOP,
        )
    }

    pub(super) fn create(&self, args: &OsStr) -> io::Result<Service> {
        let handle = unsafe {
            CreateServiceW(
                self.0.raw,
                wide(NAME).as_ptr(),
                wide("P2WLAN boot-time overlay").as_ptr(),
                INSTALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                wide(args).as_ptr(),
                null(),
                null_mut(),
                null(),
                null(), // LocalSystem, no password
                null(),
            )
        };
        Handle::new(handle).map(Service)
    }

    pub(super) fn status(&self) -> io::Result<Value> {
        let Some(service) = self.service(SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)? else {
            return Ok(json!({"installed": false, "state": "not_installed"}));
        };
        let status = service.status()?;
        Ok(json!({
            "installed": true,
            "state": state_label(status.dwCurrentState),
            "profile": service.profile()?.map(Profile::label),
            "exit_code": status.dwWin32ExitCode,
        }))
    }
}

impl Service {
    pub(super) fn ensure_stopped(&self) -> io::Result<()> {
        if self.status()?.dwCurrentState != SERVICE_STOPPED {
            return Err(io::Error::other(
                "service must be stopped before rotating the device credential",
            ));
        }
        Ok(())
    }

    pub(super) fn verify(&self, expected_args: &OsStr) -> io::Result<()> {
        let storage = query_buffer(|output, size, needed| unsafe {
            QueryServiceConfigW(self.0.raw, output.cast(), size, needed)
        })?;
        let config = unsafe { &*storage.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
        let matches = config.dwServiceType == SERVICE_WIN32_OWN_PROCESS
            && !config.lpBinaryPathName.is_null()
            && !config.lpServiceStartName.is_null()
            && unsafe { nul_terminated(config.lpBinaryPathName) }
                .iter()
                .copied()
                .eq(expected_args.encode_wide())
            && String::from_utf16_lossy(unsafe { nul_terminated(config.lpServiceStartName) })
                .eq_ignore_ascii_case("LocalSystem");
        if !matches {
            return Err(io::Error::other(
                "SCM service configuration does not match the P2WLAN product service",
            ));
        }
        Ok(())
    }

    pub(super) fn configure(&self, profile: Profile) -> io::Result<()> {
        self.set_start_type(SERVICE_AUTO_START)?;
        let mut description = wide(profile.description());
        let desc = SERVICE_DESCRIPTIONW {
            lpDescription: description.as_mut_ptr(),
        };
        bool_result(unsafe {
            ChangeServiceConfig2W(
                self.0.raw,
                SERVICE_CONFIG_DESCRIPTION,
                (&desc as *const SERVICE_DESCRIPTIONW).cast(),
            )
        })?;
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 15_000,
            },
            SC_ACTION {
                Type: SC_ACTION_NONE,
                Delay: 0,
            },
        ];
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 3_600,
            lpRebootMsg: null_mut(),
            lpCommand: null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        bool_result(unsafe {
            ChangeServiceConfig2W(
                self.0.raw,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                (&failure as *const SERVICE_FAILURE_ACTIONSW).cast(),
            )
        })?;
        let restart = SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: 1,
        };
        bool_result(unsafe {
            ChangeServiceConfig2W(
                self.0.raw,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                (&restart as *const SERVICE_FAILURE_ACTIONS_FLAG).cast(),
            )
        })
    }

    fn profile(&self) -> io::Result<Option<Profile>> {
        let storage = query_buffer(|output, size, needed| unsafe {
            QueryServiceConfig2W(self.0.raw, SERVICE_CONFIG_DESCRIPTION, output, size, needed)
        })?;
        let desc = unsafe { &*storage.as_ptr().cast::<SERVICE_DESCRIPTIONW>() };
        if desc.lpDescription.is_null() {
            return Ok(None);
        }
        let value = String::from_utf16_lossy(unsafe { nul_terminated(desc.lpDescription) });
        Ok([Profile::Personal, Profile::Room]
            .into_iter()
            .find(|profile| value == profile.description()))
    }

    fn status(&self) -> io::Result<SERVICE_STATUS_PROCESS> {
        let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let mut needed = 0;
        bool_result(unsafe {
            QueryServiceStatusEx(
                self.0.raw,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut needed,
            )
        })?;
        Ok(status)
    }

    pub(super) fn start(&self) -> io::Result<()> {
        let state = self.status()?.dwCurrentState;
        if state == SERVICE_STOP_PENDING {
            self.wait_for(SERVICE_STOPPED)?;
        }
        if state != SERVICE_RUNNING && state != SERVICE_START_PENDING {
            let result = bool_result(unsafe { StartServiceW(self.0.raw, 0, null()) });
            allow_error(result, ERROR_SERVICE_ALREADY_RUNNING)?;
        }
        self.wait_for(SERVICE_RUNNING)
    }

    pub(super) fn stop_and_delete(&self) -> io::Result<()> {
        self.set_start_type(SERVICE_DISABLED)?;
        let state = self.wait_until(|state| state != SERVICE_START_PENDING, false)?;
        if state != SERVICE_STOPPED && state != SERVICE_STOP_PENDING {
            let mut status = unsafe { std::mem::zeroed() };
            allow_error(
                bool_result(unsafe {
                    ControlService(self.0.raw, SERVICE_CONTROL_STOP, &mut status)
                }),
                ERROR_SERVICE_NOT_ACTIVE,
            )?;
        }
        self.wait_for(SERVICE_STOPPED)?;
        allow_error(
            bool_result(unsafe { DeleteService(self.0.raw) }),
            ERROR_SERVICE_MARKED_FOR_DELETE,
        )
    }

    fn wait_for(&self, desired: u32) -> io::Result<()> {
        self.wait_until(|state| state == desired, desired == SERVICE_RUNNING)
            .map(|_| ())
    }

    fn wait_until(&self, ready: impl Fn(u32) -> bool, fail_if_stopped: bool) -> io::Result<u32> {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let status = self.status()?;
            if ready(status.dwCurrentState) {
                return Ok(status.dwCurrentState);
            }
            if fail_if_stopped && status.dwCurrentState == SERVICE_STOPPED {
                return Err(io::Error::other(format!(
                    "service stopped during startup (SCM exit code {})",
                    status.dwWin32ExitCode
                )));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("service is {}", state_label(status.dwCurrentState)),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn set_start_type(&self, start_type: SERVICE_START_TYPE) -> io::Result<()> {
        bool_result(unsafe {
            ChangeServiceConfigW(
                self.0.raw,
                SERVICE_NO_CHANGE,
                start_type,
                SERVICE_NO_CHANGE,
                null(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        })
    }
}

fn state_label(state: u32) -> &'static str {
    match state {
        SERVICE_STOPPED => "stopped",
        SERVICE_START_PENDING => "start_pending",
        SERVICE_STOP_PENDING => "stop_pending",
        SERVICE_RUNNING => "running",
        SERVICE_CONTINUE_PENDING => "continue_pending",
        SERVICE_PAUSE_PENDING => "pause_pending",
        SERVICE_PAUSED => "paused",
        _ => "unknown",
    }
}

fn query_buffer(query: impl Fn(*mut u8, u32, *mut u32) -> i32) -> io::Result<Vec<usize>> {
    let mut needed = 0;
    let result = bool_result(query(null_mut(), 0, &mut needed));
    if result.as_ref().err().and_then(io::Error::raw_os_error)
        != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || !(1..=8192).contains(&needed)
    {
        return Err(result
            .err()
            .unwrap_or_else(|| io::Error::other("invalid SCM response size")));
    }
    let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    bool_result(query(data.as_mut_ptr().cast(), needed, &mut needed))?;
    Ok(data)
}

fn bool_result(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn allow_error(result: io::Result<()>, allowed: u32) -> io::Result<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(allowed as i32) => Ok(()),
        result => result,
    }
}
