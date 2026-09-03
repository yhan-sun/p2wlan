// Windows lifecycle integration points.
//
// The daemon is normally launched as a desktop child, but Windows can also
// deliver termination through console control handlers or the Service
// Control Manager (SCM). Keep those callbacks tiny and communicate with the
// async runtime through an atomic edge. The runtime owns the bounded cleanup
// and the callback never force-terminates the process.

#[cfg(target_os = "windows")]
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(target_os = "windows")]
use std::sync::{Arc, OnceLock};

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{GetLastError, BOOL};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Console::{
    AttachConsole, SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT,
    CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SESSIONCHANGE,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

#[cfg(target_os = "windows")]
const SERVICE_SESSION_LOGOFF: u32 = 0x0000_0006;

#[cfg(target_os = "windows")]
const LIFECYCLE_NONE: u32 = 0;
#[cfg(target_os = "windows")]
const LIFECYCLE_CTRL_C: u32 = 1;
#[cfg(target_os = "windows")]
const LIFECYCLE_CTRL_BREAK: u32 = 2;
#[cfg(target_os = "windows")]
const LIFECYCLE_CTRL_CLOSE: u32 = 3;
#[cfg(target_os = "windows")]
const LIFECYCLE_CTRL_LOGOFF: u32 = 4;
#[cfg(target_os = "windows")]
const LIFECYCLE_CTRL_SHUTDOWN: u32 = 5;
#[cfg(target_os = "windows")]
const LIFECYCLE_SERVICE_STOP: u32 = 6;
#[cfg(target_os = "windows")]
const LIFECYCLE_SERVICE_PRESHUTDOWN: u32 = 7;
#[cfg(target_os = "windows")]
const LIFECYCLE_SERVICE_SHUTDOWN: u32 = 8;
#[cfg(target_os = "windows")]
const LIFECYCLE_SERVICE_LOGOFF: u32 = 9;

/// Cross-thread signal shared by the native Windows callbacks and the Tokio
/// supervisor. The callback only stores the first reason; shutdown remains
/// idempotent when SCM sends STOP followed by SHUTDOWN/PRESHUTDOWN.
#[cfg(target_os = "windows")]
pub(crate) struct WindowsLifecycleSignal {
    reason: AtomicU32,
    completed: AtomicBool,
}

#[cfg(target_os = "windows")]
impl WindowsLifecycleSignal {
    fn new() -> Self {
        Self {
            reason: AtomicU32::new(LIFECYCLE_NONE),
            completed: AtomicBool::new(false),
        }
    }

    fn trigger(&self, reason: u32) {
        let _ = self.reason.compare_exchange(
            LIFECYCLE_NONE,
            reason,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn reason(&self) -> u32 {
        self.reason.load(Ordering::Acquire)
    }

    fn complete(&self) {
        self.completed.store(true, Ordering::Release);
    }

    fn is_complete(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

#[cfg(target_os = "windows")]
static CONSOLE_SIGNAL: OnceLock<Arc<WindowsLifecycleSignal>> = OnceLock::new();

/// Install the process-wide console callback used for Ctrl+C, Ctrl+Break,
/// console close, logoff, and system shutdown. A GUI-subsystem process may
/// have no console at startup; registering the handler is still valid and the
/// callback becomes active if the process attaches to one later.
#[cfg(target_os = "windows")]
pub(crate) fn install_windows_console_handler() -> p2pnet_daemon::Result<Arc<WindowsLifecycleSignal>> {
    let signal = CONSOLE_SIGNAL
        .get_or_init(|| Arc::new(WindowsLifecycleSignal::new()))
        .clone();
    let installed = unsafe { SetConsoleCtrlHandler(Some(windows_console_handler), 1) };
    if installed == 0 {
        return Err(DaemonError::Network(format!(
            "Windows console lifecycle handler registration failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(signal)
}

/// Attach to the parent's console for the dedicated Ctrl+C acceptance
/// harness. This is deliberately opt-in and is never used by the desktop
/// launcher.
#[cfg(target_os = "windows")]
pub(crate) fn attach_windows_parent_console_for_test() -> bool {
    unsafe { AttachConsole(u32::MAX) != 0 }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_console_handler(event: u32) -> BOOL {
    let Some(signal) = CONSOLE_SIGNAL.get() else {
        return 0;
    };

    let reason = match event {
        CTRL_C_EVENT => LIFECYCLE_CTRL_C,
        CTRL_BREAK_EVENT => LIFECYCLE_CTRL_BREAK,
        CTRL_CLOSE_EVENT => LIFECYCLE_CTRL_CLOSE,
        CTRL_LOGOFF_EVENT => LIFECYCLE_CTRL_LOGOFF,
        CTRL_SHUTDOWN_EVENT => LIFECYCLE_CTRL_SHUTDOWN,
        _ => return 0,
    };
    signal.trigger(reason);

    // Windows may terminate a process after a close/logoff/shutdown handler
    // returns. Hold those callbacks until the async cleanup has completed so
    // the process does not skip Wintun/route/socket teardown. Ctrl+C/Break
    // does not have this forced-termination behavior.
    if matches!(
        event,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
    ) {
        while !signal.is_complete() {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }
    1
}

#[cfg(target_os = "windows")]
struct WindowsServiceContext {
    signal: Arc<WindowsLifecycleSignal>,
    status_handle: SERVICE_STATUS_HANDLE,
}

#[cfg(target_os = "windows")]
static SERVICE_NAME: OnceLock<Vec<u16>> = OnceLock::new();

#[cfg(target_os = "windows")]
pub(crate) fn windows_service_requested() -> bool {
    std::env::args_os().any(|arg| arg == "--windows-service")
}

#[cfg(target_os = "windows")]
fn windows_service_name_from_args() -> String {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--windows-service-name" {
            if let Some(value) = args.next() {
                let name = value.to_string_lossy().trim().to_string();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }
    "p2wlan-daemon".to_string()
}

/// Enter the SCM dispatcher. `StartServiceCtrlDispatcherW` blocks until the
/// service main callback returns. A normal process invocation fails with the
/// explicit Windows error instead of silently falling back to desktop mode.
#[cfg(target_os = "windows")]
pub(crate) fn run_windows_service() -> p2pnet_daemon::Result<()> {
    let name = windows_service_name_from_args();
    let wide_name = SERVICE_NAME.get_or_init(|| {
        name.encode_utf16().chain(std::iter::once(0)).collect()
    });
    let entry = SERVICE_TABLE_ENTRYW {
        lpServiceName: wide_name.as_ptr() as *mut u16,
        lpServiceProc: Some(windows_service_main),
    };
    let terminator = SERVICE_TABLE_ENTRYW {
        lpServiceName: std::ptr::null_mut(),
        lpServiceProc: None,
    };
    let table = [entry, terminator];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        let error = unsafe { GetLastError() };
        return Err(DaemonError::Network(format!(
            "Windows Service Control Manager dispatcher failed with error {error}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_service_main(
    _argument_count: u32,
    _arguments: *mut windows_sys::core::PWSTR,
) {
    let signal = Arc::new(WindowsLifecycleSignal::new());
    let context = Box::new(WindowsServiceContext {
        signal: signal.clone(),
        status_handle: std::ptr::null_mut(),
    });
    let context_ptr = Box::into_raw(context);

    let Some(service_name) = SERVICE_NAME.get() else {
        let _ = Box::from_raw(context_ptr);
        return;
    };
    let handle = RegisterServiceCtrlHandlerExW(
        service_name.as_ptr(),
        Some(windows_service_handler),
        context_ptr.cast(),
    );
    if handle == std::ptr::null_mut() {
        let _ = Box::from_raw(context_ptr);
        return;
    }
    (*context_ptr).status_handle = handle;

    set_windows_service_status(handle, SERVICE_START_PENDING, 0);
    set_windows_service_status(handle, SERVICE_RUNNING, 0);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            set_windows_service_status(handle, SERVICE_STOPPED, 1);
            eprintln!("failed to create Windows service runtime: {error}");
            signal.complete();
            let _ = Box::from_raw(context_ptr);
            return;
        }
    };
    let result = runtime.block_on(run_daemon(signal.clone()));
    let exit_code = if result.is_ok() { 0 } else { 1 };
    set_windows_service_status(handle, SERVICE_STOPPED, exit_code);
    signal.complete();
    drop(runtime);
    let _ = Box::from_raw(context_ptr);
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_service_handler(
    control: u32,
    event_type: u32,
    _event_data: *mut std::ffi::c_void,
    context: *mut std::ffi::c_void,
) -> u32 {
    if context.is_null() {
        return 1;
    }
    let context = &*(context.cast::<WindowsServiceContext>());
    let reason = match control {
        SERVICE_CONTROL_STOP => Some(LIFECYCLE_SERVICE_STOP),
        SERVICE_CONTROL_PRESHUTDOWN => Some(LIFECYCLE_SERVICE_PRESHUTDOWN),
        SERVICE_CONTROL_SHUTDOWN => Some(LIFECYCLE_SERVICE_SHUTDOWN),
        SERVICE_CONTROL_SESSIONCHANGE if event_type == SERVICE_SESSION_LOGOFF => {
            Some(LIFECYCLE_SERVICE_LOGOFF)
        }
        SERVICE_CONTROL_INTERROGATE => None,
        _ => return 120,
    };
    if let Some(reason) = reason {
        context.signal.trigger(reason);
        if matches!(control, SERVICE_CONTROL_STOP | SERVICE_CONTROL_PRESHUTDOWN) {
            set_windows_service_status(context.status_handle, SERVICE_STOP_PENDING, 15_000);
        }
    }
    0
}

#[cfg(target_os = "windows")]
fn set_windows_service_status(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    wait_hint_or_exit_code: u32,
) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP
                | SERVICE_ACCEPT_PRESHUTDOWN
                | SERVICE_ACCEPT_SHUTDOWN
                | SERVICE_ACCEPT_SESSIONCHANGE
        } else {
            0
        },
        dwWin32ExitCode: if state == SERVICE_STOPPED {
            wait_hint_or_exit_code
        } else {
            0
        },
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if state == SERVICE_STOPPED {
            0
        } else {
            wait_hint_or_exit_code
        },
    };
    unsafe {
        let _ = SetServiceStatus(handle, &status);
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_lifecycle_reason(code: u32) -> &'static str {
    match code {
        LIFECYCLE_CTRL_C => "CTRL_C",
        LIFECYCLE_CTRL_BREAK => "CTRL_BREAK",
        LIFECYCLE_CTRL_CLOSE => "CTRL_CLOSE",
        LIFECYCLE_CTRL_LOGOFF => "CTRL_LOGOFF",
        LIFECYCLE_CTRL_SHUTDOWN => "CTRL_SHUTDOWN",
        LIFECYCLE_SERVICE_STOP => "SERVICE_STOP",
        LIFECYCLE_SERVICE_PRESHUTDOWN => "SERVICE_PRESHUTDOWN",
        LIFECYCLE_SERVICE_SHUTDOWN => "SERVICE_SHUTDOWN",
        LIFECYCLE_SERVICE_LOGOFF => "SERVICE_LOGOFF",
        _ => "WINDOWS_LIFECYCLE",
    }
}
