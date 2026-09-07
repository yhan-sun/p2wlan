use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::fmt::MakeWriter;

const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;
const LOG_BACKUPS: usize = 4;
const LOG_QUEUE_CAPACITY: usize = 512;
const LOG_ENTRY_MAX_BYTES: usize = 16 * 1024;
const LOG_DRAIN_BUDGET: Duration = Duration::from_millis(500);

#[derive(Clone, Copy)]
pub struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, writer: &mut Writer<'_>) -> fmt::Result {
        writer.write_str(&local_timestamp(SystemTime::now()))
    }
}

pub fn local_timestamp(time: SystemTime) -> String {
    let (seconds, millis) = match time.duration_since(UNIX_EPOCH) {
        Ok(value) => (
            value.as_secs().min(i64::MAX as u64) as i64,
            value.subsec_millis(),
        ),
        Err(error) => {
            let value = error.duration();
            let whole = value.as_secs().min((i64::MAX - 1) as u64) as i64;
            if value.subsec_nanos() == 0 {
                (-whole, 0)
            } else {
                (
                    -whole - 1,
                    (1_000_000_000 - value.subsec_nanos()) / 1_000_000,
                )
            }
        }
    };
    let calendar = local_calendar(seconds).unwrap_or_else(|| utc_calendar(seconds));
    calendar.format(millis)
}

#[derive(Clone, Copy, Debug)]
struct Calendar {
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    offset_seconds: i64,
}

impl Calendar {
    fn format(self, millis: u32) -> String {
        let offset = self.offset_seconds.unsigned_abs();
        let sign = if self.offset_seconds < 0 { '-' } else { '+' };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}{sign}{:02}:{:02}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            millis,
            offset / 3600,
            (offset % 3600) / 60,
        )
    }
}

fn utc_calendar(seconds: i64) -> Calendar {
    let days = seconds.div_euclid(86400) + 719468;
    let era = days.div_euclid(146097);
    let day_of_era = days - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let within_day = seconds.rem_euclid(86400);
    Calendar {
        year,
        month: month as u32,
        day: day as u32,
        hour: (within_day / 3600) as u32,
        minute: (within_day % 3600 / 60) as u32,
        second: (within_day % 60) as u32,
        offset_seconds: 0,
    }
}

#[cfg(unix)]
#[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
fn local_calendar(seconds: i64) -> Option<Calendar> {
    let seconds: libc::time_t = seconds.try_into().ok()?;
    let mut result = std::mem::MaybeUninit::<libc::tm>::uninit();
    // localtime_r initializes the caller-owned buffer on success only.
    let result = unsafe {
        if libc::localtime_r(&seconds, result.as_mut_ptr()).is_null() {
            return None;
        }
        result.assume_init()
    };
    Some(Calendar {
        year: i64::from(result.tm_year) + 1900,
        month: (result.tm_mon + 1) as u32,
        day: result.tm_mday as u32,
        hour: result.tm_hour as u32,
        minute: result.tm_min as u32,
        second: result.tm_sec as u32,
        offset_seconds: result.tm_gmtoff as i64,
    })
}

#[cfg(windows)]
fn local_calendar(seconds: i64) -> Option<Calendar> {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::Time::{
        GetDynamicTimeZoneInformation, SystemTimeToTzSpecificLocalTimeEx,
        DYNAMIC_TIME_ZONE_INFORMATION,
    };
    let value = utc_calendar(seconds);
    let utc = SYSTEMTIME {
        wYear: value.year.try_into().ok()?,
        wMonth: value.month as u16,
        wDayOfWeek: 0,
        wDay: value.day as u16,
        wHour: value.hour as u16,
        wMinute: value.minute as u16,
        wSecond: value.second as u16,
        wMilliseconds: 0,
    };
    // Both Win32 structures are plain integer/UTF-16 fields and permit zero initialization.
    let mut zone: DYNAMIC_TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let mut local: SYSTEMTIME = unsafe { std::mem::zeroed() };
    // All pointers refer to initialized, correctly aligned, live Win32 structures.
    unsafe {
        if GetDynamicTimeZoneInformation(&mut zone) == u32::MAX
            || SystemTimeToTzSpecificLocalTimeEx(&zone, &utc, &mut local) == 0
        {
            return None;
        }
    }
    let mut year = i64::from(local.wYear);
    let month = i64::from(local.wMonth);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year =
        (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(local.wDay) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let local_seconds = (era * 146097 + day_of_era - 719468) * 86400
        + i64::from(local.wHour) * 3600
        + i64::from(local.wMinute) * 60
        + i64::from(local.wSecond);
    Some(Calendar {
        year: i64::from(local.wYear),
        month: u32::from(local.wMonth),
        day: u32::from(local.wDay),
        hour: u32::from(local.wHour),
        minute: u32::from(local.wMinute),
        second: u32::from(local.wSecond),
        offset_seconds: local_seconds - seconds,
    })
}

#[cfg(not(any(unix, windows)))]
fn local_calendar(_seconds: i64) -> Option<Calendar> {
    None
}

#[derive(Clone)]
pub struct NonBlockingLog {
    sender: mpsc::SyncSender<Vec<u8>>,
    dropped: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
}

pub struct LogEventWriter {
    sink: NonBlockingLog,
    bytes: Vec<u8>,
    truncated: bool,
}

impl<'a> MakeWriter<'a> for NonBlockingLog {
    type Writer = LogEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogEventWriter {
            sink: self.clone(),
            bytes: Vec::with_capacity(512),
            truncated: false,
        }
    }
}

impl Write for LogEventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = LOG_ENTRY_MAX_BYTES.saturating_sub(self.bytes.len());
        let count = remaining.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        self.truncated |= count < bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for LogEventWriter {
    fn drop(&mut self) {
        if self.bytes.is_empty() || self.sink.stopping.load(Ordering::Acquire) {
            return;
        }
        if self.truncated {
            let suffix = b" [truncated]\n";
            self.bytes.truncate(LOG_ENTRY_MAX_BYTES - suffix.len());
            if let Err(error) = std::str::from_utf8(&self.bytes) {
                self.bytes.truncate(error.valid_up_to());
            }
            self.bytes.extend_from_slice(suffix);
        }
        if self
            .sink
            .sender
            .try_send(std::mem::take(&mut self.bytes))
            .is_err()
        {
            self.sink.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct LogWorkerGuard {
    stopping: Arc<AtomicBool>,
    completed: mpsc::Receiver<()>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for LogWorkerGuard {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if self
            .completed
            .recv_timeout(LOG_DRAIN_BUDGET + Duration::from_millis(250))
            .is_ok()
        {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

pub fn bounded_file_writer(path: &Path) -> io::Result<(NonBlockingLog, LogWorkerGuard)> {
    let mut file = RollingFile::open(path, LOG_MAX_BYTES, LOG_BACKUPS)?;
    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(LOG_QUEUE_CAPACITY);
    let (completed_tx, completed) = mpsc::channel();
    let dropped = Arc::new(AtomicUsize::new(0));
    let stopping = Arc::new(AtomicBool::new(false));
    let worker_stopping = stopping.clone();
    let worker_dropped = dropped.clone();
    let handle = thread::Builder::new()
        .name("p2wlan-log-writer".into())
        .spawn(move || {
            let mut drain_deadline = None;
            let mut write_failures = 0usize;
            loop {
                if worker_stopping.load(Ordering::Acquire) && drain_deadline.is_none() {
                    drain_deadline = Some(Instant::now() + LOG_DRAIN_BUDGET);
                }
                if drain_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    break;
                }
                let bytes = if drain_deadline.is_some() {
                    match receiver.try_recv() {
                        Ok(bytes) => bytes,
                        Err(_) => break,
                    }
                } else {
                    match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(bytes) => bytes,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                };
                let dropped_count = worker_dropped.swap(0, Ordering::Relaxed);
                if dropped_count > 0 {
                    let notice = format!(
                        "{} WARN p2wlan_daemon::logging: log_queue_overflow dropped={}\n",
                        local_timestamp(SystemTime::now()),
                        dropped_count
                    );
                    let _ = file.write_record(notice.as_bytes());
                }
                if let Err(error) = file.write_record(&bytes) {
                    write_failures = write_failures.saturating_add(1);
                    if write_failures == 1 || write_failures.is_power_of_two() {
                        eprintln!("P2WLAN log write failed ({write_failures}): {error}");
                    }
                } else if write_failures > 0 {
                    let notice = format!(
                        "{} WARN p2wlan_daemon::logging: log_write_recovered dropped={}\n",
                        local_timestamp(SystemTime::now()),
                        write_failures
                    );
                    let _ = file.write_record(notice.as_bytes());
                    write_failures = 0;
                }
            }
            let dropped_count = worker_dropped.swap(0, Ordering::Relaxed);
            if dropped_count > 0 {
                let notice = format!(
                    "{} WARN p2wlan_daemon::logging: log_queue_overflow dropped={}\n",
                    local_timestamp(SystemTime::now()),
                    dropped_count
                );
                let _ = file.write_record(notice.as_bytes());
            }
            let _ = file.flush();
            let _ = completed_tx.send(());
        })?;
    Ok((
        NonBlockingLog {
            sender,
            dropped,
            stopping: stopping.clone(),
        },
        LogWorkerGuard {
            stopping,
            completed,
            handle: Some(handle),
        },
    ))
}

struct RollingFile {
    path: PathBuf,
    file: Option<File>,
    length: u64,
    max_bytes: u64,
    backups: usize,
    #[cfg(unix)]
    owner: (u32, u32),
}

fn archive_path(path: &Path, number: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{number}"));
    PathBuf::from(name)
}

fn open_private_log(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.append(false).write(true).custom_flags(0x00200000);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log path is a reparse point",
            ));
        }
    }
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.seek(SeekFrom::End(0))?;
    Ok(file)
}

fn trim_oversized_log(file: &mut File, max_bytes: u64) -> io::Result<u64> {
    let length = file.metadata()?.len();
    if length <= max_bytes {
        return Ok(length);
    }
    file.seek(SeekFrom::Start(length - max_bytes))?;
    let mut tail = Vec::with_capacity(max_bytes as usize);
    (&mut *file).take(max_bytes).read_to_end(&mut tail)?;
    let start = tail
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| position + 1)
        .unwrap_or(tail.len());
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&tail[start..])?;
    Ok((tail.len() - start) as u64)
}

impl RollingFile {
    fn open(path: &Path, max_bytes: u64, backups: usize) -> io::Result<Self> {
        if max_bytes == 0 || backups == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "log retention limits must be positive",
            ));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = open_private_log(path)?;
        let length = trim_oversized_log(&mut file, max_bytes)?;
        #[cfg(unix)]
        let owner = {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            (metadata.uid(), metadata.gid())
        };
        for number in 1..=backups {
            let archive = archive_path(path, number);
            if archive.exists() {
                let mut old = open_private_log(&archive)?;
                trim_oversized_log(&mut old, max_bytes)?;
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            length,
            max_bytes,
            backups,
            #[cfg(unix)]
            owner,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.take();
        for number in (1..=self.backups).rev() {
            let destination = archive_path(&self.path, number);
            match std::fs::remove_file(&destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let source = if number == 1 {
                self.path.clone()
            } else {
                archive_path(&self.path, number - 1)
            };
            match std::fs::rename(&source, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let file = self.open_replacement()?;
        self.file = Some(file);
        self.length = 0;
        Ok(())
    }

    fn open_replacement(&self) -> io::Result<File> {
        let file = open_private_log(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            if (metadata.uid(), metadata.gid()) != self.owner {
                // The descriptor is live; ownership comes from the original validated log.
                if unsafe { libc::fchown(file.as_raw_fd(), self.owner.0, self.owner.1) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(file)
    }

    fn write_record(&mut self, bytes: &[u8]) -> io::Result<()> {
        let bytes = &bytes[..bytes.len().min(self.max_bytes as usize)];
        if self.file.is_none() {
            let mut file = self.open_replacement()?;
            self.length = trim_oversized_log(&mut file, self.max_bytes)?;
            self.file = Some(file);
        }
        if self.length > 0 && self.length + bytes.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        if let Some(file) = self.file.as_mut() {
            #[cfg(windows)]
            file.seek(SeekFrom::End(0))?;
            if let Err(error) = file.write_all(bytes) {
                self.length = file
                    .metadata()
                    .map(|metadata| metadata.len())
                    .unwrap_or(self.max_bytes);
                return Err(error);
            }
            self.length += bytes.len() as u64;
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> PathBuf {
        let id = rand::random::<u64>();
        std::env::temp_dir()
            .join(format!("p2wlan-log-{}-{id}", std::process::id()))
            .join("daemon.log")
    }

    #[test]
    fn timestamp_has_explicit_offset_and_handles_fractional_zones() {
        let mut calendar = utc_calendar(0);
        assert_eq!(calendar.format(123), "1970-01-01T00:00:00.123+00:00");
        calendar.offset_seconds = 5 * 3600 + 45 * 60;
        assert!(calendar.format(0).ends_with("+05:45"));
        calendar.offset_seconds = -(3 * 3600 + 30 * 60);
        assert!(calendar.format(0).ends_with("-03:30"));
        assert_eq!(
            utc_calendar(-1).format(999),
            "1969-12-31T23:59:59.999+00:00"
        );
        assert_eq!(
            utc_calendar(1709164800).format(0),
            "2024-02-29T00:00:00.000+00:00"
        );
        assert_eq!(
            &local_timestamp(UNIX_EPOCH - Duration::from_millis(1))[19..23],
            ".999"
        );
        assert_eq!(
            &local_timestamp(UNIX_EPOCH - Duration::from_millis(500))[19..23],
            ".500"
        );
        let stamp = local_timestamp(SystemTime::now());
        assert_eq!(stamp.len(), 29);
        assert!(matches!(stamp.as_bytes()[23], b'+' | b'-'));
        assert_eq!(stamp.as_bytes()[26], b':');
    }

    #[test]
    fn rotating_logs_remain_bounded_and_keep_the_newest_records() {
        let path = temp_log();
        let mut file = RollingFile::open(&path, 64, 2).unwrap();
        for index in 0..100 {
            file.write_record(format!("record-{index:03}\n").as_bytes())
                .unwrap();
        }
        file.flush().unwrap();
        drop(file);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("record-099"));
        for number in 0..=2 {
            let retained = if number == 0 {
                path.clone()
            } else {
                archive_path(&path, number)
            };
            assert!(std::fs::metadata(&retained).unwrap().len() <= 64);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(retained).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert!(!archive_path(&path, 3).exists());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn old_oversized_logs_are_trimmed_with_bounded_tail_reads() {
        let path = temp_log();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "old-record\n".repeat(1000)).unwrap();
        std::fs::write(archive_path(&path, 1), "old-backup\n".repeat(1000)).unwrap();
        let file = RollingFile::open(&path, 128, 2).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() <= 128);
        assert!(std::fs::metadata(archive_path(&path, 1)).unwrap().len() <= 128);
        drop(file);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn trimming_preserves_complete_tail_then_appends_without_sparse_gaps() {
        let path = temp_log();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = (0..100)
            .map(|index| format!("entry-{index:03}\n"))
            .collect::<String>();
        std::fs::write(&path, &original).unwrap();
        let mut file = RollingFile::open(&path, 128, 2).unwrap();
        let trimmed = std::fs::read_to_string(&path).unwrap();
        assert!(original.ends_with(&trimmed));
        assert!(!trimmed.is_empty());
        assert!(!trimmed.contains('\0'));
        file.write_record(b"last\n").unwrap();
        file.flush().unwrap();
        drop(file);
        let retained = std::fs::read_to_string(&path).unwrap();
        assert!(retained.ends_with("last\n"));
        assert!(!retained.contains('\0'));
        assert!(retained.len() <= 128);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn full_log_queue_never_blocks_and_entries_have_a_byte_bound() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicUsize::new(0));
        let sink = NonBlockingLog {
            sender,
            dropped: dropped.clone(),
            stopping: Arc::new(AtomicBool::new(false)),
        };
        {
            let mut writer = sink.make_writer();
            writer
                .write_all("测".repeat(LOG_ENTRY_MAX_BYTES).as_bytes())
                .unwrap();
        }
        {
            let mut writer = sink.make_writer();
            writer.write_all(b"dropped\n").unwrap();
        }
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let bytes = receiver.recv().unwrap();
        assert!(bytes.len() <= LOG_ENTRY_MAX_BYTES);
        assert!(std::str::from_utf8(&bytes)
            .unwrap()
            .ends_with(" [truncated]\n"));
    }

    #[test]
    fn shutdown_flushes_queued_records_without_waiting_for_global_subscriber_drop() {
        let path = temp_log();
        let (sink, guard) = bounded_file_writer(&path).unwrap();
        for index in 0..20 {
            let mut writer = sink.make_writer();
            writeln!(writer, "record-{index}").unwrap();
        }
        drop(guard);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("record-19"));
        drop(sink);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_log_paths_are_rejected_without_modifying_the_target() {
        use std::os::unix::fs::symlink;
        let path = temp_log();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = path.with_file_name("unrelated");
        std::fs::write(&target, "keep me").unwrap();
        symlink(&target, &path).unwrap();
        assert!(bounded_file_writer(&path).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
