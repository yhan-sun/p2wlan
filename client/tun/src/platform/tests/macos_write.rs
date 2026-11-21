//! VirtualInterface/fd contract tests, not privileged utun/device acceptance.
//!
//! A nonblocking Unix datagram pair supplies owned fds. Short-write cases
//! truncate the real syscall itself, so the receiver observes its actual
//! prefix/payload boundary. No fixture creates a TUN, changes routes, borrows
//! ownership with FromRawFd, or closes a descriptor owned by another object.

use super::*;
use std::os::fd::RawFd;
use std::os::unix::net::UnixDatagram as StdUnixDatagram;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UnixDatagram;
use tokio::time::timeout;

const TEST_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
enum Directive {
    Truncate(usize),
    InvalidFd,
}

#[derive(Debug, Clone)]
struct SyscallCall {
    owner_fd: RawFd,
    frame: Vec<u8>,
    returned: Option<usize>,
    errno: Option<i32>,
}

pub(super) struct WriteSyscall {
    directive: Directive,
    calls: Mutex<Vec<SyscallCall>>,
}

impl WriteSyscall {
    fn new(directive: Directive) -> Arc<Self> {
        Arc::new(Self {
            directive,
            calls: Mutex::new(Vec::with_capacity(1)),
        })
    }

    pub(super) fn write(&self, owner_fd: RawFd, frame: &[u8]) -> io::Result<usize> {
        let (syscall_fd, bytes) = match self.directive {
            Directive::Truncate(count) => {
                assert!(count <= frame.len(), "test must not read past the frame");
                (owner_fd, &frame[..count])
            }
            // A negative descriptor lets the OS produce EBADF without closing
            // the valid device fd or any unrelated descriptor.
            Directive::InvalidFd => (-1, frame),
        };
        // Safety: the slice stays alive for this nonblocking syscall. The
        // valid descriptor is owned by the device, or -1 for the errno case.
        let written = unsafe {
            libc::write(
                syscall_fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
            )
        };
        let result = if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        };
        let call = SyscallCall {
            owner_fd,
            frame: frame.to_vec(),
            returned: result.as_ref().ok().copied(),
            errno: result.as_ref().err().and_then(io::Error::raw_os_error),
        };
        let mut calls = self.calls.lock().unwrap();
        assert!(calls.is_empty(), "write must not resend a partial packet");
        calls.push(call);
        result
    }

    fn call(&self) -> SyscallCall {
        let calls = self.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "exactly one physical syscall is expected");
        calls[0].clone()
    }
}

fn fixture() -> (UtunDevice, UnixDatagram) {
    let (sender, receiver) = StdUnixDatagram::pair().unwrap();
    sender.set_nonblocking(true).unwrap();
    receiver.set_nonblocking(true).unwrap();
    // Transfer ownership through Into<OwnedFd>; never duplicate a borrowed fd.
    let fd: OwnedFd = sender.into();
    let device = UtunDevice {
        fd: AsyncFd::new(fd).unwrap(),
        name: "fd-contract-fixture".to_string(),
        mtu: 1420,
        address: "192.0.2.1".to_string(),
        is_up: true,
        test_write_syscall: None,
    };
    (device, UnixDatagram::from_std(receiver).unwrap())
}

fn ipv4_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 24];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&24u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[20..].copy_from_slice(b"data");
    packet
}

fn ipv6_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 44];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&4u16.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[40..].copy_from_slice(b"data");
    packet
}

async fn receive(receiver: &UnixDatagram) -> Vec<u8> {
    let mut bytes = [0u8; 128];
    let count = timeout(TEST_DEADLINE, receiver.recv(&mut bytes))
        .await
        .expect("owned fd write must reach the receiving datagram socket")
        .unwrap();
    bytes[..count].to_vec()
}

#[tokio::test]
async fn virtual_write_full_fd_preserves_ipv4_and_ipv6_af_prefix() {
    let (mut device, receiver) = fixture();
    for (packet, family) in [
        (ipv4_packet(), libc::AF_INET as u32),
        (ipv6_packet(), libc::AF_INET6 as u32),
    ] {
        let written = timeout(TEST_DEADLINE, VirtualInterface::write(&mut device, &packet))
            .await
            .expect("nonblocking owned fd must make progress")
            .unwrap();
        let frame = receive(&receiver).await;
        assert_eq!(written, packet.len(), "AF prefix is not business bytes");
        assert_eq!(frame.len(), packet.len() + 4);
        assert_eq!(&frame[..4], &family.to_be_bytes());
        assert_eq!(&frame[4..], packet);
    }
}

async fn assert_short_write_rejected(syscall_bytes: usize) {
    let (mut device, receiver) = fixture();
    let packet = ipv4_packet();
    let owner_fd = device.fd.get_ref().as_raw_fd();
    let syscall = WriteSyscall::new(Directive::Truncate(syscall_bytes));
    device.test_write_syscall = Some(syscall.clone());

    let result = timeout(TEST_DEADLINE, VirtualInterface::write(&mut device, &packet))
        .await
        .expect("a completed short syscall must not wait or resend");
    let call = syscall.call();
    assert_eq!(call.owner_fd, owner_fd);
    assert_eq!(call.returned, Some(syscall_bytes));
    assert_eq!(call.errno, None);
    assert_eq!(&call.frame[..4], &(libc::AF_INET as u32).to_be_bytes());
    assert_eq!(&call.frame[4..], packet);
    if syscall_bytes > 0 {
        assert_eq!(
            receive(&receiver).await,
            call.frame[..syscall_bytes],
            "receiver must see the actual short syscall, not a full frame"
        );
    }
    eprintln!(
        "scope=owned_unix_datagram_fd syscall_returned={syscall_bytes} expected_prefixed={} virtual_write_result={result:?}",
        packet.len() + 4
    );
    let error = result.expect_err("short syscall cannot report a full TUN packet");
    assert!(
        matches!(error, Error::Io(ref error) if error.kind() == io::ErrorKind::WriteZero),
        "partial utun frame must terminate with a typed I/O error: {error:?}"
    );
}

#[tokio::test]
async fn virtual_write_zero_syscall_is_not_full_packet() {
    assert_short_write_rejected(0).await;
}

#[tokio::test]
async fn virtual_write_partial_prefix_syscall_is_not_full_packet() {
    assert_short_write_rejected(3).await;
}

#[tokio::test]
async fn virtual_write_prefix_only_syscall_is_not_full_packet() {
    assert_short_write_rejected(4).await;
}

#[tokio::test]
async fn virtual_write_partial_payload_syscall_is_not_full_packet() {
    assert_short_write_rejected(ipv4_packet().len() + 3).await;
}

#[tokio::test]
async fn virtual_write_errno_is_preserved_without_fd_ownership_damage() {
    let (mut device, receiver) = fixture();
    // Keep independently owned sockets live across the device's drop. The
    // errno seam is forbidden from closing these or the device's valid fd.
    let (unrelated_sender, unrelated_receiver) = StdUnixDatagram::pair().unwrap();
    unrelated_sender.set_nonblocking(true).unwrap();
    unrelated_receiver.set_nonblocking(true).unwrap();
    let unrelated_sender = UnixDatagram::from_std(unrelated_sender).unwrap();
    let unrelated_receiver = UnixDatagram::from_std(unrelated_receiver).unwrap();
    let syscall = WriteSyscall::new(Directive::InvalidFd);
    device.test_write_syscall = Some(syscall.clone());
    let packet = ipv6_packet();

    let error = timeout(TEST_DEADLINE, VirtualInterface::write(&mut device, &packet))
        .await
        .expect("failed syscall must return immediately")
        .expect_err("EBADF must not become a successful full packet");
    assert!(matches!(error, Error::Io(ref error) if error.raw_os_error() == Some(libc::EBADF)));
    let call = syscall.call();
    assert_eq!(call.returned, None);
    assert_eq!(call.errno, Some(libc::EBADF));
    assert_eq!(call.owner_fd, device.fd.get_ref().as_raw_fd());
    assert_eq!(&call.frame[..4], &(libc::AF_INET6 as u32).to_be_bytes());
    assert_eq!(&call.frame[4..], packet);

    device.test_write_syscall = None;
    let written = timeout(TEST_DEADLINE, VirtualInterface::write(&mut device, &packet))
        .await
        .expect("the valid owned device fd must remain usable")
        .unwrap();
    assert_eq!(written, packet.len());
    assert_eq!(&receive(&receiver).await[4..], packet);
    drop(device);
    timeout(TEST_DEADLINE, unrelated_sender.send(b"still-owned"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receive(&unrelated_receiver).await, b"still-owned");
}
