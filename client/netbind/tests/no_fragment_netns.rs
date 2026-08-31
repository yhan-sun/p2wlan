#![cfg(target_os = "linux")]

use std::env;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use p2pnet_netbind::{bind_udp, udp_no_fragment_supported};

const LOW_MTU: &str = "1200";
const SENDER_IP: &str = "192.0.2.1";
const RECEIVER_IP: &str = "192.0.2.2";
const RECEIVER_PORT: u16 = 40_000;
const LARGE_UDP_DATAGRAM: usize = 1_400;
const RECEIVER_ENV: &str = "P2WLAN_NETNS_RECEIVER";
const RECEIVER_READY_PATH_ENV: &str = "P2WLAN_NETNS_RECEIVER_READY_PATH";

struct NetnsGuard {
    namespace: String,
    host_link: String,
}

struct ReceiverReadyPath(PathBuf);

impl Drop for ReceiverReadyPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl NetnsGuard {
    fn create() -> io::Result<Self> {
        let suffix = std::process::id();
        let namespace = format!("p2wlan-ns-{suffix}");
        let host_link = format!("p2wlan-h-{suffix}");
        let peer_link = format!("p2wlan-p-{suffix}");

        run_ip(&["netns", "add", &namespace])?;
        let guard = Self {
            namespace,
            host_link,
        };
        run_ip(&[
            "link",
            "add",
            &guard.host_link,
            "type",
            "veth",
            "peer",
            "name",
            &peer_link,
        ])?;
        run_ip(&["link", "set", &peer_link, "netns", &guard.namespace])?;
        run_ip(&[
            "addr",
            "add",
            &format!("{SENDER_IP}/24"),
            "dev",
            &guard.host_link,
        ])?;
        run_ip(&["link", "set", &guard.host_link, "mtu", LOW_MTU])?;
        run_ip(&["link", "set", &guard.host_link, "up"])?;
        run_ip(&[
            "netns",
            "exec",
            &guard.namespace,
            "ip",
            "link",
            "set",
            &peer_link,
            "mtu",
            LOW_MTU,
        ])?;
        run_ip(&[
            "netns",
            "exec",
            &guard.namespace,
            "ip",
            "addr",
            "add",
            &format!("{RECEIVER_IP}/24"),
            "dev",
            &peer_link,
        ])?;
        run_ip(&[
            "netns",
            "exec",
            &guard.namespace,
            "ip",
            "link",
            "set",
            &peer_link,
            "up",
        ])?;
        run_ip(&[
            "netns",
            "exec",
            &guard.namespace,
            "ip",
            "link",
            "set",
            "lo",
            "up",
        ])?;
        Ok(guard)
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = run_ip(&["netns", "del", &self.namespace]);
        let _ = run_ip(&["link", "del", &self.host_link]);
    }
}

fn run_ip(arguments: &[&str]) -> io::Result<()> {
    let output = Command::new("ip").args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format_command_failure(arguments, &output)))
}

fn format_command_failure(arguments: &[&str], output: &Output) -> String {
    format!(
        "ip {} failed: status={} stdout={} stderr={}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    )
}

fn receiver_helper() {
    let socket = std::net::UdpSocket::bind(SocketAddr::new(
        RECEIVER_IP.parse().expect("test IPv4 address"),
        RECEIVER_PORT,
    ))
    .expect("receiver must bind inside the low-MTU namespace");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("receiver read timeout must be configurable");
    let ready_path: PathBuf = env::var_os(RECEIVER_READY_PATH_ENV)
        .expect("receiver readiness path must be provided")
        .into();
    fs::write(ready_path, b"READY\n").expect("receiver readiness must be published");

    let mut buffer = [0u8; 65_535];
    match socket.recv_from(&mut buffer) {
        Ok((size, source)) => {
            panic!("large probe reached receiver: size={size} source={source}");
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) => {}
        Err(error) => panic!("receiver failed while waiting for the probe: {error}"),
    }
}

fn spawn_receiver(namespace: &str, ready_path: &Path) -> io::Result<Child> {
    let executable = env::current_exe()?;
    Command::new("ip")
        .args([
            "netns",
            "exec",
            namespace,
            executable.to_str().expect("test executable must be UTF-8"),
            "--exact",
            "linux_low_mtu_no_fragment_probe_does_not_fragment",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RECEIVER_ENV, "1")
        .env(RECEIVER_READY_PATH_ENV, ready_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
}

fn wait_for_receiver_ready(receiver: &mut Child, ready_path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if ready_path.is_file() {
            let readiness = fs::read_to_string(ready_path)?;
            if readiness.trim() == "READY" {
                return Ok(());
            }
            return Err(io::Error::other(format!(
                "receiver readiness marker was {readiness:?}"
            )));
        }
        if let Some(status) = receiver.try_wait()? {
            return Err(io::Error::other(format!(
                "receiver exited before announcing readiness: {status}"
            )));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "receiver did not announce readiness",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires Linux CAP_NET_ADMIN and iproute2; run in the required privileged CI job"]
fn linux_low_mtu_no_fragment_probe_does_not_fragment() {
    if env::var_os(RECEIVER_ENV).is_some() {
        receiver_helper();
        return;
    }

    let namespace = NetnsGuard::create().expect("low-MTU netns/veth setup must succeed");
    let ready_path = env::temp_dir().join(format!("p2wlan-netns-ready-{}", std::process::id()));
    let _ready_path = ReceiverReadyPath(ready_path.clone());
    let mut receiver =
        spawn_receiver(&namespace.namespace, &ready_path).expect("receiver must spawn");
    wait_for_receiver_ready(&mut receiver, &ready_path)
        .expect("receiver must announce readiness through the shared filesystem");

    let runtime = tokio::runtime::Runtime::new().expect("Tokio runtime must start");
    let sender = runtime
        .block_on(bind_udp(
            SocketAddr::new(SENDER_IP.parse().unwrap(), 0),
            None,
        ))
        .expect("sender must bind on the veth address");
    assert!(udp_no_fragment_supported(
        &sender,
        IpAddr::V4(RECEIVER_IP.parse().unwrap())
    ));
    let payload = vec![0xa5; LARGE_UDP_DATAGRAM];
    let destination = SocketAddr::new(RECEIVER_IP.parse().unwrap(), RECEIVER_PORT);
    let send_error = runtime
        .block_on(sender.send_to(&payload, destination))
        .expect_err("a DF UDP datagram larger than the veth MTU must fail locally");
    assert_eq!(send_error.raw_os_error(), Some(libc::EMSGSIZE));
    drop(sender);

    let status = receiver.wait().expect("receiver must exit");
    assert!(
        status.success(),
        "receiver helper must complete successfully"
    );
    println!(
        "LINUX_NO_FRAGMENT mtu={} udp_datagram={} df=true send_errno=EMSGSIZE receiver_packet=false fragmented_ack=false",
        LOW_MTU, LARGE_UDP_DATAGRAM,
    );
}
