#![cfg(target_os = "linux")]

use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use p2pnet_netbind::{bind_udp, udp_no_fragment_supported};

const LOW_MTU: &str = "1200";
const SENDER_IP: &str = "192.0.2.1";
const RECEIVER_IP: &str = "192.0.2.2";
const RECEIVER_PORT: u16 = 40_000;
const LARGE_UDP_DATAGRAM: usize = 1_400;
const RECEIVER_ENV: &str = "P2WLAN_NETNS_RECEIVER";

struct NetnsGuard {
    namespace: String,
    host_link: String,
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
    println!("READY");
    io::stdout().flush().expect("receiver readiness must flush");

    let mut buffer = [0u8; 65_535];
    match socket.recv_from(&mut buffer) {
        Ok((size, source)) => {
            println!("RECEIVED size={size} source={source}");
        }
        Err(error) if error.kind() == io::ErrorKind::TimedOut => println!("NO_PACKET"),
        Err(error) => panic!("receiver failed while waiting for the probe: {error}"),
    }
}

fn spawn_receiver(namespace: &str) -> io::Result<Child> {
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
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
}

#[test]
#[ignore = "requires Linux CAP_NET_ADMIN and iproute2; run in the required privileged CI job"]
fn linux_low_mtu_no_fragment_probe_does_not_fragment() {
    if env::var_os(RECEIVER_ENV).is_some() {
        receiver_helper();
        return;
    }

    let namespace = NetnsGuard::create().expect("low-MTU netns/veth setup must succeed");
    let mut receiver = spawn_receiver(&namespace.namespace).expect("receiver must spawn");
    let stdout = receiver
        .stdout
        .take()
        .expect("receiver stdout must be piped");
    let mut receiver_output = BufReader::new(stdout);
    let mut line = String::new();
    assert!(
        receiver_output
            .read_line(&mut line)
            .expect("receiver readiness must be readable")
            > 0,
        "receiver exited before announcing readiness"
    );
    assert_eq!(line.trim(), "READY");

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

    let mut received_packet = false;
    let mut output_line = String::new();
    while receiver_output
        .read_line(&mut output_line)
        .expect("receiver output must be readable")
        > 0
    {
        if output_line.starts_with("RECEIVED ") {
            received_packet = true;
        }
        output_line.clear();
    }
    let status = receiver.wait().expect("receiver must exit");
    assert!(
        status.success(),
        "receiver helper must complete successfully"
    );
    assert!(
        !received_packet,
        "large DPLPMTUD probe reached the receiver; fragmentation may have occurred"
    );
    println!(
        "LINUX_NO_FRAGMENT mtu={} udp_datagram={} df=true send_errno=EMSGSIZE receiver_packet=false fragmented_ack=false",
        LOW_MTU, LARGE_UDP_DATAGRAM,
    );
}
