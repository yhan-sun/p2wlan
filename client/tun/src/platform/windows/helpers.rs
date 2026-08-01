// --- Helper functions ---

/// Convert a Rust string to a null-terminated UTF-16 wide string.
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Spawn a background thread that reads packets from the Wintun ring buffer
/// and sends them through a tokio channel.
///
/// The session handle is passed as `usize` to satisfy `Send` requirements.
fn spawn_read_thread(
    session_usize: usize,
    receive_packet: WintunReceivePacketFunc,
    release_receive_packet: WintunReleaseReceivePacketFunc,
    get_read_wait_event: WintunGetReadWaitEventFunc,
    tx: mpsc::Sender<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        // Convert usize back to raw pointer
        let session = session_usize as *mut std::ffi::c_void;
        // Get the read wait event handle
        let read_event = unsafe { get_read_wait_event(session) };

        if read_event.is_null() {
            error!("WintunGetReadWaitEvent returned null");
            return;
        }

        info!("Wintun read thread started");

        loop {
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            // Try to receive a packet from the ring buffer
            let mut packet_size: u32 = 0;
            let packet_ptr = unsafe { receive_packet(session, &mut packet_size) };

            if !packet_ptr.is_null() {
                // We got a packet - copy it and release the ring buffer slot
                let packet_data =
                    unsafe { std::slice::from_raw_parts(packet_ptr, packet_size as usize) };
                let data = packet_data.to_vec();

                // Release the packet back to the ring buffer
                unsafe { release_receive_packet(session, packet_ptr) };

                // Send through the channel (blocking_send works from a std thread)
                if tx.blocking_send(data).is_err() {
                    // Channel closed, exit
                    break;
                }
            } else {
                // No packet available - wait for the read event
                // Use a short timeout so we can check the shutdown flag periodically
                unsafe {
                    WaitForSingleObject(read_event, 100); // 100ms timeout
                }
            }
        }

        info!("Wintun read thread stopped");
    })
}

fn hidden_command(program: &str) -> Command {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

/// Set the IPv4 address and netmask on an interface using netsh.
fn set_interface_address(name: &str, addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
    let prefix_len = u32::from(netmask).count_ones();
    let cidr = format!("{addr}/{prefix_len}");

    info!("Setting interface {name} address: {cidr}");

    let output = hidden_command("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "address",
            name,
            "static",
            &addr.to_string(),
            &netmask.to_string(),
        ])
        .output()
        .map_err(|e| Error::Platform(format!("failed to run netsh: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        warn!("netsh address set failed: {stderr}{stdout}");
        // Don't fail hard - the interface might still work with manual config
    } else {
        info!("IP address set: {addr}/{netmask}");
    }

    Ok(())
}

/// Set the MTU on an interface using netsh.
fn set_interface_mtu(name: &str, mtu: u32) -> Result<()> {
    info!("Setting MTU for {name}: {mtu}");

    let output = hidden_command("netsh")
        .args([
            "interface",
            "ipv4",
            "set",
            "subinterface",
            name,
            "mtu",
            &mtu.to_string(),
            "store=persistent",
        ])
        .output()
        .map_err(|e| Error::Platform(format!("failed to run netsh: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("netsh MTU set failed: {stderr}");
    }

    Ok(())
}
