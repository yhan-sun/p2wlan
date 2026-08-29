#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

use serde_json::{json, Value};

const PROBE_CYCLES: u64 = 20;
const TRAY_SOURCE_CYCLES: u64 = 12;

fn daemon_path() -> PathBuf {
    if let Some(path) = std::env::var_os("P2WLAN_DAEMON_BIN") {
        return PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_p2wlan-daemon") {
        return PathBuf::from(path);
    }
    panic!("P2WLAN_DAEMON_BIN or CARGO_BIN_EXE_p2wlan-daemon is required");
}

fn run_daemon(args: &[String]) -> Output {
    let output = Command::new(daemon_path())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to start p2wlan-daemon: {error}"));
    assert!(
        output.status.success(),
        "daemon lifecycle probe failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

#[test]
fn windows_binary_probe_repeated_start_exit_is_clean() {
    for cycle in 0..PROBE_CYCLES {
        let output = run_daemon(&["--binary-probe".to_string()]);
        let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "cycle {cycle} returned invalid probe JSON: {error}; stdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
        assert_eq!(value["status"], "ok", "cycle {cycle}: {value}");
        assert_eq!(value["protocol_version"], 1, "cycle {cycle}: {value}");
        assert!(
            value["pid"].as_u64().is_some_and(|pid| pid > 0),
            "cycle {cycle} did not report a process id: {value}"
        );
    }
}

#[test]
fn windows_tray_event_source_repeated_start_exit_is_clean() {
    for cycle in 0..TRAY_SOURCE_CYCLES {
        let event = json!({
            "event_type": "status",
            "sequence": cycle + 1,
            "emitted_at_ms": 1_700_000_000_000u64 + cycle,
            "connection_generation": cycle + 10,
            "payload": {
                "cycle": cycle,
                "state": "stopping"
            }
        });
        let args = vec![
            "--test-tray-event-source".to_string(),
            "--test-tray-event".to_string(),
            event.to_string(),
            "--test-tray-event-count".to_string(),
            "1".to_string(),
            "--test-tray-event-delay-ms".to_string(),
            "1".to_string(),
        ];
        let output = run_daemon(&args);
        let lines = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 1, "cycle {cycle}: {lines:?}");
        let envelope: Value = serde_json::from_str(&lines[0])
            .unwrap_or_else(|error| panic!("cycle {cycle} returned invalid event JSON: {error}"));
        assert_eq!(
            envelope["event"]["sequence"],
            cycle + 1,
            "cycle {cycle}: {envelope}"
        );
    }
}

#[test]
fn windows_tray_event_source_drains_bounded_sequence_before_exit() {
    let event = json!({
        "event_type": "status",
        "sequence": 77,
        "emitted_at_ms": 1_700_000_000_077u64,
        "connection_generation": 7,
        "payload": {"state": "running"}
    });
    let count = 8u64;
    let args = vec![
        "--test-tray-event-source".to_string(),
        "--test-tray-event".to_string(),
        event.to_string(),
        "--test-tray-event-count".to_string(),
        count.to_string(),
        "--test-tray-event-delay-ms".to_string(),
        Duration::from_millis(2).as_millis().to_string(),
    ];
    let output = run_daemon(&args);
    let envelopes = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("tray source must emit JSON lines"))
        .collect::<Vec<_>>();
    assert_eq!(envelopes.len(), count as usize);
    for (index, envelope) in envelopes.iter().enumerate() {
        assert_eq!(envelope["event"]["sequence"], 77 + index as u64);
    }
}
