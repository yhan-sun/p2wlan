use std::io;
use std::time::Duration;

const BINARY_PROBE_FLAG: &str = "--binary-probe";
const TRAY_SOURCE_FLAG: &str = "--test-tray-event-source";
const TRAY_EVENT_FLAG: &str = "--test-tray-event";
const TRAY_COUNT_FLAG: &str = "--test-tray-event-count";
const TRAY_DELAY_FLAG: &str = "--test-tray-event-delay-ms";

#[derive(Debug, PartialEq, Eq)]
enum LifecycleProbeCommand {
    Binary,
    Tray {
        event: String,
        count: usize,
        delay_ms: u64,
    },
}

fn lifecycle_probe_error(message: impl Into<String>) -> DaemonError {
    DaemonError::Config(format!("lifecycle probe: {}", message.into()))
}

fn parse_lifecycle_probe_args(
    args: &[String],
) -> p2pnet_daemon::Result<Option<LifecycleProbeCommand>> {
    let mentions_binary = args.iter().any(|arg| arg == BINARY_PROBE_FLAG);
    let mentions_tray = args
        .iter()
        .any(|arg| arg == TRAY_SOURCE_FLAG || arg.starts_with("--test-tray-event"));

    if !mentions_binary && !mentions_tray {
        return Ok(None);
    }
    if mentions_binary {
        if args.len() == 1 && args[0] == BINARY_PROBE_FLAG {
            return Ok(Some(LifecycleProbeCommand::Binary));
        }
        return Err(lifecycle_probe_error(
            "--binary-probe must be the only argument",
        ));
    }

    let mut source = false;
    let mut event = None;
    let mut count = 1usize;
    let mut delay_ms = 0u64;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            TRAY_SOURCE_FLAG => {
                if source {
                    return Err(lifecycle_probe_error(
                        "--test-tray-event-source was supplied more than once",
                    ));
                }
                source = true;
                index += 1;
            }
            TRAY_EVENT_FLAG => {
                let value = args.get(index + 1).ok_or_else(|| {
                    lifecycle_probe_error("--test-tray-event requires a JSON value")
                })?;
                if event.replace(value.clone()).is_some() {
                    return Err(lifecycle_probe_error(
                        "--test-tray-event was supplied more than once",
                    ));
                }
                index += 2;
            }
            TRAY_COUNT_FLAG => {
                let value = args.get(index + 1).ok_or_else(|| {
                    lifecycle_probe_error(
                        "--test-tray-event-count requires a value",
                    )
                })?;
                count = value.parse::<usize>().map_err(|_| {
                    lifecycle_probe_error(
                        "--test-tray-event-count must be an integer",
                    )
                })?;
                index += 2;
            }
            TRAY_DELAY_FLAG => {
                let value = args.get(index + 1).ok_or_else(|| {
                    lifecycle_probe_error(
                        "--test-tray-event-delay-ms requires a value",
                    )
                })?;
                delay_ms = value.parse::<u64>().map_err(|_| {
                    lifecycle_probe_error(
                        "--test-tray-event-delay-ms must be an integer",
                    )
                })?;
                index += 2;
            }
            unexpected => {
                return Err(lifecycle_probe_error(format!(
                    "unexpected argument {unexpected:?}",
                )));
            }
        }
    }

    if !source {
        return Err(lifecycle_probe_error(
            "tray event options require --test-tray-event-source",
        ));
    }
    let event = event.ok_or_else(|| {
        lifecycle_probe_error(
            "--test-tray-event-source requires --test-tray-event",
        )
    })?;
    if !(1..=1024).contains(&count) {
        return Err(lifecycle_probe_error(
            "--test-tray-event-count must be between 1 and 1024",
        ));
    }
    if delay_ms > 10_000 {
        return Err(lifecycle_probe_error(
            "--test-tray-event-delay-ms must not exceed 10000",
        ));
    }

    Ok(Some(LifecycleProbeCommand::Tray {
        event,
        count,
        delay_ms,
    }))
}

fn run_lifecycle_probe_from_process_args() -> p2pnet_daemon::Result<bool> {
    let mut args = Vec::new();
    for argument in std::env::args_os().skip(1) {
        args.push(
            argument
                .into_string()
                .map_err(|_| lifecycle_probe_error("arguments must be valid UTF-8"))?,
        );
    }
    let Some(command) = parse_lifecycle_probe_args(&args)? else {
        return Ok(false);
    };
    match command {
        LifecycleProbeCommand::Binary => emit_binary_lifecycle_probe()?,
        LifecycleProbeCommand::Tray {
            event,
            count,
            delay_ms,
        } => emit_tray_lifecycle_probe(&event, count, delay_ms)?,
    }
    Ok(true)
}

fn emit_binary_lifecycle_probe() -> p2pnet_daemon::Result<()> {
    let payload = serde_json::json!({
        "status": "ok",
        "protocol_version": 1,
        "pid": std::process::id(),
    });
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &payload).map_err(|error| {
        lifecycle_probe_error(format!(
            "failed to serialize binary response: {error}",
        ))
    })?;
    std::io::Write::write_all(&mut output, b"\n").map_err(|error| {
        lifecycle_probe_error(format!("failed to write binary response: {error}"))
    })?;
    std::io::Write::flush(&mut output).map_err(|error| {
        lifecycle_probe_error(format!("failed to flush binary response: {error}"))
    })
}

fn emit_tray_lifecycle_probe(
    raw_event: &str,
    count: usize,
    delay_ms: u64,
) -> p2pnet_daemon::Result<()> {
    let base_event: serde_json::Value = serde_json::from_str(raw_event).map_err(|error| {
        lifecycle_probe_error(format!("invalid --test-tray-event JSON: {error}"))
    })?;
    let base_sequence = base_event
        .as_object()
        .ok_or_else(|| {
            lifecycle_probe_error("--test-tray-event must be a JSON object")
        })?
        .get("sequence")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            lifecycle_probe_error(
                "--test-tray-event.sequence must be an unsigned integer",
            )
        })?;

    let stdout = io::stdout();
    let mut output = stdout.lock();
    for index in 0..count {
        let sequence = base_sequence
            .checked_add(index as u64)
            .ok_or_else(|| lifecycle_probe_error("tray event sequence overflow"))?;
        let mut event = base_event.clone();
        event
            .as_object_mut()
            .expect("tray event object was validated above")
            .insert("sequence".to_string(), serde_json::json!(sequence));
        let envelope = serde_json::json!({
            "protocol_version": 1,
            "event": event,
        });
        serde_json::to_writer(&mut output, &envelope).map_err(|error| {
            lifecycle_probe_error(format!("failed to serialize tray event: {error}"))
        })?;
        std::io::Write::write_all(&mut output, b"\n").map_err(|error| {
            lifecycle_probe_error(format!("failed to write tray event: {error}"))
        })?;
        std::io::Write::flush(&mut output).map_err(|error| {
            lifecycle_probe_error(format!("failed to flush tray event: {error}"))
        })?;
        if delay_ms > 0 && index + 1 < count {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    Ok(())
}

#[cfg(test)]
mod lifecycle_probe_tests {
    use super::*;

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn ordinary_daemon_arguments_are_not_intercepted() {
        assert_eq!(
            parse_lifecycle_probe_args(&owned(&["--config", "daemon.json"]))
                .expect("ordinary arguments must parse"),
            None
        );
    }

    #[test]
    fn binary_probe_is_exact_and_standalone() {
        assert_eq!(
            parse_lifecycle_probe_args(&owned(&[BINARY_PROBE_FLAG]))
                .expect("binary probe must parse"),
            Some(LifecycleProbeCommand::Binary)
        );
        let error = parse_lifecycle_probe_args(&owned(&[
            BINARY_PROBE_FLAG,
            "--config",
            "daemon.json",
        ]))
        .expect_err("binary probe must reject mixed daemon arguments");
        assert!(error.to_string().contains("must be the only argument"));
    }

    #[test]
    fn tray_probe_defaults_are_bounded_and_preserve_raw_event() {
        let event = r#"{"event_type":"status","sequence":77}"#;
        assert_eq!(
            parse_lifecycle_probe_args(&owned(&[
                TRAY_SOURCE_FLAG,
                TRAY_EVENT_FLAG,
                event,
            ]))
            .expect("tray probe must parse"),
            Some(LifecycleProbeCommand::Tray {
                event: event.to_string(),
                count: 1,
                delay_ms: 0,
            })
        );
    }

    #[test]
    fn tray_probe_rejects_missing_event_and_unbounded_count() {
        let missing = parse_lifecycle_probe_args(&owned(&[TRAY_SOURCE_FLAG]))
            .expect_err("tray source without an event must fail");
        assert!(missing.to_string().contains("requires --test-tray-event"));

        let too_many = parse_lifecycle_probe_args(&owned(&[
            TRAY_SOURCE_FLAG,
            TRAY_EVENT_FLAG,
            r#"{"sequence":1}"#,
            TRAY_COUNT_FLAG,
            "1025",
        ]))
        .expect_err("unbounded tray output must fail");
        assert!(too_many.to_string().contains("between 1 and 1024"));
    }
}
