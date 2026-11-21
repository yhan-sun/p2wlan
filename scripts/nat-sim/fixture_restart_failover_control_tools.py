#!/usr/bin/env python3
"""Declared offline external tools; never implements a harness decision.

Only cargo/go, curl responses, and the NAT/daemon/relay/control processes are
fixtures. Original shell/Python production entry points continue unchanged.
NEW restart/failover DRAFT only; author has not imported or executed it.
The original sampler/publisher/collector/cause and waits remain production.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import shlex
import sys
import time
from urllib.parse import urlsplit


def new_json(path, value):
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(data) > 32 * 1024:
        raise ValueError("fixture_json_limit")
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)


def append_event(root, value):
    value = {"monotonic_ns": time.monotonic_ns(), "fixture_only": True, **value}
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(data) > 4096:
        raise ValueError("fixture_event_size_limit")
    descriptor = os.open(root / "external-events.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        # One append per event. Concurrent requests retain whole bounded rows.
        if os.fstat(descriptor).st_size > 256 * 1024:
            raise ValueError("fixture_event_total_limit")
        if os.write(descriptor, data) != len(data):
            raise ValueError("fixture_short_event_write")
    finally:
        os.close(descriptor)


def argument(argv, name):
    index = argv.index(name)
    return argv[index + 1]


def round_for_path(root, value):
    path = Path(value).resolve()
    for candidate in (path, *path.parents):
        if candidate.parent == root / "artifacts" and candidate.name.startswith("round-"):
            return candidate
    raise ValueError("fixture_path_outside_original_round")



def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def regular_bytes(path, cap=32 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, "fixture_regular_capacity")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(cap + 1)
        after = os.fstat(descriptor)
        require(len(data) == before.st_size and len(data) <= cap, "fixture_regular_size")
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "fixture_regular_changed")
        return data
    finally:
        os.close(descriptor)


def regular_json(path):
    value = json.loads(regular_bytes(path))
    require(isinstance(value, dict), "fixture_json_object")
    return value


def live(pid):
    require(type(pid) is int and pid > 0, "fixture_PID_type")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def case_roles(settings):
    base = {"nat", "control", "node-a", "node-b", "relay-1"}
    return base | ({"relay-1-restart-1"} if settings["case"] == "restart-no-recovery" else {"relay-2"})


def primary(directory):
    value = regular_json(directory / "relay-1.fixture-ready.json")
    require(value["role"] == "relay-1" and value["component"] == "relay", "fixture_primary_role")
    return value["endpoint"]


def original_ready(root, directory, roles):
    try:
        events = [json.loads(row) for row in regular_bytes(root / "external-events.jsonl", 256 * 1024).splitlines()]
        require(len(events) <= 512, "fixture_events_capacity")
        for role in roles:
            ready = regular_json(directory / (role + ".fixture-ready.json"))
            require(ready["role"] == role and ready["round"] == 1 and live(ready["pid"]), "fixture_initial_role_not_live")
            matching = [row for row in events if row.get("tool") == "child_ready"
                        and row.get("role") == role and row.get("pid") == ready["pid"] and row.get("round") == 1]
            if len(matching) != 1:
                return False
            if role != "nat":
                declaration = regular_json(directory / "launches" / (role + ".json"))
                require(declaration["pid"] == ready["pid"] and declaration["role"] == role
                        and declaration["state"] == "exec_requested", "fixture_initial_launch_identity")
        return True
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def original_barrier_ready(directory):
    try:
        value = regular_json(directory / "relay-barrier.readiness.json")
        if value.get("result") != "ready":
            return False
        for side in ("a", "b"):
            ready = regular_json(directory / ("node-" + side + ".fixture-ready.json"))
            require(value["pid_" + side] == ready["pid"] and value["http_status_" + side] == 200
                    and value["process_alive_" + side] is True and value["task_health_" + side] is True
                    and value["relay_peer_confirmed_" + side] is True, "fixture_original_barrier_identity")
        return value.get("reason_code") is None
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def relay_launch(root, argv, settings):
    directory = root / "artifacts" / "round-1"
    matches = []
    for role in sorted(case_roles(settings) & {"relay-1", "relay-2", "relay-1-restart-1"}):
        path = directory / "launches" / (role + ".json")
        if path.exists():
            record = regular_json(path)
            if record.get("pid") == os.getpid():
                matches.append((role, record))
    require(len(matches) == 1, "fixture_relay_same_PID_original_launch")
    role, record = matches[0]
    artifacts = regular_json(root / "artifacts" / "artifact-set.json")
    require(record["role"] == role and record["component"] == "relay" and record["state"] == "exec_requested"
            and record["source"] == artifacts["source"] and record["artifact"] == artifacts["artifacts"]["relay"]
            and record["artifact_set_sha256"] == hashlib.sha256(regular_bytes(root / "artifacts" / "artifact-set.json")).hexdigest(),
            "fixture_relay_artifact_source")
    require(record["configuration"]["environment_keys"] == ["RELAY_AUDIENCE", "RELAY_REGION"],
            "fixture_relay_environment_scope")
    inputs = {"RELAY_AUDIENCE": os.environ.get("RELAY_AUDIENCE"), "RELAY_REGION": os.environ.get("RELAY_REGION")}
    payload = {"source": "cli_and_controlled_environment", "scope": "argv_and_allowlisted_environment",
               "argv": argv, "environment": inputs, "config_file": {"state": "not_supplied", "sha256": None},
               "excluded_inputs": []}
    argv_configuration_sha = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    require(record["configuration"]["sha256"] == argv_configuration_sha
            and record["configuration"]["argument_count"] == len(argv), "fixture_relay_original_argv")
    require(inputs["RELAY_REGION"] == "local"
            and inputs["RELAY_AUDIENCE"] == ("relay-sim-2" if role == "relay-2" else "relay-sim"),
            "fixture_relay_catalog_audience")
    bind = argument(argv, "-bind")
    require(bind.startswith("127.0.0.1:") and bind.rpartition(":")[2].isdigit(), "fixture_relay_bind")
    require("-require-auth" in argv and "-allow-insecure-plaintext" in argv
            and argument(argv, "-forward-delay") == "0ms", "fixture_relay_auth_argv")
    return directory, role, "tcp://" + bind, argv_configuration_sha


def config(root):
    value = regular_json(root / "fixture-config.json")
    require(value["case"] in {"restart-no-recovery", "failover-no-replacement"} and value["rounds"] == 1
            and value["fixture_only"] is True and value["cli_seconds"] == 24,
            "fixture_restart_failover_config")
    source_commit = value["original_source_commit"]
    require(isinstance(source_commit, str) and len(source_commit) == 40
            and all(character in "0123456789abcdef" for character in source_commit),
            "fixture_restart_failover_observed_commit_shape")
    return value


def artifact(root, destination, component, real_python):
    destination = Path(destination)
    if not destination.resolve().is_relative_to(root):
        raise ValueError("fixture_build_destination_outside_private_root")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    script = ("#!/bin/sh\nexec "
              + shlex.join([real_python, "-S", str(Path(__file__).resolve()), str(root), "child", component])
              + ' "$@"\n')
    with destination.open("x") as stream:
        os.fchmod(stream.fileno(), 0o700)
        stream.write(script)
    append_event(root, {"tool": "build", "component": component,
                        "output_sha256": hashlib.sha256(script.encode()).hexdigest()})


def child(root, component, argv):
    settings = config(root)
    extra = {}
    if component == "nat":
        directory = round_for_path(root, argument(argv, "--trace-file"))
        role = "nat"
        require("--block-direct" in argv, "fixture_original_block_direct_argv_missing")
    elif component == "daemon":
        role = argument(argv, "--device-name")
        require(role in {"node-a", "node-b"} and "--overlay-any-path" in argv
                and argument(argv, "--overlay-burst") == "256"
                and "--overlay-start-gate-file" not in argv, "fixture_relay_only_node_argv")
        directory = round_for_path(root, argument(argv, "--config"))
    elif component == "control":
        role = "control"
        directory = round_for_path(root, os.environ["DB_PATH"])
        extra["control_port"] = int(os.environ["PORT"])
    elif component == "relay":
        directory, role, endpoint, identity = relay_launch(root, argv, settings)
        extra.update(endpoint=endpoint, metrics_bind=argument(argv, "-metrics-bind"),
                     argv_sha256=hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest(),
                     original_configuration_sha256=identity)
    else:
        raise ValueError("fixture_unknown_child_component")
    require(directory.name == "round-1" and role in case_roles(settings), "fixture_role_or_round")
    ready = {"pid": os.getpid(), "role": role, "round": 1, "component": component,
             "exit_code": None, "fixture_only": True, **extra}
    stopped = False
    def stop(signum, _frame):
        nonlocal stopped
        if stopped:
            return
        stopped = True
        stamp = time.monotonic_ns()
        new_json(directory / (role + ".fixture-stopped.json"),
                 {**ready, "signal": signum, "exit_code": 0, "monotonic_ns": stamp})
        append_event(root, {"tool": "child_stopped", "role": role, "pid": os.getpid(),
                            "round": 1, "signal": signum, "exit_code": 0})
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if role.startswith("node-"):
        token = sys.stdin.readline().strip()
        require(token == "fixture-control-token", "fixture_token_stdin_not_forwarded")
        runtime = Path(argument(argv, "--config")).parent
        ready["diagnostics_port"] = int(argument(argv, "--diagnostics-bind").rpartition(":")[2])
        new_json(runtime / "config.json", {"fixture_only": True, "side": role})
        with (runtime / "p2wlan-daemon.diag-auth").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write("fixture-diagnostics-token\n")
        endpoint = primary(directory)
        print("Control plane registration confirmed", flush=True)
        print('event="relay_transport_ready_peer" t_ms=10 fixture_only=true', flush=True)
        print('event="relay_peer_confirmed" t_ms=11 relay_endpoint=' + endpoint + ' fixture_only=true', flush=True)
    elif role == "nat":
        new_json(directory / "nat-trace.jsonl", {"event": "fixture_nat_ready", "fixture_only": True})
        print("STUN_A=127.0.0.1:31001", flush=True)
        print("STUN_B=127.0.0.1:31002", flush=True)
        print("BLOCK_DIRECT=1", flush=True)
    new_json(directory / (role + ".fixture-ready.json"), {**ready, "monotonic_ns": time.monotonic_ns()})
    append_event(root, {"tool": "child_ready", "role": role, "pid": os.getpid(), "round": 1})
    # One NEW-case fixed lifetime, not a new product deadline or retry window.
    fixture_end = time.monotonic() + 24
    business = False
    while time.monotonic() < fixture_end:
        if role.startswith("node-") and not business and original_barrier_ready(directory):
            business = True
            endpoint = primary(directory)
            # Commit the fixture input before the final burst marker can let
            # the original loop take its collector snapshot.
            new_json(directory / (role + ".fixture-business.json"),
                     {"pid": os.getpid(), "role": role, "round": 1, "fixture_only": True,
                      "endpoint": endpoint, "monotonic_ns": time.monotonic_ns()})
            print('event="first_real_business_ingress" t_ms=20 path="relay" relay_id=' + endpoint + ' fixture_only=true', flush=True)
            for sequence in range(100):
                print("overlay_payload_verified ingress=relay:" + endpoint + " continuous_sequence=" + str(sequence) + " fixture_only=true", flush=True)
            for sequence in range(256):
                print("overlay_payload_verified ingress=relay:" + endpoint + " burst_sequence=" + str(sequence) + " fixture_only=true", flush=True)
            print("overlay_burst_complete packets=256 fixture_only=true", flush=True)
            append_event(root, {"tool": "initial_relay_business_complete", "role": role,
                                "pid": os.getpid(), "round": 1, "endpoint": endpoint,
                                "continuous_count": 100, "burst_count": 256})
        time.sleep(0.005)
    append_event(root, {"tool": "child_fixture_deadline", "role": role, "pid": os.getpid(), "round": 1})
    return 91


def status(directory, side, baseline):
    role = "node-" + side
    ready = regular_json(directory / (role + ".fixture-ready.json"))
    endpoint = primary(directory)
    peer = "node-b" if side == "a" else "node-a"
    business = not baseline and (directory / (role + ".fixture-business.json")).is_file()
    revision, timestamp = (4, 30) if business else (1, 5)
    summary = {"schema_version": 2, "peer_id": peer, "path": "relay", "network_generation": 1,
               "first_usable_at_ms": 20, "transition_revision": 3, "relay_ready_at_ms": 10,
               "first_usable_delta_ms": 10, "direct_first_remaining_ms_at_relay_ready": 0,
               "business_sent": True, "business_received": True, "business_exchange": True,
               "relay_id": endpoint, "relay_connection_id": 1,
               "source": "authoritative_business_ingress_commit"}
    return {"fixture_only": True, "process_id": ready["pid"], "node_id": role,
            "network_generation": 1, "revision": revision, "captured_revision": revision,
            "captured_at_ms": timestamp, "uptime_ms": timestamp, "peer_snapshot_stale": False,
            "relay_connected": True, "stats": {"outbound_drops": {}, "outbound_loss_events": []},
            "health": {"critical_tasks": [{"critical": True, "running": True, "finished": False, "error": None}]},
            "peers": [{"node_id": peer, "online": True, "relay_confirmed_endpoint": endpoint,
                       "relay_confirmed_generation": 1, "relay_confirmed_connection_id": 1,
                       "relay_first_business_sent_generation": 1 if business else None,
                       "relay_first_business_received_generation": 1 if business else None,
                       "relay_first_business_exchange_generation": 1 if business else None}],
            "connection_timeline": {"correlation_id": role + "-fixture-round-" + directory.name,
                "events": [{"event": "relay_transport_ready_peer", "at_ms": 10, "peer_id": peer,
                            "connection_generation": 1, "direct_first_remaining_ms": 0},
                           {"event": "first_usable_path", "at_ms": 20, "peer_id": peer,
                            "connection_generation": 1, "path": "relay", "transition_revision": 3}] if business else [],
                "first_usable_summaries": [summary] if business else []}}


def curl(root, argv):
    urls = [item for item in argv if item.startswith(("http://", "https://"))]
    require(len(urls) == 1, "fixture_exactly_one_url_required")
    parsed = urlsplit(urls[0])
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None,
            "fixture_non_loopback_url_rejected")
    settings = config(root)
    directory = root / "artifacts" / "round-1"
    output_text = argument(argv, "-o") if "-o" in argv else argument(argv, "--output") if "--output" in argv else None
    output = Path(output_text) if output_text else None
    sampling = output_text == os.devnull
    side = None
    if parsed.path == "/health":
        roles = {"nat", "control", "relay-1"} | ({"relay-2"} if settings["case"] == "failover-no-replacement" else set())
        if not original_ready(root, directory, roles):
            return 7
        control = regular_json(directory / "control.fixture-ready.json")
        require(parsed.port == control["control_port"], "fixture_health_original_control_port")
        value = {"fixture_only": True, "status": "ok"}
    elif parsed.path == "/api/v1/register":
        require(parsed.port == regular_json(directory / "control.fixture-ready.json")["control_port"], "fixture_register_original_port")
        value = {"token": "fixture-control-token"}
    elif parsed.path == "/metrics":
        require(str(parsed.port) == regular_json(directory / "relay-1.fixture-ready.json")["metrics_bind"].rpartition(":")[2],
                "fixture_metrics_primary_port")
        value = {"fixture_only": True, "active_connections": 2, "registered_peers": 2,
                 "forwarded_frames_total": 2, "forward_errors_total": 0}
    elif parsed.path == "/status":
        require(output is not None, "fixture_status_output_missing")
        candidates = []
        for candidate_side in ("a", "b"):
            ready = regular_json(directory / ("node-" + candidate_side + ".fixture-ready.json"))
            declaration = regular_json(directory / "launches" / ("node-" + candidate_side + ".json"))
            require(declaration["pid"] == ready["pid"] and declaration["role"] == "node-" + candidate_side,
                    "fixture_status_original_launch_PID")
            if parsed.port == ready["diagnostics_port"]:
                candidates.append(candidate_side)
        require(len(candidates) == 1, "fixture_status_diagnostics_port_side")
        side = candidates[0]
        if sampling:
            require(argv.count("--config") == 1 and argument(argv, "--config") == "-"
                    and argv.count("--output") == 1 and "-o" not in argv,
                    "fixture_sample_original_config_stdin")
            auth_input = sys.stdin.buffer.read(4097)
            require(auth_input == b'header = "Authorization: Bearer fixture-diagnostics-token"\n',
                    "fixture_sample_stdin_auth")
            require(argument(argv, "--connect-timeout") == "0.2", "fixture_sample_connect_timeout")
            max_time = argument(argv, "--max-time")
            require(max_time.isdigit() and 1 <= int(max_time) <= 5, "fixture_sample_max_time")
            writeout = "%{http_code}\t%{time_connect}\t%{time_starttransfer}\t%{time_total}\t%{size_download}"
            require(argument(argv, "--write-out") == writeout, "fixture_sample_five_TAB_writeout")
            header = Path(argument(argv, "--dump-header"))
            require(header == directory / (".status-" + side + "-headers")
                    and stat.S_IMODE(header.lstat().st_mode) == 0o600
                    and stat.S_ISREG(header.lstat().st_mode), "fixture_sample_original_header")
            regular_bytes(header, 4096)
            request_id = "fixture-sample-" + side + "-" + str(os.getpid())
            with header.open("w") as stream:
                stream.write("HTTP/1.1 200 OK\r\nX-P2WLAN-Status-Request-Id: " + request_id + "\r\n\r\n")
            # /dev/null is only a discard selection. Never open/write/chmod it.
            append_event(root, {"tool": "curl", "sampling": True, "endpoint": "/status",
                                "round": 1, "side": side, "port": parsed.port, "output": os.devnull,
                                "curl_pid": os.getpid(), "target_pid": regular_json(directory / ("node-" + side + ".fixture-ready.json"))["pid"],
                                "max_time": int(max_time), "request_id": request_id, "argv": argv,
                                "argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest(),
                                "auth_config_sha256": hashlib.sha256(auth_input).hexdigest()})
            sys.stdout.write("200\t0.001\t0.002\t0.003\t0")
            return 0
        require(round_for_path(root, output) == directory
                and output.name.startswith("node-" + side + "."), "fixture_status_output_side")
        headers = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-H"]
        require("Authorization: Bearer fixture-diagnostics-token" in headers, "fixture_diagnostics_authorization_missing")
        value = status(directory, side, ".baseline.status.json" in output.name)
    else:
        raise ValueError("fixture_unhandled_endpoint")
    require(not sampling, "fixture_devnull_only_status_sampling")
    append_event(root, {"tool": "curl", "sampling": False, "endpoint": parsed.path, "port": parsed.port,
                        "round": 1 if side else None, "side": side,
                        "output": str(output) if output is not None else None})
    payload = json.dumps(value, separators=(",", ":"))
    if output is not None:
        require(output.resolve().is_relative_to(root), "fixture_response_output_outside_private_root")
        output.write_text(payload + "\n")
        output.chmod(0o600)
    elif "-w" not in argv:
        print(payload, end="")
    if "-w" in argv:
        sys.stdout.write("200")
    return 0


def main(argv):
    root = Path(argv[0]).resolve()
    tool, arguments = argv[1], argv[2:]
    settings = config(root)
    real_python = settings["real_python"]
    if tool == "child":
        return child(root, arguments[0], arguments[1:])
    if tool == "cargo":
        manifest = str(Path(settings["private_repository"]) / "client/daemon/Cargo.toml")
        if arguments == ["build", "-p", "p2wlan-daemon", "--manifest-path", manifest]:
            artifact(root, root / "fake-target/debug/p2wlan-daemon", "daemon", real_python)
            return 0
        if arguments == ["metadata", "--no-deps", "--format-version", "1", "--manifest-path", manifest]:
            print(json.dumps({"target_directory": str(root / "fake-target")}))
            return 0
        raise ValueError("fixture_unhandled_cargo_invocation")
    if tool == "go":
        if arguments in [["build", "-o", str(root / "artifacts/control-server"), "."],
                         ["build", "-o", str(root / "artifacts/relay-server"), "./relay"]]:
            artifact(root, argument(arguments, "-o"), "control" if arguments[-1] == "." else "relay", real_python)
            return 0
        if arguments == ["run", str(Path(settings["private_repository"]) / "scripts/relay_keygen.go")]:
            print("fixture-relay-seed fixture-relay-public")
            return 0
        raise ValueError("fixture_unhandled_go_invocation")
    if tool == "curl":
        return curl(root, arguments)
    if tool == "python3":
        if not arguments:
            raise ValueError("fixture_python_arguments_missing")
        if arguments[0] not in {"-", "-c"}:
            script = Path(arguments[0]).resolve()
            if not script.is_relative_to(Path(settings["private_repository"])):
                raise ValueError("fixture_python_script_outside_private_layout")
            relative = str(script.relative_to(Path(settings["private_repository"])))
            if relative not in settings["original_sources"] or hashlib.sha256(script.read_bytes()).hexdigest() != settings["original_sources"][relative]:
                raise ValueError("fixture_python_script_not_original_bound_bytes")
            if script.name == "nat_sim.py":
                return child(root, "nat", arguments[1:])
            if script.name == "reserve_port_block.py":
                if "--release" in arguments:
                    reservation = Path(argument(arguments, "--release"))
                    lock_manifest = reservation / "port-locks"
                    if (not reservation.resolve().is_relative_to(root) or not lock_manifest.is_file()
                            or lock_manifest.stat().st_size > 4096):
                        raise ValueError("fixture_original_port_release_manifest_invalid")
                    append_event(root, {"tool": "original_port_release", "reservation": str(reservation),
                                        "original_script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                                        "lock_manifest_sha256": hashlib.sha256(lock_manifest.read_bytes()).hexdigest()})
                else:
                    append_event(root, {"tool": "original_port_reservation",
                                        "original_script_sha256": hashlib.sha256(script.read_bytes()).hexdigest()})
            if script.name == "collect_evidence.py":
                output = argument(arguments, "--output")
                directory = round_for_path(root, output)
                append_event(root, {"tool": "original_collector_enter", "round": int(directory.name.removeprefix("round-")),
                                    "output": output, "original_script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                                    "pid": os.getpid(),
                                    "command_argv_sha256": hashlib.sha256(json.dumps(["python3", *arguments], ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()})
        os.execv(real_python, [real_python, *arguments])
    raise ValueError("fixture_unhandled_tool")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, IndexError) as error:
        # Reject unknown seams. No fallback can reach real cargo/go/curl/NAT.
        print("B01_FIXTURE_INFRA_FAILURE:" + type(error).__name__ + ":" + str(error), file=sys.stderr)
        raise SystemExit(92)
