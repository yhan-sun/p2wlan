#!/usr/bin/env python3
"""Declared offline external tools; never implements a harness decision.

Only cargo/go, curl responses, and the NAT/daemon/relay/control processes are
fixtures. Original shell/Python production entry points continue unchanged.
This module is a candidate only. Its author has not executed it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
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


def config(root):
    return json.loads((root / "fixture-config.json").read_text())


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
    if component == "nat":
        directory = round_for_path(root, argument(argv, "--trace-file"))
        role = "nat"
    elif component == "daemon":
        role = argument(argv, "--device-name")
        directory = round_for_path(root, argument(argv, "--config"))
    elif component == "control":
        role = "control"
        directory = round_for_path(root, os.environ["DB_PATH"])
    elif component == "relay":
        role = "relay-1"
        # A relay starts before DB_PATH is updated in the main loop. Resolve its
        # actual original record by the current process PID; exec already wrote
        # that record before entering this external fixture binary.
        matches = []
        for record in (root / "artifacts").glob("round-*/launches/relay-1.json"):
            if json.loads(record.read_text()).get("pid") == os.getpid():
                matches.append(record.parent.parent)
        if len(matches) != 1:
            raise ValueError("fixture_relay_original_launch_record_missing")
        directory = matches[0]
    else:
        raise ValueError("fixture_unknown_child_component")
    number = int(directory.name.removeprefix("round-"))
    ready = {"pid": os.getpid(), "role": role, "round": number,
             "component": component, "exit_code": None, "fixture_only": True}
    stopped = False

    def stop(signum, _frame):
        nonlocal stopped
        if stopped:
            return
        stopped = True
        new_json(directory / (role + ".fixture-stopped.json"),
                 {**ready, "signal": signum, "exit_code": 0,
                  "monotonic_ns": time.monotonic_ns()})
        append_event(root, {"tool": "child_stopped", "role": role, "pid": os.getpid(),
                            "round": number, "signal": signum, "exit_code": 0})
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if role.startswith("node-"):
        # Launch identity, stdin forwarding, token readiness and the shell's
        # readiness implementation all remain real. This daemon itself is fake.
        token = sys.stdin.readline().strip()
        if token != "fixture-control-token":
            raise ValueError("fixture_token_stdin_not_forwarded")
        runtime = Path(argument(argv, "--config")).parent
        ready["diagnostics_port"] = int(argument(argv, "--diagnostics-bind").rpartition(":")[2])
        new_json(runtime / "config.json", {"fixture_only": True, "side": role})
        if not (settings["case"] == "startup-token-missing" and role == "node-a"):
            with (runtime / "p2wlan-daemon.diag-auth").open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write("fixture-diagnostics-token\n")
        print("Control plane registration confirmed", flush=True)
        print('event="relay_transport_ready_peer" t_ms=10 fixture_only=true', flush=True)
        print('event="relay_peer_confirmed" t_ms=11 relay_endpoint=fixture-relay fixture_only=true', flush=True)
        print('event="direct_promoted" t_ms=12 fixture_only=true', flush=True)
        print("→ direct fixture_only=true", flush=True)
    elif role == "nat":
        new_json(directory / "nat-trace.jsonl", {"event": "fixture_nat_ready", "fixture_only": True})
        print("STUN_A=127.0.0.1:31001", flush=True)
        print("STUN_B=127.0.0.1:31002", flush=True)
    new_json(directory / (role + ".fixture-ready.json"), {**ready, "monotonic_ns": time.monotonic_ns()})
    append_event(root, {"tool": "child_ready", "role": role, "pid": os.getpid(), "round": number})
    gate = directory / "business-validation.start-gate"
    business = False
    # Cooperative fake processes use one fixed fixture lifetime. This does not
    # change a production work/capture deadline, and expiry is fixture failure.
    fixture_end = time.monotonic() + 12
    while time.monotonic() < fixture_end:
        if role.startswith("node-") and gate.is_file() and not business:
            business = True
            print('event="overlay_start_gate_released" t_ms=15 fixture_only=true', flush=True)
            print('event="first_real_business_ingress" t_ms=20 path="direct" fixture_only=true', flush=True)
            print("overlay_payload_verified ingress=direct fixture_only=true", flush=True)
            new_json(directory / (role + ".fixture-business.json"),
                     {"pid": os.getpid(), "role": role, "round": number,
                      "fixture_only": True, "monotonic_ns": time.monotonic_ns()})
        time.sleep(0.005)
    append_event(root, {"tool": "child_fixture_deadline", "role": role,
                        "pid": os.getpid(), "round": number})
    return 91


def status(directory, side, baseline):
    role = "node-" + side
    ready = json.loads((directory / (role + ".fixture-ready.json")).read_text())
    peer = "node-b" if side == "a" else "node-a"
    revision = 1 if baseline else 4
    timestamp = 5 if baseline else 30
    summary = {"schema_version": 2, "peer_id": peer, "path": "direct", "network_generation": 1,
               "first_usable_at_ms": 20, "transition_revision": 3, "relay_ready_at_ms": 10,
               "first_usable_delta_ms": 10, "direct_first_remaining_ms_at_relay_ready": 0,
               "business_sent": True, "business_received": True, "business_exchange": True,
               "relay_id": None, "relay_connection_id": None,
               "source": "authoritative_business_ingress_commit"}
    value = {"fixture_only": True, "process_id": ready["pid"], "node_id": role,
             "network_generation": 1, "revision": revision, "captured_revision": revision,
             "captured_at_ms": timestamp, "uptime_ms": timestamp, "peer_snapshot_stale": False,
             "relay_connected": False, "stats": {"outbound_drops": {}, "outbound_loss_events": []},
             "health": {"critical_tasks": [{"critical": True, "running": True,
                                             "finished": False, "error": None}]},
             "peers": [{"node_id": peer, "online": True}],
             "connection_timeline": {"correlation_id": role + "-fixture-round-" + directory.name,
                 "events": [] if baseline else [
                     {"event": "relay_transport_ready_peer", "at_ms": 10, "peer_id": peer,
                      "connection_generation": 1, "direct_first_remaining_ms": 0},
                     {"event": "first_usable_path", "at_ms": 20, "peer_id": peer,
                      "connection_generation": 1, "path": "direct", "transition_revision": 3}],
                 "first_usable_summaries": [] if baseline else [summary]}}
    if not baseline and not (directory / (role + ".fixture-business.json")).is_file():
        value["connection_timeline"]["events"] = []
        value["connection_timeline"]["first_usable_summaries"] = []
    return value


def curl(root, argv):
    urls = [item for item in argv if item.startswith(("http://", "https://"))]
    if len(urls) != 1:
        raise ValueError("fixture_exactly_one_url_required")
    parsed = urlsplit(urls[0])
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise ValueError("fixture_non_loopback_url_rejected")
    output = Path(argument(argv, "-o")) if "-o" in argv else None
    settings = config(root)
    number = None
    side = None
    if parsed.path == "/health":
        value = {"fixture_only": True, "status": "ok"}
    elif parsed.path == "/api/v1/register":
        value = {"token": "fixture-control-token"}
    elif parsed.path == "/metrics":
        value = {"fixture_only": True, "active_connections": 2, "registered_peers": 2,
                 "forwarded_frames_total": 2, "forward_errors_total": 0}
    elif parsed.path == "/status":
        if output is None:
            raise ValueError("fixture_status_requires_original_output")
        directory = round_for_path(root, output)
        number = int(directory.name.removeprefix("round-"))
        side = "a" if "node-a." in output.name else "b" if "node-b." in output.name else None
        if side is None:
            # The original HTTP sampling helper uses /dev/null rather than a
            # round-side path. First batch uses Direct and never calls it.
            raise ValueError("fixture_unhandled_status_output")
        headers = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-H"]
        if "Authorization: Bearer fixture-diagnostics-token" not in headers:
            raise ValueError("fixture_diagnostics_authorization_missing")
        baseline = ".baseline.status.json" in output.name
        failed = settings["case"] in {"baseline-failure", "first-failed-second-pass"} and number == 1
        value = status(directory, side, baseline)
        if baseline and side == "b" and failed:
            value = {"fixture_only": True, "malformed_status_for_original_schema_gate": True}
        # Validate that the port came from the real main's reserved block and
        # its original declaration, rather than a fixture-chosen endpoint.
        launch = json.loads((directory / "launches" / ("node-" + side + ".json")).read_text())
        ready = json.loads((directory / ("node-" + side + ".fixture-ready.json")).read_text())
        if launch["pid"] != ready["pid"] or parsed.port != ready["diagnostics_port"]:
            raise ValueError("fixture_status_launch_pid_mismatch")
    else:
        raise ValueError("fixture_unhandled_endpoint")
    append_event(root, {"tool": "curl", "endpoint": parsed.path, "port": parsed.port,
                        "round": number, "side": side,
                        "output": str(output) if output is not None else None})
    payload = json.dumps(value, separators=(",", ":"))
    if output is not None:
        if not output.resolve().is_relative_to(root):
            raise ValueError("fixture_response_output_outside_private_root")
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
                                    "output": output, "original_script_sha256": hashlib.sha256(script.read_bytes()).hexdigest()})
        os.execv(real_python, [real_python, *arguments])
    raise ValueError("fixture_unhandled_tool")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, IndexError) as error:
        # Reject unknown seams. No fallback can reach real cargo/go/curl/NAT.
        print("B01_FIXTURE_INFRA_FAILURE:" + type(error).__name__ + ":" + str(error), file=sys.stderr)
        raise SystemExit(92)
