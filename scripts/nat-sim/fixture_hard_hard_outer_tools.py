#!/usr/bin/env python3
"""PLANNED ONLY: declared O1/O2 offline external tools candidate.

Only cargo/go artifact creation, curl control responses and cooperative
NAT/control/relay child processes are fixtures. The Hard-Hard watcher is
verified against original source bytes and exec'd unchanged at the same PID.
This author has not executed or imported this module.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import stat
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
        raise ValueError("fixture_daemon_must_not_start_before_outer_gate")
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
        raise ValueError("fixture_undeclared_daemon_role")
    elif role == "nat":
        if settings["case"] not in {"direct-gate-not-active", "watcher-not-armed"}:
            raise ValueError("fixture_undeclared_outer_case")
        direct = Path(argument(argv, "--direct-gate-file"))
        if direct != directory / "hard-hard-direct.open":
            raise ValueError("fixture_original_direct_path_mismatch")
        if settings["case"] == "watcher-not-armed":
            armed = directory / "hard-hard-direct-gate.armed"
            # One declared invalid input, created before either STUN banner.
            # The original watcher's exclusive write must reject it itself.
            armed.mkdir(mode=0o700)
            append_event(root, {"tool": "armed_input_directory", "path": str(armed),
                                "pid": os.getpid(), "round": number})
        new_json(directory / "nat-trace.jsonl", {"event": "fixture_nat_ready", "fixture_only": True})
        if settings["case"] == "watcher-not-armed":
            print("DIRECT_GATE=1", flush=True)
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


def health_children_ready(root):
    """Observed fixture readiness, never product owner/exec authority.

    One bounded read attempt; ordinary curl7 leaves the original health poll
    and its original fixed work deadline in control. No sleep or retry here.
    """
    def regular_bytes(path, cap):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
                raise ValueError("fixture_readiness_input_not_regular_or_too_large")
            data = stream.read(cap + 1)
            if len(data) > cap:
                raise ValueError("fixture_readiness_input_too_large")
            return data

    def object_at(path):
        value = json.loads(regular_bytes(path, 32 * 1024))
        if not isinstance(value, dict):
            raise ValueError("fixture_readiness_not_object")
        return value

    try:
        directory = root / "artifacts/round-1"
        data = regular_bytes(root / "external-events.jsonl", 256 * 1024)
        lines = data.splitlines()
        if len(lines) > 512 or any(len(line) > 4096 for line in lines):
            return False
        events = [json.loads(line) for line in lines]
        if any(not isinstance(event, dict) for event in events):
            return False
        pids = set()
        for role, component in (("nat", "nat"), ("control", "control"), ("relay-1", "relay")):
            ready = object_at(directory / (role + ".fixture-ready.json"))
            pid = ready.get("pid")
            if (type(pid) is not int or pid <= 0 or pid in pids
                    or ready.get("role") != role or ready.get("component") != component
                    or type(ready.get("round")) is not int or ready["round"] != 1
                    or ready.get("fixture_only") is not True or ready.get("exit_code") is not None
                    or (directory / (role + ".fixture-stopped.json")).exists()):
                return False
            matched = [event for event in events if event.get("tool") == "child_ready"
                       and event.get("role") == role and event.get("pid") == pid
                       and type(event.get("pid")) is int and type(event.get("round")) is int
                       and event["round"] == 1 and event.get("fixture_only") is True]
            if len(matched) != 1:
                return False
            if role != "nat":
                declaration = object_at(directory / "launches" / (role + ".json"))
                if (type(declaration.get("pid")) is not int or declaration["pid"] != pid
                        or declaration.get("role") != role or declaration.get("component") != component):
                    return False
            os.kill(pid, 0)
            pids.add(pid)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        # Missing/partial readiness input is an ordinary not-ready health
        # response, not an infra banner and not permission for fake success.
        return False


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
        if not health_children_ready(root):
            append_event(root, {"tool": "curl", "endpoint": "/health", "port": parsed.port,
                                "round": 1, "side": None, "output": str(output) if output is not None else None,
                                "fixture_readiness": "not_ready", "exit_code": 7})
            return 7
        value = {"fixture_only": True, "status": "ok"}
    elif parsed.path == "/api/v1/register":
        value = {"token": "fixture-control-token"}
    elif parsed.path in {"/metrics", "/status"}:
        raise ValueError("fixture_diagnostics_must_not_start_before_outer_gate")
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
            if script.name == "hard_hard_gate.py":
                if settings["case"] != "watcher-not-armed" or "--watch" not in arguments:
                    raise ValueError("fixture_undeclared_watcher_entry")
                directory = round_for_path(root, argument(arguments, "--armed-file"))
                if Path(argument(arguments, "--armed-file")) != directory / "hard-hard-direct-gate.armed":
                    raise ValueError("fixture_watcher_armed_path_mismatch")
                append_event(root, {"tool": "original_watcher_exec", "pid": os.getpid(),
                                    "parent_pid": os.getppid(), "round": int(directory.name.removeprefix("round-")),
                                    "script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
                                    "argv": arguments})
                # No subprocess/return-code substitution: the shell's $! is
                # this same PID running the bound original watcher script.
                os.execv(real_python, [real_python, *arguments])
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
