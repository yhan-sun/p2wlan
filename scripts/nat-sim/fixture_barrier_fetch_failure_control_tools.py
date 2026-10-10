#!/usr/bin/env python3
"""Declared offline external tools; never implements a harness decision.

Only cargo/go, curl responses, and the NAT/daemon/relay/control processes are
fixtures. Original shell/Python production entry points continue unchanged.
This NEW positive-control DRAFT declares one original curl7 barrier input.
Its author has neither imported nor executed this candidate or product code.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
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
    value = json.loads((root / "fixture-config.json").read_text())
    if (not isinstance(value, dict) or value.get("fixture_only") is not True
            or value.get("case") != "barrier-curl7-control"
            or type(value.get("rounds")) is not int or value["rounds"] != 1):
        raise ValueError("fixture_undeclared_barrier_case_or_round")
    return value


def artifact(root, destination, component, real_python):
    destination = Path(destination)
    if not destination.resolve().is_relative_to(root):
        raise ValueError("fixture_build_destination_outside_private_root")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fixed_arguments = (real_python, "-S", str(Path(__file__).resolve()), str(root), "child", component)
    script = "#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in fixed_arguments) + ' "$@"\n'
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
    if number != 1 or role not in {"nat", "control", "relay-1", "node-a", "node-b"}:
        raise ValueError("fixture_undeclared_child_role_or_round")
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
        if "--validate-overlay" not in argv:
            raise ValueError("fixture_original_overlay_validation_missing")
        direct = settings["case"] == "barrier-curl7-control"
        if direct:
            if ("--overlay-any-path" in argv or "--overlay-start-gate-file" not in argv
                    or Path(argument(argv, "--overlay-start-gate-file")) != directory / "business-validation.start-gate"):
                raise ValueError("fixture_original_direct_overlay_flags_mismatch")
        elif "--overlay-any-path" not in argv or "--overlay-start-gate-file" in argv:
            raise ValueError("fixture_original_availability_overlay_flags_mismatch")
        # Safe observations derived only after validating the actual original
        # argv above. The original launch record retains only its input hash.
        ready["overlay_validation"] = True
        ready["overlay_any_path"] = "--overlay-any-path" in argv
        ready["overlay_start_gate_file"] = argument(argv, "--overlay-start-gate-file") if direct else None
        with (runtime / "p2wlan-daemon.diag-auth").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write("fixture-diagnostics-token\n")
        print("Control plane registration confirmed", flush=True)
        print('event="relay_transport_ready_peer" t_ms=10 fixture_only=true', flush=True)
        print('event="relay_peer_confirmed" t_ms=11 relay_endpoint=fixture-relay fixture_only=true', flush=True)
        if direct:
            print('event="direct_promoted" t_ms=12 fixture_only=true', flush=True)
            print("→ direct fixture_only=true", flush=True)
    elif role == "nat":
        if "--direct-gate-file" in argv:
            raise ValueError("fixture_undeclared_hard_hard_nat_gate")
        availability = False
        if availability:
            if argv.count("--block-direct") != 1:
                raise ValueError("fixture_original_availability_blackhole_flag_missing")
            print("BLOCK_DIRECT=1", flush=True)
        elif "--block-direct" in argv:
            raise ValueError("fixture_undeclared_direct_blackhole_flag")
        new_json(directory / "nat-trace.jsonl", {"event": "fixture_nat_ready", "fixture_only": True})
        print("STUN_A=127.0.0.1:31001", flush=True)
        print("STUN_B=127.0.0.1:31002", flush=True)
    new_json(directory / (role + ".fixture-ready.json"), {**ready, "monotonic_ns": time.monotonic_ns()})
    append_event(root, {"tool": "child_ready", "role": role, "pid": os.getpid(), "round": number})
    gate = directory / "business-validation.start-gate"
    # These declared fake producers retain the existing fixture gate rule.
    # Availability's original argv has no overlay-start gate: withholding its
    # payload here is an external fake input, never proof of a product gate.
    business = False
    # Cooperative fake processes use one fixed fixture lifetime. This does not
    # change a production work/capture deadline, and expiry is fixture failure.
    fixture_end = time.monotonic() + 20
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


def bounded_regular_bytes(path, cap, required_mode=None):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > cap
                or (required_mode is not None and before.st_mode & 0o777 != required_mode)):
            raise ValueError("fixture_snapshot_type_mode_or_size_rejected")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(cap + 1)
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if len(data) != before.st_size or len(data) > cap or identity(before) != identity(after):
            raise ValueError("fixture_snapshot_changed_or_short")
        return data, {"dev": before.st_dev, "ino": before.st_ino, "size": before.st_size,
                      "mtime_ns": before.st_mtime_ns, "mode": before.st_mode & 0o777}
    finally:
        os.close(descriptor)


def observe_inherited_fd(settings):
    import fcntl
    expected = settings["inherited_fd"]
    descriptor = expected["fd"]
    if type(descriptor) is not int or descriptor < 3:
        raise ValueError("fixture_inherited_fd_invalid")
    info = os.fstat(descriptor)
    flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    before = os.lseek(descriptor, 0, os.SEEK_CUR)
    if (not stat.S_ISREG(info.st_mode) or info.st_size > 4096
            or (flags & os.O_ACCMODE) != os.O_RDONLY
            or info.st_dev != expected["dev"] or info.st_ino != expected["ino"]
            or info.st_size != expected["bytes"]):
        raise ValueError("fixture_inherited_fd_identity_or_access_mismatch")
    data = os.pread(descriptor, 4097, 0)
    after = os.lseek(descriptor, 0, os.SEEK_CUR)
    if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"] or before != after:
        raise ValueError("fixture_inherited_fd_content_or_offset_mismatch")
    return {"fd": descriptor, "dev": info.st_dev, "ino": info.st_ino, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "access": "read_only",
            "offset_before": before, "offset_after": after, "validated": True}


def snapshot_metadata(root, argv):
    if len(argv) != 4:
        raise ValueError("fixture_snapshot_argument_count")
    settings = config(root)
    owner_pid, incoming = int(argv[2]), int(argv[3])
    if owner_pid <= 0 or incoming < 0 or incoming > 255:
        raise ValueError("fixture_snapshot_owner_or_status_invalid")
    directory = root / "artifacts/round-1"
    inputs = {}
    for side, argument_path in zip(("a", "b"), argv[:2]):
        path = Path(argument_path)
        if path != directory / (".barrier-" + side + "-fetch"):
            raise ValueError("fixture_snapshot_not_original_metadata_path")
        data, identity = bounded_regular_bytes(path, 64 * 1024, 0o600)
        inputs[side] = {"path": str(path), "raw_hex": data.hex(), "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(), "identity": identity}
    value = {"fixture_only": True, "observer": "pre_original_metadata_rm", "owner_pid": owner_pid,
             "incoming_status": incoming, "observed_parent_pid": os.getppid(),
             "sub": 0, "frame": "fetch_relay_barrier_status_pair",
             "command": 'rm -f "$a_meta" "$b_meta"', "monotonic_ns": time.monotonic_ns(),
             "original_main_sha256": settings["original_sources"]["scripts/nat-sim/nat-sim-smoke.sh"],
             "original_metadata": inputs}
    path = root / "metadata-before-original-rm.json"
    new_json(path, value)
    append_event(root, {"tool": "original_metadata_readonly_snapshot", "owner_pid": owner_pid,
                        "snapshot_path": str(path), "snapshot_sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return 0


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
    baseline = False
    barrier = False
    barrier_unhealthy_input = False
    if parsed.path == "/health":
        if not health_children_ready(root):
            append_event(root, {"tool": "curl", "endpoint": "/health", "port": parsed.port,
                                "round": 1, "side": None, "output": str(output) if output is not None else None,
                                "fixture_readiness": "not_ready", "exit_code": 7,
                                "is_baseline": False, "is_barrier": False, "barrier_unhealthy_input": False})
            return 7
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
            # Neither declared caller enters the later HTTP sampling loop.
            # No /dev/null status or other unowned-output seam is provided.
            raise ValueError("fixture_unhandled_status_output")
        headers = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "-H"]
        if "Authorization: Bearer fixture-diagnostics-token" not in headers:
            raise ValueError("fixture_diagnostics_authorization_missing")
        if number != 1:
            raise ValueError("fixture_undeclared_status_round")
        if output.name not in {"node-" + side + suffix for suffix in
                               (".baseline.status.json", ".barrier.status.json", ".status.json.capture")}:
            raise ValueError("fixture_undeclared_status_output")
        baseline = output.name == "node-" + side + ".baseline.status.json"
        barrier = output.name == "node-" + side + ".barrier.status.json"
        value = status(directory, side, baseline)
        barrier_unhealthy_input = False
        # Validate that the port came from the real main's reserved block and
        # its original declaration, rather than a fixture-chosen endpoint.
        launch = json.loads((directory / "launches" / ("node-" + side + ".json")).read_text())
        ready = json.loads((directory / ("node-" + side + ".fixture-ready.json")).read_text())
        if launch["pid"] != ready["pid"] or parsed.port != ready["diagnostics_port"]:
            raise ValueError("fixture_status_launch_pid_mismatch")
        if barrier:
            # Failure is an actual external command exit, after original auth,
            # port and argv validation. No status/metadata/receipt is forged.
            if (argv.count("--max-time") != 1 or argument(argv, "--max-time") != "5"
                    or argv.count("-w") != 1 or argument(argv, "-w") != "%{http_code}"
                    or argv.count("-o") != 1 or "-fsS" not in argv):
                raise ValueError("fixture_original_barrier_curl_contract_mismatch")
            fd_observation = observe_inherited_fd(settings)
            sanitized = ["Authorization: Bearer [redacted]" if item.startswith("Authorization:") else item
                         for item in argv]
            common = {"tool": "curl", "endpoint": "/status", "port": parsed.port,
                      "round": number, "side": side, "pid": os.getpid(), "ppid": os.getppid(),
                      "output": str(output), "is_baseline": False, "is_barrier": True,
                      "barrier_unhealthy_input": False, "auth_valid": True, "argv": sanitized,
                      "max_time": 5, "fd_observation": fd_observation}
            if side == "a":
                if output.exists():
                    raise ValueError("fixture_failed_curl_unexpected_existing_output")
                if os.write(1, b"000") != 3:
                    raise ValueError("fixture_failed_curl_stdout_short_write")
                append_event(root, {**common, "exit_code": 7, "stdout": "000",
                                    "failure_input": True, "response_sha256": None,
                                    "output_written": False})
                return 7
    else:
        raise ValueError("fixture_unhandled_endpoint")
    payload = json.dumps(value, separators=(",", ":"))
    output_bytes = (payload + "\n").encode("utf-8")
    if output is not None:
        if not output.resolve().is_relative_to(root):
            raise ValueError("fixture_response_output_outside_private_root")
        output.write_bytes(output_bytes)
        output.chmod(0o600)
    event = {"tool": "curl", "endpoint": parsed.path, "port": parsed.port,
             "round": number, "side": side,
             "output": str(output) if output is not None else None,
             "is_baseline": baseline, "is_barrier": barrier,
             "barrier_unhealthy_input": barrier_unhealthy_input}
    if parsed.path == "/status":
        # Bind the exact original output bytes, including its trailing newline;
        # never emit the authorization header or the response body in events.
        event["response_sha256"] = hashlib.sha256(output_bytes).hexdigest()
    if parsed.path == "/status":
        event.update(exit_code=0, stdout="200", failure_input=False,
                     output_written=True, auth_valid=True, pid=os.getpid(), ppid=os.getppid())
        if barrier:
            event.update(common)
            event["response_sha256"] = hashlib.sha256(output_bytes).hexdigest()
    append_event(root, event)
    if output is None and "-w" not in argv:
        print(payload, end="")
    if "-w" in argv:
        sys.stdout.write("200")
    return 0


def main(argv):
    root = Path(argv[0]).resolve()
    tool, arguments = argv[1], argv[2:]
    settings = config(root)
    real_python = settings["real_python"]
    if tool == "snapshot-metadata":
        return snapshot_metadata(root, arguments)
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
