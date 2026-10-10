#!/usr/bin/env python3
"""Endpoint attribution candidate: endpoint-only controlled inputs; no business ACK proof."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
from types import SimpleNamespace


CASES = {"mismatch", "matching", "mixed"}


def load_original(root):
    settings = json.loads((root / "fixture-config.json").read_bytes())
    relative = "scripts/nat-sim/fixture_restart_failover_control_tools.py"
    path = Path(settings["private_repository"]) / relative
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != settings["original_sources"][relative]:
        raise ValueError("endpoint_fixture_original_tool_SHA")
    spec = importlib.util.spec_from_file_location("endpoint_fixture_original_tools", path)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    base.require(settings.get("endpoint_case") in CASES, "endpoint_fixture_case")
    adapter_relative = "scripts/nat-sim/fixture_candidate_failover_endpoint_tools.py"
    test_relative = "scripts/nat-sim/test_candidate_failover_endpoint_controls.py"
    adapter_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    base.require(settings["original_sources"].get(adapter_relative) == adapter_sha
                 and settings["external_tools_sha256"] == adapter_sha
                 and settings["endpoint_test_sha256"] == settings["original_sources"].get(test_relative),
                 "endpoint_fixture_adapter_and_test_dynamic_source_binding")
    return base, settings


def install_inputs(base, root, settings, arguments):
    original_read = base.regular_bytes

    def read_inputs(path, cap=32 * 1024):
        if Path(path) != root / "external-events.jsonl":
            return original_read(path, cap)
        # This fixture journal has only bounded single-write appenders. Live
        # readiness reads consume one complete prefix; the closed test reader
        # still validates the entire final journal and original limits.
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            base.require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap,
                         "endpoint_fixture_journal_capacity")
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                data = stream.read(before.st_size)
            after = os.fstat(descriptor)
            base.require(len(data) == before.st_size and len(data) <= cap
                         and (not data or data.endswith(b"\n"))
                         and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                         and after.st_size >= before.st_size,
                         "endpoint_fixture_complete_append_prefix")
            return data
        finally:
            os.close(descriptor)

    base.regular_bytes = read_inputs
    original_roles = base.case_roles
    base.case_roles = lambda value: original_roles(value) | {"relay-3"}
    # Fixture build launchers must return to this NEW input adapter. Original
    # CLI/Python sources in the private checkout retain their captured bytes.
    base.__file__ = str(Path(__file__).resolve())

    def relay_launch(_root, argv, value):
        directory = root / "artifacts/round-1"
        matches = []
        for role in ("relay-1", "relay-2", "relay-3"):
            path = directory / "launches" / (role + ".json")
            if path.exists():
                record = base.regular_json(path)
                if record.get("pid") == os.getpid():
                    matches.append((role, record))
        base.require(len(matches) == 1, "endpoint_fixture_relay_same_PID")
        role, record = matches[0]
        artifacts = base.regular_json(root / "artifacts/artifact-set.json")
        base.require(record["role"] == role and record["component"] == "relay"
                     and record["state"] == "exec_requested"
                     and record["source"] == artifacts["source"]
                     and record["artifact"] == artifacts["artifacts"]["relay"]
                     and record["artifact_set_sha256"] == hashlib.sha256(
                         base.regular_bytes(root / "artifacts/artifact-set.json")).hexdigest(),
                     "endpoint_fixture_relay_artifact_identity")
        inputs = {name: os.environ.get(name) for name in ("RELAY_AUDIENCE", "RELAY_REGION")}
        payload = {"source": "cli_and_controlled_environment", "scope": "argv_and_allowlisted_environment",
                   "argv": argv, "environment": inputs,
                   "config_file": {"state": "not_supplied", "sha256": None}, "excluded_inputs": []}
        identity = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        base.require(record["configuration"]["sha256"] == identity
                     and record["configuration"]["argument_count"] == len(argv)
                     and record["configuration"]["environment_keys"] == ["RELAY_AUDIENCE", "RELAY_REGION"],
                     "endpoint_fixture_original_relay_configuration")
        audience = "relay-sim" if role == "relay-1" else "relay-sim-" + role.rpartition("-")[2]
        base.require(inputs == {"RELAY_AUDIENCE": audience, "RELAY_REGION": "local"},
                     "endpoint_fixture_original_catalog_audience")
        bind = base.argument(argv, "-bind")
        base.require(bind.startswith("127.0.0.1:") and bind.rpartition(":")[2].isdigit()
                     and "-require-auth" in argv and "-allow-insecure-plaintext" in argv
                     and base.argument(argv, "-forward-delay") == "0ms", "endpoint_fixture_relay_argv")
        return directory, role, "tcp://" + bind, identity

    base.relay_launch = relay_launch
    old_ready = base.original_ready
    base.original_ready = lambda _root, directory, roles: old_ready(_root, directory, roles | {"relay-3"})
    if arguments[:2] != ["child", "daemon"]:
        return
    role = base.argument(arguments[2:], "--device-name")
    base.require(role in {"node-a", "node-b"}, "endpoint_fixture_node_role")
    directory = root / "artifacts/round-1"
    emitted = False
    original_print = base.print if hasattr(base, "print") else print

    def input_print(*values, **kwargs):
        original_print(*values, **kwargs)
        if len(values) == 1 and isinstance(values[0], str) and values[0].startswith('event="relay_peer_confirmed" t_ms=11 relay_endpoint='):
            base.require(kwargs == {"flush": True}, "endpoint_original_confirmation_flush")
            relays = [base.regular_json(directory / ("relay-" + str(i) + ".fixture-ready.json")) for i in (1, 2, 3)]
            base.require(all(base.live(row["pid"]) for row in relays)
                         and len({row["pid"] for row in relays}) == 3
                         and relays[0]["endpoint"] < relays[1]["endpoint"] < relays[2]["endpoint"],
                         "endpoint_real_catalog_sort_preserves_primary")
            wire = 'event="relay_peer_confirmed" t_ms=12 relay_endpoint=' + relays[1]["endpoint"] + ' fixture_only=true'
            original_print(wire, flush=True)
            event = {"fixture_only": True, "role": role, "pid": os.getpid(),
                     "primary_endpoint": relays[0]["endpoint"], "backup_endpoint": relays[1]["endpoint"],
                     "backup_pid": relays[1]["pid"], "monotonic_ns": time.monotonic_ns(),
                     "stdout_line_sha256": hashlib.sha256((wire + "\n").encode()).hexdigest()}
            base.new_json(directory / (role + ".fixture-backup-confirmed.json"), event)
            base.append_event(root, {"tool": "historical_backup_confirmation_flushed", **event})

    base.print = input_print

    def producer_sleep(seconds):
        nonlocal emitted
        # The observer marker is written only at the original top-level
        # re_confirmed=0, after original primary kill, actual wait and ledger.
        marker = root / "endpoint-fault-joined.ready"
        if not emitted and marker.is_file():
            emitted = True
            controller = int(base.regular_bytes(marker, 32).strip())
            base.require(controller > 0 and base.live(controller), "endpoint_fixture_controller_live")
            old = base.regular_json(directory / "relay-1.fixture-stopped.json")
            replacement = base.regular_json(directory / "relay-2.fixture-ready.json")
            other = base.regular_json(directory / "relay-3.fixture-ready.json")
            ready = base.regular_json(directory / (role + ".fixture-ready.json"))
            base.require(ready["pid"] == os.getpid() and old["signal"] == signal.SIGTERM
                         and old["exit_code"] == 0 and len({old["endpoint"], replacement["endpoint"], other["endpoint"]}) == 3,
                         "endpoint_fixture_native_fault_and_three_distinct_catalog_endpoints")
            case = settings["endpoint_case"]
            base.require(base.live(replacement["pid"]) and base.live(other["pid"])
                         and not base.live(old["pid"]), "endpoint_fault_joined_and_backups_live")
            historical = base.regular_json(directory / (role + ".fixture-backup-confirmed.json"))
            base.require(historical["pid"] == os.getpid() and historical["backup_endpoint"] == replacement["endpoint"]
                         and historical["monotonic_ns"] < old["monotonic_ns"], "endpoint_backup_confirmation_is_pre_fault")
            endpoints = ([other["endpoint"]] if case == "mismatch"
                         else [other["endpoint"], replacement["endpoint"]] if case == "mixed"
                         else [replacement["endpoint"]])
            stamp = time.monotonic_ns()
            # One bounded stdout write keeps the complete ordered batch ahead
            # of its flushed acknowledgment; there is no probabilistic sleep.
            lines = ["overlay_payload_verified ingress=relay:" + endpoint
                     + " endpoint_control_sequence=" + str(index) + " fixture_only=true"
                     for index, endpoint in enumerate(endpoints)]
            wire = "\n".join(lines) + "\n"
            base.require(len(wire.encode()) <= 4096, "endpoint_fixture_bounded_stdout_batch")
            sys.stdout.write(wire)
            sys.stdout.flush()
            event = {"pid": os.getpid(), "role": role, "round": 1, "fixture_only": True,
                     "case": case, "controller_pid": controller, "old_pid": old["pid"],
                     "old_stopped_monotonic_ns": old["monotonic_ns"], "monotonic_ns": stamp,
                     "replacement_endpoint": replacement["endpoint"], "business_endpoints": endpoints,
                     "stdout_batch_sha256": hashlib.sha256(wire.encode()).hexdigest()}
            base.new_json(directory / (role + ".fixture-failover-flushed.json"), event)
            base.append_event(root, {"tool": "post_failover_business_flushed", **event})
        time.sleep(seconds)

    base.time = SimpleNamespace(monotonic=time.monotonic, monotonic_ns=time.monotonic_ns, sleep=producer_sleep)


def main(argv):
    root = Path(argv[0]).resolve()
    base, settings = load_original(root)
    install_inputs(base, root, settings, argv[1:])
    return base.main(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, IndexError) as error:
        print("B01_FIXTURE_INFRA_FAILURE:" + type(error).__name__ + ":" + str(error), file=sys.stderr)
        raise SystemExit(92)
