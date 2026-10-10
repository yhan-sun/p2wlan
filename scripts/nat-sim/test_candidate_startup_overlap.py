#!/usr/bin/env python3
"""Real CLI A-only STUN startup controls with the original fixed windows.

One new fixture overlays only its generated python3 launcher. No old fixture,
TestCase, helper, handler, publisher or production byte is edited. Transport
input is offline and covers startup failure and registered process cleanup.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import test_actual_round_callers as legacy_fixture

HERE = Path(__file__).resolve().parent
ADAPTER = HERE / "fixture_candidate_startup_overlap_tools.py"
ALLOWED_ROLES = {"nat", "relay-1", "control"}
CASE = "nat-stun-b-missing"
TARGET = "B01_STARTUP_OVERLAP_ELIGIBILITY"
JSON_CAP = 128 * 1024


def sha_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def file_bytes(path, cap=JSON_CAP, required_mode=0o600):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o777 != required_mode or metadata.st_size > cap):
            raise AssertionError("B01 startup regular-file contract failed (not a product RED)")
        chunks = bytearray()
        while len(chunks) <= cap:
            part = os.read(descriptor, min(8192, cap + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        if len(chunks) > cap or len(chunks) != metadata.st_size:
            raise AssertionError("B01 startup file changed/cap exceeded (not a product RED)")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def json_file(path):
    value = json.loads(file_bytes(path))
    if type(value) is not dict:
        raise AssertionError("B01 startup receipt is not an object (not a product RED)")
    return value


def new_json(path, value):
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(payload) > JSON_CAP:
        raise AssertionError("B01 startup fixture receipt cap exceeded")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if os.write(descriptor, payload) != len(payload):
            raise AssertionError("B01 startup fixture short receipt write")
    finally:
        os.close(descriptor)


class StartupOverlapFixture(legacy_fixture.ActualCliFixture):
    """Non-TestCase reuse of base preparation/teardown with truthful owner rows."""

    def __init__(self, root, source, relay_count, egress):
        self.relay_count, self.egress = relay_count, egress
        super().__init__(root, source, CASE, 1)

    def prepare(self):
        preparation_end = time.monotonic() + 4
        super().prepare()
        original_driver = self.root / "fixture-external-tools.py"
        original_sha = self.original_sources["scripts/nat-sim/fixture_external_tools.py"]
        if legacy_fixture.digest(original_driver) != original_sha:
            raise AssertionError("B01 original external base not byteexact (not a product RED)")
        relative = "scripts/nat-sim/fixture_candidate_startup_overlap_tools.py"
        adapter_payload = ADAPTER.read_bytes()
        adapter_sha = sha_bytes(adapter_payload)
        if self.original_sources.get(relative) != adapter_sha:
            raise AssertionError("B01 proposed adapter must be declared private input (not a product RED)")
        adapter = self.root / "fixture-startup-overlap-tools.py"
        descriptor = os.open(adapter, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            if os.write(descriptor, adapter_payload) != len(adapter_payload):
                raise AssertionError("B01 adapter short write")
        finally:
            os.close(descriptor)
        commands = self.root / "fake-path"
        untouched = {name: legacy_fixture.digest(commands / name) for name in ("cargo", "go", "curl")}
        launcher_payload = ("#!/bin/sh\nexec "
                            + shlex.join([sys.executable, "-S", str(adapter), str(self.root), "python3"])
                            + ' "$@"\n').encode()
        launcher = commands / "python3"
        # This is the NEW fixture's generated launcher, never an old source file.
        descriptor = os.open(launcher, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o777 != 0o700:
                raise AssertionError("B01 generated launcher contract failed")
            if os.write(descriptor, launcher_payload) != len(launcher_payload):
                raise AssertionError("B01 launcher short write")
        finally:
            os.close(descriptor)
        settings = json_file(self.root / "fixture-config.json")
        self.transport = {"base_path": str(original_driver), "base_sha256": original_sha,
                          "adapter_path": str(adapter), "adapter_sha256": adapter_sha,
                          "python3_launcher_path": str(launcher),
                          "python3_launcher_sha256": sha_bytes(launcher_payload),
                          "unchanged_other_launcher_sha256": untouched,
                          "scope": "new_fixture_python3_transport_only", "input": CASE}
        settings["startup_overlap_transport"] = self.transport
        payload = (json.dumps(settings, sort_keys=True) + "\n").encode()
        if len(payload) > JSON_CAP:
            raise AssertionError("B01 startup config cap exceeded")
        descriptor = os.open(self.root / "fixture-config.json", os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        try:
            if os.write(descriptor, payload) != len(payload):
                raise AssertionError("B01 startup config short write")
        finally:
            os.close(descriptor)
        self.environment.update(RELAY_COUNT=str(self.relay_count), EGRESS_CAPTURE=self.egress)
        self.prove_source_fence()
        self.prove_transport()
        if self.artifacts.exists():
            raise AssertionError("B01 original CLI artifact destination must not preexist")
        if time.monotonic() >= preparation_end:
            raise AssertionError("B01 startup overlay exceeded original four-second preparation (not a product RED)")

    def prove_source_fence(self):
        for relative, expected in self.original_sources.items():
            if (legacy_fixture.digest(self.source / relative) != expected
                    or legacy_fixture.digest(self.repository / relative) != expected):
                raise AssertionError("B01 original source/private bytes moved (not a product RED)")

    def prove_transport(self):
        for path_key, hash_key, mode in (("base_path", "base_sha256", 0o600),
                                         ("adapter_path", "adapter_sha256", 0o600),
                                         ("python3_launcher_path", "python3_launcher_sha256", 0o700)):
            if sha_bytes(file_bytes(Path(self.transport[path_key]), required_mode=mode)) != self.transport[hash_key]:
                raise AssertionError("B01 startup transport byte fence changed")
        for name, expected in self.transport["unchanged_other_launcher_sha256"].items():
            if legacy_fixture.digest(self.root / "fake-path" / name) != expected:
                raise AssertionError("B01 non-python fixture launcher changed")
        settings = json_file(self.root / "fixture-config.json")
        if settings["startup_overlap_transport"] != self.transport:
            raise AssertionError("B01 config transport binding changed")
        if settings["external_tools_sha256"] != self.transport["base_sha256"]:
            raise AssertionError("B01 original base SHA weakened")

    def execute(self):
        # Original base protocol and teardown ceilings; no ready wait is added.
        self.protocol_end = time.monotonic() + legacy_fixture.PROTOCOL_SECONDS
        self.teardown_end = self.protocol_end + legacy_fixture.TEARDOWN_SECONDS
        with self.stdout_path.open("xb") as output, self.stderr_path.open("xb") as error:
            os.fchmod(output.fileno(), 0o600)
            os.fchmod(error.fileno(), 0o600)
            self.process = subprocess.Popen(
                [legacy_fixture.SHELL, "-x", str(self.repository / "scripts/nat-sim/nat-sim-smoke.sh")],
                cwd=self.repository, env=self.environment, stdin=subprocess.DEVNULL,
                stdout=output, stderr=error, start_new_session=True)
            try:
                self.cli_status = self.process.wait(timeout=max(0, self.protocol_end - time.monotonic()))
            except subprocess.TimeoutExpired:
                self.close()
                raise AssertionError("B01 startup original CLI timed out (not a product RED)")
        self.stdout, self.stderr = self.read_log(self.stdout_path), self.read_log(self.stderr_path)
        if "B01_FIXTURE_INFRA_FAILURE:" in self.stdout + self.stderr:
            raise AssertionError("B01 startup external seam rejected input (not a product RED): " + self.stderr[-5000:])
        self.events = self.read_events()
        if any(row.get("tool") == "child_fixture_deadline" for row in self.events):
            raise AssertionError("B01 original child lifetime expired (not a product RED)")
        self.prove_source_fence()
        self.prove_transport()
        self.prove_ports_released()
        if self.sentinel.poll() is not None or self.rescued:
            raise AssertionError("B01 sentinel/rescue prerequisite failed (not a product RED)")
        self.owner_proofs = self.prove_actual_owners_closed()
        # No fixed old five-role receipt. Actual set and desired eligibility are
        # separate so an absent early start remains the test's final target.
        receipt = {"fixture_only": True, "case": CASE, "variant": {"relay_count": self.relay_count, "egress": self.egress},
                   "cli_exit_status": self.cli_status, "cli_pid": self.process.pid,
                   "supervisor_rescue": self.rescued, "actual_owner_proofs": self.owner_proofs,
                   "actual_roles": sorted(row["role"] for row in self.owner_proofs),
                   "transport": self.transport, "original_sources": self.original_sources,
                   "stdout_sha256": legacy_fixture.digest(self.stdout_path),
                   "stderr_xtrace_sha256": legacy_fixture.digest(self.stderr_path),
                   "external_events_sha256": legacy_fixture.digest(self.root / "external-events.jsonl"),
                   "protocol_seconds": 12, "teardown_seconds": 2, "prepare_seconds": 4,
                   "round_timeout_seconds": 20, "work_timeout_seconds": 5,
                   "direct_timeout_seconds": 2, "overlay_timeout_seconds": 2, "resource_grace_cap_ms": 1000,
                   "sentinel_pid": self.sentinel.pid, "sentinel_wait": "pending_original_fixture_teardown",
                   "cleanup_duration_ms": json_file(self.artifacts / "round-1/cleanup.json")["duration_ms"],
                   "scope": "offline_original_cli_startup_failure_and_registered_owner_waits"}
        new_json(self.root / "startup-overlap-fixture-receipt.json", receipt)
        print("B01_STARTUP_OVERLAP_FIXTURE=" + str(self.root), flush=True)
        return self

    def prove_actual_owners_closed(self):
        directory = self.artifacts / "round-1"
        cleanup = json_file(directory / "cleanup.json")
        rows = cleanup["owned_processes"]
        if type(rows) is not list or not 1 <= len(rows) <= 3:
            raise AssertionError("B01 unexpected actual startup owner rows")
        roles = [row["role"] for row in rows]
        pids = [row["pid"] for row in rows]
        if (len(set(roles)) != len(rows) or not set(roles) <= ALLOWED_ROLES or "nat" not in roles
                or any(type(pid) is not int or pid <= 0 for pid in pids) or len(set(pids)) != len(rows)):
            raise AssertionError("B01 startup owner identity invalid")
        for field in ("started_process_count", "wait_completed_count", "process_count"):
            if type(cleanup[field]) is not int or cleanup[field] != len(rows):
                raise AssertionError("B01 startup actual owner aggregate differs")
        if any(cleanup[field] != 0 for field in ("pending_process_count", "unrecorded_process_count", "worker_unknown_count")):
            raise AssertionError("B01 startup pending/unknown/unrecorded ownership")
        if (cleanup["metadata_coverage"] != "complete" or cleanup["all_reaped"] is not True
                or cleanup["forced_termination"] is not False or cleanup["owned_workers"] != []):
            raise AssertionError("B01 startup closure/worker aggregate invalid")
        prefix = rf"^\++ B01_CLI pid={self.process.pid} sub=0 line=[0-9]+: (.*)$"
        commands = re.findall(prefix, self.stderr, re.MULTILINE)
        registrations = [command for command in commands if command.startswith("round_register_process ")]
        expected = [f"round_register_process {row['role']} {row['pid']}" for row in rows]
        if len(registrations) != len(expected) or set(registrations) != set(expected):
            raise AssertionError("B01 original register rows do not match cleanup")
        publications = [index for index, command in enumerate(commands) if command.startswith("_round_tool publish ")]
        if len(publications) != 1:
            raise AssertionError("B01 original publisher must execute once")
        proofs = []
        for row in rows:
            role, pid, status_code = row["role"], row["pid"], row["wait_status"]
            if (row["wait_completed"] is not True or row["forced_termination"] is not False
                    or type(status_code) is not int or status_code not in {0, 143}):
                raise AssertionError("B01 startup lacks genuine 0/143 native closure")
            register, term, wait, ledger = (f"round_register_process {role} {pid}", f"kill -TERM {pid}",
                                           f"wait {pid}", f"round_record_wait {pid} {status_code}")
            if any(commands.count(command) != 1 for command in (register, term, wait, ledger)):
                raise AssertionError("B01 original TERM/wait/ledger multiplicity differs")
            positions = [commands.index(command) for command in (register, term, wait, ledger)]
            if positions != sorted(positions) or positions[-1] >= publications[0]:
                raise AssertionError("B01 original native closure sequence is not before publication")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError("B01 startup owned PID remains live/unreaped (not a product RED)")
            stopped_rows = [event for event in self.events if event.get("tool") == "child_stopped"
                            and event.get("pid") == pid]
            stopped_path, ready_path = directory / (role + ".fixture-stopped.json"), directory / (role + ".fixture-ready.json")
            ready = json_file(ready_path) if ready_path.exists() else None
            if ready is not None and (ready.get("pid") != pid or ready.get("role") != role or ready.get("round") != 1):
                raise AssertionError("B01 observed ready identity invalid")
            stopped = None
            if status_code == 0:
                stopped = json_file(stopped_path)
                if (stopped.get("pid") != pid or stopped.get("role") != role or stopped.get("round") != 1
                        or stopped.get("signal") != signal.SIGTERM or stopped.get("exit_code") != 0
                        or type(stopped.get("monotonic_ns")) is not int or stopped["monotonic_ns"] <= 0
                        or len(stopped_rows) != 1 or stopped_rows[0].get("signal") != signal.SIGTERM
                        or stopped_rows[0].get("exit_code") != 0):
                    raise AssertionError("B01 native zero is not the real original TERM handler outcome")
            elif ready is not None or stopped_path.exists() or stopped_rows:
                raise AssertionError("B01 native143 cannot masquerade as cooperative handler zero")
            launch = None
            launch_record = directory / "launches" / (role + ".json")
            if role != "nat":
                if launch_record.exists():
                    raw = file_bytes(launch_record)
                    launch = {"bytes": len(raw), "sha256": sha_bytes(raw), "state": "partial_before_ready"}
                    try:
                        decoded = json.loads(raw)
                    except (ValueError, UnicodeDecodeError):
                        if status_code != 143:
                            raise AssertionError("B01 handler-ready exec record is malformed")
                    else:
                        if type(decoded) is not dict or decoded.get("pid") != pid or decoded.get("role") != role:
                            raise AssertionError("B01 original launch identity differs")
                        launch["state"] = "original_exec_requested_record"
                elif status_code != 143:
                    raise AssertionError("B01 handler-zero child lacks original exec record")
            proofs.append({"role": role, "pid": pid, "native_wait_status": status_code,
                           "original_wait_before_publish": True, "handler_term_zero": status_code == 0,
                           "observed_ready": ready is not None, "original_launch_record": launch,
                           "wait_trace_index": positions[2], "ledger_trace_index": positions[3]})
        return proofs


class CandidateStartupOverlapTests(unittest.TestCase):
    def fixture(self, relay_count, egress):
        parent = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if parent:
            directory = Path(parent).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-startup-overlap-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name) / "exclusive-case"
        fixture = StartupOverlapFixture(directory, legacy_fixture.source_repository(), relay_count, egress)
        self.addCleanup(fixture.close)
        return fixture.execute()

    def assert_startup_failure(self, fixture, expected_roles):
        directory = fixture.artifacts / "round-1"
        self.assertEqual(fixture.cli_status, 1)
        original_failure = "[nat-sim] round 1: FAIL reason_code=test_harness_startup_failure stage=nat_simulator"
        self.assertEqual(fixture.stderr.count(original_failure + "\n"), 1)
        nat_output = fixture.read_log(directory / "nat-sim.out")
        self.assertEqual(nat_output.count("STUN_A=127.0.0.1:31001\n"), 1)
        self.assertNotIn("STUN_B=", nat_output)
        inputs = [row for row in fixture.events if row.get("tool") == "startup_input_enter"]
        nat_row = next(row for row in fixture.owner_proofs if row["role"] == "nat")
        self.assertEqual(len(inputs), 1)
        self.assertEqual(inputs[0]["pid"], nat_row["pid"])
        self.assertEqual(inputs[0]["input"], CASE)
        self.assertEqual(inputs[0]["original_base_sha256"], fixture.transport["base_sha256"])
        self.assertTrue(nat_row["handler_term_zero"])
        self.assertFalse(any(event.get("tool") in {"curl", "original_collector_enter"}
                             for event in fixture.events))
        for role in ("node-a", "node-b"):
            self.assertFalse((directory / "launches" / (role + ".json")).exists())
            for suffix in (".fixture-ready.json", ".fixture-stopped.json", ".fixture-business.json"):
                self.assertFalse((directory / (role + suffix)).exists())
        self.assertFalse((directory / "business-validation.start-gate").exists())
        self.assertFalse((directory / "business-validation.started").exists())
        self.assertFalse((directory / ".collector-result.json").exists())
        self.assertFalse(any(row.get("role", "").startswith("node-") for row in fixture.events))
        canonical = json_file(directory / "round-finalization.json")
        self.assertEqual(canonical["terminal_reason_code"], "unexpected_exit")
        self.assertEqual(canonical["original_exit_code"], 1)
        self.assertEqual(canonical["shell_exit_status"], 1)
        self.assertEqual(canonical["shell_exit_status_source"], "exit_trap")
        self.assertEqual(canonical["round_result"], "invalid")
        self.assertIs(canonical["cleanup"]["all_reaped"], True)
        self.assertIs(canonical["cleanup"]["forced_termination"], False)
        for side in ("a", "b"):
            observed = json_file(directory / (".final-status-" + side + ".json"))
            self.assertEqual(observed["result"], "unknown")
            self.assertEqual(observed["pid"], 0)
            self.assertEqual(observed["owner_role"], "unknown")
            self.assertEqual(observed["process_observation"], "not_started")
            self.assertEqual(observed["reason_code"], "not_started")
            self.assertEqual(observed["identity_scope"], "round_owned_pid_at_capture")
            self.assertIsNone(observed["sha256"])
            self.assertEqual(observed["worker"], {"started": False})
            self.assertEqual(canonical["statuses"][side], observed)
        # Actual original validator determines the invalid denominator; no fake
        # publisher, canonical source, verdict, business payload or matrix input.
        matrix = legacy_fixture.matrix_module(fixture.repository)
        with self.assertRaises(matrix.EvidenceError) as rejected:
            matrix.validate_round(directory, matrix.SCENARIO_BY_NAME["equal-step"], 1,
                                  legacy_fixture.SOURCE_HEAD, legacy_fixture.WORKFLOW_HEAD)
        summary = matrix.aggregate_runs([{"exit_code": 1, "rounds": [
            {"result": "invalid", "reason": str(rejected.exception)}]}])
        self.assertEqual(summary["requested"]["rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0)
        self.assertFalse(fixture.rescued)
        self.assertIsNone(fixture.sentinel.poll())
        # Sole feature target, after real failure/input/native-wait prerequisites.
        self.assertEqual({row["role"] for row in fixture.owner_proofs}, expected_roles, TARGET)

    def test_eligible_direct_a_only_stun_closes_three_started_owners(self):
        self.assert_startup_failure(self.fixture(1, "listeners"), {"nat", "relay-1", "control"})

    def test_multiple_relays_keep_tcp_launch_after_stun_validation(self):
        self.assert_startup_failure(self.fixture(2, "listeners"), {"nat"})

    def test_egress_shim_keeps_tcp_launch_after_stun_validation(self):
        self.assert_startup_failure(self.fixture(1, "shim"), {"nat"})


if __name__ == "__main__":
    unittest.main()
