#!/usr/bin/env python3
"""PLANNED ONLY: independent complete-CLI O1/O2 candidates.

The author has not executed this module. Only declared external tools supply
inputs; original main, watcher, handlers, collectors and matrix remain real.
No old TestCase is imported or inherited. Production source binding is the
root-owned stage fence, separately recorded in input-manifest.json.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import shlex
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
EXTERNAL_TOOLS = HERE / "fixture_hard_hard_outer_tools.py"
SHELL = "/bin/bash"
LOG_CAP = 2 * 1024 * 1024
PROTOCOL_SECONDS = 12
TEARDOWN_SECONDS = 2
SOURCE_HEAD = "a" * 40
WORKFLOW_HEAD = "b" * 40
FAKE_ROLES = {"nat", "control", "relay-1"}
CASES = {"direct-gate-not-active", "watcher-not-armed"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_repository():
    explicit = os.environ.get("P2WLAN_B01_SOURCE_REPOSITORY")
    root = Path(explicit).resolve() if explicit else HERE.parents[1]
    if not (root / "scripts/nat-sim/nat-sim-smoke.sh").is_file():
        raise AssertionError("B01 fixture source repository is missing (not a product RED)")
    return root


def matrix_module(root):
    script_dir = root / "scripts/nat-sim"
    name = "b01_actual_cli_matrix_" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    specification = importlib.util.spec_from_file_location(name, script_dir / "run-hard-hard-matrix.py")
    if specification is None or specification.loader is None:
        raise AssertionError("B01 original matrix import missing (not a product RED)")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    sys.path.insert(0, str(script_dir))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(script_dir))
    return module


class HardHardOuterCliFixture:
    """One real CLI shell, one absolute supervisor budget and real owned waits.

    Preparation is private local Git work only, bounded separately to four
    seconds. CLI supervision is twelve seconds including every round; it is
    shorter than its unchanged twenty-second per-round deadline. A separate
    two-second teardown never repairs a protocol timeout into a desired RED.
    """

    def __init__(self, root, source, case, rounds):
        if case not in CASES or rounds != 1:
            raise AssertionError("B01 outer fixture only permits declared one-round cases")
        # Canonicalize once so private layout fences also hold under symlinked temp roots.
        root = root.resolve()
        self.root, self.source, self.case, self.rounds = root, source, case, rounds
        self.roles = FAKE_ROLES | ({"watcher"} if case == "watcher-not-armed" else set())
        self.watcher_pid = None
        self.process = None
        self.sentinel = None
        self.closed = False
        self.rescued = False
        self.cli_status = None
        self.repository = root / "private-source"
        self.artifacts = root / "artifacts"
        self.stdout_path = root / "cli.stdout"
        self.stderr_path = root / "cli.stderr-xtrace"
        self.original_sources = {}
        self.protocol_end = None
        self.teardown_end = None
        root.mkdir(mode=0o700)
        try:
            self.prepare()
        except BaseException:
            self.close()
            raise

    def prepare(self):
        preparation_end = time.monotonic() + 4

        def preparation_remaining():
            remaining = preparation_end - time.monotonic()
            if remaining <= 0:
                raise AssertionError("B01 private-layout preparation expired (not a product RED)")
            return remaining

        def git(*arguments, cwd=None):
            remaining = preparation_remaining()
            result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *arguments],
                                    cwd=cwd, capture_output=True, timeout=remaining, check=False,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                                         "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
            if result.returncode != 0:
                raise AssertionError("B01 private local Git preparation failed (not a product RED): "
                                     + result.stderr.decode(errors="replace")[:1000])
            return result.stdout

        # Local clone reads source Git objects; its index/config/checkout and
        # all fixture writes remain under this exclusive private directory.
        # There is no fetch, remote command, commit, or mutation of source Git.
        git("clone", "--local", "--shared", "--quiet", "--no-checkout",
            str(self.source), str(self.repository))
        source_head = git("rev-parse", "HEAD", cwd=self.source).decode().strip()
        git("checkout", "--quiet", "--detach", source_head, cwd=self.repository)
        paths = [self.source / "scripts/diagnostics-auth.sh"]
        paths.extend(path for path in sorted((self.source / "scripts/nat-sim").iterdir())
                     if path.is_file() and path.suffix in {".py", ".sh", ".json"})
        preparation_remaining()
        for path in paths:
            preparation_remaining()
            relative = path.relative_to(self.source)
            payload = path.read_bytes()
            self.original_sources[str(relative)] = hashlib.sha256(payload).hexdigest()
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(path.stat().st_mode & 0o777)
        for relative, expected in self.original_sources.items():
            preparation_remaining()
            if digest(self.source / relative) != expected or digest(self.repository / relative) != expected:
                raise AssertionError("B01 source moved while making private layout (not a product RED)")
        (self.repository / "server").mkdir(exist_ok=True)
        preparation_remaining()
        driver = self.root / "fixture-external-tools.py"
        shutil.copyfile(EXTERNAL_TOOLS, driver)
        driver.chmod(0o600)
        settings = {"fixture_only": True, "case": self.case, "rounds": self.rounds,
                    "real_python": sys.executable, "private_repository": str(self.repository),
                    "original_source_commit": source_head,
                    "external_tools_sha256": digest(driver),
                    "original_sources": self.original_sources}
        (self.root / "fixture-config.json").write_text(json.dumps(settings, sort_keys=True) + "\n")
        (self.root / "fixture-config.json").chmod(0o600)
        commands = self.root / "fake-path"
        commands.mkdir(mode=0o700)
        for name in ("python3", "cargo", "go", "curl"):
            preparation_remaining()
            payload = ("#!/bin/sh\nexec "
                       + shlex.join([sys.executable, "-S", str(driver), str(self.root), name])
                       + ' "$@"\n')
            with (commands / name).open("x") as stream:
                os.fchmod(stream.fileno(), 0o700)
                stream.write(payload)
        (self.root / "tmp").mkdir(mode=0o700)
        self.environment = {"PATH": str(commands) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                            "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                            "TMPDIR": str(self.root / "tmp"),
                            "MODE": "hard-hard", "ROUNDS": str(self.rounds), "RELAY_COUNT": "1",
                            "EGRESS_CAPTURE": "listeners", "UNASSIGNED_EGRESS_LISTENERS": "0",
                            "ROUND_TIMEOUT_S": "20", "DIRECT_TIMEOUT_S": "2", "OVERLAY_TIMEOUT_S": "2",
                            "ROUND_CLEANUP_GRACE_MS": "1000", "NAT_SEED_BASE": "70000",
                            "NAT_SIM_RUN_ID": "b01-actual-hh-outer-offline", "NAT_SIM_ARTIFACT_DIR": str(self.artifacts),
                            "NAT_TOPOLOGY_HEAD_SHA": SOURCE_HEAD, "NAT_TOPOLOGY_WORKFLOW_SHA": WORKFLOW_HEAD,
                            "EXPERIMENT_BASELINE_SHA": SOURCE_HEAD,
                            "EXPERIMENT_VARIANT": "b01-hh-outer-offline-fixture", "EXPERIMENT_SCENARIO": "b01-hh-outer-offline-fixture",
                            # Plain PS4 variable expansion only. The trace
                            # observes actual waits in the owning sub=0 shell.
                            "PS4": "+ B01_CLI pid=$$ sub=$BASH_SUBSHELL line=$LINENO: "}
        preparation_remaining()
        self.sentinel = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import os,signal; signal.signal(signal.SIGTERM,lambda *_:exit(0)); "
             "os.write(1,b'B01_SENTINEL_READY\\n'); signal.pause()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not select.select([self.sentinel.stdout], [], [], min(1, preparation_remaining()))[0]:
            raise AssertionError("B01 unrelated sentinel not ready (not a product RED)")
        if self.sentinel.stdout.readline() != b"B01_SENTINEL_READY\n":
            raise AssertionError("B01 unrelated sentinel response invalid (not a product RED)")
        preparation_remaining()

    def execute(self):
        self.protocol_end = time.monotonic() + PROTOCOL_SECONDS
        self.teardown_end = self.protocol_end + TEARDOWN_SECONDS
        with self.stdout_path.open("xb") as output, self.stderr_path.open("xb") as error:
            os.fchmod(output.fileno(), 0o600)
            os.fchmod(error.fileno(), 0o600)
            self.process = subprocess.Popen(
                [SHELL, "-x", str(self.repository / "scripts/nat-sim/nat-sim-smoke.sh")],
                cwd=self.repository, env=self.environment, stdin=subprocess.DEVNULL,
                stdout=output, stderr=error, start_new_session=True)
            try:
                self.cli_status = self.process.wait(timeout=max(0, self.protocol_end - time.monotonic()))
            except subprocess.TimeoutExpired:
                self.close()
                raise AssertionError("B01 complete actual CLI timed out (not a product RED)")
        self.stdout, self.stderr = self.read_log(self.stdout_path), self.read_log(self.stderr_path)
        if "B01_FIXTURE_INFRA_FAILURE:" in self.stdout + self.stderr:
            raise AssertionError("B01 external seam rejected input (not a product RED): " + self.stderr[-5000:])
        self.events = self.read_events()
        if any(row["tool"] == "child_fixture_deadline" for row in self.events):
            raise AssertionError("B01 fake child lifetime expired (not a product RED)")
        for relative, expected in self.original_sources.items():
            if digest(self.repository / relative) != expected:
                raise AssertionError("B01 original private CLI source changed (not a product RED)")
        self.prove_children_closed()
        self.prove_ports_released()
        if self.sentinel.poll() is not None:
            raise AssertionError("B01 actual CLI stopped an unregistered sentinel (not a product RED)")
        receipt = {"fixture_only": True, "case": self.case, "cli_exit_status": self.cli_status,
                   "cli_pid": self.process.pid, "supervisor_rescue": self.rescued,
                   "sentinel_pid": self.sentinel.pid, "sentinel_wait": "pending_fixture_teardown",
                   "original_sources": self.original_sources,
                   "stdout_sha256": digest(self.stdout_path), "stderr_xtrace_sha256": digest(self.stderr_path),
                   "external_events_sha256": digest(self.root / "external-events.jsonl"),
                   "protocol_seconds": PROTOCOL_SECONDS, "teardown_seconds": TEARDOWN_SECONDS,
                   "round_timeout_seconds": 20, "resource_grace_cap_ms": 1000,
                   "roles": sorted(self.roles), "rounds": self.rounds}
        with (self.root / "actual-cli-fixture-receipt.json").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(receipt, stream, sort_keys=True)
            stream.write("\n")
        print("B01_ACTUAL_CLI_FIXTURE=" + str(self.root), flush=True)
        return self

    @staticmethod
    def read_log(path):
        with path.open("rb") as stream:
            payload = stream.read(LOG_CAP + 1)
        if len(payload) > LOG_CAP:
            raise AssertionError("B01 actual CLI log cap exceeded (not a product RED)")
        return payload.decode(errors="replace")

    def read_events(self):
        with (self.root / "external-events.jsonl").open("rb") as stream:
            payload = stream.read(256 * 1024 + 1)
        if len(payload) > 256 * 1024:
            raise AssertionError("B01 external event cap exceeded (not a product RED)")
        rows = payload.splitlines()
        if len(rows) > 512 or any(len(row) > 4096 for row in rows):
            raise AssertionError("B01 external event count/row cap exceeded (not a product RED)")
        return [json.loads(row) for row in rows]

    @staticmethod
    def bounded_json(path, cap=128 * 1024):
        with path.open("rb") as stream:
            data = stream.read(cap + 1)
        if len(data) > cap:
            raise AssertionError("B01 outer fixture JSON cap exceeded (not a product RED)")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise AssertionError("B01 outer fixture object missing (not a product RED)")
        return value

    def prove_wait(self, pid, status):
        prefix = rf"^\++ B01_CLI pid={self.process.pid} sub=0 line=[0-9]+: "
        if not re.search(prefix + rf"wait {pid}$", self.stderr, re.MULTILINE):
            raise AssertionError("B01 original owning shell actual wait missing (not a product RED)")
        if not re.search(prefix + rf"round_record_wait {pid} {status}$", self.stderr, re.MULTILINE):
            raise AssertionError("B01 actual wait status ledger handoff missing (not a product RED)")
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("B01 original child remains live/unreaped (not a product RED)")

    def prove_children_closed(self):
        directory = self.artifacts / "round-1"
        ready_events = [row for row in self.events if row["tool"] == "child_ready"]
        stopped_events = [row for row in self.events if row["tool"] == "child_stopped"]
        if ({row["role"] for row in ready_events} != FAKE_ROLES or len(ready_events) != 3
                or {row["role"] for row in stopped_events} != FAKE_ROLES or len(stopped_events) != 3):
            raise AssertionError("B01 expected exactly three real fake children (not a product RED)")
        for role in FAKE_ROLES:
            ready = self.bounded_json(directory / (role + ".fixture-ready.json"))
            stopped = self.bounded_json(directory / (role + ".fixture-stopped.json"))
            if (ready["pid"] != stopped["pid"] or ready["role"] != role or stopped["role"] != role
                    or stopped["signal"] != signal.SIGTERM or stopped["exit_code"] != 0):
                raise AssertionError("B01 fake child lacks genuine TERM/wait0 (not a product RED)")
            self.prove_wait(ready["pid"], 0)
            if role != "nat":
                declaration = self.bounded_json(directory / "launches" / (role + ".json"))
                if declaration["pid"] != ready["pid"] or declaration["role"] != role:
                    raise AssertionError("B01 real launch record/child differs (not a product RED)")
        entered = [row for row in self.events if row["tool"] == "original_watcher_exec"]
        if self.case == "direct-gate-not-active":
            if entered:
                raise AssertionError("B01 O1 unexpectedly started watcher (not a product RED)")
            return
        if len(entered) != 1:
            raise AssertionError("B01 O2 original watcher exec missing/repeated (not a product RED)")
        entered = entered[0]
        self.watcher_pid = entered["pid"]
        expected_script = self.repository / "scripts/nat-sim/hard_hard_gate.py"
        if (entered["script_sha256"] != self.original_sources["scripts/nat-sim/hard_hard_gate.py"]
                or entered["argv"][0] != str(expected_script) or entered["parent_pid"] != self.process.pid):
            raise AssertionError("B01 real watcher PID/source/argv binding differs (not a product RED)")
        expected_prefix = [str(expected_script), "--watch", "--node-a-log", str(directory / "node-a.log"),
                           "--node-b-log", str(directory / "node-b.log"), "--gate-file",
                           str(directory / "hard-hard-direct.open"), "--evidence-file",
                           str(directory / "hard-hard-direct-gate.json"), "--armed-file",
                           str(directory / "hard-hard-direct-gate.armed")]
        argv = entered["argv"]
        if (len(argv) != 16 or argv[:12] != expected_prefix or argv[12] != "--deadline-ms"
                or not argv[13].isdecimal() or argv[14:] != ["--max-skew-ms", "250"]):
            raise AssertionError("B01 original watcher full argv/default fence differs (not a product RED)")
        self.prove_wait(self.watcher_pid, 1)
        prefix = rf"^\++ B01_CLI pid={self.process.pid} sub=0 line=[0-9]+: "
        if re.search(prefix + rf"kill -(?:TERM|KILL) {self.watcher_pid}$", self.stderr, re.MULTILINE):
            raise AssertionError("B01 cached watcher was signalled again (not a product RED)")
        armed = directory / "hard-hard-direct-gate.armed"
        if not armed.is_dir() or armed.is_file():
            raise AssertionError("B01 real armed-path type failure was not retained (not a product RED)")
        evidence = self.bounded_json(directory / "hard-hard-direct-gate.json")
        watcher_output = self.read_log(directory / "hard-hard-direct-gate.out")
        original = json.loads(watcher_output.strip())
        if (evidence != original or evidence["result"] != "rejected"
                or evidence["reason_code"] != "rendezvous_gate_io_failed"):
            raise AssertionError("B01 original watcher did not reject its actual write (not a product RED)")
        mutation = [row for row in self.events if row["tool"] == "armed_input_directory"]
        if (len(mutation) != 1 or mutation[0]["path"] != str(armed)
                or mutation[0]["monotonic_ns"] >= entered["monotonic_ns"]):
            raise AssertionError("B01 armed external input was not established before real exec (not a product RED)")

    def prove_ports_released(self):
        reservation_calls = [row for row in self.events if row["tool"] == "original_port_reservation"]
        release_calls = [row for row in self.events if row["tool"] == "original_port_release"]
        if len(reservation_calls) != 1 or len(release_calls) != 1:
            raise AssertionError("B01 original port reserve/release calls missing (not a product RED)")
        expected = self.original_sources["scripts/nat-sim/reserve_port_block.py"]
        if any(row["original_script_sha256"] != expected for row in [*reservation_calls, *release_calls]):
            raise AssertionError("B01 port reservation script bytes differ (not a product RED)")
        locks = self.root / "tmp/p2wlan-natsim-port-locks"
        if not locks.is_dir() or any(locks.iterdir()):
            raise AssertionError("B01 real port reservation was not released (not a product RED)")

    def close(self):
        if self.closed:
            return
        error = None
        teardown_started = time.monotonic()
        teardown_end = min(self.teardown_end or (teardown_started + TEARDOWN_SECONDS),
                           teardown_started + TEARDOWN_SECONDS)
        if self.process is not None and self.process.poll() is None:
            self.rescued = True
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=max(0, teardown_end - time.monotonic() - 0.1))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=max(0, teardown_end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    error = "B01 controller could not be reaped in fixed teardown"
        if self.sentinel is not None:
            if self.sentinel.poll() is None:
                self.sentinel.terminate()
            try:
                self.sentinel.wait(timeout=max(0, teardown_end - time.monotonic()))
            except subprocess.TimeoutExpired:
                self.sentinel.kill()
                try:
                    self.sentinel.wait(timeout=max(0, teardown_end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    error = "B01 sentinel could not be reaped in fixed teardown"
            for stream in (self.sentinel.stdout, self.sentinel.stderr):
                if stream is not None:
                    stream.close()
            if self.sentinel.returncode != 0:
                error = "B01 sentinel did not complete cooperative TERM and actual wait 0"
            with (self.root / "sentinel-cleanup.json").open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump({"fixture_only": True, "pid": self.sentinel.pid,
                           "wait_completed": self.sentinel.returncode is not None,
                           "wait_status": self.sentinel.returncode}, stream, sort_keys=True)
                stream.write("\n")
        self.closed = True
        if self.rescued or error:
            raise AssertionError((error or "B01 actual CLI needed supervisor rescue") + " (not a product RED)")


class ActualHardHardOuterCallerTests(unittest.TestCase):
    def fixture(self, case):
        source = source_repository()
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-hh-outer-cli-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name) / "exclusive-case"
        fixture = HardHardOuterCliFixture(directory, source, case, 1)
        self.addCleanup(fixture.close)
        fixture.execute()
        fixture.close()
        sentinel = fixture.bounded_json(fixture.root / "sentinel-cleanup.json")
        self.assertTrue(sentinel["wait_completed"])
        self.assertEqual(sentinel["wait_status"], 0)
        self.assertFalse(fixture.rescued)
        return fixture

    def invalid_denominator(self, fixture):
        matrix = matrix_module(fixture.repository)
        with self.assertRaises(matrix.EvidenceError) as rejected:
            matrix.validate_round(fixture.artifacts / "round-1", matrix.SCENARIO_BY_NAME["equal-step"],
                                  1, SOURCE_HEAD, WORKFLOW_HEAD)
        self.assertTrue(str(rejected.exception).startswith("raw_evidence_missing:"))
        for name in ("node-a.status.json", "node-b.status.json", "node-a.log", "node-b.log"):
            self.assertIn(name, str(rejected.exception))
        summary = matrix.aggregate_runs([{ "exit_code": 1, "rounds": [
            {"result": "invalid", "reason": str(rejected.exception)}]}])
        self.assertEqual(summary["requested"]["rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0)
        return summary

    def prerequisites(self, fixture, expected):
        directory = fixture.artifacts / "round-1"
        self.assertEqual(fixture.cli_status, 1)
        self.assertIn("ROUND 1: FAIL reason_code=" + expected, fixture.stderr)
        calls = [row["endpoint"] for row in fixture.events if row["tool"] == "curl"]
        self.assertIn("/health", calls)
        self.assertIn("/api/v1/register", calls)
        self.assertNotIn("/status", calls)
        self.assertFalse(any(row["tool"] == "original_collector_enter" for row in fixture.events))
        for side in ("a", "b"):
            for suffix in (".fixture-ready.json", ".fixture-business.json", ".status.json", ".log"):
                self.assertFalse((directory / ("node-" + side + suffix)).exists())
            self.assertFalse((directory / "launches" / ("node-" + side + ".json")).exists())
        self.assertFalse((directory / "business-validation.start-gate").exists())
        self.assertFalse((directory / "hard-hard-direct.open").exists())
        nat = fixture.read_log(directory / "nat-sim.out")
        self.assertIn("STUN_A=", nat)
        self.assertIn("STUN_B=", nat)
        if fixture.case == "direct-gate-not-active":
            self.assertNotIn("DIRECT_GATE=1", nat)
        else:
            self.assertIn("DIRECT_GATE=1", nat)
        self.invalid_denominator(fixture)

    def assert_finalization(self, fixture, expected, marker):
        directory = fixture.artifacts / "round-1"
        path = directory / "round-finalization.json"
        self.assertTrue(path.is_file(), marker + ": outer caller must preserve its round before continue/EXIT")
        value = fixture.bounded_json(path)
        self.assertEqual(value["terminal_reason_code"], expected, marker + ": preserve the original outer cause")
        self.assertEqual(value["original_exit_code"], 1, marker)
        self.assertEqual(value["round_result"], "invalid", marker)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600, marker)
        publish_prefix = rf"^\++ B01_CLI pid={fixture.process.pid} sub=[0-9]+ line=[0-9]+: "
        actual_publish = re.findall(publish_prefix + r"_round_tool publish --round-dir "
                                    + re.escape(str(directory)) + r"(?: |$)", fixture.stderr, re.MULTILINE)
        self.assertEqual(len(actual_publish), 1, marker + ": one actual receipt publication transaction")
        cleanup = fixture.bounded_json(directory / "cleanup.json")
        self.assertTrue(cleanup["all_reaped"], marker)
        self.assertFalse(cleanup["forced_termination"], marker)
        self.assertEqual({row["role"] for row in cleanup["owned_processes"]}, fixture.roles, marker)
        self.assertEqual(len(cleanup["owned_processes"]), len(fixture.roles), marker)
        for row in cleanup["owned_processes"]:
            self.assertTrue(row["wait_completed"], marker)
            self.assertEqual(row["wait_status"], 1 if row["role"] == "watcher" else 0, marker)
            if row["role"] == "watcher": self.assertEqual(row["pid"], fixture.watcher_pid, marker)
        for side in ("a", "b"):
            captured = fixture.bounded_json(directory / (".final-status-" + side + ".json"))
            self.assertEqual(captured["result"], "unknown", marker)
            self.assertEqual(captured["reason_code"], "not_started", marker)
            self.assertEqual(captured["pid"], 0, marker)
            self.assertFalse(captured["worker"]["started"], marker)
        # Real finalizer sidecars cannot substitute authenticated raw status.
        self.invalid_denominator(fixture)

    def test_actual_hh_direct_gate_not_active_preserves_outer_cause(self):
        fixture = self.fixture("direct-gate-not-active")
        reason = "hard_hard_direct_gate_not_active"
        self.prerequisites(fixture, reason)
        self.assert_finalization(fixture, reason, "B01_ACTUAL_HH_DIRECT_GATE_FINALIZATION")

    def test_actual_hh_watcher_not_armed_preserves_outer_cause_and_actual_wait(self):
        fixture = self.fixture("watcher-not-armed")
        reason = "hard_hard_gate_watcher_not_armed"
        self.prerequisites(fixture, reason)
        self.assert_finalization(fixture, reason, "B01_ACTUAL_HH_WATCHER_ARM_FINALIZATION")


if __name__ == "__main__":
    unittest.main()
