#!/usr/bin/env python3
"""PLANNED ONLY: independent complete-CLI O5/O7 barrier candidates.

The author has not executed this module. Only declared external tools supply
inputs; original main, task health, handlers, collectors and matrix remain real.
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
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from fixture_http_owner_assertions import assert_http_owner_union


HERE = Path(__file__).resolve().parent
EXTERNAL_TOOLS = HERE / "fixture_barrier_outer_tools.py"
SHELL = "/bin/bash"
LOG_CAP = 2 * 1024 * 1024
PROTOCOL_SECONDS = 12
TEARDOWN_SECONDS = 2
SOURCE_HEAD = "a" * 40
WORKFLOW_HEAD = "b" * 40
FAKE_ROLES = {"nat", "control", "relay-1", "node-a", "node-b"}
CASE_MODES = {"availability-barrier-unhealthy": "relay-only", "direct-barrier-unhealthy": "direct"}
CASES = set(CASE_MODES)


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


class BarrierOuterCliFixture:
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
        self.roles = set(FAKE_ROLES)
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
            # A single fixed shell exec avoids an extra Python interpreter;
            # quoted fixed arguments and "$@" preserve the real argument list.
            payload = "#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in
                       (sys.executable, "-S", str(driver), str(self.root), name)) + ' "$@"\n'
            with (commands / name).open("x") as stream:
                os.fchmod(stream.fileno(), 0o700)
                stream.write(payload)
        (self.root / "tmp").mkdir(mode=0o700)
        self.environment = {"PATH": str(commands) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                            "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                            "TMPDIR": str(self.root / "tmp"),
                            "MODE": CASE_MODES[self.case], "ROUNDS": str(self.rounds), "RELAY_COUNT": "1",
                            "EGRESS_CAPTURE": "listeners", "UNASSIGNED_EGRESS_LISTENERS": "0",
                            "ROUND_TIMEOUT_S": "20", "DIRECT_TIMEOUT_S": "2", "OVERLAY_TIMEOUT_S": "2",
                            "ROUND_CLEANUP_GRACE_MS": "1000", "NAT_SEED_BASE": "70000",
                            "NAT_SIM_RUN_ID": "b01-actual-barrier-outer-offline", "NAT_SIM_ARTIFACT_DIR": str(self.artifacts),
                            "NAT_TOPOLOGY_HEAD_SHA": SOURCE_HEAD, "NAT_TOPOLOGY_WORKFLOW_SHA": WORKFLOW_HEAD,
                            "EXPERIMENT_BASELINE_SHA": SOURCE_HEAD,
                            "EXPERIMENT_VARIANT": "b01-barrier-outer-offline-fixture", "EXPERIMENT_SCENARIO": "b01-barrier-outer-offline-fixture",
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
        if ({row["role"] for row in ready_events} != self.roles or len(ready_events) != 5
                or {row["role"] for row in stopped_events} != self.roles or len(stopped_events) != 5):
            raise AssertionError("B01 expected exactly five genuine fake children (not a product RED)")
        observed_pids = set()
        self.child_records = {}
        for role in self.roles:
            ready = self.bounded_json(directory / (role + ".fixture-ready.json"), 32 * 1024)
            stopped = self.bounded_json(directory / (role + ".fixture-stopped.json"), 32 * 1024)
            component = "daemon" if role.startswith("node-") else "relay" if role == "relay-1" else role
            pid = ready["pid"]
            if (type(pid) is not int or pid <= 0 or pid in observed_pids
                    or ready["role"] != role or ready["component"] != component
                    or type(ready["round"]) is not int or ready["round"] != 1
                    or ready["fixture_only"] is not True or ready["exit_code"] is not None
                    or stopped["pid"] != pid or stopped["role"] != role
                    or stopped["component"] != component or stopped["round"] != 1
                    or stopped["fixture_only"] is not True
                    or stopped["signal"] != signal.SIGTERM or stopped["exit_code"] != 0):
                raise AssertionError("B01 fake child lacks genuine identity/TERM/wait0 (not a product RED)")
            observed_pids.add(pid)
            matching_ready = [row for row in ready_events if row["role"] == role and row["pid"] == pid
                              and row["round"] == 1 and row["fixture_only"] is True]
            matching_stopped = [row for row in stopped_events if row["role"] == role and row["pid"] == pid
                                and row["round"] == 1 and row["fixture_only"] is True
                                and row["signal"] == signal.SIGTERM and row["exit_code"] == 0]
            if (len(matching_ready) != 1 or len(matching_stopped) != 1
                    or matching_ready[0]["monotonic_ns"] > matching_stopped[0]["monotonic_ns"]):
                raise AssertionError("B01 fake event/PID/TERM sequence differs (not a product RED)")
            self.prove_wait(pid, 0)
            if role != "nat":
                declaration = self.bounded_json(directory / "launches" / (role + ".json"))
                if (declaration["pid"] != pid or declaration["role"] != role
                        or declaration["component"] != component):
                    raise AssertionError("B01 original launch/child differs (not a product RED)")
            self.child_records[role] = ready
        if any(row["tool"] == "original_watcher_exec" for row in self.events):
            raise AssertionError("B01 barrier fixture unexpectedly started watcher (not a product RED)")

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


class ActualBarrierOuterCallerTests(unittest.TestCase):
    def fixture(self, case):
        source = source_repository()
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-barrier-outer-cli-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name) / "exclusive-case"
        fixture = BarrierOuterCliFixture(directory, source, case, 1)
        self.addCleanup(fixture.close)
        fixture.execute()
        fixture.close()
        sentinel = fixture.bounded_json(fixture.root / "sentinel-cleanup.json")
        self.assertTrue(sentinel["wait_completed"])
        self.assertEqual(sentinel["wait_status"], 0)
        self.assertFalse(fixture.rescued)
        return fixture

    def invalid_denominator(self, fixture, marker=None):
        message = marker or "B01 original matrix prerequisite (not a product RED)"
        matrix = matrix_module(fixture.repository)
        with self.assertRaises(matrix.EvidenceError, msg=message) as rejected:
            matrix.validate_round(fixture.artifacts / "round-1", matrix.SCENARIO_BY_NAME["equal-step"],
                                  1, SOURCE_HEAD, WORKFLOW_HEAD)
        reason = str(rejected.exception)
        self.assertTrue(reason.startswith(("raw_evidence_missing:", "nat_evidence_rejected:")), message)
        summary = matrix.aggregate_runs([{"exit_code": fixture.cli_status, "rounds": [
            {"result": "invalid", "reason": reason}]}])
        self.assertEqual(summary["requested"]["rounds"], 1, message)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1, message)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0, message)
        return summary

    def prerequisites(self, fixture):
        directory = fixture.artifacts / "round-1"
        self.assertEqual(fixture.cli_status, 1)
        actual_lines = re.findall(r"^\[nat-sim\] ROUND 1: FAIL reason_code=critical_tasks_unhealthy "
                                  r"stage=barrier(?: |$)", fixture.stderr, re.MULTILINE)
        self.assertEqual(len(actual_lines), 1)
        self.assertIn("MODE=" + CASE_MODES[fixture.case], fixture.stderr)
        prefix = rf"^\++ B01_CLI pid={fixture.process.pid} sub=0 line=[0-9]+: "
        self.assertRegex(fixture.stderr, re.compile(prefix + r"BARRIER_REASON=critical_tasks_unhealthy$", re.MULTILINE))
        self.assertRegex(fixture.stderr, re.compile(prefix + r"BARRIER_RESULT=task_failed$", re.MULTILINE))
        all_subs = rf"^\++ B01_CLI pid={fixture.process.pid} sub=[0-9]+ line=[0-9]+: "
        for side in ("a", "b"):
            path = directory / ("node-" + side + ".barrier.status.json")
            self.assertRegex(fixture.stderr, re.compile(all_subs + r"node_task_health_ok "
                                                      + re.escape(str(path)) + r"$", re.MULTILINE))
        self.assertTrue((directory / "business-validation.started").is_file())
        self.assertFalse((directory / "business-validation.start-gate").exists())
        self.assertFalse((directory / "hard-hard-direct.open").exists())
        self.assertFalse((directory / "hard-hard-direct-gate.armed").exists())
        self.assertFalse((directory / "hard-hard-direct-gate.json").exists())
        self.assertFalse(any(row["tool"] == "original_collector_enter" for row in fixture.events))
        for suffix in (".collector-result.json", ".mapping-result.json", ".continuity-result.json", ".drain-result.json"):
            self.assertFalse((directory / suffix).exists())
        barrier = fixture.bounded_json(directory / "relay-barrier.readiness.json")
        self.assertEqual(barrier["stage"], "barrier")
        self.assertEqual(barrier["result"], "task_failed")
        self.assertEqual(barrier["reason_code"], "critical_tasks_unhealthy")
        self.assertTrue(barrier["business_validation_started"])
        self.assertTrue(barrier["process_alive_a"])
        self.assertTrue(barrier["process_alive_b"])
        self.assertEqual(barrier["http_status_a"], 200)
        self.assertEqual(barrier["http_status_b"], 200)
        self.assertTrue(barrier["task_health_a"])
        self.assertFalse(barrier["task_health_b"])
        # The original barrier exits on B task health before its Relay log
        # confirmation scan; false confirmation flags are truthful here.
        self.assertFalse(barrier["relay_peer_confirmed_a"])
        self.assertFalse(barrier["relay_peer_confirmed_b"])
        calls = [row for row in fixture.events if row["tool"] == "curl"]
        self.assertTrue(any(row["endpoint"] == "/health" for row in calls))
        self.assertEqual(sum(row["endpoint"] == "/api/v1/register" for row in calls), 1)
        for side in ("a", "b"):
            role = "node-" + side
            ready = fixture.child_records[role]
            self.assertEqual(barrier["pid_" + side], ready["pid"])
            token_ready = fixture.bounded_json(directory / (role + ".readiness.json"))
            baseline_ready = fixture.bounded_json(directory / (role + ".baseline.readiness.json"))
            self.assertEqual(token_ready["result"], "ready")
            self.assertEqual(token_ready["pid"], ready["pid"])
            self.assertTrue(token_ready["process_alive"])
            self.assertTrue(token_ready["token_present"])
            self.assertEqual(baseline_ready["result"], "ready")
            self.assertEqual(baseline_ready["pid"], ready["pid"])
            self.assertTrue(baseline_ready["process_alive"])
            self.assertTrue(baseline_ready["token_present"])
            self.assertEqual(baseline_ready["http_status"], 200)
            self.assertEqual(baseline_ready["attempts"], 1)
            self.assertFalse((directory / (role + ".fixture-business.json")).exists())
            log = fixture.read_log(directory / (role + ".log"))
            self.assertIn('event="relay_peer_confirmed"', log)
            self.assertNotIn('event="overlay_start_gate_released"', log)
            self.assertNotIn("overlay_payload_verified", log)
            self.assertNotIn('event="first_real_business_ingress"', log)
            for kind in ("baseline", "barrier"):
                path = directory / (role + "." + kind + ".status.json")
                status = fixture.bounded_json(path, 1024 * 1024)
                self.assertEqual(status["process_id"], ready["pid"])
                self.assertEqual(status["node_id"], role)
                tasks = status["health"]["critical_tasks"]
                self.assertEqual(len(tasks), 1)
                task = tasks[0]
                unhealthy = side == "b" and kind == "barrier"
                self.assertIs(task["critical"], True)
                self.assertIs(task["running"], not unhealthy)
                self.assertIs(task["finished"], False)
                self.assertIsNone(task["error"])
                self.assertEqual(status["connection_timeline"]["events"], [])
                self.assertEqual(status["connection_timeline"]["first_usable_summaries"], [])
                matching = [row for row in calls if row["endpoint"] == "/status"
                            and row["output"] == str(path) and row["side"] == side and row["round"] == 1]
                self.assertEqual(len(matching), 1)
                event = matching[0]
                self.assertIs(event["is_baseline"], kind == "baseline")
                self.assertIs(event["is_barrier"], kind == "barrier")
                self.assertIs(event["barrier_unhealthy_input"], unhealthy)
                self.assertEqual(event["response_sha256"], digest(path))
        self.assertEqual(sum(row.get("barrier_unhealthy_input") is True for row in calls), 1)
        nat = fixture.read_log(directory / "nat-sim.out")
        self.assertIn("STUN_A=", nat)
        self.assertIn("STUN_B=", nat)
        if fixture.case == "availability-barrier-unhealthy":
            self.assertIn("BLOCK_DIRECT=1", nat)
            for side in ("a", "b"):
                ready = fixture.child_records["node-" + side]
                self.assertIs(ready["overlay_validation"], True)
                self.assertIs(ready["overlay_any_path"], True)
                self.assertIsNone(ready["overlay_start_gate_file"])
        else:
            self.assertNotIn("BLOCK_DIRECT=1", nat)
            for side in ("a", "b"):
                ready = fixture.child_records["node-" + side]
                self.assertIs(ready["overlay_validation"], True)
                self.assertIs(ready["overlay_any_path"], False)
                self.assertEqual(ready["overlay_start_gate_file"],
                                 str(directory / "business-validation.start-gate"))
        self.invalid_denominator(fixture)

    def assert_finalization(self, fixture, marker):
        directory = fixture.artifacts / "round-1"
        path = directory / "round-finalization.json"
        self.assertTrue(path.is_file(), marker + ": outer caller must publish its round")
        value = fixture.bounded_json(path)
        self.assertEqual(value["terminal_reason_code"], "critical_tasks_unhealthy",
                         marker + ": preserve the original barrier cause")
        self.assertEqual(value["original_exit_code"], 1, marker)
        self.assertEqual(value["round_result"], "invalid", marker)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600, marker)
        publish_prefix = rf"^\++ B01_CLI pid={fixture.process.pid} sub=[0-9]+ line=[0-9]+: "
        actual_publish = re.findall(publish_prefix + r"_round_tool publish --round-dir "
                                    + re.escape(str(directory)) + r"(?: |$)", fixture.stderr, re.MULTILINE)
        self.assertEqual(len(actual_publish), 1, marker + ": one actual publication transaction")
        cleanup = fixture.bounded_json(directory / "cleanup.json")
        self.assertTrue(cleanup["all_reaped"], marker)
        self.assertFalse(cleanup["forced_termination"], marker)
        business_owners = assert_http_owner_union(
            self, fixture, directory, cleanup, fixture.roles,
            (1,), marker)
        self.assertEqual(cleanup["pending_process_count"], 0, marker)
        self.assertEqual(cleanup["worker_unknown_count"], 0, marker)
        self.assertEqual({row["role"] for row in business_owners}, fixture.roles, marker)
        self.assertEqual(len(business_owners), 5, marker)
        for row in business_owners:
            self.assertTrue(row["wait_completed"], marker)
            self.assertEqual(row["wait_status"], 0, marker)
            self.assertEqual(row["pid"], fixture.child_records[row["role"]]["pid"], marker)
            self.assertFalse(row["forced_termination"], marker)
        for side in ("a", "b"):
            role = "node-" + side
            captured = fixture.bounded_json(directory / (".final-status-" + side + ".json"))
            self.assertEqual(value["statuses"][side], captured, marker)
            self.assertEqual(captured["pid"], fixture.child_records[role]["pid"], marker)
            self.assertEqual(captured["owner_role"], role, marker)
            self.assertIn(captured["result"], ("available", "unknown"), marker)
            canonical_calls = [row for row in fixture.events if row["tool"] == "curl"
                               and row.get("output") == str(directory / (role + ".status.json.capture"))]
            self.assertLessEqual(len(canonical_calls), 1, marker)
            worker = captured["worker"]
            self.assertIs(type(worker["started"]), bool, marker)
            if worker["started"]:
                self.assertTrue(worker["wait_completed"], marker)
                self.assertTrue(worker["command_wait_completed"], marker)
                self.assertTrue(worker["owned_group_shutdown_requested_before_wait"], marker)
                self.assertFalse(worker["forced_termination"], marker)
            raw = directory / (role + ".status.json")
            if captured["result"] == "available":
                self.assertIsNone(captured["reason_code"], marker)
                self.assertEqual(captured["process_observation"], "live_job", marker)
                self.assertTrue(worker["started"], marker)
                self.assertEqual(worker["result"], "completed", marker)
                self.assertEqual(worker["command_wait_status"], 0, marker)
                self.assertEqual(len(canonical_calls), 1, marker)
                self.assertTrue(raw.is_file(), marker)
                self.assertEqual(captured["sha256"], digest(raw), marker)
                self.assertEqual(canonical_calls[0]["response_sha256"], digest(raw), marker)
                for field in ("is_baseline", "is_barrier", "barrier_unhealthy_input"):
                    self.assertIs(canonical_calls[0][field], False, marker)
                status = fixture.bounded_json(raw, 1024 * 1024)
                self.assertEqual(status["process_id"], fixture.child_records[role]["pid"], marker)
                self.assertEqual(status["node_id"], role, marker)
                tasks = status["health"]["critical_tasks"]
                self.assertEqual(len(tasks), 1, marker)
                self.assertIs(tasks[0]["critical"], True, marker)
                self.assertIs(tasks[0]["running"], True, marker)
                self.assertIs(tasks[0]["finished"], False, marker)
                self.assertIsNone(tasks[0]["error"], marker)
                self.assertEqual(status["connection_timeline"]["events"], [], marker)
                self.assertEqual(status["connection_timeline"]["first_usable_summaries"], [], marker)
            else:
                self.assertIn(captured["reason_code"], ("deadline_exhausted", "resource_grace_exhausted",
                    "process_gone", "process_ownership_unknown", "status_unavailable", "status_auth_token_missing",
                    "status_schema_invalid", "status_schema_or_capture_failure"), marker)
                self.assertIsNone(captured["sha256"], marker)
                self.assertFalse(raw.exists(), marker)
                if captured["reason_code"] == "process_gone":
                    self.assertEqual(captured["process_observation"], "wait_complete", marker)
                    self.assertEqual(captured["identity_scope"], "round_original_owned_pid_after_actual_wait", marker)
                    self.assertFalse(worker["started"], marker)
        identity = fixture.bounded_json(directory / ".round-source-identity.json")
        self.assertEqual(value["source_identity"], identity, marker)
        self.assertIn(identity["result"], ("captured", "unknown"), marker)
        if identity["result"] == "captured":
            self.assertIsNone(identity["reason_code"], marker)
            source = fixture.bounded_json(fixture.artifacts / "source-at-build.json")
            self.assertEqual(identity["source"], source, marker)
            self.assertEqual(identity["source_at_build_sha256"], digest(fixture.artifacts / "source-at-build.json"), marker)
            self.assertEqual(identity["artifact_set_sha256"], digest(fixture.artifacts / "artifact-set.json"), marker)
            records = identity["launch_records"]
            self.assertEqual({row["role"] for row in records}, fixture.roles - {"nat"}, marker)
            self.assertEqual(len(records), 4, marker)
            for row in records:
                self.assertEqual(row["pid"], fixture.child_records[row["role"]]["pid"], marker)
                self.assertEqual(row["sha256"], digest(directory / "launches" / (row["role"] + ".json")), marker)
                self.assertEqual(row["state"], "exec_requested", marker)
        else:
            self.assertIn(identity["reason_code"], ("deadline_exhausted", "launch_capacity_or_deadline_exhausted"), marker)
        evidence = fixture.bounded_json(directory / "nat-evidence.json")
        self.assertEqual(evidence["result"], "fail", marker)
        self.assertFalse(evidence["executed"], marker)
        self.assertIsNone(evidence["nat_terminal"], marker)
        self.assertEqual(evidence["decision"]["reason_code"], "harness:critical_tasks_unhealthy", marker)
        self.invalid_denominator(fixture, marker)

    def test_actual_availability_barrier_unhealthy_preserves_outer_cause(self):
        fixture = self.fixture("availability-barrier-unhealthy")
        self.prerequisites(fixture)
        self.assert_finalization(fixture, "B01_ACTUAL_AVAILABILITY_BARRIER_FINALIZATION")

    def test_actual_direct_barrier_unhealthy_preserves_outer_cause(self):
        fixture = self.fixture("direct-barrier-unhealthy")
        self.prerequisites(fixture)
        self.assert_finalization(fixture, "B01_ACTUAL_DIRECT_BARRIER_FINALIZATION")


if __name__ == "__main__":
    unittest.main()
