#!/usr/bin/env python3
"""Test-first candidates for the complete, unchanged NAT smoke CLI.

The fixture does not source extracted branch copies, call finish/cleanup, or
manufacture a finalization receipt. All decisions and collectors are original.
Only declared offline external tools/processes supply controlled inputs.
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

from fixture_http_owner_assertions import assert_http_owner_union, bounded_http_contract_json


HERE = Path(__file__).resolve().parent
EXTERNAL_TOOLS = HERE / "fixture_external_tools.py"
SHELL = "/bin/bash"
LOG_CAP = 2 * 1024 * 1024
PROTOCOL_SECONDS = 12
TEARDOWN_SECONDS = 2
SOURCE_HEAD = "a" * 40
WORKFLOW_HEAD = "b" * 40
ROLES = {"nat", "control", "relay-1", "node-a", "node-b"}


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


class ActualCliFixture:
    """One real CLI shell, one absolute supervisor budget and real owned waits.

    Preparation is private local Git work only, bounded separately to four
    seconds. CLI supervision is twelve seconds including every round; it is
    shorter than its unchanged twenty-second per-round deadline. A separate
    two-second teardown never repairs a protocol timeout into a desired RED.
    """

    def __init__(self, root, source, case, rounds):
        # Canonicalize once so private layout fences also hold under symlinked temp roots.
        root = root.resolve()
        self.root, self.source, self.case, self.rounds = root, source, case, rounds
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

        def git(*arguments, cwd=None):
            remaining = preparation_end - time.monotonic()
            if remaining <= 0:
                raise AssertionError("B01 private-layout preparation expired (not a product RED)")
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
        for path in paths:
            relative = path.relative_to(self.source)
            payload = path.read_bytes()
            self.original_sources[str(relative)] = hashlib.sha256(payload).hexdigest()
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(path.stat().st_mode & 0o777)
        for relative, expected in self.original_sources.items():
            if digest(self.source / relative) != expected or digest(self.repository / relative) != expected:
                raise AssertionError("B01 source moved while making private layout (not a product RED)")
        (self.repository / "server").mkdir(exist_ok=True)
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
                            "MODE": "direct", "ROUNDS": str(self.rounds), "RELAY_COUNT": "1",
                            "EGRESS_CAPTURE": "listeners", "UNASSIGNED_EGRESS_LISTENERS": "0",
                            "ROUND_TIMEOUT_S": "20", "DIRECT_TIMEOUT_S": "2", "OVERLAY_TIMEOUT_S": "2",
                            "ROUND_CLEANUP_GRACE_MS": "1000", "NAT_SEED_BASE": "70000",
                            "NAT_SIM_RUN_ID": "b01-actual-offline", "NAT_SIM_ARTIFACT_DIR": str(self.artifacts),
                            "NAT_TOPOLOGY_HEAD_SHA": SOURCE_HEAD, "NAT_TOPOLOGY_WORKFLOW_SHA": WORKFLOW_HEAD,
                            "EXPERIMENT_BASELINE_SHA": SOURCE_HEAD,
                            "EXPERIMENT_VARIANT": "b01-offline-fixture", "EXPERIMENT_SCENARIO": "b01-offline-fixture",
                            # Plain PS4 variable expansion only. The trace
                            # observes actual waits in the owning sub=0 shell.
                            "PS4": "+ B01_CLI pid=$$ sub=$BASH_SUBSHELL line=$LINENO: "}
        self.sentinel = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import signal; signal.signal(signal.SIGTERM,lambda *_:exit(0)); "
             "print('B01_SENTINEL_READY',flush=True); signal.pause()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not select.select([self.sentinel.stdout], [], [], 1)[0]:
            raise AssertionError("B01 unrelated sentinel not ready (not a product RED)")
        if self.sentinel.stdout.readline() != b"B01_SENTINEL_READY\n":
            raise AssertionError("B01 unrelated sentinel response invalid (not a product RED)")

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
        if "child_fixture_deadline" in (self.root / "external-events.jsonl").read_text():
            raise AssertionError("B01 fake child lifetime expired (not a product RED)")
        for relative, expected in self.original_sources.items():
            if digest(self.repository / relative) != expected:
                raise AssertionError("B01 original private CLI source changed (not a product RED)")
        self.events = self.read_events()
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
                   "roles": sorted(ROLES), "rounds": self.rounds}
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
        payload = (self.root / "external-events.jsonl").read_bytes()
        if len(payload) > 256 * 1024:
            raise AssertionError("B01 external event cap exceeded (not a product RED)")
        rows = payload.splitlines()
        if len(rows) > 512 or any(len(row) > 4096 for row in rows):
            raise AssertionError("B01 external event count/row cap exceeded (not a product RED)")
        return [json.loads(row) for row in rows]

    def prove_children_closed(self):
        for number in range(1, self.rounds + 1):
            directory = self.artifacts / f"round-{number}"
            for role in ROLES:
                ready = json.loads((directory / (role + ".fixture-ready.json")).read_text())
                stopped = json.loads((directory / (role + ".fixture-stopped.json")).read_text())
                if (ready["pid"] != stopped["pid"] or stopped["role"] != role
                        or stopped["signal"] != signal.SIGTERM or stopped["exit_code"] != 0):
                    raise AssertionError("B01 owned child lacks genuine cooperative TERM outcome (not a product RED)")
                pid = ready["pid"]
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise AssertionError("B01 owned child remains live or unreaped (not a product RED)")
                # Trace records actual executions of wait and its immediate
                # typed ledger handoff in the owning original shell. This also
                # proves first-round waits when its final receipt is missing.
                prefix = rf"^\++ B01_CLI pid={self.process.pid} sub=0 line=[0-9]+: "
                if not re.search(prefix + rf"wait {pid}$", self.stderr, re.MULTILINE):
                    raise AssertionError("B01 owning shell did not execute actual wait (not a product RED)")
                if not re.search(prefix + rf"round_record_wait {pid} 0$", self.stderr, re.MULTILINE):
                    raise AssertionError("B01 owning shell wait result not handed to real ledger (not a product RED)")
                if role != "nat":
                    declaration = json.loads((directory / "launches" / (role + ".json")).read_text())
                    if declaration["pid"] != pid or declaration["role"] != role:
                        raise AssertionError("B01 original exec declaration differs from real child (not a product RED)")

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
        teardown_end = self.teardown_end or (time.monotonic() + TEARDOWN_SECONDS)
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


class ActualRoundCallerTests(unittest.TestCase):
    def fixture(self, case, rounds=1):
        source = source_repository()
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-actual-cli-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name) / "exclusive-case"
        fixture = ActualCliFixture(directory, source, case, rounds)
        self.addCleanup(fixture.close)
        return fixture.execute()

    def invalid_denominator(self, fixture, number=1):
        matrix = matrix_module(fixture.repository)
        with self.assertRaises(matrix.EvidenceError) as rejected:
            matrix.validate_round(fixture.artifacts / f"round-{number}",
                                  matrix.SCENARIO_BY_NAME["equal-step"], 1, SOURCE_HEAD, WORKFLOW_HEAD)
        summary = matrix.aggregate_runs([{"exit_code": 1, "rounds": [
            {"result": "invalid", "reason": str(rejected.exception)}]}])
        self.assertEqual(summary["requested"]["rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0)
        return summary

    def baseline_failure_prerequisites(self, fixture):
        directory = fixture.artifacts / "round-1"
        self.assertEqual(fixture.cli_status, 1)
        self.assertIn("ROUND 1: FAIL reason_code=baseline_status_not_available stage=baseline", fixture.stderr)
        self.assertIn("baseline captured side=a", fixture.stderr)
        a = json.loads((directory / "node-a.baseline.readiness.json").read_text())
        b = json.loads((directory / "node-b.baseline.readiness.json").read_text())
        self.assertEqual(a["result"], "ready")
        self.assertEqual(b["result"], "schema_invalid")
        self.assertEqual(b["reason_code"], "status_schema_invalid")
        for value in (a, b):
            self.assertTrue(value["process_alive"])
            self.assertTrue(value["token_present"])
            self.assertEqual(value["attempts"], 1)
        self.assertFalse((directory / "business-validation.start-gate").exists())
        self.assertFalse((directory / "node-a.fixture-business.json").exists())
        self.assertFalse((directory / "node-b.fixture-business.json").exists())
        self.assertFalse(any(row["tool"] == "original_collector_enter" and row["round"] == 1
                             for row in fixture.events))
        self.invalid_denominator(fixture)

    def assert_final_reason(self, directory, expected, marker):
        path = directory / "round-finalization.json"
        self.assertTrue(path.is_file(), marker + ": actual caller must publish this round before losing its context")
        value = json.loads(path.read_text())
        self.assertEqual(value["terminal_reason_code"], expected,
                         marker + ": preserve the actual first local caller cause")
        self.assertEqual(value["original_exit_code"], 1)
        self.assertEqual(value["round_result"], "invalid")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        cleanup = json.loads((directory / "cleanup.json").read_text())
        self.assertTrue(cleanup["all_reaped"])
        self.assertFalse(cleanup["forced_termination"])
        self.assertEqual({row["role"] for row in cleanup["owned_processes"]}, ROLES)
        self.assertTrue(all(row["wait_completed"] and row["wait_status"] == 0
                            for row in cleanup["owned_processes"]))
        return value

    def normal_prerequisites(self, fixture, number):
        directory = fixture.artifacts / f"round-{number}"
        self.assertIn(f"ROUND {number}: PASS both_direct", fixture.stdout)
        self.assertTrue((directory / "business-validation.start-gate").is_file())
        for side in ("a", "b"):
            business = json.loads((directory / ("node-" + side + ".fixture-business.json")).read_text())
            ready = json.loads((directory / ("node-" + side + ".fixture-ready.json")).read_text())
            self.assertEqual(business["pid"], ready["pid"])
            calls = [row for row in fixture.events if row["tool"] == "curl" and row["round"] == number
                     and row["side"] == side and row["output"] is not None]
            self.assertEqual(sum(".baseline.status.json" in row["output"] for row in calls), 1)
            self.assertEqual(sum(".barrier.status.json" in row["output"] for row in calls), 1)
            self.assertEqual(sum(re.search(r"node-" + side + r"\.status\.json(?:\.capture)?$", row["output"]) is not None
                                 for row in calls), 1)
        collector = [row for row in fixture.events if row["tool"] == "original_collector_enter"
                     and row["round"] == number]
        self.assertEqual(len(collector), 1)
        self.assertEqual(collector[0]["original_script_sha256"],
                         fixture.original_sources["scripts/nat-sim/collect_evidence.py"])
        canonical = directory / "nat-evidence.json"
        evidence = json.loads(canonical.read_text())
        # The old normal tail's EXIT cleanup can overwrite the canonical
        # result after CLI PASS. The common publisher itself preserves the
        # earlier real collector output. This is a historical prerequisite,
        # never acceptance of that overwritten finalization.
        if evidence.get("result") != "pass":
            evidence = json.loads((directory / ".collector-nat-evidence.json").read_text())
        self.assertEqual(evidence["schema_version"], 2)
        self.assertTrue(evidence["executed"])
        self.assertEqual(evidence["result"], "pass", evidence.get("decision"))
        for side in ("a", "b"):
            self.assertTrue(evidence["invariants"][side]["process_incarnation_stable"])
            self.assertTrue(evidence["invariants"][side]["first_business_received"])
        cleanup = bounded_http_contract_json(directory / "cleanup.json")
        business_owners = assert_http_owner_union(
            self, fixture, directory, cleanup, ROLES, (1,), "B01_NORMAL_HTTP_OWNER_CONTRACT")
        for row in business_owners:
            ready = bounded_http_contract_json(directory / (row["role"] + ".fixture-ready.json"))
            self.assertEqual(row["pid"], ready["pid"])
            self.assertIs(row["wait_completed"], True)
            self.assertEqual(row["wait_status"], 0)
            self.assertIs(row["forced_termination"], False)
        completed = bounded_http_contract_json(directory / "round-finalization.json")
        self.assertEqual(completed["terminal_reason_code"], "completed")
        self.assertEqual(completed["original_exit_code"], 0)
        self.assertEqual(completed["round_result"], "completed")
        return evidence

    def test_actual_baseline_continue_preserves_first_cause_before_exit(self):
        fixture = self.fixture("baseline-failure")
        self.baseline_failure_prerequisites(fixture)
        self.assert_final_reason(fixture.artifacts / "round-1", "baseline_status_not_available",
                                 "B01_ACTUAL_BASELINE_FINALIZATION")

    def test_actual_startup_set_e_exit_preserves_original_cause(self):
        fixture = self.fixture("startup-token-missing")
        directory = fixture.artifacts / "round-1"
        self.assertEqual(fixture.cli_status, 1)
        self.assertIn("FAIL reason_code=daemon_readiness_timeout side=a", fixture.stderr)
        readiness = json.loads((directory / "node-a.readiness.json").read_text())
        self.assertEqual(readiness["result"], "timeout")
        self.assertTrue(readiness["process_alive"])
        self.assertFalse(readiness["token_present"])
        self.assertFalse((directory / "node-a.baseline.status.json").exists())
        self.assertFalse((directory / "node-b.baseline.status.json").exists())
        self.assertFalse((directory / "business-validation.start-gate").exists())
        self.assertFalse(any(row["tool"] == "original_collector_enter" for row in fixture.events))
        self.invalid_denominator(fixture)
        value = self.assert_final_reason(directory, "daemon_readiness_timeout", "B01_ACTUAL_STARTUP_FINALIZATION")
        self.assertEqual(value["shell_exit_status"], 1)
        self.assertEqual(value["shell_exit_status_source"], "exit_trap")

    def test_actual_normal_tail_preserves_completed_receipt_and_collector(self):
        fixture = self.fixture("complete-direct")
        self.assertEqual(fixture.cli_status, 0)
        historical = self.normal_prerequisites(fixture, 1)
        self.assertIn("RESULT: PASS", fixture.stdout)
        path = fixture.artifacts / "round-1/round-finalization.json"
        marker = "B01_ACTUAL_NORMAL_FINALIZATION"
        self.assertTrue(path.is_file(), marker + ": normal caller must publish finalization")
        value = json.loads(path.read_text())
        self.assertEqual(value["terminal_reason_code"], "completed",
                         marker + ": original normal success must not acquire an EXIT-cleanup failure")
        self.assertEqual(value["original_exit_code"], 0, marker)
        self.assertEqual(value["round_result"], "completed", marker)
        canonical = json.loads((fixture.artifacts / "round-1/nat-evidence.json").read_text())
        self.assertEqual(canonical, historical,
                         marker + ": canonical result must preserve the same completed original collector evidence")

    def test_actual_second_round_still_passes_after_first_round_failed(self):
        fixture = self.fixture("first-failed-second-pass", rounds=2)
        self.baseline_failure_prerequisites(fixture)
        self.normal_prerequisites(fixture, 2)
        self.assertIn("RESULT: FAIL", fixture.stdout)
        # This GREEN control proves actual continuation/aggregate behavior;
        # it intentionally does not claim first-round finalization succeeded.
        self.assertEqual(fixture.cli_status, 1)


if __name__ == "__main__":
    unittest.main()
