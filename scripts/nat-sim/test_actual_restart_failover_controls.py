#!/usr/bin/env python3
"""NEW external DRAFT: original relay-only restart/failover failure controls.

Author has not imported, installed, or executed this test or product. Only
offline external inputs are new. First actual colors are expected PASS;
bare-wait deadline/signal contracts and real network recovery are not covered.
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

from fixture_http_owner_assertions import assert_http_owner_union
from test_actual_round_callers import ActualCliFixture, LOG_CAP, SHELL, SOURCE_HEAD, WORKFLOW_HEAD, matrix_module, source_repository

PREPARATION_SECONDS = 4
CLI_SECONDS = 24
TEARDOWN_SECONDS = 2
ROUND_SECONDS = 30
OVERLAY_SECONDS = 12
WORK_SECONDS = 15
RESOURCE_GRACE_MS = 1000
TOOL = Path(__file__).resolve().parent / "fixture_restart_failover_control_tools.py"
RESTART_MARKER = "B01_ACTUAL_RELAY_RESTART_POSITIVE_CONTROL"
FAILOVER_MARKER = "B01_ACTUAL_RELAY_FAILOVER_POSITIVE_CONTROL"
PREFIX = "B01_RESTART_FAILOVER_FIXTURE_PRECONDITION"
BASE_ROLES = {"nat", "control", "node-a", "node-b", "relay-1"}


def require(condition, reason):
    if not condition:
        raise RuntimeError(PREFIX + ": " + reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bytes_regular(path, cap=128 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, "bounded regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            payload = stream.read(cap + 1)
        after = os.fstat(fd)
        require(len(payload) == before.st_size and len(payload) <= cap, "regular size/cap")
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "read changed")
        return payload
    finally:
        os.close(fd)


def read_json(path):
    value = json.loads(bytes_regular(path))
    require(isinstance(value, dict), "JSON object")
    return value


def gone(pid):
    require(type(pid) is int and pid > 0, "positive PID")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def parent_trace(fixture):
    pattern = rf"^\++ B01_CLI pid={fixture.process.pid} sub=([0-9]+) line=([0-9]+): (.*)$"
    return [{"index": i, "sub": int(sub), "source_line": int(line), "command": command}
            for i, (sub, line, command) in enumerate(re.findall(pattern, fixture.stderr, re.MULTILINE))]


def unique(rows, predicate, description):
    matches = [row for row in rows if predicate(row)]
    require(len(matches) == 1, description + ": expected exactly one")
    return matches[0]


def exact_parent(rows, command):
    return unique(rows, lambda row: row["sub"] == 0 and row["command"] == command, command)


def original_integer(rows, source_line, name):
    row = unique(rows, lambda row: row["sub"] == 0 and row["source_line"] == source_line
                 and re.fullmatch(name + r"=[0-9]+", row["command"]) is not None,
                 "original " + name)
    return int(row["command"].split("=")[1]), row


def source_operation_lines(fixture, rows):
    relative = "scripts/nat-sim/nat-sim-smoke.sh"
    payload = bytes_regular(fixture.repository / relative, 256 * 1024)
    require(hashlib.sha256(payload).hexdigest() == fixture.original_sources[relative],
            "operation locator matches captured original main SHA")
    lines = payload.decode().splitlines()
    headers = [i for i, line in enumerate(lines)
               if re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*\(\) \{", line)]
    def locate(statement, function=None):
        indexes = range(len(lines))
        if function is not None:
            starts = [i for i in headers if lines[i] == function + "() {"]
            require(len(starts) == 1, "unique original source function " + function)
            start = starts[0]
            end = min([i for i in headers if i > start] + [len(lines)])
            indexes = range(start + 1, end)
        found = [i + 1 for i in indexes if lines[i].strip() == statement]
        require(len(found) == 1, "unique captured source statement " + statement)
        return found[0]
    function = "wait_for_relay_confirmation_barrier"
    branches = {
        "fixed": (locate('stage_end_ms=$(_round_project_deadline_ms "$deadline") || return 1', function),
                  locate('work_end_ms=$(_round_project_deadline_ms "$WORK_DEADLINE") || return 1', function)),
        "legacy": (locate("stage_end_ms=$((now + remaining * 1000))", function),
                   locate("work_end_ms=$((now + remaining * 1000))", function)),
    }
    assignments = {branch: [[row for row in rows if row["sub"] == 0 and row["source_line"] == line
                             and row["command"].startswith(name + "=")]
                            for line, name in zip(locations, ("stage_end_ms", "work_end_ms"))]
                   for branch, locations in branches.items()}
    active = [branch for branch, pairs in assignments.items() if all(len(pair) == 1 for pair in pairs)]
    require(len(active) == 1 and all(not pair for branch, pairs in assignments.items()
                                   if branch != active[0] for pair in pairs),
            "one complete actual branch; no mixed, duplicate or inactive assignments")
    stage_line, work_line = branches[active[0]]
    return {
        "barrier_stage": stage_line, "barrier_work": work_line,
        "barrier_round": locate("round_end_ms=$_ROUND_CAPTURE_END_MS", function),
        "overlay": locate('OVERLAY_DEADLINE=$(stage_deadline "$OVERLAY_TIMEOUT_S")'),
        "work": locate("WORK_DEADLINE=$((ROUND_DEADLINE - FINALIZE_BUDGET_S))"),
        "round": locate("ROUND_DEADLINE=$((SECONDS + ROUND_TIMEOUT_S))"),
        "sample_a": locate("a_pid=$!", "sample_relay_status_pair"),
        "sample_b": locate("b_pid=$!", "sample_relay_status_pair"),
    }


class RestartFailoverFixture(ActualCliFixture):
    """Non-TestCase composition: old prepare/layout/source fence remains real."""

    def __init__(self, root, source, case):
        require(case in {"restart-no-recovery", "failover-no-replacement"}, "case")
        self.roles = BASE_ROLES | ({"relay-1-restart-1"} if case == "restart-no-recovery" else {"relay-2"})
        super().__init__(root, source, case, 1)
        try:
            require(not os.path.lexists(self.artifacts), "ART must be created by original main309")
            required_sources = {
                "scripts/diagnostics-auth.sh",
                "scripts/nat-sim/test_actual_restart_failover_controls.py",
                "scripts/nat-sim/fixture_restart_failover_control_tools.py",
                "scripts/nat-sim/test_actual_round_callers.py",
                "scripts/nat-sim/fixture_external_tools.py",
                "scripts/nat-sim/fixture_http_owner_assertions.py",
                "scripts/nat-sim/nat-sim-smoke.sh",
                "scripts/nat-sim/round_cleanup.sh",
                "scripts/nat-sim/round_finalization.py",
                "scripts/nat-sim/launch_identity.py",
                "scripts/nat-sim/collect_evidence.py",
                "scripts/nat-sim/baseline_gate.sh",
                "scripts/nat-sim/daemon_readiness.py",
                "scripts/nat-sim/reserve_port_block.py",
                "scripts/nat-sim/run-hard-hard-matrix.py"}
            require(required_sources <= set(self.original_sources), "dynamic required original source inputs")
            payload = bytes_regular(TOOL, 128 * 1024)
            require(hashlib.sha256(payload).hexdigest()
                    == self.original_sources["scripts/nat-sim/fixture_restart_failover_control_tools.py"],
                    "NEW tool payload matches dynamically captured source SHA")
            driver = self.root / "fixture-external-tools.py"
            with driver.open("wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
            settings = read_json(self.root / "fixture-config.json")
            settings.update(external_tools_sha256=digest(driver), cli_seconds=CLI_SECONDS)
            (self.root / "fixture-config.json").write_text(json.dumps(settings, sort_keys=True) + "\n")
            (self.root / "fixture-config.json").chmod(0o600)
            self.environment.update(MODE="relay-only", RELAY_COUNT="1" if case == "restart-no-recovery" else "2",
                                    RELAY_KILL_RESTART="1" if case == "restart-no-recovery" else "0",
                                    RELAY_FAILOVER="0" if case == "restart-no-recovery" else "1",
                                    ROUND_TIMEOUT_S=str(ROUND_SECONDS), OVERLAY_TIMEOUT_S=str(OVERLAY_SECONDS),
                                    DIRECT_TIMEOUT_S="2")
            require("OVERLAY_BURST" not in self.environment, "preserve original default burst256")
            for name in ("python3", "cargo", "go", "curl"):
                expected = "#!/bin/sh\nexec " + shlex.join([sys.executable, "-S", str(driver), str(self.root), name]) + ' "$@"\n'
                require((self.root / "fake-path" / name).read_text() == expected, "single shell exec launcher")
            require(not os.path.lexists(self.artifacts), "new fixture setup must not precreate ART")
        except BaseException:
            self.close()
            raise

    def execute(self):
        self.protocol_end = time.monotonic() + CLI_SECONDS
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
                raise RuntimeError(PREFIX + ": actual CLI24 expired; not target RED")
        self.stdout, self.stderr = self.read_log(self.stdout_path), self.read_log(self.stderr_path)
        require("B01_FIXTURE_INFRA_FAILURE:" not in self.stdout + self.stderr, "external input rejected")
        self.events = self.read_events()
        require(not any(row["tool"] == "child_fixture_deadline" for row in self.events), "child lifetime expired")
        for relative, expected in self.original_sources.items():
            require(digest(self.repository / relative) == expected and digest(self.source / relative) == expected,
                    "source moved after actual CLI")
        self.prove_children_closed()
        self.prove_ports_released()
        require(self.sentinel.poll() is None, "unrelated sentinel affected by CLI")
        record = {"fixture_only": True, "case": self.case, "rounds": 1, "roles": sorted(self.roles),
                  "cli_exit_status": self.cli_status, "cli_pid": self.process.pid,
                  "supervisor_rescue": self.rescued, "sentinel_pid": self.sentinel.pid,
                  "sentinel_wait": "pending_fixture_teardown", "original_sources": self.original_sources,
                  "stdout_sha256": digest(self.stdout_path), "stderr_xtrace_sha256": digest(self.stderr_path),
                  "external_events_sha256": digest(self.root / "external-events.jsonl"),
                  "external_tools_sha256": digest(self.root / "fixture-external-tools.py"),
                  "protocol_seconds": CLI_SECONDS, "teardown_seconds": TEARDOWN_SECONDS,
                  "round_timeout_seconds": ROUND_SECONDS, "work_seconds": WORK_SECONDS,
                  "overlay_timeout_seconds": OVERLAY_SECONDS, "resource_grace_cap_ms": RESOURCE_GRACE_MS}
        with (self.root / "actual-cli-fixture-receipt.json").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(record, stream, sort_keys=True)
            stream.write("\n")
        print("B01_ACTUAL_CLI_FIXTURE=" + str(self.root), flush=True)
        return self

    def prove_children_closed(self):
        directory = self.artifacts / "round-1"
        rows = parent_trace(self)
        pids = set()
        for role in sorted(self.roles):
            ready = read_json(directory / (role + ".fixture-ready.json"))
            stopped = read_json(directory / (role + ".fixture-stopped.json"))
            require(ready["pid"] == stopped["pid"] and ready["role"] == stopped["role"] == role
                    and stopped["signal"] == signal.SIGTERM and stopped["exit_code"] == 0,
                    "true native cooperative TERM input " + role)
            pid = ready["pid"]
            require(pid not in pids and gone(pid), "producer PID duplicate/live")
            pids.add(pid)
            wait = exact_parent(rows, "wait " + str(pid))
            ledger = exact_parent(rows, "round_record_wait " + str(pid) + " 0")
            require(wait["index"] < ledger["index"], "producer original wait->ledger")
            if role != "nat":
                declaration = read_json(directory / "launches" / (role + ".json"))
                require(declaration["pid"] == pid and declaration["role"] == role
                        and declaration["state"] == "exec_requested", "producer source launch PID")

    def close(self):
        # Teardown may consume at most2 from actual close entry and may never
        # extend the already fixed protocol+2 boundary.
        self.teardown_end = min(self.teardown_end or float("inf"), time.monotonic() + TEARDOWN_SECONDS)
        super().close()


class ActualRestartFailoverControlTests(unittest.TestCase):
    def _case(self, case, marker):
        start = time.monotonic()
        location = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if location:
            root = Path(location).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-restart-failover-")
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name).resolve() / "exclusive-case"
        fixture = None
        try:
            fixture = RestartFailoverFixture(root, source_repository(), case)
            self.addCleanup(fixture.close)
            require(time.monotonic() < start + PREPARATION_SECONDS, "combined original prep4 and tool setup")
            require((LOG_CAP, SHELL) == (2 * 1024 * 1024, "/bin/bash"), "old log/shell caps")
            fixture.execute()
            evidence = self._preconditions(fixture)
            fixture.close()
            sentinel = read_json(fixture.root / "sentinel-cleanup.json")
            require(sentinel["wait_completed"] is True and sentinel["wait_status"] == 0, "unrelated native sentinel0")
            require(not fixture.rescued, "supervisor rescue")
        except AssertionError as error:
            raise RuntimeError(PREFIX + ": inherited fixture/contract prerequisite: " + str(error)) from error
        final, cleanup, rows, action, publish = evidence
        cause = ("relay_kill_restart_recovery_failed" if case == "restart-no-recovery"
                 else "relay_failover_no_replacement_business")
        # All infrastructure/native-input/matrix preconditions have closed.
        self.assertEqual(final["terminal_reason_code"], cause, marker)
        self.assertEqual(final["original_exit_code"], 1, marker)
        self.assertEqual(read_json(fixture.artifacts / "round-1" / "nat-evidence.json")["decision"]["reason_code"],
                         "harness:" + cause, marker)
        self.assertEqual(final["round_result"], "invalid", marker)
        self.assertEqual(fixture.cli_status, 1, marker)
        fails = [row for row in rows if row["sub"] == 0 and row["command"].startswith("round_fail ")]
        self.assertTrue(fails, marker)
        self.assertEqual(fails[0]["command"], "round_fail " + cause + " 1", marker)
        self.assertEqual(sum(row["command"] == "round_fail " + cause + " 1" for row in fails), 1, marker)
        self.assertEqual(len(publish), 1, marker)
        arguments = shlex.split(publish[0]["command"])
        self.assertEqual(arguments[arguments.index("--reason-code") + 1], cause, marker)
        self.assertEqual(arguments[arguments.index("--exit-code") + 1], "1", marker)
        self.assertEqual(len(cleanup["owned_processes"]), 8, marker)
        self.assertEqual(cleanup["wait_completed_count"], 8, marker)
        self.assertTrue(cleanup["all_reaped"], marker)
        self.assertEqual(cleanup["pending_process_count"], 0, marker)
        self.assertEqual(cleanup["worker_unknown_count"], 0, marker)
        self.assertFalse(cleanup["forced_termination"], marker)
        self.assertEqual(evidence[3]["old_role"], "relay-1", marker)

    def _preconditions(self, fixture):
        directory = fixture.artifacts / "round-1"
        rows = parent_trace(fixture)
        parent = [row for row in rows if row["sub"] == 0]
        require(fixture.cli_status == 1 and not fixture.rescued, "actual CLI1 closed, not timeout/other")
        require("RESULT: PASS" not in fixture.stdout, "final round success claimed")
        require("BLOCK_DIRECT=1" in (directory / "nat-sim.out").read_text().splitlines(), "real NAT block banner")
        nat_calls = [row for row in rows if row["command"].startswith("python3 ")
                     and "/nat_sim.py " in row["command"]]
        require(len(nat_calls) >= 1 and all("--block-direct" in row["command"] for row in nat_calls), "original NAT --block-direct")
        canonical = read_json(directory / "nat-evidence.json")
        require(canonical["result"] == "fail" and canonical["nat_terminal"] is None,
                "original failed canonical, no forged terminal")
        require(canonical["executed"] is True and canonical["collector_observations"] == {
            "available": True, "reference": ".collector-nat-evidence.json"}, "original collector truly observed")
        preserved = read_json(directory / ".collector-nat-evidence.json")
        require(preserved["schema_version"] == 2 and preserved["result"] == "pass"
                and preserved["executed"] is True and preserved["skipped"] is False
                and preserved["source_head_sha"] == SOURCE_HEAD and preserved["workflow_sha"] == WORKFLOW_HEAD
                and preserved["topology"] == "relay-blackhole" and preserved["replica"] == 1 and preserved["round"] == 1
                and preserved["exact_test_id"] == "nat-sim-smoke.sh::relay-blackhole::replica-1::round-1"
                and preserved["decision"]["result"] == "pass" and preserved["decision"]["reason_code"] is None,
                "initial original collector PASS decision, not only command0")
        compact_encoded = (json.dumps(preserved, sort_keys=True, separators=(",", ":")) + "\n").encode()
        require(bytes_regular(directory / ".collector-nat-evidence.json") == compact_encoded,
                "publisher compact backup exactly preserves captured original object")
        require(stat.S_ISREG((directory / "nat-evidence.json").lstat().st_mode)
                and stat.S_IMODE((directory / "nat-evidence.json").stat().st_mode) == 0o600,
                "canonical regular0600")
        collector = read_json(directory / ".collector-result.json")
        for field in ("started", "command_wait_completed", "wait_completed", "owned_group_shutdown_requested_before_wait"):
            require(collector[field] is True, "collector true native completion")
        require(collector["result"] == "completed" and collector["command_wait_status"] == 0
                and collector["wait_status"] == -9 and collector["forced_termination"] is False,
                "collector command0 vs held driver-9")
        outputs = collector["outputs"]
        require(len(outputs) == 1 and outputs[0]["name"] == "nat-evidence.json"
                and outputs[0]["scope"] == "bytes_at_capture", "original collector captured output")
        # Publisher preserves the object in its compact encoder. Recover the
        # original main782 pretty encoder; do not compare different raw formats.
        original_encoded = (json.dumps(preserved, indent=2, sort_keys=True) + "\n").encode()
        require(outputs[0]["captured_sha256"] == hashlib.sha256(original_encoded).hexdigest(),
                "original collector captured SHA matches preserved object and original encoder")
        collector_event = unique(fixture.events, lambda row: row["tool"] == "original_collector_enter", "one original collector")
        require(collector_event["original_script_sha256"] == fixture.original_sources["scripts/nat-sim/collect_evidence.py"]
                and collector["entry_source"]["sha256"] == collector_event["original_script_sha256"]
                and collector["entry_source"]["path"] == str(fixture.repository / "scripts/nat-sim/collect_evidence.py")
                and collector["entry_source"]["scope"] == "bytes_at_capture"
                and collector["entry_source"]["bytes"] == 34954,
                "collector real original source")
        run = unique(rows, lambda row: row["sub"] == 1 and row["command"].startswith("python3 ")
                     and "/round_finalization.py run " in row["command"] and "--label collector " in row["command"],
                     "original collector supervised action")
        arguments = shlex.split(run["command"])
        command = arguments[arguments.index("--") + 1:]
        require(hashlib.sha256(json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
                == collector["command_argv_sha256"] == collector_event["command_argv_sha256"], "collector complete argv SHA")
        require(command[0:2] == ["python3", str(fixture.repository / "scripts/nat-sim/collect_evidence.py")]
                and command[command.index("--expected-path") + 1] == "relay"
                and command[command.index("--overlay-burst") + 1] == "256"
                and command[command.index("--topology") + 1] == "relay-blackhole", "original collector relay256 inputs")
        require("PASS relay_first_evidence" in fixture.stdout, "original initial Relay strict gate PASS")
        pass_read = unique(rows, lambda row: row["sub"] == 0 and row["command"].startswith("echo ")
                           and "ROUND 1: PASS relay_first_evidence overlay_ok=1" in row["command"],
                           "original strict initial Relay gate PASS echo")
        final = read_json(directory / "round-finalization.json")
        require(final["collector"] == collector, "original collector receipt propagated")
        for side in ("a", "b"):
            ready = read_json(directory / ("node-" + side + ".fixture-ready.json"))
            baseline = read_json(directory / ("node-" + side + ".baseline.readiness.json"))
            require(baseline["result"] == "ready" and baseline["http_status"] == 200
                    and baseline["token_present"] is True and baseline["process_alive"] is True
                    and baseline["pid"] == ready["pid"], "baseline healthy original200")
            baseline_status = read_json(directory / ("node-" + side + ".baseline.status.json"))
            final_status = read_json(directory / ("node-" + side + ".status.json"))
            require(baseline_status["connection_timeline"]["first_usable_summaries"] == []
                    and final_status["process_id"] == ready["pid"] and final_status["relay_connected"] is True,
                    "initial business after baseline same PID")
            summaries = final_status["connection_timeline"]["first_usable_summaries"]
            require(len(summaries) == 1 and summaries[0]["path"] == "relay"
                    and summaries[0]["transition_revision"] > baseline_status["revision"],
                    "first original Relay summary")
            node_log = (directory / ("node-" + side + ".log")).read_text()
            require("direct_promoted" not in node_log and "→ direct" not in node_log
                    and node_log.count("overlay_payload_verified") == 356
                    and node_log.count("overlay_burst_complete packets=256") == 1,
                    "one initial100+256 Relay input only, no postfault business")
            available = final["statuses"][side]
            require(available["result"] == "available" and available["pid"] == ready["pid"]
                    and available["sha256"] == digest(directory / ("node-" + side + ".status.json")),
                    "pre-action original final-status availability")
        barrier = read_json(directory / "relay-barrier.readiness.json")
        require(barrier["result"] == "ready" and barrier["reason_code"] is None, "original barrier ready")
        for side in ("a", "b"):
            require(barrier["http_status_" + side] == 200 and barrier["task_health_" + side] is True
                    and barrier["relay_peer_confirmed_" + side] is True, "original barrier health")
        cleanup = read_json(directory / "cleanup.json")
        business = assert_http_owner_union(self, fixture, directory, cleanup, fixture.roles, (1,), PREFIX)
        require(len(business) == 6 and len(cleanup["owned_processes"]) == 8, "eight exact original registered owners")
        require(all(row["wait_completed"] is True and row["wait_status"] == 0 for row in cleanup["owned_processes"]),
                "eight actual native wait0, no127")
        require(cleanup["duration_ms"] <= RESOURCE_GRACE_MS, "fixed original resource1000")
        workers = cleanup["owned_workers"]
        require(len(workers) == 5 and {row["stage"] for row in workers} == {
            "status-a", "status-b", "collector", "http-barrier-1-a", "http-barrier-1-b"},
            "five separate workers")
        worker_pids = set()
        owner_pids = {row["pid"] for row in cleanup["owned_processes"]}
        for worker in workers:
            require(type(worker["pid"]) is int and worker["pid"] > 0 and worker["pid"] not in owner_pids
                    and worker["pid"] not in worker_pids and gone(worker["pid"]), "distinct native worker driver gone")
            worker_pids.add(worker["pid"])
            require(worker["command_wait_completed"] is True and worker["command_wait_status"] == 0
                    and worker["wait_completed"] is True and worker["wait_status"] == -9
                    and worker["forced_termination"] is False, "separate command0/driver-9 workers")
        publish = [row for row in rows if row["sub"] == 1 and row["command"].startswith("python3 ")
                   and "/round_finalization.py publish " in row["command"]]
        require(len(publish) == 1, "one native publisher body")
        for row in cleanup["owned_processes"]:
            wait = exact_parent(rows, "wait " + str(row["pid"]))
            ledger = exact_parent(rows, "round_record_wait " + str(row["pid"]) + " 0")
            require(wait["index"] < ledger["index"] < publish[0]["index"], "native owner wait/ledger before publish")
        action = self._action_and_samples(fixture, rows, run, pass_read, cleanup, publish[0])
        identity = final["source_identity"]
        require(identity["result"] == "captured" and identity["artifact_validation_scope"] == "declaration_only",
                "source/launch declaration identity")
        require(len(identity["launch_records"]) == 5 and {row["role"] for row in identity["launch_records"]}
                == fixture.roles - {"nat"}, "old/new relay launch history retained")
        owners = {row["role"]: row["pid"] for row in cleanup["owned_processes"]}
        for row in identity["launch_records"]:
            declaration = directory / "launches" / (row["role"] + ".json")
            require(row["pid"] == owners[row["role"]] and row["sha256"] == digest(declaration),
                    "history source identity matches original owning PID")
        matrix = matrix_module(fixture.repository)
        try:
            matrix.validate_round(directory, matrix.SCENARIO_BY_NAME["equal-step"], 1, SOURCE_HEAD, WORKFLOW_HEAD)
        except matrix.EvidenceError as error:
            reason = str(error)
        else:
            raise RuntimeError(PREFIX + ": original matrix accepted failed canonical")
        require(reason.startswith("nat_evidence_rejected:harness:"), "original canonical matrix rejection")
        summary = matrix.aggregate_runs([{"exit_code": 1, "rounds": [{"result": "invalid", "reason": reason}]}])
        require(summary["requested"]["rounds"] == 1 and summary["evidence_validity"]["invalid_rounds"] == 1
                and summary["evidence_validity"]["valid_rounds"] == 0, "requested1 invalid1 valid0 denominator")
        return final, cleanup, rows, action, publish

    def _action_and_samples(self, fixture, rows, collector_run, pass_read, cleanup, publish):
        directory = fixture.artifacts / "round-1"
        old = read_json(directory / "relay-1.fixture-ready.json")
        old_stop = read_json(directory / "relay-1.fixture-stopped.json")
        primary = old["endpoint"]
        require(primary.startswith("tcp://127.0.0.1:"), "primary real original catalog port")
        old_pid = old["pid"]
        kill = exact_parent(rows, "kill " + str(old_pid))
        wait = exact_parent(rows, "wait " + str(old_pid))
        ledger = exact_parent(rows, "round_record_wait " + str(old_pid) + " 0")
        require(collector_run["index"] < pass_read["index"] < kill["index"] < wait["index"] < ledger["index"],
                "initial original collector PASS before actual fault TERM/wait")
        require(not any(row["sub"] == 0 and row["command"] == "kill -TERM " + str(old_pid) for row in rows),
                "already waited old relay must not be re-signalled")
        operations = source_operation_lines(fixture, rows)
        stage_end, stage_row = original_integer(rows, operations["barrier_stage"], "stage_end_ms")
        work_end, work_row = original_integer(rows, operations["barrier_work"], "work_end_ms")
        round_end, round_row = original_integer(rows, operations["barrier_round"], "round_end_ms")
        overlay, _ = original_integer(rows, operations["overlay"], "OVERLAY_DEADLINE")
        work, _ = original_integer(rows, operations["work"], "WORK_DEADLINE")
        round_deadline, _ = original_integer(rows, operations["round"], "ROUND_DEADLINE")
        require(stage_row["index"] < work_row["index"] < round_row["index"],
                "actual barrier source coordinate order")
        require(work == round_deadline - 15 and overlay <= work and stage_end <= work_end <= round_end,
                "original absolute Overlay/WORK/ROUND boundaries")
        # The active original stage assignment is source-bound, distinct from
        # receipt.input_deadline (curl5 clamped request end).
        stop_ms = old_stop["monotonic_ns"] // 1_000_000
        minimum = 4000 if fixture.case == "restart-no-recovery" else 2000
        require(stage_end - stop_ms >= minimum, "insufficient original conservative action margin")
        for side in ("a", "b"):
            request = read_json(directory / (".http-barrier-1-" + side + "-result.json"))
            require(request["input_deadline_monotonic_ms"] <= stage_end
                    and request["work_deadline_monotonic_ms"] == work_end
                    and request["round_deadline_monotonic_ms"] == round_end, "HTTP input is a distinct clamp")
        if fixture.case == "restart-no-recovery":
            replacement = read_json(directory / "relay-1-restart-1.fixture-ready.json")
            require(replacement["endpoint"] == primary and replacement["metrics_bind"] == old["metrics_bind"]
                    and replacement["pid"] != old_pid, "same original bind/metrics distinct replacement PID")
            require(replacement["monotonic_ns"] // 1_000_000 <= stage_end - 1000,
                    "replacement truly ready within original overlay")
            registered = exact_parent(rows, "round_register_process relay-1-restart-1 " + str(replacement["pid"]))
            assignment = exact_parent(rows, "RELAY_PIDS[0]=" + str(replacement["pid"]))
            require(ledger["index"] < assignment["index"] < registered["index"] < publish["index"],
                    "old native join before new $!/register/publish")
        else:
            backup = read_json(directory / "relay-2.fixture-ready.json")
            require(backup["endpoint"] != primary and backup["pid"] != old_pid, "backup genuine distinct candidate")
            require(exact_parent(rows, "ACTIVE_ENDPOINT=" + primary)["index"] < kill["index"],
                    "original primary selection before fault")
            require(exact_parent(rows, "killed=1")["index"] > ledger["index"], "original owned active relay found")
            require(exact_parent(rows, "kill -TERM " + str(backup["pid"]))["index"] > ledger["index"],
                    "backup remained to original final cleanup")
        # Sampling has a different, unregistered two-process native wait ledger.
        sampling = [event for event in fixture.events if event["tool"] == "curl" and event.get("sampling") is True]
        require(sampling and len(sampling) % 2 == 0, "actual sample pairs required")
        sample_bytes = bytes_regular(directory / "status-http-samples.log", 256 * 1024)
        sample_rows = [json.loads(row) for row in sample_bytes.splitlines()]
        require(len(sample_rows) == len(sampling), "actual original sampler log denominator")
        all_owner_pids = {row["pid"] for row in cleanup["owned_processes"]}
        sample_proof = []
        for side, line in (("a", operations["sample_a"]), ("b", operations["sample_b"])):
            assignments = [row for row in rows if row["sub"] == 0 and row["source_line"] == line
                           and re.fullmatch(side + r"_pid=[1-9][0-9]*", row["command"])]
            events = [event for event in sampling if event["side"] == side]
            records = [record for record in sample_rows if record["side"] == side]
            require(len(assignments) == len(events) == len(records) >= 1, "actual sampling count per side")
            for assignment in assignments:
                pid = int(assignment["command"].split("=")[1])
                require(pid not in all_owner_pids and gone(pid), "sample PID distinct/unregistered/gone")
                native_wait = exact_parent(rows, "wait " + str(pid))
                native_ledger = exact_parent(rows, "round_record_wait " + str(pid) + " 0")
                require(assignment["index"] < native_wait["index"] < native_ledger["index"] < collector_run["index"],
                        "native sample wait and no-op original ledger before collector")
                sample_proof.append({"side": side, "pid": pid, "wait": native_wait, "ledger": native_ledger})
            for event in events:
                node = read_json(directory / ("node-" + side + ".fixture-ready.json"))
                require(gone(event["curl_pid"]) and event["curl_pid"] not in all_owner_pids
                        and event["target_pid"] == node["pid"] and event["port"] == node["diagnostics_port"]
                        and event["endpoint"] == "/status" and event["output"] == os.devnull,
                        "native sample curl/target port and PID identity")
                require(hashlib.sha256(json.dumps(event["argv"], separators=(",", ":")).encode()).hexdigest()
                        == event["argv_sha256"], "sample complete original curl argv SHA")
                matched = [record for record in records if record["server_request_id"] == event["request_id"]]
                require(len(matched) == 1, "native original sample request-id header readback")
                record = matched[0]
                require(record["curl_exit_code"] == 0 and record["http_status"] == "200"
                        and record["target_process_pid"] == event["target_pid"]
                        and isinstance(record["target_process_start"], str) and record["target_process_start"],
                        "native ps and true sampler200")
                require(record["time_connect_s"] == 0.001 and record["time_starttransfer_s"] == 0.002
                        and record["time_total_s"] == 0.003 and record["response_bytes"] == 0,
                        "all five controlled write-out fields parsed by original sampler")
                require(event["auth_config_sha256"] == hashlib.sha256(
                    b'header = "Authorization: Bearer fixture-diagnostics-token"\n').hexdigest(),
                    "native config stdin auth observed")
        require(len({row["pid"] for row in sample_proof}) == len(sample_proof), "sample PID uniqueness")
        for side in ("a", "b"):
            require(not (directory / (".status-" + side + "-code.json")).exists()
                    and not (directory / (".status-" + side + "-headers")).exists(), "original sampler scratch/rm")
        # Persist observations, never product cause/verdict/cleanup/collector.
        observations = {"fixture_only": True, "product_result_claimed": False,
                        "observation_scope": "original_xtrace_and_external_native_inputs_after_cli",
                        "old_role": "relay-1", "primary_endpoint": primary, "old_pid": old_pid,
                        "action_kill": kill, "old_native_wait": wait, "old_original_ledger": ledger,
                        "original_overlay_stage_end_ms": stage_end, "stage_end_source": stage_row,
                        "original_work_end_ms": work_end, "work_end_source": work_row,
                        "original_round_end_ms": round_end, "round_end_source": round_row,
                        "original_overlay_deadline_SECONDS": overlay, "original_work_deadline_SECONDS": work,
                        "native_old_TERM_observed_ms": stop_ms, "minimum_conservative_margin_ms": minimum,
                        "sample_pair_count_actual": len(sampling) // 2, "sample_native_waits": sample_proof,
                        "sample_request_records": sample_rows}
        with (fixture.root / "restart-failover-observations.json").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(observations, stream, sort_keys=True)
            stream.write("\n")
        return observations

    def test_actual_relay_restart_without_recovery_keeps_original_cause_and_owner_history(self):
        self._case("restart-no-recovery", RESTART_MARKER)

    def test_actual_relay_failover_without_replacement_business_keeps_original_cause_and_owner_history(self):
        self._case("failover-no-replacement", FAILOVER_MARKER)


if __name__ == "__main__":
    unittest.main()
