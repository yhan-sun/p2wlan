#!/usr/bin/env python3
"""Offline behavior contracts for round-owned failure finalization.

Phase one calls the existing cleanup API, not an absent finalizer API. The
shell owns actual fake children. Status callbacks are fixture responses, not
native daemon authentication, NAT, TUN, or business-delivery evidence.
"""

from __future__ import annotations

import importlib.util
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
sys.path.insert(0, str(HERE))
RUNNER_SPEC = importlib.util.spec_from_file_location(
    "round_cleanup_matrix", HERE / "run-hard-hard-matrix.py"
)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = MATRIX
RUNNER_SPEC.loader.exec_module(MATRIX)


FAKE_CHILD = r"""
import json
import os
import signal
import sys
from pathlib import Path

root, role = Path(sys.argv[1]), sys.argv[2]
finished = False
def finish(signum, _frame):
    global finished
    if finished:
        return
    finished = True
    value = {"pid": os.getpid(), "role": role, "signal": signum, "exit_code": 0}
    path = root / (role + ".stopped.json")
    with path.open("x") as output:
        json.dump(value, output)
    path.chmod(0o600)
    if role == "nat":
        with (root / "nat-trace.jsonl").open("a") as trace:
            trace.write(json.dumps({"event": "fixture_nat_shutdown", "pid": os.getpid()}) + "\n")
    raise SystemExit(0)
signal.signal(signal.SIGTERM, finish)
signal.signal(signal.SIGINT, finish)
os.write(1, ("CHILD_READY:" + role + ":" + str(os.getpid()) + "\n").encode())
while True:
    signal.pause()
"""


# The process/cleanup implementation is sourced, not duplicated here. The
# baseline capture and status callbacks are controlled fixture boundaries.
CONTROLLER = r"""
set -euo pipefail
ROOT_DIR=$1
BASE_DIR=$2
fixture_python=$3
fixture_child=$4
PORT_LOCK_DIR=""
PIDS=()
overall=0
CLEANUP_FORCED=0
source "$ROOT_DIR/scripts/nat-sim/baseline_gate.sh"
source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"
trap cleanup EXIT
round=0

start_round() {
  round=$((round + 1))
  ROUND_DIR="$BASE_DIR/round-$round"
  ROUND_RUN_ID="fixture-run-round-$round"
  ROUND_DEADLINE=$((SECONDS + 3))
  WORK_DEADLINE=$ROUND_DEADLINE
  FINALIZE_BUDGET_S=15
  ROUND_FINISH_REASON=""
  ROUND_FINISH_EXIT_CODE=0
  ROUND_FINALIZATION_STATE=open
  CLEANUP_FORCED=0
  MODE=hard-hard
  EGRESS_CAPTURE=none
  DIAG_A_PORT=1; DIAG_B_PORT=2
  overall=0
  reset_baseline_pair
  BARRIER_RESULT=pending
  BARRIER_A_CONFIRMED=false; BARRIER_B_CONFIRMED=false
  BARRIER_A_HTTP=0; BARRIER_B_HTTP=0
  NODE_A_RUNTIME="$ROUND_DIR/node-a-runtime"
  NODE_B_RUNTIME="$ROUND_DIR/node-b-runtime"
  mkdir -p "$NODE_A_RUNTIME" "$NODE_B_RUNTIME" "$ROUND_DIR/launches"
  printf 'fixture node A log\n' >"$ROUND_DIR/node-a.log"
  printf 'fixture node B log\n' >"$ROUND_DIR/node-b.log"
  for directory in "$NODE_A_RUNTIME" "$NODE_B_RUNTIME"; do
    (umask 077; printf '%s\n' fixture-only >"$directory/p2wlan-daemon.diag-auth")
  done
  for role in node-a node-b nat watcher control relay-1; do
    "$fixture_python" -u "$fixture_child" "$ROUND_DIR" "$role" </dev/null &
    pid=$!
    PIDS+=("$pid")
    case "$role" in
      node-a) NODE_A_PID=$pid ;;
      node-b) NODE_B_PID=$pid ;;
      nat) NAT_PID=$pid ;;
      watcher) HARD_HARD_WATCHER_PID=$pid ;;
      control) SERVER_PID=$pid ;;
      relay-1) RELAY_PIDS=("$pid") ;;
    esac
  done
  printf 'ROUND_READY:%s\n' "$round"
}

capture_baseline_status() {
  local answer
  printf 'ENTER:%s\n' "$4"
  IFS= read -r answer || return 23
  [[ "$answer" == ok && -s "$3" ]] || return 23
  cp "$BASE_DIR/final-$4.input.json" "$2"
  chmod 600 "$2"
}

# Implements the current fetch_required_json callback signature. Phase one
# cleanup does not call it. Phase two must use a real bounded fetch boundary.
fetch_required_json() {
  local side output="$2"
  case "$4" in
    "$NODE_A_RUNTIME/p2wlan-daemon.diag-auth") side=a ;;
    "$NODE_B_RUNTIME/p2wlan-daemon.diag-auth") side=b ;;
    *) return 29 ;;
  esac
  printf '%s\n' "$side" >>"$ROUND_DIR/fixture-final-fetch.calls"
  [[ -s "$4" ]] || return 29
  cp "$BASE_DIR/final-$side.input.json" "$output"
  chmod 600 "$output"
  FETCH_HTTP_STATUS=200
  FETCH_REASON_CODE=""
}

start_round
while IFS= read -r command; do
  case "$command" in
    CAPTURE)
      if capture_baseline_pair a "$ROUND_DIR/node-a.baseline.status.json" \
          "$NODE_A_RUNTIME/p2wlan-daemon.diag-auth" a "$NODE_A_PID" \
          b "$ROUND_DIR/node-b.baseline.status.json" \
          "$NODE_B_RUNTIME/p2wlan-daemon.diag-auth" b "$NODE_B_PID"; then
        status=0
      else
        status=$?
        ROUND_FINISH_REASON=baseline_status_not_available
        ROUND_FINISH_EXIT_CODE=1
        overall=1
      fi
      printf 'CAPTURE:%s\n' "$status" ;;
    BARRIER_FAIL)
      BARRIER_RESULT=barrier_timeout
      if release_hard_hard_business_gate "$ROUND_DIR/business-validation.start-gate"; then
        exit 98
      else
        status=$?
      fi
      ROUND_FINISH_REASON=barrier_timeout
      ROUND_FINISH_EXIT_CODE=1
      overall=1
      printf 'BARRIER_FAIL:%s\n' "$status" ;;
    EXPIRE)
      ROUND_DEADLINE=$SECONDS
      WORK_DEADLINE=$ROUND_DEADLINE
      ROUND_FINISH_REASON=round_deadline_elapsed
      ROUND_FINISH_EXIT_CODE=1
      overall=1
      printf 'EXPIRED:%s\n' "$ROUND_DEADLINE" ;;
    FINISH)
      before=$ROUND_DEADLINE
      cleanup
      printf 'FINISHED:%s:%s:%s:%s\n' "$round" "$before" "$ROUND_DEADLINE" "${#PIDS[@]}" ;;
    NEXT) start_round ;;
    EXIT7)
      ROUND_FINISH_REASON=fixture_command_failed
      ROUND_FINISH_EXIT_CODE=7
      (exit 7) ;;
    QUIT) exit "$overall" ;;
    *) exit 97 ;;
  esac
done
"""


class OwnedCleanupProcesses:
    """Three-second protocol window plus a separate two-second teardown.

    Timeouts indicate fixture supervision failure, never the desired RED.
    Cleanup always drains/joins the controller and cooperative owned children.
    """

    roles = {"node-a", "node-b", "nat", "watcher", "control", "relay-1"}

    def __init__(self, root: Path):
        self.root = root
        self.protocol_end = time.monotonic() + 3
        self.teardown_end = self.protocol_end + 2
        self.round_number = 1
        self.owners: dict[int, dict[str, int]] = {}
        self.buffer = b""
        self.process = None
        self.closed = False
        child = root / "fixture-child.py"
        child.write_text(FAKE_CHILD, encoding="utf-8")
        for side in ("a", "b"):
            self.write_json(root / f"final-{side}.input.json", {
                "fixture_response_side": side,
                "peers": [{"node_id": "fixture-peer", "active_path": "direct"}],
            })
        # The bounded fixture's shell helpers use the same selected interpreter
        # as its children, including normal site startup; host shims add no fixture semantics.
        environment = os.environ.copy()
        environment["PATH"] = str(Path(sys.executable).parent) + os.pathsep + environment.get("PATH", "")
        try:
            self.process = subprocess.Popen(
                ["bash", "-c", CONTROLLER, "fixture", str(REPOSITORY), str(root),
                 sys.executable, str(child)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, env=environment,
            )
            self.ready_round(1)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def write_json(path: Path, value):
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")
        path.chmod(0o600)

    @property
    def round_dir(self):
        return self.root / f"round-{self.round_number}"

    def receive(self):
        while b"\n" not in self.buffer:
            remaining = self.protocol_end - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise AssertionError("fixture protocol deadline expired (not a product RED)")
            data = os.read(self.process.stdout.fileno(), 4096)
            if not data:
                raise AssertionError("fixture controller exited before its protocol response")
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.decode()

    def send(self, command):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()

    def command(self, command):
        self.send(command)
        return self.receive()

    def ready_round(self, number):
        owners = {}
        ready = False
        while set(owners) != self.roles or not ready:
            value = self.receive()
            if value.startswith("CHILD_READY:"):
                _, role, pid = value.split(":")
                if role not in self.roles or role in owners:
                    raise AssertionError("fixture ownership response was duplicated or unknown")
                owners[role] = int(pid)
            elif value == f"ROUND_READY:{number}":
                ready = True
            else:
                raise AssertionError(f"unexpected fixture startup response: {value}")
        self.owners[number] = owners

    def capture(self, second_answer="fail"):
        if self.command("CAPTURE") != "ENTER:a":
            raise AssertionError("actual baseline helper did not enter side A")
        if self.command("ok") != "ENTER:b":
            raise AssertionError("actual baseline helper did not enter side B")
        return self.command(second_answer)

    def finish(self):
        value = self.command("FINISH").split(":")
        if len(value) != 5 or value[0] != "FINISHED":
            raise AssertionError(f"unexpected cleanup response: {value}")
        return tuple(map(int, value[1:]))

    def next_round(self):
        self.send("NEXT")
        self.round_number += 1
        self.ready_round(self.round_number)

    def terminated_children(self, number=None):
        number = number or self.round_number
        directory = self.root / f"round-{number}"
        result = {}
        for role, pid in self.owners[number].items():
            path = directory / f"{role}.stopped.json"
            if not path.is_file():
                raise AssertionError(f"owned fixture child did not terminate: {role}")
            value = json.loads(path.read_text())
            if value["pid"] != pid or value["role"] != role or value["exit_code"] != 0:
                raise AssertionError("owned fixture child identity/outcome differs")
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError(f"owned fixture child remains live or unreaped: {role}")
            result[role] = value
        return result

    def close(self):
        if self.process is None or self.closed:
            return
        if self.process.poll() is None:
            try:
                self.send("QUIT")
            except (BrokenPipeError, OSError):
                pass
        try:
            self.process.communicate(timeout=max(0, self.teardown_end - time.monotonic()))
        except subprocess.TimeoutExpired:
            # Fixture rescue has its own fixed budget, does not change a
            # harness deadline, and must never count as the expected RED.
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.communicate(timeout=1)
            raise AssertionError("fixture needed supervisor rescue (not a product RED)")
        for number in self.owners:
            self.terminated_children(number)
        self.closed = True


class RoundCleanupBehaviorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(prefix="p2wlan-round-cleanup-")
        self.addCleanup(temporary.cleanup)
        fixture = OwnedCleanupProcesses(Path(temporary.name))
        self.addCleanup(fixture.close)
        return fixture

    def receipt(self, fixture, reason, exit_code=1):
        path = fixture.round_dir / "round-finalization.json"
        self.assertTrue(path.is_file(), "cleanup must save bounded finalization receipt")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        value = json.loads(path.read_text())
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["round_run_id"], f"fixture-run-round-{fixture.round_number}")
        self.assertEqual(value["terminal_reason_code"], reason)
        self.assertEqual(value["original_exit_code"], exit_code)
        self.assertEqual(value["round_result"], "invalid")
        return value

    def cleanup_receipt(self, fixture):
        path = fixture.round_dir / "cleanup.json"
        self.assertTrue(path.is_file(), "actual cleanup must save wait receipts")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        value = json.loads(path.read_text())
        self.assertTrue(value["all_reaped"])
        self.assertFalse(value["forced_termination"])
        processes = value["owned_processes"]
        self.assertEqual(len(processes), len(fixture.roles))
        self.assertEqual({item["role"]: item["pid"] for item in processes},
                         fixture.owners[fixture.round_number])
        self.assertTrue(all(item["wait_completed"] is True and item["wait_status"] == 0
                            for item in processes))
        return value

    def invalid_summary(self, round_dir, reason=None):
        scenario = MATRIX.SCENARIO_BY_NAME["equal-step"]
        with self.assertRaises(MATRIX.EvidenceError) as rejected:
            MATRIX.validate_round(round_dir, scenario, 1, "a" * 40, "a" * 40)
        if reason is not None:
            self.assertIn(reason, str(rejected.exception))
        summary = MATRIX.aggregate_runs([{
            "exit_code": 1,
            "rounds": [{"result": "invalid", "reason": str(rejected.exception)}],
        }])
        self.assertEqual(summary["requested"]["rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0)

    def test_baseline_failure_emits_final_status_nat_and_owned_wait_receipts(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        self.assertTrue((fixture.round_dir / "node-a.baseline.status.json").is_file())
        self.assertFalse((fixture.round_dir / "node-b.baseline.status.json").exists())
        self.assertFalse((fixture.round_dir / "business-validation.start-gate").exists())
        self.assertEqual(fixture.finish()[-1], 0)
        fixture.terminated_children()
        self.invalid_summary(fixture.round_dir)
        self.receipt(fixture, "baseline_status_not_available")
        self.cleanup_receipt(fixture)
        for side in ("a", "b"):
            path = fixture.round_dir / f"node-{side}.status.json"
            self.assertEqual(json.loads(path.read_text())["fixture_response_side"], side)
        self.assertEqual(sorted((fixture.round_dir / "fixture-final-fetch.calls").read_text().splitlines()),
                         ["a", "b"])
        evidence = json.loads((fixture.round_dir / "nat-evidence.json").read_text())
        self.assertEqual(evidence["result"], "fail")
        self.assertIn("baseline_status_not_available", evidence["decision"]["reason_code"])
        self.invalid_summary(fixture.round_dir, "nat_evidence_rejected")

    def test_zero_remaining_is_unknown_without_status_read_or_deadline_extension(self):
        fixture = self.fixture()
        self.assertTrue(fixture.command("EXPIRE").startswith("EXPIRED:"))
        _, before, after, pending = fixture.finish()
        self.assertEqual(before, after)
        self.assertEqual(pending, 0)
        fixture.terminated_children()
        self.assertFalse((fixture.round_dir / "fixture-final-fetch.calls").exists())
        value = self.receipt(fixture, "round_deadline_elapsed")
        self.assertEqual(value["statuses"]["a"]["reason_code"], "deadline_exhausted")
        self.assertEqual(value["statuses"]["b"]["reason_code"], "deadline_exhausted")
        self.assertFalse((fixture.round_dir / "node-a.status.json").exists())
        self.assertFalse((fixture.round_dir / "node-b.status.json").exists())

    def test_two_rounds_and_repeated_cleanup_keep_once_only_receipts(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        # Capture availability without ending before the actual second round.
        # The receipt assertions below still fail when phase one emits none.
        first = {path.name: ((path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
                            if path.is_file() else None)
                 for path in (fixture.round_dir / "round-finalization.json",
                              fixture.round_dir / "cleanup.json")}
        fixture.finish()
        for name, expected in first.items():
            path = fixture.round_dir / name
            observed = ((path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
                        if path.is_file() else None)
            self.assertEqual(observed, expected)
        fixture.next_round()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        self.receipt(fixture, "baseline_status_not_available")
        self.cleanup_receipt(fixture)
        second = {path.name: (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
                  for path in (fixture.round_dir / "round-finalization.json",
                               fixture.round_dir / "cleanup.json")}
        fixture.close()  # Actual EXIT trap must reuse this round's receipt.
        for name, expected in second.items():
            path = fixture.round_dir / name
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino), expected)
        for name, expected in first.items():
            path = fixture.root / "round-1" / name
            self.assertIsNotNone(expected, "first round must also have actual saved receipts")
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino), expected)

    def test_failed_barrier_keeps_business_closed_and_emits_failure_receipt(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture("ok"), "CAPTURE:0")
        self.assertEqual(fixture.command("BARRIER_FAIL"), "BARRIER_FAIL:1")
        self.assertFalse((fixture.round_dir / "business-validation.start-gate").exists())
        fixture.finish()
        fixture.terminated_children()
        self.receipt(fixture, "barrier_timeout")
        self.cleanup_receipt(fixture)

    def test_set_e_exit_preserves_original_code_and_emits_failure_receipt(self):
        fixture = self.fixture()
        fixture.send("EXIT7")
        fixture.close()
        self.assertEqual(fixture.process.returncode, 7)
        fixture.terminated_children()
        self.receipt(fixture, "fixture_command_failed", exit_code=7)
        self.cleanup_receipt(fixture)

    def test_legacy_cleanup_terminates_owned_children_and_preserves_failure_exit(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        self.assertEqual(fixture.finish()[-1], 0)
        fixture.terminated_children()
        self.assertEqual(fixture.finish()[-1], 0)
        fixture.next_round()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        self.assertEqual(fixture.finish()[-1], 0)
        fixture.terminated_children()
        fixture.terminated_children(1)
        fixture.close()
        self.assertEqual(fixture.process.returncode, 1)

    def test_late_direct_files_keep_explicit_harness_failure_invalid(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        # A collector-control envelope, not a claim that phase-one production
        # emitted these files. Added Direct observations cannot erase cause.
        for side in ("a", "b"):
            fixture.write_json(fixture.round_dir / f"node-{side}.status.json",
                               json.loads((fixture.root / f"final-{side}.input.json").read_text()))
            (fixture.round_dir / f"node-{side}.log").write_text("fixture log\n")
        fixture.write_json(fixture.round_dir / "nat-evidence.json", {
            "result": "fail", "executed": True,
            "decision": {"reason_code": "harness:baseline_status_not_available"},
        })
        fixture.write_json(fixture.round_dir / "cleanup.json", {
            "schema_version": 1, "all_reaped": True, "forced_termination": False,
            "duration_ms": 0, "process_count": 5,
        })
        self.invalid_summary(fixture.round_dir, "nat_evidence_rejected:harness:baseline_status_not_available")

    def test_original_baseline_success_and_cleanup_do_not_release_business(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture("ok"), "CAPTURE:0")
        self.assertTrue((fixture.round_dir / "node-a.baseline.status.json").is_file())
        self.assertTrue((fixture.round_dir / "node-b.baseline.status.json").is_file())
        self.assertFalse((fixture.round_dir / "business-validation.start-gate").exists())
        fixture.finish()
        fixture.terminated_children()
        fixture.close()
        self.assertEqual(fixture.process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
