#!/usr/bin/env python3
"""Actual offline semantic regressions, separate from the frozen 19 controls.

All children, collectors, signals and waits are real local processes. Status
and collector JSON are fixture responses, not native authentication or NAT
proof. The existing three-second protocol and two-second teardown are reused.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import unittest
from unittest.mock import patch

import test_round_cleanup as legacy
import test_round_finalization as common


COMMANDS = r'''
    REAP_NODE_A)
      _round_context
      kill -TERM "$NODE_A_PID"
      if wait "$NODE_A_PID"; then rc=0; else rc=$?; fi
      round_record_wait "$NODE_A_PID" "$rc"
      printf 'NODE_A_REAPED:%s:%s\n' "$NODE_A_PID" "$rc" ;;
    RUN_COLLECTOR_CUTOFF|RUN_COLLECTOR_EARLY)
      _round_context
      _round_fixed_windows
      candidate=$(($(_round_now) + 600))
      if (( candidate < _ROUND_CAPTURE_END_MS )); then _ROUND_CAPTURE_END_MS=$candidate; fi
      if [[ "$command" == RUN_COLLECTOR_CUTOFF ]]; then mode=cutoff; else mode=early; fi
      if round_run_collector collector "$fixture_python" "$BASE_DIR/fixture-collector.py" \
          "$ROUND_DIR" "$mode"; then rc=0; else rc=$?; fi
      printf 'COLLECTOR:%s:%s:%s\n' "$rc" "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" ;;
    EXIT7_DURING_CAPTURE)
      printf '%s\n' "$$" >"$ROUND_DIR/fixture-native-term-owner.pid"
      chmod 600 "$ROUND_DIR/fixture-native-term-owner.pid"
      ROUND_FINISH_REASON=fixture_command_failed
      ROUND_FINISH_EXIT_CODE=7
      (exit 7) ;;
'''


COLLECTOR = r'''
import json
import os
from pathlib import Path
import signal
import sys

directory, mode = Path(sys.argv[1]), sys.argv[2]
finished = False
def write(name, value):
    path = directory / name
    with path.open("x") as output:
        output.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o600)
def finish(signum, _frame):
    global finished
    if finished:
        return
    finished = True
    write("nat-evidence.json", {
        "schema_version": 1, "executed": True, "result": "pass",
        "decision": {"result": "pass", "reason_code": "fixture_collector_completed"},
        "nat_terminal": None,
    })
    write("fixture-collector-completed.json", {
        "pid": os.getpid(), "signal": signum, "exit_code": 0,
    })
    raise SystemExit(0)
signal.signal(signal.SIGTERM, finish)
write("fixture-collector-entered.json", {"pid": os.getpid(), "mode": mode})
if mode == "early":
    finish(0, None)
while True:
    signal.pause()
'''


NATIVE_TERM = r'''
  if [[ -s "$ROUND_DIR/fixture-native-term-owner.pid" ]]; then
    IFS= read -r fixture_exit_owner <"$ROUND_DIR/fixture-native-term-owner.pid"
    builtin kill -TERM "$fixture_exit_owner"
    printf '%s:%s\n' "$fixture_exit_owner" "$side" >>"$ROUND_DIR/fixture-native-term-sent.calls"
    chmod 600 "$ROUND_DIR/fixture-native-term-sent.calls"
  fi'''


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise AssertionError("fixture extension anchor changed")
    return text.replace(before, after, 1)


def controller(*, explicit_init=False):
    text = common.controller()
    text = replace_once(text, "    CAPTURE)\n", COMMANDS + "    CAPTURE)\n")
    marker = '''  printf '%s\\n' "$side" >>"$ROUND_DIR/fixture-final-fetch.calls"'''
    text = replace_once(text, marker, marker + NATIVE_TERM)
    if explicit_init:
        marker = "  for role in node-a node-b nat watcher control relay-1; do\n"
        initialization = r'''
  round_init
  (umask 077; printf '%s:%s:%s:%s:%s:%s:%s:%s:%s\n' \
    "$_ROUND_STATE" "${#PIDS[@]}" "$_ROUND_STARTED" "${#_ROUND_OWNER_PID[@]}" \
    "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" "${NODE_A_PID:-empty}" \
    "${NODE_B_PID:-empty}" "${HARD_HARD_WATCHER_PID:-empty}" \
    >"$ROUND_DIR/fixture-before-first-spawn.txt")
'''
        text = replace_once(text, marker, initialization + marker)
        text = replace_once(text, '    PIDS+=("$pid")\n',
                            '    round_register_process "$role" "$pid"\n')
    return text


class RoundFinalizationRegressions(unittest.TestCase):
    def fixture(self, **options):
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
            directory.mkdir(mode=0o700)
        else:
            temporary = legacy.tempfile.TemporaryDirectory(prefix="p2wlan-finalizer-regressions-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name)
        with patch.object(legacy, "CONTROLLER", controller(**options)):
            fixture = legacy.OwnedCleanupProcesses(directory)
        self.addCleanup(fixture.close)
        (fixture.root / "fixture-collector.py").write_text(COLLECTOR, encoding="utf-8")
        return fixture

    @staticmethod
    def read(fixture, name):
        return common.RoundFinalizationControls.read(fixture, name)

    def gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def failed_and_reaped(self, fixture, reason="baseline_status_not_available", code=1,
                          rejection="nat_evidence_rejected"):
        fixture.close()
        self.assertEqual(fixture.process.returncode, code)
        fixture.terminated_children()
        value = self.read(fixture, "round-finalization.json")
        self.assertEqual(value["terminal_reason_code"], reason)
        self.assertEqual(value["original_exit_code"], code)
        self.assertEqual(value["round_result"], "invalid")
        cleanup = self.read(fixture, "cleanup.json")
        self.assertTrue(cleanup["all_reaped"])
        self.assertFalse(cleanup["forced_termination"])
        self.assertEqual(cleanup["started_process_count"], 6)
        self.assertEqual(cleanup["wait_completed_count"], 6)
        self.assertEqual({row["role"]: row["pid"] for row in cleanup["owned_processes"]}, fixture.owners[1])
        self.assertTrue(all(row["wait_completed"] and row["wait_status"] == 0
                            for row in cleanup["owned_processes"]))
        self.assertFalse((fixture.round_dir / "business-validation.start-gate").exists())
        checks = legacy.RoundCleanupBehaviorTests()
        checks.invalid_summary(fixture.round_dir, rejection)
        return value, cleanup

    def test_cached_node_retains_original_identity_after_actual_wait(self):
        fixture = self.fixture()
        pid = fixture.owners[1]["node-a"]
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        self.assertEqual(fixture.command("REAP_NODE_A"), f"NODE_A_REAPED:{pid}:0")
        self.gone(pid)
        before = (fixture.round_dir / "fixture-signal.calls").read_bytes()
        self.assertEqual(fixture.finish()[-1], 0)
        value, _ = self.failed_and_reaped(fixture, rejection="raw_evidence_missing:node-a.status.json")
        after = (fixture.round_dir / "fixture-signal.calls").read_bytes()
        self.assertNotIn(str(pid).encode(), after[len(before):])
        self.assertEqual((fixture.round_dir / "fixture-final-fetch.calls").read_text().splitlines(), ["b"])
        self.assertFalse((fixture.round_dir / "node-a.status.json").exists())
        self.assertFalse(value["statuses"]["a"]["worker"]["started"])
        status = value["statuses"]["a"]
        self.assertEqual((status["pid"], status["owner_role"], status["reason_code"]),
                         (pid, "node-a", "process_gone"),
                         "B01_CACHED_NODE_IDENTITY: preserve the real ended node PID and typed process_gone")

    def collector_result(self, fixture, command, expected_exit, expected_mode, expected_signal):
        response = fixture.command(command).split(":")
        self.assertEqual(len(response), 4)
        self.assertEqual(response[:2], ["COLLECTOR", str(expected_exit)])
        receipt = self.read(fixture, ".collector-result.json")
        self.assertTrue(receipt["started"])
        self.assertTrue(receipt["wait_completed"])
        self.assertTrue(receipt["command_wait_completed"])
        self.assertEqual(receipt["command_wait_status"], 0)
        self.assertTrue(receipt["owned_group_shutdown_requested_before_wait"])
        self.assertFalse(receipt["forced_termination"])
        self.assertEqual(receipt["resource_grace_deadline_monotonic_ms"], int(response[3]))
        self.gone(receipt["pid"])
        snapshot = fixture.round_dir / ".bounded-collector"
        entered = json.loads((snapshot / "fixture-collector-entered.json").read_bytes())
        completed = json.loads((snapshot / "fixture-collector-completed.json").read_bytes())
        self.assertEqual(entered["mode"], expected_mode)
        self.assertEqual(completed, {"pid": entered["pid"], "signal": expected_signal, "exit_code": 0})
        self.gone(entered["pid"])
        staged = snapshot / "nat-evidence.json"
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        generated = json.loads(staged.read_bytes())
        self.assertEqual(generated["schema_version"], 1)
        self.assertIs(generated["executed"], True)
        self.assertEqual(generated["result"], "pass")
        self.assertEqual(generated["decision"], {"result": "pass", "reason_code": "fixture_collector_completed"})
        self.assertIsNone(generated["nat_terminal"])
        return receipt, staged, int(response[2])

    def test_cutoff_collector_cannot_promote_zero_exit_output(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        receipt, _, capture_end = self.collector_result(
            fixture, "RUN_COLLECTOR_CUTOFF", 1, "cutoff", signal.SIGTERM)
        self.assertEqual(receipt["result"], "unknown")
        self.assertEqual(receipt["reason_code"], "deadline_exhausted")
        promoted_before_finish = (fixture.round_dir / "nat-evidence.json").exists()
        self.assertEqual(fixture.finish()[-1], 0)
        value, _ = self.failed_and_reaped(
            fixture, rejection="raw_evidence_missing:node-a.status.json,node-b.status.json")
        self.assertLessEqual(value["capture_deadline_monotonic_ms"], capture_end)
        self.assertFalse((fixture.round_dir / "fixture-final-fetch.calls").exists())
        self.assertFalse(value["statuses"]["a"]["worker"]["started"])
        self.assertFalse(value["statuses"]["b"]["worker"]["started"])
        self.assertEqual(value["collector"]["result"], "unknown")
        self.assertFalse(promoted_before_finish,
                         "B01_CUTOFF_COLLECTOR_CANONICAL: unknown cutoff output must remain staged")

    def test_early_collector_promotes_only_completed_output(self):
        fixture = self.fixture()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        receipt, staged, _ = self.collector_result(
            fixture, "RUN_COLLECTOR_EARLY", 0, "early", 0)
        self.assertEqual(receipt["result"], "completed")
        self.assertIsNone(receipt["reason_code"])
        canonical = fixture.round_dir / "nat-evidence.json"
        canonical_bytes = canonical.read_bytes()
        self.assertEqual(canonical.stat().st_mode & 0o777, 0o600)
        digest = hashlib.sha256(canonical_bytes).hexdigest()
        expected = json.loads(staged.read_bytes())
        self.assertEqual(fixture.finish()[-1], 0)
        value, _ = self.failed_and_reaped(fixture)
        self.assertEqual(value["collector"]["result"], "completed")
        self.assertIs(self.read(fixture, "nat-evidence.json")["executed"], True)
        self.assertEqual((json.loads(canonical_bytes), receipt["outputs"]),
                         (expected, [{"name": "nat-evidence.json", "captured_sha256": digest}]),
                         "B01_EARLY_COLLECTOR_PROMOTION: a completed bounded collector retains its output")

    def test_explicit_round_init_before_first_spawn_tracks_all_actual_waits(self):
        fixture = self.fixture(explicit_init=True)
        initialized = (fixture.round_dir / "fixture-before-first-spawn.txt").read_text().strip()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        self.assertEqual(fixture.finish()[-1], 0)
        _, cleanup = self.failed_and_reaped(fixture)
        self.assertEqual((initialized, cleanup["started_process_count"], cleanup["wait_completed_count"]),
                         ("open:0:0:0:0:0:empty:empty:empty", 6, 6),
                         "B01_EXPLICIT_ROUND_INIT: empty initialization must precede six real registrations and waits")

    def test_real_exit7_wins_over_native_term_during_cleanup_capture(self):
        fixture = self.fixture()
        owner_pid = fixture.process.pid
        fixture.send("EXIT7_DURING_CAPTURE")
        fixture.close()
        value, _ = self.failed_and_reaped(fixture, "fixture_command_failed", 7)
        self.assertEqual((fixture.round_dir / "fixture-final-fetch.calls").read_text().splitlines(), ["a", "b"])
        self.assertEqual((fixture.round_dir / "fixture-native-term-sent.calls").read_text().splitlines(),
                         [f"{owner_pid}:a", f"{owner_pid}:b"])
        self.assertTrue(all(value["statuses"][side]["result"] == "available" for side in ("a", "b")))
        self.assertEqual((fixture.process.returncode, value["original_exit_code"],
                          value["shell_exit_status"], value["shell_exit_status_source"]),
                         (7, 7, 7, "exit_trap"),
                         "B01_EXIT7_DURING_CLEANUP: native EXIT7 retains priority over cleanup TERM")


if __name__ == "__main__":
    unittest.main()
