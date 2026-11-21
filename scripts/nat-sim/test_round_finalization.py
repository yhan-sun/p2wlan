#!/usr/bin/env python3
"""Offline controls for the common finalizer, before harness caller wiring.

Uses the unchanged phase-one controller/actual children and production module.
Fixture JSON/status and launch declarations do not prove native authentication,
NAT, exact business delivery, or a successful exec of a product binary.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import time
import unittest
from unittest.mock import patch

import launch_identity
import test_round_cleanup as legacy


COMMANDS = r'''
    PREPARE)
      ROUND_CLEANUP_GRACE_MS=700
      _round_context
      _round_fixed_windows
      printf 'WINDOWS:%s:%s\n' "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" ;;
    SHORT_CAPTURE)
      _round_context
      _round_fixed_windows
      _ROUND_CAPTURE_END_MS=$(($(_round_now) + 300))
      printf 'SHORT_CAPTURE:%s\n' "$_ROUND_CAPTURE_END_MS" ;;
    REAP_WATCHER)
      _round_context
      kill -TERM "$HARD_HARD_WATCHER_PID"
      if wait "$HARD_HARD_WATCHER_PID"; then rc=0; else rc=$?; fi
      round_record_wait "$HARD_HARD_WATCHER_PID" "$rc"
      printf 'WATCHER_REAPED:%s:%s\n' "$HARD_HARD_WATCHER_PID" "$rc" ;;
    SPAWN_SENTINEL)
      "$fixture_python" -u "$fixture_child" "$ROUND_DIR" sentinel </dev/null &
      SENTINEL_PID=$!
      printf 'SENTINEL:%s\n' "$SENTINEL_PID" ;;
    REAP_SENTINEL)
      kill -TERM "$SENTINEL_PID"
      if wait "$SENTINEL_PID"; then rc=0; else rc=$?; fi
      printf 'SENTINEL_REAPED:%s\n' "$rc" ;;
    SPAWN_STUBBORN)
      "$fixture_python" -u "$BASE_DIR/stubborn.py" &
      STUBBORN_PID=$!
      round_register_process stubborn "$STUBBORN_PID"
      printf 'STUBBORN:%s\n' "$STUBBORN_PID" ;;
    MARK_FAILURE)
      round_fail fixture_original_failure 7
      printf 'MARKED:7\n' ;;
    SWAP_CAPTURE_A)
      _round_context
      NODE_A_PID=$NAT_PID
      printf 'SWAPPED_A:%s\n' "$NODE_A_PID" ;;
    STOP_A)
      stop_pid_group_bounded "$NODE_A_PID"
      printf 'STOPPED_A:%s\n' "$_ROUND_RESOURCE_END_MS" ;;
    EXTRAS)
      _round_context
      for ((extra=0; extra<130; extra++)); do
        bash -c 'exit 0' &
        extra_pid=$!
        printf '%s\n' "$extra_pid" >>"$ROUND_DIR/fixture-extra.pids"
        round_register_process "short-$extra" "$extra_pid"
      done
      printf 'EXTRAS:%s\n' "$_ROUND_STARTED" ;;
    SIGNAL_INT) builtin kill -INT "$$" ;;
    SIGNAL_TERM) builtin kill -TERM "$$" ;;
'''

AUDIT_KILL = r'''
kill() {
  if [[ "${1:-}" != -0 ]]; then
    printf '%s\n' "$*" >>"$ROUND_DIR/fixture-signal.calls"
  fi
  builtin kill "$@"
}
'''


def controller(*, blocked=False, pipeline=False):
    text = legacy.CONTROLLER.replace("trap cleanup EXIT", "round_install_traps", 1)
    text = text.replace('    CAPTURE)\n', COMMANDS + '    CAPTURE)\n', 1)
    text = text.replace("start_round\nwhile IFS=", AUDIT_KILL + "\nstart_round\nwhile IFS=", 1)
    if blocked:
        marker = '''  printf '%s\\n' "$side" >>"$ROUND_DIR/fixture-final-fetch.calls"'''
        replacement = marker + r'''
  if [[ "$side" == a ]]; then
    printf '%s\n' "$$" >"$ROUND_DIR/fixture-blocked-status.pid"
    IFS= read -r unused <"$ROUND_DIR/status-block.fifo"
  fi'''
        if marker not in text:
            raise AssertionError("fixture callback anchor changed")
        text = text.replace(marker, replacement, 1)
    if pipeline:
        marker = '''    "$fixture_python" -u "$fixture_child" "$ROUND_DIR" "$role" </dev/null &'''
        replacement = '''    printf 'fixture-only\\n' | "$fixture_python" -u "$fixture_child" "$ROUND_DIR" "$role" &'''
        if marker not in text:
            raise AssertionError("fixture spawn anchor changed")
        text = text.replace(marker, replacement, 1)
    return text


class RoundFinalizationControls(unittest.TestCase):
    def fixture(self, **options):
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
            directory.mkdir(mode=0o700)
        else:
            temporary = legacy.tempfile.TemporaryDirectory(prefix="p2wlan-finalizer-controls-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name)
        with patch.object(legacy, "CONTROLLER", controller(**options)):
            fixture = legacy.OwnedCleanupProcesses(directory)
        self.addCleanup(fixture.close)
        return fixture

    @staticmethod
    def read(fixture, name):
        path = fixture.round_dir / name
        value = json.loads(path.read_bytes())
        if path.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("private receipt mode differs")
        return value

    def gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_cached_watcher_wait_is_preserved_without_later_signal(self):
        fixture = self.fixture()
        expected_pid = fixture.owners[1]["watcher"]
        self.assertEqual(fixture.command("REAP_WATCHER"), f"WATCHER_REAPED:{expected_pid}:0")
        before = (fixture.round_dir / "fixture-signal.calls").read_bytes()
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        after = (fixture.round_dir / "fixture-signal.calls").read_bytes()
        self.assertNotIn(str(expected_pid).encode(), after[len(before):])
        cleanup = self.read(fixture, "cleanup.json")
        self.assertTrue(cleanup["all_reaped"])
        watcher = next(row for row in cleanup["owned_processes"] if row["role"] == "watcher")
        self.assertEqual(watcher["pid"], expected_pid)
        self.assertTrue(watcher["wait_completed"])
        self.assertEqual(watcher["wait_status"], 0)
        self.assertEqual(cleanup["started_process_count"], 6)
        self.assertEqual(cleanup["wait_completed_count"], 6)

    def test_unregistered_live_sentinel_is_not_signalled_or_claimed(self):
        fixture = self.fixture()
        fixture.send("SPAWN_SENTINEL")
        answers = [fixture.receive(), fixture.receive()]
        pid = int(next(value.split(":")[1] for value in answers if value.startswith("SENTINEL:")))
        self.assertIn(f"CHILD_READY:sentinel:{pid}", answers)
        try:
            self.assertEqual(fixture.capture(), "CAPTURE:23")
            fixture.finish()
            fixture.terminated_children()
            os.kill(pid, 0)
            self.assertFalse((fixture.round_dir / "sentinel.stopped.json").exists())
            cleanup = self.read(fixture, "cleanup.json")
            self.assertNotIn(pid, [row["pid"] for row in cleanup["owned_processes"]])
            self.assertTrue(cleanup["all_reaped"])
        finally:
            self.assertEqual(fixture.command("REAP_SENTINEL"), "SENTINEL_REAPED:0")
        self.gone(pid)

    def test_pipeline_last_pid_is_owned_and_actually_waited(self):
        fixture = self.fixture(pipeline=True)
        self.assertTrue(fixture.command("PREPARE").startswith("WINDOWS:"))
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        cleanup = self.read(fixture, "cleanup.json")
        self.assertTrue(cleanup["all_reaped"])
        self.assertEqual({row["role"]: row["pid"] for row in cleanup["owned_processes"]}, fixture.owners[1])
        self.assertTrue(all(row["wait_completed"] and row["wait_status"] == 0 for row in cleanup["owned_processes"]))

    def test_forced_second_group_shares_original_grace_and_first_failure(self):
        fixture = self.fixture()
        child = fixture.root / "stubborn.py"
        child.write_text("import os,signal\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
                         "signal.signal(signal.SIGINT,signal.SIG_IGN)\n"
                         "print('STUBBORN_READY:'+str(os.getpid()),flush=True)\n"
                         "while True: signal.pause()\n")
        fixture.send("SPAWN_STUBBORN")
        answers = [fixture.receive(), fixture.receive()]
        pid = int(next(value.split(":")[1] for value in answers if value.startswith("STUBBORN:")))
        self.assertIn(f"STUBBORN_READY:{pid}", answers)
        self.assertEqual(fixture.command("MARK_FAILURE"), "MARKED:7")
        _, capture_end, grace_end = fixture.command("PREPARE").split(":")
        self.assertEqual(fixture.command("STOP_A"), f"STOPPED_A:{grace_end}")
        fixture.finish()
        fixture.terminated_children()
        self.gone(pid)
        value = self.read(fixture, "round-finalization.json")
        cleanup = self.read(fixture, "cleanup.json")
        self.assertEqual(value["terminal_reason_code"], "fixture_original_failure")
        self.assertEqual(value["original_exit_code"], 7)
        self.assertEqual(value["round_result"], "invalid")
        self.assertLessEqual(value["capture_deadline_monotonic_ms"], int(capture_end))
        self.assertEqual(cleanup["resource_grace_deadline_monotonic_ms"], int(grace_end))
        self.assertLess(cleanup["duration_ms"], 1500)
        self.assertTrue(cleanup["all_reaped"])
        self.assertTrue(cleanup["forced_termination"])
        stubborn = next(row for row in cleanup["owned_processes"] if row["pid"] == pid)
        self.assertTrue(stubborn["forced_termination"])
        self.assertTrue(stubborn["wait_completed"])
        self.assertEqual(stubborn["wait_status"], 128 + signal.SIGKILL)

    def test_expired_capture_worker_is_closed_before_actual_wait(self):
        fixture = self.fixture(blocked=True)
        os.mkfifo(fixture.round_dir / "status-block.fifo", 0o600)
        self.assertTrue(fixture.command("SHORT_CAPTURE").startswith("SHORT_CAPTURE:"))
        fixture.finish()
        fixture.terminated_children()
        value = self.read(fixture, "round-finalization.json")
        a, b = value["statuses"]["a"], value["statuses"]["b"]
        self.assertEqual(a["reason_code"], "deadline_exhausted")
        self.assertEqual(b["reason_code"], "deadline_exhausted")
        self.assertTrue(a["worker"]["wait_completed"])
        self.assertTrue(a["worker"]["owned_group_shutdown_requested_before_wait"])
        self.assertTrue(a["worker"]["command_wait_completed"])
        self.assertTrue((fixture.round_dir / "fixture-blocked-status.pid").is_file(),
                        "controlled callback must actually enter before its deadline")
        self.gone(a["worker"]["pid"])
        self.assertEqual((fixture.round_dir / "fixture-final-fetch.calls").read_text().splitlines(), ["a"])
        self.assertFalse((fixture.round_dir / "node-a.status.json").exists())
        self.assertFalse((fixture.round_dir / "node-b.status.json").exists())
        self.assertEqual(a["worker"]["resource_grace_deadline_monotonic_ms"],
                         self.read(fixture, "cleanup.json")["resource_grace_deadline_monotonic_ms"])

    def test_metadata_cap_does_not_truncate_actual_child_waits(self):
        fixture = self.fixture()
        self.assertEqual(fixture.command("EXTRAS"), "EXTRAS:136")
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        cleanup = self.read(fixture, "cleanup.json")
        self.assertEqual(cleanup["started_process_count"], 136)
        self.assertEqual(cleanup["wait_completed_count"], 136)
        self.assertEqual(cleanup["unrecorded_process_count"], 8)
        self.assertEqual(cleanup["metadata_coverage"], "capacity_exceeded")
        self.assertEqual(len(cleanup["owned_processes"]), 128)
        self.assertTrue(cleanup["all_reaped"])
        self.assertEqual(cleanup["process_count"], 135)
        self.assertLess((fixture.round_dir / "cleanup.json").stat().st_size, 128 * 1024)
        self.assertLess((fixture.round_dir / "round-finalization.json").stat().st_size, 128 * 1024)
        for pid in (fixture.round_dir / "fixture-extra.pids").read_text().splitlines():
            self.gone(int(pid))

    def test_sigint_preserves_130_and_actual_owned_wait_receipts(self):
        self.signal_control("SIGNAL_INT", 130, "interrupted")

    def test_sigterm_preserves_143_and_actual_owned_wait_receipts(self):
        self.signal_control("SIGNAL_TERM", 143, "terminated")

    def signal_control(self, command, code, reason):
        fixture = self.fixture()
        fixture.send(command)
        fixture.close()
        self.assertEqual(fixture.process.returncode, code)
        fixture.terminated_children()
        value = self.read(fixture, "round-finalization.json")
        self.assertEqual(value["terminal_reason_code"], reason)
        self.assertEqual(value["original_exit_code"], code)
        self.assertEqual(value["shell_exit_status"], code)
        self.assertEqual(value["shell_exit_status_source"], "exit_trap")
        self.assertEqual(value["round_result"], "invalid")
        self.assertTrue(self.read(fixture, "cleanup.json")["all_reaped"])

    @staticmethod
    def launch_fixture(fixture, pid):
        source = {"commit": "a" * 40, "patch_sha256": "b" * 64}
        artifact = {"path": "artifacts/daemon", "sha256": hashlib.sha256(b"fixture").hexdigest(), "size_bytes": 7}
        artifact_set = {"schema_version": 1, "source": source, "artifacts": {"daemon": artifact}}
        legacy.OwnedCleanupProcesses.write_json(fixture.root / "source-at-build.json", source)
        legacy.OwnedCleanupProcesses.write_json(fixture.root / "artifact-set.json", artifact_set)
        artifact_hash = hashlib.sha256((fixture.root / "artifact-set.json").read_bytes()).hexdigest()
        record = {"schema_version": 1, "source": source, "role": "node-a", "component": "daemon",
                  "state": "exec_requested", "pid": pid, "monotonic_ns": time.monotonic_ns(),
                  "artifact_set_sha256": artifact_hash, "artifact": artifact,
                  "configuration": launch_identity.configuration_identity([], {}, [], stdin_authorization=True)}
        legacy.OwnedCleanupProcesses.write_json(fixture.round_dir / "launches" / "node-a.json", record)
        return source, artifact_hash

    def test_launch_declaration_is_bound_to_original_owned_pid_and_captured_bytes(self):
        fixture = self.fixture()
        source, digest = self.launch_fixture(fixture, fixture.owners[1]["node-a"])
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        identity = self.read(fixture, "round-finalization.json")["source_identity"]
        self.assertEqual(identity["result"], "captured")
        self.assertEqual(identity["source"], source)
        self.assertEqual(identity["artifact_set_sha256"], digest)
        self.assertEqual(identity["artifact_validation_scope"], "declaration_only")
        self.assertEqual(identity["launch_records"][0]["pid"], fixture.owners[1]["node-a"])
        self.assertEqual(identity["launch_records"][0]["state"], "exec_requested")
        self.assertNotIn("fixture-only", (fixture.round_dir / "round-finalization.json").read_text())

    def test_changed_launch_pid_is_unknown_without_relabeling_final_status(self):
        fixture = self.fixture()
        self.launch_fixture(fixture, fixture.owners[1]["node-a"] + 1)
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        fixture.finish()
        fixture.terminated_children()
        value = self.read(fixture, "round-finalization.json")
        self.assertEqual(value["source_identity"]["result"], "unknown")
        self.assertEqual(value["source_identity"]["reason_code"], "source_or_launch_identity_invalid")
        self.assertEqual(value["statuses"]["a"]["pid"], fixture.owners[1]["node-a"])
        self.assertEqual(value["terminal_reason_code"], "baseline_status_not_available")

    def test_other_owned_role_cannot_be_read_as_node_a_status(self):
        fixture = self.fixture()
        self.assertEqual(fixture.command("MARK_FAILURE"), "MARKED:7")
        self.assertEqual(fixture.command("SWAP_CAPTURE_A"), f"SWAPPED_A:{fixture.owners[1]['nat']}")
        fixture.finish()
        fixture.terminated_children()
        value = self.read(fixture, "round-finalization.json")
        self.assertEqual(value["statuses"]["a"]["result"], "unknown")
        self.assertEqual(value["statuses"]["a"]["reason_code"], "side_owner_identity_mismatch")
        self.assertEqual(value["statuses"]["a"]["owner_role"], "nat")
        self.assertFalse(value["statuses"]["a"]["worker"]["started"])
        self.assertFalse((fixture.round_dir / "node-a.status.json").exists())
        self.assertEqual((fixture.round_dir / "fixture-final-fetch.calls").read_text().splitlines(), ["b"])
        self.assertEqual(value["terminal_reason_code"], "fixture_original_failure")


if __name__ == "__main__":
    unittest.main()
