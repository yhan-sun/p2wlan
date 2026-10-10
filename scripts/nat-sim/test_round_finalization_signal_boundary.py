#!/usr/bin/env python3
"""Unexecuted offline signal-boundary candidate; root must authorize source copy.

Native INT/TERM and production traps are used. DEBUG/functrace only pauses the
real finish_round at state boundaries; production handlers are not copied or
called directly. Existing three-second protocol/two-second teardown are reused.
Fixture status JSON does not prove daemon authentication, NAT or TUN delivery.
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


COMMANDS = r"""
    BOUNDARY_FINISH)
      _FIXTURE_BOUNDARY_STAGE=armed
      finish_round
      (umask 077; printf '%s\n' unexpected_finish_return >"$ROUND_DIR/fixture-boundary-infrastructure-error")
      exit 96 ;;
"""

# Guards restrict pauses to the owning shell and the actual production
# finish_round frame. Background/subshell work inherits functrace but cannot
# publish a controller handshake. Busy protects the hook during native traps.
DEBUG_INSTALL = r"""
_FIXTURE_CONTROLLER_PID=$$
_FIXTURE_BOUNDARY_STAGE=idle
_FIXTURE_DEBUG_BUSY=0

_fixture_boundary_error() {
  (umask 077; printf '%s\n' "$1" >"$ROUND_DIR/fixture-boundary-infrastructure-error")
  return 96
}
_fixture_boundary_read() {
  local expected="$1" received="" attempt
  # A native trap may interrupt a builtin read. At most one such interruption
  # is allowed per handshake; this is not a new deadline or timed retry.
  for attempt in 1 2; do
    if IFS= read -r received; then
      [[ "$received" == "$expected" ]] || { _fixture_boundary_error unexpected_release_token; return 96; }
      return 0
    fi
  done
  _fixture_boundary_error interrupted_or_closed_handshake
}
_fixture_boundary_debug() {
  [[ "${BASH_SUBSHELL:-0}" == 0 ]] || return 0
  [[ "${FUNCNAME[1]:-}" == finish_round ]] || return 0
  [[ "${_FIXTURE_DEBUG_BUSY:-0}" == 0 ]] || return 0
  if [[ "${_FIXTURE_BOUNDARY_STAGE:-idle}" == armed && "${_ROUND_STATE:-}" == finalizing ]]; then
    _FIXTURE_DEBUG_BUSY=1
    _FIXTURE_BOUNDARY_STAGE=first-wait
    (umask 077; printf '%s\n' "$1" >"$ROUND_DIR/fixture-boundary-finalizing.command")
    printf 'BOUNDARY_FINALIZING:%s:%s:%s\n' "$_FIXTURE_CONTROLLER_PID" "$_ROUND_STATE" "${_ROUND_SIGNAL_EXIT:-0}"
    _fixture_boundary_read BOUNDARY_RELEASE_INT || return 96
    [[ "${_ROUND_SIGNAL_EXIT:-0}" == 130 && "${_ROUND_STATE:-}" == finalizing ]] || {
      _fixture_boundary_error native_int_not_deferred_in_finalizing; return 96;
    }
    _FIXTURE_BOUNDARY_STAGE=first-recorded
    printf 'BOUNDARY_INT_RECORDED:%s:%s\n' "$_ROUND_SIGNAL_EXIT" "$_ROUND_STATE"
    _FIXTURE_DEBUG_BUSY=0
  elif [[ "${_FIXTURE_BOUNDARY_STAGE:-idle}" == first-recorded && "${_ROUND_STATE:-}" == finalized ]]; then
    _FIXTURE_DEBUG_BUSY=1
    _FIXTURE_BOUNDARY_STAGE=second-wait
    (umask 077; printf '%s\n' "$1" >"$ROUND_DIR/fixture-boundary-finalized.command")
    printf 'BOUNDARY_FINALIZED:%s:%s:%s:%s\n' "$_FIXTURE_CONTROLLER_PID" "$_ROUND_STATE" "${_ROUND_SIGNAL_EXIT:-0}" "${_ROUND_WAIT_COMPLETED:-0}"
    _fixture_boundary_read BOUNDARY_RELEASE_FINALIZED || return 96
    _FIXTURE_BOUNDARY_STAGE=done
    _FIXTURE_DEBUG_BUSY=0
  fi
  return 0
}
set -o functrace
trap '_fixture_boundary_debug "${BASH_COMMAND:-}"' DEBUG
"""


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise AssertionError("signal fixture extension anchor changed")
    return text.replace(before, after, 1)


def controller():
    text = common.controller()
    text = replace_once(text, "    CAPTURE)\n", COMMANDS + "    CAPTURE)\n")
    return replace_once(text, "start_round\nwhile IFS=", DEBUG_INSTALL + "\nstart_round\nwhile IFS=")



class RoundFinalizationSignalBoundary(unittest.TestCase):
    def fixture(self):
        temporary = legacy.tempfile.TemporaryDirectory(prefix="p2wlan-signal-boundary-")
        self.addCleanup(temporary.cleanup)
        with patch.object(legacy, "CONTROLLER", controller()):
            fixture = legacy.OwnedCleanupProcesses(Path(temporary.name))
        self.addCleanup(fixture.close)
        return fixture

    @staticmethod
    def read(fixture, name):
        return common.RoundFinalizationControls.read(fixture, name)

    def gone(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def assert_finalized_prerequisites(self, fixture):
        value = self.read(fixture, "round-finalization.json")
        cleanup = self.read(fixture, "cleanup.json")
        fixture.terminated_children()
        self.assertEqual(value["terminal_reason_code"], "baseline_status_not_available")
        self.assertEqual(value["original_exit_code"], 1)
        self.assertEqual(value["round_result"], "invalid")
        self.assertEqual((value["shell_exit_status"], value["shell_exit_status_source"]), (130, "deferred_signal"))
        self.assertTrue(cleanup["all_reaped"])
        self.assertFalse(cleanup["forced_termination"])
        self.assertEqual(cleanup["pending_process_count"], 0)
        self.assertEqual((cleanup["started_process_count"], cleanup["wait_completed_count"]), (6, 6))
        self.assertEqual({row["role"]: row["pid"] for row in cleanup["owned_processes"]}, fixture.owners[1])
        self.assertTrue(all(row["wait_completed"] and row["wait_status"] == 0 for row in cleanup["owned_processes"]))
        self.assertFalse((fixture.round_dir / "business-validation.start-gate").exists())
        self.assertEqual((fixture.round_dir / "fixture-final-fetch.calls").read_text().splitlines(), ["a", "b"])
        for side in ("a", "b"):
            status = value["statuses"][side]
            self.assertEqual(status["result"], "available")
            self.assertEqual(status["pid"], fixture.owners[1]["node-" + side])
            self.assertEqual(status["owner_role"], "node-" + side)
            worker = status["worker"]
            self.assertTrue(worker["started"])
            self.assertTrue(worker["wait_completed"])
            self.assertTrue(worker["command_wait_completed"])
            self.assertEqual(worker["command_wait_status"], 0)
            self.assertTrue(worker["owned_group_shutdown_requested_before_wait"])
            self.assertFalse(worker["forced_termination"])
            self.gone(worker["pid"])
            self.assertEqual(worker["resource_grace_deadline_monotonic_ms"], cleanup["resource_grace_deadline_monotonic_ms"])
        legacy.RoundCleanupBehaviorTests().invalid_summary(fixture.round_dir, "nat_evidence_rejected")
        return value, cleanup

    def run_boundary(self, *, second_term):
        fixture = self.fixture()
        owner = fixture.process.pid
        self.assertEqual(fixture.capture(), "CAPTURE:23")
        self.assertTrue((fixture.round_dir / "node-a.baseline.status.json").is_file())
        self.assertFalse((fixture.round_dir / "node-b.baseline.status.json").exists())
        fixture.send("BOUNDARY_FINISH")
        self.assertEqual(fixture.receive(), f"BOUNDARY_FINALIZING:{owner}:finalizing:0")
        self.assertTrue((fixture.round_dir / "fixture-boundary-finalizing.command").read_text().strip())
        os.kill(owner, signal.SIGINT)
        fixture.send("BOUNDARY_RELEASE_INT")
        self.assertEqual(fixture.receive(), "BOUNDARY_INT_RECORDED:130:finalizing")
        self.assertEqual(fixture.receive(), f"BOUNDARY_FINALIZED:{owner}:finalized:130:6")
        self.assertTrue((fixture.round_dir / "fixture-boundary-finalized.command").read_text().strip())
        value, cleanup = self.assert_finalized_prerequisites(fixture)
        saved = {name: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                 for name in ("round-finalization.json", "cleanup.json")
                 for path in (fixture.round_dir / name,)}
        if second_term:
            os.kill(owner, signal.SIGTERM)
        try:
            fixture.send("BOUNDARY_RELEASE_FINALIZED")
        except (BrokenPipeError, OSError):
            # A native signal may already have exited the paused controller.
            # Actual close/wait and all following prerequisites are still required.
            pass
        fixture.close()
        fixture.terminated_children()
        self.assertFalse((fixture.round_dir / "fixture-boundary-infrastructure-error").exists())
        self.assertIn(fixture.process.returncode, (130, 143), "controller must exit by the observed native INT/TERM")
        for name, expected in saved.items():
            path = fixture.round_dir / name
            self.assertEqual((path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns), expected)
        self.assert_finalized_prerequisites(fixture)
        return fixture.process.returncode, value, cleanup

    def test_single_native_int_reaches_fixed_finalized_boundary_then_exits130(self):
        actual, _, _ = self.run_boundary(second_term=False)
        self.assertEqual(actual, 130, "single INT control must retain its deferred exit")

    def test_first_native_int_survives_term_after_finalized_boundary(self):
        actual, value, _ = self.run_boundary(second_term=True)
        self.assertEqual((actual, value["shell_exit_status"], value["original_exit_code"]),
                         (130, 130, 1),
                         "B01_FIRST_DEFERRED_SIGNAL_EXIT: first deferred INT130 must survive finalized-boundary TERM")


if __name__ == "__main__":
    unittest.main()
