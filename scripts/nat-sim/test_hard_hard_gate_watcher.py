#!/usr/bin/env python3
"""Offline runtime regressions for a round-owned actual-start gate watcher.

The existing main/release API cases are executable before the watcher exists.
All watcher and business helpers bind the implemented API directly.
Temporary missing-API guards are absent; final acceptance runs every case.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import os
import select
import subprocess
import time
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hard_hard_gate as gate
from test_hard_hard_gate import complementary, log_line


class VirtualClock:
    def __init__(self, now_ms=9_850, on_sleep=None):
        self.value = now_ms
        self.on_sleep = on_sleep
        self.sleep_count = 0

    def now_ms(self):
        return self.value

    def sleep(self, seconds):
        self.sleep_count += 1
        if self.sleep_count > 1_000:
            raise AssertionError("virtual watcher exceeded the bounded fixture lifetime")
        self.value += max(1, round(seconds * 1_000))
        if self.on_sleep is not None:
            self.on_sleep(self)


class GateFixture:
    def __init__(self, root):
        self.a_log = root / "node-a.log"
        self.b_log = root / "node-b.log"
        self.probe_gate = root / "probe.open"
        self.evidence = root / "probe.json"
        self.armed = root / "watcher.armed"
        self.business_gate = root / "business.open"
        self.a, self.b = complementary("initial-owner", punch_a=10_000, punch_b=10_002)

    def publish(self):
        self.a_log.write_text(log_line(self.a) + "\n", encoding="utf-8")
        self.b_log.write_text(log_line(self.b) + "\n", encoding="utf-8")

    def append_new_a_owner(self):
        replacement, _ = complementary("replacement-owner", punch_a=10_200, punch_b=10_202)
        with self.a_log.open("a", encoding="utf-8") as output:
            output.write(log_line(replacement) + "\n")
        return replacement


def run_existing_main(fixture, clock):
    """Execute the actual old CLI/main with its existing release dependencies."""
    release = gate.release_gate

    def release_with_clock(plan, gate_path, evidence_path, **kwargs):
        kwargs["now_ms"] = clock.now_ms
        kwargs["sleep"] = clock.sleep
        return release(plan, gate_path, evidence_path, **kwargs)

    argv = [
        str(Path(gate.__file__)),
        "--node-a-log", str(fixture.a_log),
        "--node-b-log", str(fixture.b_log),
        "--gate-file", str(fixture.probe_gate),
        "--evidence-file", str(fixture.evidence),
        "--max-skew-ms", "250",
        "--lead-ms", "10",
        "--max-future-ms", "5000",
        "--max-late-ms", "25",
    ]
    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(sys, "argv", argv),
        mock.patch.object(gate.time, "time_ns", side_effect=lambda: clock.now_ms() * 1_000_000),
        mock.patch.object(gate, "release_gate", side_effect=release_with_clock),
        contextlib.redirect_stdout(stdout),
        contextlib.redirect_stderr(stderr),
    ):
        result = gate.main()
    return result, stdout.getvalue(), stderr.getvalue()


class ExistingMainOwnershipTests(unittest.TestCase):
    def test_main_does_not_release_owner_replaced_during_wait(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            replacements = []

            def replace_while_waiting(_clock):
                if not replacements:
                    self.assertFalse(fixture.probe_gate.exists())
                    replacements.append(fixture.append_new_a_owner())

            clock = VirtualClock(on_sleep=replace_while_waiting)
            result, _stdout, _stderr = run_existing_main(fixture, clock)
            self.assertGreater(clock.sleep_count, 0, "the actual release must reach its wait")
            self.assertEqual(len(replacements), 1)
            self.assertEqual(
                gate.extract_rendezvous_markers(fixture.a_log)[-1].plan_tag,
                replacements[0].plan_tag,
                "the new owner must already be visible before the old write boundary",
            )
            # This runtime assertion, not a missing API/import, is the RED.
            self.assertFalse(fixture.probe_gate.exists(), "a retired owner opened the probe gate")
            self.assertFalse(fixture.evidence.exists())
            self.assertNotEqual(result, 0)
            self.assertFalse(fixture.business_gate.exists())

    def test_main_preserves_on_time_release_with_unchanged_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            clock = VirtualClock()
            result, _stdout, _stderr = run_existing_main(fixture, clock)
            self.assertEqual(result, 0)
            self.assertTrue(fixture.probe_gate.exists())
            receipt = json.loads(fixture.evidence.read_text(encoding="utf-8"))
            self.assertEqual(receipt["plan_tag"], fixture.a.plan_tag)
            self.assertEqual(receipt["release_offset_from_earliest_punch_ms"], -10)
            self.assertEqual(receipt["lead_ms"], 10)
            self.assertEqual(receipt["result"], "released")
            self.assertEqual(fixture.probe_gate.stat().st_mode & 0o777, 0o600)
            self.assertFalse(fixture.business_gate.exists())

    def test_main_keeps_original_25ms_late_fence(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()

            def delay_release(clock):
                clock.value = 10_026

            result, _stdout, stderr = run_existing_main(
                fixture, VirtualClock(on_sleep=delay_release),
            )
            self.assertNotEqual(result, 0)
            self.assertIn("rendezvous_release_late:26", stderr)
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.evidence.exists())
            self.assertFalse(fixture.business_gate.exists())


class NewWatcherBehaviorTests(unittest.TestCase):
    def watcher(self):
        return gate.watch_gate

    def run_watcher(self, fixture, clock, **limits):
        return self.watcher()(
            node_a_log=fixture.a_log,
            node_b_log=fixture.b_log,
            gate_path=fixture.probe_gate,
            evidence_path=fixture.evidence,
            armed_path=fixture.armed,
            deadline_ms=10_050,
            max_skew_ms=250,
            lead_ms=10,
            max_future_ms=5000,
            max_late_ms=25,
            now_ms=clock.now_ms,
            sleep=clock.sleep,
            monotonic=lambda: clock.now_ms() / 1000,
            **limits,
        )

    def test_watcher_arms_before_activation_and_releases_while_baseline_waits(self):
        self.watcher()
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            armed_observed = threading.Event()
            daemon_launch = threading.Event()
            baseline_entered = threading.Event()
            baseline_continue = threading.Event()
            baseline_completed = threading.Event()
            watcher_done = threading.Event()
            errors = []

            def activation_after_arm(_clock):
                self.assertTrue(fixture.armed.exists(), "watcher must be armed before launch")
                self.assertFalse(fixture.business_gate.exists())
                armed_observed.set()
                if not daemon_launch.wait(1):
                    raise AssertionError("fixture daemons did not launch under native supervision")

            clock = VirtualClock(on_sleep=activation_after_arm)

            def run_watch():
                try:
                    self.run_watcher(fixture, clock)
                except BaseException as error:
                    errors.append(error)
                finally:
                    watcher_done.set()

            def blocked_baseline():
                baseline_entered.set()
                if baseline_continue.wait(2):
                    baseline_completed.set()

            watcher_thread = threading.Thread(target=run_watch)
            baseline_thread = threading.Thread(target=blocked_baseline)
            watcher_thread.start()
            baseline_thread.start()
            try:
                self.assertTrue(armed_observed.wait(1))
                self.assertTrue(fixture.armed.exists())
                self.assertTrue(baseline_entered.wait(1))
                self.assertFalse(baseline_completed.is_set())
                # The controller represents fixture daemon launch only after
                # the actual watcher has published its armed acknowledgment.
                fixture.publish()
                daemon_launch.set()
                self.assertTrue(watcher_done.wait(1))
                if errors:
                    raise errors[0]
                self.assertFalse(baseline_completed.is_set())
                self.assertTrue(fixture.probe_gate.exists())
                self.assertFalse(fixture.business_gate.exists())
                receipt = json.loads(fixture.evidence.read_text(encoding="utf-8"))
                self.assertEqual(receipt["result"], "released")
                self.assertEqual(receipt["plan_tag"], fixture.a.plan_tag)
                self.assertEqual(receipt["release_offset_from_earliest_punch_ms"], -10)
                self.assertLessEqual(clock.value, 10_050)
            finally:
                daemon_launch.set()
                baseline_continue.set()
                watcher_thread.join(1)
                baseline_thread.join(1)
            self.assertFalse(watcher_thread.is_alive())
            self.assertFalse(baseline_thread.is_alive())

    def test_watcher_never_releases_replaced_owner_or_renews_round_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            changed = []

            def replace_once(_clock):
                if not changed:
                    changed.append(fixture.append_new_a_owner())

            clock = VirtualClock(on_sleep=replace_once)
            self.run_watcher(fixture, clock)
            self.assertEqual(len(changed), 1)
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())
            self.assertLessEqual(clock.value, 10_050)
            receipt = json.loads(fixture.evidence.read_text(encoding="utf-8"))
            self.assertNotEqual(receipt["result"], "released")

    def test_watcher_rechecks_original_late_fence_at_write_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()

            def delay_release(clock):
                clock.value = 10_026

            self.run_watcher(fixture, VirtualClock(on_sleep=delay_release))
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())
            receipt = json.loads(fixture.evidence.read_text(encoding="utf-8"))
            self.assertNotEqual(receipt["result"], "released")
            self.assertTrue(receipt["reason_code"].startswith((
                "rendezvous_release_late", "rendezvous_deadline_elapsed",
            )))

    def test_watcher_bounds_retained_markers_and_parse_input(self):
        for limits in ({"max_markers": 1}, {"max_log_bytes": 32}):
            with self.subTest(limits=limits), tempfile.TemporaryDirectory() as temporary:
                fixture = GateFixture(Path(temporary))
                fixture.publish()
                fixture.append_new_a_owner()
                self.run_watcher(fixture, VirtualClock(), **limits)
                self.assertFalse(fixture.probe_gate.exists())
                self.assertFalse(fixture.business_gate.exists())
                receipt = json.loads(fixture.evidence.read_text(encoding="utf-8"))
                self.assertNotEqual(receipt["result"], "released")
                self.assertIn("coverage", receipt["reason_code"])


class WatcherLifecycleTests(unittest.TestCase):
    watcher = NewWatcherBehaviorTests.watcher
    run_watcher = NewWatcherBehaviorTests.run_watcher
    def test_paired_terminal_before_activation_preserves_closed_probe_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            for path in (fixture.a_log, fixture.b_log):
                path.write_text('event="hard_hard_attempt_report"\n', encoding="utf-8")
            result = self.run_watcher(fixture, VirtualClock())
            self.assertEqual(result["result"], "terminal_before_rendezvous")
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())

    def test_single_terminal_keeps_pending_until_original_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.a_log.write_text('event="hard_hard_attempt_report"\n', encoding="utf-8")
            fixture.b_log.write_text("", encoding="utf-8")
            clock = VirtualClock()
            result = self.run_watcher(fixture, clock)
            self.assertEqual(clock.value, 10_050)
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["reason_code"], "rendezvous_watch_deadline_elapsed")
            self.assertFalse(fixture.probe_gate.exists())

    def test_partial_activation_and_log_replacement_fail_coverage_closed(self):
        for failure in ("partial", "replace"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                fixture = GateFixture(Path(temporary))
                fixture.publish()

                def disrupt(_clock):
                    if failure == "partial":
                        with fixture.a_log.open("a") as output:
                            output.write('event="hard_hard_start_activated" session_tag="')
                    else:
                        replacement = fixture.a_log.with_suffix(".new")
                        replacement.write_text(log_line(fixture.a) + "\n")
                        replacement.replace(fixture.a_log)

                result = self.run_watcher(fixture, VirtualClock(on_sleep=disrupt))
                self.assertEqual(result["result"], "rejected")
                self.assertIn("coverage", result["reason_code"])
                self.assertFalse(fixture.probe_gate.exists())

    def test_new_paired_owner_during_wait_cannot_replan_or_release_old_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            replacement = complementary("new-paired-owner")

            def replace_pair(_clock):
                for path, marker in zip((fixture.a_log, fixture.b_log), replacement):
                    with path.open("a") as output:
                        output.write(log_line(marker) + "\n")

            result = self.run_watcher(fixture, VirtualClock(on_sleep=replace_pair))
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["reason_code"], "rendezvous_owner_changed_before_write")
            self.assertFalse(fixture.probe_gate.exists())

    def test_malformed_oversized_numeric_marker_is_typed_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            fixture.a_log.write_text(log_line(fixture.a).replace(
                "punch_at_ms=10000", "punch_at_ms=" + "9" * 100,
            ) + "\n")
            result = self.run_watcher(fixture, VirtualClock())
            self.assertEqual(result["result"], "rejected")
            self.assertIn("rendezvous_field_invalid", result["reason_code"])
            self.assertFalse(fixture.probe_gate.exists())

    def test_truncated_activation_tag_at_write_boundary_keeps_gate_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            partial = b'event="hard_hard_start_acti'
            appended = []

            def append_truncated_event(_clock):
                self.assertFalse(fixture.probe_gate.exists())
                with fixture.a_log.open("ab") as output:
                    output.write(partial)
                appended.append(partial)

            clock = VirtualClock(on_sleep=append_truncated_event)
            result = self.run_watcher(fixture, clock)
            self.assertEqual(clock.sleep_count, 1, "the actual old-pair release reached its wait")
            self.assertEqual(appended, [partial])
            self.assertTrue(fixture.a_log.read_bytes().endswith(partial))
            self.assertFalse(partial.endswith(b"\n"), "the actual event tail is unfinished")
            # A partial event tag cannot establish coverage of latest owner.
            self.assertFalse(fixture.probe_gate.exists())
            self.assertNotEqual(result["result"], "released")
            self.assertIn("coverage", result["reason_code"])
            self.assertFalse(fixture.business_gate.exists())

    def test_unknown_non_activation_tail_at_write_boundary_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            partial = b'unrelated log prefix still being written'

            def append_unknown_tail(_clock):
                with fixture.b_log.open("ab") as output:
                    output.write(partial)

            result = self.run_watcher(fixture, VirtualClock(on_sleep=append_unknown_tail))
            self.assertTrue(fixture.b_log.read_bytes().endswith(partial))
            self.assertEqual(result["result"], "rejected")
            self.assertIn("coverage_partial_line", result["reason_code"])
            self.assertFalse(fixture.probe_gate.exists())

    def test_initial_partial_line_can_complete_and_release_with_original_fences(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            with fixture.a_log.open("ab") as output:
                output.write(b'unrelated log prefix still being written')
            completed = []

            def complete_once(_clock):
                if not completed:
                    self.assertFalse(fixture.probe_gate.exists())
                    with fixture.a_log.open("ab") as output:
                        output.write(b"\n")
                    completed.append(True)

            clock = VirtualClock(on_sleep=complete_once)
            result = self.run_watcher(fixture, clock)
            self.assertEqual(completed, [True])
            self.assertEqual(clock.sleep_count, 2, "pending read then the actual release wait")
            self.assertEqual(result["result"], "released")
            self.assertEqual(result["plan_tag"], fixture.a.plan_tag)
            self.assertEqual(result["release_offset_from_earliest_punch_ms"], -10)
            self.assertTrue(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())

    def test_paired_terminal_cannot_bypass_unknown_partial_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.a_log.write_text('event="hard_hard_attempt_report"\nunidentified unfinished tail')
            fixture.b_log.write_text('event="hard_hard_attempt_report"\n')
            clock = VirtualClock()
            result = self.run_watcher(fixture, clock)
            self.assertEqual(clock.value, 10_050)
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["reason_code"], "rendezvous_watch_deadline_elapsed")
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())

    def test_wall_reversal_between_plan_and_release_cannot_extend_watcher_lifetime(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.publish()
            initial_wall_ms = 9_850
            deadline_ms = 10_050
            wall_ms = [initial_wall_ms]
            monotonic_s = [0.0]
            requested_sleeps = []
            actual_plans = []
            original_plan_gate = gate.plan_gate

            def record_actual_plan(*args, **kwargs):
                plan = original_plan_gate(*args, **kwargs)
                actual_plans.append((args[0], args[1], plan))
                # The actual parser and planner have selected the original
                # owner. The next release_gate clock read observes rollback.
                wall_ms[0] -= 1_000
                return plan

            def observed_sleep(seconds):
                requested_sleeps.append(seconds)
                monotonic_s[0] += seconds
                wall_ms[0] += round(seconds * 1000)

            with mock.patch.object(gate, "plan_gate", side_effect=record_actual_plan):
                result = gate.watch_gate(
                    node_a_log=fixture.a_log, node_b_log=fixture.b_log,
                    gate_path=fixture.probe_gate, evidence_path=fixture.evidence,
                    armed_path=fixture.armed, deadline_ms=deadline_ms,
                    now_ms=lambda: wall_ms[0], sleep=observed_sleep,
                    monotonic=lambda: monotonic_s[0],
                )
            self.assertEqual(len(actual_plans), 1)
            pair, planned_now_ms, plan = actual_plans[0]
            self.assertEqual(pair, gate.select_common_rendezvous(
                gate.extract_rendezvous_markers(fixture.a_log),
                gate.extract_rendezvous_markers(fixture.b_log),
            ))
            self.assertEqual(pair.node_a, fixture.a)
            self.assertEqual(pair.node_b, fixture.b)
            self.assertEqual(planned_now_ms, initial_wall_ms)
            self.assertEqual(plan.release_at_ms, 9_990)
            self.assertEqual(plan.lead_ms, 10)
            self.assertEqual(plan.planned_wait_ms, 140)
            self.assertEqual(len(requested_sleeps), 1)
            self.assertGreater(requested_sleeps[0], 0)
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["reason_code"], "rendezvous_watch_deadline_elapsed")
            # This observed sleep request, not an artificial exception or
            # missing API, detects renewal beyond the original 200ms lifetime.
            self.assertLessEqual(sum(requested_sleeps), (deadline_ms - initial_wall_ms) / 1000)
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())

    def test_pending_poll_wall_reversal_cannot_exceed_original_monotonic_lifetime(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            fixture.a_log.write_text("")
            fixture.b_log.write_text("")
            initial_wall_ms = 9_850
            deadline_ms = 9_852
            wall_ms = [initial_wall_ms]
            monotonic_s = [0.0]
            requested_sleeps = []
            actual_pending_reads = []
            original_observed_pair = gate.observed_pair

            def observe_actual_pending(*args, **kwargs):
                try:
                    return original_observed_pair(*args, **kwargs)
                except gate.GatePending:
                    actual_pending_reads.append(tuple(len(log.markers) for log in args[0]))
                    # Rethrow the real missing-marker result. The next actual
                    # pending-poll wall read sees rollback, not a new API error.
                    wall_ms[0] -= 1_000
                    raise

            def observed_sleep(seconds):
                requested_sleeps.append(seconds)
                monotonic_s[0] += seconds
                wall_ms[0] += round(seconds * 1000)

            with mock.patch.object(gate, "observed_pair", side_effect=observe_actual_pending):
                result = gate.watch_gate(
                    node_a_log=fixture.a_log, node_b_log=fixture.b_log,
                    gate_path=fixture.probe_gate, evidence_path=fixture.evidence,
                    armed_path=fixture.armed, deadline_ms=deadline_ms,
                    now_ms=lambda: wall_ms[0], sleep=observed_sleep,
                    monotonic=lambda: monotonic_s[0],
                )
            self.assertEqual(actual_pending_reads, [(0, 0)])
            self.assertTrue(fixture.armed.exists())
            self.assertEqual(len(requested_sleeps), 1)
            self.assertGreater(requested_sleeps[0], 0)
            self.assertEqual(result["result"], "rejected")
            self.assertEqual(result["reason_code"], "rendezvous_watch_deadline_elapsed")
            self.assertFalse(fixture.probe_gate.exists())
            self.assertFalse(fixture.business_gate.exists())
            self.assertLessEqual(sum(requested_sleeps), (deadline_ms - initial_wall_ms) / 1000)

    def test_cli_owned_watcher_sigterm_is_reaped_with_cancelled_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = GateFixture(Path(temporary))
            process = subprocess.Popen([
                sys.executable, gate.__file__, "--watch",
                "--node-a-log", str(fixture.a_log), "--node-b-log", str(fixture.b_log),
                "--gate-file", str(fixture.probe_gate), "--evidence-file", str(fixture.evidence),
                "--armed-file", str(fixture.armed),
                "--deadline-ms", str(time.time_ns() // 1_000_000 + 20_000),
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            try:
                deadline = time.monotonic() + 3
                while not fixture.armed.exists() and process.poll() is None and time.monotonic() < deadline:
                    # Readiness supervision only; no activation/late-fence timing
                    # depends on host scheduling in this lifecycle control.
                    select.select([], [], [], 0.01)
                self.assertTrue(fixture.armed.exists())
                process.terminate()
                process.communicate(timeout=3)
                self.assertNotEqual(process.returncode, 0)
                receipt = json.loads(fixture.evidence.read_text())
                self.assertEqual(receipt["reason_code"], "rendezvous_watch_cancelled")
                self.assertFalse(fixture.probe_gate.exists())
                self.assertFalse(fixture.business_gate.exists())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=3)
            self.assertIsNotNone(process.returncode)


class BusinessGateProcesses:
    """Execute the shared production shell helper, with result fixtures.

    Callback token files model successful/failed authenticated captures; no
    real HTTP or daemon barrier is exercised. Generators are owned subprocesses
    that inspect the actual passed business file before emitting a payload.
    """

    def __init__(self, root):
        self.root = root
        self.round = root / "round-1"
        self.round.mkdir()
        self.business = self.round / "business-validation.start-gate"
        for side in ("a", "b"):
            (root / (side + ".token")).write_text("fixture-only")
        helper = Path(gate.__file__).with_name("baseline_gate.sh")
        controller = r"""
set -u
source "$1"
fixture_root=$2
ROUND_DIR="$fixture_root/round-1"
reset_baseline_pair
BARRIER_RESULT=pending
BARRIER_A_CONFIRMED=false
BARRIER_B_CONFIRMED=false
BARRIER_A_HTTP=0
BARRIER_B_HTTP=0
capture_baseline_status() {
  local answer
  printf 'ENTER:%s\n' "$4"
  IFS= read -r answer || return 23
  [[ "$answer" == ok && -s "$3" ]] || return 23
  printf '%s\n' '{"fixture_authenticated_result":true}' >"$2"
}
printf 'READY\n'
while IFS= read -r command; do
  case "$command" in
    CAPTURE)
      if capture_baseline_pair a "$ROUND_DIR/node-a.baseline.status.json" "$fixture_root/a.token" a 101 \
          b "$ROUND_DIR/node-b.baseline.status.json" "$fixture_root/b.token" b 202; then status=0; else status=$?; fi
      printf 'CAPTURE:%s\n' "$status" ;;
    OPEN)
      if release_hard_hard_business_gate "$ROUND_DIR/business-validation.start-gate"; then status=0; else status=$?; fi
      printf 'OPEN:%s\n' "$status" ;;
    BARRIER)
      BARRIER_RESULT=ready
      BARRIER_A_CONFIRMED=true; BARRIER_B_CONFIRMED=true
      BARRIER_A_HTTP=200; BARRIER_B_HTTP=200
      printf 'BARRIER:ready\n' ;;
    NEWROUND)
      ROUND_DIR="$fixture_root/round-2"
      mkdir "$ROUND_DIR"
      reset_baseline_pair
      printf 'NEWROUND:ready\n' ;;
    QUIT) exit 0 ;;
    *) exit 97 ;;
  esac
done
"""
        self.controller = subprocess.Popen(
            ["bash", "-c", controller, "fixture", str(helper), str(root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        generator = r"""
import argparse
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('--overlay-start-gate-file', type=Path, required=True)
args=parser.parse_args()
print('READY', flush=True)
while True:
    try: command=input()
    except EOFError: break
    if command == 'CHECK': print('GENERATED' if args.overlay_start_gate_file.is_file() else 'CLOSED', flush=True)
    elif command == 'QUIT': break
    else: raise SystemExit(97)
"""
        self.generators = [subprocess.Popen(
            [sys.executable, "-u", "-c", generator, "--overlay-start-gate-file", str(self.business)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) for _ in ("a", "b")]
        for child in [self.controller, *self.generators]:
            if self.receive(child) != "READY":
                self.close()
                raise AssertionError("owned fixture child did not become ready")

    @staticmethod
    def receive(child):
        if not select.select([child.stdout], [], [], 3)[0]:
            raise AssertionError("owned fixture protocol exceeded native supervision")
        line = child.stdout.readline()
        if not line:
            raise AssertionError("owned fixture exited before protocol response")
        return line.strip()

    @staticmethod
    def send(child, command):
        child.stdin.write(command + "\n")
        child.stdin.flush()

    def command(self, command):
        self.send(self.controller, command)
        return self.receive(self.controller)

    def observe_generators(self):
        results = []
        for child in self.generators:
            self.send(child, "CHECK")
            results.append(self.receive(child))
        return results

    def close(self):
        results = []
        for child in [self.controller, *self.generators]:
            if child.poll() is None:
                try:
                    self.send(child, "QUIT")
                except (BrokenPipeError, OSError):
                    pass
            try:
                child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=3)
                results.append(False)
            results.append(child.returncode == 0)
        return all(results)


class BusinessGateBehaviorTests(unittest.TestCase):
    def test_business_requires_both_baselines_and_original_barrier_then_generates(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = BusinessGateProcesses(Path(temporary))
            try:
                self.assertEqual(fixture.command("OPEN"), "OPEN:1")
                self.assertEqual(fixture.command("CAPTURE"), "ENTER:a")
                self.assertEqual(fixture.observe_generators(), ["CLOSED", "CLOSED"])
                self.assertEqual(fixture.command("ok"), "ENTER:b")
                self.assertEqual(fixture.observe_generators(), ["CLOSED", "CLOSED"])
                self.assertFalse(fixture.business.exists())
                self.assertEqual(fixture.command("ok"), "CAPTURE:0")
                self.assertEqual(fixture.command("OPEN"), "OPEN:1")
                self.assertEqual(fixture.observe_generators(), ["CLOSED", "CLOSED"])
                self.assertEqual(fixture.command("BARRIER"), "BARRIER:ready")
                self.assertEqual(fixture.command("OPEN"), "OPEN:0")
                self.assertEqual(fixture.observe_generators(), ["GENERATED", "GENERATED"])
                self.assertEqual(fixture.business.stat().st_mode & 0o777, 0o600)
                self.assertEqual(fixture.command("OPEN"), "OPEN:1", "exclusive release must not overwrite")
            finally:
                self.assertTrue(fixture.close(), "all owned controller/generator children must be reaped")

    def test_second_baseline_failure_keeps_business_closed_and_children_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = BusinessGateProcesses(Path(temporary))
            try:
                self.assertEqual(fixture.command("CAPTURE"), "ENTER:a")
                self.assertEqual(fixture.command("ok"), "ENTER:b")
                self.assertEqual(fixture.observe_generators(), ["CLOSED", "CLOSED"])
                self.assertEqual(fixture.command("fail"), "CAPTURE:23")
                self.assertEqual(fixture.command("BARRIER"), "BARRIER:ready")
                self.assertEqual(fixture.command("OPEN"), "OPEN:1")
                self.assertFalse(fixture.business.exists())
                self.assertEqual(fixture.observe_generators(), ["CLOSED", "CLOSED"])
            finally:
                self.assertTrue(fixture.close())

    def test_previous_round_success_cannot_release_new_round_without_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = BusinessGateProcesses(Path(temporary))
            try:
                self.assertEqual(fixture.command("CAPTURE"), "ENTER:a")
                self.assertEqual(fixture.command("ok"), "ENTER:b")
                self.assertEqual(fixture.command("ok"), "CAPTURE:0")
                self.assertEqual(fixture.command("BARRIER"), "BARRIER:ready")
                self.assertEqual(fixture.command("NEWROUND"), "NEWROUND:ready")
                self.assertEqual(fixture.command("OPEN"), "OPEN:1")
                self.assertFalse((fixture.root / "round-2/business-validation.start-gate").exists())
                self.assertEqual(fixture.observe_generators(), ["CLOSED", "CLOSED"])
            finally:
                self.assertTrue(fixture.close())


if __name__ == "__main__":
    unittest.main()
