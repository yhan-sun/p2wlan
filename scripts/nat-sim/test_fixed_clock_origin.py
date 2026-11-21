#!/usr/bin/env python3
"""Fixed deadline coordinates; native outer callers prove the production path."""

from __future__ import annotations

import json
import unittest

import test_capture_window_observation as clock_fixture


ORIGIN = """
ROUND_CLOCK_ORIGIN_UNIX_S=1000
ROUND_CLOCK_ORIGIN_SECONDS=100
ROUND_CLOCK_ORIGIN_MONOTONIC_MS=123000
ROUND_CLOCK_ORIGIN_UNIX_MS=1000250
"""


class FixedClockOriginTests(unittest.TestCase):
    run_shell = clock_fixture.CaptureWindowObservationTests.run_shell

    def test_fractional_remaining_time_survives_late_capture(self):
        result = self.run_shell(ORIGIN + """
ROUND_DEADLINE=101
_round_capture_window 123500 100
""")
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["end"], "123750")
        self.assertEqual(result[5], 0)

    def test_repeated_capture_cannot_move_the_fixed_deadline(self):
        result = self.run_shell(ORIGIN + """
ROUND_DEADLINE=101
_round_capture_window 123500 100
_round_capture_window 123600 100
_round_capture_window 124000 101
""")
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["end"], "123750")

    def test_existing_earlier_capture_remains_authoritative(self):
        result = self.run_shell(ORIGIN + """
ROUND_DEADLINE=101
_ROUND_CAPTURE_END_MS=123400
_round_capture_window 123500 100
""")
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["end"], "123400")

    def test_partial_invalid_and_inconsistent_origin_hard_fail(self):
        cases = (
            "ROUND_CLOCK_ORIGIN_MONOTONIC_MS=123000",
            ORIGIN + "ROUND_CLOCK_ORIGIN_MONOTONIC_MS=0123000",
            ORIGIN + "ROUND_CLOCK_ORIGIN_UNIX_MS=1001001",
            ORIGIN + "ROUND_CLOCK_ORIGIN_SECONDS=10000000000",
            ORIGIN + "ROUND_CLOCK_ORIGIN_UNIX_S=not-a-number",
        )
        for index, origin in enumerate(cases):
            with self.subTest(index=index):
                result = self.run_shell(origin + "\n_round_capture_window 123500 100", str(index))
                self.assertEqual(result[0], 1)
                self.assertEqual(result[2]["end"], "0")

    def test_barrier_fetch_receives_fixed_stage_round_and_work_cutoffs(self):
        result = self.run_shell(ORIGIN + r'''
WORK_DEADLINE=101
_round_now() { printf '123500\n'; }
fetch_relay_barrier_status_pair() {
  printf '%s\n' "$@" >"$ROUND_DIR/fetch-cutoffs"
  BARRIER_FETCH_A_HTTP=200; BARRIER_FETCH_B_HTTP=200
  BARRIER_FETCH_A_OK=1; BARRIER_FETCH_B_OK=1
}
node_task_health_ok() { printf '1\n'; }
printf 'event="relay_peer_confirmed"\n' >"$ROUND_DIR/node-a.log"
printf 'event="relay_peer_confirmed"\n' >"$ROUND_DIR/node-b.log"
wait_for_relay_confirmation_barrier 101
''', barrier=True)
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["result"], "ready")
        self.assertEqual((result[1] / "fetch-cutoffs").read_text().splitlines(),
                         ["1", "123750", "142750", "123750"])
        self.assertEqual(result[5], 2)

    def test_expired_projection_does_not_open_a_fetch(self):
        result = self.run_shell(ORIGIN + r'''
WORK_DEADLINE=101
_round_now() { printf '124000\n'; }
fetch_relay_barrier_status_pair() { touch "$ROUND_DIR/unexpected-fetch"; }
wait_for_relay_confirmation_barrier 101
''', barrier=True)
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["result"], "barrier_timeout")
        self.assertEqual(result[2]["end"], "142750")
        self.assertFalse((result[1] / "unexpected-fetch").exists())
        readiness = json.loads((result[1] / "relay-barrier.readiness.json").read_text())
        self.assertEqual(readiness["reason_code"], "relay_peer_confirmation_timeout")


if __name__ == "__main__":
    unittest.main()
