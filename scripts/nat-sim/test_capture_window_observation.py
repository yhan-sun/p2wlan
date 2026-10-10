#!/usr/bin/env python3
"""Clock-coordinate contracts; controlled tuple inputs are not native CLI proof."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]

PRELUDE = r'''
set -euxo pipefail
umask 077
ROOT_DIR=$1; ROUND_DIR=$2
PIDS=(); RELAY_PIDS=(); overall=0
ROUND_RUN_ID=clock-coordinate-unit
source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"
round_init
unset SECONDS
SECONDS=100
ROUND_DEADLINE=120; WORK_DEADLINE=120
NODE_A_PID=$$; NODE_B_PID=$$
ROUND_FINISH_REASON=sentinel
_snapshot() {
  printf 'exit\t%s\nend\t%s\nresource\t%s\ncause\t%s\nsequence\t%s\npending\t%s\nresult\t%s\n' \
    "$1" "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" "$ROUND_FINISH_REASON" \
    "$_ROUND_HTTP_PAIR_SEQUENCE" "${#PIDS[@]}" "${BARRIER_RESULT:-unset}" >"$ROUND_DIR/snapshot.tsv"
}
trap '_snapshot "$?"' EXIT
'''


class CaptureWindowObservationTests(unittest.TestCase):
    def run_shell(self, body, label="case", barrier=False):
        destination = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if destination:
            root = Path(destination) / (self._testMethodName + "-" + label)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-clock-coordinate-")
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name) / label
        root.mkdir(mode=0o700)
        functions = ""
        if barrier:
            text = (HERE / "nat-sim-smoke.sh").read_text()
            start = "write_barrier_readiness() {"
            end = 'source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"'
            self.assertEqual(text.count(start), 1)
            self.assertEqual(text.count(end), 1)
            functions = text[text.index(start):text.index(end)]
        program = PRELUDE + functions + "\n" + body + "\n"
        with (root / "controller.sh").open("x") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(program)
        process = subprocess.Popen(
            ["/bin/bash", str(root / "controller.sh"), str(REPOSITORY), str(root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=1)
            self.fail("clock fixture protocol timeout")
        for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
            with (root / name).open("xb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(data)
        snapshot = dict(line.split("\t", 1) for line in (root / "snapshot.tsv").read_text().splitlines())
        self.assertEqual(int(snapshot["exit"]), process.returncode)
        self.assertEqual(snapshot["resource"], "0")
        self.assertEqual(snapshot["cause"], "sentinel")
        self.assertEqual(snapshot["sequence"], "0")
        self.assertEqual(snapshot["pending"], "0")
        clock_calls = sum(line.lstrip("+ ") == "_round_now" for line in stderr.decode().splitlines())
        return process.returncode, root, snapshot, stdout.decode(), stderr.decode(), clock_calls

    def test_tuple_preserves_the_observed_shell_coordinate(self):
        result = self.run_shell(r'''
capture_now=$(_round_now); capture_seconds=$SECONDS
SECONDS=101
_round_capture_window "$capture_now" "$capture_seconds"
printf '%s\n' "$((capture_now + 19000))"
''')
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["end"], result[3].strip())
        self.assertEqual(result[5], 1, "tuple consumption must not start another clock")

    def test_tuple_never_renews_an_existing_capture_end(self):
        result = self.run_shell(r'''
capture_now=$(_round_now)
_ROUND_CAPTURE_END_MS=$((capture_now - 1))
_round_capture_window "$capture_now" "$SECONDS"
printf '%s\n' "$((capture_now - 1))"
''')
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["end"], result[3].strip())

    def test_remaining_one_zero_and_negative_have_no_positive_window(self):
        for remaining in (1, 0, -1):
            with self.subTest(remaining=remaining):
                result = self.run_shell('capture_now=$(_round_now)\nROUND_DEADLINE=%s\n'
                                        '_round_capture_window "$capture_now" "$SECONDS"\n'
                                        'printf "%%s\\n" "$capture_now"' % (100 + remaining), str(remaining))
                self.assertEqual(result[0], 0)
                self.assertEqual(result[2]["end"], result[3].strip())

    def test_no_argument_keeps_original_native_capture(self):
        result = self.run_shell("_round_capture_window")
        self.assertEqual(result[0], 0)
        observed = re.findall(r"^\+ now=([0-9]+)$", result[4], re.MULTILINE)
        self.assertEqual(len(observed), 1)
        self.assertEqual(int(result[2]["end"]), int(observed[0]) + 19000)
        self.assertEqual(result[5], 1)

    def test_partial_or_extra_tuple_hard_fails_before_capture(self):
        for arguments in ('12345', '12345 100 extra'):
            with self.subTest(arguments=arguments):
                result = self.run_shell("_round_capture_window " + arguments, str(len(arguments.split())))
                self.assertEqual(result[0], 1)
                self.assertEqual(result[2]["end"], "0")
                self.assertEqual(result[5], 0)

    def test_invalid_or_overflow_tuple_hard_fails_before_arithmetic(self):
        arguments = ('"" 100', '012345 100', '12345 -1', '12345 0100',
                     '9999999999999999 100', '12345 10000000000', 'not-a-number 100')
        for index, values in enumerate(arguments):
            with self.subTest(arguments=values):
                result = self.run_shell("_round_capture_window " + values, str(index))
                self.assertEqual(result[0], 1)
                self.assertEqual(result[2]["end"], "0")
                self.assertEqual(result[5], 0)

    def test_native_clock_failure_does_not_consume_previous_end(self):
        result = self.run_shell('_ROUND_CAPTURE_END_MS=12345\n_round_now() { return 73; }\n_round_capture_window')
        self.assertEqual(result[0], 73)
        self.assertEqual(result[2]["end"], "12345")

    def test_malformed_native_clock_preserves_existing_end(self):
        result = self.run_shell('_ROUND_CAPTURE_END_MS=12345\n'
                                '_round_now() { printf "invalid\\n"; }\n_round_capture_window')
        self.assertEqual(result[0], 1)
        self.assertEqual(result[2]["end"], "12345")

    def test_barrier_malformed_fresh_clock_starts_no_fetch(self):
        result = self.run_shell(r'''
_round_now() {
  if [[ -f "$ROUND_DIR/clock-observed" ]]; then printf 'invalid\n';
  else touch "$ROUND_DIR/clock-observed"; printf '123500\n'; fi
}
fetch_relay_barrier_status_pair() { touch "$ROUND_DIR/unexpected-fetch"; }
wait_for_relay_confirmation_barrier 102
''', barrier=True)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[2]["end"], "142500")
        self.assertEqual(result[2]["result"], "unset")
        self.assertFalse((result[1] / "unexpected-fetch").exists())
        self.assertFalse((result[1] / "relay-barrier.readiness.json").exists())

    def test_barrier_zero_window_uses_one_initial_native_observation(self):
        result = self.run_shell('wait_for_relay_confirmation_barrier 101', barrier=True)
        self.assertEqual(result[0], 0)
        self.assertEqual(result[5], 1)
        self.assertEqual(result[2]["result"], "barrier_timeout")
        readiness = json.loads((result[1] / "relay-barrier.readiness.json").read_text())
        self.assertEqual(readiness["reason_code"], "relay_peer_confirmation_timeout")

    def test_barrier_bad_clock_is_hard_failure_not_timeout_footer(self):
        result = self.run_shell('_round_now() { printf "invalid\\n"; }\n'
                                'wait_for_relay_confirmation_barrier 101', barrier=True)
        self.assertEqual(result[0], 1)
        self.assertEqual(result[2]["end"], "0")
        self.assertEqual(result[2]["result"], "unset")
        self.assertFalse((result[1] / "relay-barrier.readiness.json").exists())


if __name__ == "__main__":
    unittest.main()
