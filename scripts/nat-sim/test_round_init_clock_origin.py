#!/usr/bin/env python3
"""Original budget reuse at real initialization; controlled clocks only."""

from __future__ import annotations

import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
ORIGIN = """
ROUND_CLOCK_ORIGIN_UNIX_S=1000
ROUND_CLOCK_ORIGIN_SECONDS=100
ROUND_CLOCK_ORIGIN_MONOTONIC_MS=123000
ROUND_CLOCK_ORIGIN_UNIX_MS=1000250
"""
PRELUDE = r'''
set -euxo pipefail
umask 077
ROOT_DIR=$1; ROUND_DIR=$2
PIDS=(); RELAY_PIDS=(); overall=0
unset ROUND_CLOCK_ORIGIN_UNIX_S ROUND_CLOCK_ORIGIN_UNIX_MS
unset ROUND_CLOCK_ORIGIN_MONOTONIC_MS ROUND_CLOCK_ORIGIN_SECONDS
unset SECONDS
SECONDS=100
ROUND_DEADLINE=120; WORK_DEADLINE=120
source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"
_snapshot() {
  printf 'exit\t%s\nend\t%s\nresource\t%s\ncause\t%s\npending\t%s\n' \
    "$1" "${_ROUND_CAPTURE_END_MS:-unset}" "${_ROUND_RESOURCE_END_MS:-unset}" \
    "${ROUND_FINISH_REASON:-}" "${#PIDS[@]}" >"$ROUND_DIR/snapshot.tsv"
}
trap '_snapshot "$?"' EXIT
'''


class RoundInitClockOriginTests(unittest.TestCase):
    def run_shell(self, body, label="case", clock_status=0):
        destination = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if destination:
            root = Path(destination) / (self._testMethodName + "-" + label)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-init-origin-")
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name) / label
        root.mkdir(mode=0o700)
        clock = ('_round_now() { printf "called\\n" >>"$ROUND_DIR/clock.calls"; '
                 'printf "123500\\n"; return %d; }\n' % clock_status)
        program = PRELUDE + clock + body + "\n"
        with (root / "controller.sh").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(program)
        process = subprocess.Popen(["/bin/bash", str(root / "controller.sh"), str(REPOSITORY), str(root)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                   env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=1)
            self.fail("init origin fixture protocol timeout")
        for name, data in (("stdout.log", stdout), ("stderr.log", stderr)):
            with (root / name).open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
        snapshot = dict(line.split("\t", 1) for line in (root / "snapshot.tsv").read_text().splitlines())
        self.assertEqual(int(snapshot["exit"]), process.returncode)
        self.assertEqual(snapshot["resource"], "0")
        self.assertEqual(snapshot["cause"], "")
        self.assertEqual(snapshot["pending"], "0")
        calls = (root / "clock.calls").read_text().splitlines() if (root / "clock.calls").exists() else []
        self.assertTrue(all(row == "called" for row in calls))
        return process.returncode, root, snapshot, stderr.decode(), len(calls)

    def test_late_init_reuses_original_deadline_and_later_capture_can_only_tighten(self):
        result = self.run_shell(ORIGIN + r'''
ROUND_DEADLINE=101
SECONDS=103
round_init business
printf '%s\n' "$_ROUND_CAPTURE_END_MS" >"$ROUND_DIR/initial-end"
_round_capture_window 999000 1000
printf '%s\n' "$_ROUND_CAPTURE_END_MS" >"$ROUND_DIR/late-end"
_ROUND_CAPTURE_END_MS=123400
_round_capture_window 999000 1000
''', clock_status=7)
        self.assertEqual(result[0], 0, "original origin must not depend on a second native sample")
        self.assertEqual((result[1] / "initial-end").read_text().strip(), "123750")
        self.assertEqual((result[1] / "late-end").read_text().strip(), "123750")
        self.assertEqual(result[2]["end"], "123400")
        self.assertEqual(result[4], 0)

    def test_valid_wall_ceil_boundary_and_crossed_parent_second_remain_conservative(self):
        result = self.run_shell(ORIGIN + """
ROUND_CLOCK_ORIGIN_UNIX_MS=1001000
ROUND_CLOCK_ORIGIN_SECONDS=101
ROUND_DEADLINE=104
SECONDS=103
round_init business
""")
        self.assertEqual(result[0], 0)
        self.assertEqual(result[2]["end"], "125000")
        self.assertEqual(result[4], 0, "valid original packet needs no second native sample")

    def test_present_invalid_origin_hard_fails_without_native_fallback(self):
        cases = (
            "ROUND_CLOCK_ORIGIN_MONOTONIC_MS=123000",
            "ROUND_CLOCK_ORIGIN_MONOTONIC_MS=''; ROUND_CLOCK_ORIGIN_SECONDS=''\n"
            "ROUND_CLOCK_ORIGIN_UNIX_S=''; ROUND_CLOCK_ORIGIN_UNIX_MS=''",
            ORIGIN + "ROUND_CLOCK_ORIGIN_MONOTONIC_MS=0123000",
            ORIGIN + "ROUND_CLOCK_ORIGIN_UNIX_MS=1001001",
            ORIGIN + "ROUND_CLOCK_ORIGIN_SECONDS=10000000000",
            ORIGIN + "ROUND_DEADLINE=0101",
            ORIGIN + "ROUND_CLOCK_ORIGIN_MONOTONIC_MS=1; ROUND_DEADLINE=100",
        )
        for index, origin in enumerate(cases):
            with self.subTest(index=index):
                result = self.run_shell(origin + "\nround_init business", str(index))
                self.assertEqual(result[0], 1)
                self.assertEqual(result[2]["end"], "0")
                self.assertEqual(result[4], 0, "invalid present packet cannot sample a native fallback")

    def test_all_unset_keeps_native_conversion_and_original_failure_status(self):
        result = self.run_shell("round_init business", "native-ok")
        self.assertEqual(result[0], 0)
        observed = re.findall(r"^\+ observed_seconds=([0-9]+)$", result[3], re.MULTILINE)
        self.assertEqual(len(observed), 1)
        self.assertEqual(int(result[2]["end"]), 123500 + (120 - int(observed[0]) - 1) * 1000)
        self.assertEqual(result[4], 1)
        failed = self.run_shell("round_init business", "native-failure", clock_status=7)
        self.assertEqual(failed[0], 7)
        self.assertEqual(failed[2]["end"], "0")
        self.assertEqual(failed[4], 1)


if __name__ == "__main__":
    unittest.main()
