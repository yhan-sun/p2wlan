#!/usr/bin/env python3
"""Fixed-window samples, clock errors and immutable capture/resource deadlines."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
import test_capture_window_observation as legacy

COMMON = r"""
unset ROUND_CLOCK_ORIGIN_MONOTONIC_MS ROUND_CLOCK_ORIGIN_UNIX_MS
unset ROUND_CLOCK_ORIGIN_UNIX_S ROUND_CLOCK_ORIGIN_SECONDS
FINALIZE_BUDGET_S=15; ROUND_CLEANUP_GRACE_MS=1000
_snapshot_plus() {
  _snapshot "$1"
  printf 'finalizer\t%s\n' "$_ROUND_FINALIZER_START_MS" >>"$ROUND_DIR/snapshot.tsv"
}
trap '_snapshot_plus "$?"' EXIT
_round_now() {
  printf '123500\n' >>"$ROUND_DIR/clock.calls"
  printf '123500\n'
}
"""
ORIGIN = r"""
ROUND_CLOCK_ORIGIN_MONOTONIC_MS=123000
ROUND_CLOCK_ORIGIN_UNIX_S=1000
ROUND_CLOCK_ORIGIN_UNIX_MS=1000250
ROUND_CLOCK_ORIGIN_SECONDS=100
"""
EXISTING = r"""
_ROUND_CAPTURE_END_MS=111111
_ROUND_RESOURCE_END_MS=222222
_ROUND_FINALIZER_START_MS=333333
"""

class FixedWindowSampleReuseTests(unittest.TestCase):
    def run_shell(self, body, label="case"):
        destination = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if destination:
            root = Path(destination) / (self._testMethodName + "-" + label)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-fixed-window-")
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name) / label
        root.mkdir(mode=0o700)
        program = legacy.PRELUDE + COMMON + "\n" + body + "\n"
        with (root / "controller.sh").open("x") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(program)
        process = subprocess.Popen(
            ["/bin/bash", str(root / "controller.sh"), str(legacy.REPOSITORY), str(root)],
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
        self.assertEqual(snapshot["cause"], "sentinel")
        self.assertEqual(snapshot["sequence"], "0")
        self.assertEqual(snapshot["pending"], "0")
        calls = (root / "clock.calls").read_text().splitlines()
        trace_calls = sum(line.lstrip("+ ") == "_round_now" for line in stderr.decode().splitlines())
        self.assertEqual(trace_calls, len(calls), "actual function calls must match persistent sample observations")
        return process.returncode, root, snapshot, calls

    def assert_windows(self, result, rc, capture, resource, finalizer, samples):
        self.assertEqual(result[0], rc)
        self.assertEqual(result[2]["end"], str(capture))
        self.assertEqual(result[2]["resource"], str(resource))
        self.assertEqual(result[2]["finalizer"], str(finalizer))
        self.assertEqual(result[3], samples)

    def test_fixed_origin_reuses_one_native_sample(self):
        result = self.run_shell(ORIGIN + "\n_round_fixed_windows\n")
        self.assert_windows(result, 0, 142750, 124500, 123500, ["123500"])

    def test_clock_73_preserves_existing_windows(self):
        result = self.run_shell(ORIGIN + EXISTING + r"""
_round_now() { printf 'failure73\n' >>"$ROUND_DIR/clock.calls"; return 73; }
if _round_fixed_windows; then status=0; else status=$?; fi
exit "$status"
""")
        self.assert_windows(result, 73, 111111, 222222, 333333, ["failure73"])

    def test_partial_origin_hard_fails_without_second_sample(self):
        result = self.run_shell(EXISTING + r"""
ROUND_CLOCK_ORIGIN_MONOTONIC_MS=123000
if _round_fixed_windows; then status=0; else status=$?; fi
exit "$status"
""")
        self.assert_windows(result, 1, 111111, 222222, 333333, ["123500"])

    def test_all_unset_keeps_two_native_samples(self):
        result = self.run_shell(r"""
_round_now() {
  local value=123500
  [[ ! -f "$ROUND_DIR/clock.calls" ]] || value=124000
  printf '%s\n' "$value" >>"$ROUND_DIR/clock.calls"
  printf '%s\n' "$value"
}
_round_fixed_windows
""")
        self.assert_windows(result, 0, 143000, 124500, 123500, ["123500", "124000"])

    def test_repeated_fixed_windows_never_renew(self):
        result = self.run_shell(ORIGIN + r"""
_round_now() {
  local value=123500
  [[ ! -f "$ROUND_DIR/clock.calls" ]] || value=125500
  printf '%s\n' "$value" >>"$ROUND_DIR/clock.calls"
  printf '%s\n' "$value"
}
_round_fixed_windows
printf '%s\t%s\t%s\n' "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" "$_ROUND_FINALIZER_START_MS" >"$ROUND_DIR/history.tsv"
ROUND_DEADLINE=121; SECONDS=101; ROUND_CLEANUP_GRACE_MS=15000
_round_fixed_windows
printf '%s\t%s\t%s\n' "$_ROUND_CAPTURE_END_MS" "$_ROUND_RESOURCE_END_MS" "$_ROUND_FINALIZER_START_MS" >>"$ROUND_DIR/history.tsv"
ROUND_DEADLINE=119
_round_fixed_windows
""")
        self.assertEqual((result[1] / "history.tsv").read_text().splitlines(),
                         ["142750\t124500\t123500", "142750\t124500\t123500"])
        self.assert_windows(result, 0, 141750, 124500, 123500, ["123500", "125500", "125500"])

if __name__ == "__main__":
    unittest.main()
