#!/usr/bin/env python3
"""Real process boundaries for the harness clock and expired command fence."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def kernel_ns():
    # Independent oracle: do not import the production clock into the parent.
    if sys.platform == "darwin":
        return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)
    return time.monotonic_ns()


class SharedClockProcesses(unittest.TestCase):
    def run_python(self, *arguments):
        return subprocess.run([sys.executable, *map(str, arguments)], cwd=HERE,
                              text=True, capture_output=True, timeout=3, check=True)

    def assert_bracketed(self, before, value, after):
        self.assertLessEqual(before // 1_000_000, value)
        self.assertLessEqual(value, after // 1_000_000)

    def test_separate_finalizer_processes_share_kernel_epoch(self):
        before = kernel_ns()
        first = int(self.run_python(HERE / "round_finalization.py", "now").stdout)
        second = int(self.run_python(HERE / "round_finalization.py", "now").stdout)
        after = kernel_ns()
        self.assert_bracketed(before, first, after)
        self.assert_bracketed(before, second, after)
        self.assertLessEqual(first, second)

    def test_shell_reader_shares_finalizer_epoch(self):
        environment = dict(os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"])
        before = kernel_ns()
        result = subprocess.run(["/bin/bash", "-c",
                                 'ROOT_DIR=$1; source "$ROOT_DIR/scripts/nat-sim/round_cleanup.sh"; _round_now',
                                 "clock-test", str(ROOT)], env=environment, text=True,
                                capture_output=True, timeout=3, check=True)
        self.assert_bracketed(before, int(result.stdout), kernel_ns())

    def test_origin_preserves_conservative_wall_projection(self):
        before, wall_before = kernel_ns(), time.time_ns()
        values = self.run_python(HERE / "monotonic_clock.py", "origin").stdout.split()
        wall_after, after = time.time_ns(), kernel_ns()
        self.assertEqual(len(values), 3)
        monotonic_ms, wall_seconds, wall_ceil_ms = map(int, values)
        self.assert_bracketed(before, monotonic_ms, after)
        self.assertLessEqual(wall_before // 1_000_000_000, wall_seconds)
        self.assertLessEqual(wall_seconds, wall_after // 1_000_000_000)
        self.assertLessEqual((wall_before + 999_999) // 1_000_000, wall_ceil_ms)
        self.assertLessEqual(wall_ceil_ms, (wall_after + 999_999) // 1_000_000)
        self.assertLessEqual(wall_seconds * 1000, wall_ceil_ms)
        self.assertLessEqual(wall_ceil_ms, (wall_seconds + 1) * 1000)

    def test_expired_parent_deadline_cannot_start_real_command(self):
        with tempfile.TemporaryDirectory(prefix="p2wlan-shared-clock-") as directory:
            root = Path(directory)
            marker, receipt = root / "unexpected-command", root / "receipt.json"
            now = kernel_ns() // 1_000_000
            result = subprocess.run([
                sys.executable, str(HERE / "round_finalization.py"), "run",
                "--deadline-ms", str(now - 1), "--grace-end-ms", str(now + 1000),
                "--receipt", str(receipt), "--", sys.executable, "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('started')", str(marker),
            ], text=True, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(marker.exists())
            value = json.loads(receipt.read_text())
            self.assertEqual(value["reason_code"], "deadline_exhausted")
            self.assertEqual(value["result"], "unknown")
            self.assertIs(value["started"], False)
            self.assertNotIn("pid", value)

    def test_trace_and_continuity_samples_share_parent_epoch(self):
        with tempfile.TemporaryDirectory(prefix="p2wlan-clock-evidence-") as directory:
            root = Path(directory)
            for side in ("a", "b"):
                (root / ("node-" + side + ".log")).write_text("overlay_payload_verified ingress=direct\n")
            before = kernel_ns()
            self.run_python("-c", "from nat_sim import NatTrace; import sys; "
                            "trace=NatTrace(sys.argv[1]); trace.record('clock_control'); trace.close()",
                            root / "nat-trace.jsonl")
            self.run_python("-c", "from continuity_evidence import sample; from pathlib import Path; "
                            "import sys; sample(Path(sys.argv[1]))", root)
            after = kernel_ns()
            trace = json.loads((root / "nat-trace.jsonl").read_text())
            sample = json.loads((root / "business-samples.jsonl").read_text())
            stamps = [trace["monotonic_ns"], sample["monotonic_ns"], sample["completed_monotonic_ns"]]
            self.assertEqual(stamps, sorted(stamps))
            for stamp in stamps:
                self.assertLessEqual(before, stamp)
                self.assertLessEqual(stamp, after)
            self.assertEqual((sample["a"], sample["b"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
