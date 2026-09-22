#!/usr/bin/env python3
"""Tests for the fail-closed Hard<->Hard simulator gate release."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hard_hard_gate import GateError, extract_punch_at_ms, plan_gate, release_gate


class HardHardGateTests(unittest.TestCase):
    def test_extracts_latest_typed_rendezvous_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "node.log"
            log.write_text(
                'event="hard_hard_rendezvous_scheduled" punch_at_ms=1000\n'
                'event="unrelated" punch_at_ms=9999\n'
                'event="hard_hard_rendezvous_scheduled" punch_at_ms=2000\n',
                encoding="utf-8",
            )
            self.assertEqual(extract_punch_at_ms(log), 2000)

    def test_plan_rejects_skew_future_and_elapsed_deadline(self):
        common = dict(max_skew_ms=250, lead_ms=10, max_future_ms=5000, max_late_ms=25)
        with self.assertRaisesRegex(GateError, "rendezvous_skew_exceeded"):
            plan_gate(10_000, 10_251, 9_000, **common)
        with self.assertRaisesRegex(GateError, "rendezvous_deadline_too_far"):
            plan_gate(20_000, 20_001, 10_000, **common)
        with self.assertRaisesRegex(GateError, "rendezvous_deadline_elapsed"):
            plan_gate(10_000, 10_001, 10_026, **common)

    def test_release_writes_private_gate_and_evidence_at_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = plan_gate(
                10_000,
                10_002,
                9_000,
                max_skew_ms=250,
                lead_ms=10,
                max_future_ms=5000,
                max_late_ms=25,
            )
            clock = iter((9_000, 9_991))
            sleeps: list[float] = []
            evidence = release_gate(
                plan,
                root / "direct.open",
                root / "gate.json",
                max_late_ms=25,
                now_ms=lambda: next(clock),
                sleep=sleeps.append,
            )
            self.assertEqual(sleeps, [0.99])
            self.assertEqual(evidence["release_offset_from_earliest_punch_ms"], -9)
            self.assertEqual((root / "direct.open").stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "gate.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((root / "gate.json").read_text())["result"], "released")

    def test_release_fails_closed_after_scheduler_delay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = plan_gate(
                10_000,
                10_001,
                9_000,
                max_skew_ms=250,
                lead_ms=10,
                max_future_ms=5000,
                max_late_ms=25,
            )
            clock = iter((9_000, 10_026))
            with self.assertRaisesRegex(GateError, "rendezvous_release_late"):
                release_gate(
                    plan,
                    root / "direct.open",
                    root / "gate.json",
                    max_late_ms=25,
                    now_ms=lambda: next(clock),
                    sleep=lambda _seconds: None,
                )
            self.assertFalse((root / "direct.open").exists())


if __name__ == "__main__":
    unittest.main()
