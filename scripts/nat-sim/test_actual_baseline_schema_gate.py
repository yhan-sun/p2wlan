#!/usr/bin/env python3
"""One complete real CLI test of inline schema-validator exit propagation.

Reuse the unchanged first-four fixture and external inputs. Import its module,
not its TestCase, so discovery of this module adds exactly one test. Neither
the validator nor a production branch/handler is reproduced here.
"""

import json
from pathlib import Path
import sys
import unittest


HERE = Path(__file__).resolve().parent
if not (HERE / "test_actual_round_callers.py").is_file():
    # External candidate location only. Once copied beside the original test
    # by root, normal module import resolves that unchanged sibling instead.
    sys.path.insert(0, str(HERE.parent / "b01-actual-caller-candidate"))
import test_actual_round_callers as actual


class ActualBaselineSchemaGateTests(unittest.TestCase):
    def test_actual_baseline_schema_validator_failure_blocks_business(self):
        self.assertEqual(actual.digest(Path(actual.__file__)),
                         "1ca4209403db3b8ef9b7c73b72b41620c797deb168983b5ebbdd05d1a538c4fb",
                         "Original first-four fixture changed (not a product RED)")
        self.assertEqual(actual.digest(actual.EXTERNAL_TOOLS),
                         "b6e56e156abf4f649cff86358eb34ad638f1c3b6864f47ac2c1cabd53e09cbfa",
                         "Original external inputs changed (not a product RED)")
        fixture = actual.ActualRoundCallerTests.fixture(self, "baseline-failure")
        # execute() has already proved every one of the five real owned
        # children received TERM, was waited by the owning original shell,
        # and disappeared. It also proved real port reservation/release.
        # Close now, before the target, to include the unrelated sentinel's
        # cooperative TERM and actual wait 0 among mandatory prerequisites.
        fixture.close()
        sentinel = json.loads((fixture.root / "sentinel-cleanup.json").read_text())
        self.assertTrue(sentinel["wait_completed"], "Sentinel wait missing (not a product RED)")
        self.assertEqual(sentinel["wait_status"], 0, "Sentinel wait failed (not a product RED)")
        self.assertFalse(fixture.rescued, "Supervisor rescue occurred (not a product RED)")

        directory = fixture.artifacts / "round-1"
        malformed = json.loads((directory / "node-b.baseline.status.json").read_text())
        self.assertEqual(malformed, {"fixture_only": True,
                                    "malformed_status_for_original_schema_gate": True},
                         "Declared malformed baseline input absent (not a product RED)")
        self.assertIn("status_schema_incomplete", fixture.stderr,
                      "Original inline validator failure not observed (not a product RED)")
        a = json.loads((directory / "node-a.baseline.readiness.json").read_text())
        b = json.loads((directory / "node-b.baseline.readiness.json").read_text())
        self.assertEqual(a["result"], "ready", "Control baseline did not become ready (not a product RED)")
        for readiness in (a, b):
            self.assertTrue(readiness["process_alive"], "Daemon was not live at baseline (not a product RED)")
            self.assertTrue(readiness["token_present"], "Diagnostics token absent (not a product RED)")
            self.assertEqual(readiness["attempts"], 1, "Baseline did not use one original attempt (not a product RED)")
        b_calls = [row for row in fixture.events if row["tool"] == "curl"
                   and row["round"] == 1 and row["side"] == "b"
                   and row["output"] is not None and ".baseline.status.json" in row["output"]]
        self.assertEqual(len(b_calls), 1, "Original baseline HTTP call missing/duplicated (not a product RED)")

        observed = {"cli_exit_status": fixture.cli_status,
                    "baseline_b_result": b["result"],
                    "baseline_b_reason": b["reason_code"],
                    "business_gate_exists": (directory / "business-validation.start-gate").exists(),
                    "node_a_business_exists": (directory / "node-a.fixture-business.json").exists(),
                    "node_b_business_exists": (directory / "node-b.fixture-business.json").exists(),
                    "original_collector_started": any(row["tool"] == "original_collector_enter"
                                                      for row in fixture.events)}
        self.assertEqual(observed,
                         {"cli_exit_status": 1, "baseline_b_result": "schema_invalid",
                          "baseline_b_reason": "status_schema_invalid", "business_gate_exists": False,
                          "node_a_business_exists": False, "node_b_business_exists": False,
                          "original_collector_started": False},
                         "B01_ACTUAL_SCHEMA_EXIT_PROPAGATION: original validator failure must close the baseline pair")
        actual.ActualRoundCallerTests.invalid_denominator(self, fixture)


if __name__ == "__main__":
    unittest.main()
