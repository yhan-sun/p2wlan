from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("aggregate_evidence.py")
SPEC = importlib.util.spec_from_file_location("cross_task_aggregate", MODULE_PATH)
assert SPEC and SPEC.loader
aggregate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(aggregate)

SHA = "a" * 40
WORKFLOW_SHA = "b" * 40

CONTRACT = {
    "schema_version": 1,
    "repository": "yhan-sun/p2wlan",
    "trigger_marker": "client/daemon/cross_task_integration_gate_version.txt",
    "required_checks": [
        {"name": "A Required", "category": "a"},
        {"name": "B Required", "category": "b"},
    ],
}


def snapshot():
    return {
        "repository": "yhan-sun/p2wlan",
        "source_head_sha": SHA,
        "checks": [
            {
                "name": "A Required",
                "id": 1,
                "status": "completed",
                "conclusion": "success",
                "details_url": "https://example.invalid/a",
            },
            {
                "name": "B Required",
                "id": 2,
                "status": "completed",
                "conclusion": "success",
                "details_url": "https://example.invalid/b",
            },
        ],
    }


class CrossTaskEvidenceTests(unittest.TestCase):
    def build(self, *, contract=None, evidence=None):
        return aggregate.build_manifest(
            contract=copy.deepcopy(contract or CONTRACT),
            snapshot=copy.deepcopy(evidence or snapshot()),
            repository="yhan-sun/p2wlan",
            source_head_sha=SHA,
            workflow_sha=WORKFLOW_SHA,
            event_name="pull_request",
            run_id="123",
            run_attempt="1",
        )

    def test_valid_manifest_passes(self):
        value = self.build()
        self.assertEqual(value["result"], "pass")
        self.assertTrue(value["no_skipped_required_gate"])
        self.assertEqual(value["observed_required_check_count"], 2)

    def test_missing_required_check_fails(self):
        value = snapshot()
        value["checks"].pop()
        result = self.build(evidence=value)
        self.assertEqual(result["result"], "fail")
        self.assertIn("missing:B Required", result["reasons"])

    def test_skipped_required_check_fails(self):
        value = snapshot()
        value["checks"][1]["conclusion"] = "skipped"
        result = self.build(evidence=value)
        self.assertEqual(result["result"], "fail")
        self.assertFalse(result["no_skipped_required_gate"])

    def test_failed_required_check_fails(self):
        value = snapshot()
        value["checks"][0]["conclusion"] = "failure"
        result = self.build(evidence=value)
        self.assertEqual(result["result"], "fail")
        self.assertIn("not_success:A Required:failure", result["reasons"])

    def test_pending_required_check_fails(self):
        value = snapshot()
        value["checks"][0]["status"] = "in_progress"
        value["checks"][0]["conclusion"] = None
        result = self.build(evidence=value)
        self.assertEqual(result["result"], "fail")
        self.assertIn("not_completed:A Required:in_progress", result["reasons"])

    def test_snapshot_sha_mismatch_is_rejected(self):
        value = snapshot()
        value["source_head_sha"] = "c" * 40
        with self.assertRaises(aggregate.EvidenceError):
            self.build(evidence=value)

    def test_duplicate_contract_check_is_rejected(self):
        contract = copy.deepcopy(CONTRACT)
        contract["required_checks"].append({"name": "A Required", "category": "duplicate"})
        with self.assertRaises(aggregate.EvidenceError):
            self.build(contract=contract)

    def test_duplicate_snapshot_check_fails_closed(self):
        value = snapshot()
        value["checks"].append(copy.deepcopy(value["checks"][0]))
        result = self.build(evidence=value)
        self.assertEqual(result["result"], "fail")
        self.assertIn("duplicate_checks:A Required", result["reasons"])


if __name__ == "__main__":
    unittest.main()
