#!/usr/bin/env python3
"""Fail-closed tests for the DPLPMTUD evidence contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
COLLECT_SPEC = importlib.util.spec_from_file_location(
    "dplpmtud_collect", HERE / "collect_evidence.py"
)
assert COLLECT_SPEC and COLLECT_SPEC.loader
COLLECT = importlib.util.module_from_spec(COLLECT_SPEC)
COLLECT_SPEC.loader.exec_module(COLLECT)

AGGREGATE_SPEC = importlib.util.spec_from_file_location(
    "dplpmtud_aggregate", HERE / "aggregate_evidence.py"
)
assert AGGREGATE_SPEC and AGGREGATE_SPEC.loader
AGGREGATE = importlib.util.module_from_spec(AGGREGATE_SPEC)
AGGREGATE_SPEC.loader.exec_module(AGGREGATE)


class DplpmtudEvidenceTests(unittest.TestCase):
    SOURCE = "a" * 40
    WORKFLOW = "b" * 40

    def setUp(self) -> None:
        self.contract = json.loads(
            (HERE.parent.parent / "contracts" / "dplpmtud_acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._write_valid_logs()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _marker(self, scenario_id: str, test_id: str, decision: str) -> dict:
        if scenario_id == "DP-01":
            rows = []
            for boundary in self.contract["required_boundaries"]:
                for family, overhead in (("ipv4", 28), ("ipv6", 48)):
                    rows.append(
                        {
                            "outer_ip_packet_size": boundary,
                            "outer_ip_family": family,
                            "outer_ip_udp_overhead": overhead,
                            "udp_datagram_size": boundary - overhead,
                            "overlay_payload_budget": boundary - overhead - 32,
                        }
                    )
            return {
                "scenario_id": scenario_id,
                "test_id": test_id,
                "decision": decision,
                "path_kind": "direct",
                "outer_ip_family": "ipv4_ipv6",
                "boundaries": self.contract["required_boundaries"],
                "rows": rows,
                "invariants": {
                    "all_required_boundaries_executed": True,
                    "outer_udp_overhead_separated": True,
                },
            }
        return {
            "scenario_id": scenario_id,
            "test_id": test_id,
            "decision": decision,
            "path_kind": "direct",
            "outer_ip_family": "ipv4",
            "reason_code": "bounded_test_reason",
            "counter_names": ["probe_count", "timeout_count"],
            "invariants": {"exact_test_executed": True, "identity_fenced": True},
        }

    def _write_valid_logs(self) -> None:
        for spec in self.contract["scenarios"]:
            lines = [
                "running 1 test",
            ]
            if spec["marker_required"]:
                marker = self._marker(
                    spec["scenario_id"],
                    spec["test_id"],
                    spec["expected_decision"],
                )
                lines.append(
                    COLLECT.MARKER_PREFIX
                    + json.dumps(marker, sort_keys=True, separators=(",", ":"))
                )
            else:
                prefix = spec["summary_prefix"]
                tokens = " ".join(spec["required_summary_tokens"])
                lines.append(f"{prefix} {tokens} probe_count=3")
            lines.append(f"test {spec['test_id']} ... ok")
            lines.extend(["", "test result: ok. 1 passed; 0 failed; 0 ignored"])
            (self.root / spec["log_file"]).write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )

    def _collect(self, contract=None):
        return COLLECT.collect(
            contract or self.contract,
            self.root,
            self.SOURCE,
            self.WORKFLOW,
        )

    def _aggregate(
        self,
        component=None,
        *,
        event_name="pull_request",
        component_result="success",
        external_result="success",
    ):
        return AGGREGATE.aggregate(
            self.contract,
            component or self._collect(),
            self.SOURCE,
            self.WORKFLOW,
            event_name,
            component_result,
            external_result,
        )

    def test_valid_actual_execution_report_and_aggregate_pass(self):
        component = self._collect()
        self.assertEqual(component["result"], "pass")
        self.assertEqual(component["scenario_count"], 10)
        aggregate = self._aggregate(component)
        self.assertEqual(aggregate["result"], "pass")
        self.assertEqual(aggregate["required_boundaries"], [1280, 1360, 1380, 1420, 1500])
        self.assertTrue(aggregate["business_mtu_gate_required"])

    def test_missing_exact_test_result_fails(self):
        spec = self.contract["scenarios"][2]
        (self.root / spec["log_file"]).write_text("running 1 test\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "test_not_passed:DP-03"):
            self._collect()

    def test_skipped_exact_test_result_fails(self):
        spec = self.contract["scenarios"][2]
        path = self.root / spec["log_file"]
        text = path.read_text(encoding="utf-8").replace(
            f"test {spec['test_id']} ... ok",
            f"test {spec['test_id']} ... ignored",
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "test_not_passed:DP-03.*skipped"):
            self._collect()

    def test_marker_missing_fails_even_when_test_passes(self):
        spec = self.contract["scenarios"][0]
        path = self.root / spec["log_file"]
        text = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if COLLECT.MARKER_PREFIX not in line
        )
        path.write_text(text + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "marker_count_invalid:DP-01:0"):
            self._collect()

    def test_boundary_manifest_tamper_fails(self):
        spec = self.contract["scenarios"][0]
        path = self.root / spec["log_file"]
        text = path.read_text(encoding="utf-8")
        text = text.replace(
            json.dumps(self.contract["required_boundaries"], separators=(",", ":")),
            json.dumps([1280, 1380, 1420, 1500], separators=(",", ":")),
        )
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "boundary_matrix_mismatch"):
            self._collect()

    def test_high_cardinality_endpoint_in_marker_fails(self):
        spec = self.contract["scenarios"][1]
        path = self.root / spec["log_file"]
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if COLLECT.MARKER_PREFIX in line:
                marker = json.loads(line.split(COLLECT.MARKER_PREFIX, 1)[1])
                marker["remote_endpoint"] = "192.0.2.1:40000"
                lines[index] = COLLECT.MARKER_PREFIX + json.dumps(marker)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "high_cardinality_key_forbidden"):
            self._collect()

    def test_summary_token_missing_fails(self):
        spec = next(item for item in self.contract["scenarios"] if item["scenario_id"] == "DP-07")
        path = self.root / spec["log_file"]
        text = path.read_text(encoding="utf-8").replace("emsgsize_recovery=true ", "")
        path.write_text(text, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "summary_required_token_missing"):
            self._collect()

    def test_duplicate_test_mapping_in_contract_fails(self):
        contract = copy.deepcopy(self.contract)
        contract["scenarios"][1]["test_id"] = contract["scenarios"][0]["test_id"]
        with self.assertRaisesRegex(ValueError, "duplicate_test_mapping"):
            self._collect(contract)

    def test_missing_component_scenario_fails_aggregate(self):
        component = self._collect()
        component["scenarios"] = component["scenarios"][:-1]
        component["scenario_count"] -= 1
        component_without_digest = dict(component)
        component_without_digest.pop("report_digest", None)
        component["report_digest"] = AGGREGATE._canonical_sha256(component_without_digest)
        with self.assertRaisesRegex(ValueError, "component_missing_scenarios"):
            self._aggregate(component)

    def test_source_sha_mismatch_fails_aggregate(self):
        component = self._collect()
        component["source_head_sha"] = "c" * 40
        component_without_digest = dict(component)
        component_without_digest.pop("report_digest", None)
        component["report_digest"] = AGGREGATE._canonical_sha256(component_without_digest)
        with self.assertRaisesRegex(ValueError, "component_source_head_mismatch"):
            self._aggregate(component)

    def test_report_digest_tamper_fails(self):
        component = self._collect()
        component["scenarios"][0]["result"] = "fail"
        with self.assertRaisesRegex(ValueError, "component_report_digest_mismatch"):
            self._aggregate(component)

    def test_failed_component_job_fails(self):
        with self.assertRaisesRegex(ValueError, "component_job_not_success"):
            self._aggregate(component_result="failure")

    def test_pull_request_requires_external_gates(self):
        with self.assertRaisesRegex(ValueError, "external_gates_result_invalid"):
            self._aggregate(external_result="skipped")

    def test_dispatch_accepts_skipped_external_gates(self):
        aggregate = self._aggregate(
            event_name="workflow_dispatch",
            external_result="skipped",
        )
        self.assertEqual(aggregate["result"], "pass")
        self.assertFalse(aggregate["business_mtu_gate_required"])


if __name__ == "__main__":
    unittest.main()
