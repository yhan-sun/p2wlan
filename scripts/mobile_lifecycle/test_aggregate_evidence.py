#!/usr/bin/env python3
"""Tamper tests for the fail-closed mobile lifecycle aggregate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from .aggregate_evidence import EvidenceError, aggregate
    from .component_report import build_report
except ImportError:  # pragma: no cover - direct test execution
    from aggregate_evidence import EvidenceError, aggregate
    from component_report import build_report


ROOT = Path(__file__).resolve().parents[2]
SOURCE_SHA = "0" * 40
WORKFLOW_SHA = "1" * 40
MANIFEST_ROOT = ROOT / "scripts" / "mobile_lifecycle" / "manifests"

EVENTS = {
    "ML-01": ["app_backgrounded"],
    "ML-02": ["app_resumed"],
    "ML-03": ["native_runtime_stopped", "native_runtime_started"],
    "ML-04": ["physical_network_changed", "candidate_refresh_started"],
    "ML-05": ["physical_network_changed", "candidate_refresh_started"],
    "ML-06": ["vpn_permission_revoked", "bridge_detached"],
    "ML-07": ["vpn_permission_granted", "native_runtime_started"],
    "ML-08": ["activity_recreated", "bridge_attached"],
    "ML-09": ["service_recreated", "native_runtime_started"],
    "ML-10": ["bridge_detached", "bridge_attached"],
    "ML-11": ["bridge_detached", "bridge_attached"],
    "ML-12": ["control_disconnected", "control_reconnected"],
    "ML-13": ["control_reconnected"],
    "ML-14": ["candidate_refresh_started", "physical_network_changed"],
    "ML-15": ["physical_network_changed", "candidate_refresh_started"],
    "ML-16": ["relay_retained", "candidate_refresh_started", "direct_reconfirmed"],
    "ML-17": ["candidate_refresh_started", "direct_reconfirmed"],
    "ML-18": ["physical_network_changed", "physical_network_changed"],
}

IDENTITY_KEY = {
    "ML-01": "event_loop_generation",
    "ML-02": "event_loop_generation",
    "ML-03": "runtime_incarnation",
    "ML-04": "network_generation",
    "ML-05": "network_generation",
    "ML-06": "permission_request_id",
    "ML-07": "permission_request_id",
    "ML-08": "activity_incarnation",
    "ML-09": "service_incarnation",
    "ML-10": "bridge_incarnation",
    "ML-11": "bridge_incarnation",
    "ML-12": "control_connection_generation",
    "ML-13": "control_connection_generation",
    "ML-14": "candidate_epoch",
    "ML-15": "socket_publication_generation",
    "ML-16": "network_generation",
    "ML-17": "network_generation",
    "ML-18": "event_loop_generation",
}


class AggregateEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.reports = Path(self.temp.name)
        for component in ("flutter", "android_jvm", "rust"):
            report = build_report(
                root=ROOT,
                component=component,
                source_head_sha=SOURCE_SHA,
                workflow_sha=WORKFLOW_SHA,
                manifest_path=MANIFEST_ROOT / f"{component}.json",
                execution_records=self.actual_records(component),
                toolchain={"test_runner": "fixture-actual-runner"},
            )
            (self.reports / f"{component}.json").write_text(
                json.dumps(report), encoding="utf-8"
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def manifest_entries(self, component: str) -> list[dict[str, str]]:
        value = json.loads(
            (MANIFEST_ROOT / f"{component}.json").read_text(encoding="utf-8")
        )
        return value["scenarios"]

    def actual_records(self, component: str) -> list[dict]:
        contract = json.loads(
            (ROOT / "contracts" / "mobile_lifecycle.json").read_text(encoding="utf-8")
        )
        required = {
            scenario["id"]: scenario for scenario in contract["required_scenarios"]
        }
        records = []
        for entry in self.manifest_entries(component):
            scenario_id = entry["scenario_id"]
            decision = required[scenario_id]["required_decision"]
            key = IDENTITY_KEY[scenario_id]
            old = {key: 1}
            new = {key: 1 if scenario_id == "ML-18" else 2}
            records.append(
                {
                    "scenario_id": scenario_id,
                    "exact_test_id": entry["exact_test_id"],
                    "executed": True,
                    "skipped": False,
                    "result": "pass",
                    "events": EVENTS[scenario_id],
                    "observed_old_identity": old,
                    "observed_new_identity": new,
                    "observed_decision": decision,
                    "invariants": {
                        invariant: True
                        for invariant in required[scenario_id]["required_invariants"]
                    },
                    "execution_source": "fixture_actual_runner",
                }
            )
        return records

    def load(self, component: str) -> dict:
        path = self.reports / f"{component}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, component: str, value: dict) -> None:
        (self.reports / f"{component}.json").write_text(
            json.dumps(value), encoding="utf-8"
        )

    def assertRejects(self, mutate) -> None:  # noqa: N802 - unittest-style helper
        mutate()
        with self.assertRaises(EvidenceError):
            aggregate(self.reports, SOURCE_SHA, WORKFLOW_SHA)

    def test_valid_complete_evidence_passes(self) -> None:
        result = aggregate(self.reports, SOURCE_SHA, WORKFLOW_SHA)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(result["aggregate_artifact_id"], "mobile-lifecycle-aggregate")
        self.assertEqual(result["required_scenarios"], [f"ML-{i:02d}" for i in range(1, 19)])

    def test_component_exit_zero_but_missing_ml15_is_rejected(self) -> None:
        records = [
            record
            for record in self.actual_records("rust")
            if record["scenario_id"] != "ML-15"
        ]
        with self.assertRaises(ValueError):
            build_report(
                root=ROOT,
                component="rust",
                source_head_sha=SOURCE_SHA,
                workflow_sha=WORKFLOW_SHA,
                manifest_path=MANIFEST_ROOT / "rust.json",
                execution_records=records,
                toolchain={"exit_status": 0},
            )

    def test_test_name_changed_is_rejected(self) -> None:
        records = self.actual_records("rust")
        records[0]["exact_test_id"] += "_renamed"
        with self.assertRaises(ValueError):
            build_report(
                root=ROOT,
                component="rust",
                source_head_sha=SOURCE_SHA,
                workflow_sha=WORKFLOW_SHA,
                manifest_path=MANIFEST_ROOT / "rust.json",
                execution_records=records,
                toolchain={"test_runner": "fixture-actual-runner"},
            )

    def test_skipped_test_is_rejected(self) -> None:
        records = self.actual_records("android_jvm")
        records[0]["skipped"] = True
        with self.assertRaises(ValueError):
            build_report(
                root=ROOT,
                component="android_jvm",
                source_head_sha=SOURCE_SHA,
                workflow_sha=WORKFLOW_SHA,
                manifest_path=MANIFEST_ROOT / "android_jvm.json",
                execution_records=records,
                toolchain={"test_runner": "fixture-actual-runner"},
            )

    def test_static_manifest_adds_fictional_scenario_is_rejected(self) -> None:
        value = json.loads((MANIFEST_ROOT / "rust.json").read_text(encoding="utf-8"))
        value["scenarios"].append(
            {"scenario_id": "ML-99", "exact_test_id": "fictional::test"}
        )
        manifest = self.reports / "fictional-rust-manifest.json"
        manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(ValueError):
            build_report(
                root=ROOT,
                component="rust",
                source_head_sha=SOURCE_SHA,
                workflow_sha=WORKFLOW_SHA,
                manifest_path=manifest,
                execution_records=self.actual_records("rust"),
                toolchain={"test_runner": "fixture-actual-runner"},
            )

    def test_duplicate_conflicting_test_record_is_rejected(self) -> None:
        records = self.actual_records("rust")
        duplicate = copy.deepcopy(
            next(record for record in records if record["scenario_id"] == "ML-12")
        )
        duplicate["observed_decision"] = "stale_rejected"
        records.append(duplicate)
        with self.assertRaises(ValueError):
            build_report(
                root=ROOT,
                component="rust",
                source_head_sha=SOURCE_SHA,
                workflow_sha=WORKFLOW_SHA,
                manifest_path=MANIFEST_ROOT / "rust.json",
                execution_records=records,
                toolchain={"test_runner": "fixture-actual-runner"},
            )

    def test_missing_flutter_report_fails(self) -> None:
        self.assertRejects(lambda: (self.reports / "flutter.json").unlink())

    def test_missing_android_report_fails(self) -> None:
        self.assertRejects(lambda: (self.reports / "android_jvm.json").unlink())

    def test_missing_rust_report_fails(self) -> None:
        self.assertRejects(lambda: (self.reports / "rust.json").unlink())

    def test_source_sha_mismatch_fails(self) -> None:
        def mutate() -> None:
            report = self.load("flutter")
            report["source_head_sha"] = "2" * 40
            self.save("flutter", report)

        self.assertRejects(mutate)

    def test_workflow_sha_mismatch_fails(self) -> None:
        def mutate() -> None:
            report = self.load("android_jvm")
            report["workflow_sha"] = "2" * 40
            self.save("android_jvm", report)

        self.assertRejects(mutate)

    def test_duplicate_component_artifact_fails(self) -> None:
        self.assertRejects(lambda: (self.reports / "flutter-copy.json").write_text("{}"))

    def test_extra_artifact_directory_fails(self) -> None:
        self.assertRejects(lambda: (self.reports / "unexpected").mkdir())

    def test_duplicate_component_identity_fails(self) -> None:
        def mutate() -> None:
            report = self.load("flutter")
            report["component"] = "android_jvm"
            self.save("flutter", report)

        self.assertRejects(mutate)

    def test_unknown_schema_fails(self) -> None:
        def mutate() -> None:
            report = self.load("rust")
            report["schema_version"] = 99
            self.save("rust", report)

        self.assertRejects(mutate)

    def test_empty_scenarios_fails(self) -> None:
        def mutate() -> None:
            report = self.load("flutter")
            report["scenarios"] = []
            self.save("flutter", report)

        self.assertRejects(mutate)

    def test_required_scenario_deferred_fails(self) -> None:
        def mutate() -> None:
            report = self.load("flutter")
            report["scenarios"][0]["decision"] = "deferred"
            self.save("flutter", report)

        self.assertRejects(mutate)

    def test_stale_result_falsely_marked_applied_fails(self) -> None:
        def mutate() -> None:
            report = self.load("flutter")
            report["scenarios"][0]["decision"] = "applied"
            self.save("flutter", report)

        self.assertRejects(mutate)

    def test_relay_retention_false_fails(self) -> None:
        def mutate() -> None:
            report = self.load("rust")
            scenario = next(item for item in report["scenarios"] if item["scenario_id"] == "ML-16")
            scenario["invariants"]["relay_retained_until_direct_commit"] = False
            self.save("rust", report)

        self.assertRejects(mutate)

    def test_old_bridge_cleanup_falsely_accepted_fails(self) -> None:
        def mutate() -> None:
            report = self.load("android_jvm")
            scenario = next(item for item in report["scenarios"] if item["scenario_id"] == "ML-11")
            scenario["decision"] = "applied"
            self.save("android_jvm", report)

        self.assertRejects(mutate)

    def test_conflicting_duplicate_scenario_fails(self) -> None:
        def mutate() -> None:
            report = self.load("rust")
            duplicate = copy.deepcopy(next(item for item in report["scenarios"] if item["scenario_id"] == "ML-12"))
            duplicate["decision"] = "stale_rejected"
            report["scenarios"].append(duplicate)
            self.save("rust", report)

        self.assertRejects(mutate)

    def test_conflicting_duplicate_identity_fails(self) -> None:
        def mutate() -> None:
            report = self.load("rust")
            duplicate = copy.deepcopy(
                next(item for item in report["scenarios"] if item["scenario_id"] == "ML-12")
            )
            duplicate["new_identity"]["control_connection_generation"] = 99
            report["scenarios"].append(duplicate)
            self.save("rust", report)

        self.assertRejects(mutate)

    def test_component_job_failure_fails(self) -> None:
        with self.assertRaises(EvidenceError):
            aggregate(
                self.reports,
                SOURCE_SHA,
                WORKFLOW_SHA,
                job_results={
                    "flutter": "success",
                    "android_jvm": "failure",
                    "rust": "success",
                },
            )

    def test_package_job_failure_fails(self) -> None:
        with self.assertRaises(EvidenceError):
            aggregate(
                self.reports,
                SOURCE_SHA,
                WORKFLOW_SHA,
                job_results={
                    "flutter": "success",
                    "android_jvm": "success",
                    "rust": "success",
                    "package": "failure",
                },
            )


if __name__ == "__main__":
    unittest.main()
