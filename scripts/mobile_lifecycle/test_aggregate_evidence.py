#!/usr/bin/env python3
"""Tamper tests for the fail-closed mobile lifecycle aggregate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from aggregate_evidence import EvidenceError, aggregate
from component_report import build_report


ROOT = Path(__file__).resolve().parents[2]
SOURCE_SHA = "0" * 40
WORKFLOW_SHA = "1" * 40


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
                result="pass",
                manifest_path=ROOT / "scripts" / "mobile_lifecycle" / "manifests" / f"{component}.json",
                toolchain={"test_runner": "deterministic-unit-tests"},
            )
            (self.reports / f"{component}.json").write_text(
                json.dumps(report), encoding="utf-8"
            )

    def tearDown(self) -> None:
        self.temp.cleanup()

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
        self.assertEqual(result["required_scenarios"], [f"ML-{i:02d}" for i in range(1, 19)])

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
