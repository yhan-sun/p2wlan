#!/usr/bin/env python3
"""Unit tests for machine-output to lifecycle-record adapters."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from .android_junit_records import extract as extract_android
    from .flutter_machine_records import extract as extract_flutter
    from .rust_test_records import extract as extract_rust
except ImportError:  # pragma: no cover - direct test execution
    from android_junit_records import extract as extract_android
    from flutter_machine_records import extract as extract_flutter
    from rust_test_records import extract as extract_rust


ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "scripts" / "mobile_lifecycle" / "manifests"


def marker(scenario_id: str, exact_test_id: str) -> str:
    return json.dumps(
        {
            "scenario_id": scenario_id,
            "exact_test_id": exact_test_id,
            "events": ["bridge_attached"],
            "observed_old_identity": {"bridge_incarnation": 1},
            "observed_new_identity": {"bridge_incarnation": 2},
            "observed_decision": "applied",
            "invariants": {"bridge_identity_adopted": True},
            "execution_source": "test",
        },
        separators=(",", ":"),
    )


def entries(component: str) -> list[dict[str, str]]:
    value = json.loads(
        (MANIFESTS / f"{component}.json").read_text(encoding="utf-8")
    )
    return value["scenarios"]


class ExecutionRecordAdapterTest(unittest.TestCase):
    def test_flutter_machine_output_binds_print_to_completed_test(self) -> None:
        output = []
        exact_id = next(
            entry["exact_test_id"]
            for entry in entries("flutter")
            if entry["scenario_id"] == "ML-10"
        )
        for test_number, entry in enumerate(entries("flutter"), 1):
            test_id = entry["exact_test_id"]
            name = test_id.split("::", 1)[1]
            output.extend(
                [
                    json.dumps(
                        {
                            "type": "testStart",
                            "test": {
                                "id": test_number,
                                "name": name,
                                "url": "package:p2wlan_flutter_client/test/mobile_lifecycle_evidence_test.dart",
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "type": "print",
                            "testID": test_number,
                            "message": "MOBILE_LIFECYCLE_RECORD "
                            + marker(entry["scenario_id"], test_id),
                        }
                    ),
                    json.dumps(
                        {"type": "testDone", "testID": test_number, "result": "success"}
                    ),
                ]
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flutter-machine.json"
            path.write_text("\n".join(output) + "\n", encoding="utf-8")
            records = extract_flutter(path, MANIFESTS / "flutter.json")
        record = next(record for record in records if record["exact_test_id"] == exact_id)
        self.assertTrue(record["executed"])
        self.assertFalse(record["skipped"])
        self.assertEqual(record["result"], "pass")

    def test_android_junit_output_binds_system_out_to_method(self) -> None:
        exact_id = next(
            entry["exact_test_id"]
            for entry in entries("android_jvm")
            if entry["scenario_id"] == "ML-10"
        )
        testcases = []
        for entry in entries("android_jvm"):
            classname, name = entry["exact_test_id"].split("#", 1)
            testcases.append(
                f'''  <testcase classname="{classname}" name="{name}">
    <system-out><![CDATA[MOBILE_LIFECYCLE_RECORD {marker(entry["scenario_id"], entry["exact_test_id"])}]]></system-out>
  </testcase>'''
            )
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite xmlns="urn:test" tests="1" failures="0" errors="0" skipped="0">
{chr(10).join(testcases)}
</testsuite>
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "TEST-MobileLifecycle.xml").write_text(xml, encoding="utf-8")
            records = extract_android(root, MANIFESTS / "android_jvm.json")
        record = next(record for record in records if record["exact_test_id"] == exact_id)
        self.assertEqual(record["result"], "pass")

    def test_rust_output_handles_nocapture_marker_before_harness_status(self) -> None:
        exact_id = next(
            entry["exact_test_id"]
            for entry in entries("rust")
            if entry["scenario_id"] == "ML-10"
        )
        output = ""
        for entry in entries("rust"):
            output += (
                f"test {entry['exact_test_id']} ... MOBILE_LIFECYCLE_RECORD "
                f"{marker(entry['scenario_id'], entry['exact_test_id'])}\n"
                "ok\n"
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rust-output.log"
            path.write_text(output, encoding="utf-8")
            records = extract_rust(path, MANIFESTS / "rust.json")
        record = next(record for record in records if record["exact_test_id"] == exact_id)
        self.assertEqual(record["result"], "pass")


if __name__ == "__main__":
    unittest.main()
