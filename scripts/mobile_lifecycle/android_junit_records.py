#!/usr/bin/env python3
"""Extract per-method lifecycle records from Android JUnit XML."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


PREFIX = "MOBILE_LIFECYCLE_RECORD "


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _manifest(path: Path) -> set[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return {entry["exact_test_id"] for entry in value["scenarios"]}


def _testcases(xml_root: Path) -> dict[str, ET.Element]:
    result: dict[str, ET.Element] = {}
    for path in sorted(xml_root.rglob("TEST-*.xml")):
        root = ET.parse(path).getroot()
        for testcase in root.iter():
            if _local_name(testcase.tag) != "testcase":
                continue
            classname = testcase.attrib.get("classname")
            name = testcase.attrib.get("name")
            if not classname or not name:
                continue
            exact_test_id = f"{classname}#{name}"
            if exact_test_id in result:
                raise ValueError(f"duplicate Android JUnit test ID: {exact_test_id}")
            result[exact_test_id] = testcase
    return result


def _markers(xml_root: Path) -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    for path in sorted(xml_root.rglob("TEST-*.xml")):
        root = ET.parse(path).getroot()
        for output in root.iter():
            if _local_name(output.tag) != "system-out":
                continue
            message = output.text or ""
            for line in message.splitlines():
                line = line.strip()
                if not line.startswith(PREFIX):
                    continue
                record = json.loads(line[len(PREFIX) :])
                if not isinstance(record, dict):
                    raise ValueError(f"Android lifecycle record in {path} is not an object")
                exact_test_id = record.get("exact_test_id")
                if not isinstance(exact_test_id, str) or not exact_test_id:
                    raise ValueError(f"Android lifecycle record in {path} has no test ID")
                result.setdefault(exact_test_id, []).append(record)
    return result


def _record_from_testcase(
    exact_test_id: str,
    testcase: ET.Element,
    marker_records: dict[str, list[dict]],
) -> dict:
    """Combine one JUnit method's status with its emitted lifecycle record.

    The Gradle Android test task commonly writes one suite-level system-out
    block containing all test stdout, while some JUnit emitters attach stdout
    directly to the testcase.  _markers normalizes both layouts and the JUnit
    testcase table remains the authority for execution status.
    """
    markers = marker_records.get(exact_test_id, [])
    for record in markers:
        if record.get("exact_test_id") != exact_test_id:
            raise ValueError(f"Android record test ID does not match {exact_test_id}")
    if len(markers) != 1:
        raise ValueError(
            f"Android JUnit test {exact_test_id} must emit exactly one lifecycle record, "
            f"got {len(markers)}"
        )
    record = markers[0]
    skipped = any(_local_name(child.tag) == "skipped" for child in testcase.iter())
    failed = any(
        _local_name(child.tag) in {"failure", "error"} for child in testcase.iter()
    )
    record["executed"] = True
    record["skipped"] = skipped
    record["result"] = "fail" if failed else "pass"
    return record


def extract(xml_root: Path, manifest_path: Path) -> list[dict]:
    expected = _manifest(manifest_path)
    actual = _testcases(xml_root)
    marker_records = _markers(xml_root)
    unknown_markers = sorted(set(marker_records) - set(actual))
    if unknown_markers:
        raise ValueError(f"Android JUnit output has a record for an unknown test: {unknown_markers}")
    records: list[dict] = []
    for exact_test_id in sorted(expected):
        testcase = actual.get(exact_test_id)
        if testcase is None:
            raise ValueError(f"Android JUnit output has no mapped test: {exact_test_id}")
        records.append(_record_from_testcase(exact_test_id, testcase, marker_records))
    if set(actual) & expected != expected:
        missing = sorted(expected - set(actual))
        raise ValueError(f"Android JUnit output is missing mapped tests: {missing}")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = extract(args.xml_root, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "records": records}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
