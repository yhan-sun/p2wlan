#!/usr/bin/env python3
"""Extract per-test lifecycle records from Flutter's machine reporter."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import unquote, urlparse


PREFIX = "MOBILE_LIFECYCLE_RECORD "


def _test_file(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    if url.startswith("package:"):
        package_path = url.removeprefix("package:")
        if "/" in package_path:
            package_path = package_path.split("/", 1)[1]
        if package_path.startswith("test/"):
            return "apps/flutter_client/" + package_path
    path = unquote(urlparse(url).path)
    marker = "/apps/flutter_client/test/"
    if marker in path:
        return "apps/flutter_client/test/" + path.split(marker, 1)[1]
    if path.startswith("/test/"):
        return "apps/flutter_client" + path
    if path.startswith("test/"):
        return "apps/flutter_client/" + path
    if path.endswith("/test/mobile_lifecycle_evidence_test.dart"):
        return "apps/flutter_client/test/mobile_lifecycle_evidence_test.dart"
    return None


def _manifest(path: Path) -> set[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return {entry["exact_test_id"] for entry in value["scenarios"]}


def extract(machine_output: Path, manifest_path: Path) -> list[dict]:
    expected = _manifest(manifest_path)
    tests: dict[object, str] = {}
    done: dict[object, tuple[str, bool]] = {}
    pending: list[tuple[dict, object]] = []
    with machine_output.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            event_type = event.get("type")
            if event_type == "testStart":
                test = event.get("test")
                if not isinstance(test, dict):
                    test = event
                test_id = event.get("testID", test.get("id"))
                name = test.get("name")
                test_file = _test_file(test.get("url"))
                if test_id is not None and isinstance(name, str) and test_file:
                    tests[test_id] = f"{test_file}::{name}"
            elif event_type == "testDone":
                test_id = event.get("testID", event.get("test", {}).get("id"))
                if test_id is not None:
                    result = event.get("result")
                    skipped = event.get("skipped") is True or result == "skipped"
                    done[test_id] = ("pass" if result == "success" else "fail", skipped)
            elif event_type == "print":
                message = event.get("message")
                if not isinstance(message, str) or not message.startswith(PREFIX):
                    continue
                test_id = event.get("testID")
                try:
                    record = json.loads(message[len(PREFIX) :])
                except json.JSONDecodeError as error:
                    raise ValueError(f"invalid Flutter lifecycle record on line {line_number}: {error}") from error
                if not isinstance(record, dict):
                    raise ValueError(f"Flutter lifecycle record on line {line_number} is not an object")
                exact_test_id = record.get("exact_test_id")
                if tests.get(test_id) != exact_test_id:
                    raise ValueError(
                        f"Flutter lifecycle record {exact_test_id!r} is not emitted by the named test"
                    )
                if exact_test_id not in expected:
                    raise ValueError(f"Flutter output contains an unmanifested test: {exact_test_id}")
                pending.append((record, test_id))
    records: list[dict] = []
    for record, test_id in pending:
        if test_id not in done:
            # The record is retained so component_report can reject it as not
            # completed instead of silently passing.
            record["executed"] = False
        else:
            runner_result, skipped = done[test_id]
            record["executed"] = True
            record["result"] = runner_result
            record["skipped"] = skipped
        records.append(record)
    by_test = {record.get("exact_test_id") for record in records}
    missing = expected - by_test
    if missing:
        raise ValueError(f"Flutter machine output has no record for: {sorted(missing)}")
    if len(records) != len(by_test):
        raise ValueError("Flutter machine output contains duplicate lifecycle records")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--machine-output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = extract(args.machine_output, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "records": records}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
