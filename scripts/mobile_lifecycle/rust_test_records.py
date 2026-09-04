#!/usr/bin/env python3
"""Extract lifecycle records emitted by Rust tests run with --nocapture."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


PREFIX = "MOBILE_LIFECYCLE_RECORD "
TEST_RE = re.compile(r"^test\s+(\S+)\s+\.\.\.\s*(.*)$")
STATUS_RE = re.compile(r"^(ok|FAILED|ignored)\s*$")


def _manifest(path: Path) -> set[str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return {entry["exact_test_id"] for entry in value["scenarios"]}


def extract(test_output: Path, manifest_path: Path) -> list[dict]:
    expected = _manifest(manifest_path)
    finished: dict[str, tuple[str, bool]] = {}
    pending: list[dict] = []
    current_test: str | None = None

    def add_record(line: str, line_number: int) -> None:
        if not line.startswith(PREFIX):
            return
        try:
            record = json.loads(line[len(PREFIX) :])
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid Rust lifecycle record on line {line_number}: {error}") from error
        if not isinstance(record, dict):
            raise ValueError(f"Rust lifecycle record on line {line_number} is not an object")
        exact_test_id = record.get("exact_test_id")
        if not isinstance(exact_test_id, str) or exact_test_id not in expected:
            raise ValueError(f"Rust output contains an unmanifested test: {exact_test_id!r}")
        pending.append(record)

    with test_output.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            stripped = line.strip()
            match = TEST_RE.match(stripped)
            if match:
                current_test, remainder = match.groups()
                status = STATUS_RE.match(remainder.strip())
                if status:
                    status_name = status.group(1)
                    finished[current_test] = (status_name, status_name == "ignored")
                    current_test = None
                else:
                    marker_offset = remainder.find(PREFIX)
                    if marker_offset >= 0:
                        add_record(remainder[marker_offset:], line_number)
                continue
            status = STATUS_RE.match(stripped)
            if status and current_test is not None:
                status_name = status.group(1)
                finished[current_test] = (status_name, status_name == "ignored")
                current_test = None
                continue
            add_record(stripped, line_number)
    records: list[dict] = []
    for record in pending:
        exact_test_id = record["exact_test_id"]
        matching = [
            test_id
            for test_id in finished
            if test_id == exact_test_id
            or exact_test_id.endswith(f"::{test_id}")
            or test_id.endswith(f"::{exact_test_id}")
        ]
        if not matching:
            raise ValueError(f"Rust lifecycle record is not tied to a completed test: {exact_test_id}")
        status, skipped = finished[matching[-1]]
        record["executed"] = True
        record["skipped"] = skipped
        record["result"] = "pass" if status == "ok" else "fail"
        records.append(record)
    by_test = {record.get("exact_test_id") for record in records}
    missing = expected - by_test
    if missing:
        raise ValueError(f"Rust test output has no record for: {sorted(missing)}")
    if len(records) != len(by_test):
        raise ValueError("Rust test output contains duplicate lifecycle records")
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = extract(args.test_output, args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schema_version": 1, "records": records}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
