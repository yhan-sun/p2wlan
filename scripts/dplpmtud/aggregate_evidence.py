#!/usr/bin/env python3
"""Fail-closed aggregate for DPLPMTUD live-dataplane evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

AGGREGATE_SCHEMA_VERSION = 1
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}_invalid:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label}_not_object")
    return value


def _canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_sha(value: str, label: str) -> None:
    if SHA40.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")


def aggregate(
    contract: dict[str, Any],
    component: dict[str, Any],
    source_head_sha: str,
    workflow_sha: str,
    event_name: str,
    component_result: str,
    external_gates_result: str,
) -> dict[str, Any]:
    _validate_sha(source_head_sha, "source_head_sha")
    _validate_sha(workflow_sha, "workflow_sha")
    if event_name not in {"pull_request", "push", "workflow_dispatch"}:
        raise ValueError("event_name_invalid")
    if component_result != "success":
        raise ValueError(f"component_job_not_success:{component_result}")
    expected_external = "success" if event_name == "pull_request" else "skipped"
    if external_gates_result != expected_external:
        raise ValueError(
            f"external_gates_result_invalid:{event_name}:{external_gates_result}:{expected_external}"
        )
    if contract.get("schema_version") != 1:
        raise ValueError("contract_schema_unknown")
    if contract.get("repository") != "yhan-sun/p2wlan":
        raise ValueError("contract_repository_mismatch")
    if component.get("schema_version") != 1:
        raise ValueError("component_schema_unknown")
    if component.get("repository") != contract.get("repository"):
        raise ValueError("component_repository_mismatch")
    if component.get("component") != contract.get("component"):
        raise ValueError("component_name_mismatch")
    if component.get("source_head_sha") != source_head_sha:
        raise ValueError("component_source_head_mismatch")
    if component.get("workflow_sha") != workflow_sha:
        raise ValueError("component_workflow_sha_mismatch")
    if component.get("result") != "pass":
        raise ValueError("component_result_not_pass")
    expected_contract_digest = _canonical_sha256(contract)
    if component.get("contract_sha256") != expected_contract_digest:
        raise ValueError("component_contract_digest_mismatch")
    claimed_report_digest = component.get("report_digest")
    if not isinstance(claimed_report_digest, str):
        raise ValueError("component_report_digest_missing")
    component_without_digest = dict(component)
    component_without_digest.pop("report_digest", None)
    if _canonical_sha256(component_without_digest) != claimed_report_digest:
        raise ValueError("component_report_digest_mismatch")

    specs = contract.get("scenarios")
    records = component.get("scenarios")
    if not isinstance(specs, list) or not isinstance(records, list):
        raise ValueError("scenario_arrays_missing")
    expected_by_id: dict[str, dict[str, Any]] = {}
    for spec in specs:
        if not isinstance(spec, dict) or not isinstance(spec.get("scenario_id"), str):
            raise ValueError("contract_scenario_invalid")
        scenario_id = spec["scenario_id"]
        if scenario_id in expected_by_id:
            raise ValueError(f"contract_duplicate_scenario:{scenario_id}")
        expected_by_id[scenario_id] = spec

    seen: set[str] = set()
    compact_records: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("component_scenario_not_object")
        scenario_id = record.get("scenario_id")
        if not isinstance(scenario_id, str) or scenario_id not in expected_by_id:
            raise ValueError(f"component_unknown_scenario:{scenario_id}")
        if scenario_id in seen:
            raise ValueError(f"component_duplicate_scenario:{scenario_id}")
        seen.add(scenario_id)
        spec = expected_by_id[scenario_id]
        if record.get("exact_test_id") != spec.get("test_id"):
            raise ValueError(f"component_test_id_mismatch:{scenario_id}")
        if record.get("category") != spec.get("category"):
            raise ValueError(f"component_category_mismatch:{scenario_id}")
        if record.get("decision") != spec.get("expected_decision"):
            raise ValueError(f"component_decision_mismatch:{scenario_id}")
        if record.get("executed") is not True:
            raise ValueError(f"component_test_not_executed:{scenario_id}")
        if record.get("skipped") is not False:
            raise ValueError(f"component_test_skipped:{scenario_id}")
        if record.get("result") != "pass":
            raise ValueError(f"component_test_not_pass:{scenario_id}")
        if not isinstance(record.get("observed"), dict) or not record["observed"]:
            raise ValueError(f"component_observed_missing:{scenario_id}")
        compact_records.append(
            {
                "scenario_id": scenario_id,
                "category": record["category"],
                "exact_test_id": record["exact_test_id"],
                "decision": record["decision"],
                "result": "pass",
            }
        )

    missing = sorted(set(expected_by_id) - seen)
    if missing:
        raise ValueError("component_missing_scenarios:" + ",".join(missing))
    if component.get("scenario_count") != len(expected_by_id):
        raise ValueError("component_scenario_count_mismatch")

    boundaries = contract.get("required_boundaries")
    if boundaries != [1280, 1360, 1380, 1420, 1500]:
        raise ValueError("required_boundary_contract_changed")
    boundary_record = next(
        record for record in records if record.get("scenario_id") == "DP-01"
    )
    marker = boundary_record["observed"]
    if marker.get("boundaries") != boundaries:
        raise ValueError("boundary_evidence_mismatch")

    aggregate_value: dict[str, Any] = {
        "schema_version": AGGREGATE_SCHEMA_VERSION,
        "repository": contract["repository"],
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "event_name": event_name,
        "result": "pass",
        "business_mtu_gate_required": event_name == "pull_request",
        "external_required_gates_result": external_gates_result,
        "required_boundaries": boundaries,
        "scenario_count": len(compact_records),
        "scenarios": sorted(compact_records, key=lambda item: item["scenario_id"]),
        "contract_sha256": expected_contract_digest,
        "component_report_digest": claimed_report_digest,
    }
    aggregate_value["aggregate_digest"] = _canonical_sha256(aggregate_value)
    return aggregate_value


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--component-result", required=True)
    parser.add_argument("--external-gates-result", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    result = aggregate(
        _load(Path(args.contract), "contract"),
        _load(Path(args.component), "component"),
        args.source_head_sha,
        args.workflow_sha,
        args.event_name,
        args.component_result,
        args.external_gates_result,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "result": result["result"],
        "scenario_count": result["scenario_count"],
        "aggregate_digest": result["aggregate_digest"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
