#!/usr/bin/env python3
"""Validate component evidence produced by the component's real test runner.

The checked-in manifest is deliberately only a mapping from a required
scenario to an exact test ID. It is not allowed to carry a result, identity,
decision, or invariant: those values must come from a test that actually ran.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

try:
    from .contract import ContractError, load_contract, scenarios_by_id
except ImportError:  # pragma: no cover - direct CI script execution
    from contract import ContractError, load_contract, scenarios_by_id


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
COMPONENTS = {"flutter", "android_jvm", "rust"}
MANIFEST_ENTRY_FIELDS = {"scenario_id", "exact_test_id"}
RECORD_FIELDS = {
    "scenario_id",
    "exact_test_id",
    "executed",
    "skipped",
    "result",
    "events",
    "observed_old_identity",
    "observed_new_identity",
    "observed_decision",
    "invariants",
    "execution_source",
}
OUTCOMES = {"applied", "duplicate", "stale_rejected", "superseded", "failed"}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read JSON {path}: {error}") from error


def _read_manifest(path: Path) -> dict[str, Any]:
    value = _read_json(path)
    if not isinstance(value, dict):
        raise ValueError("component manifest must be an object")
    return value


def _read_execution_records(path: Path) -> list[dict[str, Any]]:
    value = _read_json(path)
    if isinstance(value, dict):
        value = value.get("records")
    if not isinstance(value, list) or not value:
        raise ValueError("execution records must be a non-empty array")
    if any(not isinstance(record, dict) for record in value):
        raise ValueError("execution record must be an object")
    return value


def _validate_identity(identity: Any, fields: set[str], *, name: str) -> dict[str, Any]:
    if not isinstance(identity, dict) or not identity:
        raise ValueError(f"{name} must be a non-empty object")
    unknown = set(identity) - fields
    if unknown:
        raise ValueError(f"{name} has unknown identity fields: {sorted(unknown)}")
    for key, value in identity.items():
        if key == "trace_id":
            if not isinstance(value, str) or not re.fullmatch(
                r"mobile-lifecycle-[0-9a-f]{12}", value
            ):
                raise ValueError(f"{name}.trace_id is invalid")
        elif not isinstance(value, (int, str)) or isinstance(value, bool):
            raise ValueError(f"{name}.{key} must be an integer or string")
        elif isinstance(value, int) and value < 0:
            raise ValueError(f"{name}.{key} cannot be negative")
    return dict(identity)


def _manifest_mapping(
    manifest: dict[str, Any],
    *,
    component: str,
    scenarios: dict[str, dict[str, Any]],
) -> dict[str, str]:
    if manifest.get("component") != component:
        raise ValueError("manifest component does not match report component")
    entries = manifest.get("scenarios")
    if not isinstance(entries, list) or not entries:
        raise ValueError("component manifest scenarios must be non-empty")
    mapping: dict[str, str] = {}
    test_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("component manifest scenario must be an object")
        if set(entry) != MANIFEST_ENTRY_FIELDS:
            raise ValueError(
                "component manifest may contain only scenario_id and exact_test_id"
            )
        scenario_id = entry.get("scenario_id")
        exact_test_id = entry.get("exact_test_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("component manifest scenario_id must be non-empty")
        if scenario_id not in scenarios:
            raise ValueError(f"unknown required scenario {scenario_id!r}")
        if component not in scenarios[scenario_id]["authoritative_components"]:
            raise ValueError(f"{component} is not authoritative for {scenario_id}")
        if not isinstance(exact_test_id, str) or not exact_test_id:
            raise ValueError(f"{scenario_id} exact_test_id must be non-empty")
        if scenario_id in mapping:
            raise ValueError(f"duplicate scenario {scenario_id}")
        if exact_test_id in test_ids:
            raise ValueError(f"duplicate exact_test_id {exact_test_id}")
        mapping[scenario_id] = exact_test_id
        test_ids.add(exact_test_id)
    return mapping


def _normalize_records(
    records: list[dict[str, Any]],
    *,
    component: str,
    mapping: dict[str, str],
    scenarios: dict[str, dict[str, Any]],
    contract_events: set[str],
    identity_fields: set[str],
    trace_id: str,
) -> list[dict[str, Any]]:
    seen_scenarios: set[str] = set()
    seen_test_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for record in records:
        unknown = set(record) - RECORD_FIELDS
        if unknown:
            raise ValueError(f"execution record has unknown fields: {sorted(unknown)}")
        scenario_id = record.get("scenario_id")
        exact_test_id = record.get("exact_test_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("execution record scenario_id must be non-empty")
        if not isinstance(exact_test_id, str) or not exact_test_id:
            raise ValueError(f"{scenario_id} exact_test_id must be non-empty")
        if scenario_id not in mapping:
            raise ValueError(f"execution record has no manifest scenario: {scenario_id!r}")
        if exact_test_id != mapping[scenario_id]:
            raise ValueError(
                f"{scenario_id} exact_test_id does not match the checked-in mapping"
            )
        if scenario_id in seen_scenarios:
            raise ValueError(f"duplicate execution record for {scenario_id}")
        if exact_test_id in seen_test_ids:
            raise ValueError(f"duplicate execution record for {exact_test_id}")
        seen_scenarios.add(scenario_id)
        seen_test_ids.add(exact_test_id)

        if record.get("executed") is not True:
            raise ValueError(f"{scenario_id} was not executed")
        if record.get("skipped") is not False:
            raise ValueError(f"{scenario_id} was skipped")
        if record.get("result") != "pass":
            raise ValueError(f"{scenario_id} did not pass")
        execution_source = record.get("execution_source", component)
        if not isinstance(execution_source, str) or not execution_source:
            raise ValueError(f"{scenario_id} has no execution source")

        contract_scenario = scenarios[scenario_id]
        events = record.get("events")
        if (
            not isinstance(events, list)
            or not events
            or any(not isinstance(event, str) or event not in contract_events for event in events)
        ):
            raise ValueError(f"{scenario_id} has invalid observed events")
        observed_decision = record.get("observed_decision")
        if not isinstance(observed_decision, str) or observed_decision not in OUTCOMES:
            raise ValueError(f"{scenario_id} has an invalid observed decision")
        if observed_decision != contract_scenario["required_decision"]:
            raise ValueError(f"{scenario_id} has the wrong observed decision")
        invariants = record.get("invariants")
        if not isinstance(invariants, dict) or not invariants:
            raise ValueError(f"{scenario_id} has no observed invariants")
        if any(not isinstance(value, bool) for value in invariants.values()):
            raise ValueError(f"{scenario_id} invariants must be booleans")
        missing = set(contract_scenario["required_invariants"]) - set(invariants)
        if missing:
            raise ValueError(f"{scenario_id} is missing invariants: {sorted(missing)}")
        if not all(invariants.values()):
            raise ValueError(f"{scenario_id} has a false invariant")

        old = _validate_identity(
            record.get("observed_old_identity"),
            identity_fields,
            name=f"{scenario_id}.observed_old_identity",
        )
        new = _validate_identity(
            record.get("observed_new_identity"),
            identity_fields,
            name=f"{scenario_id}.observed_new_identity",
        )
        for identity, name in ((old, "old_identity"), (new, "new_identity")):
            supplied_trace = identity.get("trace_id")
            if supplied_trace is not None and supplied_trace != trace_id:
                raise ValueError(f"{scenario_id}.{name} trace_id does not bind to source SHA")
            identity["trace_id"] = trace_id

        normalized.append(
            {
                "scenario_id": scenario_id,
                "scenario_name": contract_scenario["name"],
                "exact_test_id": exact_test_id,
                "executed": True,
                "skipped": False,
                "result": "pass",
                "events": list(events),
                "observed_old_identity": dict(old),
                "observed_new_identity": dict(new),
                "observed_decision": observed_decision,
                "old_identity": dict(old),
                "new_identity": dict(new),
                "decision": observed_decision,
                "invariants": dict(invariants),
                "execution_source": execution_source,
            }
        )
    missing_scenarios = set(mapping) - seen_scenarios
    if missing_scenarios:
        raise ValueError(
            "manifest scenarios have no actual execution record: "
            f"{sorted(missing_scenarios)}"
        )
    if set(mapping.values()) != seen_test_ids:
        raise ValueError("actual test IDs do not exactly cover the manifest")
    return normalized


def build_report(
    *,
    root: Path,
    component: str,
    source_head_sha: str,
    workflow_sha: str,
    manifest_path: Path,
    execution_records_path: Path | None = None,
    execution_records: list[dict[str, Any]] | None = None,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    contract = load_contract(root / "contracts" / "mobile_lifecycle.json")
    scenarios = scenarios_by_id(contract)
    if component not in COMPONENTS:
        raise ValueError(f"unknown component {component}")
    if not SHA_RE.fullmatch(source_head_sha) or not SHA_RE.fullmatch(workflow_sha):
        raise ValueError("source_head_sha and workflow_sha must be 40-character SHA-1 values")
    if execution_records is None:
        if execution_records_path is None:
            raise ValueError("actual execution records are required")
        execution_records = _read_execution_records(execution_records_path)
    elif execution_records_path is not None:
        raise ValueError("provide execution_records or execution_records_path, not both")
    manifest = _read_manifest(manifest_path)
    mapping = _manifest_mapping(manifest, component=component, scenarios=scenarios)
    trace_id = f"mobile-lifecycle-{source_head_sha[:12]}"
    normalized = _normalize_records(
        execution_records,
        component=component,
        mapping=mapping,
        scenarios=scenarios,
        contract_events=set(contract["events"]),
        identity_fields=set(contract["identity_fields"]),
        trace_id=trace_id,
    )
    return {
        "schema_version": 2,
        "repository": "yhan-sun/p2wlan",
        "component": component,
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "toolchain": toolchain,
        "result": "pass",
        "trace_id": trace_id,
        "scenarios": normalized,
    }


def _write_failure(
    path: Path,
    *,
    component: str,
    source_head_sha: str,
    workflow_sha: str,
    error: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "repository": "yhan-sun/p2wlan",
                "component": component,
                "source_head_sha": source_head_sha,
                "workflow_sha": workflow_sha,
                "result": "fail",
                "error": error,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--component", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--execution-records", type=Path, required=True)
    parser.add_argument("--toolchain", default="{}")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        toolchain = json.loads(args.toolchain)
        if not isinstance(toolchain, dict):
            raise ValueError("--toolchain must be a JSON object")
        report = build_report(
            root=args.root.resolve(),
            component=args.component,
            source_head_sha=args.source_head_sha,
            workflow_sha=args.workflow_sha,
            manifest_path=args.manifest,
            execution_records_path=args.execution_records,
            toolchain=toolchain,
        )
    except (ContractError, ValueError, TypeError, json.JSONDecodeError, OSError) as error:
        _write_failure(
            args.output,
            component=args.component,
            source_head_sha=args.source_head_sha,
            workflow_sha=args.workflow_sha,
            error=str(error),
        )
        print(f"mobile lifecycle component evidence rejected: {error}", flush=True)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
