#!/usr/bin/env python3
"""Create a schema-2 component report from a checked-in test manifest.

The caller supplies the result of the real component test command.  This
keeps the report generator a serializer/validator instead of a source of
synthetic green evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

try:
    from .contract import ContractError, load_contract, scenarios_by_id
except ImportError:  # pragma: no cover - direct CI script execution
    from contract import ContractError, load_contract, scenarios_by_id


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
COMPONENTS = {"flutter", "android_jvm", "rust"}


def _git_head(root: Path) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("component manifest must be an object")
    return value


def _validate_identity(identity: dict[str, Any], fields: set[str], *, name: str) -> None:
    if not isinstance(identity, dict):
        raise ValueError(f"{name} must be an object")
    unknown = set(identity) - fields
    if unknown:
        raise ValueError(f"{name} has unknown identity fields: {sorted(unknown)}")
    for key, value in identity.items():
        if key == "trace_id":
            if not isinstance(value, str) or not re.fullmatch(r"mobile-lifecycle-[0-9a-f]{12}", value):
                raise ValueError(f"{name}.trace_id is invalid")
        elif not isinstance(value, (int, str)) or isinstance(value, bool):
            raise ValueError(f"{name}.{key} must be an integer or string")
        elif isinstance(value, int) and value < 0:
            raise ValueError(f"{name}.{key} cannot be negative")


def build_report(
    *,
    root: Path,
    component: str,
    source_head_sha: str,
    workflow_sha: str,
    result: str,
    manifest_path: Path,
    toolchain: dict[str, Any],
) -> dict[str, Any]:
    contract = load_contract(root / "contracts" / "mobile_lifecycle.json")
    scenarios = scenarios_by_id(contract)
    if component not in COMPONENTS:
        raise ValueError(f"unknown component {component}")
    if not SHA_RE.fullmatch(source_head_sha) or not SHA_RE.fullmatch(workflow_sha):
        raise ValueError("source_head_sha and workflow_sha must be 40-character SHA-1 values")
    if result not in {"pass", "fail"}:
        raise ValueError("result must be pass or fail")
    manifest = _read_json(manifest_path)
    manifest_component = manifest.get("component")
    if manifest_component != component:
        raise ValueError("manifest component does not match report component")
    entries = manifest.get("scenarios")
    if not isinstance(entries, list) or not entries:
        raise ValueError("component manifest scenarios must be non-empty")
    identity_fields = set(contract["identity_fields"])
    trace_id = f"mobile-lifecycle-{source_head_sha[:12]}"
    report_scenarios: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("component manifest scenario must be an object")
        scenario_id = entry.get("scenario_id")
        if scenario_id not in scenarios:
            raise ValueError(f"unknown required scenario {scenario_id!r}")
        if scenario_id in seen:
            raise ValueError(f"duplicate scenario {scenario_id}")
        if component not in scenarios[scenario_id]["authoritative_components"]:
            raise ValueError(f"{component} is not authoritative for {scenario_id}")
        seen.add(scenario_id)
        events = entry.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError(f"{scenario_id} must include events")
        if any(event not in contract["events"] for event in events):
            raise ValueError(f"{scenario_id} contains an unknown event")
        decision = entry.get("decision")
        if decision not in contract["outcomes"]:
            raise ValueError(f"{scenario_id} contains an invalid decision")
        if decision != scenarios[scenario_id]["required_decision"]:
            raise ValueError(
                f"{scenario_id} requires decision {scenarios[scenario_id]['required_decision']!r}"
            )
        invariants = entry.get("invariants")
        if not isinstance(invariants, dict) or not invariants:
            raise ValueError(f"{scenario_id} must include invariants")
        if any(not isinstance(value, bool) for value in invariants.values()):
            raise ValueError(f"{scenario_id} invariants must be booleans")
        missing_invariants = set(scenarios[scenario_id]["required_invariants"]) - set(invariants)
        if missing_invariants:
            raise ValueError(f"{scenario_id} is missing invariants: {sorted(missing_invariants)}")
        if not all(invariants.values()) and result == "pass":
            raise ValueError(f"{scenario_id} has a false invariant in a passing report")
        old_identity = dict(entry.get("old_identity") or {})
        new_identity = dict(entry.get("new_identity") or {})
        old_identity.setdefault("trace_id", trace_id)
        new_identity.setdefault("trace_id", trace_id)
        _validate_identity(old_identity, identity_fields, name=f"{scenario_id}.old_identity")
        _validate_identity(new_identity, identity_fields, name=f"{scenario_id}.new_identity")
        scenario_result = result
        report_scenarios.append(
            {
                "scenario_id": scenario_id,
                "scenario_name": scenarios[scenario_id]["name"],
                "events": events,
                "old_identity": old_identity,
                "new_identity": new_identity,
                "decision": decision,
                "invariants": invariants,
                "result": scenario_result,
                "test_name": entry.get("test_name", scenario_id),
            }
        )
    return {
        "schema_version": 2,
        "repository": "yhan-sun/p2wlan",
        "component": component,
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "toolchain": toolchain,
        "result": result,
        "trace_id": trace_id,
        "scenarios": report_scenarios,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--component", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--result", choices=("pass", "fail"), required=True)
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
            result=args.result,
            manifest_path=args.manifest,
            toolchain=toolchain,
        )
    except (ContractError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
