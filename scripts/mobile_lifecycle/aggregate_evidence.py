#!/usr/bin/env python3
"""Fail-closed aggregation for deterministic mobile lifecycle evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from .contract import ContractError, load_contract, scenarios_by_id
except ImportError:  # pragma: no cover - direct CI script execution
    from contract import ContractError, load_contract, scenarios_by_id


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
COMPONENTS = ("flutter", "android_jvm", "rust")
REPORT_NAMES = tuple(f"{component}.json" for component in COMPONENTS)
SENSITIVE_MARKERS = (
    "authorization",
    "bearer ",
    "jwt",
    "private_key",
    "diagnostics_token",
    "auth_token",
    "-----begin",
)


class EvidenceError(ValueError):
    """Raised for any malformed or incomplete evidence."""


def _load_report(path: Path) -> dict[str, Any]:
    if path.stat().st_size == 0:
        raise EvidenceError(f"empty report: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"invalid report {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"report {path.name} must be an object")
    return value


def _scan_sensitive(value: Any, path: str = "report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in SENSITIVE_MARKERS):
                raise EvidenceError(f"sensitive field is not allowed: {path}.{key}")
            _scan_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_sensitive(child, f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in SENSITIVE_MARKERS):
            raise EvidenceError(f"sensitive value is not allowed at {path}")


def _identity(identity: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(identity, dict) or not identity:
        raise EvidenceError(f"{name} must be a non-empty object")
    unknown = set(identity) - fields
    if unknown:
        raise EvidenceError(f"{name} has unknown fields: {sorted(unknown)}")
    for key, value in identity.items():
        if key == "trace_id":
            if not isinstance(value, str) or not re.fullmatch(r"mobile-lifecycle-[0-9a-f]{12}", value):
                raise EvidenceError(f"{name}.trace_id is invalid")
        elif isinstance(value, bool) or not isinstance(value, (int, str)):
            raise EvidenceError(f"{name}.{key} must be an integer or string")
        elif isinstance(value, int) and value < 0:
            raise EvidenceError(f"{name}.{key} cannot be negative")
    return identity


def aggregate(
    reports_dir: Path,
    source_head_sha: str,
    workflow_sha: str,
    *,
    job_results: dict[str, str] | None = None,
) -> dict[str, Any]:
    contract = load_contract()
    if not SHA_RE.fullmatch(source_head_sha) or not SHA_RE.fullmatch(workflow_sha):
        raise EvidenceError("aggregate SHA values must be 40-character SHA-1 values")
    if not reports_dir.is_dir():
        raise EvidenceError(f"reports directory does not exist: {reports_dir}")
    if job_results is not None:
        if not isinstance(job_results, dict):
            raise EvidenceError("job results must be an object")
        allowed_job_keys = {frozenset(COMPONENTS), frozenset((*COMPONENTS, "package"))}
        if frozenset(job_results) not in allowed_job_keys:
            raise EvidenceError("job results must name the required components and optional package job")
        allowed_job_results = {"success", "failure", "cancelled", "skipped"}
        if any(value not in allowed_job_results for value in job_results.values()):
            raise EvidenceError("job results contain an unknown conclusion")
        if "package" in job_results and job_results["package"] != "success":
            raise EvidenceError("Android package job did not succeed")
    actual = sorted(path.name for path in reports_dir.iterdir())
    if tuple(actual) != tuple(sorted(REPORT_NAMES)):
        raise EvidenceError(f"reports directory must contain exactly {list(REPORT_NAMES)}, got {actual}")
    reports: dict[str, dict[str, Any]] = {}
    trace_ids: set[str] = set()
    identity_fields = set(contract["identity_fields"])
    by_scenario: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for component in COMPONENTS:
        report = _load_report(reports_dir / f"{component}.json")
        _scan_sensitive(report)
        if report.get("schema_version") != 2:
            raise EvidenceError(f"{component} report schema_version is not 2")
        if report.get("repository") != "yhan-sun/p2wlan":
            raise EvidenceError(f"{component} report repository is invalid")
        if report.get("component") != component:
            raise EvidenceError(f"{component} report component field is invalid")
        if report.get("source_head_sha") != source_head_sha:
            raise EvidenceError(f"{component} report source_head_sha mismatch")
        if report.get("workflow_sha") != workflow_sha:
            raise EvidenceError(f"{component} report workflow_sha mismatch")
        if report.get("result") != "pass":
            raise EvidenceError(f"{component} report is not passing")
        trace_id = report.get("trace_id")
        if not isinstance(trace_id, str) or trace_id != f"mobile-lifecycle-{source_head_sha[:12]}":
            raise EvidenceError(f"{component} report trace_id does not bind to source SHA")
        trace_ids.add(trace_id)
        scenarios = report.get("scenarios")
        if not isinstance(scenarios, list) or not scenarios:
            raise EvidenceError(f"{component} report scenarios are empty")
        seen: set[str] = set()
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                raise EvidenceError(f"{component} scenario is not an object")
            scenario_id = scenario.get("scenario_id")
            if scenario_id not in scenarios_by_id(contract):
                raise EvidenceError(f"{component} has unknown scenario {scenario_id!r}")
            if scenario_id in seen:
                raise EvidenceError(f"{component} repeats scenario {scenario_id}")
            seen.add(scenario_id)
            allowed = scenarios_by_id(contract)[scenario_id]["authoritative_components"]
            if component not in allowed:
                raise EvidenceError(f"{component} is not authoritative for {scenario_id}")
            events = scenario.get("events")
            if not isinstance(events, list) or not events or any(event not in contract["events"] for event in events):
                raise EvidenceError(f"{component}/{scenario_id} has invalid events")
            decision = scenario.get("decision")
            if decision not in contract["outcomes"]:
                raise EvidenceError(f"{component}/{scenario_id} has invalid decision")
            if decision != scenarios_by_id(contract)[scenario_id]["required_decision"]:
                raise EvidenceError(f"{component}/{scenario_id} has the wrong decision")
            if scenario.get("result") != "pass":
                raise EvidenceError(f"{component}/{scenario_id} is not passing")
            invariants = scenario.get("invariants")
            if not isinstance(invariants, dict) or not invariants or not all(invariants.values()):
                raise EvidenceError(f"{component}/{scenario_id} has a false/missing invariant")
            required_invariants = set(scenarios_by_id(contract)[scenario_id]["required_invariants"])
            if not required_invariants.issubset(invariants):
                raise EvidenceError(f"{component}/{scenario_id} is missing a required invariant")
            old = _identity(scenario.get("old_identity"), identity_fields, f"{component}/{scenario_id}/old_identity")
            new = _identity(scenario.get("new_identity"), identity_fields, f"{component}/{scenario_id}/new_identity")
            if old.get("trace_id") != trace_id or new.get("trace_id") != trace_id:
                raise EvidenceError(f"{component}/{scenario_id} trace identity mismatch")
            if decision == "applied" and old == new and scenario_id not in {"ML-18"}:
                raise EvidenceError(f"{component}/{scenario_id} applied without an identity transition")
            if decision == "stale_rejected" and old == new:
                raise EvidenceError(f"{component}/{scenario_id} stale rejection has no old identity")
            by_scenario.setdefault(scenario_id, []).append((component, scenario))
        reports[component] = report
        if job_results is not None and job_results.get(component) != "success":
            raise EvidenceError(f"component job {component} did not succeed")
    required = scenarios_by_id(contract)
    missing = sorted(set(required) - set(by_scenario))
    if missing:
        raise EvidenceError(f"required scenarios are missing: {missing}")
    for scenario_id, entries in by_scenario.items():
        if len(entries) > 1:
            decisions = {entry[1]["decision"] for entry in entries}
            traces = {entry[1]["new_identity"].get("trace_id") for entry in entries}
            if len(decisions) > 1 or len(traces) != 1:
                raise EvidenceError(f"conflicting duplicate scenario evidence: {scenario_id}")
            # Components may contribute only the identities they own, but
            # overlapping fields must describe the same transition. This
            # prevents three mutually unrelated fakes from satisfying one
            # shared scenario ID.
            for index, (_, left) in enumerate(entries):
                for _, right in entries[index + 1 :]:
                    for side in ("old_identity", "new_identity"):
                        left_identity = left[side]
                        right_identity = right[side]
                        overlap = set(left_identity) & set(right_identity)
                        if any(left_identity[key] != right_identity[key] for key in overlap):
                            raise EvidenceError(
                                f"conflicting duplicate scenario identity: {scenario_id}/{side}"
                            )
    if len(trace_ids) != 1:
        raise EvidenceError("component reports do not share one trace identity")
    return {
        "schema_version": 2,
        "repository": "yhan-sun/p2wlan",
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "result": "pass",
        "components": {component: reports[component] for component in COMPONENTS},
        "required_scenarios": sorted(by_scenario),
        "manual_device_matrix": {
            "required": False,
            "status": "not_run",
            "blocking": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--job-results", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    job_results = None
    try:
        if args.job_results:
            job_results = json.loads(args.job_results.read_text(encoding="utf-8"))
        result = aggregate(
            args.reports_dir.resolve(),
            args.source_head_sha,
            args.workflow_sha,
            job_results=job_results,
        )
    except (ContractError, EvidenceError, OSError, json.JSONDecodeError, TypeError) as error:
        # Keep a structured, non-green artifact even when a component is
        # missing or malformed. The caller still receives a non-zero status;
        # this file is useful for diagnosing why the required check failed.
        args.output.parent.mkdir(parents=True, exist_ok=True)
        failure = {
            "schema_version": 2,
            "repository": "yhan-sun/p2wlan",
            "source_head_sha": args.source_head_sha,
            "workflow_sha": args.workflow_sha,
            "result": "fail",
            "error": str(error),
            "manual_device_matrix": {
                "required": False,
                "status": "not_run",
                "blocking": False,
            },
        }
        args.output.write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"mobile lifecycle evidence rejected: {error}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
