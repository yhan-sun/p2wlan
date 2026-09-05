#!/usr/bin/env python3
"""Build and validate fail-closed cross-task integration evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain a JSON object")
    return value


def _require_sha(value: str, field: str) -> str:
    if not _SHA_RE.fullmatch(value):
        raise EvidenceError(f"{field} must be a lowercase 40-character git SHA")
    return value


def _required_checks(contract: dict[str, Any]) -> list[dict[str, str]]:
    if contract.get("schema_version") != 1:
        raise EvidenceError("unsupported contract schema_version")
    if contract.get("repository") != "yhan-sun/p2wlan":
        raise EvidenceError("unexpected contract repository")
    raw = contract.get("required_checks")
    if not isinstance(raw, list) or not raw:
        raise EvidenceError("required_checks must be a non-empty list")

    checks: list[dict[str, str]] = []
    names: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise EvidenceError(f"required_checks[{index}] must be an object")
        name = item.get("name")
        category = item.get("category")
        if not isinstance(name, str) or not name.strip():
            raise EvidenceError(f"required_checks[{index}].name must be non-empty")
        if not isinstance(category, str) or not category.strip():
            raise EvidenceError(f"required_checks[{index}].category must be non-empty")
        if name in names:
            raise EvidenceError(f"duplicate required check name: {name}")
        names.add(name)
        checks.append({"name": name, "category": category})
    return checks


def build_manifest(
    *,
    contract: dict[str, Any],
    snapshot: dict[str, Any],
    repository: str,
    source_head_sha: str,
    workflow_sha: str,
    event_name: str,
    run_id: str,
    run_attempt: str,
) -> dict[str, Any]:
    required = _required_checks(contract)
    if repository != contract["repository"]:
        raise EvidenceError("repository does not match contract")
    _require_sha(source_head_sha, "source_head_sha")
    _require_sha(workflow_sha, "workflow_sha")

    if snapshot.get("repository") != repository:
        raise EvidenceError("snapshot repository mismatch")
    if snapshot.get("source_head_sha") != source_head_sha:
        raise EvidenceError("snapshot source_head_sha mismatch")

    raw_checks = snapshot.get("checks")
    if not isinstance(raw_checks, list):
        raise EvidenceError("snapshot checks must be a list")

    by_name: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for item in raw_checks:
        if not isinstance(item, dict):
            raise EvidenceError("snapshot check entry must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise EvidenceError("snapshot check name must be non-empty")
        if name in by_name:
            duplicates.append(name)
        else:
            by_name[name] = item

    reasons: list[str] = []
    if duplicates:
        reasons.append("duplicate_checks:" + ",".join(sorted(set(duplicates))))

    evidence_checks: list[dict[str, Any]] = []
    skipped: list[str] = []
    for requirement in required:
        name = requirement["name"]
        item = by_name.get(name)
        if item is None:
            reasons.append(f"missing:{name}")
            evidence_checks.append(
                {
                    "name": name,
                    "category": requirement["category"],
                    "present": False,
                    "status": "missing",
                    "conclusion": None,
                }
            )
            continue

        status = item.get("status")
        conclusion = item.get("conclusion")
        if status != "completed":
            reasons.append(f"not_completed:{name}:{status}")
        if conclusion == "skipped":
            skipped.append(name)
        if status == "completed" and conclusion != "success":
            reasons.append(f"not_success:{name}:{conclusion}")

        evidence_checks.append(
            {
                "name": name,
                "category": requirement["category"],
                "present": True,
                "check_run_id": item.get("id"),
                "status": status,
                "conclusion": conclusion,
                "details_url": item.get("details_url"),
                "started_at": item.get("started_at"),
                "completed_at": item.get("completed_at"),
            }
        )

    if skipped:
        reasons.append("skipped_required:" + ",".join(skipped))

    result = "pass" if not reasons else "fail"
    return {
        "schema_version": 1,
        "repository": repository,
        "source_head_sha": source_head_sha,
        "workflow_sha": workflow_sha,
        "event_name": event_name,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "trigger_marker": contract.get("trigger_marker"),
        "required_check_count": len(required),
        "observed_required_check_count": sum(1 for item in evidence_checks if item["present"]),
        "no_skipped_required_gate": not skipped,
        "exact_head": snapshot.get("source_head_sha") == source_head_sha,
        "checks": evidence_checks,
        "result": result,
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output: dict[str, Any]
    try:
        output = build_manifest(
            contract=_load_json(args.contract),
            snapshot=_load_json(args.snapshot),
            repository=args.repository,
            source_head_sha=args.source_head_sha,
            workflow_sha=args.workflow_sha,
            event_name=args.event_name,
            run_id=args.run_id,
            run_attempt=args.run_attempt,
        )
    except EvidenceError as exc:
        output = {
            "schema_version": 1,
            "repository": args.repository,
            "source_head_sha": args.source_head_sha,
            "workflow_sha": args.workflow_sha,
            "event_name": args.event_name,
            "run_id": str(args.run_id),
            "run_attempt": str(args.run_attempt),
            "result": "fail",
            "reasons": [f"evidence_error:{exc}"],
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output.get("result") != "pass":
        print("Cross-task integration evidence rejected: " + "; ".join(output.get("reasons", [])))
        return 1
    print(
        "Cross-task integration evidence passed for "
        f"{output['source_head_sha']} with {output['required_check_count']} required checks"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
