#!/usr/bin/env python3
"""Classify every outdated, discontinued or retracted Flutter package.

The policy is intentionally narrow: it only requires dependency updates when
Pub reports a direct/dev dependency with a newer resolvable version, or any
package that is discontinued, retracted, or affected by an advisory. Transitive
and SDK-constrained drift is recorded as evidence so it cannot silently
disappear from a release review.
"""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

from report_common import make_report

DIRECT_KINDS = {"direct", "dev", "direct main", "direct dev"}


def _version(value: Any) -> str | None:
    if isinstance(value, dict):
        raw = value.get("version")
        return str(raw) if raw is not None else None
    if value is None:
        return None
    return str(value)


def _bool(value: Any) -> bool:
    return value is True


def classify(package: dict[str, Any]) -> dict[str, Any] | None:
    name = str(package.get("package") or package.get("name") or "")
    kind = str(package.get("kind") or package.get("dependency") or "unknown").lower()
    current = _version(package.get("current"))
    upgradable = _version(package.get("upgradable"))
    resolvable = _version(package.get("resolvable"))
    latest = _version(package.get("latest"))
    discontinued = _bool(package.get("isDiscontinued"))
    retracted = _bool(package.get("isCurrentRetracted")) or _bool(
        package.get("isRetracted")
    )
    affected_by_advisory = _bool(package.get("isCurrentAffectedByAdvisory"))
    outdated = bool(current and latest and current != latest)

    if not (outdated or discontinued or retracted or affected_by_advisory):
        return None

    blocker = False
    if affected_by_advisory:
        classification = "current_version_affected_by_advisory"
        reason = "Pub marks the resolved package version as affected by an advisory."
        blocker = True
    elif discontinued:
        classification = "discontinued"
        reason = (
            "Pub marks this package discontinued; replacement or documented "
            "removal is required."
        )
        blocker = True
    elif retracted:
        classification = "current_version_retracted"
        reason = "The resolved version is retracted and is not release-admissible."
        blocker = True
    elif kind in DIRECT_KINDS and current and resolvable and current != resolvable:
        classification = "direct_resolvable_upgrade_required"
        reason = (
            "A newer direct/dev version resolves under current constraints; "
            "update and retest before release."
        )
        blocker = True
    elif kind in DIRECT_KINDS:
        classification = "direct_constraint_or_sdk_pinned"
        reason = (
            "Latest differs, but current constraints or the Flutter SDK do not "
            "resolve a newer version."
        )
    else:
        classification = "transitive_or_sdk_pinned"
        reason = (
            "Transitive drift is tracked; the owning direct dependency or "
            "Flutter SDK controls the update."
        )

    return {
        "package": name,
        "kind": kind,
        "current": current,
        "upgradable": upgradable,
        "resolvable": resolvable,
        "latest": latest,
        "discontinued": discontinued,
        "retracted": retracted,
        "affected_by_advisory": affected_by_advisory,
        "classification": classification,
        "release_blocker": blocker,
        "reason": reason,
    }


def run(
    input_path: Path,
    head_sha: str | None = None,
    *,
    repository: str | None = None,
    workflow_sha: str | None = None,
) -> dict[str, Any]:
    command = ["flutter_outdated_triage.py", "--input", input_path.as_posix()]
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        findings = [{"code": "invalid_outdated_json", "message": str(error)}]
        return make_report(
            component="flutter_outdated_triage",
            head_sha=head_sha,
            workflow_sha=workflow_sha,
            repository=repository,
            result="fail",
            findings=findings,
            tool="flutter_outdated_triage.py",
            tools={"python": platform.python_version()},
            command=command,
            evidence_summary={
                "reported": 0,
                "classified": 0,
                "blockers": 1,
            },
            policy={},
            counts={"reported": 0, "classified": 0, "blockers": 1},
            packages=[],
        )

    if not isinstance(payload, dict):
        findings = [
            {
                "code": "invalid_outdated_schema",
                "message": "flutter pub outdated --json root must be an object",
            }
        ]
        return make_report(
            component="flutter_outdated_triage",
            head_sha=head_sha,
            workflow_sha=workflow_sha,
            repository=repository,
            result="fail",
            findings=findings,
            tool="flutter_outdated_triage.py",
            tools={"python": platform.python_version()},
            command=command,
            evidence_summary={"reported": 0, "classified": 0, "blockers": 1},
            policy={},
            counts={"reported": 0, "classified": 0, "blockers": 1},
            packages=[],
        )

    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, list):
        findings = [
            {
                "code": "packages_missing",
                "message": (
                    "flutter pub outdated --json did not return a packages array"
                ),
            }
        ]
        return make_report(
            component="flutter_outdated_triage",
            head_sha=head_sha,
            workflow_sha=workflow_sha,
            repository=repository,
            result="fail",
            findings=findings,
            tool="flutter_outdated_triage.py",
            tools={"python": platform.python_version()},
            command=command,
            evidence_summary={
                "reported": 0,
                "classified": 0,
                "blockers": 1,
            },
            policy={},
            counts={"reported": 0, "classified": 0, "blockers": 1},
            packages=[],
        )

    malformed = [package for package in raw_packages if not isinstance(package, dict)]
    for package in raw_packages:
        if isinstance(package, dict) and not (package.get("package") or package.get("name")):
            malformed.append(package)
    findings: list[dict[str, str]] = []
    if malformed:
        findings.append(
            {
                "code": "invalid_package_record",
                "message": "flutter pub outdated --json contains a package record without a name",
            }
        )
    classified = [
        item
        for package in raw_packages
        if isinstance(package, dict)
        if (item := classify(package))
    ]
    classified.sort(key=lambda item: str(item["package"]))
    blockers = [item for item in classified if item["release_blocker"]]
    findings.extend(
        {
            "code": "release_blocking_dependency",
            "package": item["package"],
            "classification": item["classification"],
            "message": item["reason"],
        }
        for item in blockers
    )
    counts = {
        "reported": len(raw_packages),
        "classified": len(classified),
        "blockers": len(blockers),
    }
    policy = {
        "discontinued_or_retracted": "block",
        "current_version_affected_by_advisory": "block",
        "direct_resolvable_upgrade": "block",
        "direct_constraint_or_sdk_pinned": "record",
        "transitive_or_sdk_pinned": "record",
    }
    return make_report(
        component="flutter_outdated_triage",
        head_sha=head_sha,
        workflow_sha=workflow_sha,
        repository=repository,
        result="pass" if not findings else "fail",
        findings=findings,
        tool="flutter_outdated_triage.py",
        tools={"python": platform.python_version()},
        command=command,
        evidence_summary=counts,
        policy=policy,
        counts=counts,
        packages=classified,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--head-sha")
    parser.add_argument("--workflow-sha")
    parser.add_argument("--repository")
    args = parser.parse_args()
    evidence = run(
        args.input,
        args.head_sha,
        repository=args.repository,
        workflow_sha=args.workflow_sha,
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
