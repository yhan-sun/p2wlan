#!/usr/bin/env python3
"""Aggregate security evidence with strict identity and schema validation."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from report_common import SCHEMA_VERSION, failure_categories, make_report, repository_name

REQUIRED = {
    "rust-summary.json": "rust_dependency_audit",
    "go-summary.json": "go_vulnerability_audit",
    "flutter-summary.json": "flutter_dependency_audit",
    "flutter-lock-policy.json": "flutter_lock_source_policy",
    "flutter-outdated-triage.json": "flutter_outdated_triage",
    "workflow-permissions.json": "workflow_permission_audit",
    "credential-scan.json": "credential_transport_scan",
    "release-assets.json": "release_asset_verification",
    "release-asset-credential-scan.json": "release_asset_plaintext_scan",
    "evidence-credential-scan.json": "generated_evidence_plaintext_scan",
}
REQUIRED_JOB_NAMES = (
    "repository-policy",
    "rust-dependencies",
    "go-dependencies",
    "flutter-dependencies",
    "release-assets",
)
ALLOWED_EVIDENCE_FILES = {
    *REQUIRED,
    "cargo-audit-root.json",
    "cargo-audit-root.stderr",
    "cargo-audit-fuzz.json",
    "cargo-audit-fuzz.stderr",
    "cargo-deny-root.jsonl",
    "cargo-deny-root.stderr",
    "cargo-deny-fuzz.jsonl",
    "cargo-deny-fuzz.stderr",
    "go-mod-verify.txt",
    "go-test.txt",
    "go-vet.txt",
    "go-modules.json",
    "go-modules.stderr",
    "govulncheck.jsonl",
    "govulncheck-json.stderr",
    "govulncheck.txt",
    "pubspec.lock.before",
    "flutter-pub-get.txt",
    "flutter-deps.txt",
    "flutter-deps.stderr",
    "flutter-outdated.json",
    "flutter-outdated.stderr",
    "flutter-analyze.txt",
    "flutter-lock-policy.txt",
    "flutter-outdated-triage.txt",
    "release.json",
    "releases.json",
    "gh-version.txt",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(root.rglob("*"))


def _load_named(root: Path, filename: str) -> dict[str, Any]:
    matches = [
        path
        for path in _files(root)
        if path.name == filename and path.is_file() and not path.is_symlink()
    ]
    if len(matches) != 1:
        return {}
    try:
        value = json.loads(matches[0].read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _int_value(value: dict[str, Any], key: str) -> int:
    raw = value.get(key)
    return raw if isinstance(raw, int) and not isinstance(raw, bool) else 0


def _nested_int(value: dict[str, Any], parent: str, key: str) -> int:
    raw = value.get(parent)
    if not isinstance(raw, dict):
        return 0
    nested = raw.get(key)
    return nested if isinstance(nested, int) and not isinstance(nested, bool) else 0


def _field(findings: list[dict[str, Any]], filename: str, code: str, message: str) -> None:
    findings.append({"code": code, "message": f"{filename}: {message}"})


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_report(
    filename: str,
    expected_component: str,
    value: dict[str, Any],
    *,
    repository: str,
    head_sha: str,
    workflow_sha: str | None,
    findings: list[dict[str, Any]],
) -> None:
    required_fields = {
        "schema_version",
        "repository",
        "component",
        "source_commit",
        "head_sha",
        "workflow_sha",
        "tool",
        "tools",
        "tool_versions",
        "command",
        "generated_at",
        "result",
        "failure_category",
        "evidence_summary",
        "findings",
    }
    for name in sorted(required_fields - value.keys()):
        _field(findings, filename, "report_schema_field_missing", f"missing {name}")

    if value.get("schema_version") != SCHEMA_VERSION:
        _field(findings, filename, "report_schema_version", f"expected {SCHEMA_VERSION}, got {value.get('schema_version')!r}")
    if value.get("repository") != repository:
        _field(findings, filename, "report_repository_mismatch", f"expected {repository!r}, got {value.get('repository')!r}")
    if value.get("component") != expected_component:
        _field(findings, filename, "report_component_mismatch", f"expected {expected_component!r}, got {value.get('component')!r}")
    if value.get("source_commit") != head_sha or value.get("head_sha") != head_sha:
        _field(findings, filename, "evidence_head_mismatch", f"expected source/head {head_sha}, got {value.get('source_commit')!r}/{value.get('head_sha')!r}")
    if workflow_sha is not None and value.get("workflow_sha") != workflow_sha:
        _field(findings, filename, "evidence_workflow_sha_mismatch", f"expected {workflow_sha}, got {value.get('workflow_sha')!r}")
    elif workflow_sha is None and value.get("workflow_sha") != head_sha:
        _field(findings, filename, "evidence_workflow_sha_mismatch", f"expected {head_sha}, got {value.get('workflow_sha')!r}")

    if not isinstance(value.get("tool"), str) or not value.get("tool"):
        _field(findings, filename, "report_tool_missing", "tool is not a non-empty string")
    if not isinstance(value.get("tools"), dict) or not value.get("tools"):
        _field(findings, filename, "report_tool_versions_missing", "tools is not a non-empty object")
    if not isinstance(value.get("tool_versions"), dict) or not value.get("tool_versions"):
        _field(findings, filename, "report_tool_versions_missing", "tool_versions is not a non-empty object")
    if not isinstance(value.get("command"), (str, list)) or not value.get("command"):
        _field(findings, filename, "report_command_missing", "command is empty or has an invalid type")
    if not _valid_timestamp(value.get("generated_at")):
        _field(findings, filename, "report_timestamp_invalid", "generated_at is not an ISO-8601 timestamp")
    if value.get("result") not in {"pass", "fail"}:
        _field(findings, filename, "report_result_invalid", f"result is {value.get('result')!r}")
    if not isinstance(value.get("failure_category"), list) or any(
        not isinstance(item, str) or not item for item in value.get("failure_category", [])
    ):
        _field(findings, filename, "report_failure_category_invalid", "failure_category must be a list of strings")
    if not isinstance(value.get("evidence_summary"), dict):
        _field(findings, filename, "report_evidence_summary_invalid", "evidence_summary must be an object")
    report_findings = value.get("findings")
    if not isinstance(report_findings, list) or any(not isinstance(item, dict) for item in report_findings):
        _field(findings, filename, "report_findings_invalid", "findings must be a list of objects")
        report_findings = []

    expected_categories = sorted(
        {str(item.get("code")) for item in report_findings if item.get("code")}
    )
    if value.get("failure_category") != expected_categories:
        _field(findings, filename, "report_failure_category_inconsistent", "failure_category does not match findings")
    expected_result = "pass" if not report_findings and not expected_categories else "fail"
    if value.get("result") != expected_result:
        _field(findings, filename, "report_result_inconsistent", f"result should be {expected_result!r} for the reported findings")

    checks = value.get("checks")
    if isinstance(checks, dict):
        for check_name, status in checks.items():
            if not isinstance(status, int) or isinstance(status, bool) or status != 0:
                _field(findings, filename, "report_check_not_success", f"{check_name} has status {status!r}")

    if expected_component == "rust_dependency_audit" and _nested_int(value, "vulnerability_counts", "total") != 0:
        _field(findings, filename, "report_vulnerability_count_nonzero", "Rust vulnerability count is non-zero")
    if expected_component == "go_vulnerability_audit" and _int_value(value, "vulnerability_count") != 0:
        _field(findings, filename, "report_vulnerability_count_nonzero", "Go vulnerability count is non-zero")
    if expected_component == "flutter_outdated_triage" and _nested_int(value, "counts", "blockers") != 0:
        _field(findings, filename, "report_outdated_blocker_count_nonzero", "Flutter outdated blocker count is non-zero")
    if expected_component == "flutter_dependency_audit" and _nested_int(value, "outdated_dependency_counts", "blockers") != 0:
        _field(findings, filename, "report_outdated_blocker_count_nonzero", "Flutter outdated blocker count is non-zero")
    if expected_component == "release_asset_verification":
        if _int_value(value, "verified_asset_count") != _int_value(value, "asset_count"):
            _field(findings, filename, "report_asset_count_inconsistent", "verified_asset_count does not equal asset_count")
        classes = value.get("required_asset_classes")
        if not isinstance(classes, dict) or not classes or not all(classes.values()):
            _field(findings, filename, "report_required_asset_class_missing", "not all required asset classes are true")


def run(
    root: Path,
    head_sha: str,
    *,
    repository: str | None = None,
    workflow_sha: str | None = None,
    needs_results: dict[str, str] | None = None,
) -> dict[str, Any]:
    expected_repository = repository_name(repository)
    findings: list[dict[str, Any]] = []
    files = _files(root)
    if not root.is_dir() or not files:
        findings.append({"code": "evidence_root_empty", "message": "evidence root is missing or empty"})

    for path in files:
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            findings.append({"code": "unsafe_evidence_entry", "message": relative})
        elif relative not in ALLOWED_EVIDENCE_FILES:
            findings.append({"code": "unknown_evidence_file", "message": relative})

    if needs_results is None:
        findings.append({"code": "needs_results_missing", "message": "aggregate was not given all required job results"})
    else:
        unknown_jobs = sorted(set(needs_results) - set(REQUIRED_JOB_NAMES))
        for name in unknown_jobs:
            findings.append({"code": "unknown_needs_result", "message": name})
        for name in REQUIRED_JOB_NAMES:
            status = needs_results.get(name)
            if status is None:
                findings.append({"code": "needs_result_missing", "message": name})
            elif status != "success":
                findings.append({"code": "required_job_not_success", "message": f"{name}: {status}"})

    checks: dict[str, Any] = {}
    evidence_files: list[dict[str, Any]] = []
    loaded: dict[str, dict[str, Any]] = {}
    for filename, component in REQUIRED.items():
        matches = [
            path
            for path in files
            if path.name == filename and path.is_file() and not path.is_symlink()
        ]
        if len(matches) != 1:
            findings.append({"code": "evidence_file_missing_or_ambiguous", "message": f"{filename}: found {len(matches)}"})
            continue
        path = matches[0]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            findings.append({"code": "invalid_evidence_json", "message": f"{filename}: {error}"})
            continue
        if not isinstance(value, dict):
            findings.append({"code": "invalid_evidence_schema", "message": f"{filename}: root is not an object"})
            continue
        loaded[filename] = value
        _validate_report(
            filename,
            component,
            value,
            repository=expected_repository,
            head_sha=head_sha,
            workflow_sha=workflow_sha,
            findings=findings,
        )
        checks[component] = {
            "result": value.get("result"),
            "source": filename,
            "source_commit": value.get("source_commit"),
            "workflow_sha": value.get("workflow_sha"),
        }

    for path in files:
        if path.is_file() and not path.is_symlink() and path.relative_to(root).as_posix() in ALLOWED_EVIDENCE_FILES:
            try:
                evidence_files.append(
                    {
                        "path": path.relative_to(root).as_posix(),
                        "size": path.stat().st_size,
                        "sha256": digest(path),
                    }
                )
            except OSError as error:
                findings.append({"code": "evidence_file_unreadable", "message": f"{path.name}: {error}"})

    rust = loaded.get("rust-summary.json", {})
    go = loaded.get("go-summary.json", {})
    flutter = loaded.get("flutter-summary.json", {})
    release = loaded.get("release-assets.json", {})
    counts = {
        "rust_vulnerabilities": _nested_int(rust, "vulnerability_counts", "total"),
        "go_vulnerabilities": _int_value(go, "vulnerability_count"),
        "flutter_outdated_classified": _nested_int(flutter, "outdated_dependency_counts", "classified"),
        "flutter_outdated_blockers": _nested_int(flutter, "outdated_dependency_counts", "blockers"),
        "release_assets_verified": _int_value(release, "verified_asset_count"),
    }
    tools = {
        key: value.get("tools", {})
        for key, value in {
            "rust": rust,
            "go": go,
            "flutter": flutter,
        }.items()
        if isinstance(value, dict)
    }
    evidence = make_report(
        component="security_audit_aggregate",
        head_sha=head_sha,
        workflow_sha=workflow_sha,
        repository=expected_repository,
        result="pass" if not findings else "fail",
        findings=findings,
        tool="aggregate_evidence.py",
        tools={"python": platform.python_version()},
        command=["aggregate_evidence.py", "--root", root.as_posix(), "--head-sha", head_sha],
        evidence_summary={
            "checks": checks,
            "summary_counts": counts,
            "evidence_file_count": len(evidence_files),
        },
        checks=checks,
        summary_counts=counts,
        tool_versions_by_component=tools,
        evidence_files=sorted(evidence_files, key=lambda item: str(item["path"])),
        product_signing={
            "code_signing": "deferred_non_blocking",
            "notarization": "deferred_non_blocking",
            "authenticode": "deferred_non_blocking",
            "reason": (
                "Issue #30 audits dependencies, workflows, credential transport and checksums "
                "without making product signing a gate."
            ),
        },
    )
    return evidence


def _parse_needs(values: list[str] | None) -> tuple[dict[str, str], list[str]]:
    parsed: dict[str, str] = {}
    errors: list[str] = []
    for value in values or []:
        if "=" not in value:
            errors.append(value)
            continue
        name, status = value.split("=", 1)
        if not name or not status or name in parsed:
            errors.append(value)
            continue
        parsed[name] = status
    return parsed, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--workflow-sha")
    parser.add_argument("--repository")
    parser.add_argument("--need", action="append", dest="needs_results")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    needs, parse_errors = _parse_needs(args.needs_results)
    evidence = run(
        args.root,
        args.head_sha,
        repository=args.repository,
        workflow_sha=args.workflow_sha,
        needs_results=needs,
    )
    for value in parse_errors:
        evidence["findings"].append({"code": "invalid_needs_result", "message": value})
    if parse_errors:
        evidence["result"] = "fail"
        evidence["failure_category"] = failure_categories(evidence["findings"])
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
