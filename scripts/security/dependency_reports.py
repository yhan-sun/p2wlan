#!/usr/bin/env python3
"""Build structured, fail-closed dependency audit summaries.

Scanner exit codes remain authoritative. This module extracts stable counts and
tool metadata without converting a failed scanner into a warning.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from report_common import make_report


def _read_json(
    path: Path, findings: list[dict[str, str]], code: str
) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        findings.append({"code": code, "message": f"{path}: {error}"})
        return None


def _read_json_lines(
    path: Path, findings: list[dict[str, str]], code: str
) -> list[Any]:
    values: list[Any] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        findings.append({"code": code, "message": f"{path}: {error}"})
        return values
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError as error:
            findings.append(
                {"code": code, "message": f"{path}:{number}: {error}"}
            )
    return values


def _read_json_stream(
    path: Path, findings: list[dict[str, str]], code: str
) -> list[Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        findings.append({"code": code, "message": f"{path}: {error}"})
        return []
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = 0
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as error:
            findings.append({"code": code, "message": f"{path}: {error}"})
            break
        values.append(value)
    return values


def _is_reachable_govulncheck_finding(finding: dict[str, Any]) -> bool:
    """Return whether a govulncheck finding has a code/package trace.

    govulncheck's JSON stream includes one-frame module metadata findings even
    when the vulnerable code is not reachable. A finding without a usable
    trace is treated as actionable so malformed evidence fails closed.
    """
    trace = finding.get("trace")
    if not isinstance(trace, list) or not trace:
        return True
    return any(
        isinstance(frame, dict)
        and any(key in frame for key in ("package", "function", "position"))
        for frame in trace
    )


def _audit_counts(value: Any) -> tuple[int, int]:
    if not isinstance(value, dict):
        return 0, 0
    vulnerabilities = value.get("vulnerabilities")
    vulnerability_count = 0
    if isinstance(vulnerabilities, dict):
        raw = vulnerabilities.get("count")
        if isinstance(raw, int):
            vulnerability_count = raw
        elif isinstance(vulnerabilities.get("list"), list):
            vulnerability_count = len(vulnerabilities["list"])
    warnings = value.get("warnings")
    warning_count = 0
    if isinstance(warnings, dict):
        warning_count = sum(
            len(items) for items in warnings.values() if isinstance(items, list)
        )
    elif isinstance(warnings, list):
        warning_count = len(warnings)
    return vulnerability_count, warning_count


def rust_summary(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    statuses = {
        "cargo_audit_root": args.root_audit_status,
        "cargo_audit_fuzz": args.fuzz_audit_status,
        "cargo_deny_root": args.root_deny_status,
        "cargo_deny_fuzz": args.fuzz_deny_status,
    }
    for name, status in statuses.items():
        if status != 0:
            findings.append(
                {"code": "scanner_nonzero", "message": f"{name} exited {status}"}
            )

    root_audit = _read_json(
        args.root_audit, findings, "invalid_cargo_audit_json"
    )
    fuzz_audit = _read_json(
        args.fuzz_audit, findings, "invalid_cargo_audit_json"
    )
    root_vulns, root_warnings = _audit_counts(root_audit)
    fuzz_vulns, fuzz_warnings = _audit_counts(fuzz_audit)
    root_deny = _read_json_lines(
        args.root_deny, findings, "invalid_cargo_deny_jsonl"
    )
    fuzz_deny = _read_json_lines(
        args.fuzz_deny, findings, "invalid_cargo_deny_jsonl"
    )

    result = "pass" if not findings else "fail"
    return make_report(
        component="rust_dependency_audit",
        head_sha=args.head_sha,
        workflow_sha=getattr(args, "workflow_sha", None),
        repository=getattr(args, "repository", None),
        result=result,
        findings=findings,
        tool="cargo-audit/cargo-deny",
        tools={
            "cargo_audit": args.cargo_audit_version,
            "cargo_deny": args.cargo_deny_version,
        },
        command=[
            "cargo audit --file Cargo.lock --json",
            "cargo audit --file fuzz/Cargo.lock --json",
            "cargo deny --config deny.toml --format json check advisories bans licenses sources",
            "cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --format json check advisories bans licenses sources",
        ],
        evidence_summary={
            "checks": statuses,
            "vulnerability_counts": {
                "root": root_vulns,
                "fuzz": fuzz_vulns,
                "total": root_vulns + fuzz_vulns,
            },
            "warning_counts": {
                "root": root_warnings,
                "fuzz": fuzz_warnings,
                "total": root_warnings + fuzz_warnings,
            },
            "cargo_deny_record_counts": {
                "root": len(root_deny),
                "fuzz": len(fuzz_deny),
            },
        },
        checks=statuses,
        vulnerability_counts={
            "root": root_vulns,
            "fuzz": fuzz_vulns,
            "total": root_vulns + fuzz_vulns,
        },
        warning_counts={
            "root": root_warnings,
            "fuzz": fuzz_warnings,
            "total": root_warnings + fuzz_warnings,
        },
        cargo_deny_record_counts={
            "root": len(root_deny),
            "fuzz": len(fuzz_deny),
        },
        advisory_ignores=[],
    )


def go_summary(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    statuses = {
        "go_mod_verify": args.mod_status,
        "go_test": args.test_status,
        "go_vet": getattr(args, "vet_status", 0),
        "go_list_modules": args.modules_status,
        "govulncheck_json": args.json_status,
        "govulncheck_gate": args.vuln_status,
    }
    for name, status in statuses.items():
        if status != 0:
            findings.append(
                {"code": "scanner_nonzero", "message": f"{name} exited {status}"}
            )

    messages = _read_json_stream(
        args.govulncheck_json, findings, "invalid_govulncheck_json_stream"
    )
    if not messages:
        findings.append(
            {
                "code": "empty_govulncheck_json",
                "message": "govulncheck JSON output contained no documents",
            }
        )
    modules = _read_json_stream(
        args.modules_json, findings, "invalid_go_module_json_stream"
    )
    if not modules:
        findings.append(
            {
                "code": "empty_go_module_json",
                "message": "go list -m -json all produced no module documents",
            }
        )
    osv_ids: set[str] = set()
    finding_messages = 0
    unreachable_finding_messages = 0
    for value in messages:
        if not isinstance(value, dict):
            continue
        finding = value.get("finding")
        if isinstance(finding, dict):
            finding_messages += 1
            osv = finding.get("osv")
            if isinstance(osv, str) and osv:
                if _is_reachable_govulncheck_finding(finding):
                    osv_ids.add(osv)
                else:
                    unreachable_finding_messages += 1
        osv = value.get("osv")
        # govulncheck emits full OSV advisory documents for reachable and
        # unreachable module metadata. Only ``finding`` documents are
        # actionable; retain support for the small synthetic ``{"osv":
        # {"id": ...}}`` shape used by local policy fixtures.
        if isinstance(osv, dict) and set(osv).issubset({"id"}):
            identifier = osv.get("id")
            if isinstance(identifier, str) and identifier:
                osv_ids.add(identifier)

    result = "pass" if not findings else "fail"
    return make_report(
        component="go_vulnerability_audit",
        head_sha=args.head_sha,
        workflow_sha=getattr(args, "workflow_sha", None),
        repository=getattr(args, "repository", None),
        result=result,
        findings=findings,
        tool="go/govulncheck",
        tools={
            "go": args.go_version,
            "govulncheck": args.govulncheck_version,
        },
        command=[
            "go mod verify",
            "go test ./... -count=1",
            "go vet ./...",
            "go list -m -json all",
            "govulncheck -json ./...",
            "govulncheck ./...",
        ],
        evidence_summary={
            "checks": statuses,
            "module_count": len(modules),
            "vulnerability_count": len(osv_ids),
            "finding_message_count": finding_messages,
            "vulnerability_ids": sorted(osv_ids),
            "unreachable_finding_message_count": unreachable_finding_messages,
        },
        checks=statuses,
        module_count=len(modules),
        vulnerability_count=len(osv_ids),
        finding_message_count=finding_messages,
        unreachable_finding_message_count=unreachable_finding_messages,
        vulnerability_ids=sorted(osv_ids),
    )


def flutter_summary(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    statuses = {
        "flutter_pub_get": args.get_status,
        "lockfile_unchanged": args.lock_status,
        "flutter_pub_deps": args.deps_status,
        "flutter_pub_outdated": args.outdated_status,
        "flutter_analyze": args.analyze_status,
        "lockfile_source_policy": args.lock_policy_status,
        "outdated_dependency_triage": args.triage_status,
    }
    for name, status in statuses.items():
        if status != 0:
            findings.append(
                {"code": "scanner_nonzero", "message": f"{name} exited {status}"}
            )

    lock_policy = _read_json(
        args.lock_policy, findings, "invalid_flutter_lock_policy"
    )
    triage = _read_json(
        args.triage, findings, "invalid_flutter_outdated_triage"
    )
    for name, value in (
        ("lockfile_source_policy", lock_policy),
        ("outdated_dependency_triage", triage),
    ):
        if isinstance(value, dict) and value.get("result") != "pass":
            findings.append(
                {
                    "code": "policy_failed",
                    "message": f"{name}: {value.get('result')!r}",
                }
            )

    triage_counts = (
        triage.get("counts", {}) if isinstance(triage, dict) else {}
    )
    lock_counts = (
        lock_policy.get("source_counts", {})
        if isinstance(lock_policy, dict)
        else {}
    )
    result = "pass" if not findings else "fail"
    return make_report(
        component="flutter_dependency_audit",
        head_sha=args.head_sha,
        workflow_sha=getattr(args, "workflow_sha", None),
        repository=getattr(args, "repository", None),
        result=result,
        findings=findings,
        tool="flutter/dart",
        tools={
            "flutter": args.flutter_version,
            "dart": args.dart_version,
        },
        command=[
            "flutter pub get",
            "flutter pub deps --style=compact",
            "flutter pub outdated --json",
            "flutter analyze",
            "flutter_lock_policy.py",
            "flutter_outdated_triage.py",
        ],
        evidence_summary={
            "checks": statuses,
            "dependency_source_counts": lock_counts,
            "outdated_dependency_counts": triage_counts,
        },
        checks=statuses,
        dependency_source_counts=lock_counts,
        outdated_dependency_counts=triage_counts,
    )


def _write(value: dict[str, Any], output: Path) -> int:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if value["result"] == "pass" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    rust = subparsers.add_parser("rust")
    rust.add_argument("--head-sha", required=True)
    rust.add_argument("--workflow-sha")
    rust.add_argument("--repository")
    rust.add_argument("--root-audit", type=Path, required=True)
    rust.add_argument("--fuzz-audit", type=Path, required=True)
    rust.add_argument("--root-deny", type=Path, required=True)
    rust.add_argument("--fuzz-deny", type=Path, required=True)
    rust.add_argument("--root-audit-status", type=int, required=True)
    rust.add_argument("--fuzz-audit-status", type=int, required=True)
    rust.add_argument("--root-deny-status", type=int, required=True)
    rust.add_argument("--fuzz-deny-status", type=int, required=True)
    rust.add_argument("--cargo-audit-version", required=True)
    rust.add_argument("--cargo-deny-version", required=True)
    rust.add_argument("--output", type=Path, required=True)

    go = subparsers.add_parser("go")
    go.add_argument("--head-sha", required=True)
    go.add_argument("--workflow-sha")
    go.add_argument("--repository")
    go.add_argument("--govulncheck-json", type=Path, required=True)
    go.add_argument("--modules-json", type=Path, required=True)
    go.add_argument("--mod-status", type=int, required=True)
    go.add_argument("--test-status", type=int, required=True)
    go.add_argument("--vet-status", type=int, required=True)
    go.add_argument("--modules-status", type=int, required=True)
    go.add_argument("--json-status", type=int, required=True)
    go.add_argument("--vuln-status", type=int, required=True)
    go.add_argument("--go-version", required=True)
    go.add_argument("--govulncheck-version", required=True)
    go.add_argument("--output", type=Path, required=True)

    flutter = subparsers.add_parser("flutter")
    flutter.add_argument("--head-sha", required=True)
    flutter.add_argument("--workflow-sha")
    flutter.add_argument("--repository")
    flutter.add_argument("--lock-policy", type=Path, required=True)
    flutter.add_argument("--triage", type=Path, required=True)
    flutter.add_argument("--get-status", type=int, required=True)
    flutter.add_argument("--lock-status", type=int, required=True)
    flutter.add_argument("--deps-status", type=int, required=True)
    flutter.add_argument("--outdated-status", type=int, required=True)
    flutter.add_argument("--analyze-status", type=int, required=True)
    flutter.add_argument("--lock-policy-status", type=int, required=True)
    flutter.add_argument("--triage-status", type=int, required=True)
    flutter.add_argument("--flutter-version", required=True)
    flutter.add_argument("--dart-version", required=True)
    flutter.add_argument("--output", type=Path, required=True)

    args = parser.parse_args()
    if args.command == "rust":
        return _write(rust_summary(args), args.output)
    if args.command == "go":
        return _write(go_summary(args), args.output)
    return _write(flutter_summary(args), args.output)


if __name__ == "__main__":
    raise SystemExit(main())
