#!/usr/bin/env python3
"""Aggregate all security gate evidence into one fail-closed manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_named(root: Path, filename: str) -> dict[str, object]:
    matches = list(root.rglob(filename))
    if len(matches) != 1:
        return {}
    try:
        value = json.loads(matches[0].read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _int_value(value: dict[str, object], key: str) -> int:
    raw = value.get(key)
    return raw if isinstance(raw, int) else 0


def _nested_int(value: dict[str, object], parent: str, key: str) -> int:
    raw = value.get(parent)
    if not isinstance(raw, dict):
        return 0
    nested = raw.get(key)
    return nested if isinstance(nested, int) else 0


def run(root: Path, head_sha: str) -> dict[str, object]:
    checks: dict[str, object] = {}
    findings: list[dict[str, str]] = []
    evidence_files: list[dict[str, object]] = []

    for filename, check_name in REQUIRED.items():
        matches = list(root.rglob(filename))
        if len(matches) != 1:
            findings.append(
                {
                    "code": "evidence_file_missing_or_ambiguous",
                    "message": f"{filename}: found {len(matches)}",
                }
            )
            continue
        path = matches[0]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            findings.append(
                {
                    "code": "invalid_evidence_json",
                    "message": f"{filename}: {error}",
                }
            )
            continue
        result = value.get("result")
        evidence_head = value.get("head_sha")
        checks[check_name] = {
            "result": result,
            "source": filename,
            "head_sha": evidence_head,
        }
        if evidence_head is not None and evidence_head != head_sha:
            findings.append(
                {
                    "code": "evidence_head_mismatch",
                    "message": (
                        f"{filename}: expected {head_sha}, got {evidence_head}"
                    ),
                }
            )
        if result != "pass":
            findings.append(
                {
                    "code": "check_failed",
                    "message": f"{check_name}: {result!r}",
                }
            )
        evidence_files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": digest(path),
            }
        )

    rust = _load_named(root, "rust-summary.json")
    go = _load_named(root, "go-summary.json")
    flutter = _load_named(root, "flutter-summary.json")
    release = _load_named(root, "release-assets.json")

    return {
        "schema_version": 1,
        "result": "pass" if not findings else "fail",
        "head_sha": head_sha,
        "checks": checks,
        "summary_counts": {
            "rust_vulnerabilities": _nested_int(
                rust, "vulnerability_counts", "total"
            ),
            "go_vulnerabilities": _int_value(go, "vulnerability_count"),
            "flutter_outdated_classified": _nested_int(
                flutter, "outdated_dependency_counts", "classified"
            ),
            "flutter_outdated_blockers": _nested_int(
                flutter, "outdated_dependency_counts", "blockers"
            ),
            "release_assets_verified": _int_value(
                release, "verified_asset_count"
            ),
        },
        "tool_versions": {
            "rust": rust.get("tools", {}) if isinstance(rust, dict) else {},
            "go": go.get("tools", {}) if isinstance(go, dict) else {},
            "flutter": (
                flutter.get("tools", {}) if isinstance(flutter, dict) else {}
            ),
        },
        "evidence_files": sorted(
            evidence_files, key=lambda item: str(item["path"])
        ),
        "product_signing": {
            "code_signing": "deferred_non_blocking",
            "notarization": "deferred_non_blocking",
            "authenticode": "deferred_non_blocking",
            "reason": (
                "Issue #30 explicitly audits dependencies, workflows, "
                "credential transport and checksums without making product "
                "signing a gate."
            ),
        },
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    evidence = run(args.root, args.head_sha)
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
