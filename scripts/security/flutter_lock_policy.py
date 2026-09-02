#!/usr/bin/env python3
"""Validate the Flutter lockfile's dependency sources and hosted checksums."""

from __future__ import annotations

import argparse
import json
import platform
import re
from pathlib import Path

from report_common import make_report

PACKAGE_RE = re.compile(r"^  ([A-Za-z0-9_+.-]+):$")
SOURCE_RE = re.compile(r"^    source: ([A-Za-z0-9_-]+)$")
SHA_RE = re.compile(r'^      sha256: "?([0-9a-fA-F]{64})"?$')
URL_RE = re.compile(r'^      url: "?(https?://[^" ]+)"?$')
VERSION_RE = re.compile(r'^    version: "?([^" ]+)"?$')


def run(
    lockfile: Path,
    head_sha: str | None = None,
    *,
    repository: str | None = None,
    workflow_sha: str | None = None,
    manifest: Path | None = None,
) -> dict[str, object]:
    packages: dict[str, dict[str, object]] = {}
    current: str | None = None
    findings: list[dict[str, str]] = []
    try:
        lock_text = lockfile.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        lock_text = ""
        findings.append({"code": "invalid_lockfile", "message": str(error)})

    for raw in lock_text.splitlines():
        if match := PACKAGE_RE.match(raw):
            current = match.group(1)
            packages[current] = {}
            continue
        if current is None:
            continue
        if match := SOURCE_RE.match(raw):
            packages[current]["source"] = match.group(1)
        elif match := SHA_RE.match(raw):
            packages[current]["sha256"] = match.group(1).lower()
        elif match := URL_RE.match(raw):
            packages[current]["url"] = match.group(1)
        elif match := VERSION_RE.match(raw):
            packages[current]["version"] = match.group(1)

    source_counts: dict[str, int] = {}
    if not packages:
        findings.append(
            {
                "code": "empty_lockfile",
                "message": "pubspec.lock contains no package entries",
            }
        )
    if manifest is not None:
        try:
            manifest_lines = manifest.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            findings.append({"code": "invalid_manifest", "message": str(error)})
        else:
            in_overrides = False
            for raw in manifest_lines:
                stripped = raw.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                indent = len(raw) - len(raw.lstrip(" "))
                if indent == 0:
                    in_overrides = stripped == "dependency_overrides:"
                    if in_overrides:
                        findings.append(
                            {
                                "code": "dependency_override",
                                "message": "pubspec.yaml contains dependency_overrides",
                            }
                        )
                    continue
                if in_overrides and indent > 0:
                    in_overrides = False
                if re.match(r"^\s+(?:git|path):", raw):
                    findings.append(
                        {
                            "code": "untrusted_manifest_source",
                            "message": "pubspec.yaml contains a git/path dependency source",
                        }
                    )
    for name, package in sorted(packages.items()):
        if not package.get("version"):
            findings.append(
                {
                    "package": name,
                    "code": "missing_version",
                    "message": "lockfile package lacks a resolved version",
                }
            )
        source = str(package.get("source", "missing"))
        source_counts[source] = source_counts.get(source, 0) + 1
        if source not in {"hosted", "sdk"}:
            findings.append(
                {
                    "package": name,
                    "code": "untrusted_source",
                    "message": f"source {source!r} is not hosted/sdk",
                }
            )
            continue
        if source == "hosted":
            if package.get("url") != "https://pub.dev":
                findings.append(
                    {
                        "package": name,
                        "code": "unexpected_registry",
                        "message": f"hosted URL is {package.get('url')!r}",
                    }
                )
            if not re.fullmatch(r"[0-9a-f]{64}", str(package.get("sha256", ""))):
                findings.append(
                    {
                        "package": name,
                        "code": "missing_checksum",
                        "message": "hosted dependency lacks a SHA-256",
                    }
                )

    result = "pass" if not findings else "fail"
    return make_report(
        component="flutter_lock_source_policy",
        head_sha=head_sha,
        workflow_sha=workflow_sha,
        repository=repository,
        result=result,
        findings=findings,
        tool="flutter_lock_policy.py",
        tools={"python": platform.python_version()},
        command=[
            "flutter_lock_policy.py",
            "--lockfile",
            lockfile.as_posix(),
            *(["--manifest", manifest.as_posix()] if manifest is not None else []),
        ],
        evidence_summary={
            "package_count": len(packages),
            "source_counts": source_counts,
        },
        lockfile=lockfile.as_posix(),
        package_count=len(packages),
        source_counts=source_counts,
        manifest=manifest.as_posix() if manifest is not None else None,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--head-sha")
    parser.add_argument("--workflow-sha")
    parser.add_argument("--repository")
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    evidence = run(
        args.lockfile,
        args.head_sha,
        repository=args.repository,
        workflow_sha=args.workflow_sha,
        manifest=args.manifest,
    )
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
