#!/usr/bin/env python3
"""Validate the Flutter lockfile's dependency sources and hosted checksums."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PACKAGE_RE = re.compile(r"^  ([A-Za-z0-9_+.-]+):$")
SOURCE_RE = re.compile(r"^    source: ([A-Za-z0-9_-]+)$")
SHA_RE = re.compile(r'^      sha256: "?([0-9a-fA-F]{64})"?$')
URL_RE = re.compile(r'^      url: "?(https?://[^" ]+)"?$')
VERSION_RE = re.compile(r'^    version: "?([^" ]+)"?$')


def run(lockfile: Path, head_sha: str | None = None) -> dict[str, object]:
    packages: dict[str, dict[str, object]] = {}
    current: str | None = None
    for raw in lockfile.read_text(encoding="utf-8").splitlines():
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

    findings: list[dict[str, str]] = []
    source_counts: dict[str, int] = {}
    for name, package in sorted(packages.items()):
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

    return {
        "schema_version": 1,
        "result": "pass" if not findings else "fail",
        "head_sha": head_sha,
        "lockfile": lockfile.as_posix(),
        "package_count": len(packages),
        "source_counts": source_counts,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lockfile", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--head-sha")
    args = parser.parse_args()
    evidence = run(args.lockfile, args.head_sha)
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
