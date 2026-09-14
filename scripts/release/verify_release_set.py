#!/usr/bin/env python3
"""Validate the complete client release set and write its identity manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

EXPECTED = (
    "p2wlan-android-arm64-release.apk",
    "p2wlan-ios-arm64-unsigned.ipa",
    "p2wlan-linux-arm64-cli.tar.gz",
    "p2wlan-linux-arm64-cli.tar.gz.sha256",
    "p2wlan-linux-x64-cli.tar.gz",
    "p2wlan-linux-x64-cli.tar.gz.sha256",
    "p2wlan-linux-x64.tar.gz",
    "p2wlan-macos-arm64.dmg",
    "p2wlan-macos-x64.dmg",
    "p2wlan-windows-x64-setup.exe",
)


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    errors: list[str] = []
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        errors.append("source SHA must be a full lowercase Git commit")
    if not re.fullmatch(r"v[A-Za-z0-9._-]+", args.tag):
        errors.append("tag must be a client release tag")

    files: dict[str, dict[str, int | str]] = {}
    for name in EXPECTED:
        path = args.directory / name
        if not path.is_file():
            errors.append(f"missing release asset: {name}")
            continue
        files[name] = {"bytes": path.stat().st_size, "sha256": digest(path)}

    for checksum_name in (
        "p2wlan-linux-arm64-cli.tar.gz.sha256",
        "p2wlan-linux-x64-cli.tar.gz.sha256",
    ):
        checksum = args.directory / checksum_name
        if not checksum.is_file():
            continue
        fields = checksum.read_text(encoding="utf-8").strip().split()
        target = checksum_name.removesuffix(".sha256")
        if len(fields) < 2 or fields[1].lstrip("*") != target:
            errors.append(f"invalid checksum record: {checksum_name}")
        elif fields[0] != digest(args.directory / target):
            errors.append(f"checksum mismatch: {checksum_name}")

    if errors:
        print("FAIL release set")
        for error in errors:
            print(f"- {error}")
        return 1

    manifest = {
        "schema_version": 1,
        "tag": args.tag,
        "source_sha": args.source_sha,
        "files": files,
    }
    output = args.directory / "RELEASE-MANIFEST.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS release set ({len(files)} assets); manifest={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
