#!/usr/bin/env python3
"""Bind a final release artifact digest to the exact workflow source identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


TOKEN_RE = re.compile(r"[A-Za-z0-9._-]+")


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--identity", required=True)
    args = parser.parse_args()

    errors: list[str] = []
    if not args.artifact.is_file():
        errors.append(f"artifact does not exist: {args.artifact}")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        errors.append("source SHA must be a full lowercase Git commit")
    if not re.fullmatch(r"v[A-Za-z0-9._-]+", args.tag):
        errors.append("tag must be a client release tag")
    for label, value in (
        ("platform", args.platform),
        ("arch", args.arch),
        ("identity", args.identity),
    ):
        if not TOKEN_RE.fullmatch(value):
            errors.append(f"{label} contains unsupported characters: {value!r}")

    if errors:
        print("FAIL artifact metadata")
        for error in errors:
            print(f"- {error}")
        return 1

    output = args.output or args.artifact.with_name(args.artifact.name + ".metadata.json")
    metadata = {
        "schema_version": 1,
        "artifact": args.artifact.name,
        "source_sha": args.source_sha,
        "tag": args.tag,
        "platform": args.platform,
        "arch": args.arch,
        "identity": args.identity,
        "bytes": args.artifact.stat().st_size,
        "sha256": sha256(args.artifact),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PASS artifact metadata {args.artifact.name} -> {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
