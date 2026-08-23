#!/usr/bin/env python3
"""Emit the Dart defines that stamp a Flutter client with checkout identity.

The daemon build script and this helper intentionally use the same dirty
material: a clean build has an empty diff hash, while a dirty build hashes the
porcelain status, binary tracked diff, and bytes of every untracked file.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run_bytes(*args: str) -> bytes:
    return subprocess.check_output(args, cwd=ROOT)


def run_text(*args: str) -> str:
    return run_bytes(*args).decode("utf-8", errors="replace")


def app_version() -> str:
    text = (ROOT / "apps/flutter_client/pubspec.yaml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version:\s*([^+\s]+)", text)
    if not match:
        raise SystemExit("Flutter pubspec has no version")
    return match.group(1)


def checkout_identity() -> tuple[str, str, str]:
    commit = run_text("git", "rev-parse", "HEAD").strip()
    status = run_text("git", "status", "--porcelain=v1", "--untracked-files=all")
    if not status.strip():
        return commit, "false", ""

    material = bytearray(status.encode("utf-8"))
    material.extend(run_bytes("git", "diff", "HEAD", "--no-ext-diff", "--binary"))
    untracked = run_bytes("git", "ls-files", "--others", "--exclude-standard", "-z")
    for raw_path in untracked.split(b"\0"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", errors="replace")
        material.extend(f"\n-- untracked: {path} --\n".encode("utf-8"))
        material.extend((ROOT / path).read_bytes())
    # `git hash-object --stdin` hashes a Git blob header plus the material.
    blob_header = f"blob {len(material)}\0".encode("ascii")
    diff_hash = hashlib.sha1(blob_header + material).hexdigest()
    return commit, "true", diff_hash


def main() -> None:
    commit, dirty, diff_hash = checkout_identity()
    build_id = commit[:12]
    if dirty == "true":
        build_id = f"{build_id}-dirty-{diff_hash[:12]}"
    profile = "release" if "--release" in sys.argv[1:] else "debug"
    values = {
        "P2WLAN_CLIENT_APP_VERSION": app_version(),
        "P2WLAN_CLIENT_GIT_COMMIT": commit,
        "P2WLAN_CLIENT_BUILD_ID": build_id,
        "P2WLAN_CLIENT_DIRTY": dirty,
        "P2WLAN_CLIENT_DIFF_HASH": diff_hash,
        "P2WLAN_CLIENT_PROFILE": profile,
    }
    for key, value in values.items():
        print(f"--dart-define={key}={value}")


if __name__ == "__main__":
    main()
