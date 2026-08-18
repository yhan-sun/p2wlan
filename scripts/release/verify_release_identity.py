#!/usr/bin/env python3
"""Fail-closed identity gate for daemon/App release artifacts.

The gate is intentionally independent of the packaging shell scripts so the
actual release workflow can invoke the same checks before it uploads anything.
It validates the source version, checkout state, daemon self-report, binary
hash, optional App Info.plist, and optional bundle manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    raise SystemExit(f"identity gate: FAIL: {message}")


def run(*args: str) -> str:
    try:
        return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as exc:
        fail(f"command failed: {' '.join(args)}: {exc.output.strip()}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        fail(f"cannot read binary {path}: {exc}")
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def cargo_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"", text)
    if not match:
        fail("workspace Cargo.toml has no package version")
    return match.group(1)


def flutter_version() -> str:
    text = (ROOT / "apps/flutter_client/pubspec.yaml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^version:\s*([^+\s]+)(?:\+[^\s]+)?\s*$", text)
    if not match:
        fail("Flutter pubspec has no version")
    return match.group(1)


def expected_commit(cli_value: str | None) -> str:
    commit = cli_value or run("git", "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        fail(f"expected commit is not a full SHA-1: {commit!r}")
    return commit.lower()


def daemon_info(args: argparse.Namespace) -> dict[str, Any]:
    if args.build_info_file:
        return read_json(Path(args.build_info_file))
    if not args.daemon:
        fail("--daemon or --build-info-file is required")
    try:
        raw = subprocess.check_output(
            [args.daemon, "--build-info"], cwd=ROOT, text=True, stderr=subprocess.STDOUT
        )
        value = json.loads(raw)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        fail(f"daemon --build-info failed or was not JSON: {exc}")
    if not isinstance(value, dict):
        fail("daemon --build-info root is not an object")
    return value


def verify(args: argparse.Namespace) -> dict[str, Any]:
    version = cargo_version()
    app_version = flutter_version()
    if app_version != version:
        fail(f"Flutter/Cargo version mismatch: app={app_version} cargo={version}")
    commit = expected_commit(args.expected_commit)

    dirty_files = run("git", "status", "--porcelain=v1", "--untracked-files=all")
    if args.release and dirty_files:
        fail("release input is dirty")
    if args.release and os.environ.get("GITHUB_REF", "").startswith("refs/tags/"):
        tag_ref = os.environ.get("GITHUB_REF_NAME", "")
        if not tag_ref:
            fail("tag workflow has no GITHUB_REF_NAME")
        tag_commit = run("git", "rev-list", "-n", "1", tag_ref)
        if tag_commit.lower() != commit:
            fail(f"HEAD {commit} does not match tag {tag_ref} commit {tag_commit}")

    info = daemon_info(args)
    required = (
        "app_version",
        "daemon_version",
        "git_commit",
        "build_id",
        "binary_sha256",
        "binary_path",
        "profile",
        "built_at_ms",
        "dirty",
    )
    for field in required:
        if field not in info or info[field] in (None, ""):
            fail(f"build-info missing {field}")
    if info["app_version"] != version or info["daemon_version"] != version:
        fail(
            f"daemon/App version mismatch: build_info app={info['app_version']} "
            f"daemon={info['daemon_version']} expected={version}"
        )
    if str(info["git_commit"]).lower() != commit:
        fail(f"daemon commit {info['git_commit']} does not match checkout {commit}")
    if args.release and bool(info["dirty"]):
        fail("release daemon was built from a dirty checkout")
    if not args.release and bool(info["dirty"]) and not info["diff_hash"]:
        fail("dirty development daemon has no diff_hash")
    if bool(info["dirty"]) and "diff_hash" not in info:
        fail("dirty build-info is missing diff_hash")
    binary = Path(args.daemon) if args.daemon else Path(str(info["binary_path"]))
    if not binary.is_file():
        fail(f"daemon binary does not exist: {binary}")
    actual_sha = sha256(binary)
    if str(info["binary_sha256"]).lower() != actual_sha:
        fail(f"reported binary SHA {info['binary_sha256']} != actual {actual_sha}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", str(info["binary_sha256"])):
        fail("binary_sha256 is not a SHA-256")

    if args.app_info:
        try:
            plist = plistlib.loads(Path(args.app_info).read_bytes())
        except (OSError, plistlib.InvalidFileException) as exc:
            fail(f"invalid App Info.plist: {exc}")
        if plist.get("CFBundleShortVersionString") != version:
            fail("App Info.plist version does not match Cargo/Flutter")

    if args.manifest:
        manifest = read_json(Path(args.manifest))
        for field in ("app_version", "git_commit", "build_id", "daemon_sha256", "daemon_build_info"):
            if field not in manifest:
                fail(f"manifest missing {field}")
        if manifest["app_version"] != version or manifest["git_commit"].lower() != commit:
            fail("manifest version/commit mismatch")
        if manifest["build_id"] != info["build_id"]:
            fail("manifest build_id mismatch")
        if manifest["daemon_sha256"].lower() != actual_sha:
            fail("manifest daemon_sha256 mismatch")
        embedded_info = manifest["daemon_build_info"]
        if not isinstance(embedded_info, dict):
            fail("manifest daemon_build_info is not an object")
        if embedded_info.get("binary_sha256", "").lower() != actual_sha:
            fail("manifest embedded daemon SHA mismatch")

    return {
        "app_version": version,
        "git_commit": commit,
        "build_id": info["build_id"],
        "daemon_sha256": actual_sha,
        "dirty": bool(info["dirty"]),
        "diff_hash": info["diff_hash"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--daemon")
    parser.add_argument("--build-info-file")
    parser.add_argument("--manifest")
    parser.add_argument("--emit-manifest")
    parser.add_argument("--app-info")
    parser.add_argument("--expected-commit")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    result = verify(args)
    if args.emit_manifest:
        info = daemon_info(args)
        manifest = {
            "app_version": result["app_version"],
            "git_commit": result["git_commit"],
            "build_id": result["build_id"],
            "daemon_sha256": result["daemon_sha256"],
            "daemon_build_info": dict(info),
            "toolchain": {
                "cargo": cargo_version(),
                "flutter": flutter_version(),
            },
        }
        out_path = Path(args.emit_manifest)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print(f"manifest written to {out_path}", flush=True, file=sys.stderr)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
