#!/usr/bin/env python3
"""Audit a published client release against its tag and manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

MANIFEST_NAME = "RELEASE-MANIFEST.json"
EXPECTED_PAYLOADS = (
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
PRIMARY_ARTIFACTS = {
    "p2wlan-android-arm64-release.apk": ("android", "arm64"),
    "p2wlan-ios-arm64-unsigned.ipa": ("ios", "arm64"),
    "p2wlan-linux-arm64-cli.tar.gz": ("linux-cli", "arm64"),
    "p2wlan-linux-x64-cli.tar.gz": ("linux-cli", "x64"),
    "p2wlan-linux-x64.tar.gz": ("linux", "x64"),
    "p2wlan-macos-arm64.dmg": ("macos", "arm64"),
    "p2wlan-macos-x64.dmg": ("macos", "x64"),
    "p2wlan-windows-x64-setup.exe": ("windows", "x64"),
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
TOKEN_RE = re.compile(r"[A-Za-z0-9._-]+")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(
    release: dict[str, Any],
    manifest: dict[str, Any],
    manifest_path: Path,
    expected_tag: str,
    tag_commit: str,
    require_immutable: bool = False,
) -> tuple[list[str], list[str], dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []

    if release.get("tag_name") != expected_tag:
        errors.append(f"release tag mismatch: {release.get('tag_name')!r} != {expected_tag!r}")
    if release.get("draft") is not False:
        errors.append("release is still a draft")
    if release.get("prerelease") is not False:
        errors.append("client release must not be a prerelease")
    if not release.get("published_at"):
        errors.append("release has no published_at timestamp")

    immutable = release.get("immutable")
    if immutable is not True:
        message = "release is mutable; enable GitHub immutable releases for future tags"
        if require_immutable:
            errors.append(message)
        else:
            warnings.append(message)

    if not COMMIT_RE.fullmatch(tag_commit):
        errors.append(f"tag commit is not a full lowercase SHA-1: {tag_commit!r}")

    if manifest.get("schema_version") != 2:
        errors.append(f"unsupported manifest schema_version: {manifest.get('schema_version')!r}")
    if manifest.get("tag") != expected_tag:
        errors.append(f"manifest tag mismatch: {manifest.get('tag')!r} != {expected_tag!r}")
    source_sha = manifest.get("source_sha")
    if source_sha != tag_commit:
        errors.append(f"manifest source_sha {source_sha!r} != tag commit {tag_commit!r}")

    files = manifest.get("files")
    if not isinstance(files, dict):
        errors.append("manifest files is not an object")
        files = {}

    expected_payloads = set(EXPECTED_PAYLOADS)
    manifest_payloads = set(files)
    for name in sorted(expected_payloads - manifest_payloads):
        errors.append(f"manifest is missing payload: {name}")
    for name in sorted(manifest_payloads - expected_payloads):
        errors.append(f"manifest has unexpected payload: {name}")

    assets_raw = release.get("assets")
    if not isinstance(assets_raw, list):
        errors.append("release assets is not an array")
        assets_raw = []
    assets: dict[str, dict[str, Any]] = {}
    for value in assets_raw:
        if not isinstance(value, dict) or not isinstance(value.get("name"), str):
            errors.append("release contains an asset without a valid name")
            continue
        name = value["name"]
        if name in assets:
            errors.append(f"release contains duplicate asset: {name}")
            continue
        assets[name] = value

    expected_assets = expected_payloads | {MANIFEST_NAME}
    actual_assets = set(assets)
    for name in sorted(expected_assets - actual_assets):
        errors.append(f"release is missing asset: {name}")
    for name in sorted(actual_assets - expected_assets):
        errors.append(f"release has unexpected asset: {name}")

    for name in EXPECTED_PAYLOADS:
        meta = files.get(name)
        asset = assets.get(name)
        if not isinstance(meta, dict):
            errors.append(f"manifest has invalid metadata for {name}")
            continue
        if asset is None:
            continue
        expected_size = meta.get("bytes")
        expected_digest = meta.get("sha256")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
            errors.append(f"manifest has invalid byte size for {name}")
        if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
            errors.append(f"manifest has invalid sha256 for {name}")
        if name in PRIMARY_ARTIFACTS:
            expected_platform, expected_arch = PRIMARY_ARTIFACTS[name]
            if meta.get("platform") != expected_platform:
                errors.append(
                    f"manifest platform mismatch for {name}: {meta.get('platform')!r} != {expected_platform!r}"
                )
            if meta.get("arch") != expected_arch:
                errors.append(
                    f"manifest arch mismatch for {name}: {meta.get('arch')!r} != {expected_arch!r}"
                )
            identity = meta.get("identity")
            if not isinstance(identity, str) or not TOKEN_RE.fullmatch(identity):
                errors.append(f"manifest has invalid artifact identity for {name}")
        if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
            continue
        if asset.get("state") != "uploaded":
            errors.append(f"release asset is not uploaded: {name}")
        if asset.get("size") != expected_size:
            errors.append(
                f"release asset size mismatch for {name}: {asset.get('size')!r} != {expected_size!r}"
            )
        if asset.get("digest") != f"sha256:{expected_digest}":
            errors.append(
                f"release asset digest mismatch for {name}: {asset.get('digest')!r} != sha256:{expected_digest}"
            )

    manifest_asset = assets.get(MANIFEST_NAME)
    if manifest_path.is_file():
        manifest_size = manifest_path.stat().st_size
        manifest_digest = sha256(manifest_path)
    else:
        errors.append(f"downloaded manifest does not exist: {manifest_path}")
        manifest_size = None
        manifest_digest = None
    if manifest_asset is not None:
        if manifest_asset.get("state") != "uploaded":
            errors.append("release manifest asset is not uploaded")
        if manifest_size is not None and manifest_asset.get("size") != manifest_size:
            errors.append("release manifest asset size does not match downloaded manifest")
        if manifest_digest is not None and manifest_asset.get("digest") != f"sha256:{manifest_digest}":
            errors.append("release manifest asset digest does not match downloaded manifest")

    report = {
        "tag": expected_tag,
        "source_sha": tag_commit,
        "published_at": release.get("published_at"),
        "immutable": immutable is True,
        "asset_count": len(actual_assets),
        "payload_count": len(expected_payloads),
        "manifest_schema_version": manifest.get("schema_version"),
        "manifest_sha256": manifest_digest,
        "warnings": warnings,
    }
    return errors, warnings, report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--tag-commit", required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--require-immutable", action="store_true")
    args = parser.parse_args()

    try:
        release = load_json(args.release_json)
        manifest = load_json(args.manifest)
    except ValueError as exc:
        print(f"FAIL published release audit\n- {exc}")
        return 1

    errors, warnings, report = verify(
        release,
        manifest,
        args.manifest,
        args.tag,
        args.tag_commit,
        args.require_immutable,
    )
    for warning in warnings:
        print(f"WARN: {warning}")
    if errors:
        print("FAIL published release audit")
        for error in errors:
            print(f"- {error}")
        return 1

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"PASS published release audit tag={args.tag} source={args.tag_commit} "
        f"assets={report['asset_count']} manifest_sha256={report['manifest_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
