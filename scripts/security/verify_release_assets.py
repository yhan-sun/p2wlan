#!/usr/bin/env python3
"""Verify every downloaded GitHub Release asset against API size/digest metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from pathlib import Path

REQUIRED_ASSET_PATTERNS = {
    "android_arm64": re.compile(r"android-arm64.*\.apk$"),
    "ios_arm64": re.compile(r"ios-arm64.*\.ipa$"),
    "linux_flutter_x64": re.compile(r"flutter-linux-x64.*\.tar\.gz$"),
    "macos_arm64": re.compile(r"macos-arm64.*\.dmg$"),
    "macos_x64": re.compile(r"macos-x64.*\.dmg$"),
    "windows_x64": re.compile(r"windows-x64.*\.(?:exe|zip)$"),
    "linux_cli_arm64": re.compile(r"linux-arm64-cli.*\.tar\.gz$"),
    "linux_cli_x64": re.compile(r"linux-x64-cli.*\.tar\.gz$"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    release_json: Path,
    assets_dir: Path,
    head_sha: str | None = None,
) -> dict[str, object]:
    release = json.loads(release_json.read_text(encoding="utf-8"))
    findings: list[dict[str, str]] = []
    tag = str(release.get("tag_name", ""))
    if release.get("draft") is not False:
        findings.append(
            {
                "code": "draft_release",
                "message": "latest release is draft or field is missing",
            }
        )
    if release.get("prerelease") is not False:
        findings.append(
            {"code": "prerelease", "message": "latest release is a prerelease"}
        )
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", tag):
        findings.append(
            {"code": "invalid_tag", "message": f"unexpected release tag {tag!r}"}
        )

    raw_assets = release.get("assets")
    assets = raw_assets if isinstance(raw_assets, list) else []
    if not assets:
        findings.append(
            {"code": "no_assets", "message": "latest release has no assets"}
        )

    metadata_names = [str(asset.get("name", "")) for asset in assets]
    if len(metadata_names) != len(set(metadata_names)):
        findings.append(
            {
                "code": "duplicate_asset_name",
                "message": "release metadata contains duplicate names",
            }
        )

    downloaded_names = (
        sorted(path.name for path in assets_dir.iterdir() if path.is_file())
        if assets_dir.is_dir()
        else []
    )
    if sorted(metadata_names) != downloaded_names:
        findings.append(
            {
                "code": "asset_set_mismatch",
                "message": (
                    f"metadata={sorted(metadata_names)!r} "
                    f"downloaded={downloaded_names!r}"
                ),
            }
        )

    verified: list[dict[str, object]] = []
    for asset in sorted(assets, key=lambda item: str(item.get("name", ""))):
        name = str(asset.get("name", ""))
        path = assets_dir / name
        expected_size = asset.get("size")
        digest_value = str(asset.get("digest", ""))
        digest_match = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", digest_value)
        if asset.get("state") != "uploaded":
            findings.append({"code": "asset_not_uploaded", "message": name})
        if not isinstance(expected_size, int) or expected_size <= 0:
            findings.append({"code": "invalid_asset_size", "message": name})
        if digest_match is None:
            findings.append({"code": "missing_asset_digest", "message": name})
        if not path.is_file():
            continue
        actual_size = path.stat().st_size
        actual_digest = sha256(path)
        if isinstance(expected_size, int) and actual_size != expected_size:
            findings.append(
                {
                    "code": "asset_size_mismatch",
                    "message": (
                        f"{name}: expected {expected_size}, got {actual_size}"
                    ),
                }
            )
        if digest_match and actual_digest.lower() != digest_match.group(1).lower():
            findings.append(
                {
                    "code": "asset_digest_mismatch",
                    "message": (
                        f"{name}: expected {digest_match.group(1)}, "
                        f"got {actual_digest}"
                    ),
                }
            )
        verified.append(
            {
                "name": name,
                "size": actual_size,
                "sha256": actual_digest,
            }
        )

    pattern_results: dict[str, bool] = {}
    for label, pattern in REQUIRED_ASSET_PATTERNS.items():
        matched = any(pattern.search(name) for name in metadata_names)
        pattern_results[label] = matched
        if not matched:
            findings.append(
                {"code": "required_asset_class_missing", "message": label}
            )

    return {
        "schema_version": 1,
        "result": "pass" if not findings else "fail",
        "head_sha": head_sha,
        "tool_versions": {
            "python": platform.python_version(),
            "hash": "sha256",
        },
        "digest_source": "GitHub Release asset digest metadata",
        "release_id": release.get("id"),
        "tag": tag,
        "asset_count": len(assets),
        "verified_asset_count": len(verified),
        "mismatch_count": len(findings),
        "required_asset_classes": pattern_results,
        "assets": verified,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    parser.add_argument("--head-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    evidence = run(args.release_json, args.assets_dir, args.head_sha)
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if evidence["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
